"""Scoped, same-domain crawler used to feed the web app detection checks.

Safety notes:
- Stays within the target's own domain (never follows links off-domain).
- Respects robots.txt disallow rules.
- Hard page-count cap and a per-request delay, so the crawler behaves like a
  polite single client rather than a load-generating tool.
- GET-only traversal. Forms are recorded (for the CSRF check) but never
  submitted — the crawler observes, it doesn't interact.
"""

import time
import urllib.robotparser
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx

from app.scanning.common import ScanEngineError


@dataclass
class FormInfo:
    action: str
    method: str
    input_names: list[str] = field(default_factory=list)


@dataclass
class PageResult:
    url: str
    status_code: int
    headers: dict
    body: str
    forms: list[FormInfo] = field(default_factory=list)
    links: list[str] = field(default_factory=list)


@dataclass
class CrawlResult:
    base_url: str
    pages: list[PageResult] = field(default_factory=list)


class _PageHTMLParser(HTMLParser):
    def __init__(self, page_url: str):
        super().__init__()
        self.page_url = page_url
        self.links: list[str] = []
        self.forms: list[FormInfo] = []
        self._current_form: FormInfo | None = None

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        if tag == "a" and "href" in attr_dict:
            self.links.append(urljoin(self.page_url, attr_dict["href"]))
        elif tag == "form":
            action = urljoin(self.page_url, attr_dict.get("action", self.page_url))
            method = attr_dict.get("method", "get").lower()
            self._current_form = FormInfo(action=action, method=method)
            self.forms.append(self._current_form)
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name = attr_dict.get("name")
            if name:
                self._current_form.input_names.append(name)

    def handle_endtag(self, tag):
        if tag == "form":
            self._current_form = None


def _same_domain(base_netloc: str, candidate: str) -> bool:
    return urlparse(candidate).netloc == base_netloc


def crawl(base_url: str, max_pages: int = 40, delay_seconds: float = 0.5) -> CrawlResult:
    parsed_base = urlparse(base_url)
    if parsed_base.scheme not in ("http", "https"):
        raise ScanEngineError("Target URL must start with http:// or https://")

    robots = urllib.robotparser.RobotFileParser()
    robots_url = urljoin(base_url, "/robots.txt")
    try:
        robots.set_url(robots_url)
        robots.read()
    except Exception:  # noqa: BLE001 - missing/unreachable robots.txt just means no restrictions known
        robots = None

    to_visit = [base_url]
    visited: set[str] = set()
    result = CrawlResult(base_url=base_url)

    with httpx.Client(timeout=15, follow_redirects=True, headers={"User-Agent": "DefensivePentestScanner/1.0"}) as client:
        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            if not _same_domain(parsed_base.netloc, url):
                continue
            if robots is not None and not robots.can_fetch("DefensivePentestScanner", url):
                continue

            visited.add(url)
            try:
                resp = client.get(url)
            except httpx.HTTPError:
                continue

            time.sleep(delay_seconds)

            body = resp.text if "text/html" in resp.headers.get("content-type", "") else ""
            page = PageResult(url=str(resp.url), status_code=resp.status_code, headers=dict(resp.headers), body=body)

            if body:
                parser = _PageHTMLParser(str(resp.url))
                try:
                    parser.feed(body)
                except Exception:  # noqa: BLE001 - malformed HTML shouldn't kill the crawl
                    pass
                page.links = parser.links
                page.forms = parser.forms
                for link in parser.links:
                    if link not in visited and _same_domain(parsed_base.netloc, link):
                        to_visit.append(link)

            result.pages.append(page)

    return result
