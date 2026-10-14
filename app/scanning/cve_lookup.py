"""Known-CVE lookup for service versions nmap identifies, via the NVD CVE API 2.0
(https://nvd.nist.gov/developers/vulnerabilities) -- the US government's free,
official vulnerability database.

nmap's -sV reports a CPE for many services (e.g. cpe:/a:apache:http_server:2.4.49).
NVD's `virtualMatchString` matches that CPE against the version ranges in each CVE's
configuration, so "Apache httpd 2.4.49" finds every CVE whose affected range includes
2.4.49 -- not just CVEs that happen to mention that exact string.

Passive with respect to the target: this only sends the product/version to NVD, never
contacts the scanned host. Rate limits are respected (NVD allows 5 requests per rolling
30 seconds without an API key, 50 with one), results are cached per CPE for the life of
the process, and any NVD failure degrades to "lookup unavailable" rather than failing the
scan.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

import httpx

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_USER_AGENT = "DefensivePentestScanner/0.1 (+self-hosted authorized scanner)"


@dataclass(frozen=True)
class Cve:
    cve_id: str
    score: float | None
    severity: str | None  # CRITICAL / HIGH / MEDIUM / LOW, from the CVSS metric used
    known_exploited: bool  # listed in CISA's Known Exploited Vulnerabilities catalog
    summary: str

    @property
    def url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"


@dataclass
class CveLookupResult:
    cpe: str
    cves: list[Cve] = field(default_factory=list)
    total: int = 0
    error: str | None = None


def nmap_cpe_to_match_string(cpe: str) -> str | None:
    """'cpe:/a:apache:http_server:2.4.49' -> 'cpe:2.3:a:apache:http_server:2.4.49'.

    Returns None unless the CPE names an application or OS *with a version* -- a bare
    'cpe:/o:microsoft:windows' would match thousands of CVEs and say nothing useful about
    this particular host."""
    if not cpe.startswith("cpe:/"):
        return None
    parts = cpe[5:].split(":")
    if len(parts) < 4 or parts[0] not in ("a", "o", "h"):
        return None
    part, vendor, product, version = parts[:4]
    if not vendor or not product or not version or version in ("*", "-"):
        return None
    return f"cpe:2.3:{part}:{vendor}:{product}:{version}"


def _parse_cve(item: dict) -> Cve:
    cve = item.get("cve", {})
    metrics = cve.get("metrics", {})
    score = severity = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            metric = metrics[key][0]
            data = metric.get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or metric.get("baseSeverity")
            break
    summary = next(
        (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )
    return Cve(
        cve_id=cve.get("id", "UNKNOWN"),
        score=score,
        severity=(severity or "").upper() or None,
        known_exploited=bool(cve.get("cisaExploitAdd")),
        summary=summary,
    )


def rank(cves: list[Cve]) -> list[Cve]:
    """Actively exploited first, then by CVSS score -- the order a defender should patch in."""
    return sorted(cves, key=lambda c: (not c.known_exploited, -(c.score or 0.0), c.cve_id))


class NvdClient:
    """Thread-safe, rate-limited, caching NVD client. One shared instance per process so
    concurrent scans can't jointly exceed NVD's limits."""

    def __init__(self, api_key: str = "", *, timeout: float = 20.0):
        self.api_key = api_key
        self.timeout = timeout
        # NVD: 5 requests / 30 s without a key, 50 / 30 s with one. Spacing requests evenly
        # (6 s / 0.6 s apart) keeps any rolling 30 s window under the limit.
        self.min_interval = 0.6 if api_key else 6.0
        self._last_request = 0.0
        self._lock = threading.Lock()
        self._cache: dict[str, CveLookupResult] = {}

    def lookup(self, cpe: str) -> CveLookupResult:
        match = nmap_cpe_to_match_string(cpe)
        if match is None:
            return CveLookupResult(cpe=cpe, error="CPE has no version to match")
        with self._lock:
            if match in self._cache:
                return self._cache[match]
            wait = self._last_request + self.min_interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()
            result = self._fetch(cpe, match)
            if result.error is None:
                self._cache[match] = result
            return result

    def _fetch(self, cpe: str, match: str) -> CveLookupResult:
        headers = {"User-Agent": _USER_AGENT}
        if self.api_key:
            headers["apiKey"] = self.api_key
        try:
            response = httpx.get(
                _NVD_URL,
                params={"virtualMatchString": match, "resultsPerPage": 500},
                headers=headers,
                timeout=self.timeout,
            )
        except httpx.HTTPError as exc:
            return CveLookupResult(cpe=cpe, error=f"NVD request failed: {exc}")
        if response.status_code in (403, 429):
            return CveLookupResult(cpe=cpe, error="NVD rate limit reached; try again later or set NVD_API_KEY")
        if response.status_code != 200:
            return CveLookupResult(cpe=cpe, error=f"NVD returned HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError:
            return CveLookupResult(cpe=cpe, error="NVD returned an unparsable response")
        cves = rank([_parse_cve(item) for item in data.get("vulnerabilities", [])])
        return CveLookupResult(cpe=cpe, cves=cves, total=data.get("totalResults", len(cves)))
