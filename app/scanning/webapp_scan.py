import httpx

from app.config import settings
from app.scanning.common import RawFinding, ScanEngineError
from app.scanning.webapp.checks import run_all_checks
from app.scanning.webapp.crawler import crawl


def _resolve_base_url(target_value: str) -> str:
    """Target values for domain/hostname targets are stored bare (e.g.
    'example.com', matching what the DNS TXT/well-known verification flow
    uses) unless the operator included a scheme themselves. Prefer HTTPS,
    falling back to HTTP only if HTTPS isn't reachable at all."""
    if target_value.startswith("http://") or target_value.startswith("https://"):
        return target_value

    try:
        httpx.head(f"https://{target_value}", timeout=8, follow_redirects=True)
        return f"https://{target_value}"
    except httpx.HTTPError:
        pass

    try:
        httpx.head(f"http://{target_value}", timeout=8, follow_redirects=True)
        return f"http://{target_value}"
    except httpx.HTTPError as exc:
        raise ScanEngineError(f"Could not reach '{target_value}' over HTTPS or HTTP: {exc}") from exc


def run_webapp_scan(target_value: str) -> list[RawFinding]:
    base_url = _resolve_base_url(target_value)
    crawl_result = crawl(
        base_url,
        max_pages=settings.crawler_max_pages,
        delay_seconds=settings.crawler_request_delay_seconds,
    )
    return run_all_checks(crawl_result, base_url)
