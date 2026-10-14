"""Detection-only web application checks. Every check here confirms a
condition exists (a missing header, a reflected marker, a DB error string) —
none of them exploit further, brute force, or attempt to modify data.

SQLi/XSS detection technique, deliberately chosen to stay non-destructive:
- XSS: reflect a unique, inert marker string back through each query
  parameter and check whether it comes back unescaped. No script execution
  is attempted (no browser/JS engine involved) — this is a reflection check,
  not a proof-of-exploit.
- SQLi: append a single quote to each query parameter and diff the response
  against a baseline (unmodified) request, looking for database error
  signatures. This is purely response-diffing / error-based detection — no
  time-based blind techniques are used, since those work by deliberately
  slowing down the target's database and are a worse fit for a "safe by
  default" scanner.
"""

import re
import secrets
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import httpx

from app.models import Severity
from app.scanning.common import RawFinding
from app.scanning.webapp.crawler import CrawlResult

SECURITY_HEADERS = {
    "content-security-policy": (
        Severity.MEDIUM,
        "Content-Security-Policy",
        "Restricts what sources scripts/styles/frames can load from, reducing XSS impact.",
    ),
    "strict-transport-security": (
        Severity.MEDIUM,
        "Strict-Transport-Security (HSTS)",
        "Forces browsers to use HTTPS for this domain, preventing downgrade/SSL-stripping attacks.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "X-Frame-Options",
        "Prevents the page from being embedded in a clickjacking iframe.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "X-Content-Type-Options",
        "Prevents browsers from MIME-sniffing responses away from the declared Content-Type.",
    ),
    "referrer-policy": (
        Severity.INFO,
        "Referrer-Policy",
        "Controls how much referrer information is leaked to other sites.",
    ),
}

SENSITIVE_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/backup.zip",
    "/backup.sql",
    "/database.sql",
    "/.svn/entries",
    "/.DS_Store",
    "/wp-config.php.bak",
    "/config.php.bak",
    "/docker-compose.yml",
    "/.aws/credentials",
    "/admin",
    "/administrator",
    "/.well-known/security.txt",
]

_SQLI_SIGNATURES = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysql", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"pg_query\(\)|PostgreSQL.*ERROR", re.I),
    re.compile(r"sqlite3\.OperationalError|SQLite3::", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"System\.Data\.SqlClient", re.I),
]

_CSRF_TOKEN_NAME_HINTS = re.compile(r"csrf|xsrf|authenticity_token|_token|nonce", re.I)


def check_security_headers(crawl: CrawlResult) -> list[RawFinding]:
    if not crawl.pages:
        return []
    headers = {k.lower(): v for k, v in crawl.pages[0].headers.items()}
    findings = []
    for header, (severity, label, why) in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(
                RawFinding(
                    severity=severity,
                    title=f"Missing security header: {label}",
                    description=f"{crawl.base_url} does not set the {label} response header. {why}",
                    remediation=f"Add the {label} header to responses, scoped appropriately for this application.",
                    affected_asset=crawl.base_url,
                )
            )
    return findings


def check_exposed_files(base_url: str) -> list[RawFinding]:
    findings: list[RawFinding] = []
    with httpx.Client(timeout=10, headers={"User-Agent": "DefensivePentestScanner/1.0"}) as client:
        baseline_path = f"/this-path-should-not-exist-{secrets.token_hex(8)}"
        try:
            baseline = client.get(urljoin(base_url, baseline_path))
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code
        except httpx.HTTPError:
            baseline_len, baseline_status = 0, 404

        for path in SENSITIVE_PATHS:
            url = urljoin(base_url, path)
            try:
                resp = client.get(url)
            except httpx.HTTPError:
                continue

            if resp.status_code != 200:
                continue
            # Skip soft-404 pages that return 200 with the same catch-all body.
            if baseline_status == 200 and abs(len(resp.text) - baseline_len) < 25:
                continue

            confidence_boost = ""
            if path == "/.git/HEAD" and "ref:" not in resp.text:
                continue
            if path.startswith("/.env") and "=" not in resp.text:
                continue

            findings.append(
                RawFinding(
                    severity=Severity.HIGH if path in ("/.git/HEAD", "/.env", "/.aws/credentials") else Severity.MEDIUM,
                    title=f"Potentially exposed sensitive path: {path}",
                    description=f"{url} returned HTTP 200 with content that differs from the site's default 404 page.",
                    remediation="Remove or block public access to this path (web server config / .htaccess / firewall rule).",
                    affected_asset=url,
                    evidence=resp.text[:200],
                )
            )
    return findings


def check_tls(base_url: str) -> list[RawFinding]:
    parsed = urlparse(base_url)
    if parsed.scheme != "https":
        return [
            RawFinding(
                severity=Severity.HIGH,
                title="Site does not use HTTPS",
                description=f"{base_url} was scanned over plain HTTP.",
                remediation="Serve the site over HTTPS and redirect HTTP to HTTPS.",
                affected_asset=base_url,
            )
        ]

    host = parsed.hostname
    port = parsed.port or 443
    findings: list[RawFinding] = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

        if protocol in ("TLSv1", "TLSv1.1"):
            findings.append(
                RawFinding(
                    severity=Severity.MEDIUM,
                    title=f"Outdated TLS protocol negotiated: {protocol}",
                    description=f"{host}:{port} negotiated {protocol}, which is deprecated.",
                    remediation="Disable TLS 1.0/1.1 on the server and require TLS 1.2+.",
                    affected_asset=f"{host}:{port}",
                )
            )

        not_after = cert.get("notAfter")
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(
                    RawFinding(
                        severity=Severity.CRITICAL,
                        title="TLS certificate has expired",
                        description=f"Certificate for {host} expired on {expiry.date()}.",
                        remediation="Renew the TLS certificate immediately.",
                        affected_asset=host,
                    )
                )
            elif days_left < 14:
                findings.append(
                    RawFinding(
                        severity=Severity.MEDIUM,
                        title="TLS certificate expiring soon",
                        description=f"Certificate for {host} expires on {expiry.date()} ({days_left} days).",
                        remediation="Renew the TLS certificate before it expires.",
                        affected_asset=host,
                    )
                )
    except ssl.SSLCertVerificationError as exc:
        findings.append(
            RawFinding(
                severity=Severity.HIGH,
                title="TLS certificate validation failed",
                description=f"Could not validate the TLS certificate for {host}:{port}: {exc}",
                remediation="Ensure the certificate is valid, not expired, and matches the hostname.",
                affected_asset=f"{host}:{port}",
            )
        )
    except Exception as exc:  # noqa: BLE001
        findings.append(
            RawFinding(
                severity=Severity.INFO,
                title="TLS check could not complete",
                description=f"Could not establish a TLS connection to {host}:{port}: {exc}",
                remediation="Verify the host is reachable on the expected HTTPS port.",
                affected_asset=f"{host}:{port}",
            )
        )
    return findings


def _urls_with_query(crawl: CrawlResult) -> list[str]:
    return [p.url for p in crawl.pages if parse_qs(urlparse(p.url).query)]


def _inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = [value]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def check_reflected_xss(crawl: CrawlResult) -> list[RawFinding]:
    findings: list[RawFinding] = []
    urls = _urls_with_query(crawl)
    if not urls:
        return findings

    with httpx.Client(timeout=10, headers={"User-Agent": "DefensivePentestScanner/1.0"}) as client:
        for url in urls:
            params = parse_qs(urlparse(url).query)
            for param in params:
                marker = f"psxss{secrets.token_hex(4)}"
                payload = f"<{marker}>"
                test_url = _inject_param(url, param, payload)
                try:
                    resp = client.get(test_url)
                except httpx.HTTPError:
                    continue
                if payload in resp.text:
                    findings.append(
                        RawFinding(
                            severity=Severity.HIGH,
                            title=f"Possible reflected XSS via '{param}' parameter",
                            description=(
                                f"Injecting an inert marker into the '{param}' parameter at {url} was reflected "
                                "back unescaped in the response, indicating the value is not HTML-encoded on output."
                            ),
                            remediation=(
                                "HTML-encode all user-controlled output, and/or apply a Content-Security-Policy "
                                "restricting inline script execution."
                            ),
                            affected_asset=test_url,
                            evidence=payload,
                        )
                    )
    return findings


def check_sqli_indicators(crawl: CrawlResult) -> list[RawFinding]:
    findings: list[RawFinding] = []
    urls = _urls_with_query(crawl)
    if not urls:
        return findings

    with httpx.Client(timeout=10, headers={"User-Agent": "DefensivePentestScanner/1.0"}) as client:
        for url in urls:
            params = parse_qs(urlparse(url).query)
            try:
                baseline = client.get(url)
            except httpx.HTTPError:
                continue
            baseline_hits = {sig.pattern for sig in _SQLI_SIGNATURES if sig.search(baseline.text)}

            for param, values in params.items():
                original = values[0] if values else ""
                test_url = _inject_param(url, param, original + "'")
                try:
                    resp = client.get(test_url)
                except httpx.HTTPError:
                    continue

                for sig in _SQLI_SIGNATURES:
                    if sig.search(resp.text) and sig.pattern not in baseline_hits:
                        findings.append(
                            RawFinding(
                                severity=Severity.CRITICAL,
                                title=f"Possible SQL injection via '{param}' parameter",
                                description=(
                                    f"Appending a single quote to the '{param}' parameter at {url} produced a "
                                    "database error message that was not present in the baseline response, "
                                    "suggesting unsanitized input reaches a SQL query."
                                ),
                                remediation="Use parameterized queries/prepared statements for all database access.",
                                affected_asset=test_url,
                                evidence=sig.pattern,
                            )
                        )
                        break
    return findings


def check_csrf(crawl: CrawlResult) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for page in crawl.pages:
        for form in page.forms:
            if form.method != "post":
                continue
            has_token = any(_CSRF_TOKEN_NAME_HINTS.search(name) for name in form.input_names)
            if not has_token:
                findings.append(
                    RawFinding(
                        severity=Severity.MEDIUM,
                        title="POST form without an apparent CSRF token",
                        description=(
                            f"The form submitting to {form.action} on {page.url} has no input field matching "
                            "common CSRF token naming patterns."
                        ),
                        remediation=(
                            "Add a per-session CSRF token to this form (or confirm the framework's CSRF "
                            "protection covers it) and verify it server-side on submit."
                        ),
                        affected_asset=form.action,
                    )
                )
    return findings


def run_all_checks(crawl: CrawlResult, base_url: str) -> list[RawFinding]:
    findings: list[RawFinding] = []
    findings += check_security_headers(crawl)
    findings += check_exposed_files(base_url)
    findings += check_tls(base_url)
    findings += check_reflected_xss(crawl)
    findings += check_sqli_indicators(crawl)
    findings += check_csrf(crawl)
    return findings
