"""Tier 1 (self-owned) ownership verification.

Domains: the operator publishes a DNS TXT record or a well-known file
containing a token the app generated, mirroring how Let's Encrypt / Google
Search Console verify domain ownership. IP/internal hosts: self-attestation
only, since these are typically the operator's own infrastructure — but it's
still logged with a timestamp so there's a record of the claim.
"""

import ipaddress

import dns.resolver
import httpx

VERIFICATION_TXT_PREFIX = "pentest-scanner-verify="


def is_ip_or_range(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def check_dns_txt(domain: str, token: str) -> tuple[bool, str]:
    record_name = f"_pentest-verify.{domain}"
    expected = f"{VERIFICATION_TXT_PREFIX}{token}"
    try:
        answers = dns.resolver.resolve(record_name, "TXT", lifetime=10)
    except Exception as exc:  # noqa: BLE001 - surface any resolver error as a failed check
        return False, f"DNS lookup for {record_name} failed: {exc}"

    for rdata in answers:
        raw = b"".join(rdata.strings).decode("utf-8", errors="ignore") if hasattr(rdata, "strings") else str(rdata)
        if raw.strip('"') == expected:
            return True, f"Found matching TXT record at {record_name}."
    return False, f"No matching TXT record found at {record_name}."


def check_well_known_file(domain: str, token: str) -> tuple[bool, str]:
    url = f"https://{domain}/.well-known/pentest-scanner-verification.txt"
    try:
        resp = httpx.get(url, timeout=10, follow_redirects=True)
    except Exception as exc:  # noqa: BLE001
        return False, f"Could not fetch {url}: {exc}"

    if resp.status_code != 200:
        return False, f"{url} returned HTTP {resp.status_code}."
    if resp.text.strip() == token:
        return True, f"Verification file at {url} matched the expected token."
    return False, f"Verification file at {url} did not match the expected token."
