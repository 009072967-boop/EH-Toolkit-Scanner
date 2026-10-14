"""Dependency / CVE scan engine, backed by the OSV.dev API (osv.dev — free,
no API key required). Accepts a manifest file's contents, parses it into
(name, version, ecosystem) tuples, batch-queries OSV for known
vulnerabilities, then fetches full details for each hit to get severity and
the fixed version.
"""

import re

import httpx

from app.models import Severity
from app.scanning.common import RawFinding, ScanEngineError

OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"

SUPPORTED_MANIFESTS = {
    "package.json": "npm",
    "requirements.txt": "PyPI",
    "go.mod": "Go",
}


def detect_ecosystem(filename: str) -> str:
    lower = filename.lower()
    for name, ecosystem in SUPPORTED_MANIFESTS.items():
        if lower.endswith(name):
            return ecosystem
    raise ScanEngineError(
        f"Unsupported manifest '{filename}'. Supported: {', '.join(SUPPORTED_MANIFESTS)}"
    )


def _parse_package_json(content: str) -> list[tuple[str, str]]:
    import json

    data = json.loads(content)
    packages: dict[str, str] = {}
    for section in ("dependencies", "devDependencies"):
        packages.update(data.get(section, {}) or {})

    results = []
    for name, version_spec in packages.items():
        version = re.sub(r"^[\^~>=<\s]+", "", version_spec).strip()
        if version and version[0].isdigit():
            results.append((name, version))
    return results


def _parse_requirements_txt(content: str) -> list[tuple[str, str]]:
    results = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*==\s*([A-Za-z0-9_.\-]+)", line)
        if match:
            name = re.sub(r"\[.*\]", "", match.group(1))
            results.append((name, match.group(2)))
    return results


def _parse_go_mod(content: str) -> list[tuple[str, str]]:
    results = []
    in_require_block = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require_block = True
            continue
        if in_require_block and stripped == ")":
            in_require_block = False
            continue

        candidate = None
        if in_require_block:
            candidate = stripped
        elif stripped.startswith("require "):
            candidate = stripped[len("require "):].strip()

        if candidate:
            parts = candidate.split()
            if len(parts) >= 2:
                results.append((parts[0], parts[1]))
    return results


def parse_manifest(filename: str, content: str) -> tuple[str, list[tuple[str, str]]]:
    ecosystem = detect_ecosystem(filename)
    if ecosystem == "npm":
        packages = _parse_package_json(content)
    elif ecosystem == "PyPI":
        packages = _parse_requirements_txt(content)
    elif ecosystem == "Go":
        packages = _parse_go_mod(content)
    else:  # pragma: no cover - guarded by detect_ecosystem
        raise ScanEngineError(f"No parser for ecosystem {ecosystem}")

    if not packages:
        raise ScanEngineError(
            "No pinned package versions could be parsed from this manifest. "
            "Dependency scanning requires exact/locked versions (e.g. name==1.2.3)."
        )
    return ecosystem, packages


def _severity_from_osv(vuln: dict) -> Severity:
    db_severity = str(vuln.get("database_specific", {}).get("severity", "")).upper()
    if db_severity in ("CRITICAL",):
        return Severity.CRITICAL
    if db_severity in ("HIGH",):
        return Severity.HIGH
    if db_severity in ("MODERATE", "MEDIUM"):
        return Severity.MEDIUM
    if db_severity in ("LOW",):
        return Severity.LOW

    for entry in vuln.get("severity", []) or []:
        score = entry.get("score", "")
        cvss_match = re.search(r"(\d+(\.\d+)?)$", score) if isinstance(score, str) else None
        try:
            value = float(cvss_match.group(1)) if cvss_match else float(score)
        except (TypeError, ValueError):
            continue
        if value >= 9.0:
            return Severity.CRITICAL
        if value >= 7.0:
            return Severity.HIGH
        if value >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW

    return Severity.MEDIUM


def _fixed_version(vuln: dict, ecosystem: str) -> str | None:
    for affected in vuln.get("affected", []) or []:
        if affected.get("package", {}).get("ecosystem") != ecosystem:
            continue
        for rng in affected.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                if "fixed" in event:
                    return event["fixed"]
    return None


def run_dependency_scan(filename: str, content: str, timeout_seconds: int = 120) -> list[RawFinding]:
    ecosystem, packages = parse_manifest(filename, content)

    queries = [
        {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        for name, version in packages
    ]

    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            batch_resp = client.post(OSV_QUERY_BATCH_URL, json={"queries": queries})
            batch_resp.raise_for_status()
            batch_results = batch_resp.json().get("results", [])

            findings: list[RawFinding] = []
            for (name, version), result in zip(packages, batch_results):
                vuln_ids = [v["id"] for v in result.get("vulns", []) or []]
                for vuln_id in vuln_ids:
                    detail_resp = client.get(OSV_VULN_URL.format(id=vuln_id))
                    if detail_resp.status_code != 200:
                        continue
                    vuln = detail_resp.json()
                    summary = vuln.get("summary") or (vuln.get("details", "")[:300] if vuln.get("details") else "")
                    fixed = _fixed_version(vuln, ecosystem)
                    findings.append(
                        RawFinding(
                            severity=_severity_from_osv(vuln),
                            title=f"{name}@{version}: {vuln_id}",
                            description=summary or f"{vuln_id} affects {name}@{version} ({ecosystem}).",
                            remediation=(
                                f"Upgrade {name} to {fixed} or later." if fixed
                                else f"No fixed version published yet for {vuln_id} — track upstream for a patch."
                            ),
                            affected_asset=f"{name}@{version}",
                            evidence=f"https://osv.dev/vulnerability/{vuln_id}",
                        )
                    )
    except httpx.HTTPError as exc:
        raise ScanEngineError(f"OSV.dev request failed: {exc}") from exc

    return findings
