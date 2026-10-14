"""Network / port scan engine, backed by the nmap binary via python-nmap.

Safety notes:
- Target values are strictly validated before being handed to nmap. python-nmap
  invokes the binary without a shell (no shell=True), but an unvalidated target
  string could still start with "-" and be interpreted as an nmap flag
  (argument injection), so we require the value to be a clean IP/CIDR or
  hostname before it ever reaches the subprocess call.
- Standard intensity uses conservative timing (-T3) and the top 1000 ports.
  Aggressive intensity (full port range, faster timing) is only used when a
  scan is explicitly launched with intensity="aggressive".
- A per-scan host timeout is always passed to nmap so a single scan can't run
  forever even if the orchestrator's own timeout didn't fire first.
"""

import ipaddress
import re

import nmap

from app.scanning.common import RawFinding, ScanEngineError
from app.models import Severity

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

# service -> (severity, why it matters when reachable at all)
_RISKY_SERVICES = {
    "telnet": (Severity.HIGH, "Telnet transmits credentials and data in cleartext."),
    "ftp": (Severity.MEDIUM, "Unencrypted FTP transmits credentials in cleartext."),
    "rlogin": (Severity.HIGH, "rlogin is an unauthenticated/cleartext legacy remote-access protocol."),
    "ms-wbt-server": (Severity.MEDIUM, "RDP exposed to the network is a common ransomware entry point."),
    "microsoft-ds": (Severity.MEDIUM, "SMB exposed to the network is a common lateral-movement target."),
    "redis": (Severity.HIGH, "Redis exposed without authentication allows full data access/RCE in some configs."),
    "mongodb": (Severity.HIGH, "MongoDB exposed to the network may allow unauthenticated data access."),
    "elasticsearch": (Severity.HIGH, "Elasticsearch exposed to the network may allow unauthenticated data access."),
    "vnc": (Severity.HIGH, "VNC exposed to the network is a common remote-takeover target."),
}


def validate_target_value(value: str) -> None:
    try:
        ipaddress.ip_network(value, strict=False)
        return
    except ValueError:
        pass
    if _HOSTNAME_RE.match(value):
        return
    raise ScanEngineError(f"'{value}' is not a valid IP, CIDR range, or hostname for a network scan.")


def run_network_scan(target_value: str, intensity: str = "standard", timeout_seconds: int = 900) -> list[RawFinding]:
    validate_target_value(target_value)

    if intensity == "aggressive":
        args = f"-T4 -p- -sV --host-timeout {timeout_seconds}s"
    else:
        args = f"-T3 --top-ports 1000 -sV --host-timeout {timeout_seconds}s"

    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=target_value, arguments=args)
    except nmap.PortScannerError as exc:
        raise ScanEngineError(f"nmap failed: {exc}") from exc
    except Exception as exc:  # noqa: BLE001
        raise ScanEngineError(
            "Could not run nmap. Is the nmap binary installed and on PATH? "
            f"Original error: {exc}"
        ) from exc

    findings: list[RawFinding] = []
    for host in scanner.all_hosts():
        host_data = scanner[host]
        state = host_data.state()
        findings.append(
            RawFinding(
                severity=Severity.INFO,
                title=f"Host {host} is {state}",
                description=f"Host discovery reported {host} as {state} during this scan.",
                remediation="No action needed unless this host is not expected to be reachable.",
                affected_asset=host,
            )
        )
        for proto in host_data.all_protocols():
            for port, port_data in sorted(host_data[proto].items()):
                if port_data.get("state") != "open":
                    continue
                service = port_data.get("name", "unknown")
                product = port_data.get("product", "")
                version = port_data.get("version", "")
                banner = " ".join(p for p in [product, version] if p).strip()
                asset = f"{host}:{port}/{proto}"

                risky = _RISKY_SERVICES.get(service)
                if risky:
                    severity, why = risky
                    findings.append(
                        RawFinding(
                            severity=severity,
                            title=f"Potentially risky service exposed: {service} on port {port}",
                            description=(
                                f"{asset} is open and running {service}"
                                f"{f' ({banner})' if banner else ''}. {why}"
                            ),
                            remediation=(
                                "Confirm this service needs to be reachable at all. If not, firewall it off or "
                                "bind it to a private interface. If it must be reachable, ensure it requires "
                                "strong authentication and, where possible, is placed behind a VPN."
                            ),
                            affected_asset=asset,
                            evidence=banner or None,
                        )
                    )
                else:
                    findings.append(
                        RawFinding(
                            severity=Severity.INFO,
                            title=f"Open port: {port}/{proto} ({service})",
                            description=(
                                f"{asset} is open, service identified as {service}"
                                f"{f' ({banner})' if banner else ''}."
                            ),
                            remediation="Confirm this service is intended to be reachable from this network context.",
                            affected_asset=asset,
                            evidence=banner or None,
                        )
                    )
    return findings
