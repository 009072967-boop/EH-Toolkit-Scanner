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
- NSE scripts are limited to nmap's "safe" category (scripts nmap's authors
  classify as unlikely to crash services, use large bandwidth, or exploit
  anything), plus a short allow-list of named safe checks. Aggressive intensity
  adds "vuln and safe" -- still never intrusive, brute-force, DoS, or exploit.
- A per-scan host timeout is always passed to nmap so a single scan can't run
  forever even if the orchestrator's own timeout didn't fire first.

Findings are built by `analyze_host`, a pure function over python-nmap's parsed
host data, so the interpretation logic is unit-testable without running nmap.
"""

from __future__ import annotations

import ctypes
import ipaddress
import os
import re
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import nmap

from app.models import Severity
from app.scanning.common import RawFinding, ScanEngineError
from app.scanning.cve_lookup import CveLookupResult, nmap_cpe_to_match_string

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

# Named safe scripts run in addition to the "default and safe" set: each answers a specific
# configuration question (SMB versions/signing, RDP NLA, SSH algorithms, HTTP headers) without
# authenticating, brute-forcing, or sending anything beyond normal protocol negotiation.
_EXTRA_SAFE_SCRIPTS = (
    "smb-protocols",
    "smb2-security-mode",
    "smb-security-mode",
    "rdp-enum-encryption",
    "ssh2-enum-algos",
    "http-security-headers",
)
_STANDARD_SCRIPTS = "(default and safe) or " + " or ".join(_EXTRA_SAFE_SCRIPTS)
_AGGRESSIVE_SCRIPTS = f"({_STANDARD_SCRIPTS}) or (vuln and safe)"

# service -> (severity, why it matters when reachable at all, remediation)
_RESTRICT = (
    "Confirm this service needs to be reachable at all. If not, firewall it off or bind it to "
    "localhost/a private interface. If it must be reachable, require strong authentication and, "
    "where possible, place it behind a VPN."
)
_RISKY_SERVICES: dict[str, tuple[Severity, str, str]] = {
    "telnet": (Severity.HIGH, "Telnet transmits credentials and data in cleartext.",
               "Disable Telnet and use SSH instead."),
    "rlogin": (Severity.HIGH, "rlogin is an unauthenticated/cleartext legacy remote-access protocol.",
               "Disable rlogin and use SSH instead."),
    "rsh": (Severity.HIGH, "rsh is a cleartext legacy remote shell with host-based trust.",
            "Disable rsh and use SSH instead."),
    "exec": (Severity.HIGH, "rexec sends credentials in cleartext.", "Disable rexec and use SSH instead."),
    "ftp": (Severity.MEDIUM, "Unencrypted FTP transmits credentials in cleartext.",
            "Replace with SFTP/FTPS, or restrict access to trusted hosts."),
    "tftp": (Severity.MEDIUM, "TFTP has no authentication at all.", _RESTRICT),
    "ms-wbt-server": (Severity.MEDIUM, "RDP exposed to the network is a common ransomware entry point.",
                      "Restrict RDP to a VPN or trusted IPs, require NLA, and enforce strong passwords/MFA."),
    "microsoft-ds": (Severity.MEDIUM, "SMB exposed to the network is a common lateral-movement target.",
                     "Block TCP 445 at the network edge; allow it only between hosts that need file sharing."),
    "netbios-ssn": (Severity.LOW, "NetBIOS session service exposes legacy Windows file-sharing.",
                    "Disable NetBIOS over TCP/IP if SMB over 445 is all that's needed."),
    "vnc": (Severity.HIGH, "VNC exposed to the network is a common remote-takeover target.", _RESTRICT),
    "x11": (Severity.HIGH, "An exposed X11 server can let remote clients capture input and screens.", _RESTRICT),
    "redis": (Severity.HIGH, "Redis exposed without authentication allows full data access/RCE in some configs.",
              "Bind Redis to localhost, enable `requirepass`/ACLs, and firewall the port."),
    "mongodb": (Severity.HIGH, "MongoDB exposed to the network may allow unauthenticated data access.",
                "Enable authentication, bind to localhost/private interfaces, and firewall the port."),
    "elasticsearch": (Severity.HIGH, "Elasticsearch exposed to the network may allow unauthenticated data access.",
                      "Enable security features (authentication/TLS) and firewall the port."),
    "memcached": (Severity.HIGH, "Exposed memcached allows data access and has been abused for DDoS amplification.",
                  "Bind memcached to localhost and disable UDP."),
    "docker": (Severity.CRITICAL, "An exposed Docker API gives full control of the host to anyone who can reach it.",
               "Never expose the Docker socket over TCP without mutual TLS; bind it to a Unix socket instead."),
    "mysql": (Severity.MEDIUM, "Database servers reachable from the network invite credential attacks.", _RESTRICT),
    "postgresql": (Severity.MEDIUM, "Database servers reachable from the network invite credential attacks.", _RESTRICT),
    "ms-sql-s": (Severity.MEDIUM, "Database servers reachable from the network invite credential attacks.", _RESTRICT),
    "oracle-tns": (Severity.MEDIUM, "Database servers reachable from the network invite credential attacks.", _RESTRICT),
    "ldap": (Severity.MEDIUM, "Cleartext LDAP can leak directory data and credentials.",
             "Require LDAPS/StartTLS and restrict anonymous binds."),
    "snmp": (Severity.MEDIUM, "SNMP (especially v1/v2c) often leaks device configuration via guessable community strings.",
             "Use SNMPv3 with authentication, or disable SNMP."),
    "rpcbind": (Severity.LOW, "rpcbind reveals which RPC services (e.g. NFS) are running.", _RESTRICT),
    "nfs": (Severity.MEDIUM, "Exposed NFS shares may be mountable by untrusted hosts.",
            "Restrict exports to specific trusted hosts and firewall NFS."),
    "upnp": (Severity.LOW, "UPnP can let devices open firewall ports without your knowledge.",
             "Disable UPnP on routers and devices that don't need it."),
    "wsman": (Severity.LOW, "WinRM (remote PowerShell) is reachable over cleartext HTTP.",
              "Use WinRM over HTTPS (5986) only, restricted to administrators' networks."),
}
# When nmap can't name a service (common for unprivileged scans), fall back on the well-known port.
_PORT_HINTS = {
    23: "telnet", 21: "ftp", 69: "tftp", 445: "microsoft-ds", 139: "netbios-ssn", 3389: "ms-wbt-server",
    5900: "vnc", 6000: "x11", 6379: "redis", 27017: "mongodb", 9200: "elasticsearch", 11211: "memcached",
    2375: "docker", 3306: "mysql", 5432: "postgresql", 1433: "ms-sql-s", 1521: "oracle-tns", 389: "ldap",
    111: "rpcbind", 2049: "nfs", 5985: "wsman", 512: "exec", 513: "rlogin", 514: "rsh",
}

_WEAK_SSH_ALGORITHMS = (
    "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1", "ssh-dss", "arcfour",
    "3des-cbc", "blowfish-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "hmac-md5", "hmac-sha1-96",
)
_DYNAMIC_RPC_START = 49152  # Windows' dynamic RPC range is 49152-65535


def validate_target_value(value: str) -> None:
    try:
        ipaddress.ip_network(value, strict=False)
        return
    except ValueError:
        pass
    if _HOSTNAME_RE.match(value):
        return
    raise ScanEngineError(f"'{value}' is not a valid IP, CIDR range, or hostname for a network scan.")


def is_privileged() -> bool:
    """OS fingerprinting (-O) needs raw sockets: root on Linux/macOS, Administrator on Windows."""
    try:
        if os.name == "nt":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:  # noqa: BLE001
        return False


def build_nmap_args(intensity: str, timeout_seconds: int, privileged: bool) -> str:
    if intensity == "aggressive":
        base = "-T4 -p-"
        scripts = _AGGRESSIVE_SCRIPTS
    else:
        base = "-T3 --top-ports 1000"
        scripts = _STANDARD_SCRIPTS
    os_detection = " -O --osscan-limit" if privileged else ""
    return (
        f'{base} -sV{os_detection} --script "{scripts}" --script-timeout 60s '
        f"--host-timeout {timeout_seconds}s"
    )


def run_network_scan(
    target_value: str,
    intensity: str = "standard",
    timeout_seconds: int = 900,
    cve_lookup: Callable[[str], CveLookupResult] | None = None,
    max_cve_lookups: int = 10,
) -> list[RawFinding]:
    validate_target_value(target_value)
    privileged = is_privileged()
    args = build_nmap_args(intensity, timeout_seconds, privileged)

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
    if not privileged:
        findings.append(
            RawFinding(
                severity=Severity.INFO,
                title="OS detection skipped (scanner not running with admin/root rights)",
                description=(
                    "nmap needs raw-socket access for OS fingerprinting and SYN scanning. This scan used "
                    "a TCP connect scan and identified the OS only where services revealed it."
                ),
                remediation="To include OS detection, run the scanner as Administrator (Windows) or root.",
                affected_asset=target_value,
            )
        )
    lookups_left = [max_cve_lookups]
    for host in scanner.all_hosts():
        findings.extend(analyze_host(host, scanner[host], cve_lookup=cve_lookup, lookups_left=lookups_left))
    return findings


def analyze_host(
    host: str,
    host_data: dict,
    *,
    cve_lookup: Callable[[str], CveLookupResult] | None = None,
    lookups_left: list[int] | None = None,
    now: datetime | None = None,
) -> list[RawFinding]:
    """Turns one host's parsed nmap results into findings. `host_data` is python-nmap's
    per-host dict (or an equivalent plain dict in tests)."""
    now = now or datetime.now(timezone.utc)
    lookups_left = lookups_left if lookups_left is not None else [10]
    findings: list[RawFinding] = [_host_summary(host, host_data)]

    dynamic_rpc: list[int] = []
    cpes: dict[str, tuple[str, str]] = {}  # cpe -> (service label, first asset)

    for proto in ("tcp", "udp"):
        for port, port_data in sorted((host_data.get(proto) or {}).items()):
            if port_data.get("state") != "open":
                continue
            asset = f"{host}:{port}/{proto}"
            service = (port_data.get("name") or "").strip()
            label = _service_label(port_data)
            scripts = port_data.get("script") or {}

            if port >= _DYNAMIC_RPC_START and service in ("msrpc", "unknown", "") and not scripts:
                dynamic_rpc.append(port)
                continue

            findings.append(_port_finding(port, proto, asset, service, label, scripts))
            findings.extend(_script_findings(asset, scripts, now))

            for cpe in (port_data.get("cpe") or "").split():
                if nmap_cpe_to_match_string(cpe) and cpe not in cpes:
                    cpes[cpe] = (label or service, asset)

    if dynamic_rpc:
        findings.append(
            RawFinding(
                severity=Severity.INFO,
                title=f"Windows dynamic RPC ports open ({len(dynamic_rpc)})",
                description=(
                    f"{len(dynamic_rpc)} ports in Windows' dynamic RPC range (49152-65535) are open: "
                    f"{', '.join(map(str, dynamic_rpc))}. These are normal on Windows hosts and are used "
                    "by RPC services the endpoint mapper (port 135) hands out."
                ),
                remediation=(
                    "Normal on a Windows machine. They should not be reachable from untrusted networks -- "
                    "block 135 and 49152-65535 at the network edge and in Windows Firewall's public profile."
                ),
                affected_asset=f"{host}:{dynamic_rpc[0]}-{dynamic_rpc[-1]}/tcp",
            )
        )

    findings.extend(_host_script_findings(host, host_data.get("hostscript") or [], now))

    if cve_lookup is not None:
        for cpe, (label, asset) in cpes.items():
            if lookups_left[0] <= 0:
                findings.append(
                    RawFinding(
                        severity=Severity.INFO,
                        title=f"Known-CVE lookup skipped for {label}",
                        description="The per-scan CVE lookup limit was reached before this service was checked.",
                        remediation="Raise MAX_CVE_LOOKUPS_PER_SCAN or re-scan just this host.",
                        affected_asset=asset,
                        evidence=cpe,
                    )
                )
                continue
            lookups_left[0] -= 1
            finding = _cve_finding(label, asset, cve_lookup(cpe))
            if finding:
                findings.append(finding)
    return findings


def _service_label(port_data: dict) -> str:
    parts = [port_data.get("product"), port_data.get("version"), port_data.get("extrainfo")]
    return " ".join(p for p in parts if p).strip()


def _host_summary(host: str, host_data: dict) -> RawFinding:
    state = (host_data.get("status") or {}).get("state", "unknown")
    details: list[str] = []
    hostnames = [h.get("name") for h in host_data.get("hostnames") or [] if h.get("name")]
    if hostnames:
        details.append(f"hostname: {', '.join(hostnames)}")
    vendor = host_data.get("vendor") or {}
    if vendor:
        details.append("hardware vendor: " + ", ".join(f"{v} ({mac})" for mac, v in vendor.items()))
    os_matches = host_data.get("osmatch") or []
    if os_matches:
        best = os_matches[0]
        details.append(f"OS guess: {best.get('name')} ({best.get('accuracy')}% confidence)")
    return RawFinding(
        severity=Severity.INFO,
        title=f"Host {host} is {state}" + (f" — {os_matches[0].get('name')}" if os_matches else ""),
        description=f"Host discovery reported {host} as {state}." + (" " + "; ".join(details) + "." if details else ""),
        remediation="No action needed unless this host is not expected to be reachable.",
        affected_asset=host,
    )


def _port_finding(port: int, proto: str, asset: str, service: str, label: str, scripts: dict) -> RawFinding:
    shown = service if service and service != "unknown" else "unidentified service"
    risky_key = service if service in _RISKY_SERVICES else None
    if risky_key is None and (service in ("", "unknown") or service.endswith("?")):
        hint = _PORT_HINTS.get(port)
        risky_key = hint if hint in _RISKY_SERVICES else None
    script_evidence = "\n".join(f"[{sid}] {out.strip()}" for sid, out in scripts.items()) or None
    evidence = "\n".join(p for p in (label, script_evidence) if p) or None

    if risky_key:
        severity, why, remediation = _RISKY_SERVICES[risky_key]
        return RawFinding(
            severity=severity,
            title=f"Risky service exposed: {risky_key} on {port}/{proto}" + (f" ({label})" if label else ""),
            description=f"{asset} is open and running {risky_key}{f' ({label})' if label else ''}. {why}",
            remediation=remediation,
            affected_asset=asset,
            evidence=evidence,
        )
    return RawFinding(
        severity=Severity.INFO,
        title=f"Open port {port}/{proto}: {shown}" + (f" — {label}" if label else ""),
        description=(
            f"{asset} is open; service identified as {shown}{f' ({label})' if label else ''}."
            + ("" if service and service != "unknown" else
               " nmap could not fingerprint it -- check which local program is listening on this port.")
        ),
        remediation="Confirm this service is intended to be reachable from this network context.",
        affected_asset=asset,
        evidence=evidence,
    )


def _script_findings(asset: str, scripts: dict[str, str], now: datetime) -> list[RawFinding]:
    out: list[RawFinding] = []

    def add(severity, title, description, remediation, evidence):
        out.append(RawFinding(severity=severity, title=title, description=description,
                              remediation=remediation, affected_asset=asset, evidence=evidence.strip()))

    methods = scripts.get("http-methods", "")
    risky = re.search(r"Potentially risky methods:\s*(.+)", methods)
    if risky:
        verbs = risky.group(1).split()
        severity = Severity.MEDIUM if {"PUT", "DELETE"} & set(verbs) else Severity.LOW
        add(severity, f"Risky HTTP methods enabled: {', '.join(verbs)}",
            "The web server accepts HTTP methods that are rarely needed. TRACE enables cross-site tracing; "
            "PUT/DELETE can allow file upload or deletion if not properly restricted.",
            "Disable unused HTTP methods in the web server configuration (e.g. `TraceEnable off` in Apache).",
            methods)

    if "http-security-headers" in scripts or "http-headers" in scripts:
        seen = (scripts.get("http-security-headers", "") + scripts.get("http-headers", "")).lower()
        wanted = {
            "Content-Security-Policy": "content-security-policy",
            "X-Frame-Options (or CSP frame-ancestors)": "x-frame-options",
            "X-Content-Type-Options": "x-content-type-options",
        }
        if "ssl-cert" in scripts:
            wanted["Strict-Transport-Security"] = "strict-transport-security"
        missing = [name for name, needle in wanted.items()
                   if needle not in seen and not (needle == "x-frame-options" and "frame-ancestors" in seen)]
        if missing:
            add(Severity.LOW, f"Missing HTTP security headers: {', '.join(missing)}",
                "These response headers protect browsers against clickjacking, MIME sniffing, and content "
                "injection. Their absence isn't a vulnerability on its own, but removes a layer of defense.",
                "Add the missing headers in the web server or application configuration.",
                scripts.get("http-security-headers") or scripts.get("http-headers", ""))

    cors = scripts.get("http-cors", "")
    if cors.strip():
        add(Severity.LOW, "CORS allows cross-origin requests from any origin",
            "The server answered a cross-origin preflight for an arbitrary origin, allowing these methods: "
            f"{cors.strip()}. If any endpoint returns user data, other websites may be able to read it.",
            "Restrict Access-Control-Allow-Origin to the specific origins that need access.", cors)

    if "Proxy might be redirecting requests" in scripts.get("http-open-proxy", "") or re.search(
        r"open proxy", scripts.get("http-open-proxy", ""), re.IGNORECASE
    ):
        add(Severity.MEDIUM, "Possible open HTTP proxy",
            "nmap's http-open-proxy check suggests this server may relay requests to other sites. Open "
            "proxies are abused to hide attack traffic. This check can produce false positives -- verify manually.",
            "If the server isn't meant to be a proxy, disable proxy modules (e.g. mod_proxy) or require auth.",
            scripts["http-open-proxy"])

    if re.search(r"Anonymous FTP login allowed", scripts.get("ftp-anon", ""), re.IGNORECASE):
        add(Severity.HIGH, "Anonymous FTP login allowed",
            "Anyone can log in to this FTP server without credentials.",
            "Disable anonymous FTP unless the server is intentionally a public file mirror.", scripts["ftp-anon"])

    if "sshv1" in scripts and "supports SSHv1" in scripts["sshv1"]:
        add(Severity.HIGH, "SSH protocol version 1 supported",
            "SSHv1 has fundamental cryptographic weaknesses and should never be enabled.",
            "Set `Protocol 2` (OpenSSH) and restart the SSH service.", scripts["sshv1"])

    algos = scripts.get("ssh2-enum-algos", "")
    weak = sorted({a for a in _WEAK_SSH_ALGORITHMS if re.search(rf"(?m)^\s*{re.escape(a)}\s*$", algos)})
    if weak:
        add(Severity.LOW, f"Weak SSH algorithms offered: {', '.join(weak)}",
            "The SSH server still offers legacy key-exchange, cipher, or MAC algorithms that modern guidance "
            "deprecates.", "Remove these from the server's KexAlgorithms/Ciphers/MACs configuration.", algos)

    cert = scripts.get("ssl-cert", "")
    expiry = re.search(r"Not valid after:\s*(\d{4}-\d{2}-\d{2})(?:T(\d{2}:\d{2}:\d{2}))?", cert)
    if expiry:
        not_after = datetime.fromisoformat(f"{expiry.group(1)}T{expiry.group(2) or '00:00:00'}+00:00")
        if not_after < now:
            add(Severity.MEDIUM, f"TLS certificate expired on {expiry.group(1)}",
                "Clients will show security warnings, and users trained to click through them are easier to "
                "intercept.", "Renew the certificate (e.g. with Let's Encrypt) and enable automatic renewal.", cert)
        elif not_after - now < timedelta(days=30):
            add(Severity.LOW, f"TLS certificate expires soon ({expiry.group(1)})",
                "The certificate expires within 30 days.", "Renew the certificate before it expires.", cert)
    if re.search(r"commonName=[^/\n]*(TEMP|REPLACE|localhost|example)", cert, re.IGNORECASE):
        add(Severity.LOW, "TLS certificate looks like a placeholder/default certificate",
            "The certificate's subject suggests a vendor default or temporary certificate rather than one issued "
            "for this host, so clients can't meaningfully verify the server's identity.",
            "Replace it with a certificate issued for this host's real name.", cert)

    for sid, output in scripts.items():
        if output and re.search(r"State:\s*(LIKELY\s+)?VULNERABLE", output):
            add(Severity.HIGH, f"nmap vulnerability check flagged this service ({sid})",
                "One of nmap's non-intrusive vulnerability checks reports this service as vulnerable. "
                "See the evidence for the specific issue and references.",
                "Apply the vendor patch or mitigation referenced in the evidence, then re-scan.", output)
    return out


def _host_script_findings(host: str, host_scripts: list[dict], now: datetime) -> list[RawFinding]:
    scripts = {s.get("id"): s.get("output", "") for s in host_scripts}
    out: list[RawFinding] = []
    asset = f"{host}:445/tcp"

    protocols = scripts.get("smb-protocols", "")
    if re.search(r"NT LM 0\.12|SMBv1", protocols):
        out.append(RawFinding(
            severity=Severity.HIGH, title="SMBv1 is enabled",
            description="SMB version 1 is obsolete and was the vector for WannaCry/NotPetya (EternalBlue).",
            remediation="Disable SMBv1 (Windows: `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`).",
            affected_asset=asset, evidence=protocols.strip()))

    signing = scripts.get("smb2-security-mode", "")
    if re.search(r"enabled but not required", signing, re.IGNORECASE):
        out.append(RawFinding(
            severity=Severity.MEDIUM, title="SMB signing not required",
            description="Without mandatory signing, SMB traffic can be relayed or tampered with (NTLM relay attacks).",
            remediation="Require SMB signing (Group Policy: 'Microsoft network server: Digitally sign communications (always)').",
            affected_asset=asset, evidence=signing.strip()))

    legacy = scripts.get("smb-security-mode", "")
    if re.search(r"message_signing:\s*disabled", legacy):
        out.append(RawFinding(
            severity=Severity.HIGH, title="SMB message signing disabled",
            description="The server does not support SMB signing at all, leaving sessions open to relay/tampering.",
            remediation="Enable and require SMB signing.", affected_asset=asset, evidence=legacy.strip()))
    if re.search(r"account_used:\s*guest", legacy):
        out.append(RawFinding(
            severity=Severity.MEDIUM, title="SMB allows guest access",
            description="The SMB server accepted a guest session, which may expose shares without credentials.",
            remediation="Disable guest access to SMB shares.", affected_asset=asset, evidence=legacy.strip()))

    rdp = scripts.get("rdp-enum-encryption", "")
    if re.search(r"(Native RDP|RDSTLS|SSL):\s*SUCCESS", rdp):
        out.append(RawFinding(
            severity=Severity.MEDIUM, title="RDP accepts connections without Network Level Authentication",
            description="Without NLA, the login screen is reachable before authentication, exposing it to "
                        "pre-auth vulnerabilities (e.g. BlueKeep) and resource exhaustion.",
            remediation="Require NLA (System Properties > Remote > 'Allow connections only from computers running "
                        "Remote Desktop with Network Level Authentication').",
            affected_asset=f"{host}:3389/tcp", evidence=rdp.strip()))

    os_info = scripts.get("smb-os-discovery", "")
    if os_info.strip():
        out.append(RawFinding(
            severity=Severity.INFO, title="Operating system details disclosed over SMB",
            description="The SMB service reveals OS version, computer name, and domain details to unauthenticated clients.",
            remediation="Expected on internal networks; ensure SMB is not reachable from untrusted networks.",
            affected_asset=asset, evidence=os_info.strip()))
    return out


def _cve_finding(label: str, asset: str, result: CveLookupResult) -> RawFinding | None:
    if result.error:
        return RawFinding(
            severity=Severity.INFO, title=f"Known-CVE lookup unavailable for {label}",
            description=f"Could not check {label} against the NVD database: {result.error}.",
            remediation="Re-run the scan later, or check the version manually at https://nvd.nist.gov/.",
            affected_asset=asset, evidence=result.cpe)
    if not result.cves:
        return None

    exploited = [c for c in result.cves if c.known_exploited]
    by_severity: dict[str, int] = {}
    for cve in result.cves:
        by_severity[cve.severity or "UNSCORED"] = by_severity.get(cve.severity or "UNSCORED", 0) + 1
    worst = min((_NVD_SEVERITY.get(c.severity or "", Severity.INFO) for c in result.cves),
                key=lambda s: list(Severity).index(s))
    if exploited:
        worst = Severity.CRITICAL
    counts = ", ".join(f"{n} {sev.lower()}" for sev, n in sorted(
        by_severity.items(), key=lambda kv: list(_NVD_SEVERITY).index(kv[0]) if kv[0] in _NVD_SEVERITY else 99))
    top = result.cves[:10]
    lines = [
        f"{c.cve_id} (CVSS {c.score if c.score is not None else 'n/a'}"
        f"{', ACTIVELY EXPLOITED - CISA KEV' if c.known_exploited else ''}): {c.summary[:180]}"
        for c in top
    ]
    return RawFinding(
        severity=worst,
        title=f"{label}: {result.total} known CVEs"
              + (f" ({len(exploited)} actively exploited)" if exploited else f" ({counts})"),
        description=(
            f"NVD lists {result.total} CVEs affecting {label} ({counts})."
            + (f" {len(exploited)} are in CISA's Known Exploited Vulnerabilities catalog, meaning attackers "
               "are using them in the wild." if exploited else "")
            + " Version-based matching: confirm the vendor hasn't backported fixes (common in Linux distro packages)."
        ),
        remediation=f"Upgrade {label} to the latest supported release. Highest-priority CVEs: "
                    + ", ".join(c.cve_id for c in top[:5]) + ".",
        affected_asset=asset,
        evidence="\n".join(lines) + (f"\n... and {result.total - len(top)} more" if result.total > len(top) else ""),
    )


_NVD_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}
