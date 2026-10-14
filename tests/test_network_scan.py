from datetime import datetime, timezone

import httpx
import pytest

from app.models import SEVERITY_RANK, Severity
from app.scanning import cve_lookup
from app.scanning.cve_lookup import Cve, CveLookupResult, NvdClient, nmap_cpe_to_match_string, rank
from app.scanning.network import analyze_host, build_nmap_args, validate_target_value
from app.scanning.common import ScanEngineError

NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)


def _host(tcp=None, hostscript=None, **extra):
    return {"status": {"state": "up"}, "hostnames": [], "vendor": {}, "tcp": tcp or {},
            "hostscript": hostscript or [], **extra}


def _port(name="", product="", version="", cpe="", script=None, extrainfo=""):
    return {"state": "open", "name": name, "product": product, "version": version, "extrainfo": extrainfo,
            "cpe": cpe, "script": script or {}}


def _titles(findings):
    return [f.title for f in findings]


def test_nmap_args_never_select_intrusive_script_categories():
    for intensity in ("standard", "aggressive"):
        args = build_nmap_args(intensity, 900, privileged=False)
        for forbidden in ("intrusive", "brute", "dos", "exploit", "fuzzer", "malware"):
            assert forbidden not in args
        assert "-O" not in args  # no OS detection without raw-socket rights
    assert "-O" in build_nmap_args("standard", 900, privileged=True)
    assert "(vuln and safe)" in build_nmap_args("aggressive", 900, privileged=False)
    assert "(vuln and safe)" not in build_nmap_args("standard", 900, privileged=False)


def test_target_validation_rejects_argument_injection():
    validate_target_value("192.168.1.21")
    validate_target_value("192.168.1.0/24")
    validate_target_value("scanme.example.org")
    with pytest.raises(ScanEngineError):
        validate_target_value("-iL /etc/passwd")


def test_open_port_titles_include_service_and_version():
    findings = analyze_host("10.0.0.5", _host(tcp={8001: _port("http", "Uvicorn")}), now=NOW)
    assert "Open port 8001/tcp: http — Uvicorn" in _titles(findings)


def test_unidentified_risky_port_uses_well_known_port_hint():
    findings = analyze_host("10.0.0.5", _host(tcp={445: _port("")}), now=NOW)
    smb = next(f for f in findings if "microsoft-ds" in f.title)
    assert smb.severity == Severity.MEDIUM


def test_windows_dynamic_rpc_ports_are_grouped():
    tcp = {p: _port("msrpc" if p % 2 else "") for p in (49664, 49665, 49668, 49669, 49670)}
    tcp[135] = _port("msrpc", "Microsoft Windows RPC")
    findings = analyze_host("10.0.0.5", _host(tcp=tcp), now=NOW)
    grouped = [f for f in findings if "dynamic RPC" in f.title]
    assert len(grouped) == 1 and "(5)" in grouped[0].title
    assert not any(f.title.startswith("Open port 4966") for f in findings)


def test_http_script_checks():
    scripts = {
        "http-methods": "\n  Supported Methods: GET HEAD POST OPTIONS TRACE\n  Potentially risky methods: TRACE",
        "http-security-headers": "\n  Strict_Transport_Security: \n    Header: Strict-Transport-Security: max-age=1",
        "http-cors": "HEAD GET POST PUT DELETE PATCH",
        "ssl-cert": "Subject: commonName=TEMP VENDOR - REPLACE\nNot valid before: 2020-01-01T00:00:00\n"
                    "Not valid after:  2026-01-01T00:00:00",
    }
    findings = analyze_host("10.0.0.5", _host(tcp={8443: _port("https", script=scripts)}), now=NOW)
    titles = _titles(findings)
    assert "Risky HTTP methods enabled: TRACE" in titles
    assert any(t.startswith("Missing HTTP security headers") and "Content-Security-Policy" in t for t in titles)
    assert not any("Strict-Transport-Security" in t for t in titles)  # present, so not reported missing
    assert "CORS allows cross-origin requests from any origin" in titles
    assert "TLS certificate expired on 2026-01-01" in titles
    assert "TLS certificate looks like a placeholder/default certificate" in titles


def test_smb_and_rdp_host_script_checks():
    hostscript = [
        {"id": "smb-protocols", "output": "\n  dialects: \n    NT LM 0.12 (SMBv1) [dangerous, but default]\n    2.1"},
        {"id": "smb2-security-mode", "output": "\n  3.1.1: \n    Message signing enabled but not required"},
        {"id": "rdp-enum-encryption", "output": "\n  Security layer\n    CredSSP (NLA): SUCCESS\n    SSL: SUCCESS"},
    ]
    findings = analyze_host("10.0.0.5", _host(hostscript=hostscript), now=NOW)
    by_title = {f.title: f for f in findings}
    assert by_title["SMBv1 is enabled"].severity == Severity.HIGH
    assert by_title["SMB signing not required"].severity == Severity.MEDIUM
    assert "RDP accepts connections without Network Level Authentication" in by_title


def test_smb_signing_required_is_not_reported():
    hostscript = [{"id": "smb2-security-mode", "output": "\n  3.1.1: \n    Message signing enabled and required"}]
    assert not any("signing" in t for t in _titles(analyze_host("10.0.0.5", _host(hostscript=hostscript), now=NOW)))


def test_nse_vulnerable_state_becomes_high_finding():
    script = {"ssl-heartbleed": "\n  VULNERABLE:\n  The Heartbleed Bug\n    State: VULNERABLE\n    IDs: CVE-2014-0160"}
    findings = analyze_host("10.0.0.5", _host(tcp={443: _port("https", script=script)}), now=NOW)
    assert any(f.severity == Severity.HIGH and "ssl-heartbleed" in f.title for f in findings)


def test_cve_lookup_produces_ranked_finding():
    calls = []

    def fake_lookup(cpe):
        calls.append(cpe)
        return CveLookupResult(cpe=cpe, total=3, cves=rank([
            Cve("CVE-2000-0001", 5.0, "MEDIUM", False, "minor"),
            Cve("CVE-2021-41773", 7.5, "HIGH", True, "path traversal"),
            Cve("CVE-2000-0002", 9.8, "CRITICAL", False, "bad"),
        ]))

    port = _port("http", "Apache httpd", "2.4.49", cpe="cpe:/a:apache:http_server:2.4.49")
    findings = analyze_host("10.0.0.5", _host(tcp={8080: port}), cve_lookup=fake_lookup, now=NOW)
    cve = next(f for f in findings if "known CVEs" in f.title)
    assert calls == ["cpe:/a:apache:http_server:2.4.49"]
    assert cve.severity == Severity.CRITICAL  # actively exploited outranks CVSS
    assert "1 actively exploited" in cve.title
    assert cve.evidence.splitlines()[0].startswith("CVE-2021-41773")  # KEV first, then by score


def test_cve_lookup_respects_per_scan_limit_and_reports_errors():
    tcp = {
        80: _port("http", "Apache httpd", "2.4.49", cpe="cpe:/a:apache:http_server:2.4.49"),
        22: _port("ssh", "OpenSSH", "8.2p1", cpe="cpe:/a:openbsd:openssh:8.2p1"),
    }
    findings = analyze_host(
        "10.0.0.5", _host(tcp=tcp), now=NOW, lookups_left=[1],
        cve_lookup=lambda cpe: CveLookupResult(cpe=cpe, error="NVD rate limit reached"),
    )
    titles = _titles(findings)
    assert sum("Known-CVE lookup unavailable" in t for t in titles) == 1
    assert sum("Known-CVE lookup skipped" in t for t in titles) == 1


def test_cpe_conversion_requires_a_version():
    assert nmap_cpe_to_match_string("cpe:/a:apache:http_server:2.4.49") == "cpe:2.3:a:apache:http_server:2.4.49"
    assert nmap_cpe_to_match_string("cpe:/o:microsoft:windows") is None
    assert nmap_cpe_to_match_string("not-a-cpe") is None


def test_nvd_client_parses_and_caches(monkeypatch):
    requests = []

    def fake_get(url, params, headers, timeout):
        requests.append(params["virtualMatchString"])
        return httpx.Response(200, json={"totalResults": 1, "vulnerabilities": [{"cve": {
            "id": "CVE-2021-41773", "cisaExploitAdd": "2021-11-03",
            "descriptions": [{"lang": "en", "value": "Path traversal"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
        }}]})

    monkeypatch.setattr(cve_lookup.httpx, "get", fake_get)
    client = NvdClient()
    client.min_interval = 0
    first = client.lookup("cpe:/a:apache:http_server:2.4.49")
    second = client.lookup("cpe:/a:apache:http_server:2.4.49")
    assert first.cves[0] == Cve("CVE-2021-41773", 7.5, "HIGH", True, "Path traversal")
    assert second is first and requests == ["cpe:2.3:a:apache:http_server:2.4.49"]


def test_nvd_rate_limit_is_reported_not_raised(monkeypatch):
    monkeypatch.setattr(cve_lookup.httpx, "get", lambda *a, **k: httpx.Response(429))
    client = NvdClient()
    client.min_interval = 0
    assert "rate limit" in client.lookup("cpe:/a:apache:http_server:2.4.49").error


def test_severity_rank_orders_info_last():
    ordered = sorted([Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.CRITICAL], key=SEVERITY_RANK.get)
    assert ordered == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW, Severity.INFO]
