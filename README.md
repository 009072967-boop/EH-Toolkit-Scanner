# Defensive Pentest Scanner

A self-hosted web app for running authorized, non-destructive security scans — network/port,
dependency/CVE, and web application checks — against infrastructure you own or have explicit
authorization to test. See [PRD.md](PRD.md) for the full product spec.

**This tool enforces its own authorization rules server-side.** A scan cannot be launched against a
target that hasn't completed ownership verification, consent, and (for third-party targets) a signed
authorization document upload. Read `app/models.py`'s `Target.is_scannable()` and `PRD.md`'s
"Scope, authorization, and legal guardrails" section before pointing this at anything.

## Requirements

- Python 3.11+
- [nmap](https://nmap.org/download.html) installed and on your `PATH` (required for network scans).
  - Windows: install the official nmap package, which bundles Npcap.
  - macOS: `brew install nmap`
  - Linux: `apt install nmap` / equivalent

## Local setup

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
# then edit .env and set SECRET_KEY to a real random value:
python -c "import secrets; print(secrets.token_urlsafe(32))"

uvicorn app.main:app --reload
```

Open http://localhost:8000.

Network scans that use SYN scanning (`-sS`, nmap's default when available) need elevated privileges.
If you see permission errors from nmap, either run the app with the privileges nmap needs, or note
that nmap will fall back to a TCP connect scan otherwise.

## Docker

```bash
docker compose up --build
```

This bundles nmap inside the container so no host install is needed. Data (SQLite DB + encrypted
authorization documents) persists in `./data` via the volume mount — back that directory up like you
would any other credential store.

## Project layout

```
app/
  main.py                 FastAPI app + router wiring
  config.py                Settings (from .env)
  database.py, models.py    SQLite/SQLAlchemy models — Target, Consent, AuthorizationDocument,
                             ScanRun, Finding, AuditLogEntry
  security.py                Encryption-at-rest + result hashing
  routers/                    HTTP routes (targets, scans, audit, dashboard)
  services/
    verification.py            Tier 1 (self-owned) DNS TXT / well-known file checks
    authorization.py            Tier 2 (third-party) signed document storage
    audit.py                     Immutable audit log writer
    report.py                     PDF/JSON report generation
    retention.py                   Optional scan-result purge (RETENTION_DAYS in .env)
  scanning/
    network.py                nmap wrapper (network/port scan engine)
    dependency.py               OSV.dev-backed CVE scan engine
    webapp/crawler.py             Scoped same-domain crawler
    webapp/checks.py               Header/exposed-file/TLS/XSS/SQLi/CSRF detection checks
    orchestrator.py                Runs a ScanRun's modules as a background task
  templates/                 Jinja2 + HTMX server-rendered UI
```

## Adding a target

1. **Targets → Add target.** Choose a type (domain/hostname for web app scanning, IP/CIDR for network
   scanning) and an ownership tier.
2. **Verify ownership.**
   - Self-owned domain: publish the generated DNS TXT record or well-known file, then click verify.
   - Self-owned IP/range: confirm via the self-attestation checkbox (still logged).
   - Third-party: ownership verification still applies if it's a domain you can prove control of;
     either way, you also need step 4.
3. **Record consent** — a timestamped attestation that you're authorized to test this target.
4. **Third-party targets only:** upload a signed authorization document naming the scope, authorized
   scan types, and a start/end window. The target isn't scannable without one, and scans stop
   automatically once the window expires.
5. Once the target shows "scannable," launch a scan and pick modules.

## What the network scan reports

Beyond open ports, a network scan now interprets what it finds:

- **Service and version on every port** (e.g. `Open port 8080/tcp: http — Apache httpd 2.4.49`), with
  Windows' dynamic RPC ports (49152+) grouped into one finding instead of a row each.
- **Known CVEs for detected versions**, looked up in the [NVD](https://nvd.nist.gov/) by the CPE nmap
  reports. Actively exploited CVEs (CISA KEV) are ranked first and raise the finding to Critical. Only
  the product/version is sent to NVD, never anything about the target. Set `NVD_API_KEY` in `.env`
  (free) for faster lookups; `CVE_LOOKUP_ENABLED=false` turns it off.
- **Configuration checks from nmap's safe scripts**: SMBv1 and SMB signing, RDP without NLA, weak SSH
  algorithms, anonymous FTP, risky HTTP methods, missing security headers, permissive CORS, possible
  open proxies, expired/placeholder TLS certificates, and anything a `vuln and safe` script reports as
  vulnerable (aggressive intensity only).
- **Risk rules for ~25 commonly abused services** (Telnet, RDP, SMB, exposed databases, Docker API,
  Redis, VNC, SNMP, ...), falling back on the well-known port when nmap can't name the service.

Only nmap's `safe` script category (plus a short list of named safe checks) is ever used: nothing
intrusive, brute-force, DoS, or exploit-based. OS detection needs Administrator/root; without it the
scan says so and carries on.

## Tests

```bash
pip install -r requirements.txt
pytest
```

## Data retention

By default scan results are kept forever. Set `RETENTION_DAYS` in `.env` to auto-purge old scan runs;
run `python -m app.services.retention` periodically (cron / Task Scheduler) to apply it. The audit log
itself is never purged by this mechanism.
