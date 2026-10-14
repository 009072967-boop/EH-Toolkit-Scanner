# Defensive Pentest Scanner — PRD (v2)
Sep 17, 2026 · @Brian

## Overview

This PRD describes a self-hosted web application for running authorized, defensive security scans against infrastructure you own or have explicit authorization to test — your own devices/sites, and third-party systems under a formal authorization agreement. It combines three scan categories (web application vulnerabilities, network/port exposure, and vulnerable dependencies) behind one web UI, so a single operator can add a target, verify ownership or authorization, run a scan, and get a readable, actionable report.

The ambition is to build something that functions like the pentest scanning software you'd otherwise purchase (Nessus, Qualys, Burp Suite Pro) — not to match their check-count on day one, but to end up structurally capable of that breadth: an extensible check-module architecture, authenticated scanning, compliance-style reporting, and support for real engagement workflows, not just a hobby scanner. v1 stays lean; the roadmap is what carries it toward commercial-grade over time.

This is explicitly not an offensive tool. Every design decision downstream — the allow-list, the two-tier authorization model, the non-destructive defaults — exists to keep this a tool for testing systems you own or are formally authorized to test, not a general-purpose scanner aimed at arbitrary targets.

## Goals and non-goals (v1)

### Goals
- One web UI to add a target, verify/authorize it, launch scans, and review results across all three scan categories.
- Reports that are actually actionable: severity, plain-language description, remediation guidance — not a raw tool dump.
- Authorization enforced by the system itself, not just documented as policy — a scan cannot launch against a target that hasn't been verified and, for third-party targets, formally authorized.
- Support both target ownership tiers from v1: infrastructure you personally own/control, and third-party infrastructure under a signed authorization agreement — the latter gated by real workflow, not a checkbox.
- A codebase Brian can extend and maintain going forward, built incrementally in VS Code with Claude Code, structured so check coverage can grow toward commercial-grade depth without re-architecting.

### Non-goals (v1)
- Not a multi-user or multi-tenant product — single operator, single instance.
- v1's own check list is intentionally lean (well-known, high-value checks). This is a sequencing choice, not a ceiling — see the roadmap for how coverage is meant to grow toward commercial-scanner depth.
- No active exploitation beyond confirming a vulnerability is present (e.g., detecting reflected XSS is in scope; using it to pivot further is not).
- No automated credential brute-forcing or password spraying by default.
- No destructive testing (no data modification/deletion tests) in v1.

## Scope, authorization, and legal guardrails

Scanning infrastructure you don't own or don't have explicit permission to test is illegal in most jurisdictions (e.g. the U.S. Computer Fraud and Abuse Act) even when done with good intentions and no damage caused. This section is not optional polish — it's the part of the PRD that has to be built before any scan engine, because it's what keeps this a defensive tool rather than a liability.

**Two authorization tiers, gated differently by risk:**

**Tier 1 — Self-owned/controlled infrastructure.** For domains: a DNS TXT record or well-known file token the app generates and asks you to publish, mirroring how Let's Encrypt/Google Search Console verify domain ownership. For IP ranges/internal hosts (e.g. a home network): self-attestation is acceptable since these are typically your own infrastructure, but it's still logged with target details and timestamp. Before first scan, a simple attestation checkbox ("I own this system") is required.

**Tier 2 — Third-party authorized infrastructure.** Before a third-party target can be verified, the app requires a signed authorization document tied to that specific target record:
- Upload a signed authorization letter (PDF or scanned document), or generate one from an in-app template that names the target scope (specific hosts/domains/IP ranges), permitted scan types and intensity, the authorization window (start/end date), and the authorizer's name, role, and contact info.
- The document is stored (encrypted at rest, given it names a third party and may contain contact/business info) and linked immutably to the target record.
- The target becomes scannable only once a document is on file. The authorization window's end date is enforced: scans are automatically blocked once it lapses, and the target shows as "authorization expired" until a new document is uploaded.
- The app can verify the document exists and has the required fields filled in — it cannot verify the signature is genuine or that the signer had authority to grant it. That's a known limitation (see Risks), and until there's a reason to automate it, treat every third-party target as something Brian personally reviews before first scan, not something the system self-approves.

Both tiers share the same downstream controls:

**Target allow-list, enforced server-side.** Every scan request is checked against a stored list of approved targets, each tagged with its authorization tier and (for Tier 2) current authorization validity. There is no UI-only gate — the API itself rejects a scan against anything not on the list or out of its authorization window.

**Audit log.** Every scan — who ran it, what target, what modules, when, authorization tier, and a hash of the results — is recorded immutably.

**Non-destructive by default.** Default scan profiles only probe and observe; nothing that could disrupt a production service runs unless explicitly opted into per scan.

## Users and use cases

The primary (and for v1, only) user is Brian, using the tool against infrastructure he owns/controls (Tier 1) or has a signed authorization for (Tier 2). Representative use cases:
- **Pre-launch check** (Tier 1): before pushing a new site or app live, scan it for common OWASP-style issues so they're caught before an attacker finds them.
- **Home network hygiene** (Tier 1): periodically scan a home lab or home network for open ports and outdated/misconfigured services.
- **Dependency hygiene** (Tier 1): scan a project's manifest files for known-CVE dependencies before deploying.
- **Client/authorized engagement** (Tier 2): with a signed authorization document on file, run the relevant scans against a third party's infrastructure and export a clean report to hand to them. This is a first-class v1 use case now, not a deferred stretch goal — it's what the Tier 2 workflow exists for.

## Core features

*(Web application scanning, network/port scanning, dependency/CVE scanning — scoped crawler with safe detection checks, nmap-backed port/service scanning, OSV.dev-backed dependency CVE checks. See roadmap for how each grows.)*

**Reporting**
- Unified findings dashboard across all three categories, grouped by severity (Critical/High/Medium/Low/Info).
- Export to PDF and JSON.
- Scan history per target, so results can be compared over time.
- Report includes the target's authorization tier and (for Tier 2) a reference to the authorization document on file — useful when handing a report to the third party as proof the engagement was authorized.

## Recommended architecture and tech stack

- **Backend:** Python + FastAPI. Nearly every useful scanning building block is Python-native or has a mature Python wrapper (python-nmap around the nmap binary, httpx for the web crawler, OSV.dev's REST API for CVE lookups), and FastAPI gives a clean typed API plus auto-generated docs.
- **Background jobs:** scans are I/O-bound and can take minutes; they run as background tasks (FastAPI BackgroundTasks for v1 simplicity, upgrading to Celery/RQ with Redis only if scans need to survive a server restart or run concurrently at scale) rather than blocking the request.
- **Frontend:** server-rendered with HTMX, not a full SPA. FastAPI + Jinja2 templates + HTMX gives a responsive-feeling UI (live scan progress, dynamic result tables) without a separate frontend build step.
- **Storage:** SQLite. Sufficient for a single-user tool (targets, scan results, audit log); easy to run with zero setup. Can migrate to Postgres later if the tool grows into a multi-user product.
- **Scan engines:** nmap (network scanning, invoked as a subprocess and parsed), a lightweight custom crawler + check modules for web scanning (rather than wrapping a full tool like ZAP, to keep the codebase legible), and the OSV.dev API for dependency CVEs — all free and requiring no paid API keys for v1.
- **Packaging:** Dockerfile bundling the app and the nmap binary, so the tool is portable to a homelab server or another machine without manual setup.
- **Check-module architecture as a first-class design constraint, not an afterthought.** Each detection check (a header check, an nmap NSE script wrapper, a CVE source) should be a self-registering module with a common interface (target in, findings out), so that growing from "a handful of checks" to "commercial-scanner-scale breadth" is a matter of adding modules, not restructuring the scan/report pipeline. This is what makes the later "raise the ceiling" roadmap phases realistic instead of aspirational.

## Built-in safety controls

- Target allow-list enforced in the API layer, checked on every scan request.
- Tier 1: ownership verification (DNS TXT/file token, or logged self-attestation for private/internal targets).
- Tier 2: signed authorization document required, tied to a specific target scope and time window, with automatic scan-blocking on expiration.
- Consent/legal attestation, timestamped, stored per target (both tiers).
- Non-destructive, read-only default scan profiles; higher-intensity options require explicit opt-in per scan.
- Rate limiting/throttling on all outbound scan traffic.
- Immutable audit log: target, tier, modules run, initiator, timestamps, results hash, for every scan.
- Scan timeout / kill switch.
- A visible reminder on the scan-launch screen restating that scans may only run against verified/authorized targets, with the tier and (for Tier 2) authorization expiration shown inline.
- Authorization documents and any future scan credentials encrypted at rest.

## Non-functional requirements

- **Performance:** scans run as background jobs with configurable timeouts so the UI stays responsive while a scan is in progress.
- **Reliability:** scans can be cancelled mid-run; failures surface a clear error rather than hanging silently.
- **Extensibility:** new scan modules can be added without modifying the core scan/report pipeline.
- **Local-first:** runs on Brian's own machine or homelab with no required cloud dependency, while remaining deployable elsewhere if desired.
- **Data retention:** scan results may contain sensitive details about a target's weaknesses, so retention should be configurable (e.g., auto-purge after N days) rather than kept forever by default. Authorization documents follow the same retention/encryption posture as scan results, since they may contain a third party's contact and business details.

## Phased roadmap (for building in VS Code with Claude Code)

1. **Phase 0 — Safety scaffolding first.** Project structure, FastAPI skeleton, database models, target allow-list, Tier 1 ownership verification, and Tier 2 signed-authorization upload/validation/expiration flow. No scan engine yet.
2. **Phase 1 — Network/port scanning.** nmap wrapper plus a basic results view. Validates the full flow end-to-end for both tiers.
3. **Phase 2 — Dependency/CVE scanning.** Manifest upload/parsing plus OSV.dev integration.
4. **Phase 3 — Web application vulnerability scanning.** Crawler and detection checks (headers, exposed files, XSS/SQLi indicators, CSRF, TLS).
5. **Phase 4 — Unified dashboard and polish.** Combined findings view, historical comparison, PDF export, Tier 2 authorization reference on exported reports.
6. **Phase 5 — Toward commercial-grade breadth.** This is where the "as close as possible to purchasable software" ambition actually gets built out, once the core loop is solid:
   - Expand each check category's module count substantially (more nmap NSE scripts, more header/config checks, broader CVE source coverage) using the Phase 0 module architecture.
   - Authenticated scanning (stored, encrypted credentials) for logged-in-state web app checks.
   - Compliance-style report templates (e.g. OWASP Top 10 mapping, CIS benchmark-style sections) alongside the raw findings report.
   - Scheduled/recurring scans.
   - Additional integrations (e.g. Shodan) for passive recon.
   - Revisit whether Tier 2's document-only verification needs to become identity-verified (e.g. e-signature provider integration) once real third-party engagements are happening regularly.

## Risks, open questions, and success metrics

### Risks
- False positives/negatives in detection logic could erode trust in reports or give false confidence.
- **Forged or invalid authorization documents.** The system checks that a document exists and is filled out, not that it's genuine or that the signer had authority. Mitigation for now: Brian manually reviews every Tier 2 target before first scan; this is a process control, not a system one, and should be revisited if third-party engagements become frequent enough that manual review doesn't scale.
- Scope creep toward rebuilding a commercial-grade scanner instead of building it incrementally — the Phase 5 ambition needs to stay sequenced behind a working core, not front-loaded.
- Legal exposure if the allow-list, tier gating, or authorization expiration is ever bypassed, misconfigured, or a target is added without real authorization.
- Scan traffic could trigger a target's own security monitoring or an ISP's abuse detection, even against authorized infrastructure — worth a heads-up to the third party before a Tier 2 scan, though not a system-enforced step.

### Open questions
- Manual upload + review vs. an e-signature integration (DocuSign-style) for Tier 2 authorization — start manual, revisit per Phase 5.
- Should Tier 2 authorization require a mandatory expiration date (no open-ended authorizations), or allow one with a recommended default?
- Local-only deployment, or eventually hosted somewhere?
- Preferred report export format long-term — PDF, HTML, or JSON-first for scripting?

### Success metrics
- Successfully scans and produces an actionable report for at least one real Tier 1 target and one real Tier 2 (signed-authorization) target across all three scan categories.
- Zero scans ever executed against a non-allow-listed, unverified, or (for Tier 2) authorization-expired target.
- Time from "add target" to "first report" stays under about 10 minutes for a small site or home network (Tier 1).
