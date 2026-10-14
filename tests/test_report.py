from datetime import datetime, timezone

from app.models import (
    Finding,
    ScanModule,
    ScanRun,
    ScanStatus,
    Severity,
    Target,
    TargetType,
    Tier,
    VerificationStatus,
)
from app.services.report import _pdf_text, build_pdf_report


def _scan_with(finding: Finding) -> ScanRun:
    target = Target(name="Lab", target_type=TargetType.IP, value="127.0.0.1", tier=Tier.SELF_OWNED,
                    verification_status=VerificationStatus.VERIFIED)
    scan = ScanRun(target=target, modules=["network"], intensity="standard", status=ScanStatus.COMPLETED,
                   initiated_by="test", started_at=datetime.now(timezone.utc),
                   completed_at=datetime.now(timezone.utc))
    scan.findings = [finding]
    return scan


def test_pdf_text_escapes_markup_and_keeps_line_breaks():
    assert _pdf_text("a < b & c\nnext") == "a &lt; b &amp; c<br/>next"


def test_pdf_export_survives_markup_characters_in_findings():
    # ReportLab parses Paragraph text as markup. Unescaped, an unbalanced tag-like string made
    # PDF export raise ValueError, and tag-like text such as nmap's "<none>" silently vanished.
    finding = Finding(
        category=ScanModule.NETWORK, severity=Severity.HIGH,
        title="Apache httpd 2.4.49: 3 known CVEs <b>",
        description="Versions < 2.4.51 & > 2.4.48 are affected",
        remediation="Upgrade to >= 2.4.62",
        affected_asset="127.0.0.1:8080/tcp",
        evidence="Allowed: <none>\n<b>unclosed tag",
    )
    pdf = build_pdf_report(_scan_with(finding))
    assert pdf.startswith(b"%PDF")
