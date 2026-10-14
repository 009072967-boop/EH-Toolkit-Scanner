"""Report generation: a JSON export for scripting/archival, and a PDF export
for handing to a client or keeping as a dated record. Both pull from the
same ScanRun/Finding data so the two formats never drift apart.
"""

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.models import ScanRun

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_COLORS = {
    "critical": colors.HexColor("#7f1d1d"),
    "high": colors.HexColor("#b91c1c"),
    "medium": colors.HexColor("#c2410c"),
    "low": colors.HexColor("#a16207"),
    "info": colors.HexColor("#374151"),
}


def _sorted_findings(scan_run: ScanRun):
    return sorted(scan_run.findings, key=lambda f: _SEVERITY_ORDER.index(f.severity.value))


def build_json_report(scan_run: ScanRun) -> dict:
    target = scan_run.target
    active_auth = target.active_authorization()
    return {
        "scan_id": scan_run.id,
        "status": scan_run.status.value,
        "modules": scan_run.modules,
        "intensity": scan_run.intensity,
        "initiated_by": scan_run.initiated_by,
        "started_at": scan_run.started_at.isoformat() if scan_run.started_at else None,
        "completed_at": scan_run.completed_at.isoformat() if scan_run.completed_at else None,
        "results_hash": scan_run.results_hash,
        "error_message": scan_run.error_message,
        "target": {
            "id": target.id,
            "name": target.name,
            "type": target.target_type.value,
            "value": target.value,
            "tier": target.tier.value,
            "verification_status": target.verification_status.value,
            "authorization_on_file": bool(active_auth),
            "authorization_window": (
                {
                    "start": active_auth.window_start.isoformat(),
                    "end": active_auth.window_end.isoformat(),
                    "authorizer_name": active_auth.authorizer_name,
                }
                if active_auth
                else None
            ),
        },
        "findings": [
            {
                "category": f.category.value,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "remediation": f.remediation,
                "affected_asset": f.affected_asset,
                "evidence": f.evidence,
            }
            for f in _sorted_findings(scan_run)
        ],
    }


def build_pdf_report(scan_run: ScanRun) -> bytes:
    target = scan_run.target
    findings = _sorted_findings(scan_run)
    active_auth = target.active_authorization()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=LETTER, topMargin=0.75 * inch, bottomMargin=0.75 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleCustom", parent=styles["Title"], fontSize=18)
    h2 = styles["Heading2"]
    body = styles["BodyText"]
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=8, textColor=colors.grey)

    story = [
        Paragraph("Defensive Pentest Scan Report", title_style),
        Spacer(1, 6),
        Paragraph(f"Target: {target.name} ({target.value})", body),
        Paragraph(f"Tier: {target.tier.value.replace('_', ' ').title()}", body),
        Paragraph(f"Scan status: {scan_run.status.value}", body),
        Paragraph(f"Modules run: {', '.join(scan_run.modules)}", body),
        Paragraph(
            f"Completed: {scan_run.completed_at.strftime('%Y-%m-%d %H:%M UTC') if scan_run.completed_at else 'n/a'}",
            body,
        ),
        Paragraph(f"Results hash (integrity check): {scan_run.results_hash}", small),
    ]

    if target.tier.value == "third_party" and active_auth:
        story += [
            Spacer(1, 6),
            Paragraph(
                f"Authorized by {active_auth.authorizer_name} ({active_auth.authorizer_role}), "
                f"window {active_auth.window_start.date()} to {active_auth.window_end.date()}.",
                small,
            ),
        ]

    story.append(Spacer(1, 16))
    story.append(Paragraph(f"Findings ({len(findings)})", h2))

    if not findings:
        story.append(Paragraph("No findings were recorded for this scan.", body))
    else:
        for f in findings:
            sev = f.severity.value.upper()
            sev_style = ParagraphStyle(
                "SevHeading",
                parent=styles["Heading3"],
                textColor=_SEVERITY_COLORS.get(f.severity.value, colors.black),
            )
            story.append(Spacer(1, 10))
            story.append(Paragraph(f"[{sev}] {f.title}", sev_style))
            table_data = [
                ["Category", f.category.value],
                ["Affected asset", f.affected_asset],
                ["Description", f.description],
                ["Remediation", f.remediation],
            ]
            if f.evidence:
                table_data.append(["Evidence", f.evidence[:500]])
            table = Table(
                [[Paragraph(k, body), Paragraph(str(v), body)] for k, v in table_data],
                colWidths=[1.3 * inch, 4.7 * inch],
            )
            table.setStyle(
                TableStyle(
                    [
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
                    ]
                )
            )
            story.append(table)

    doc.build(story)
    return buffer.getvalue()
