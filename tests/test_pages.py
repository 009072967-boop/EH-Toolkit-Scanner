from fastapi.testclient import TestClient

from app.config import settings
from app.database import SessionLocal
from app.main import app
from app.models import Finding, ScanModule, ScanRun, ScanStatus, Severity, Target, TargetType, Tier

client = TestClient(app)


def test_tests_use_a_throwaway_database():
    assert "scanner-tests-" in settings.database_url


def test_every_page_renders_with_data():
    db = SessionLocal()
    target = Target(name="Lab box", target_type=TargetType.IP, value="127.0.0.1", tier=Tier.SELF_OWNED)
    db.add(target)
    db.commit()
    scan = ScanRun(target_id=target.id, modules=["network"], intensity="standard", status=ScanStatus.COMPLETED,
                   initiated_by="test")
    db.add(scan)
    db.commit()
    db.add_all([
        Finding(scan_run_id=scan.id, category=ScanModule.NETWORK, severity=sev, title=f"{sev.value} finding",
                description="d", remediation="r", affected_asset="127.0.0.1:80/tcp", evidence="<none>")
        for sev in Severity
    ])
    db.commit()
    target_id, scan_id = target.id, scan.id
    db.close()

    for path in ("/", "/targets", "/targets/new", f"/targets/{target_id}", f"/scans/{scan_id}", "/audit"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "/static/css/app.css" in response.text, path

    report = client.get(f"/scans/{scan_id}").text
    # Critical listed before info, evidence escaped rather than rendered as a tag.
    assert report.index("critical finding") < report.index("info finding")
    assert "&lt;none&gt;" in report


def test_stylesheet_is_served():
    response = client.get("/static/css/app.css")
    assert response.status_code == 200 and "--critical" in response.text
