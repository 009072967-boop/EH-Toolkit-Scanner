from collections import Counter

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Finding, ScanRun, ScanStatus, Target
from app.templating import templates

router = APIRouter(tags=["dashboard"])


@router.get("/")
def dashboard(request: Request, db: Session = Depends(get_db)):
    targets = db.query(Target).all()
    recent_scans = (
        db.query(ScanRun)
        .filter(ScanRun.status == ScanStatus.COMPLETED)
        .order_by(ScanRun.completed_at.desc())
        .limit(50)
        .all()
    )

    severity_counts: Counter = Counter()
    for scan in recent_scans:
        for f in scan.findings:
            severity_counts[f.severity.value] += 1

    all_scans = db.query(ScanRun).order_by(ScanRun.created_at.desc()).limit(15).all()

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "target_count": len(targets),
            "scannable_count": sum(1 for t in targets if t.is_scannable()[0]),
            "severity_counts": severity_counts,
            "recent_scans": all_scans,
        },
    )
