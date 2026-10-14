from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditLogEntry
from app.templating import templates

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
def audit_log_view(request: Request, db: Session = Depends(get_db)):
    entries = db.query(AuditLogEntry).order_by(AuditLogEntry.timestamp.desc()).limit(500).all()
    return templates.TemplateResponse("audit_log.html", {"request": request, "entries": entries})
