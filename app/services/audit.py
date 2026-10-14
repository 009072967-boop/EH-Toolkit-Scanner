import json

from sqlalchemy.orm import Session

from app.models import AuditLogEntry


def log(
    db: Session,
    *,
    actor: str,
    action: str,
    target_id: str | None = None,
    scan_run_id: str | None = None,
    details: dict | None = None,
    result_hash: str | None = None,
) -> AuditLogEntry:
    """Append an immutable audit log entry. Callers should never update or
    delete rows in this table — it exists as a record of what was actually
    done, independent of what the UI currently shows."""
    entry = AuditLogEntry(
        actor=actor,
        action=action,
        target_id=target_id,
        scan_run_id=scan_run_id,
        details=json.dumps(details, default=str) if details is not None else None,
        result_hash=result_hash,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
