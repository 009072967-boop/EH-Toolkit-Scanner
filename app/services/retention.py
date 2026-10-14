"""Configurable data retention for scan results. RETENTION_DAYS=0 (default)
keeps everything forever. Set it to a positive number of days to have old
scan runs (and their findings) purged. This does not touch the audit log —
that stays immutable regardless of retention settings, since it's the
record of what was done, not a copy of what was found.

Intended to be run periodically (e.g. via cron/Task Scheduler calling
`python -m app.services.retention`), not automatically on every request.
"""

from datetime import datetime, timedelta, timezone

from app.config import settings
from app.database import SessionLocal
from app.models import ScanRun
from app.services.audit import log as audit_log


def purge_old_scans() -> int:
    if settings.retention_days <= 0:
        return 0

    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.retention_days)
    db = SessionLocal()
    try:
        old_runs = db.query(ScanRun).filter(ScanRun.created_at < cutoff).all()
        count = len(old_runs)
        for run in old_runs:
            audit_log(
                db,
                actor="retention-policy",
                action="scan_purged",
                target_id=run.target_id,
                scan_run_id=run.id,
                details={"created_at": run.created_at.isoformat(), "retention_days": settings.retention_days},
            )
            db.delete(run)
        db.commit()
        return count
    finally:
        db.close()


if __name__ == "__main__":
    purged = purge_old_scans()
    print(f"Purged {purged} scan run(s) older than {settings.retention_days} day(s).")
