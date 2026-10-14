"""Dispatches a ScanRun to the right engine(s), persists findings, and keeps
the audit log/results hash up to date. Runs inside a FastAPI BackgroundTask
so the launch request returns immediately and the UI polls for status.

The allow-list check (Target.is_scannable) is re-verified here, not just at
launch time in the router — a scan can take minutes, and authorization could
expire or be revoked while it's queued/running. If that happens the run is
stopped rather than allowed to continue against a target that's no longer
authorized.
"""

import json
import threading
import time
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.config import settings
from app.models import Finding, ScanModule, ScanRun, ScanStatus, Target
from app.scanning.common import RawFinding, ScanEngineError
from app.scanning.cve_lookup import NvdClient
from app.scanning.dependency import run_dependency_scan
from app.scanning.network import run_network_scan
from app.scanning.webapp_scan import run_webapp_scan
from app.security import hash_results
from app.services.audit import log as audit_log

# One shared NVD client per process so concurrent scans share its rate limiting and cache.
_nvd = NvdClient(api_key=settings.nvd_api_key)

# Tracks scan runs that have been asked to cancel. Best-effort: engines check
# this between discrete steps, but a single long-running nmap/httpx call
# in progress cannot be interrupted mid-call.
_cancel_flags: set[str] = set()
_cancel_lock = threading.Lock()


def request_cancel(scan_run_id: str) -> None:
    with _cancel_lock:
        _cancel_flags.add(scan_run_id)


def _is_cancelled(scan_run_id: str) -> bool:
    with _cancel_lock:
        return scan_run_id in _cancel_flags


def _clear_cancel(scan_run_id: str) -> None:
    with _cancel_lock:
        _cancel_flags.discard(scan_run_id)


def _persist_findings(db: Session, scan_run_id: str, category: ScanModule, raw_findings: list[RawFinding]) -> None:
    for rf in raw_findings:
        db.add(
            Finding(
                scan_run_id=scan_run_id,
                category=category,
                severity=rf.severity,
                title=rf.title,
                description=rf.description,
                remediation=rf.remediation,
                affected_asset=rf.affected_asset,
                evidence=rf.evidence,
            )
        )
    db.commit()


def execute_scan(scan_run_id: str, dependency_manifest: tuple[str, str] | None = None) -> None:
    """Entry point invoked as a BackgroundTask. Opens its own DB session
    since it runs outside the request's session lifecycle."""
    db = SessionLocal()
    try:
        scan_run = db.get(ScanRun, scan_run_id)
        if scan_run is None:
            return

        target = db.get(Target, scan_run.target_id)
        allowed, reason = target.is_scannable()
        if not allowed:
            scan_run.status = ScanStatus.FAILED
            scan_run.error_message = f"Blocked by allow-list check at execution time: {reason}"
            scan_run.completed_at = datetime.now(timezone.utc)
            db.commit()
            audit_log(
                db,
                actor=scan_run.initiated_by,
                action="scan_blocked",
                target_id=target.id,
                scan_run_id=scan_run.id,
                details={"reason": reason},
            )
            return

        scan_run.status = ScanStatus.RUNNING
        scan_run.started_at = datetime.now(timezone.utc)
        db.commit()
        audit_log(db, actor=scan_run.initiated_by, action="scan_started", target_id=target.id, scan_run_id=scan_run.id,
                   details={"modules": scan_run.modules, "intensity": scan_run.intensity})

        started = time.monotonic()
        all_results: dict[str, list[dict]] = {}
        errors: list[str] = []

        for module in scan_run.modules:
            if _is_cancelled(scan_run_id):
                break
            if time.monotonic() - started > settings.scan_timeout_seconds:
                errors.append(f"Scan timed out after {settings.scan_timeout_seconds}s before running '{module}'.")
                break

            try:
                if module == ScanModule.NETWORK.value:
                    raw = run_network_scan(
                        target.value,
                        intensity=scan_run.intensity,
                        timeout_seconds=settings.scan_timeout_seconds,
                        cve_lookup=_nvd.lookup if settings.cve_lookup_enabled else None,
                        max_cve_lookups=settings.max_cve_lookups_per_scan,
                    )
                    _persist_findings(db, scan_run.id, ScanModule.NETWORK, raw)
                    all_results[module] = [rf.__dict__ for rf in raw]
                elif module == ScanModule.DEPENDENCY.value:
                    if dependency_manifest is None:
                        errors.append("Dependency scan requested but no manifest was provided.")
                        continue
                    filename, content = dependency_manifest
                    raw = run_dependency_scan(filename, content, timeout_seconds=min(settings.scan_timeout_seconds, 120))
                    _persist_findings(db, scan_run.id, ScanModule.DEPENDENCY, raw)
                    all_results[module] = [rf.__dict__ for rf in raw]
                elif module == ScanModule.WEBAPP.value:
                    raw = run_webapp_scan(target.value)
                    _persist_findings(db, scan_run.id, ScanModule.WEBAPP, raw)
                    all_results[module] = [rf.__dict__ for rf in raw]
            except ScanEngineError as exc:
                errors.append(f"{module}: {exc}")
            except Exception as exc:  # noqa: BLE001 - an engine bug must not leave the run stuck at "running"
                errors.append(f"{module}: unexpected error: {exc}")

        scan_run.completed_at = datetime.now(timezone.utc)
        scan_run.results_hash = hash_results(all_results)
        if _is_cancelled(scan_run_id):
            scan_run.status = ScanStatus.CANCELLED
        elif errors and not all_results:
            scan_run.status = ScanStatus.FAILED
            scan_run.error_message = "; ".join(errors)
        else:
            scan_run.status = ScanStatus.COMPLETED
            if errors:
                scan_run.error_message = "Completed with some module errors: " + "; ".join(errors)
        db.commit()

        audit_log(
            db,
            actor=scan_run.initiated_by,
            action=f"scan_{scan_run.status.value}",
            target_id=target.id,
            scan_run_id=scan_run.id,
            details={"errors": errors} if errors else None,
            result_hash=scan_run.results_hash,
        )
    except Exception as exc:  # noqa: BLE001 - a bug here must not leave the run stuck at "running" forever
        try:
            scan_run = db.get(ScanRun, scan_run_id)
            if scan_run is not None and scan_run.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
                scan_run.status = ScanStatus.FAILED
                scan_run.error_message = f"Scan orchestration failed unexpectedly: {exc}"
                scan_run.completed_at = datetime.now(timezone.utc)
                db.commit()
                audit_log(db, actor="system", action="scan_failed", target_id=scan_run.target_id,
                           scan_run_id=scan_run.id, details={"error": str(exc)})
        except Exception:  # noqa: BLE001 - best-effort; do not raise out of a background task
            pass
    finally:
        _clear_cancel(scan_run_id)
        db.close()
