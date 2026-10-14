from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException, Request, UploadFile, File
from fastapi.responses import JSONResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import ScanModule, ScanRun, ScanStatus, Target
from app.scanning.orchestrator import execute_scan, request_cancel
from app.services.audit import log as audit_log
from app.services.report import build_json_report, build_pdf_report
from app.templating import templates

router = APIRouter(tags=["scans"])


@router.post("/targets/{target_id}/scans")
def launch_scan(
    target_id: str,
    background_tasks: BackgroundTasks,
    modules: list[str] = Form(...),
    intensity: str = Form("standard"),
    manifest_file: UploadFile | None = File(None),
    db: Session = Depends(get_db),
):
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(404, "Target not found")

    # Server-side allow-list enforcement: this check is the actual gate. The
    # UI hides the launch form when a target isn't scannable, but that's a
    # convenience, not the control — a scan cannot be created via this
    # endpoint at all unless this check passes.
    allowed, reason = target.is_scannable()
    if not allowed:
        raise HTTPException(403, f"Scan blocked: {reason}")

    valid_modules = {m.value for m in ScanModule}
    for m in modules:
        if m not in valid_modules:
            raise HTTPException(400, f"Unknown scan module '{m}'.")
    if intensity not in ("standard", "aggressive"):
        raise HTTPException(400, "Intensity must be 'standard' or 'aggressive'.")

    dependency_manifest = None
    if ScanModule.DEPENDENCY.value in modules:
        if manifest_file is None:
            raise HTTPException(400, "Dependency scan selected but no manifest file was uploaded.")
        content_bytes = manifest_file.file.read()
        dependency_manifest = (manifest_file.filename, content_bytes.decode("utf-8", errors="replace"))

    scan_run = ScanRun(
        target_id=target.id,
        modules=modules,
        intensity=intensity,
        status=ScanStatus.PENDING,
        initiated_by=settings.operator_name,
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    audit_log(db, actor=settings.operator_name, action="scan_queued", target_id=target.id, scan_run_id=scan_run.id,
               details={"modules": modules, "intensity": intensity})

    background_tasks.add_task(execute_scan, scan_run.id, dependency_manifest)

    return RedirectResponse(f"/scans/{scan_run.id}", status_code=303)


@router.get("/scans/{scan_id}")
def scan_detail(request: Request, scan_id: str, db: Session = Depends(get_db)):
    scan_run = db.get(ScanRun, scan_id)
    if scan_run is None:
        raise HTTPException(404, "Scan not found")
    findings = sorted(scan_run.findings, key=lambda f: (f.severity.value != "critical", f.severity.value))
    return templates.TemplateResponse(
        "scan_detail.html",
        {"request": request, "scan": scan_run, "target": scan_run.target, "findings": findings},
    )


@router.get("/scans/{scan_id}/status")
def scan_status_partial(request: Request, scan_id: str, db: Session = Depends(get_db)):
    scan_run = db.get(ScanRun, scan_id)
    if scan_run is None:
        raise HTTPException(404, "Scan not found")
    return templates.TemplateResponse("_scan_status.html", {"request": request, "scan": scan_run})


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str, db: Session = Depends(get_db)):
    scan_run = db.get(ScanRun, scan_id)
    if scan_run is None:
        raise HTTPException(404, "Scan not found")
    request_cancel(scan_id)
    audit_log(db, actor=settings.operator_name, action="scan_cancel_requested", target_id=scan_run.target_id,
               scan_run_id=scan_run.id)
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


@router.get("/scans/{scan_id}/report.json")
def scan_report_json(scan_id: str, db: Session = Depends(get_db)):
    scan_run = db.get(ScanRun, scan_id)
    if scan_run is None:
        raise HTTPException(404, "Scan not found")
    return JSONResponse(build_json_report(scan_run))


@router.get("/scans/{scan_id}/report.pdf")
def scan_report_pdf(scan_id: str, db: Session = Depends(get_db)):
    scan_run = db.get(ScanRun, scan_id)
    if scan_run is None:
        raise HTTPException(404, "Scan not found")
    pdf_bytes = build_pdf_report(scan_run)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}_report.pdf"},
    )
