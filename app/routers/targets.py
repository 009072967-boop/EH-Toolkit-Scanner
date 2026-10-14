import ipaddress
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile, File
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import (
    AuthDocStatus,
    AuthorizationDocument,
    Consent,
    Target,
    TargetType,
    Tier,
    VerificationMethod,
    VerificationStatus,
)
from app.security import generate_verification_token
from app.services import authorization as auth_service
from app.services import verification
from app.services.audit import log as audit_log
from app.templating import templates

router = APIRouter(prefix="/targets", tags=["targets"])

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

CONSENT_ATTESTATION_TEXT = (
    "I own this system or have explicit written authorization to test it, and I accept "
    "responsibility for ensuring this scan is authorized."
)


def _validate_value(target_type: TargetType, value: str) -> None:
    value = value.strip()
    if target_type in (TargetType.IP, TargetType.IP_RANGE):
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise HTTPException(400, f"'{value}' is not a valid IP address or CIDR range.") from exc
    else:
        # domain / hostname: allow an optional scheme+path for webapp scanning convenience,
        # but require a clean hostname underneath.
        hostname = value
        if "://" in hostname:
            hostname = hostname.split("://", 1)[1]
        hostname = hostname.split("/")[0]
        if not _DOMAIN_RE.match(hostname):
            raise HTTPException(400, f"'{value}' is not a valid domain/hostname.")


@router.get("")
def list_targets(request: Request, db: Session = Depends(get_db)):
    targets = db.query(Target).order_by(Target.created_at.desc()).all()
    return templates.TemplateResponse(
        "targets_list.html", {"request": request, "targets": targets}
    )


@router.get("/new")
def new_target_form(request: Request):
    return templates.TemplateResponse("target_add.html", {"request": request})


@router.post("")
def create_target(
    request: Request,
    name: str = Form(...),
    target_type: TargetType = Form(...),
    value: str = Form(...),
    tier: Tier = Form(...),
    notes: str = Form(""),
    db: Session = Depends(get_db),
):
    _validate_value(target_type, value)

    target = Target(
        name=name.strip(),
        target_type=target_type,
        value=value.strip(),
        tier=tier,
        notes=notes.strip() or None,
    )
    if target_type in (TargetType.DOMAIN, TargetType.HOSTNAME):
        target.verification_token = generate_verification_token()

    db.add(target)
    db.commit()
    db.refresh(target)

    audit_log(db, actor=settings.operator_name, action="target_added", target_id=target.id,
               details={"name": target.name, "type": target_type.value, "tier": tier.value})

    return RedirectResponse(f"/targets/{target.id}", status_code=303)


@router.get("/{target_id}")
def target_detail(request: Request, target_id: str, db: Session = Depends(get_db)):
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(404, "Target not found")
    allowed, reason = target.is_scannable()
    return templates.TemplateResponse(
        "target_detail.html",
        {
            "request": request,
            "target": target,
            "allowed": allowed,
            "block_reason": reason,
            "consent_text": CONSENT_ATTESTATION_TEXT,
            "well_known_prefix": verification.VERIFICATION_TXT_PREFIX,
            "operator_name": settings.operator_name,
            "message": request.query_params.get("message"),
            "error": request.query_params.get("error"),
        },
    )


@router.post("/{target_id}/verify/domain")
def verify_domain(
    target_id: str,
    method: VerificationMethod = Form(...),
    db: Session = Depends(get_db),
):
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(404, "Target not found")
    if target.target_type not in (TargetType.DOMAIN, TargetType.HOSTNAME):
        raise HTTPException(400, "This endpoint is only for domain/hostname targets.")

    hostname = target.value.split("://")[-1].split("/")[0]

    if method == VerificationMethod.DNS_TXT:
        ok, detail = verification.check_dns_txt(hostname, target.verification_token)
    elif method == VerificationMethod.WELL_KNOWN_FILE:
        ok, detail = verification.check_well_known_file(hostname, target.verification_token)
    else:
        raise HTTPException(400, "Unsupported verification method for a domain target.")

    if ok:
        target.verification_status = VerificationStatus.VERIFIED
        target.verification_method = method
        target.verified_at = datetime.now(timezone.utc)
        db.commit()
        audit_log(db, actor=settings.operator_name, action="target_verified", target_id=target.id,
                   details={"method": method.value, "detail": detail})
        return RedirectResponse(f"/targets/{target_id}?message=Ownership verified.", status_code=303)

    audit_log(db, actor=settings.operator_name, action="target_verification_failed", target_id=target.id,
               details={"method": method.value, "detail": detail})
    return RedirectResponse(f"/targets/{target_id}?error={detail}", status_code=303)


@router.post("/{target_id}/verify/self-attest")
def verify_self_attestation(
    target_id: str,
    confirm: bool = Form(...),
    db: Session = Depends(get_db),
):
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(404, "Target not found")
    if target.target_type not in (TargetType.IP, TargetType.IP_RANGE):
        raise HTTPException(400, "This endpoint is only for IP/IP-range targets.")
    if not confirm:
        raise HTTPException(400, "Self-attestation must be explicitly confirmed.")

    target.verification_status = VerificationStatus.VERIFIED
    target.verification_method = VerificationMethod.SELF_ATTESTATION
    target.verified_at = datetime.now(timezone.utc)
    db.commit()

    audit_log(db, actor=settings.operator_name, action="target_verified", target_id=target.id,
               details={"method": "self_attestation"})
    return RedirectResponse(f"/targets/{target_id}?message=Ownership self-attestation recorded.", status_code=303)


@router.post("/{target_id}/consent")
def record_consent(
    target_id: str,
    accepted_by: str = Form(...),
    confirm: bool = Form(...),
    db: Session = Depends(get_db),
):
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(404, "Target not found")
    if not confirm:
        raise HTTPException(400, "Consent must be explicitly confirmed.")

    consent = Consent(
        target_id=target.id,
        attestation_text=CONSENT_ATTESTATION_TEXT,
        accepted_by=accepted_by.strip() or settings.operator_name,
    )
    db.add(consent)
    db.commit()

    audit_log(db, actor=accepted_by, action="consent_recorded", target_id=target.id)
    return RedirectResponse(f"/targets/{target_id}?message=Consent recorded.", status_code=303)


@router.post("/{target_id}/authorization")
def upload_authorization(
    target_id: str,
    authorizer_name: str = Form(...),
    authorizer_role: str = Form(...),
    authorizer_contact: str = Form(...),
    scope_description: str = Form(...),
    authorized_scan_types: str = Form(...),
    window_start: str = Form(...),
    window_end: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(404, "Target not found")
    if target.tier != Tier.THIRD_PARTY:
        raise HTTPException(400, "Authorization documents only apply to third-party targets.")

    try:
        start_dt = datetime.fromisoformat(window_start).replace(tzinfo=timezone.utc)
        end_dt = datetime.fromisoformat(window_end).replace(tzinfo=timezone.utc)
        auth_service.validate_window(start_dt, end_dt)
        content = file.file.read()
        stored_path = auth_service.store_document(file.filename, content)
    except auth_service.InvalidAuthorizationDocument as exc:
        return RedirectResponse(f"/targets/{target_id}?error={exc}", status_code=303)

    # A new signed document supersedes any prior active one for this target.
    for existing in target.authorizations:
        if existing.status == AuthDocStatus.ACTIVE:
            existing.status = AuthDocStatus.REVOKED

    doc = AuthorizationDocument(
        target_id=target.id,
        encrypted_file_path=stored_path,
        original_filename=file.filename,
        authorizer_name=authorizer_name.strip(),
        authorizer_role=authorizer_role.strip(),
        authorizer_contact=authorizer_contact.strip(),
        scope_description=scope_description.strip(),
        authorized_scan_types=authorized_scan_types.strip(),
        window_start=start_dt,
        window_end=end_dt,
        status=AuthDocStatus.ACTIVE,
        uploaded_by=settings.operator_name,
    )
    db.add(doc)
    db.commit()

    audit_log(
        db,
        actor=settings.operator_name,
        action="authorization_document_uploaded",
        target_id=target.id,
        details={
            "authorizer_name": authorizer_name,
            "window_start": window_start,
            "window_end": window_end,
        },
    )
    return RedirectResponse(f"/targets/{target_id}?message=Authorization document recorded.", status_code=303)


@router.post("/{target_id}/delete")
def delete_target(target_id: str, db: Session = Depends(get_db)):
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(404, "Target not found")
    audit_log(db, actor=settings.operator_name, action="target_deleted", target_id=target.id,
               details={"name": target.name, "value": target.value})
    db.delete(target)
    db.commit()
    return RedirectResponse("/targets", status_code=303)
