import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class TargetType(str, enum.Enum):
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    IP = "ip"
    IP_RANGE = "ip_range"


class Tier(str, enum.Enum):
    SELF_OWNED = "self_owned"
    THIRD_PARTY = "third_party"


class VerificationStatus(str, enum.Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"


class VerificationMethod(str, enum.Enum):
    DNS_TXT = "dns_txt"
    WELL_KNOWN_FILE = "well_known_file"
    SELF_ATTESTATION = "self_attestation"


class AuthDocStatus(str, enum.Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ScanModule(str, enum.Enum):
    NETWORK = "network"
    DEPENDENCY = "dependency"
    WEBAPP = "webapp"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Most to least severe -- use this for ordering, never the enum's string value.
SEVERITY_RANK = {severity: i for i, severity in enumerate(Severity)}


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255))
    target_type: Mapped[TargetType] = mapped_column(Enum(TargetType))
    value: Mapped[str] = mapped_column(String(255))
    tier: Mapped[Tier] = mapped_column(Enum(Tier))

    verification_status: Mapped[VerificationStatus] = mapped_column(
        Enum(VerificationStatus), default=VerificationStatus.PENDING
    )
    verification_method: Mapped[VerificationMethod | None] = mapped_column(
        Enum(VerificationMethod), nullable=True
    )
    verification_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    consents: Mapped[list["Consent"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    authorizations: Mapped[list["AuthorizationDocument"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    scan_runs: Mapped[list["ScanRun"]] = relationship(back_populates="target", cascade="all, delete-orphan")

    @property
    def is_verified(self) -> bool:
        return self.verification_status == VerificationStatus.VERIFIED

    @property
    def has_consent(self) -> bool:
        return len(self.consents) > 0

    def active_authorization(self) -> "AuthorizationDocument | None":
        now = _now()
        for doc in self.authorizations:
            if doc.status != AuthDocStatus.ACTIVE:
                continue
            start = doc.window_start
            end = doc.window_end
            if start and start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
            if end and end.tzinfo is None:
                end = end.replace(tzinfo=timezone.utc)
            if start and now < start:
                continue
            if end and now > end:
                continue
            return doc
        return None

    def is_scannable(self) -> tuple[bool, str]:
        """Server-side allow-list check. Returns (allowed, reason_if_not)."""
        if not self.is_verified:
            return False, "Target has not completed ownership verification."
        if not self.has_consent:
            return False, "No consent/legal attestation on file for this target."
        if self.tier == Tier.THIRD_PARTY:
            if self.active_authorization() is None:
                return False, "No active signed authorization document on file for this target."
        return True, ""


class Consent(Base):
    __tablename__ = "consents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"))
    attestation_text: Mapped[str] = mapped_column(Text)
    accepted_by: Mapped[str] = mapped_column(String(255))
    accepted_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    target: Mapped["Target"] = relationship(back_populates="consents")


class AuthorizationDocument(Base):
    __tablename__ = "authorization_documents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"))

    encrypted_file_path: Mapped[str] = mapped_column(String(500))
    original_filename: Mapped[str] = mapped_column(String(255))

    authorizer_name: Mapped[str] = mapped_column(String(255))
    authorizer_role: Mapped[str] = mapped_column(String(255))
    authorizer_contact: Mapped[str] = mapped_column(String(255))
    scope_description: Mapped[str] = mapped_column(Text)
    authorized_scan_types: Mapped[str] = mapped_column(String(255))

    window_start: Mapped[datetime] = mapped_column(DateTime)
    window_end: Mapped[datetime] = mapped_column(DateTime)

    status: Mapped[AuthDocStatus] = mapped_column(Enum(AuthDocStatus), default=AuthDocStatus.ACTIVE)
    uploaded_by: Mapped[str] = mapped_column(String(255))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    target: Mapped["Target"] = relationship(back_populates="authorizations")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"))

    modules: Mapped[list] = mapped_column(JSON, default=list)
    intensity: Mapped[str] = mapped_column(String(20), default="standard")
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING)

    initiated_by: Mapped[str] = mapped_column(String(255))
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    results_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    target: Mapped["Target"] = relationship(back_populates="scan_runs")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan_run", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_run_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_runs.id"))

    category: Mapped[ScanModule] = mapped_column(Enum(ScanModule))
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    affected_asset: Mapped[str] = mapped_column(String(500))
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    scan_run: Mapped["ScanRun"] = relationship(back_populates="findings")


class AuditLogEntry(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_now)
    actor: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(100))
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    scan_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
