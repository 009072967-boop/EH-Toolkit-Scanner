from dataclasses import dataclass

from app.models import Severity


@dataclass
class RawFinding:
    severity: Severity
    title: str
    description: str
    remediation: str
    affected_asset: str
    evidence: str | None = None


class ScanEngineError(RuntimeError):
    """Raised when a scan engine cannot complete (bad input, tool missing, timeout)."""
