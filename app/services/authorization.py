"""Tier 2 (third-party) signed authorization document handling.

The app can confirm a document exists, is linked to a specific target, has
the required fields filled in, and has a valid (non-expired) time window —
it cannot verify the signature is genuine or that the signer had authority to
grant it. Treat every Tier 2 target as something the operator personally
reviews before the first scan; this module enforces the paperwork, not the
trust decision.
"""

import uuid
from datetime import datetime
from pathlib import Path

from app.config import settings
from app.security import decrypt_bytes, encrypt_bytes

ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".docx"}
MAX_UPLOAD_BYTES = 15 * 1024 * 1024


class InvalidAuthorizationDocument(ValueError):
    pass


def validate_window(window_start: datetime, window_end: datetime) -> None:
    if window_end <= window_start:
        raise InvalidAuthorizationDocument("Authorization end date must be after the start date.")


def store_document(original_filename: str, content: bytes) -> str:
    """Encrypts and writes the uploaded document to disk, returns the storage path."""
    ext = Path(original_filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise InvalidAuthorizationDocument(
            f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )
    if len(content) > MAX_UPLOAD_BYTES:
        raise InvalidAuthorizationDocument("File exceeds the 15MB upload limit.")
    if len(content) == 0:
        raise InvalidAuthorizationDocument("Uploaded file is empty.")

    stored_name = f"{uuid.uuid4()}{ext}.enc"
    dest = settings.auth_docs_path / stored_name
    dest.write_bytes(encrypt_bytes(content))
    return str(dest)


def read_document(encrypted_file_path: str) -> bytes:
    return decrypt_bytes(Path(encrypted_file_path).read_bytes())
