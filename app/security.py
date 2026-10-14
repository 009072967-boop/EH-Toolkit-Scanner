import base64
import hashlib
import json
import secrets

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.config import settings

# Derive a stable Fernet key from SECRET_KEY so no separate key file is needed.
# Salt is fixed/app-wide: this protects data at rest against casual disk access
# (e.g. a stolen backup), not against someone who already has SECRET_KEY.
_KDF_SALT = b"defensive-pentest-scanner-auth-docs"


def _fernet() -> Fernet:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=_KDF_SALT, iterations=390_000)
    key = base64.urlsafe_b64encode(kdf.derive(settings.secret_key.encode("utf-8")))
    return Fernet(key)


def encrypt_bytes(data: bytes) -> bytes:
    return _fernet().encrypt(data)


def decrypt_bytes(token: bytes) -> bytes:
    return _fernet().decrypt(token)


def generate_verification_token() -> str:
    return secrets.token_hex(16)


def hash_results(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
