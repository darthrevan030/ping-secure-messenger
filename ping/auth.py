"""Password hardening: Scrypt, then an HKDF split into a login key and a file key."""

import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SCRYPT = {"n": 2**17, "r": 8, "p": 1}
MIN_PASSWORD_LEN = 12


def new_salt() -> bytes:
    return os.urandom(16)


def _hkdf(pw_key: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(
        pw_key
    )


def derive(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """Return (k_auth, k_file). k_auth only proves the password; k_file opens key files."""
    pw_key = Scrypt(salt=salt, length=32, **SCRYPT).derive(password.encode("utf-8"))
    return _hkdf(pw_key, b"ping/auth"), _hkdf(pw_key, b"ping/keyfile")


def make_verifier(k_auth: bytes) -> bytes:
    return hmac.digest(k_auth, b"ping/login-v1", "sha256")


def check_verifier(k_auth: bytes, verifier: bytes) -> bool:
    return hmac.compare_digest(make_verifier(k_auth), verifier)


def check_password_policy(password: str) -> None:
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")
