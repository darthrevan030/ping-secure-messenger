"""Shared helpers: canonical JSON, base64url, safe file I/O, trace output."""

import base64
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

_USERNAME = re.compile(r"^[a-z0-9_]{3,32}$")
_trace_on = False


class TooLarge(Exception):
    """A file exceeds its size limit (checked before reading or parsing)."""


def canon(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def valid_username(s: str) -> str:
    if not isinstance(s, str) or not _USERNAME.fullmatch(s):
        raise ValueError("invalid username (use 3-32 chars of a-z, 0-9, _)")
    return s


def atomic_write(path, data: bytes, mode: int = 0o600) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def create_exclusive(path, data: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def read_limited(path, limit: int) -> bytes:
    if os.stat(path).st_size > limit:
        raise TooLarge(f"{Path(path).name} exceeds {limit} bytes")
    with open(path, "rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise TooLarge(f"{Path(path).name} exceeds {limit} bytes")
    return data


def set_trace(on: bool) -> None:
    global _trace_on
    _trace_on = on


def trace(msg: str) -> None:
    if _trace_on:
        print(f"[trace] {msg}")
