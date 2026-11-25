"""AES-GCM sealed containers for private keys and per-user files, plus user key files."""

import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ping import auth, util

_FIELDS = {"v", "alg", "kdf", "owner", "role", "pub_fp", "nonce", "ct"}
_MAX_KEY_FILE = 64 * 1024


def _aad(container: dict) -> bytes:
    return util.canon({k: v for k, v in container.items() if k != "ct"})


def seal(payload: bytes, kek: bytes, *, owner: str, role: str, pub_fp: str, kdf) -> dict:
    container = {
        "v": 1,
        "alg": "AES-256-GCM",
        "kdf": kdf,
        "owner": owner,
        "role": role,
        "pub_fp": pub_fp,
        "nonce": util.b64e(os.urandom(12)),
    }
    ct = AESGCM(kek).encrypt(util.b64d(container["nonce"]), payload, _aad(container))
    container["ct"] = util.b64e(ct)
    return container


def open(container: dict, kek: bytes) -> bytes:  # noqa: A001 - name fixed by the interface
    """Authenticate and decrypt. Raises InvalidTag on any tampering, ValueError if malformed."""
    if not isinstance(container, dict) or set(container) != _FIELDS:
        raise ValueError("malformed key container")
    if container["v"] != 1 or container["alg"] != "AES-256-GCM":
        raise ValueError("unsupported key container version or algorithm")
    try:
        nonce = util.b64d(container["nonce"])
        ct = util.b64d(container["ct"])
    except (ValueError, TypeError) as e:
        raise ValueError("malformed key container") from e
    if len(nonce) != 12:
        raise ValueError("malformed key container")
    return AESGCM(kek).decrypt(nonce, ct, _aad(container))


def kdf_params(salt: bytes) -> dict:
    return {"name": "scrypt", **auth.SCRYPT, "salt": util.b64e(salt)}


def kek_from_passphrase(passphrase: str, kdf: dict) -> bytes:
    return Scrypt(
        salt=util.b64d(kdf["salt"]), length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]
    ).derive(passphrase.encode("utf-8"))


@dataclass(frozen=True)
class UserKeys:
    sign_priv: mldsa.MLDSA65PrivateKey
    kem_priv: mlkem.MLKEM768PrivateKey
    sign_pub_der: bytes
    kem_pub_der: bytes


@dataclass(frozen=True)
class Session:
    home: Path
    user: str
    keys: UserKeys
    pinned_root_fp: str


def _spki(priv) -> bytes:
    return priv.public_key().public_bytes(
        ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo
    )


def _pkcs8(priv) -> bytes:
    return priv.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption())


def _keys_from(sign_priv, kem_priv) -> UserKeys:
    return UserKeys(sign_priv, kem_priv, _spki(sign_priv), _spki(kem_priv))


def generate_user_keys() -> UserKeys:
    return _keys_from(mldsa.MLDSA65PrivateKey.generate(), mlkem.MLKEM768PrivateKey.generate())


def _user_dir(home, user: str) -> Path:
    return Path(home) / "users" / util.valid_username(user)


def _write_container(path: Path, container: dict) -> None:
    util.atomic_write(path, json.dumps(container).encode("utf-8"))


def _read_container(path: Path, user: str, role: str, k_file: bytes) -> tuple[dict, bytes]:
    try:
        container = json.loads(util.read_limited(path, _MAX_KEY_FILE))
    except json.JSONDecodeError as e:
        raise ValueError(f"malformed key container: {path.name}") from e
    payload = open(container, k_file)  # authenticate first, then trust the metadata
    if container["owner"] != user:
        raise ValueError(f"{path.name}: owner mismatch")
    if container["role"] != role:
        raise ValueError(f"{path.name}: unexpected role {container['role']!r}")
    return container, payload


def write_user_keys(home, user: str, keys: UserKeys, k_file: bytes) -> None:
    d = _user_dir(home, user)
    for name, role, priv, pub_der in (
        ("sign.key.json", "user-sign", keys.sign_priv, keys.sign_pub_der),
        ("kem.key.json", "user-kem", keys.kem_priv, keys.kem_pub_der),
    ):
        container = seal(
            _pkcs8(priv), k_file, owner=user, role=role,
            pub_fp=util.fingerprint(pub_der), kdf="user-login",
        )
        _write_container(d / name, container)


def load_user_keys(home, user: str, k_file: bytes) -> UserKeys:
    d = _user_dir(home, user)
    loaded = []
    for name, role, cls in (
        ("sign.key.json", "user-sign", mldsa.MLDSA65PrivateKey),
        ("kem.key.json", "user-kem", mlkem.MLKEM768PrivateKey),
    ):
        container, der = _read_container(d / name, user, role, k_file)
        priv = ser.load_der_private_key(der, None)
        if not isinstance(priv, cls):
            raise ValueError(f"{name}: wrong key type")
        if util.fingerprint(_spki(priv)) != container["pub_fp"]:
            raise ValueError(f"{name}: pub_fp mismatch")
        loaded.append(priv)
    return _keys_from(*loaded)


def write_trust(home, user: str, root_fp: str, k_file: bytes) -> None:
    container = seal(
        root_fp.encode("utf-8"), k_file, owner=user, role="user-trust",
        pub_fp=root_fp, kdf="user-login",
    )
    _write_container(_user_dir(home, user) / "trust.json", container)


def read_trust(home, user: str, k_file: bytes) -> str:
    container, payload = _read_container(
        _user_dir(home, user) / "trust.json", user, "user-trust", k_file
    )
    root_fp = payload.decode("utf-8")
    if root_fp != container["pub_fp"]:
        raise ValueError("trust.json: pub_fp mismatch")
    return root_fp
