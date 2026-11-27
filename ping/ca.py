"""Offline CA admin tool: `ping init-pki`, `ping ca list`, `ping ca approve <u>`, `ping ca renew <u>`.

Sign-up writes requests/<u>.json. Approval checks it and issues the two
certificates into certs/<u>/. Only this module ever opens the CA keys.
"""
import json
import os
import shutil
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

from ping import auth, keystore, pki, util

BIND_CONTEXT = b"ping/v1/kem-bind"
MAX_REQUEST = 64 * 1024
MIN_PASSPHRASE = auth.MIN_PASSWORD_LEN  # 12
_REQUEST_FIELDS = {"v", "user", "csr", "ek", "bind"}


class CAError(Exception):
    """The CA refused an operation (bad request, wrong passphrase, ...). The message says why."""


def _pki_dir(home) -> Path:
    return Path(home) / "pki"


# ---------- CA private keys: sealed with a key derived from a passphrase ----------

def _seal_ca_key(path: Path, private_key, passphrase: str, role: str) -> None:
    kdf = keystore.kdf_params(auth.new_salt())                 # Scrypt parameters + random salt
    kek = keystore.kek_from_passphrase(passphrase, kdf)        # passphrase -> AES-256 key
    der = private_key.private_bytes(serialization.Encoding.DER,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
    container = keystore.seal(der, kek, owner="ca", role=role,
                              pub_fp=util.fingerprint(pki._spki(private_key.public_key())), kdf=kdf)
    util.create_exclusive(path, json.dumps(container, indent=2).encode())   # never overwrite, mode 0600


def _open_ca_key(home, role: str, passphrase: str):
    """Open root.key.json or sub.key.json. CAError on a wrong passphrase or a tampered file."""
    label = "Root" if role == "root" else "sub-CA"
    try:
        container = json.loads(util.read_limited(_pki_dir(home) / f"{role}.key.json", MAX_REQUEST))
        der = keystore.open(container, keystore.kek_from_passphrase(passphrase, container["kdf"]))
    except InvalidTag:
        raise CAError(f"wrong {label} passphrase (or the key file was tampered with)") from None
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise CAError(f"cannot read the {label} key file: {e}") from None
    # The tag only proves the file is intact; check it is the right key for the right certificate.
    if container["owner"] != "ca" or container["role"] != role:
        raise CAError(f"{role}.key.json is not the {label} key")
    key = serialization.load_der_private_key(der, password=None)
    cert = pki._load_pem(_pki_dir(home) / f"{role}.crt.pem")
    if util.fingerprint(pki._spki(key.public_key())) != container["pub_fp"] or \
            util.fingerprint(pki._spki(cert.public_key())) != container["pub_fp"]:
        raise CAError(f"{label} key does not match its certificate")
    return key, cert


# ---------- init-pki ----------

def init_pki(home, root_pass: str, sub_pass: str, now=None) -> str:
    """Create the Root CA and the Sub-CA. Returns the Root fingerprint, which
    every user confirms and pins at sign-up."""
    for pw in (root_pass, sub_pass):
        if len(pw) < MIN_PASSPHRASE:
            raise ValueError(f"CA passphrases need at least {MIN_PASSPHRASE} characters")
    if root_pass == sub_pass:
        raise ValueError("Root and Sub-CA passphrases must differ")
    d = _pki_dir(home)
    if d.exists():
        raise FileExistsError(f"{d} already exists; refusing to overwrite the PKI")
    d.mkdir(parents=True, mode=0o700)

    root_key, root_cert = pki.create_root(now)
    sub_key, sub_cert = pki.create_sub(root_key, root_cert, now)
    _seal_ca_key(d / "root.key.json", root_key, root_pass, "root")
    _seal_ca_key(d / "sub.key.json", sub_key, sub_pass, "sub")
    util.atomic_write(d / "root.crt.pem", root_cert.public_bytes(serialization.Encoding.PEM), 0o644)
    util.atomic_write(d / "sub.crt.pem", sub_cert.public_bytes(serialization.Encoding.PEM), 0o644)
    del root_key  # the Root key is not kept after signing the Sub-CA certificate
    return pki.root_fingerprint(root_cert)


# ---------- requests ----------

def build_request(user: str, sign_key, kem_public_key) -> dict:
    """The request file sign-up writes: CSR (signed with the ML-DSA key) + KEM key + binding."""
    util.valid_username(user)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(pki._name(user))
           .sign(sign_key, None))
    ek_der = pki._spki(kem_public_key)
    bind = sign_key.sign(pki.bind_message(user, ek_der), context=BIND_CONTEXT)
    return {"v": 1, "user": user,
            "csr": csr.public_bytes(serialization.Encoding.PEM).decode(),
            "ek": util.b64e(ek_der), "bind": util.b64e(bind)}


def list_pending(home) -> list[str]:
    """Names of requests waiting for approval (name check only; approve validates the rest)."""
    d = Path(home) / "requests"
    names = []
    for p in sorted(d.glob("*.json")) if d.exists() else []:
        try:
            names.append(util.valid_username(p.stem))
        except ValueError:
            continue
    return names


def _read_request(home, user: str) -> dict:
    path = Path(home) / "requests" / f"{user}.json"
    if not path.exists():
        raise CAError(f"no pending request for {user!r}")
    try:
        req = json.loads(util.read_limited(path, MAX_REQUEST))
    except util.TooLarge:
        raise CAError("request file is too large") from None
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise CAError("request file is not valid JSON") from None
    if not isinstance(req, dict) or set(req) != _REQUEST_FIELDS or req["v"] != 1 \
            or not all(isinstance(req[k], str) for k in ("user", "csr", "ek", "bind")):
        raise CAError("request file has the wrong format")
    if req["user"] != user:
        raise CAError("request file names another user")
    return req


def _check_request(req: dict, user: str):
    """Return (sign_pub, kem_pub) if the request is acceptable, CAError otherwise."""
    # 1. The CSR is self-signed with the user's ML-DSA-65 key and names the user.
    try:
        csr = x509.load_pem_x509_csr(req["csr"].encode())
        valid = csr.is_signature_valid
    except ValueError:
        raise CAError("CSR is malformed") from None
    if not valid:
        raise CAError("CSR signature is invalid")
    sign_pub = csr.public_key()
    if not isinstance(sign_pub, mldsa.MLDSA65PublicKey):
        raise CAError("CSR key is not ML-DSA-65")
    if pki._cn(csr.subject) != user:
        raise CAError("CSR common name does not match the requested user")
    # 2. The KEM key is an ML-KEM-768 key...
    try:
        ek_der = util.b64d(req["ek"])
        kem_pub = serialization.load_der_public_key(ek_der)
        bind = util.b64d(req["bind"])
    except ValueError:
        raise CAError("KEM key or binding is malformed") from None
    if not isinstance(kem_pub, mlkem.MLKEM768PublicKey):
        raise CAError("KEM key is not ML-KEM-768")
    # 3. ...bound to the same person: signed with the CSR key.
    try:
        sign_pub.verify(bind, pki.bind_message(user, ek_der), context=BIND_CONTEXT)
    except InvalidSignature:
        raise CAError("KEM binding signature is invalid") from None
    return sign_pub, kem_pub


# ---------- approve and renew ----------

def approve(home, user: str, sub_pass: str, now=None) -> None:
    """Check the pending request and issue the user's sign and KEM certificates."""
    util.valid_username(user)                       # before any path is built
    req = _read_request(home, user)
    certs = Path(home) / "certs"
    if (certs / user).exists():
        raise CAError(f"{user!r} already has certificates")
    sign_pub, kem_pub = _check_request(req, user)

    sub_key, sub_cert = _open_ca_key(home, "sub", sub_pass)
    # The CA sets every field itself; nothing requested in the CSR is copied.
    sign_cert = pki.issue_user_cert(sub_key, sub_cert, user, sign_pub, "sign", now)
    kem_cert = pki.issue_user_cert(sub_key, sub_cert, user, kem_pub, "kem", now)

    # All or nothing: write both into certs/<u>.tmp/, then rename the folder into place.
    tmp = certs / f"{user}.tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    try:
        for purpose, cert in (("sign", sign_cert), ("kem", kem_cert)):
            util.atomic_write(tmp / f"{purpose}.crt.pem", cert.public_bytes(serialization.Encoding.PEM), 0o644)
        os.rename(tmp, certs / user)                # fails if certs/<u> appeared meanwhile
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    (Path(home) / "requests" / f"{user}.json").unlink()


def renew(home, user: str, sub_pass: str, now=None) -> None:
    """Issue fresh certificates for the user's existing keys (e.g. after they expired)."""
    util.valid_username(user)
    try:
        old = {p: pki.load_cert(home, user, p) for p in pki.PURPOSES}
    except FileNotFoundError:
        raise CAError(f"{user!r} has no certificates to renew") from None
    sub_key, sub_cert = _open_ca_key(home, "sub", sub_pass)
    for purpose in pki.PURPOSES:                    # same keys, new validity window
        cert = pki.issue_user_cert(sub_key, sub_cert, user, old[purpose].public_key(), purpose, now)
        util.atomic_write(Path(home) / "certs" / user / f"{purpose}.crt.pem",
                          cert.public_bytes(serialization.Encoding.PEM), 0o644)
