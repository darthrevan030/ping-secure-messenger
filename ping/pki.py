"""Mini-PKI: Root CA -> Sub-CA -> two certificates per user.

    Root   ML-DSA-87   signs only the Sub-CA certificate, then stays sealed.
    Sub-CA ML-DSA-65   signs each user's signing cert and KEM cert.
    User   ML-DSA-65 cert (digitalSignature)   +   ML-KEM-768 cert (keyEncipherment)

Every time a public key is used, the caller runs verify_chain(). Nothing is
cached as "trusted".
"""
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.x509.oid import NameOID

from ping import util

# The higher a certificate is in the hierarchy, the longer it lasts:
# a certificate should never outlive the certificate of whoever signed it.
ROOT_DAYS = 3650   # 10 years
SUB_DAYS = 1825    # 5 years
USER_DAYS = 365    # 1 year
CLOCK_SKEW = datetime.timedelta(minutes=5)  # not_valid_before is set 5 min in the past

ROOT_NAME = "Ping Root CA"
SUB_NAME = "Ping Sub-CA"
PURPOSES = ("sign", "kem")

# Let us now define the capabilities of each key: 9 booleans that determine whether the key is allowed to perform each action.
# KeyUsage(digital_signature, content_commitment, key_encipherment, data_encipherment, key_agreement, key_cert_sign, crl_sign, encipher_only, decipher_only)
KU_CA = x509.KeyUsage(False, False, False, False, False, True, True, False, False)
KU_SIGN = x509.KeyUsage(True, False, False, False, False, False, False, False, False)
KU_KEM = x509.KeyUsage(False, False, True, False, False, False, False, False, False)


# ERROR class:
class ChainError(Exception):
    """A certificate failed a check. The message says which one."""
# ChainError: the certificate is not trusted. Messaging shows it as
# "sender certificate invalid: <text>", so the texts below are part of the interface:
# root fingerprint does not match pin, bad issuer, certificate expired, certificate not yet valid,
# not a CA, path length, leaf is a CA certificate, wrong key type, wrong key usage, wrong subject.


# Let us set up functions that will be often used, each explained in the line before def.

# Actual time given in UTC time
def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# Picks a common name
def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


# Public key in SubjectPublicKeyInfo DER (binary) form.
# We use DER instead of PEM because PEM is base64 with headers, so a line break or a single
# extra space would change the fingerprint without changing the key.
def _spki(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)


# Root fingerprint: SHA-256 (hex) of the Root's public key. This is what every user
# confirms at sign-up and keeps sealed in trust.json (the pin).
def root_fingerprint(root_cert: x509.Certificate) -> str:
    return util.fingerprint(_spki(root_cert.public_key()))


# The message a user signs to tie their KEM key to their signing key (see ca.approve).
def bind_message(user: str, ek_der: bytes) -> bytes:
    return util.canon({"user": user, "ek_fp": util.fingerprint(ek_der)})


# load_cert and _load_pem read certificates in PEM format: the text
# format (it starts with -----BEGIN CERTIFICATE-----) that can be opened and inspected.
def load_cert(home, user: str, purpose: str) -> x509.Certificate:
    """certs/<user>/<purpose>.crt.pem. FileNotFoundError if the user has none yet."""
    if purpose not in PURPOSES:
        raise ValueError("purpose must be 'sign' or 'kem'")
    path = Path(home) / "certs" / util.valid_username(user) / f"{purpose}.crt.pem"
    return _load_pem(path)


def _load_pem(path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


# ---------- building certificates ----------

# Building certificates rely on the next function, and it is used by the three types of certificates: Root, Sub-CA and user
def _build_cert(*, subject: str, issuer: str, public_key, signer, days: int, now,
                ca: bool, path_length, key_usage: x509.KeyUsage, san_user: str | None = None):
    now = now or _now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))   # 1. Who the certificate is for
        .issuer_name(_name(issuer))     # 2. Who signs it
        .public_key(public_key)         # 3. The key being certified
        .serial_number(x509.random_serial_number()) # 4. Random serial number
        .not_valid_before(now - CLOCK_SKEW)          # 5. Validity window
        .not_valid_after(now + datetime.timedelta(days=days)) # 5. Validity window
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True) # 6. BasicConstraints: Checks if the certificate is CA and route length to check its position in hierarchy
        .add_extension(key_usage, critical=True) # 7. KeyUsage
    )
    if san_user is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(f"ping:user:{san_user}")]),
            critical=False)
    # ML-DSA signs the whole TBS certificate itself, so the hash argument is None.
    return builder.sign(signer, None)


def create_root(now=None):
    """New Root CA: ML-DSA-87 key and self-signed certificate (CA, path length 1)."""
    key = mldsa.MLDSA87PrivateKey.generate()
    cert = _build_cert(subject=ROOT_NAME, issuer=ROOT_NAME, public_key=key.public_key(),
                       signer=key, days=ROOT_DAYS, now=now, ca=True, path_length=1,
                       key_usage=KU_CA)
    util.trace(f"ML-DSA-87.KeyGen + self-sign Root -> cert {len(cert.public_bytes(serialization.Encoding.DER))} B")
    return key, cert


def create_sub(root_key, root_cert, now=None):
    """New Sub-CA: ML-DSA-65 key, certificate signed by the Root (CA, path length 0)."""
    key = mldsa.MLDSA65PrivateKey.generate()
    cert = _build_cert(subject=SUB_NAME, issuer=_cn(root_cert.subject), public_key=key.public_key(),
                       signer=root_key, days=SUB_DAYS, now=now, ca=True, path_length=0,
                       key_usage=KU_CA)
    util.trace(f"ML-DSA-65.KeyGen + Root signs Sub-CA -> cert {len(cert.public_bytes(serialization.Encoding.DER))} B")
    return key, cert


def issue_user_cert(sub_key, sub_cert, user: str, public_key, purpose: str, now=None):
    """The CA builds the user certificate itself: it ignores anything the user asked
    for and sets subject, SAN, KeyUsage and BasicConstraints."""
    util.valid_username(user)
    if purpose == "sign":
        if not isinstance(public_key, mldsa.MLDSA65PublicKey):
            raise ValueError("signing key must be ML-DSA-65")
        key_usage = KU_SIGN
    elif purpose == "kem":
        if not isinstance(public_key, mlkem.MLKEM768PublicKey):
            raise ValueError("KEM key must be ML-KEM-768")
        key_usage = KU_KEM
    else:
        raise ValueError("purpose must be 'sign' or 'kem'")
    cert = _build_cert(subject=user, issuer=_cn(sub_cert.subject), public_key=public_key,
                       signer=sub_key, days=USER_DAYS, now=now, ca=False, path_length=None,
                       key_usage=key_usage, san_user=user)
    util.trace(f"Sub-CA ML-DSA-65.Sign {purpose} cert for {user} -> {len(cert.public_bytes(serialization.Encoding.DER))} B")
    return cert


def _cn(name: x509.Name) -> str:
    cns = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return cns[0].value if len(cns) == 1 else ""


# ---------- verification, run on every use of a public key ----------

def _ext(cert, cls, label):
    try:
        return cert.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        raise ChainError(f"{label} certificate has no {cls.__name__}") from None


def _check_signed_by(cert, issuer_cert, label: str) -> None:
    try:
        # Checks issuer name == issuer's subject AND the signature with the issuer's key.
        cert.verify_directly_issued_by(issuer_cert)
    except Exception as e:  # noqa: BLE001  InvalidSignature, ValueError, TypeError: all mean "not this issuer"
        raise ChainError(f"bad issuer: {label} certificate is not signed by its issuer") from e


def _check_validity(cert, at, label: str) -> None:
    if at < cert.not_valid_before_utc:
        raise ChainError(f"certificate not yet valid ({label})")
    if at > cert.not_valid_after_utc:
        raise ChainError(f"certificate expired ({label})")


def verify_chain(home, cert: x509.Certificate, purpose: str, user: str,
                 pinned_root_fp: str, at=None) -> None:
    """Check that `cert` is a valid `purpose` ("sign" or "kem") certificate for
    `user`, chained to the pinned Root. Returns None, raises ChainError."""
    if purpose not in PURPOSES:
        raise ValueError("purpose must be 'sign' or 'kem'")
    at = at or _now()
    root = _load_pem(Path(home) / "pki" / "root.crt.pem")
    sub = _load_pem(Path(home) / "pki" / "sub.crt.pem")

    # 1. Trust anchor: the shared root file must be the Root this user pinned.
    if root_fingerprint(root) != pinned_root_fp:
        raise ChainError("root fingerprint does not match pin")
    util.trace("Root fingerprint == pinned ✔")

    # 2. Each link: Root self-signed, Sub-CA signed by Root, leaf signed by Sub-CA.
    _check_signed_by(root, root, "Root")
    _check_signed_by(sub, root, "Sub-CA")
    _check_signed_by(cert, sub, "user")
    util.trace(f"ML-DSA.Verify Root->Sub-CA->{user} ({purpose}) ✔")

    # 3. Validity of all three at `at`.
    for c, label in ((root, "Root"), (sub, "Sub-CA"), (cert, "user")):
        _check_validity(c, at, label)

    # 4. BasicConstraints and path length: Root and Sub are CAs, the Sub-CA may
    #    only sign end users (pathlen 0), the leaf is not a CA.
    for c, label in ((root, "Root"), (sub, "Sub-CA")):
        if not _ext(c, x509.BasicConstraints, label).ca or not _ext(c, x509.KeyUsage, label).key_cert_sign:
            raise ChainError(f"not a CA ({label})")
    if _ext(sub, x509.BasicConstraints, "Sub-CA").path_length != 0:
        raise ChainError("path length of the Sub-CA must be 0")
    if _ext(cert, x509.BasicConstraints, "user").ca:
        raise ChainError("leaf is a CA certificate")

    # 5. Key types: Root ML-DSA-87, Sub-CA ML-DSA-65, leaf by purpose.
    expected = mldsa.MLDSA65PublicKey if purpose == "sign" else mlkem.MLKEM768PublicKey
    for c, cls, label in ((root, mldsa.MLDSA87PublicKey, "Root"),
                          (sub, mldsa.MLDSA65PublicKey, "Sub-CA"),
                          (cert, expected, "user")):
        if not isinstance(c.public_key(), cls):
            raise ChainError(f"wrong key type ({label})")

    # 6. KeyUsage must match what the key is used for, and nothing else.
    ku = _ext(cert, x509.KeyUsage, "user")
    if purpose == "sign" and not (ku.digital_signature and not ku.key_encipherment):
        raise ChainError("wrong key usage: not a signing certificate")
    if purpose == "kem" and not (ku.key_encipherment and not ku.digital_signature):
        raise ChainError("wrong key usage: not a KEM certificate")

    # 7. Identity: CN and SAN must both name the expected user.
    if _cn(cert.subject) != user:
        raise ChainError(f"wrong subject: certificate is not for {user!r}")
    san = _ext(cert, x509.SubjectAlternativeName, "user")
    if san.get_values_for_type(x509.UniformResourceIdentifier) != [f"ping:user:{user}"]:
        raise ChainError(f"wrong subject: SAN is not ping:user:{user}")
