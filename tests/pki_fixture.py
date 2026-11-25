"""Test-only mini-PKI standing in for Person B's `ping.pki` until it lands.

Deliberately re-implements a minimal verify_chain; Task 8 of the plan swaps the
messaging tests onto the real one.
"""

import datetime as dt
from dataclasses import dataclass
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.x509.oid import NameOID

from ping import keystore, util


class ChainError(Exception):
    pass


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _spki(pub):
    return pub.public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)


def _build(subject, pub, issuer, ikey, *, ca, ku=None, expired=False):
    now = dt.datetime.now(dt.timezone.utc)
    nb, na = (now - dt.timedelta(days=2), now - dt.timedelta(days=1)) if expired else (
        now - dt.timedelta(minutes=5), now + dt.timedelta(days=30))
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True))
    if ku:
        b = b.add_extension(ku, critical=True)
    return b.sign(ikey, None)


@dataclass
class CA:
    root_key: object
    root_cert: x509.Certificate
    sub_key: object
    sub_cert: x509.Certificate
    label: str

    @property
    def root_fp(self):
        return util.fingerprint(_spki(self.root_cert.public_key()))


def make_ca(label="ping") -> CA:
    rk, sk = mldsa.MLDSA87PrivateKey.generate(), mldsa.MLDSA65PrivateKey.generate()
    rc = _build(f"{label}-root", rk.public_key(), f"{label}-root", rk, ca=True)
    sc = _build(f"{label}-sub", sk.public_key(), f"{label}-root", rk, ca=True)
    return CA(rk, rc, sk, sc, label)


def issue(ca: CA, user, pub, purpose, *, expired=False) -> x509.Certificate:
    ku = x509.KeyUsage(
        digital_signature=purpose == "sign", content_commitment=False,
        key_encipherment=purpose == "kem", data_encipherment=False, key_agreement=False,
        key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False)
    return _build(user, pub, f"{ca.label}-sub", ca.sub_key, ca=False, ku=ku, expired=expired)


def write_cert(home, user, purpose, cert):
    util.atomic_write(home / "certs" / user / f"{purpose}.crt.pem",
                      cert.public_bytes(ser.Encoding.PEM), 0o644)


class Env:
    def __init__(self, home):
        self.home = home
        self.ca, self.rogue = make_ca("ping"), make_ca("rogue")
        for name, cert in (("root", self.ca.root_cert), ("sub", self.ca.sub_cert)):
            util.atomic_write(home / "pki" / f"{name}.crt.pem", cert.public_bytes(ser.Encoding.PEM), 0o644)
        self.pki = SimpleNamespace(ChainError=ChainError, load_cert=self._load_cert,
                                   verify_chain=self._verify_chain)

    def add_user(self, name, *, ca=None, expired=False):
        """Generate keys, issue both certs (by `ca`, default the trusted one), return a Session."""
        ca = ca or self.ca
        keys = keystore.generate_user_keys()
        write_cert(self.home, name, "sign", issue(ca, name, keys.sign_priv.public_key(), "sign", expired=expired))
        write_cert(self.home, name, "kem", issue(ca, name, keys.kem_priv.public_key(), "kem", expired=expired))
        return keystore.Session(self.home, name, keys, self.ca.root_fp)

    @staticmethod
    def _load_cert(home, user, purpose):
        return x509.load_pem_x509_certificate((home / "certs" / user / f"{purpose}.crt.pem").read_bytes())

    def _verify_chain(self, cert, purpose, user, pinned_root_fp, at=None):
        at = at or dt.datetime.now(dt.timezone.utc)
        load = lambda n: x509.load_pem_x509_certificate((self.home / "pki" / f"{n}.crt.pem").read_bytes())
        root, sub = load("root"), load("sub")
        if util.fingerprint(_spki(root.public_key())) != pinned_root_fp:
            raise ChainError("root fingerprint does not match pin")
        try:
            cert.verify_directly_issued_by(sub)
            sub.verify_directly_issued_by(root)
        except Exception as e:
            raise ChainError(f"bad issuer: {e}") from e
        for c in (cert, sub, root):
            if not c.not_valid_before_utc <= at <= c.not_valid_after_utc:
                raise ChainError("certificate not valid at this time")
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ChainError("leaf is a CA certificate")
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not (ku.digital_signature if purpose == "sign" else ku.key_encipherment):
            raise ChainError(f"certificate not valid for {purpose}")
        if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != user:
            raise ChainError("wrong subject")
