import datetime as dt
import hashlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

from ping import pki, util


def write(home, rel, cert):
    util.atomic_write(home / rel, cert.public_bytes(ser.Encoding.PEM), 0o644)


@pytest.fixture
def chain(tmp_home):
    """A real chain built with the builders: pki/root, pki/sub, certs/alice/{sign,kem}."""
    root_key, root = pki.create_root()
    sub_key, sub = pki.create_sub(root_key, root)
    sk, dk = mldsa.MLDSA65PrivateKey.generate(), mlkem.MLKEM768PrivateKey.generate()
    sign = pki.issue_user_cert(sub_key, sub, "alice", sk.public_key(), "sign")
    kem = pki.issue_user_cert(sub_key, sub, "alice", dk.public_key(), "kem")
    write(tmp_home, "pki/root.crt.pem", root)
    write(tmp_home, "pki/sub.crt.pem", sub)
    write(tmp_home, "certs/alice/sign.crt.pem", sign)
    write(tmp_home, "certs/alice/kem.crt.pem", kem)
    return dict(home=tmp_home, root_key=root_key, root=root, sub_key=sub_key, sub=sub,
                sign=sign, kem=kem, sk=sk, dk=dk, pin=pki.root_fingerprint(root))


def ok(c, cert=None, purpose="sign", user="alice", **kw):
    assert pki.verify_chain(c["home"], cert or c[purpose], purpose, user, c["pin"], **kw) is None


def rejected(c, cert, purpose, text, user="alice", **kw):
    with pytest.raises(pki.ChainError, match=text):
        pki.verify_chain(c["home"], cert, purpose, user, c["pin"], **kw)


def raw_cert(subject, issuer, pub, signer, *, ca, path_length=None, ku=pki.KU_SIGN, san=None, days=365):
    """A certificate built directly with cryptography, to break one property at a time."""
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(pki._name(subject)).issuer_name(pki._name(issuer))
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
         .add_extension(ku, critical=True))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san)]), critical=False)
    return b.sign(signer, None)


def test_valid_chain_verifies_for_both_purposes(chain):
    ok(chain, purpose="sign")
    ok(chain, purpose="kem")


def test_rogue_root_rejected(chain):
    """A leaf from a second, unrelated PKI."""
    rk, rroot = pki.create_root()
    rsk, rsub = pki.create_sub(rk, rroot)
    fake = pki.issue_user_cert(rsk, rsub, "alice", chain["sk"].public_key(), "sign")
    ok(chain)
    rejected(chain, fake, "sign", "bad issuer")


def test_swapped_root_file_rejected_by_pin(chain):
    ok(chain)
    _, other_root = pki.create_root()
    write(chain["home"], "pki/root.crt.pem", other_root)
    rejected(chain, chain["sign"], "sign", "root fingerprint does not match pin")


def test_expired_and_not_yet_valid(chain):
    leaf = chain["sign"]
    ok(chain)
    rejected(chain, leaf, "sign", "certificate expired", at=leaf.not_valid_after_utc + dt.timedelta(seconds=1))
    rejected(chain, leaf, "sign", "certificate not yet valid", at=leaf.not_valid_before_utc - dt.timedelta(seconds=1))


def test_expired_sub_ca(chain):
    long_ago = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=pki.SUB_DAYS + 10)
    old_sub_key, old_sub = pki.create_sub(chain["root_key"], chain["root"], now=long_ago)
    write(chain["home"], "pki/sub.crt.pem", old_sub)
    leaf = pki.issue_user_cert(old_sub_key, old_sub, "alice", chain["sk"].public_key(), "sign")
    rejected(chain, leaf, "sign", "certificate expired")


def test_kem_cert_as_signing_cert_and_reverse(chain):
    ok(chain, purpose="sign")
    rejected(chain, chain["kem"], "sign", "wrong key type")
    rejected(chain, chain["sign"], "kem", "wrong key type")


def test_wrong_key_usage(chain):
    """Right key type, but KeyUsage says KEM: the type check passes, KeyUsage catches it."""
    leaf = raw_cert("alice", pki.SUB_NAME, chain["sk"].public_key(), chain["sub_key"],
                    ca=False, ku=pki.KU_KEM, san="ping:user:alice")
    rejected(chain, leaf, "sign", "wrong key usage")


def test_ca_cert_as_leaf(chain):
    leaf = raw_cert("alice", pki.SUB_NAME, chain["sk"].public_key(), chain["sub_key"],
                    ca=True, path_length=0, san="ping:user:alice")
    rejected(chain, leaf, "sign", "leaf is a CA certificate")


def test_sub_ca_path_length(chain):
    sk2 = mldsa.MLDSA65PrivateKey.generate()
    for path_length, ca, text in ((1, True, "path length"), (None, False, "not a CA")):
        sub = raw_cert(pki.SUB_NAME, pki.ROOT_NAME, sk2.public_key(), chain["root_key"],
                       ca=ca, path_length=path_length, ku=pki.KU_CA)
        write(chain["home"], "pki/sub.crt.pem", sub)
        leaf = pki.issue_user_cert(sk2, sub, "alice", chain["sk"].public_key(), "sign")
        rejected(chain, leaf, "sign", text)


def test_wrong_cn_and_wrong_san(chain):
    ok(chain)
    rejected(chain, chain["sign"], "sign", "wrong subject", user="bobby")
    leaf = raw_cert("alice", pki.SUB_NAME, chain["sk"].public_key(), chain["sub_key"],
                    ca=False, san="ping:user:bobby")
    rejected(chain, leaf, "sign", "wrong subject")


def test_cert_properties(chain):
    bc = lambda c: c.extensions.get_extension_for_class(x509.BasicConstraints).value  # noqa: E731
    ku = lambda c: c.extensions.get_extension_for_class(x509.KeyUsage).value  # noqa: E731
    for c in (chain["sign"], chain["kem"]):
        assert bc(c).ca is False
        san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert san.get_values_for_type(x509.UniformResourceIdentifier) == ["ping:user:alice"]
        assert (c.not_valid_after_utc - c.not_valid_before_utc) == dt.timedelta(days=365) + pki.CLOCK_SKEW
    assert ku(chain["sign"]).digital_signature and not ku(chain["sign"]).key_encipherment
    assert ku(chain["kem"]).key_encipherment and not ku(chain["kem"]).digital_signature
    assert bc(chain["sub"]).path_length == 0
    assert (chain["sub"].not_valid_after_utc - chain["sub"].not_valid_before_utc).days == pki.SUB_DAYS
    chain["root"].verify_directly_issued_by(chain["root"])   # self-signed


def test_load_cert_missing_raises_filenotfound(chain):
    assert pki.load_cert(chain["home"], "alice", "sign") == chain["sign"]
    with pytest.raises(FileNotFoundError):
        pki.load_cert(chain["home"], "bobby", "sign")
    with pytest.raises(ValueError):
        pki.load_cert(chain["home"], "../x", "sign")


def test_bind_message_known_value():
    fp = hashlib.sha256(b"\x00").hexdigest()
    assert pki.bind_message("alice", b"\x00") == ('{"ek_fp":"%s","user":"alice"}' % fp).encode()


def test_issue_rejects_wrong_key_types(chain):
    with pytest.raises(ValueError):
        pki.issue_user_cert(chain["sub_key"], chain["sub"], "alice", chain["dk"].public_key(), "sign")
    with pytest.raises(ValueError):
        pki.issue_user_cert(chain["sub_key"], chain["sub"], "alice", chain["sk"].public_key(), "kem")
