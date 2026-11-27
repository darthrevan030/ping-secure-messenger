import datetime as dt
import json
import secrets

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

from ping import ca, keystore, pki, util


def new_pass():
    return secrets.token_urlsafe(16)   # random per run: no passphrase is written in the code


@pytest.fixture
def home(tmp_home):
    root_pass, sub_pass = new_pass(), new_pass()
    pin = ca.init_pki(tmp_home, root_pass, sub_pass)
    return dict(path=tmp_home, root_pass=root_pass, sub_pass=sub_pass, pin=pin)


def make_request(home, name, **tamper):
    """Write a valid request the way sign-up will, optionally breaking one field."""
    sk, dk = mldsa.MLDSA65PrivateKey.generate(), mlkem.MLKEM768PrivateKey.generate()
    req = ca.build_request(name, sk, dk.public_key())
    req.update(tamper)
    util.create_exclusive(home["path"] / "requests" / f"{name}.json", json.dumps(req).encode())
    return sk, dk


def csr_pem(sk, cn, *extensions):
    b = x509.CertificateSigningRequestBuilder().subject_name(pki._name(cn))
    for ext in extensions:
        b = b.add_extension(ext, critical=False)
    return b.sign(sk, None).public_bytes(ser.Encoding.PEM).decode()


def refused(home, name, text):
    with pytest.raises(ca.CAError, match=text):
        ca.approve(home["path"], name, home["sub_pass"])
    assert not (home["path"] / "certs" / name).exists()
    assert (home["path"] / "requests" / f"{name}.json").exists()


# ---------- init-pki ----------

def test_init_pki_creates_sealed_keys_and_certs(home):
    d = home["path"] / "pki"
    root = x509.load_pem_x509_certificate((d / "root.crt.pem").read_bytes())
    assert home["pin"] == pki.root_fingerprint(root)
    for role, right, wrong in (("root", home["root_pass"], home["sub_pass"]),
                               ("sub", home["sub_pass"], home["root_pass"])):
        c = json.loads((d / f"{role}.key.json").read_text())
        keystore.open(c, keystore.kek_from_passphrase(right, c["kdf"]))
        with pytest.raises(InvalidTag):
            keystore.open(c, keystore.kek_from_passphrase(wrong, c["kdf"]))
    root_container = json.loads((d / "root.key.json").read_text())
    assert root_container["pub_fp"] == util.fingerprint(pki._spki(root.public_key()))


def test_init_pki_refuses_second_run(home):
    d = home["path"] / "pki"
    before = {p.name: p.read_bytes() for p in d.iterdir()}
    with pytest.raises(FileExistsError):
        ca.init_pki(home["path"], new_pass(), new_pass())
    assert {p.name: p.read_bytes() for p in d.iterdir()} == before


def test_init_pki_rejects_short_or_equal_passphrases(tmp_path):
    with pytest.raises(ValueError):
        ca.init_pki(tmp_path / "a", "short", new_pass())
    same = new_pass()
    with pytest.raises(ValueError):
        ca.init_pki(tmp_path / "b", same, same)


# ---------- approve ----------

def test_approve_issues_both_certs_that_verify(home):
    sk, dk = make_request(home, "alice")
    assert ca.list_pending(home["path"]) == ["alice"]
    ca.approve(home["path"], "alice", home["sub_pass"])
    for purpose, key in (("sign", sk), ("kem", dk)):
        cert = pki.load_cert(home["path"], "alice", purpose)
        pki.verify_chain(home["path"], cert, purpose, "alice", home["pin"])
        assert cert.public_key() == key.public_key()
    assert not (home["path"] / "requests" / "alice.json").exists()
    assert ca.list_pending(home["path"]) == []


def test_approve_ignores_requested_extensions(home):
    sk = mldsa.MLDSA65PrivateKey.generate()
    greedy = csr_pem(sk, "alice", x509.BasicConstraints(ca=True, path_length=None),
                     x509.SubjectAlternativeName([x509.UniformResourceIdentifier("ping:user:bobby")]))
    dk = mlkem.MLKEM768PrivateKey.generate()
    req = ca.build_request("alice", sk, dk.public_key())
    req["csr"] = greedy
    util.create_exclusive(home["path"] / "requests" / "alice.json", json.dumps(req).encode())
    ca.approve(home["path"], "alice", home["sub_pass"])
    cert = pki.load_cert(home["path"], "alice", "sign")
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == ["ping:user:alice"]


def test_approve_refuses_bad_csr_signature(home):
    sk = mldsa.MLDSA65PrivateKey.generate()
    pem = csr_pem(sk, "alice")
    der = bytearray(x509.load_pem_x509_csr(pem.encode()).public_bytes(ser.Encoding.DER))
    der[-10] ^= 1                                              # flip a bit in the signature
    broken = x509.load_der_x509_csr(bytes(der)).public_bytes(ser.Encoding.PEM).decode()
    make_request(home, "alice", csr=broken)
    refused(home, "alice", "CSR signature is invalid")


def test_approve_refuses_bad_bind(home):
    other = mldsa.MLDSA65PrivateKey.generate()                 # bind signed by a different key
    _, dk = make_request(home, "alice")
    ek_der = pki._spki(dk.public_key())
    bad = other.sign(pki.bind_message("alice", ek_der), context=ca.BIND_CONTEXT)
    req_path = home["path"] / "requests" / "alice.json"
    req = json.loads(req_path.read_text())
    req["bind"] = util.b64e(bad)
    req_path.write_text(json.dumps(req))
    refused(home, "alice", "binding")


def test_approve_refuses_bind_over_another_kem_key(home):
    mallory_ek = pki._spki(mlkem.MLKEM768PrivateKey.generate().public_key())
    make_request(home, "alice", ek=util.b64e(mallory_ek))     # swap the KEM key, keep alice's bind
    refused(home, "alice", "binding")


def test_approve_refuses_csr_cn_mismatch(home):
    sk = mldsa.MLDSA65PrivateKey.generate()
    make_request(home, "alice", csr=csr_pem(sk, "bobby"))
    refused(home, "alice", "common name")


def test_approve_refuses_name_already_issued(home):
    make_request(home, "alice")
    ca.approve(home["path"], "alice", home["sub_pass"])
    first = pki.load_cert(home["path"], "alice", "sign")
    make_request(home, "alice")
    with pytest.raises(ca.CAError, match="already has certificates"):
        ca.approve(home["path"], "alice", home["sub_pass"])
    assert pki.load_cert(home["path"], "alice", "sign") == first     # untouched
    assert (home["path"] / "requests" / "alice.json").exists()


def test_approve_refuses_wrong_sub_passphrase(home):
    make_request(home, "alice")
    with pytest.raises(ca.CAError, match="wrong sub-CA passphrase"):
        ca.approve(home["path"], "alice", home["root_pass"])
    assert not (home["path"] / "certs" / "alice").exists()


def test_approve_refuses_missing_request(home):
    with pytest.raises(ca.CAError, match="no pending request"):
        ca.approve(home["path"], "alice", home["sub_pass"])


def test_approve_refuses_kem_key_of_wrong_type(home):
    big = pki._spki(mlkem.MLKEM1024PrivateKey.generate().public_key())
    make_request(home, "alice", ek=util.b64e(big))
    refused(home, "alice", "ML-KEM-768")


@pytest.mark.parametrize("content, text", [
    (b"", "not valid JSON"),
    (b"not json", "not valid JSON"),
    (b"[1,2]", "wrong format"),
    (b'{"v":1}', "wrong format"),
    (b"x" * (ca.MAX_REQUEST + 1), "too large"),
], ids=["empty", "text", "list", "partial", "huge"])
def test_approve_refuses_garbage_request_files(home, content, text):
    (home["path"] / "requests").mkdir()
    (home["path"] / "requests" / "alice.json").write_bytes(content)
    refused(home, "alice", text)


def test_approve_is_all_or_nothing(home, monkeypatch):
    make_request(home, "alice")
    real = util.atomic_write

    def fail_on_kem(path, data, mode=0o600):
        if str(path).endswith("kem.crt.pem"):
            raise OSError("disk full")
        real(path, data, mode)

    monkeypatch.setattr(util, "atomic_write", fail_on_kem)
    with pytest.raises(OSError):
        ca.approve(home["path"], "alice", home["sub_pass"])
    assert not (home["path"] / "certs" / "alice").exists()
    monkeypatch.setattr(util, "atomic_write", real)
    ca.approve(home["path"], "alice", home["sub_pass"])
    assert (home["path"] / "certs" / "alice" / "kem.crt.pem").exists()


def test_list_pending_skips_bad_files(home):
    make_request(home, "alice")
    d = home["path"] / "requests"
    (d / "Bad Name.json").write_text("x")
    (d / "notes.txt").write_text("x")
    (d / "bobby.json").write_bytes(b"")                       # listed by name, refused at approve
    assert ca.list_pending(home["path"]) == ["alice", "bobby"]


def test_every_path_argument_is_validated(home):
    with pytest.raises(ValueError):
        ca.approve(home["path"], "../x", home["sub_pass"])
    with pytest.raises(ValueError):
        ca.renew(home["path"], "Bob", home["sub_pass"])


# ---------- renew ----------

def test_renew_keeps_keys_and_extends_validity(home):
    long_ago = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=400)
    make_request(home, "alice")
    ca.approve(home["path"], "alice", home["sub_pass"], now=long_ago)
    old = pki.load_cert(home["path"], "alice", "sign")
    with pytest.raises(pki.ChainError, match="certificate expired"):
        pki.verify_chain(home["path"], old, "sign", "alice", home["pin"])
    ca.renew(home["path"], "alice", home["sub_pass"])
    for purpose in pki.PURPOSES:
        new = pki.load_cert(home["path"], "alice", purpose)
        pki.verify_chain(home["path"], new, purpose, "alice", home["pin"])
    new = pki.load_cert(home["path"], "alice", "sign")
    assert new.public_key() == old.public_key()
    assert new.not_valid_after_utc > old.not_valid_after_utc


def test_renew_refuses_unknown_user_and_wrong_passphrase(home):
    with pytest.raises(ca.CAError, match="no certificates"):
        ca.renew(home["path"], "alice", home["sub_pass"])
    make_request(home, "alice")
    ca.approve(home["path"], "alice", home["sub_pass"])
    with pytest.raises(ca.CAError, match="wrong sub-CA passphrase"):
        ca.renew(home["path"], "alice", home["root_pass"])


def test_request_file_naming_another_user_refused(home):
    """requests/alice.json whose content says it is bobby's request."""
    sk, dk = mldsa.MLDSA65PrivateKey.generate(), mlkem.MLKEM768PrivateKey.generate()
    req = ca.build_request("bobby", sk, dk.public_key())
    util.create_exclusive(home["path"] / "requests" / "alice.json", json.dumps(req).encode())
    refused(home, "alice", "another user")
