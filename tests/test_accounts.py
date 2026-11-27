import datetime as dt
import json
import logging
import shutil

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import mldsa

from ping import accounts, auth, ca, pki, util
from tests.real_env import RealEnv


@pytest.fixture
def env(tmp_home):
    return RealEnv(tmp_home)


def nothing_for(home, name):
    return not any(p.exists() for p in (home / "users" / name, home / "requests" / f"{name}.json",
                                        home / "certs" / name))


# ---------- sign-up ----------

def test_signup_writes_files_and_request(env):
    env.signup("alice")
    u = env.home / "users" / "alice"
    for f in ("account.json", "sign.key.json", "kem.key.json", "trust.json"):
        assert (u / f).exists()
    req = json.loads((env.home / "requests" / "alice.json").read_text())
    csr = x509.load_pem_x509_csr(req["csr"].encode())
    assert pki._cn(csr.subject) == "alice"
    ca._check_request(req, "alice")                 # CSR signature and bind verify
    account = (u / "account.json").read_text()
    assert env.PASSWORD not in account
    assert set(json.loads(account)) == {"v", "user", "salt", "verifier"}
    session = env_login_after_approval(env, "alice")
    assert session.k_file.hex() not in account
    assert csr.public_key() == session.keys.sign_priv.public_key()


def env_login_after_approval(env, name):
    ca.approve(env.home, name, env.SUB_PASS)
    return accounts.login(env.home, name, env.PASSWORD)


def test_signup_shows_root_fingerprint_and_abort_writes_nothing(env):
    seen = []

    def refuse(fp):
        seen.append(fp)
        return False

    with pytest.raises(RuntimeError, match="aborted"):
        accounts.signup(env.home, "alice", env.PASSWORD, refuse)
    root = pki._load_pem(env.home / "pki" / "root.crt.pem")
    assert seen == [pki.root_fingerprint(root)]
    assert nothing_for(env.home, "alice")


def test_signup_refuses_taken_names_and_bad_input(env, tmp_path):
    env.signup("alice")                                             # user dir + request
    with pytest.raises(ValueError, match="taken"):
        env.signup("alice")
    shutil.rmtree(env.home / "users" / "alice")                     # only the request left
    with pytest.raises(ValueError, match="taken"):
        env.signup("alice")
    (env.home / "certs" / "bobby").mkdir(parents=True)              # only issued certs
    with pytest.raises(ValueError, match="taken"):
        env.signup("bobby")
    assert not (env.home / "users" / "bobby").exists()
    for bad_name in ("../x", "Alice", "ab"):
        with pytest.raises(ValueError):
            env.signup(bad_name)
    with pytest.raises(ValueError, match="at least 12"):
        env.signup("carol", password="short")
    assert nothing_for(env.home, "carol")
    with pytest.raises(ValueError, match="init-pki"):              # no PKI at all
        accounts.signup(tmp_path / "empty", "carol", env.PASSWORD, lambda fp: True)


def test_signup_failure_midway_releases_the_name(env, monkeypatch):
    def broken(path, data):
        raise OSError("disk full")

    monkeypatch.setattr(util, "create_exclusive", broken)
    with pytest.raises(OSError):
        env.signup("alice")
    assert nothing_for(env.home, "alice")
    monkeypatch.undo()
    env.signup("alice")                                             # the name is free again
    assert (env.home / "requests" / "alice.json").exists()


# ---------- login ----------

def test_login_before_approval_is_pending(env):
    env.signup("alice")
    with pytest.raises(accounts.PendingApproval):
        accounts.login(env.home, "alice", env.PASSWORD)


def test_login_returns_working_session(env):
    s = env.add_user("alice")
    assert s.user == "alice"
    assert s.pinned_root_fp == env.root_fp
    assert len(s.k_file) == 32
    assert pki._spki(pki.load_cert(env.home, "alice", "sign").public_key()) == s.keys.sign_pub_der
    assert pki._spki(pki.load_cert(env.home, "alice", "kem").public_key()) == s.keys.kem_pub_der


def test_wrong_password_and_unknown_user_are_indistinguishable(env, monkeypatch):
    env.add_user("alice")
    calls = []
    real = auth.derive

    def spy(password, salt):
        calls.append(1)
        return real(password, salt)

    monkeypatch.setattr(auth, "derive", spy)
    errors = []
    for name, pw in (("alice", "wrong-password-123"), ("nobody", env.PASSWORD)):
        calls.clear()
        with pytest.raises(accounts.LoginError) as e:
            accounts.login(env.home, name, pw)
        errors.append(str(e.value))
        assert len(calls) == 1                      # one Scrypt either way
    assert errors[0] == errors[1] == "wrong username or password"


@pytest.mark.parametrize("victim", ["sign.key.json", "trust.json"])
def test_tampered_key_file_is_reported_as_tampered(env, victim):
    env.add_user("alice")
    path = env.home / "users" / "alice" / victim
    c = json.loads(path.read_text())
    ct = bytearray(util.b64d(c["ct"]))
    ct[0] ^= 1                                       # flip one bit of the ciphertext
    c["ct"] = util.b64e(bytes(ct))
    path.write_text(json.dumps(c))
    with pytest.raises(accounts.TamperedError):
        accounts.login(env.home, "alice", env.PASSWORD)


def test_swapped_key_file_between_users_is_refused(env):
    env.add_user("alice")
    env.add_user("bobby")
    shutil.copy(env.home / "users" / "bobby" / "sign.key.json", env.home / "users" / "alice" / "sign.key.json")
    with pytest.raises(accounts.TamperedError):
        accounts.login(env.home, "alice", env.PASSWORD)


def test_login_with_swapped_root_file_is_refused(env):
    env.add_user("alice")
    _, rogue = pki.create_root()
    util.atomic_write(env.home / "pki" / "root.crt.pem", rogue.public_bytes(ser.Encoding.PEM), 0o644)
    with pytest.raises(accounts.CertificateProblem, match="pin"):
        accounts.login(env.home, "alice", env.PASSWORD)


def test_login_with_expired_certificate(env, monkeypatch):
    env.add_user("alice")
    future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=400)
    monkeypatch.setattr(accounts, "_now", lambda: future)
    with pytest.raises(accounts.CertificateProblem, match="certificate expired: ask the CA to renew"):
        accounts.login(env.home, "alice", env.PASSWORD)
    ca.renew(env.home, "alice", env.SUB_PASS, now=future)
    assert accounts.login(env.home, "alice", env.PASSWORD).user == "alice"


def test_login_refuses_certificate_for_other_keys(env):
    env.add_user("alice")
    sub_key, sub_cert = ca._open_ca_key(env.home, "sub", env.SUB_PASS)
    other = pki.issue_user_cert(sub_key, sub_cert, "alice", mldsa.MLDSA65PrivateKey.generate().public_key(), "sign")
    util.atomic_write(env.home / "certs" / "alice" / "sign.crt.pem", other.public_bytes(ser.Encoding.PEM), 0o644)
    with pytest.raises(accounts.CertificateProblem, match="does not match your key"):
        accounts.login(env.home, "alice", env.PASSWORD)


def test_trace_and_logs_never_contain_secrets(env, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    util.set_trace(True)
    try:
        env.signup("alice")
        ca.approve(env.home, "alice", env.SUB_PASS)
        s = accounts.login(env.home, "alice", env.PASSWORD)
    finally:
        util.set_trace(False)
    out = capsys.readouterr().out + caplog.text
    assert "[trace]" in out
    secrets_ = [env.PASSWORD, env.SUB_PASS, env.ROOT_PASS, s.k_file.hex()]
    for priv in (s.keys.sign_priv, s.keys.kem_priv):
        der = priv.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption())
        secrets_ += [der.hex(), util.b64e(der)]
    for secret in secrets_:
        assert secret not in out
