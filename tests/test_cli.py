import secrets

import pytest
from cryptography.hazmat.primitives import serialization as ser

from ping import cli, messaging, util


@pytest.fixture(autouse=True)
def restore_messaging_pki(monkeypatch):
    # cli.main installs a bridge into messaging.pki; put the original back after each test.
    monkeypatch.setattr(messaging, "pki", messaging.pki)


class Script:
    """Feeds scripted answers to getpass and input, and records everything printed."""

    def __init__(self, secrets_=(), inputs=()):
        self.secrets, self.inputs, self.lines = list(secrets_), list(inputs), []

    def getpass(self, prompt=""):
        return self.secrets.pop(0)

    def input_fn(self, prompt=""):
        if not self.inputs:
            raise EOFError
        return self.inputs.pop(0)

    def out(self, *parts):
        self.lines.append(" ".join(str(p) for p in parts))

    @property
    def text(self):
        return "\n".join(self.lines)


def run(home, argv, secrets_=(), inputs=(), trace=False):
    s = Script(secrets_, inputs)
    code = cli.main((["--trace"] if trace else []) + ["--home", str(home)] + argv,
                    getpass=s.getpass, input_fn=s.input_fn, out=s.out)
    return code, s


@pytest.fixture
def world(tmp_home):
    """init-pki, alice and bobby signed up and approved, all through main()."""
    w = dict(home=tmp_home, root=secrets.token_urlsafe(16), sub=secrets.token_urlsafe(16),
             pw=secrets.token_urlsafe(16))
    code, s = run(tmp_home, ["init-pki"], [w["root"], w["root"], w["sub"], w["sub"]])
    assert code == 0, s.text
    for u in ("alice", "bobby"):
        code, s = run(tmp_home, ["signup"], [w["pw"], w["pw"]], [u, "y"])
        assert code == 0, s.text
        code, s = run(tmp_home, ["ca", "approve", u], [w["sub"]])
        assert code == 0, s.text
    return w


def test_render_each_item_type():
    ts = 1795776000                                          # 2026-11-27 10:40 UTC
    assert cli.render(messaging.Message("id", 0, "alice", ts, "hola", "f.json")) == "[2026-11-27 10:40] alice: hola"
    assert cli.render(messaging.Rejected("x.json", "bad signature")) == "⚠ REJECTED (x.json): bad signature"
    assert cli.render(messaging.Warning("MISSING", "1 message missing")) == "1 message missing"


def test_full_flow_through_main(world):
    h, pw = world["home"], world["pw"]
    code, s = run(h, ["login"], [pw], ["alice", "open bobby", "hello bob, from alice", "/back", "logout"])
    assert code == 0, s.text
    assert "(sent)" in s.text
    code, s = run(h, ["login"], [pw], ["bobby", "open alice", "/back", "logout"])
    assert code == 0, s.text
    assert "alice: hello bob, from alice" in s.text
    assert "REJECTED" not in s.text


def test_signup_aborted_at_fingerprint_prompt(world):
    code, s = run(world["home"], ["signup"], [world["pw"], world["pw"]], ["carol", "n"])
    assert code == 1 and "aborted" in s.text
    assert not (world["home"] / "users" / "carol").exists()


def test_chats_lists_only_my_conversations(world):
    h, pw = world["home"], world["pw"]
    run(h, ["login"], [pw], ["alice", "open bobby", "hi", "/back", "logout"])
    (h / "mail" / "carol__dave").mkdir()                     # two other users
    (h / "mail" / "Junk Name").mkdir()                       # junk is ignored
    (h / "mail" / "alice__").mkdir()
    code, s = run(h, ["login"], [pw], ["alice", "chats", "logout"])
    assert "bobby" in s.lines
    assert not any(x in s.text for x in ("carol", "dave", "Junk"))


def test_fingerprints_command(world):
    code, s = run(world["home"], ["login"], [world["pw"]], ["alice", "fingerprints", "logout"])
    assert "root (pinned)" in s.text and "sign" in s.text and "kem" in s.text


def test_wrong_login_prints_one_generic_line_and_exits_1(world):
    for user, pw in (("alice", "wrong-password-123"), ("nobody", world["pw"])):
        code, s = run(world["home"], ["login"], [pw], [user])
        assert code == 1
        assert s.lines == ["error: wrong username or password"]


def test_ca_commands_on_missing_pki(tmp_home):
    code, s = run(tmp_home, ["ca", "list"])
    assert code == 1 and "init-pki" in s.text
    code, s = run(tmp_home, ["ca", "approve", "alice"], ["whatever-passphrase"])
    assert code == 1 and s.text.startswith("error:")


def test_init_pki_twice_exits_1(world):
    code, s = run(world["home"], ["init-pki"], [world["root"]] * 2 + [world["sub"]] * 2)
    assert code == 1 and "already exists" in s.text


def test_ca_list_and_renew(world):
    run(world["home"], ["signup"], [world["pw"], world["pw"]], ["carol", "y"])
    code, s = run(world["home"], ["ca", "list"])
    assert s.lines == ["carol"]
    code, s = run(world["home"], ["ca", "renew", "alice"], [world["sub"]])
    assert code == 0 and "Renewed" in s.text


def test_trace_flag_prints_crypto_lines_without_secrets(world, capsys):
    h, pw = world["home"], world["pw"]
    code, s = run(h, ["login"], [pw], ["alice", "open bobby", "traced message", "/back", "logout"], trace=True)
    printed = capsys.readouterr().out                        # util.trace prints to stdout
    assert code == 0
    assert "[trace]" in printed
    assert "HMAC verifier" in printed                        # login steps
    assert "verified bobby's KEM certificate" in printed     # messaging steps
    from ping import accounts
    session = accounts.login(h, "alice", pw)
    leaks = [pw, world["sub"], world["root"], session.k_file.hex()]
    for priv in (session.keys.sign_priv, session.keys.kem_priv):
        leaks.append(priv.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption()).hex())
    for secret in leaks:
        assert secret not in printed and secret not in s.text


def test_unknown_command_and_missing_peer_do_not_traceback(world):
    code, s = run(world["home"], ["frobnicate"])
    assert code == 1 and s.text.startswith("error:")
    code, s = run(world["home"], ["login"], [world["pw"]],
                  ["alice", "dance", "open", "open zed", "open ../x", "open alice", "logout"])
    assert code == 0
    assert "unknown command" in s.text and "usage: open <peer>" in s.text
    assert s.text.count("error:") >= 3                       # zed (no cert), ../x, yourself
    assert "Traceback" not in s.text


def test_eof_in_menu_logs_out(world):
    code, s = run(world["home"], ["login"], [world["pw"]], ["alice"])     # no more input
    assert code == 0 and "Bye." in s.text


def test_mismatched_password_at_signup(world):
    code, s = run(world["home"], ["signup"], [world["pw"], world["pw"] + "x"], ["carol"])
    assert code == 1 and "do not match" in s.text


def test_util_trace_is_off_after_main(world):
    run(world["home"], ["ca", "list"], trace=True)
    assert util._trace_on is False
