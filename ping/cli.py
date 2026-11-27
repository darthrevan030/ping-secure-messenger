"""Command-line interface (plan B, Task 4).

    uv run python -m ping [--home DIR] [--trace] init-pki
    uv run python -m ping [--home DIR] [--trace] ca list | ca approve <u> | ca renew <u>
    uv run python -m ping [--home DIR] [--trace] signup
    uv run python -m ping [--home DIR] [--trace] login      -> menu: chats, open <peer>, fingerprints, logout

Passwords and passphrases are only read through `getpass` (never echoed in clear,
never taken from the command line). Every handled error prints one line, never a traceback.
"""
import argparse
import datetime as dt
import getpass as _getpass
import os
import sys
import types
from pathlib import Path

from cryptography import x509

from ping import accounts, ca, messaging, pki, util

DEFAULT_HOME = "./ping_data"

# Errors a user can cause or meet: shown as one line, exit code 1.
HANDLED = (ValueError, FileExistsError, FileNotFoundError, RuntimeError, ca.CAError,
           accounts.LoginError, accounts.PendingApproval, accounts.TamperedError,
           accounts.CertificateProblem, pki.ChainError, util.TooLarge)


# ---------- password input with visible asterisks ----------

def read_secret(prompt: str) -> str:
    """Like getpass, but shows one * per character on Windows so you can see it is typing."""
    if os.name != "nt" or not sys.stdin.isatty():
        return _getpass.getpass(prompt)
    import msvcrt
    print(prompt, end="", flush=True)
    chars = []
    while True:
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):            # Enter
            print()
            return "".join(chars)
        if ch == "\x03":                  # Ctrl+C
            raise KeyboardInterrupt
        if ch == "\x08":                  # Backspace
            if chars:
                chars.pop()
                print("\b \b", end="", flush=True)
        elif ch in ("\x00", "\xe0"):      # arrow/function keys: ignore
            msvcrt.getwch()
        else:
            chars.append(ch)
            print("*", end="", flush=True)


# ---------- temporary bridge until Person A's Task 9 ----------

def bridge_messaging(home) -> None:
    """Person A's messaging still calls pki.verify_chain(cert, ...) without `home`
    (A's Task 9 changes that). Until then, insert `home` here. Once A's code passes
    `home` itself, calls go straight through, so this is harmless and can then be deleted."""
    home = Path(home)

    def verify_chain(*args, **kwargs):
        if args and isinstance(args[0], x509.Certificate):
            return pki.verify_chain(home, *args, **kwargs)
        return pki.verify_chain(*args, **kwargs)

    messaging.pki = types.SimpleNamespace(ChainError=pki.ChainError, load_cert=pki.load_cert,
                                          verify_chain=verify_chain)


# ---------- rendering ----------

def render(item) -> str:
    if isinstance(item, messaging.Message):
        when = dt.datetime.fromtimestamp(item.ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M")
        return f"[{when}] {item.sender}: {item.text}"
    if isinstance(item, messaging.Rejected):
        return f"⚠ REJECTED ({item.file}): {item.reason}"
    if isinstance(item, messaging.Warning):
        return item.text
    return str(item)


def my_conversations(home, me: str) -> list[str]:
    """Peers I have a conversation with: mail/<a>__<b>/ with me as a or b."""
    peers = []
    d = Path(home) / "mail"
    for p in sorted(d.iterdir()) if d.is_dir() else []:
        a, sep, b = p.name.partition("__")
        if not (sep and p.is_dir()):
            continue
        try:
            util.valid_username(a), util.valid_username(b)
        except ValueError:
            continue                                  # junk directory names are ignored
        if a < b and me in (a, b):
            peers.append(b if a == me else a)
    return peers


# ---------- commands ----------

def _new_secret(getpass, label: str) -> str:
    first = getpass(f"{label} (12+ characters): ")
    if getpass("  repeat it: ") != first:
        raise ValueError("the two entries do not match")
    return first


def _cmd_init_pki(args, getpass, input_fn, out) -> int:
    root_pass = _new_secret(getpass, "New Root CA passphrase")
    sub_pass = _new_secret(getpass, "New Sub-CA passphrase")
    out("Creating the Root CA (ML-DSA-87) and the Sub-CA (ML-DSA-65)...")
    fp = ca.init_pki(args.home, root_pass, sub_pass)
    out(f"Done. Root fingerprint (users must confirm it at sign-up):\n  {fp}")
    return 0


def _cmd_ca(args, getpass, input_fn, out) -> int:
    if args.ca_cmd == "list":
        if not (Path(args.home) / "pki").exists():
            raise ValueError("no PKI here yet: run init-pki first")
        pending = ca.list_pending(args.home)
        out("\n".join(pending) if pending else "(no pending requests)")
        return 0
    sub_pass = getpass("Sub-CA passphrase: ")
    if args.ca_cmd == "approve":
        ca.approve(args.home, args.user, sub_pass)
        out(f"Approved {args.user}: sign and KEM certificates issued (valid 1 year).")
    else:
        ca.renew(args.home, args.user, sub_pass)
        out(f"Renewed {args.user}'s certificates (same keys, new validity).")
    return 0


def _cmd_signup(args, getpass, input_fn, out) -> int:
    user = input_fn("Username: ").strip()
    util.valid_username(user)
    password = _new_secret(getpass, "Password")

    def confirm(fp: str) -> bool:
        out("Root CA fingerprint of this installation:")
        out(f"  {fp}")
        return input_fn("Does it match the one the admin gave you? [y/N] ").strip().lower() == "y"

    accounts.signup(args.home, user, password, confirm)
    out(f"Account {user!r} created. Ask the admin to run: ca approve {user}")
    return 0


def _cmd_login(args, getpass, input_fn, out) -> int:
    user = input_fn("Username: ").strip()
    session = accounts.login(args.home, user, getpass("Password: "))
    out(f"Logged in as {session.user}. Commands: chats, open <peer>, fingerprints, logout")
    _menu(session, input_fn, out)
    return 0


def _menu(session, input_fn, out) -> None:
    while True:
        try:
            line = input_fn(f"{session.user}> ").strip()
        except EOFError:
            line = "logout"
        cmd, _, rest = line.partition(" ")
        try:
            if cmd == "logout":
                out("Bye.")
                return
            if cmd == "chats":
                peers = my_conversations(session.home, session.user)
                out("\n".join(peers) if peers else "(no conversations yet: try `open <peer>`)")
            elif cmd == "fingerprints":
                for label, fp in accounts.fingerprints(session).items():
                    out(f"  {label:14} {fp}")
            elif cmd == "open":
                if not rest.strip():
                    out("usage: open <peer>")
                else:
                    _conversation(session, rest.strip(), input_fn, out)
            elif cmd in ("", "help"):
                out("Commands: chats, open <peer>, fingerprints, logout")
            else:
                out(f"unknown command {cmd!r}. Commands: chats, open <peer>, fingerprints, logout")
        except HANDLED as e:
            out(f"error: {e}")


def _conversation(session, peer: str, input_fn, out) -> None:
    def show():
        items = messaging.open_conversation(session, peer)
        out(f"--- conversation with {peer} ---")
        for item in items:
            out(render(item))
        if not items:
            out("(no messages yet)")
        out("--- type a message and press Enter; /refresh to reload, /back to leave ---")

    show()
    while True:
        try:
            text = input_fn(f"{session.user} -> {peer}> ")
        except EOFError:
            return
        if text.strip() == "/back":
            return
        if text.strip() == "/refresh":
            show()
        elif text.strip():
            try:
                messaging.send(session, peer, text)
                out("(sent)")
            except HANDLED as e:
                out(f"error: {e}")


# ---------- entry point ----------

class _ArgError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    """Bad arguments raise instead of exiting, so main() can print one line and return 1."""
    def error(self, message):
        raise _ArgError(message)


def _parser() -> argparse.ArgumentParser:
    p = _Parser(prog="ping", description="Ping: post-quantum secure messenger")
    p.add_argument("--home", default=DEFAULT_HOME, help=f"data directory (default {DEFAULT_HOME})")
    p.add_argument("--trace", action="store_true", help="print each cryptographic step")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-pki", help="create the Root CA and the Sub-CA (admin)")
    cap = sub.add_parser("ca", help="CA administration (admin)")
    casub = cap.add_subparsers(dest="ca_cmd", required=True)
    casub.add_parser("list", help="pending requests")
    for name in ("approve", "renew"):
        casub.add_parser(name).add_argument("user")
    sub.add_parser("signup", help="create an account")
    sub.add_parser("login", help="log in and chat")
    return p


def main(argv=None, *, getpass=read_secret, input_fn=input, out=print) -> int:
    try:
        args = _parser().parse_args(argv)
    except _ArgError as e:
        out(f"error: {e} (try --help)")
        return 1
    except SystemExit as e:                      # --help
        return int(e.code or 0)
    util.set_trace(args.trace)
    bridge_messaging(args.home)
    commands = {"init-pki": _cmd_init_pki, "ca": _cmd_ca, "signup": _cmd_signup, "login": _cmd_login}
    try:
        return commands[args.cmd](args, getpass, input_fn, out)
    except HANDLED as e:
        out(f"error: {e}")
        return 1
    except (KeyboardInterrupt, EOFError):
        out("\ncancelled")
        return 1
    finally:
        util.set_trace(False)
