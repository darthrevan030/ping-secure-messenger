"""Hands-on check of the PKI and CA, outside the test suite.

    uv run python scripts/pki_walkthrough.py setup   # build demo/ with users alice and bob
    uv run python scripts/pki_walkthrough.py show    # print what is inside each certificate
    uv run python scripts/pki_walkthrough.py check   # run verify_chain on everything

Then edit, copy or delete files under demo/ by hand and run `check` again.
demo/ is in .gitignore. Passphrases are typed in, never stored.
"""
import os
import sys
from getpass import getpass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem  # noqa: E402

from ping import ca, pki, util  # noqa: E402

HOME = Path("demo")
PIN_FILE = HOME / "pinned_root.txt"   # in the real app the pin is sealed in trust.json
USERS = ["alice", "bob"]


def read_secret(prompt: str) -> str:
    """Like getpass, but shows one * per character so you can see it is typing."""
    if os.name != "nt":
        return getpass(prompt)
    import msvcrt
    print(prompt, end="", flush=True)
    chars = []
    while True:
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):          # Enter
            print()
            return "".join(chars)
        if ch == "\x03":                 # Ctrl+C
            raise KeyboardInterrupt
        if ch == "\x08":                 # Backspace
            if chars:
                chars.pop()
                print("\b \b", end="", flush=True)
        elif ch in ("\x00", "\xe0"):     # arrow/function keys: ignore
            msvcrt.getwch()
        else:
            chars.append(ch)
            print("*", end="", flush=True)


def ask_passphrase(label: str) -> str:
    while True:
        pw = read_secret(f"{label} passphrase (12+ characters): ")
        if len(pw) < ca.MIN_PASSPHRASE:
            print("  too short")
        elif read_secret("  repeat it: ") != pw:
            print("  they don't match")
        else:
            return pw


def setup():
    if HOME.exists():
        sys.exit(f"{HOME}/ already exists. Delete the folder to start again.")
    root_pw = ask_passphrase("Root CA")
    sub_pw = ask_passphrase("Sub-CA")
    print("\nCreating the PKI (Scrypt takes a moment)...")
    root_fp = ca.init_pki(HOME, root_pw, sub_pw)
    PIN_FILE.write_text(root_fp)
    print(f"Root fingerprint (pinned): {root_fp}")

    for user in USERS:
        sign_key = mldsa.MLDSA65PrivateKey.generate()
        kem_key = mlkem.MLKEM768PrivateKey.generate()
        request = ca.build_request(user, sign_key, kem_key.public_key())
        util.create_exclusive(HOME / "requests" / f"{user}.json", json.dumps(request).encode())
        print(f"Request written: requests/{user}.json")
    print(f"Pending: {ca.list_pending(HOME)}")
    for user in USERS:
        ca.approve(HOME, user, sub_pw)
        print(f"Approved {user}: certs/{user}/sign.crt.pem and kem.crt.pem")
    print(f"Pending now: {ca.list_pending(HOME)}")
    print("\nNext: `show` to look inside, `check` to verify.")


def describe(path: Path):
    cert = pki._load_pem(path)
    cn = lambda name: name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value  # noqa: E731
    key = cert.public_key()
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    allowed = [n for n in ("digital_signature", "key_encipherment", "key_cert_sign", "crl_sign")
               if getattr(ku, n)]
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san = san.get_values_for_type(x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound:
        san = "-"
    print(f"\n{path}  ({path.stat().st_size} bytes)")
    print(f"  subject   {cn(cert.subject)}")
    print(f"  issuer    {cn(cert.issuer)}")
    print(f"  key       {type(key).__name__.replace('PublicKey', '')}")
    print(f"  valid     {cert.not_valid_before_utc:%Y-%m-%d} -> {cert.not_valid_after_utc:%Y-%m-%d}")
    print(f"  CA        {bc.ca}  path length {bc.path_length}")
    print(f"  may       {', '.join(allowed)}")
    print(f"  SAN       {san}")
    print(f"  serial    {cert.serial_number:x}"[:40] + "...")
    print(f"  key fp    {util.fingerprint(pki._spki(cert.public_key()))[:32]}...")


def show():
    for p in [HOME / "pki" / "root.crt.pem", HOME / "pki" / "sub.crt.pem"] + \
             [HOME / "certs" / u / f for u in USERS for f in ("sign.crt.pem", "kem.crt.pem")]:
        if p.exists():
            describe(p)
        else:
            print(f"\n{p}: missing")


def check():
    pinned = PIN_FILE.read_text().strip()
    print(f"Pinned Root: {pinned[:32]}...\n")
    print("Expected OK:")
    for user in USERS:
        for purpose, f in (("sign", "sign.crt.pem"), ("kem", "kem.crt.pem")):
            run(user, purpose, HOME / "certs" / user / f, pinned)
    print("\nExpected REJECTED (wrong use or wrong person):")
    run("alice", "sign", HOME / "certs" / "alice" / "kem.crt.pem", pinned)   # KEM cert used to sign
    run("alice", "kem", HOME / "certs" / "alice" / "sign.crt.pem", pinned)   # signing cert used as KEM
    run("alice", "sign", HOME / "certs" / "bob" / "sign.crt.pem", pinned)    # bob's cert as alice's
    run("alice", "sign", HOME / "pki" / "sub.crt.pem", pinned)               # CA cert as a user cert

    print("\nOpening the Sub-CA key file (pki/sub.key.json), twice:")
    for attempt in ("1/2 type the REAL Sub-CA passphrase: ",
                    "2/2 now type a WRONG one: "):
        pw = read_secret(attempt)
        try:
            ca._open_ca_key(HOME, "sub", pw)
            print("  [OK]       opened, and it matches sub.crt.pem")
        except ca.CAError as e:
            print(f"  [REJECTED] {e}")


def run(user, purpose, path, pinned):
    label = f"{user:5} as {purpose:4} <- {path.relative_to(HOME)}"
    try:
        cert = pki._load_pem(path)
        pki.verify_chain(HOME, cert, purpose, user, pinned)
        print(f"  [OK]       {label}")
    except pki.ChainError as e:
        print(f"  [REJECTED] {label}: {e}")
    except (OSError, ValueError) as e:
        print(f"  [BROKEN]   {label}: {type(e).__name__}: {e}")


if __name__ == "__main__":
    commands = {"setup": setup, "show": show, "check": check}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        sys.exit(__doc__)
    commands[sys.argv[1]]()
