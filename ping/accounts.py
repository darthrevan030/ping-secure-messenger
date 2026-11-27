"""Sign-up and login (plan B, Task 3).

    signup: claim the name -> derive keys from the password -> generate the user's
            ML-DSA-65 and ML-KEM-768 keys -> seal them -> pin the Root -> write the
            certification request (last). The user is then "pending" until the CA approves.
    login:  check the password -> open the sealed files -> check the certificates
            against the pinned Root -> return a keystore.Session for messaging.
"""
import datetime
import json
import shutil
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidTag

from ping import auth, ca, keystore, pki, util

MAX_ACCOUNT_FILE = 4096
# Used for unknown users so that a failed login always costs one Scrypt derivation:
# timing must not reveal whether the username exists.
_DUMMY_SALT = b"ping/no-such-user"


class LoginError(Exception):
    """Wrong username or password (deliberately the same message for both)."""


class PendingApproval(Exception):
    """The account exists, but the CA has not issued its certificates yet."""


class TamperedError(Exception):
    """A sealed file (keys or trust pin) failed authentication: it was changed or swapped."""


class CertificateProblem(Exception):
    """The user's own certificates do not verify (expired, wrong Root, not their keys...)."""


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _user_dir(home, user: str) -> Path:
    return Path(home) / "users" / user


# ---------- sign-up ----------

def signup(home, username: str, password: str, confirm_root_fp: Callable[[str], bool]) -> None:
    """Create the account and the certification request. Raises ValueError (bad input,
    name taken, no PKI) or RuntimeError (sign-up aborted at the fingerprint prompt)."""
    home = Path(home)
    user = util.valid_username(username)
    auth.check_password_policy(password)
    if _name_taken(home, user):
        raise ValueError(f"the username {user!r} is already taken")
    try:
        root_cert = _load_root(home)
    except FileNotFoundError:
        raise ValueError("no PKI here yet: the admin must run init-pki first") from None

    # The user checks this fingerprint against the one the admin announced (out of band).
    root_fp = pki.root_fingerprint(root_cert)
    if not confirm_root_fp(root_fp):
        raise RuntimeError("sign-up aborted: Root fingerprint not confirmed")

    # Claim the name: an exclusive mkdir fails if someone else got there first.
    udir = _user_dir(home, user)
    udir.parent.mkdir(parents=True, exist_ok=True)
    try:
        udir.mkdir()
    except FileExistsError:
        raise ValueError(f"the username {user!r} is already taken") from None

    try:
        salt = auth.new_salt()
        k_auth, k_file = auth.derive(password, salt)                    # Scrypt + HKDF split
        util.trace(f"Scrypt(n={auth.SCRYPT['n']}, r={auth.SCRYPT['r']}) + HKDF -> K_auth, K_file (32 B each)")
        account = {"v": 1, "user": user, "salt": util.b64e(salt),
                   "verifier": util.b64e(auth.make_verifier(k_auth))}
        util.atomic_write(udir / "account.json", json.dumps(account).encode())

        keys = keystore.generate_user_keys()
        util.trace(f"ML-DSA-65.KeyGen (pk {len(keys.sign_pub_der)} B) + ML-KEM-768.KeyGen (ek {len(keys.kem_pub_der)} B)")
        keystore.write_user_keys(home, user, keys, k_file)               # sealed under K_file
        keystore.write_trust(home, user, root_fp, k_file)                # the pin, sealed too
        util.trace("AES-256-GCM seal sign.key.json, kem.key.json, trust.json under K_file")

        request = ca.build_request(user, keys.sign_priv, keys.kem_priv.public_key())
        util.trace("CSR signed with ML-DSA-65; KEM binding signed (context ping/v1/kem-bind)")
        # Written last and exclusively: a request exists only for a complete account.
        util.create_exclusive(home / "requests" / f"{user}.json", json.dumps(request).encode())
    except BaseException:
        shutil.rmtree(udir, ignore_errors=True)    # release the name: no half-created accounts
        raise


def _name_taken(home: Path, user: str) -> bool:
    return any(p.exists() for p in (_user_dir(home, user),
                                    home / "requests" / f"{user}.json",
                                    home / "certs" / user))


def _load_root(home):
    return pki._load_pem(Path(home) / "pki" / "root.crt.pem")


# ---------- login ----------

def login(home, username: str, password: str) -> keystore.Session:
    home = Path(home)
    try:
        user = util.valid_username(username)
        account = _read_account(home, user)
    except (ValueError, OSError):
        account = None
    if account is None:
        auth.derive(password, _DUMMY_SALT)          # same cost as a real attempt
        raise LoginError("wrong username or password")

    # 1. Password.
    k_auth, k_file = auth.derive(password, account["salt"])
    if not auth.check_verifier(k_auth, account["verifier"]):
        raise LoginError("wrong username or password")
    util.trace("Scrypt + HKDF; HMAC verifier == stored ✔")

    # 2. Sealed files. The password is right, so a failure here means the file was changed.
    try:
        root_fp = keystore.read_trust(home, user, k_file)
        keys = keystore.load_user_keys(home, user, k_file)
    except (InvalidTag, ValueError, KeyError, TypeError) as e:
        raise TamperedError(f"your key files were modified or swapped ({type(e).__name__}): "
                            "refusing to log in") from None
    except FileNotFoundError:
        raise TamperedError("one of your key files is missing: refusing to log in") from None
    util.trace("AES-256-GCM open trust.json, sign.key.json, kem.key.json ✔")

    # 3. Certificates: issued yet?
    try:
        certs = {p: pki.load_cert(home, user, p) for p in pki.PURPOSES}
    except FileNotFoundError:
        raise PendingApproval("your account is waiting for the CA to approve it") from None

    # 4. They must verify against MY pinned Root and certify MY keys.
    at = _now()
    for purpose, cert in certs.items():
        try:
            pki.verify_chain(home, cert, purpose, user, root_fp, at)
        except pki.ChainError as e:
            if "certificate expired" in str(e):
                raise CertificateProblem(f"certificate expired: ask the CA to renew ({e})") from None
            raise CertificateProblem(f"your {purpose} certificate is not valid: {e}") from None
    for purpose, own_der in (("sign", keys.sign_pub_der), ("kem", keys.kem_pub_der)):
        if pki._spki(certs[purpose].public_key()) != own_der:
            raise CertificateProblem(f"{purpose} certificate does not match your key")
    util.trace("own sign and KEM certificates verify and match the local keys ✔")

    return keystore.Session(home=home, user=user, keys=keys, pinned_root_fp=root_fp, k_file=k_file)


def _read_account(home: Path, user: str):
    path = _user_dir(home, user) / "account.json"
    if not path.exists():
        return None
    acc = json.loads(util.read_limited(path, MAX_ACCOUNT_FILE))
    if not isinstance(acc, dict) or acc.get("v") != 1 or acc.get("user") != user:
        raise ValueError("account.json is malformed")
    return {"salt": util.b64d(acc["salt"]), "verifier": util.b64d(acc["verifier"])}


def fingerprints(session: keystore.Session) -> dict:
    """For the CLI's `fingerprints` command: public values only."""
    return {"sign": util.fingerprint(session.keys.sign_pub_der),
            "kem": util.fingerprint(session.keys.kem_pub_der),
            "root (pinned)": session.pinned_root_fp}

