"""KEM-DEM messaging: one ML-KEM-encrypted copy per reader, encrypt-then-sign envelope."""

import datetime as dt
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ping import keystore, util
from ping.keystore import Session

try:  # Person B's module; absent until it lands (tests inject a stand-in)
    from ping import pki
except ImportError:  # pragma: no cover
    pki = None

CONTEXT_ENVELOPE = b"ping/v1/envelope"
MAX_TEXT = 4096
MAX_ENVELOPE = 1_000_000
SALT_LEN = 32


@dataclass(frozen=True)
class Message:
    msg_id: str
    seq: int
    sender: str
    ts: int
    text: str
    file: str


@dataclass(frozen=True)
class Rejected:
    file: str
    reason: str


@dataclass(frozen=True)
class Warning:
    kind: str  # "MISSING" | "CONFLICT"
    text: str


Item = Message | Rejected | Warning


class Reject(Exception):
    """A single envelope file failed verification; the reason is shown to the user."""


def conv_dir(home, a: str, b: str) -> Path:
    x, y = sorted((util.valid_username(a), util.valid_username(b)))
    return Path(home) / "mail" / f"{x}__{y}"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _commit(pt_salt: bytes, plaintext: bytes) -> str:
    return util.b64e(hashlib.sha256(b"ping/v1/pt" + pt_salt + plaintext).digest())


def _dem_key(shared: bytes, kem_ct: bytes, ek_der: bytes, header: dict) -> bytes:
    info = (
        b"ping/v1/dem" + kem_ct + hashlib.sha256(ek_der).digest()
        + hashlib.sha256(util.canon(header)).digest()
    )
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)


def _spki(pub) -> bytes:
    return pub.public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)


def send(session: Session, peer: str, text: str) -> str:
    me = session.user
    util.valid_username(peer)
    if peer == me:
        raise ValueError("cannot send a message to yourself")
    plaintext = text.encode("utf-8")
    if not plaintext or len(plaintext) > MAX_TEXT:
        raise ValueError(f"message must be 1-{MAX_TEXT} bytes")

    cert = pki.load_cert(session.home, peer, "kem")
    pki.verify_chain(cert, "kem", peer, session.pinned_root_fp, _now())
    peer_ek = cert.public_key()
    if not isinstance(peer_ek, mlkem.MLKEM768PublicKey):
        raise ValueError("recipient certificate does not hold an ML-KEM-768 key")
    util.trace(f"verified {peer}'s KEM certificate chain (ML-DSA-65 / ML-DSA-87)")

    prior = [
        i.seq for i in open_conversation(session, peer)
        if isinstance(i, Message) and i.sender == me
    ]
    # The sealed counter is what stops a number being reused after a deletion or an expired
    # certificate hides earlier messages; the verified messages are a floor if it was lost.
    seq = max(keystore.read_seq(session.home, me, peer, session.k_file),
              max(prior) + 1 if prior else 0)
    # Reserve before writing: a send that fails afterwards leaves a visible gap, never a reuse.
    keystore.write_seq(session.home, me, peer, seq + 1, session.k_file)
    pt_salt = os.urandom(SALT_LEN)
    msg_id = os.urandom(16).hex()
    header = {
        "v": 1, "msg_id": msg_id, "seq": seq,
        "sender": me, "recipient": peer, "ts": int(_now().timestamp()),
        "sender_sign_fp": util.fingerprint(session.keys.sign_pub_der),
        "sender_kem_fp": util.fingerprint(session.keys.kem_pub_der),
        "recipient_kem_fp": util.fingerprint(_spki(peer_ek)),
        "pt_commit": _commit(pt_salt, plaintext),
    }

    to = {}
    for reader, ek in ((peer, peer_ek), (me, session.keys.kem_priv.public_key())):
        shared, kem_ct = ek.encapsulate()
        key = _dem_key(shared, kem_ct, _spki(ek), header)
        nonce = os.urandom(12)
        aad = util.canon({"header": header, "r": reader})
        ctext = AESGCM(key).encrypt(nonce, pt_salt + plaintext, aad)
        to[reader] = {"kem_ct": util.b64e(kem_ct), "nonce": util.b64e(nonce), "ctext": util.b64e(ctext)}
        util.trace(f"ML-KEM-768 encapsulate for {reader}: ct {len(kem_ct)} B; AES-256-GCM: {len(ctext)} B")

    sig = session.keys.sign_priv.sign(util.canon({"header": header, "to": to}), CONTEXT_ENVELOPE)
    util.trace(f"ML-DSA-65 sign envelope (context {CONTEXT_ENVELOPE.decode()}): sig {len(sig)} B")
    envelope = {"header": header, "to": to, "sig": util.b64e(sig)}
    util.create_exclusive(
        conv_dir(session.home, me, peer) / f"{msg_id}.json", json.dumps(envelope).encode("utf-8")
    )
    return msg_id


_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEADER_STR = ("sender", "recipient", "sender_sign_fp", "sender_kem_fp", "recipient_kem_fp", "pt_commit")


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _check_schema(env) -> None:
    """Required fields and types only; raises Reject('malformed: ...')."""
    def bad(what):
        raise Reject(f"malformed: {what}")

    if not isinstance(env, dict) or not isinstance(env.get("header"), dict):
        bad("header")
    h, to = env["header"], env.get("to")
    if not isinstance(env.get("sig"), str):
        bad("sig")
    if h.get("v") != 1 or not _is_int(h.get("v")):
        bad("version")
    if not isinstance(h.get("msg_id"), str) or not _HEX32.match(h["msg_id"]):
        bad("msg_id")
    if not _is_int(h.get("seq")) or h["seq"] < 0 or not _is_int(h.get("ts")):
        bad("seq/ts")
    for k in _HEADER_STR:
        if not isinstance(h.get(k), str):
            bad(k)
    for k in ("sender", "recipient"):
        try:
            util.valid_username(h[k])
        except ValueError:
            bad(k)
    if h["sender"] == h["recipient"]:
        bad("sender equals recipient")
    if not isinstance(to, dict) or set(to) != {h["sender"], h["recipient"]}:
        bad("to")
    for copy in to.values():
        if not isinstance(copy, dict) or not all(
            isinstance(copy.get(k), str) for k in ("kem_ct", "nonce", "ctext")
        ):
            bad("copy")


def _open_one(session: Session, peer: str, path: Path) -> Message:
    """Verify and decrypt one envelope file; raises Reject with the reason shown to the user."""
    me = session.user
    try:
        raw = util.read_limited(path, MAX_ENVELOPE)
    except util.TooLarge:
        raise Reject("malformed: file too large") from None
    try:
        env = json.loads(raw)
    except ValueError:
        raise Reject("malformed: not valid JSON") from None
    _check_schema(env)  # 1. schema
    h, to = env["header"], env["to"]

    try:  # 2. sender certificate chain, then its key against the header
        cert = pki.load_cert(session.home, h["sender"], "sign")
        pki.verify_chain(cert, "sign", h["sender"], session.pinned_root_fp, _now())
    except (pki.ChainError, OSError, ValueError) as e:
        raise Reject(f"sender certificate invalid: {e}") from None
    sender_pub = cert.public_key()
    if not isinstance(sender_pub, mldsa.MLDSA65PublicKey):
        raise Reject("sender certificate invalid: not an ML-DSA-65 key")
    if util.fingerprint(_spki(sender_pub)) != h["sender_sign_fp"]:
        raise Reject("sender key mismatch: header fingerprint differs from certificate")

    try:  # 3. signature, before anything is decrypted
        sender_pub.verify(util.b64d(env["sig"]), util.canon({"header": h, "to": to}), CONTEXT_ENVELOPE)
    except (InvalidSignature, ValueError):
        raise Reject("bad signature") from None

    if {h["sender"], h["recipient"]} != {me, peer}:  # 4. addressing
        raise Reject("wrong conversation: not between you and this peer")
    my_fp = util.fingerprint(session.keys.kem_pub_der)
    if my_fp != (h["sender_kem_fp"] if h["sender"] == me else h["recipient_kem_fp"]):
        raise Reject("not encrypted for you: KEM key fingerprint differs")

    try:  # 5. decapsulate, derive, decrypt
        kem_ct = util.b64d(to[me]["kem_ct"])
        shared = session.keys.kem_priv.decapsulate(kem_ct)
        key = _dem_key(shared, kem_ct, session.keys.kem_pub_der, h)
        opened = AESGCM(key).decrypt(
            util.b64d(to[me]["nonce"]), util.b64d(to[me]["ctext"]),
            util.canon({"header": h, "r": me}),
        )
    except (InvalidTag, ValueError):
        raise Reject("decryption failed") from None
    util.trace(f"ML-KEM-768 decapsulate + AES-256-GCM decrypt OK: {len(opened)} B")

    pt_salt, plaintext = opened[:SALT_LEN], opened[SALT_LEN:]  # 6. commitment
    if len(opened) < SALT_LEN or not hmac.compare_digest(_commit(pt_salt, plaintext), h["pt_commit"]):
        raise Reject("copies differ: plaintext does not match the signed commitment")
    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        raise Reject("malformed: text is not UTF-8") from None
    return Message(h["msg_id"], h["seq"], h["sender"], h["ts"], text, path.name)


def conv_files(session: Session, peer: str) -> list[Path]:
    d = conv_dir(session.home, session.user, peer)
    if not d.is_dir():
        return []
    return sorted(p for p in d.iterdir() if p.suffix == ".json" and p.is_file())


def open_conversation(session: Session, peer: str) -> list[Item]:
    util.valid_username(peer)
    if peer == session.user:
        raise ValueError("no conversation with yourself")
    messages, rejected = [], []
    for path in conv_files(session, peer):
        try:
            messages.append(_open_one(session, peer, path))
        except Reject as e:
            rejected.append(Rejected(path.name, str(e)))
        except Exception as e:  # fail closed: a hostile file must never crash the reader
            rejected.append(Rejected(path.name, f"malformed: unexpected {type(e).__name__}"))
    seen, unique = set(), []
    for m in messages:  # duplicate msg_id: the first file (by name) wins
        if m.msg_id not in seen:
            seen.add(m.msg_id)
            unique.append(m)
    unique.sort(key=lambda m: (m.ts, m.seq, m.msg_id))
    return unique + rejected + _seq_warnings(unique)


def _seq_warnings(messages: list[Message]) -> list[Warning]:
    """Per sender: gaps in the signed sequence numbers, and distinct messages sharing one."""
    by_sender: dict[str, dict[int, int]] = {}
    for m in messages:
        counts = by_sender.setdefault(m.sender, {})
        counts[m.seq] = counts.get(m.seq, 0) + 1
    out = []
    for sender, counts in sorted(by_sender.items()):
        expected = 0
        for seq in sorted(counts):
            if seq > expected:
                out.append(Warning(
                    "MISSING", f"⚠ MISSING: {seq - expected} message(s) from {sender} before seq {seq}"))
            if counts[seq] > 1:
                out.append(Warning(
                    "CONFLICT", f"⚠ CONFLICT: {sender} sent different messages with seq {seq}"))
            expected = seq + 1
    return out
