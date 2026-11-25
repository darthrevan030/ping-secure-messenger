"""KEM-DEM messaging: one ML-KEM-encrypted copy per reader, encrypt-then-sign envelope."""

import datetime as dt
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ping import util
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
    pt_salt = os.urandom(SALT_LEN)
    msg_id = os.urandom(16).hex()
    header = {
        "v": 1, "msg_id": msg_id, "seq": max(prior) + 1 if prior else 0,
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


def _open_one(session: Session, peer: str, path: Path) -> Message:
    envelope = json.loads(util.read_limited(path, MAX_ENVELOPE))
    header = envelope["header"]
    copy = envelope["to"][session.user]
    ek_der = session.keys.kem_pub_der
    shared = session.keys.kem_priv.decapsulate(util.b64d(copy["kem_ct"]))
    key = _dem_key(shared, util.b64d(copy["kem_ct"]), ek_der, header)
    aad = util.canon({"header": header, "r": session.user})
    opened = AESGCM(key).decrypt(util.b64d(copy["nonce"]), util.b64d(copy["ctext"]), aad)
    return Message(
        header["msg_id"], header["seq"], header["sender"], header["ts"],
        opened[SALT_LEN:].decode("utf-8"), path.name,
    )


def conv_files(session: Session, peer: str) -> list[Path]:
    d = conv_dir(session.home, session.user, peer)
    if not d.is_dir():
        return []
    return sorted(p for p in d.iterdir() if p.suffix == ".json" and p.is_file())


def open_conversation(session: Session, peer: str) -> list[Item]:
    util.valid_username(peer)
    if peer == session.user:
        raise ValueError("no conversation with yourself")
    messages = [_open_one(session, peer, p) for p in conv_files(session, peer)]
    return sorted(messages, key=lambda m: (m.ts, m.msg_id))
