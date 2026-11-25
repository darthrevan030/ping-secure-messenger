"""Helpers for building, tampering with and inspecting envelopes in tests."""

import json
import os

from ping import messaging, util
from ping.messaging import Message, Rejected


def msgs(items):
    return [i for i in items if isinstance(i, Message)]


def spki(pub):
    return messaging._spki(pub)


def envelope_path(session, peer, mid):
    return messaging.conv_dir(session.home, session.user, peer) / f"{mid}.json"


def tamper(path, fn):
    data = json.loads(path.read_text())
    fn(data)
    path.write_text(json.dumps(data))


def resign(path, signer, ctx=b"ping/v1/envelope"):
    def fn(d):
        sig = signer.keys.sign_priv.sign(util.canon({"header": d["header"], "to": d["to"]}), ctx)
        d["sig"] = util.b64e(sig)

    tamper(path, fn)


def forge(sender, peer, texts, *, signer=None, ctx=b"ping/v1/envelope", header=None,
          eks=None, commit_for=None, dest=None, seq=0, ts=1_760_000_000):
    """Hand-build an envelope with full control over each step. Returns its path.

    texts: {username: plaintext} for the two readers. commit_for: whose text the
    signed pt_commit commits to (default the recipient's).
    """
    signer = signer or sender
    eks = eks or {}
    commit_for = commit_for or peer.user
    salt = os.urandom(32)
    h = {
        "v": 1, "msg_id": os.urandom(16).hex(), "seq": seq, "sender": sender.user,
        "recipient": peer.user, "ts": ts,
        "sender_sign_fp": util.fingerprint(sender.keys.sign_pub_der),
        "sender_kem_fp": util.fingerprint(sender.keys.kem_pub_der),
        "recipient_kem_fp": util.fingerprint(peer.keys.kem_pub_der),
        "pt_commit": messaging._commit(salt, texts[commit_for].encode()),
    }
    h.update(header or {})
    to = {}
    for reader, owner in ((h["recipient"], peer), (h["sender"], sender)):
        ek = eks.get(reader) or owner.keys.kem_priv.public_key()
        shared, kem_ct = ek.encapsulate()
        key = messaging._dem_key(shared, kem_ct, spki(ek), h)
        nonce = os.urandom(12)
        ct = messaging.AESGCM(key).encrypt(
            nonce, salt + texts[reader].encode(), util.canon({"header": h, "r": reader}))
        to[reader] = {"kem_ct": util.b64e(kem_ct), "nonce": util.b64e(nonce), "ctext": util.b64e(ct)}
    sig = signer.keys.sign_priv.sign(util.canon({"header": h, "to": to}), ctx)
    a, b = dest or (h["sender"], h["recipient"])
    path = messaging.conv_dir(sender.home, a, b) / f"{h['msg_id']}.json"
    util.create_exclusive(path, json.dumps({"header": h, "to": to, "sig": util.b64e(sig)}).encode())
    return path


def assert_only_rejected(items, reason):
    assert not msgs(items), "tampered envelope was delivered as a message"
    rejected = [i for i in items if isinstance(i, Rejected)]
    assert len(rejected) == 1
    assert reason in rejected[0].reason, rejected[0].reason
