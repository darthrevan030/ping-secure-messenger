import pytest
from cryptography.hazmat.primitives.asymmetric import mlkem

from ping import messaging, util
from tests.messaging_helpers import (
    assert_only_rejected, envelope_path, forge, msgs, resign, spki, tamper,
)


def flip_byte_b64(s, i=0):
    raw = bytearray(util.b64d(s))
    raw[i] ^= 1
    return util.b64e(bytes(raw))


class TestRejections:
    def test_untampered_message_is_accepted(self, alice, bob):
        # positive twin: the tamper helper alone must not cause rejection
        mid = messaging.send(alice, "bobby", "ok")
        tamper(envelope_path(alice, "bobby", mid), lambda d: None)
        assert len(msgs(messaging.open_conversation(bob, "alice"))) == 1

    def test_flipped_header_field_rejected(self, alice, bob):
        mid = messaging.send(alice, "bobby", "hi")
        tamper(envelope_path(alice, "bobby", mid),
               lambda d: d["header"].update(ts=d["header"]["ts"] + 1))
        assert_only_rejected(messaging.open_conversation(bob, "alice"), "bad signature")

    def test_flipped_ciphertext_rejected_by_signature(self, alice, bob):
        mid = messaging.send(alice, "bobby", "hi")
        tamper(envelope_path(alice, "bobby", mid),
               lambda d: d["to"]["bobby"].update(ctext=flip_byte_b64(d["to"]["bobby"]["ctext"])))
        assert_only_rejected(messaging.open_conversation(bob, "alice"), "bad signature")

    def test_flipped_ciphertext_rejected_by_aead_when_resigned(self, alice, bob):
        mid = messaging.send(alice, "bobby", "hi")
        p = envelope_path(alice, "bobby", mid)
        tamper(p, lambda d: d["to"]["bobby"].update(ctext=flip_byte_b64(d["to"]["bobby"]["ctext"])))
        resign(p, alice)
        assert_only_rejected(messaging.open_conversation(bob, "alice"), "decryption failed")

    def test_flipped_signature_rejected(self, alice, bob):
        mid = messaging.send(alice, "bobby", "hi")
        tamper(envelope_path(alice, "bobby", mid),
               lambda d: d.update(sig=flip_byte_b64(d["sig"], 5)))
        assert_only_rejected(messaging.open_conversation(bob, "alice"), "bad signature")

    def test_signature_checked_before_decryption(self, alice, bob, monkeypatch):
        mid = messaging.send(alice, "bobby", "hi")
        tamper(envelope_path(alice, "bobby", mid), lambda d: d["header"].update(ts=1))

        class Boom:
            def __init__(self, key):
                pass

            def decrypt(self, *a):
                raise AssertionError("decrypted before verifying the signature")

        monkeypatch.setattr(messaging, "AESGCM", Boom)
        assert_only_rejected(messaging.open_conversation(bob, "alice"), "bad signature")

    def test_envelope_copied_into_another_conversation(self, alice, bob, carol):
        mid = messaging.send(alice, "bobby", "for bobby only")
        src = envelope_path(alice, "bobby", mid)
        dst = messaging.conv_dir(alice.home, "alice", "carol") / src.name
        dst.parent.mkdir(parents=True)
        dst.write_bytes(src.read_bytes())
        # header says {alice, bobby}; carol reads her conversation with alice
        assert_only_rejected(messaging.open_conversation(carol, "alice"), "wrong conversation")

    def test_signed_by_mallory_under_alices_name(self, env, alice, bob):
        mallory = env.add_user("mallory")
        forge(mallory, bob, {"bobby": "pay mallory", "alice": "pay mallory"},
              header={"sender": "alice"}, dest=("alice", "bobby"))
        assert_only_rejected(messaging.open_conversation(bob, "alice"), "sender key mismatch")

    def test_mallory_claiming_alices_fingerprint_fails_signature(self, env, alice, bob):
        mallory = env.add_user("mallory")
        forge(mallory, bob, {"bobby": "x", "alice": "x"},
              header={"sender": "alice",
                      "sender_sign_fp": util.fingerprint(alice.keys.sign_pub_der)},
              dest=("alice", "bobby"))
        assert_only_rejected(messaging.open_conversation(bob, "alice"), "bad signature")

    def test_rogue_kem_key_substituted_for_bobs(self, alice, bob):
        rogue_ek = mlkem.MLKEM768PrivateKey.generate().public_key()
        forge(alice, bob, {"bobby": "x", "alice": "x"}, eks={"bobby": rogue_ek},
              header={"recipient_kem_fp": util.fingerprint(spki(rogue_ek))})
        assert_only_rejected(messaging.open_conversation(bob, "alice"), "not encrypted for you")

    @pytest.mark.parametrize(
        "commit_for,rejecting,accepting",
        [("alice", "bobby", "alice"), ("bobby", "alice", "bobby")],
    )
    def test_different_plaintext_in_two_copies(self, alice, bob, commit_for, rejecting, accepting):
        # The signed commitment matches exactly one of the two texts. The reader holding
        # the other text must reject; nobody is ever shown a text the sender didn't commit to.
        forge(alice, bob, {"bobby": "text-for-bobby", "alice": "text-for-alice"},
              commit_for=commit_for)
        sessions = {"alice": (alice, "bobby"), "bobby": (bob, "alice")}
        s, peer = sessions[rejecting]
        assert_only_rejected(messaging.open_conversation(s, peer), "copies differ")
        s, peer = sessions[accepting]
        assert [m.text for m in msgs(messaging.open_conversation(s, peer))] == [
            f"text-for-{commit_for}"
        ]

    def test_wrong_context_signature_rejected(self, alice, bob):
        forge(alice, bob, {"bobby": "x", "alice": "x"}, ctx=b"ping/v1/kem-bind")
        assert_only_rejected(messaging.open_conversation(bob, "alice"), "bad signature")

    def test_expired_sender_cert_rejected(self, env, bob):
        erin = env.add_user("erin", expired=True)
        messaging.send(erin, "bobby", "hi")
        assert_only_rejected(messaging.open_conversation(bob, "erin"), "sender certificate")

    def test_sender_cert_from_rogue_ca_rejected(self, env, bob):
        eve = env.add_user("eveee", ca=env.rogue)
        messaging.send(eve, "bobby", "hi")
        assert_only_rejected(messaging.open_conversation(bob, "eveee"), "sender certificate")

    def test_kem_cert_presented_as_signing_cert_rejected(self, alice, bob):
        messaging.send(alice, "bobby", "hi")
        certs = alice.home / "certs" / "alice"
        (certs / "sign.crt.pem").write_bytes((certs / "kem.crt.pem").read_bytes())
        assert_only_rejected(messaging.open_conversation(bob, "alice"), "sender certificate")

    def test_sender_without_certificate_rejected(self, alice, bob):
        messaging.send(alice, "bobby", "hi")
        (alice.home / "certs" / "alice" / "sign.crt.pem").unlink()
        assert_only_rejected(messaging.open_conversation(bob, "alice"), "sender certificate")


class TestKeyScheduleIsPinned:
    """Independently computed vectors, so the forge helper can't hide a wrong KDF input."""

    def test_commit_known_answer(self):
        assert messaging._commit(b"\x01" * 32, b"hello") == "dr9jNddHbCLyZJoRWUo8neO7FN0vVvFG8jNfOjYnWh0"

    def test_dem_key_known_answer(self):
        key = messaging._dem_key(b"s" * 32, b"c" * 1088, b"e" * 10, {"a": 1})
        assert key.hex() == "3325a857b982855a19be588f526f364de55bf7a6a367af6608fd69950114513e"

    def test_changed_header_resigned_fails_decryption(self, alice, bob):
        # The header is bound into both the KDF info and the AEAD AAD, not only the signature.
        mid = messaging.send(alice, "bobby", "hi")
        p = envelope_path(alice, "bobby", mid)
        tamper(p, lambda d: d["header"].update(ts=d["header"]["ts"] + 1))
        resign(p, alice)
        assert_only_rejected(messaging.open_conversation(bob, "alice"), "decryption failed")
