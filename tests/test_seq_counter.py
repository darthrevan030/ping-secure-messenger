import json

import pytest
from cryptography.exceptions import InvalidTag

from ping import keystore, messaging, util
from tests.messaging_helpers import assert_only_rejected, envelope_path, msgs

K = b"k" * 32


class TestSealedCounterFile:
    def test_missing_counter_reads_as_zero(self, tmp_home):
        assert keystore.read_seq(tmp_home, "alice", "bobby", K) == 0

    def test_roundtrip_per_peer(self, tmp_home):
        keystore.write_seq(tmp_home, "alice", "bobby", 7, K)
        keystore.write_seq(tmp_home, "alice", "carol", 2, K)
        assert keystore.read_seq(tmp_home, "alice", "bobby", K) == 7
        assert keystore.read_seq(tmp_home, "alice", "carol", K) == 2

    def test_wrong_key_or_flipped_byte_raises_invalid_tag(self, tmp_home):
        keystore.write_seq(tmp_home, "alice", "bobby", 7, K)
        with pytest.raises(InvalidTag):
            keystore.read_seq(tmp_home, "alice", "bobby", b"j" * 32)
        p = tmp_home / "users/alice/seq/bobby.json"
        c = json.loads(p.read_text())
        raw = bytearray(util.b64d(c["ct"]))
        raw[0] ^= 1
        c["ct"] = util.b64e(bytes(raw))
        p.write_text(json.dumps(c))
        with pytest.raises(InvalidTag):
            keystore.read_seq(tmp_home, "alice", "bobby", K)

    def test_counter_copied_to_another_peer_is_refused(self, tmp_home):
        keystore.write_seq(tmp_home, "alice", "bobby", 9, K)
        dst = tmp_home / "users/alice/seq/carol.json"
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes((tmp_home / "users/alice/seq/bobby.json").read_bytes())
        with pytest.raises(ValueError, match="peer"):
            keystore.read_seq(tmp_home, "alice", "carol", K)

    def test_negative_counter_refused(self, tmp_home):
        with pytest.raises(ValueError):
            keystore.write_seq(tmp_home, "alice", "bobby", -1, K)

    def test_bad_peer_name_refused(self, tmp_home):
        with pytest.raises(ValueError):
            keystore.read_seq(tmp_home, "alice", "../x", K)


class TestSeqIsNeverReused:
    def test_deleted_newest_message_does_not_free_its_seq(self, alice, bob):
        for i in range(3):
            messaging.send(alice, "bobby", f"m{i}")
        by_seq = {m.seq: m for m in msgs(messaging.open_conversation(bob, "alice"))}
        envelope_path(alice, "bobby", by_seq[2].msg_id).unlink()
        messaging.send(alice, "bobby", "after deletion")
        items = messaging.open_conversation(bob, "alice")
        assert sorted(m.seq for m in msgs(items)) == [0, 1, 3]
        assert [w.text for w in items if isinstance(w, messaging.Warning)] == [
            "⚠ MISSING: 1 message(s) from alice before seq 3"
        ]

    def test_counter_is_sealed_under_the_session_file_key(self, alice, bob):
        messaging.send(alice, "bobby", "x")
        assert keystore.read_seq(alice.home, "alice", "bobby", alice.k_file) == 1

    def test_tampered_counter_makes_send_fail_closed(self, alice, bob):
        messaging.send(alice, "bobby", "x")
        p = alice.home / "users/alice/seq/bobby.json"
        c = json.loads(p.read_text())
        c["owner"] = "mallory"
        p.write_text(json.dumps(c))
        with pytest.raises(InvalidTag):
            messaging.send(alice, "bobby", "y")
        assert len(msgs(messaging.open_conversation(bob, "alice"))) == 1

    def test_failed_send_never_reuses_a_number(self, alice, bob, monkeypatch):
        messaging.send(alice, "bobby", "m0")

        def boom(*a, **k):
            raise OSError("disk full")

        with monkeypatch.context() as m:
            m.setattr(messaging.util, "create_exclusive", boom)
            with pytest.raises(OSError):
                messaging.send(alice, "bobby", "lost")
        messaging.send(alice, "bobby", "m2")
        seqs = sorted(m.seq for m in msgs(messaging.open_conversation(bob, "alice")))
        assert seqs == [0, 2]  # a visible gap, never a duplicate

    def test_each_conversation_has_its_own_counter(self, alice, bob, carol):
        messaging.send(alice, "bobby", "a")
        messaging.send(alice, "bobby", "b")
        messaging.send(alice, "carol", "c")
        assert [m.seq for m in msgs(messaging.open_conversation(carol, "alice"))] == [0]


class TestCertificateRenewal:
    def test_history_survives_expiry_and_renewal_with_same_keys(self, env, alice, bob):
        messaging.send(alice, "bobby", "before expiry 0")
        messaging.send(alice, "bobby", "before expiry 1")
        env.reissue("alice", expired=True)
        # while the certificate is expired, her messages are refused, loudly
        items = messaging.open_conversation(bob, "alice")
        assert not msgs(items)
        assert all("sender certificate" in r.reason for r in items)
        # she sends while expired: the sealed counter keeps numbering from 2
        messaging.send(alice, "bobby", "sent while expired")
        env.reissue("alice")  # the CA renews: same keys, fresh validity
        items = messaging.open_conversation(bob, "alice")
        assert [m.text for m in msgs(items)] == [
            "before expiry 0", "before expiry 1", "sent while expired",
        ]
        assert [m.seq for m in msgs(items)] == [0, 1, 2]
        assert len(items) == 3  # no REJECTED, no MISSING, no CONFLICT

    def test_renewal_with_a_different_signing_key_does_not_vouch_for_old_messages(self, env, alice, bob):
        messaging.send(alice, "bobby", "signed by the old key")
        env.reissue("alice", new_sign_key=True)
        assert_only_rejected(messaging.open_conversation(bob, "alice"), "sender key mismatch")


class TestDisplayOrder:
    def test_same_second_messages_from_one_sender_follow_their_seq(self, alice, bob):
        from tests.messaging_helpers import forge

        # same timestamp; the later message has the *lower* msg_id, so msg_id order would flip them
        forge(alice, bob, {"bobby": "second", "alice": "second"},
              header={"msg_id": "00" * 16}, ts=100, seq=1)
        forge(alice, bob, {"bobby": "first", "alice": "first"},
              header={"msg_id": "ff" * 16}, ts=100, seq=0)
        assert [m.text for m in msgs(messaging.open_conversation(bob, "alice"))] == ["first", "second"]
