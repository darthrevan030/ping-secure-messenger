import pytest

from ping import messaging
from ping.messaging import Message
from tests.pki_fixture import ChainError


from tests.messaging_helpers import msgs


class TestSendAndRead:
    def test_roundtrip_both_participants_read(self, alice, bob):
        messaging.send(alice, "bobby", "héllo 🙂")
        for me, peer in ((bob, "alice"), (alice, "bobby")):
            items = messaging.open_conversation(me, peer)
            assert len(items) == 1
            m = items[0]
            assert isinstance(m, Message)
            assert (m.text, m.sender, m.seq) == ("héllo 🙂", "alice", 0)

    def test_seq_increments_per_sender(self, alice, bob):
        for s, peer in ((alice, "bobby"), (alice, "bobby"), (bob, "alice"), (alice, "bobby")):
            messaging.send(s, peer, "x")
        got = msgs(messaging.open_conversation(bob, "alice"))
        assert sorted(m.seq for m in got if m.sender == "alice") == [0, 1, 2]
        assert [m.seq for m in got if m.sender == "bobby"] == [0]

    def test_envelope_has_both_copies_and_no_plaintext(self, alice, bob):
        import json

        mid = messaging.send(alice, "bobby", "needle-in-haystack")
        path = messaging.conv_dir(alice.home, "alice", "bobby") / f"{mid}.json"
        raw = path.read_bytes()
        assert b"needle-in-haystack" not in raw
        env = json.loads(raw)
        assert set(env["to"]) == {"alice", "bobby"}
        assert env["header"]["msg_id"] == mid

    def test_conv_dir_name_is_sorted(self, tmp_home):
        assert messaging.conv_dir(tmp_home, "bobby", "alice").name == "alice__bobby"

    def test_send_to_self_refused(self, alice):
        with pytest.raises(ValueError):
            messaging.send(alice, "alice", "hi")
        assert not (alice.home / "mail").exists()

    @pytest.mark.parametrize("peer", ["../x", "Bob", "a"])
    def test_send_rejects_bad_peer(self, alice, peer):
        with pytest.raises(ValueError):
            messaging.send(alice, peer, "hi")

    @pytest.mark.parametrize("text", ["", "a" * 4097, "é" * 2049])
    def test_send_rejects_bad_text(self, alice, bob, text):
        with pytest.raises(ValueError):
            messaging.send(alice, "bobby", text)
        assert not (alice.home / "mail").exists()

    def test_send_accepts_exactly_4096_bytes(self, alice, bob):
        messaging.send(alice, "bobby", "a" * 4096)
        assert len(msgs(messaging.open_conversation(bob, "alice"))[0].text) == 4096

    def test_send_refuses_unverifiable_recipient_cert(self, env, alice):
        env.add_user("dave", ca=env.rogue)
        with pytest.raises(ChainError):
            messaging.send(alice, "dave", "hi")
        assert not (alice.home / "mail").exists()

    def test_open_empty_or_missing_conversation(self, alice, bob):
        assert messaging.open_conversation(alice, "bobby") == []

    def test_open_rejects_bad_peer_name(self, alice):
        with pytest.raises(ValueError):
            messaging.open_conversation(alice, "../x")
