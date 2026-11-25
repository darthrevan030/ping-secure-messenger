import os

import pytest

from ping import messaging
from ping.messaging import Message, Rejected, Warning
from tests.messaging_helpers import envelope_path, forge, msgs, tamper


def warnings(items):
    return [i for i in items if isinstance(i, Warning)]


def rejected(items):
    return [i for i in items if isinstance(i, Rejected)]


def send_three(alice):
    return [messaging.send(alice, "bobby", f"m{i}") for i in range(3)]


class TestSequence:
    def test_deleted_middle_message_reports_gap(self, alice, bob):
        ids = send_three(alice)
        by_seq = {m.seq: m for m in msgs(messaging.open_conversation(bob, "alice"))}
        envelope_path(alice, "bobby", by_seq[1].msg_id).unlink()
        items = messaging.open_conversation(bob, "alice")
        assert sorted(m.seq for m in msgs(items)) == [0, 2]
        w = warnings(items)
        assert len(w) == 1 and w[0].kind == "MISSING"
        assert w[0].text == "⚠ MISSING: 1 message(s) from alice before seq 2"
        assert not rejected(items) and ids

    def test_deleted_first_message_reports_gap(self, alice, bob):
        send_three(alice)
        by_seq = {m.seq: m for m in msgs(messaging.open_conversation(bob, "alice"))}
        envelope_path(alice, "bobby", by_seq[0].msg_id).unlink()
        w = warnings(messaging.open_conversation(bob, "alice"))
        assert [x.text for x in w] == ["⚠ MISSING: 1 message(s) from alice before seq 1"]

    def test_deleted_newest_is_not_detected(self, alice, bob):
        send_three(alice)
        by_seq = {m.seq: m for m in msgs(messaging.open_conversation(bob, "alice"))}
        envelope_path(alice, "bobby", by_seq[2].msg_id).unlink()
        items = messaging.open_conversation(bob, "alice")
        assert len(msgs(items)) == 2 and not warnings(items)  # documented limit

    def test_no_warning_for_a_complete_sequence(self, alice, bob):
        send_three(alice)
        assert not warnings(messaging.open_conversation(bob, "alice"))

    def test_gaps_are_judged_per_sender(self, alice, bob):
        messaging.send(alice, "bobby", "a0")
        messaging.send(bob, "alice", "b0")
        messaging.send(alice, "bobby", "a1")
        messaging.send(bob, "alice", "b1")
        assert not warnings(messaging.open_conversation(alice, "bobby"))

    def test_two_messages_same_seq_conflict(self, alice, bob):
        messaging.send(alice, "bobby", "original")
        forge(alice, bob, {"bobby": "different", "alice": "different"}, seq=0)
        items = messaging.open_conversation(bob, "alice")
        assert sorted(m.text for m in msgs(items)) == ["different", "original"]
        w = warnings(items)
        assert [x.text for x in w] == ["⚠ CONFLICT: alice sent different messages with seq 0"]


class TestRobustness:
    def test_duplicate_msg_id_shown_once(self, alice, bob):
        mid = messaging.send(alice, "bobby", "once")
        src = envelope_path(alice, "bobby", mid)
        (src.parent / "copy-of-it.json").write_bytes(src.read_bytes())
        items = messaging.open_conversation(bob, "alice")
        assert [m.text for m in msgs(items)] == ["once"]
        assert not rejected(items) and not warnings(items)

    def test_garbage_and_oversized_files_dont_block_good_ones(self, alice, bob):
        messaging.send(alice, "bobby", "still readable")
        d = messaging.conv_dir(alice.home, "alice", "bobby")
        (d / "junk.json").write_bytes(os.urandom(300))
        (d / "empty.json").write_bytes(b"")
        (d / "big.json").write_bytes(b"x" * (1_000_000 + 1))
        (d / "note.txt").write_text("not an envelope")
        (d / "dir.json").mkdir()
        items = messaging.open_conversation(bob, "alice")
        assert [m.text for m in msgs(items)] == ["still readable"]
        rej = {r.file: r.reason for r in rejected(items)}
        assert set(rej) == {"junk.json", "empty.json", "big.json"}
        assert "too large" in rej["big.json"]
        assert all(r.startswith("malformed") for r in rej.values())

    @pytest.mark.parametrize(
        "content",
        [
            '{"header": [], "to": 5, "sig": null}',
            "[]",
            "null",
            '"just a string"',
            '{"header": {"v": 1}, "to": {}, "sig": "x"}',
        ],
    )
    def test_valid_json_wrong_types_rejected_not_crashing(self, alice, bob, content):
        messaging.send(alice, "bobby", "good")
        d = messaging.conv_dir(alice.home, "alice", "bobby")
        (d / "weird.json").write_text(content)
        items = messaging.open_conversation(bob, "alice")
        assert [m.text for m in msgs(items)] == ["good"]
        assert [r.reason.split(":")[0] for r in rejected(items)] == ["malformed"]

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda d: d["header"].update(ts="x"),
            lambda d: d["header"].update(seq=-1),
            lambda d: d["header"].update(seq=True),
            lambda d: d["header"].update(msg_id="../../etc"),
            lambda d: d["to"].pop("bobby"),
            lambda d: d["to"]["bobby"].update(kem_ct=7),
            lambda d: d.update(sig=None),
        ],
    )
    def test_field_level_type_errors_are_malformed(self, alice, bob, mutate):
        mid = messaging.send(alice, "bobby", "x")
        tamper(envelope_path(alice, "bobby", mid), mutate)
        items = messaging.open_conversation(bob, "alice")
        assert not msgs(items)
        assert [r.reason.split(":")[0] for r in rejected(items)] == ["malformed"]

    def test_messages_sorted_by_ts_then_msg_id(self, alice, bob):
        ids = {"late_low": "00" * 16, "early_high": "ff" * 16, "early_mid": "aa" * 16}
        forge(alice, bob, {"bobby": "L", "alice": "L"}, header={"msg_id": ids["late_low"]}, ts=200, seq=2)
        forge(alice, bob, {"bobby": "H", "alice": "H"}, header={"msg_id": ids["early_high"]}, ts=100, seq=1)
        forge(alice, bob, {"bobby": "M", "alice": "M"}, header={"msg_id": ids["early_mid"]}, ts=100, seq=0)
        order = [m.text for m in msgs(messaging.open_conversation(bob, "alice"))]
        assert order == ["M", "H", "L"]

    def test_one_bad_file_leaves_other_messages_intact(self, alice, bob):
        ids = send_three(alice)
        tamper(envelope_path(alice, "bobby", ids[1]), lambda d: d["header"].update(ts=1))
        items = messaging.open_conversation(bob, "alice")
        assert sorted(m.text for m in msgs(items)) == ["m0", "m2"]
        assert len(rejected(items)) == 1
