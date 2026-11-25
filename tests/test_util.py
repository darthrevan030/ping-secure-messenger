import os
import sys

import pytest

from ping import util


def test_canon_is_order_independent_and_compact():
    assert util.canon({"b": 1, "a": [2]}) == b'{"a":[2],"b":1}'


def test_canon_rejects_floats_nan():
    with pytest.raises(ValueError):
        util.canon({"x": float("nan")})


def test_b64_roundtrip_unpadded():
    assert util.b64e(b"\xff\xfe") == "__4"
    assert util.b64d("__4") == b"\xff\xfe"


def test_fingerprint_known_vector():
    assert (
        util.fingerprint(b"abc")
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_valid_username_accepts_and_rejects():
    assert util.valid_username("alice_01") == "alice_01"
    for bad in ["../x", "Bob", "ab", "a" * 33, "a b", ""]:
        with pytest.raises(ValueError):
            util.valid_username(bad)


def test_create_exclusive_refuses_overwrite(tmp_path):
    p = tmp_path / "m.json"
    util.create_exclusive(p, b"first")
    with pytest.raises(FileExistsError):
        util.create_exclusive(p, b"second")
    assert p.read_bytes() == b"first"


def test_atomic_write_replaces_and_sets_mode(tmp_path):
    p = tmp_path / "k.json"
    util.atomic_write(p, b"one")
    util.atomic_write(p, b"two")
    assert p.read_bytes() == b"two"
    assert [f.name for f in tmp_path.iterdir()] == ["k.json"]
    if sys.platform != "win32":
        assert os.stat(p).st_mode & 0o777 == 0o600


def test_read_limited_rejects_before_reading(tmp_path):
    big = tmp_path / "big"
    big.write_bytes(b"x" * 2048)
    small = tmp_path / "small"
    small.write_bytes(b"y" * 1024)
    with pytest.raises(util.TooLarge):
        util.read_limited(big, 1024)
    assert util.read_limited(small, 1024) == b"y" * 1024


def test_trace_prints_only_when_enabled(capsys):
    util.set_trace(False)
    util.trace("hidden")
    assert capsys.readouterr().out == ""
    util.set_trace(True)
    try:
        util.trace("shown")
        assert capsys.readouterr().out == "[trace] shown\n"
    finally:
        util.set_trace(False)
