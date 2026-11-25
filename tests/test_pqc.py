"""Checks of PQC behaviour the report relies on (§10).

Several of these exercise the `cryptography` library, not our code: they are what
makes the report's claims (sizes, implicit rejection, context separation) true on
this machine, and `scripts/pqc_lab.py` is what prints them.
"""

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

from scripts import pqc_lab


def test_tampered_kem_ciphertext_gives_different_secret_no_exception():
    secret, tampered = pqc_lab.implicit_rejection_demo()
    assert len(secret) == len(tampered) == 32
    assert tampered != secret


def test_wrong_length_kem_ciphertext_raises_valueerror():
    sk = mlkem.MLKEM768PrivateKey.generate()
    _, ct = sk.public_key().encapsulate()
    with pytest.raises(ValueError):
        sk.decapsulate(ct[:-1])


def test_mldsa_context_separation():
    ok_same, ok_other = pqc_lab.context_separation_demo()
    assert ok_same is True and ok_other is False
    sk = mldsa.MLDSA65PrivateKey.generate()
    sig = sk.sign(b"m", b"a")
    sk.public_key().verify(sig, b"m", b"a")
    with pytest.raises(InvalidSignature):
        sk.public_key().verify(sig, b"m", b"b")


def test_mldsa_signing_is_randomized():
    a, b = pqc_lab.randomized_signing_demo()
    assert a != b


def test_sizes_match_report_table():
    sizes = pqc_lab.sizes()
    assert sizes["ML-DSA-65"] == {"pk": 1952, "sig": 3309}
    assert sizes["ML-KEM-768"] == {"pk": 1184, "ct": 1088}


def test_main_prints_every_section(capsys):
    pqc_lab.main(runs=3)
    out = capsys.readouterr().out
    for title in ("Size and speed", "Implicit rejection", "Randomized signing",
                  "Context separation", "Parameter sets"):
        assert title in out
    for row in ("Ed25519", "ML-DSA-65", "X25519", "ML-KEM-768", "ML-DSA-44", "ML-DSA-87", "ML-KEM-1024"):
        assert row in out
