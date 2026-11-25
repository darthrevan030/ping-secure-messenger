import pytest

from ping import auth


class TestAuth:
    def test_derive_is_deterministic_and_splits(self):
        salt = b"s" * 16
        k_auth, k_file = auth.derive("correct horse battery", salt)
        assert (k_auth, k_file) == auth.derive("correct horse battery", salt)
        assert k_auth != k_file
        assert len(k_auth) == len(k_file) == 32
        o_auth, o_file = auth.derive("correct horse battery", b"t" * 16)
        assert o_auth != k_auth and o_file != k_file

    def test_derive_known_answer(self):
        # Vector computed independently with hashlib.scrypt (n=16) and a
        # hand-written HKDF-SHA256 (zero salt), info = ping/auth, ping/keyfile.
        k_auth, k_file = auth.derive("correct horse battery", b"\x00" * 16)
        assert k_auth.hex() == (
            "dc0d02932c5bd3906fb713f3573d738871140c2fa762e1987a8a44f14f041717"
        )
        assert k_file.hex() == (
            "5e9a0de2e66e1e16caa9e07c0656ee819647c5d002f063906970f08697d826d7"
        )

    def test_verifier_accepts_right_rejects_wrong(self):
        salt = auth.new_salt()
        k_auth, _ = auth.derive("correct horse battery", salt)
        verifier = auth.make_verifier(k_auth)
        assert auth.check_verifier(k_auth, verifier) is True
        wrong, _ = auth.derive("correct horse batterz", salt)
        assert auth.check_verifier(wrong, verifier) is False

    def test_verifier_does_not_open_key_files(self):
        k_auth, k_file = auth.derive("correct horse battery", b"s" * 16)
        verifier = auth.make_verifier(k_auth)
        assert verifier not in (k_auth, k_file)

    def test_policy_rejects_short_password(self):
        with pytest.raises(ValueError):
            auth.check_password_policy("a" * 11)
        auth.check_password_policy("a" * 12)

    def test_salt_is_random_16_bytes(self):
        a, b = auth.new_salt(), auth.new_salt()
        assert a != b and len(a) == len(b) == 16
