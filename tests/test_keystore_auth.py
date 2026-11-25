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


# ---------------------------------------------------------------- keystore
import copy
import hashlib
import json
import os
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

from ping import keystore, util

KEK = b"k" * 32


def _seal(payload=b"secret", **over):
    args = dict(owner="alice", role="user-sign", pub_fp="ab", kdf="user-login")
    args.update(over)
    return keystore.seal(payload, KEK, **args)


def _flip_b64(s: str) -> str:
    raw = bytearray(util.b64d(s))
    raw[0] ^= 1
    return util.b64e(bytes(raw))


class TestKeystore:
    def test_seal_open_roundtrip(self):
        c = _seal()
        assert keystore.open(c, KEK) == b"secret"
        assert set(c) == {"v", "alg", "kdf", "owner", "role", "pub_fp", "nonce", "ct"}

    def test_wrong_kek_raises_invalid_tag(self):
        with pytest.raises(InvalidTag):
            keystore.open(_seal(), b"j" * 32)

    @pytest.mark.parametrize(
        "field,value",
        [
            ("owner", "mallory"),
            ("role", "user-kem"),
            ("pub_fp", "cd"),
            ("kdf", {"name": "scrypt"}),
        ],
    )
    def test_every_metadata_field_is_authenticated(self, field, value):
        c = _seal()
        c[field] = value
        with pytest.raises(InvalidTag):
            keystore.open(c, KEK)

    @pytest.mark.parametrize("field", ["nonce", "ct"])
    def test_flipped_bit_in_nonce_or_ct_fails(self, field):
        c = _seal()
        c[field] = _flip_b64(c[field])
        with pytest.raises(InvalidTag):
            keystore.open(c, KEK)

    @pytest.mark.parametrize("field,value", [("v", 2), ("alg", "AES-128-GCM")])
    def test_version_and_alg_changes_are_refused(self, field, value):
        c = _seal()
        c[field] = value
        with pytest.raises(ValueError):
            keystore.open(c, KEK)

    def test_missing_field_is_valueerror(self):
        c = _seal()
        del c["owner"]
        with pytest.raises(ValueError):
            keystore.open(c, KEK)

    def test_swapping_two_users_files_fails(self):
        alice = _seal(b"alice-key", owner="alice")
        bob = _seal(b"bob-key", owner="bob")
        franken = copy.deepcopy(bob)
        franken["ct"] = alice["ct"]
        with pytest.raises(InvalidTag):
            keystore.open(franken, KEK)
        # and bob's own container still opens: the swap, not the fixture, failed
        assert keystore.open(bob, KEK) == b"bob-key"

    def test_nonce_is_fresh(self):
        a, b = _seal(), _seal()
        assert a["nonce"] != b["nonce"] and a["ct"] != b["ct"]

    def test_generate_and_reload_user_keys(self, tmp_home):
        keys = keystore.generate_user_keys()
        keystore.write_user_keys(tmp_home, "alice", keys, KEK)
        assert (tmp_home / "users/alice/sign.key.json").is_file()
        assert (tmp_home / "users/alice/kem.key.json").is_file()
        back = keystore.load_user_keys(tmp_home, "alice", KEK)
        assert isinstance(back.sign_priv, mldsa.MLDSA65PrivateKey)
        assert isinstance(back.kem_priv, mlkem.MLKEM768PrivateKey)
        sig = back.sign_priv.sign(b"msg", b"ping/v1/envelope")
        keys.sign_priv.public_key().verify(sig, b"msg", b"ping/v1/envelope")
        ss, ct = keys.kem_priv.public_key().encapsulate()
        assert back.kem_priv.decapsulate(ct) == ss
        assert back.sign_pub_der == keys.sign_pub_der
        assert back.kem_pub_der == keys.kem_pub_der

    def test_public_der_is_spki_of_the_private_key(self):
        keys = keystore.generate_user_keys()
        spki = keys.sign_priv.public_key().public_bytes(
            ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo
        )
        assert keys.sign_pub_der == spki

    def test_load_with_wrong_k_file_raises_invalid_tag(self, tmp_home):
        keystore.write_user_keys(tmp_home, "alice", keystore.generate_user_keys(), KEK)
        with pytest.raises(InvalidTag):
            keystore.load_user_keys(tmp_home, "alice", b"j" * 32)

    def test_load_rejects_pub_fp_mismatch(self, tmp_home):
        keys = keystore.generate_user_keys()
        der = keys.sign_priv.private_bytes(
            ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption()
        )
        bad = keystore.seal(
            der, KEK, owner="alice", role="user-sign", pub_fp="00" * 32, kdf="user-login"
        )
        keystore.write_user_keys(tmp_home, "alice", keys, KEK)
        (tmp_home / "users/alice/sign.key.json").write_text(json.dumps(bad))
        with pytest.raises(ValueError, match="pub_fp mismatch"):
            keystore.load_user_keys(tmp_home, "alice", KEK)

    def test_load_rejects_role_swap(self, tmp_home):
        keys = keystore.generate_user_keys()
        keystore.write_user_keys(tmp_home, "alice", keys, KEK)
        d = tmp_home / "users/alice"
        (d / "kem.key.json").write_bytes((d / "sign.key.json").read_bytes())
        with pytest.raises(ValueError, match="role"):
            keystore.load_user_keys(tmp_home, "alice", KEK)

    def test_load_rejects_another_users_file(self, tmp_home):
        keystore.write_user_keys(tmp_home, "alice", keystore.generate_user_keys(), KEK)
        keystore.write_user_keys(tmp_home, "bobby", keystore.generate_user_keys(), KEK)
        (tmp_home / "users/alice/sign.key.json").write_bytes(
            (tmp_home / "users/bobby/sign.key.json").read_bytes()
        )
        with pytest.raises(ValueError, match="owner"):
            keystore.load_user_keys(tmp_home, "alice", KEK)

    def test_trust_roundtrip_and_tamper(self, tmp_home):
        keystore.write_trust(tmp_home, "alice", "ab" * 32, KEK)
        assert keystore.read_trust(tmp_home, "alice", KEK) == "ab" * 32
        p = tmp_home / "users/alice/trust.json"
        c = json.loads(p.read_text())
        c["ct"] = _flip_b64(c["ct"])
        p.write_text(json.dumps(c))
        with pytest.raises(InvalidTag):
            keystore.read_trust(tmp_home, "alice", KEK)

    def test_passphrase_kek_for_ca(self):
        kdf = keystore.kdf_params(b"s" * 16)
        assert kdf["name"] == "scrypt" and set(kdf) >= {"n", "r", "p", "salt"}
        a = keystore.kek_from_passphrase("p" * 12, kdf)
        assert a == hashlib.scrypt(b"p" * 12, salt=b"s" * 16, n=16, r=8, p=1, dklen=32)
        assert a != keystore.kek_from_passphrase("q" * 12, kdf)
        assert a != keystore.kek_from_passphrase("p" * 12, keystore.kdf_params(b"t" * 16))

    def test_ca_key_sealed_with_passphrase_kek_roundtrips(self):
        kdf = keystore.kdf_params(b"s" * 16)
        kek = keystore.kek_from_passphrase("p" * 12, kdf)
        c = keystore.seal(b"root", kek, owner="ca", role="root", pub_fp="ab", kdf=kdf)
        assert keystore.open(c, kek) == b"root"
        c["kdf"] = dict(kdf, n=kdf["n"] * 2)
        with pytest.raises(InvalidTag):
            keystore.open(c, kek)

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
    def test_key_files_are_0600(self, tmp_home):
        keystore.write_user_keys(tmp_home, "alice", keystore.generate_user_keys(), KEK)
        for name in ("sign.key.json", "kem.key.json"):
            assert os.stat(tmp_home / "users/alice" / name).st_mode & 0o777 == 0o600
