# Person A: crypto core + messaging, implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `util`, `auth`, `keystore`, `messaging` and `scripts/pqc_lab.py`, with tests, so Person B's `pki` / `ca` / `cli` can plug in through fixed interfaces.

**Architecture:** A flat package `ping/` at the repo root. `util` has no crypto policy. `auth` and `keystore` own the password → key → sealed-file chain. `messaging` is a KEM-DEM envelope (one ML-KEM copy per reader, encrypt-then-sign, signed plaintext commitment, per-sender `seq`). It calls `pki.verify_chain` (B's) on every public-key use. Every file is read fail-closed.

**Tech Stack:** Python 3.14, uv, `cryptography>=50.0.2` (verified: `mldsa.MLDSA{44,65,87}`, `mlkem.MLKEM{768,1024}`, `sign(data, context=...)`, `encapsulate()` / `decapsulate()`), pytest.

**Spec:** [plan-bare-bones.md](plan-bare-bones.md). Section references (§n) below point there.

## Status (2026-11-25)

Tasks 1–7 are built on branch `feat/sam/crypto-core-messenging` (100 passed, 1 skipped, each key check mutation-tested). Changes made after the original plan:

- **Review fixes:** known-answer tests for `_commit` and `_dem_key`, a re-signed-header test, an independent KAT for `kek_from_passphrase`.
- **Sealed `seq` counter** (`keystore.read_seq` / `write_seq`, `users/<u>/seq/<peer>.json`, role `user-seq`): `send` uses `max(counter, 1 + highest verified own seq)` and writes it before the envelope, so a number is never reused. `Session` gained `k_file` (hidden from `repr`, as is `keys`).
- **Display order** is `(ts, seq, msg_id)`.
- **Certificate renewal** needs no messaging change: `ca renew` (Person B) re-issues certificates for the same keys, and old messages verify again. Covered by `tests/test_seq_counter.py` using the stand-in's `Env.reissue`.
- **Test layout:** `test_messaging.py` (send/read), `test_messaging_rejections.py`, `test_messaging_robustness.py`, `test_seq_counter.py`, with helpers in `tests/messaging_helpers.py`.
- **Ruling:** "copies differ" is shown only to the reader whose copy mismatches the signed commitment (one commitment can't match both texts).

Still open: Task 8 (integrate with B's real `pki`, write `test_pki` / `test_e2e`) and Task 9 below.

## Global Constraints

- All asymmetric crypto is PQC: ML-DSA-87 root, ML-DSA-65 Sub-CA and user signing, ML-KEM-768 KEM. No classical asymmetric code.
- AES-256-GCM, Scrypt n=2^17 r=8 p=1, HKDF-SHA256, HMAC-SHA256, SHA-256.
- HKDF infos: `ping/auth`, `ping/keyfile`. Login verifier = `HMAC(K_auth, b"ping/login-v1")`, compared with `hmac.compare_digest`.
- ML-DSA contexts: `ping/v1/envelope`, `ping/v1/kem-bind`. Plaintext commitment prefix `ping/v1/pt`. DEM HKDF info prefix `ping/v1/dem`.
- Usernames `^[a-z0-9_]{3,32}$`. Passwords at least 12 chars (enforced by B's CLI; `auth` exposes the check).
- Limits: envelope file 1 MB, message text 4 KB, both checked before parsing.
- Key files mode 0600. Writes go to a temp file, then `os.replace`. Messages and requests use `O_EXCL`.
- Container JSON: `{"v":1,"alg":"AES-256-GCM","kdf":{...}|"user-login","owner","role","pub_fp","nonce","ct"}`, with `ct = AESGCM(kek).encrypt(nonce, der, aad=canon(all other fields))`.
- Private keys are PKCS#8 DER inside the container. Messages are canonical JSON with base64url.
- Nothing is committed (project decision, and the global rule is to commit only when asked). Each task ends with a full-suite run, not a commit.
- Tests use fast Scrypt parameters. Production defaults stay at n=2^17.

## Review Focus

1. A peer argument like `../x`, `Bob` or `a` (invalid username) is rejected before it touches a path.
2. Sending to yourself is refused. Empty text and text over 4 KB are refused. Non-ASCII text round-trips.
3. A well-formed JSON envelope with wrong types (`header` a list, `ts` a string, `copies` missing my entry) shows `⚠ REJECTED` and never raises.
4. A conversation with no `mail/<a>__<b>/` directory yields an empty list, not a crash.
5. A random-bytes file, an empty file, and a non-`.json` file in the mail dir are each handled without hiding the valid messages.

---

## Interface contract with Person B (agree on day 1)

The spec's signatures leave the sending user's keys out: `messaging.send(home, me, peer, text)` can't sign or decapsulate without them. This plan makes **`me` a `Session`** object (defined in `keystore`), which B's login builds and passes to messaging. **Raise this with B before starting.**

```python
# ping/util.py
canon(obj) -> bytes; b64e(b: bytes) -> str; b64d(s: str) -> bytes
fingerprint(der: bytes) -> str                       # hex SHA-256
valid_username(s: str) -> str                        # raises ValueError
atomic_write(path, data: bytes, mode=0o600) -> None
create_exclusive(path, data: bytes) -> None          # O_EXCL, raises FileExistsError
read_limited(path, limit: int) -> bytes              # raises TooLarge before reading everything
trace(msg: str) -> None; set_trace(on: bool) -> None

# ping/auth.py
SCRYPT = {"n": 2**17, "r": 8, "p": 1}                # tests monkeypatch "n"
new_salt() -> bytes
derive(password: str, salt: bytes) -> tuple[bytes, bytes]   # (k_auth, k_file)
make_verifier(k_auth: bytes) -> bytes
check_verifier(k_auth: bytes, verifier: bytes) -> bool
check_password_policy(password: str) -> None         # raises ValueError if < 12 chars

# ping/keystore.py
seal(payload: bytes, kek: bytes, *, owner: str, role: str, pub_fp: str, kdf) -> dict
open(container: dict, kek: bytes) -> bytes           # raises cryptography.exceptions.InvalidTag
kdf_params(salt: bytes) -> dict                      # {"name":"scrypt","n","r","p","salt"} for root/sub
kek_from_passphrase(passphrase: str, kdf: dict) -> bytes   # B's init-pki uses this for root/sub
@dataclass(frozen=True) class UserKeys: sign_priv; kem_priv; sign_pub_der; kem_pub_der
generate_user_keys() -> UserKeys
write_user_keys(home, user, keys: UserKeys, k_file: bytes) -> None   # sign.key.json, kem.key.json
load_user_keys(home, user, k_file: bytes) -> UserKeys
write_trust(home, user, root_fp: str, k_file) -> None
read_trust(home, user, k_file) -> str                # pinned root fp
@dataclass(frozen=True) class Session: home; user; keys: UserKeys; pinned_root_fp: str; k_file: bytes
read_seq(home, user, peer, k_file) -> int            # sealed per-conversation counter, 0 if absent; raises InvalidTag
write_seq(home, user, peer, next_seq, k_file) -> None   # users/<u>/seq/<peer>.json, role user-seq

# Added after review (not in spec §8): `send` uses max(sealed counter, 1 + highest verified own seq)
# and writes the counter BEFORE the envelope, so a deleted newest message, an expired certificate
# or a failed write can never cause a seq to be reused. Display order is (ts, seq, msg_id).
# Limit: deleting the counter file together with the newest message is indistinguishable
# from a fresh conversation; a rolled-back (older, valid) counter file is also accepted.
# Person B must implement `ca renew <u>`: re-issue both certificates for the user's EXISTING
# public keys with a fresh validity period. Old messages then verify again, because the sender's
# key fingerprint is unchanged; a renewal with a different signing key (rotation) deliberately
# does not vouch for old messages ("sender key mismatch"). `login` must build Session with k_file.

# ping/messaging.py
send(session: Session, peer: str, text: str) -> str            # returns msg_id
open_conversation(session: Session, peer: str) -> list[Item]   # Message | Rejected | Warning

# provided by B, consumed here
ping.pki.verify_chain(home, cert, purpose, user, pinned_root_fp, at) -> None   # raises ping.pki.ChainError
# (amended: `home` added so verify_chain can read pki/root.crt.pem and pki/sub.crt.pem; the code built so far
#  still uses the old form without `home` — updating it is Task 9)
ping.pki.load_cert(home, user, purpose) -> x509.Certificate              # reads certs/<u>/{sign,kem}.crt.pem
```

**Open dependency:** until B lands `pki`, messaging tests use `tests/pki_fixture.py` (Task 4), a test-only mini-PKI built directly with `cryptography.x509`. Once B's `pki` exists, Task 8 points the same tests at the real `verify_chain`.

---

## File structure

| File | Responsibility |
| --- | --- |
| `ping/__init__.py` | Empty package marker (shared with B; create if absent) |
| `ping/util.py` | Canonical JSON, base64url, fingerprint, username check, atomic and exclusive file I/O, size-limited read, trace |
| `ping/auth.py` | Scrypt + HKDF split, verifier |
| `ping/keystore.py` | AES-GCM container, PKCS#8 key files, trust pin, `Session` |
| `ping/messaging.py` | Envelope build, per-file verification pipeline, `seq` checks |
| `scripts/pqc_lab.py` | PQC demos for report §10 |
| `tests/conftest.py` | Fast-Scrypt fixture, `tmp_home` fixture |
| `tests/pki_fixture.py` | Test-only Root → Sub-CA → user cert builder (rogue CA, expired variants) |
| `tests/test_util.py`, `test_keystore_auth.py`, `test_messaging.py`, `test_pqc.py` | Tests |

---

### Task 1: Scaffold and `util`

**Files:**

- Modify: `pyproject.toml` (add dev dep `pytest`, `[tool.pytest.ini_options] pythonpath = ["."]`, `testpaths = ["tests"]`)
- Create: `ping/__init__.py`, `ping/util.py`, `tests/conftest.py`, `tests/test_util.py`

**Interfaces:**

- Produces: the `util` block in the contract above. `TooLarge(Exception)` is defined here.

- [ ] **Step 1: Add pytest** with `uv add --dev pytest`, then create the empty `ping/__init__.py` and an empty `tests/` directory. (`tests/conftest.py` needs `auth`, so it is written in Task 2.) Update the Files list: `tests/conftest.py` is not part of this task.
- [ ] **Step 2: Write failing tests** in `tests/test_util.py`:
  - `test_canon_is_order_independent_and_compact`: `canon({"b":1,"a":[2]}) == b'{"a":[2],"b":1}'` (literal expected value).
  - `test_canon_rejects_floats_nan`: `canon({"x": float("nan")})` raises `ValueError`.
  - `test_b64_roundtrip_unpadded`: `b64e(b"\xff\xfe") == "__4"` and `b64d("__4") == b"\xff\xfe"`.
  - `test_fingerprint_known_vector`: `fingerprint(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"`.
  - `test_valid_username_accepts_and_rejects`: accepts `"alice_01"`. Rejects `"../x"`, `"Bob"`, `"ab"`, `"a"*33`, `"a b"` with `ValueError`.
  - `test_create_exclusive_refuses_overwrite`: the second call raises `FileExistsError` and the file still holds the first bytes.
  - `test_atomic_write_replaces_and_sets_mode`: contents replaced, no `*.tmp` left in the dir. On POSIX, mode is `0o600` (skip the mode assertion on Windows).
  - `test_read_limited_rejects_before_reading`: a 2 KB file with `limit=1024` raises `TooLarge`. A 1 KB file with the same limit is returned.
- [ ] **Step 3: Run** `uv run pytest tests/test_util.py -v`. Expected: FAIL with `ModuleNotFoundError` / `ImportError`.
- [ ] **Step 4: Implement `ping/util.py`** per the contract. `canon` uses `json.dumps(sort_keys=True, separators=(",", ":"), allow_nan=False)` encoded as UTF-8. `read_limited` checks `os.stat().st_size` first, then reads at most `limit + 1` bytes. `trace` prints `[trace] <msg>` only when enabled.
- [ ] **Step 5: Run** `uv run pytest tests/test_util.py -v`. Expected: all PASS.
- [ ] **Step 6: Run the full suite** with `uv run pytest -q`. Expected: green.

---

### Task 2: `auth`

**Files:**

- Create: `ping/auth.py`, `tests/test_keystore_auth.py` (auth half), and `tests/conftest.py` (`fast_scrypt` autouse fixture, `tmp_home` fixture returning `tmp_path / "home"`)

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces: the `auth` block of the contract.

- [ ] **Step 1: Write failing tests** (class `TestAuth`):
  - `test_derive_is_deterministic_and_splits`: the same `(password, salt)` gives the same pair. `k_auth != k_file`. Both are 32 bytes. A different salt changes both.
  - `test_derive_known_answer`: with `SCRYPT n=2**4`, a hard-coded hex pair for `("correct horse battery", b"\x00"*16)`. Compute it once with an independent script using `hashlib.scrypt` + a hand-written HKDF in the test, and paste the hex. This proves the info strings.
  - `test_verifier_accepts_right_rejects_wrong`: `check_verifier(k_auth, make_verifier(k_auth))` is True. With a key derived from a wrong password it is False.
  - `test_verifier_does_not_open_key_files`: the verifier bytes differ from both `k_auth` and `k_file`.
  - `test_policy_rejects_short_password`: 11 chars raises `ValueError`, 12 chars passes.
  - `test_salt_is_random_16_bytes`: two `new_salt()` calls differ, and each is 16 bytes.
- [ ] **Step 2: Run** `uv run pytest tests/test_keystore_auth.py -v`. Expected: FAIL (import error).
- [ ] **Step 3: Implement `ping/auth.py`** per the contract. `derive` reads `SCRYPT` at call time. `check_verifier` uses `hmac.compare_digest`.
- [ ] **Step 4: Run** the file, then also run one **un-patched** call with `SCRYPT n=2**17` once, by hand: `uv run python -c "import time; from ping import auth; t=time.time(); auth.derive('x'*12, b'0'*16); print(time.time()-t)"`. Expected: no `ValueError` about memory, about 0.3 s. **If OpenSSL refuses (maxmem), report it**: the fix is in `derive` and the spec's Scrypt parameter claim needs re-checking.
- [ ] **Step 5: Run the full suite** `uv run pytest -q`. Expected: green.

---

### Task 3: `keystore`

**Files:**

- Create: `ping/keystore.py`
- Test: `tests/test_keystore_auth.py` (keystore half)

**Interfaces:**

- Consumes: `util.canon`, `b64e`, `b64d`, `fingerprint`, `atomic_write`; `auth.derive`, `auth.SCRYPT`.
- Produces: the `keystore` block of the contract. `UserKeys` holds live `MLDSA65PrivateKey` and `MLKEM768PrivateKey` objects plus the public SPKI DER bytes. `Session` is a frozen dataclass.

- [ ] **Step 1: Write failing tests** (class `TestKeystore`):
  - `test_seal_open_roundtrip`: `open(seal(b"secret", kek, owner="alice", role="user-sign", pub_fp="ab", kdf="user-login"), kek) == b"secret"`. The container has exactly the keys `v, alg, kdf, owner, role, pub_fp, nonce, ct`.
  - `test_wrong_kek_raises_invalid_tag`: a different 32-byte key raises `InvalidTag`.
  - `test_every_field_is_authenticated` (parametrised over `owner`, `role`, `pub_fp`, `kdf`, `v`, `alg`, and a flipped bit in `nonce` and `ct`): change the field, `open` raises `InvalidTag`. (A changed `nonce`/`ct` fails for the same reason; `v` and `alg` fail on schema or tag. Accept either `InvalidTag` or `ValueError` for those two only, and say which in the assertion message.)
  - `test_swapping_two_users_files_fails`: seal alice's and bob's keys under the same kek, put alice's `ct` into bob's container, `open` raises `InvalidTag`.
  - `test_nonce_is_fresh`: two seals of the same payload differ in `nonce` and `ct`.
  - `test_generate_and_reload_user_keys`: `write_user_keys`, then `load_user_keys` with the same `k_file`. The reloaded sign key signs a message that the original public key verifies (context `ping/v1/envelope`). The reloaded KEM key decapsulates an `encapsulate()` made to the original public key to the same secret. Files exist at `users/alice/sign.key.json` and `kem.key.json`.
  - `test_load_with_wrong_k_file_raises_invalid_tag`.
  - `test_load_rejects_pub_fp_mismatch`: re-seal alice's real PKCS#8 under the correct kek but with a wrong `pub_fp` in the container. `load_user_keys` raises `ValueError("pub_fp mismatch")`. (§5: check the public half against `pub_fp` after opening.)
  - `test_load_rejects_role_swap`: copy `sign.key.json` over `kem.key.json`, and `load_user_keys` raises. (Role is AAD-bound, but the loader must also check `role` and `owner` against what it expected, because it can build a container with matching tag if the attacker has `k_file`; the test seals a sign key under role `user-kem`.)
  - `test_trust_roundtrip_and_tamper`: `read_trust` returns the written fingerprint. A flipped byte in `trust.json` raises `InvalidTag`.
  - `test_passphrase_kek_for_ca`: `kek_from_passphrase("p"*12, kdf_params(b"s"*16))` is 32 bytes, deterministic, and changes with the passphrase.
  - `test_key_files_are_0600` (skip on Windows).
- [ ] **Step 2: Run** the file. Expected: FAIL.
- [ ] **Step 3: Implement `ping/keystore.py`.** Details the contract leaves open:
  - `seal`: nonce is 12 random bytes. AAD is `canon` of the container without `ct`.
  - `open`: rebuilds the AAD from the container the same way.
  - `write_user_keys` uses `private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())` on each key, seals with `role` `user-sign` / `user-kem` and `pub_fp = fingerprint(public SPKI DER)`, and uses `atomic_write`.
  - `load_user_keys` opens, then loads with `load_der_private_key`, recomputes the public SPKI DER, compares its fingerprint to `pub_fp` and checks `owner` and `role`.
  - `trust.json` uses role `user-trust` and the payload is `root_fp` in UTF-8, with `pub_fp = root_fp`.
  - **Check first** that `load_der_private_key` accepts ML-DSA / ML-KEM PKCS#8 in 50.0.2. If it does not, fall back to `from_seed_bytes` with the seed from `private_bytes_raw()`, and report the change, since §5 says PKCS#8.
- [ ] **Step 4: Run** the file. Expected: PASS.
- [ ] **Step 5: Run the full suite.** Expected: green.

---

### Task 4: Messaging: send and read, happy path

**Files:**

- Create: `ping/messaging.py`, `tests/pki_fixture.py`, `tests/test_messaging.py`

**Interfaces:**

- Consumes: `util.*`; `keystore.Session`, `UserKeys`; `pki.verify_chain`, `pki.load_cert` (B's; see the contract). The module imports `ping.pki as pki` and calls `pki.verify_chain` / `pki.load_cert` through the module, so tests can swap in the fixture.
- Produces:
  - `@dataclass Message: msg_id, seq, sender, ts, text, file`
  - `@dataclass Rejected: file, reason`
  - `@dataclass Warning: kind ("MISSING"|"CONFLICT"), text`
  - `Item = Message | Rejected | Warning`
  - `send`, `open_conversation` as in the contract
  - `conv_dir(home, a, b) -> Path` (sorted names, `a__b`)

**`tests/pki_fixture.py`** (test-only) builds, with `cryptography.x509` and ML-DSA keys, a Root (87) → Sub-CA (65, CA=true, pathlen 0) → per-user sign cert (`digitalSignature`) and KEM cert (`keyEncipherment`, CN=user). It writes them to `certs/<u>/{sign,kem}.crt.pem`. It also exposes `make_rogue_ca()` (a second, unrelated Root → Sub-CA) and `issue(user, keys, ca=...)`, and a `pki_stub` fixture that monkeypatches `ping.messaging.pki` with a namespace providing `load_cert` (reads those PEMs) and a minimal `verify_chain` (checks root fingerprint pin, issuer signature chain, KeyUsage purpose, CN). The stub is the one piece deliberately duplicating B's logic; keep it under 50 lines.

**Message file schema** (decided here, since the spec leaves it open):

```json
{"header": {"v":1,"msg_id":"<32 hex>","seq":0,"sender":"alice","recipient":"bob","ts":1760000000,
            "sender_sign_fp":"…","sender_kem_fp":"…","recipient_kem_fp":"…","pt_commit":"b64url"},
 "to": {"alice": {"kem_ct":"b64url","nonce":"b64url","ctext":"b64url"},
        "bob":   {"kem_ct":"…","nonce":"…","ctext":"…"}},
 "sig": "b64url"}
```

`sig = Sign(canon({"header":header,"to":to}), context=b"ping/v1/envelope")`. Per-reader AAD is `canon({"header":header,"r":R})`. DEM key is `HKDF(SHA256, 32, salt=None, info=b"ping/v1/dem" + kem_ct + SHA256(ek_R) + SHA256(canon(header)))` applied to the KEM shared secret. Plaintext inside AES-GCM is `pt_salt (32 B) ‖ utf-8 text`. `ts` is integer Unix seconds. `msg_id` is 16 random bytes in hex. Filename is `mail/<a>__<b>/<msg_id>.json`.

- [ ] **Step 1: Write failing tests**, using fixtures `alice`, `bob` (a `Session` each, built from `generate_user_keys()` + the fixture PKI):
  - `test_roundtrip_both_participants_read`: alice sends `"héllo 🙂"` to bob. `open_conversation(bob_session, "alice")` and `open_conversation(alice_session, "bob")` each return exactly one `Message` with `text == "héllo 🙂"`, `sender == "alice"`, `seq == 0`.
  - `test_seq_increments_per_sender`: alice sends 2, bob sends 1, alice sends 1 more. The alice seqs read back are `[0, 1, 2]` and bob's are `[0]`.
  - `test_envelope_has_both_copies_and_no_plaintext`: the written file parses as JSON with `to` keys `{"alice","bob"}`. The raw file bytes do not contain the text. The file name equals `header.msg_id + ".json"`.
  - `test_send_to_self_refused`: `ValueError`, and no file written.
  - `test_send_rejects_bad_peer_and_bad_text`: peers `"../x"`, `"Bob"` raise `ValueError`. Text `""` and `"a"*4097` (bytes) raise `ValueError`. Exactly 4096 bytes is accepted.
  - `test_send_refuses_unverifiable_recipient_cert`: recipient cert issued by the rogue CA, `send` raises `pki.ChainError`-equivalent (the stub's error type) and writes no file.
  - `test_open_empty_or_missing_conversation`: no directory yields `[]`.
- [ ] **Step 2: Run** `uv run pytest tests/test_messaging.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement `send`** (spec §8 Send steps 1–5), with `util.trace` lines per crypto step (algorithm and sizes). Create the conv dir if needed, write with `create_exclusive`. Compute `seq` as one more than the highest `seq` among messages in this conversation that `open_conversation` returns as verified `Message`s from `session.user`; 0 if none.
- [ ] **Step 4: Implement `open_conversation`**: list `*.json` in the conversation dir and run each through a private `_open_one(session, peer, path) -> Message` that raises `Reject(reason)`. Sort by `(ts, msg_id)`. Only the happy path is required now; Task 5 fills in the checks.
- [ ] **Step 5: Run** the file. Expected: PASS.
- [ ] **Step 6: Run the full suite.** Expected: green.

---

### Task 5: Messaging: fail-closed verification pipeline

**Files:**

- Modify: `ping/messaging.py` (`_open_one`)
- Test: `tests/test_messaging.py`

**Interfaces:**

- Consumes: Task 4. Produces: `Rejected.reason` strings below, which tests and `tamper_demo` (B's) match on.

Order inside `_open_one` is the spec's §8 Read: (1) schema, (2) sender chain + fingerprint, (3) signature **before any decryption**, (4) addressing, (5) decapsulate + HKDF + AES-GCM, (6) commitment. Reasons (substring-matched by tests):

| Failure | `Rejected.reason` contains |
| --- | --- |
| bad schema / wrong types / missing fields | `malformed` |
| sender certificate chain fails | `sender certificate` |
| cert fingerprint != `sender_sign_fp` | `sender key mismatch` |
| signature invalid | `bad signature` |
| not addressed to me and peer | `wrong conversation` |
| my KEM fingerprint absent from header | `not encrypted for you` |
| AES-GCM failure | `decryption failed` |
| commitment mismatch | `copies differ` |

- [ ] **Step 1: Write failing tests**, each: alice → bob message made normally, then tampered in the file, then read as bob; assert exactly one `Rejected` with the reason above and **no** `Message`. Use a helper `tamper(path, fn)` that loads the JSON, mutates, rewrites.
  - `test_flipped_header_field_rejected`: change `header.ts` → `bad signature`.
  - `test_flipped_ciphertext_rejected`: flip a bit in `to.bob.ctext`. The signature covers `to`, so → `bad signature`. A second case re-signs with alice's real key after the flip, and expects `decryption failed` (proves the AEAD layer on its own).
  - `test_flipped_signature_rejected` → `bad signature`.
  - `test_signature_checked_before_decryption`: with `monkeypatch`, make `AESGCM.decrypt` raise `AssertionError` and verify that a bad-signature file still yields `bad signature` without ever reaching it.
  - `test_envelope_copied_into_another_conversation`: copy alice→bob's file into `mail/alice__carol/` and read as carol (a third session) with peer `alice` → `wrong conversation` or `not encrypted for you` (assert on one named reason, chosen by which check your code hits first, and document it in the test).
  - `test_signed_by_mallory_under_alices_name`: mallory has a valid cert, signs an envelope whose header says `sender: "alice"` → `sender certificate` (CN mismatch) or `sender key mismatch`. Name the one produced.
  - `test_rogue_ca_kem_cert_swapped_in`: bob's KEM cert replaced by one from the rogue CA, sender side `send` already refuses (Task 4). On the read side, an attacker-built envelope encrypted to a rogue KEM key with `recipient_kem_fp` of that key and a **valid** alice signature → `not encrypted for you` (bob's KEM fp is absent).
  - `test_different_plaintext_in_two_copies`: build an envelope by hand (using the module's own private helpers or a copy of the steps in the test) where the bob copy and the alice copy hold different texts, correctly signed. Bob and alice both → `copies differ`.
  - `test_wrong_context_signature_rejected`: signature made over the same bytes with `context=b"ping/v1/kem-bind"` → `bad signature`.
  - `test_expired_sender_cert_rejected`: sender cert expired in the fixture → `sender certificate`.
  - `test_wrong_purpose_cert_as_signing_cert`: the sender's KEM cert presented in place of the sign cert → `sender certificate`.
- [ ] **Step 2: Run.** Expected: the new tests FAIL (fail-open or wrong reason).
- [ ] **Step 3: Implement the checks in `_open_one`** in the order above. Wrap each stage so the only exceptions that escape are `Reject`. Any other exception inside a stage becomes a `Reject` with the stage's reason (never a traceback).
- [ ] **Step 4: Run** `uv run pytest tests/test_messaging.py -v`. Expected: PASS.
- [ ] **Step 5: Run the full suite.** Expected: green.

---

### Task 6: Messaging: `seq`, duplicates, robustness

**Files:**

- Modify: `ping/messaging.py` (`open_conversation`)
- Test: `tests/test_messaging.py`

**Interfaces:**

- Produces: `Warning` items appended after all messages: `MISSING` text `⚠ MISSING: n message(s) from <sender> before seq k`, `CONFLICT` text `⚠ CONFLICT: <sender> sent different messages with seq k`.

Decisions made here (the spec leaves them open; flag them to B): duplicate means **two files with the same `header.msg_id`**: the first by filename order is kept and the others are dropped silently. The filename stem is not required to equal `msg_id`. A gap is judged per sender over accepted `Message`s only.

- [ ] **Step 1: Write failing tests:**
  - `test_deleted_middle_message_reports_gap`: alice sends 3, the middle file is deleted. Bob sees 2 messages and a `MISSING` warning naming `alice`, 1 message, before seq 2.
  - `test_deleted_newest_is_not_detected`: alice sends 3, the last is deleted. No warning, 2 messages (documents the stated limit).
  - `test_two_messages_same_seq_conflict`: craft a second valid envelope from alice with `seq=0` and a different text. A `CONFLICT` warning for seq 0. Both messages are still shown.
  - `test_duplicate_msg_id_shown_once`: copy a valid file under another filename, and exactly one `Message` and no `Rejected`.
  - `test_garbage_and_oversized_files_dont_block_good_ones`: put in the dir `junk.json` (random bytes), `empty.json` (0 B), `big.json` (1 MB + 1 B), `note.txt`, and one valid message. Result: the valid `Message`, a `Rejected` for each `.json` junk file (`malformed` / `too large`), and `note.txt` ignored.
  - `test_valid_json_wrong_types_rejected_not_crashing`: `{"header": [], "to": 5, "sig": null}` → `Rejected` `malformed`. Also a header with `ts: "x"`, and a `to` missing my entry.
  - `test_messages_sorted_by_ts_then_msg_id`: write two valid messages with equal `ts` and check the order matches `msg_id`.
  - `test_one_bad_file_leaves_other_messages_intact`: tamper one of three messages; the other two are returned as `Message`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** in `open_conversation`: size check via `read_limited(path, 1_000_000)` before `json.loads`, dedupe by `msg_id`, sort, then `_seq_warnings(messages) -> list[Warning]`.
- [ ] **Step 4: Run** the file. Expected: PASS.
- [ ] **Step 5: Run the full suite.** Expected: green.

---

### Task 7: `scripts/pqc_lab.py` and `test_pqc`

**Files:**

- Create: `scripts/pqc_lab.py`, `tests/test_pqc.py`

**Interfaces:** Consumes only `cryptography`. Produces a script with `main()` that prints five sections (spec §10) and helper functions `implicit_rejection_demo() -> tuple[bytes, bytes]` and `context_separation_demo() -> tuple[bool, bool]` the tests import.

- [ ] **Step 1: Write failing tests** in `tests/test_pqc.py`:
  - `test_tampered_kem_ciphertext_gives_different_secret_no_exception`: encapsulate with ML-KEM-768, flip one byte of the ciphertext, `decapsulate` returns 32 bytes `!=` the original secret and does not raise.
  - `test_wrong_length_kem_ciphertext_raises_valueerror`.
  - `test_mldsa_context_separation`: signature under `b"a"` verifies under `b"a"` and raises `InvalidSignature` under `b"b"`.
  - `test_mldsa_signing_is_randomized`: two signatures of the same message differ, and both verify.
  - `test_sizes_match_report_table`: ML-DSA-65 public key is 1952 B and signature 3309 B; ML-KEM-768 public key is 1184 B and ciphertext 1088 B (these are the spec's §10 numbers, and the test is what makes them true).
- [ ] **Step 2: Run.** Expected: FAIL if `pqc_lab` helpers are imported, otherwise note which pass already (they test the library, so they validate the spec's claims, not our code; say so in the file header comment).
- [ ] **Step 3: Implement `pqc_lab.py`**: five sections: size/speed table (Ed25519, ML-DSA-65, X25519, ML-KEM-768, timed with `time.perf_counter` over N=200 runs, printed in the §10 column layout), implicit rejection, randomized signing, context separation, parameter-set comparison (ML-DSA-44/65/87, ML-KEM-768/1024: key/sig/ct sizes).
- [ ] **Step 4: Run** `uv run pytest tests/test_pqc.py -v` and `uv run python scripts/pqc_lab.py`. Expected: PASS, and the printed table replaces the sandbox numbers in the report.
- [ ] **Step 5: Run the full suite.** Expected: green.

---

### Task 8: Integrate with B and write B's tests (blocked until B delivers `pki`, `ca`, `cli`)

**Files:**

- Modify: `tests/test_messaging.py` (drop `pki_stub` in favor of the real `ping.pki`)
- Create: `tests/test_pki.py`, `tests/test_e2e.py` (the spec makes each partner test the other's modules)

- [ ] **Step 1:** Make the messaging fixtures issue certs through B's `ca` functions instead of `tests/pki_fixture.py`. Keep the rogue CA builder in the fixture. Run `uv run pytest tests/test_messaging.py`. **Expected: the same tests pass.** Any difference between the stub and B's `verify_chain` is a bug in one of them: report it, don't weaken a test.
- [ ] **Step 2:** Write `test_pki.py` from spec §13: chain verifies; rejected: rogue Root, swapped Root file (pin), expired, KEM cert as signing cert and the reverse, CA cert as leaf, wrong CN; the CA ignores requested extensions; approval refused for bad CSR signature, bad `bind`, name already issued. Each rejection test asserts the specific `ChainError` message, and each also has a positive twin so the fixture cannot be toothless.
- [ ] **Step 3:** Write `test_e2e.py`: sign-up → approve → login → send → read through B's CLI functions. Capture logs with `caplog` and trace output with `capsys`, and assert neither contains the password, `k_file` hex, or any private key bytes.
- [ ] **Step 4: Run the full suite.** Expected: green. Also run `uv run python -m pytest --co -q` and check no test file imports `ping.messaging.pki` stubs any more.

---

### Task 9: `verify_chain` takes `home` (do together with Task 8)

**Files:**

- Modify: `ping/messaging.py` (the two `pki.verify_chain(...)` calls, in `send` and `_open_one`), `tests/pki_fixture.py` (`Env._verify_chain` gains the leading `home` parameter and stops closing over `self.home`)
- Test: `tests/test_messaging.py`, `tests/test_messaging_rejections.py`

**Interfaces:**

- Consumes: B's `pki.verify_chain(home, cert, purpose, user, pinned_root_fp, at)`.

- [ ] **Step 1:** Change the stand-in's signature first. Run `uv run pytest -q`. Expected: FAIL in every test that sends or reads (the call sites still use the old form).
- [ ] **Step 2:** Pass `session.home` as the first argument at both call sites. Run `uv run pytest -q`. Expected: all pass again.
- [ ] **Step 3:** With B's real `pki` in place, make expiry tests deterministic by patching `messaging._now` to a time past the certificates' validity, not by backdating certificates. Run the full suite. Expected: green.

---

## Self-review

- **Spec coverage:** §2 and §10 → Task 7. §4 and §5 → Task 3. Auth (§8) → Task 2. Send and Read (§8) → Tasks 4–6. §13 `test_keystore_auth`, `test_messaging`, `test_pqc` → Tasks 2, 3, 5, 6, 7. `test_pki` and `test_e2e` → Task 8. Report sections §2, §4, §5, messaging flows and §10 are prose work for Person A. They come after Task 6 and 7 and are not code tasks here. **Not covered on purpose:** `pki`, `ca`, `cli`, `tamper_demo`, which are B's.
- **Type consistency:** `Session`, `UserKeys`, `Message` / `Rejected` / `Warning`, and the reasons table are defined once and reused by name.
- **Spec gaps this plan filled (confirm with B):** `Session` as the first parameter of `send` / `open_conversation`; the envelope's `to` object and what the signature covers; duplicate = same `header.msg_id`; `ts` as integer seconds; empty text refused; the `Rejected.reason` strings, which B's `tamper_demo` will print.
- **Risks to check early:** PKCS#8 loading for ML-DSA / ML-KEM (Task 3), Scrypt n=2^17 under OpenSSL's memory cap (Task 2), and whether `uv run` picks Python 3.14 (the system Python is 3.11; `.python-version` pins 3.14).
