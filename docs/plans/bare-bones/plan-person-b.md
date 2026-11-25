# Person B: PKI + app, implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `pki`, `ca`, `accounts` (sign-up / login), `cli` and `scripts/tamper_demo.py`, with tests, so Alice and Bob can sign up, get certified, log in and chat from the command line, and every attack in the demo prints `ATTACK → REJECTED: <reason>`.

**Architecture:** `pki` owns certificates (build, load, verify chain). `ca` is an offline admin tool built on `pki` and `keystore`; no user process ever holds a CA key. `accounts` composes `auth`, `keystore`, `pki` into sign-up and login and returns a `keystore.Session`. `cli` is argparse plus a menu on top of `accounts`, `ca` and `messaging`.

**Tech Stack:** Python 3.14, uv, `cryptography>=50.0.2` (verified: ML-DSA-signed CSRs and certificates work, `is_signature_valid` detects a tampered CSR, SAN URIs and `not_valid_*_utc` are available), pytest.

**Spec:** [plan-bare-bones.md](plan-bare-bones.md) (§6 PKI, §8 flows, §9 CLI, §13 tests). Person A's side: [plan-person-a.md](plan-person-a.md).

## Prerequisites

- Person A's `util`, `auth`, `keystore`, `messaging` live on branch `feat/sam/crypto-core-messenging` (not on `main` yet). Merge or branch from it before starting. B must not edit those files: ask A, or add a test and report.
- Run everything with `uv run` (the system Python is 3.11; the project needs 3.14).
- Nothing is committed unless the project owners ask (project decision).

## Global Constraints

- Root ML-DSA-87 (10 y), Sub-CA ML-DSA-65 (5 y, CA=true, pathlen 0), user sign and KEM certificates 1 y (spec §2, §4, §6).
- User sign cert: KeyUsage `digitalSignature`, ML-DSA-65 key. User KEM cert: KeyUsage `keyEncipherment` only, ML-KEM-768 key. CA=false, CN = username, SAN URI `ping:user:<u>`.
- The CA sets subject, SAN, KeyUsage and BasicConstraints itself and ignores everything requested in the CSR.
- `verify_chain` is called on every use of a public key and never caches "trusted".
- Trust pin: the Root fingerprint the user confirmed at sign-up, sealed in `trust.json`.
- Usernames `^[a-z0-9_]{3,32}$` (`util.valid_username`); passwords and CA passphrases at least 12 chars.
- Request files at most 64 KB, read with `util.read_limited` before parsing. Writes are atomic; requests are created exclusively.
- ML-DSA contexts: `ping/v1/kem-bind` for the KEM binding (A already uses `ping/v1/envelope` for messages).
- `--trace` lines (`util.trace`) for every crypto step B performs: algorithm and sizes, never key material.
- Tests use fast Scrypt (the `fast_scrypt` autouse fixture in `tests/conftest.py`).

## Review Focus

1. `ca approve ../x`, `ca renew Bob` and a request file named for another user are refused before any path is used.
2. A garbage, empty, oversized or wrong-typed request file is refused with a message, never a traceback, and does not stop `ca list` or other approvals.
3. `init-pki` run twice refuses and leaves the existing keys untouched.
4. Login for an unknown user and for a wrong password give the identical message, and both spend one Scrypt derivation.
5. Aborting sign-up at the fingerprint prompt, or a crash after the name is claimed, never leaves a half-created account that blocks the name forever.

---

## Interface contract with Person A

```python
# ping/pki.py
class ChainError(Exception): ...
def create_root(now=None) -> tuple[MLDSA87PrivateKey, x509.Certificate]
def create_sub(root_key, root_cert, now=None) -> tuple[MLDSA65PrivateKey, x509.Certificate]
def issue_user_cert(sub_key, sub_cert, user, public_key, purpose, now=None) -> x509.Certificate  # purpose "sign"|"kem"
def root_fingerprint(root_cert) -> str                      # util.fingerprint(SPKI DER)
def bind_message(user: str, ek_der: bytes) -> bytes         # canon({"user": user, "ek_fp": fingerprint(ek_der)})
def load_cert(home, user, purpose) -> x509.Certificate      # certs/<u>/{sign,kem}.crt.pem; FileNotFoundError if absent
def verify_chain(home, cert, purpose, user, pinned_root_fp, at) -> None   # raises ChainError (message contains the reasons below)

# ping/ca.py
class CAError(Exception): ...
def init_pki(home, root_pass, sub_pass, now=None) -> str    # returns the Root fingerprint
def list_pending(home) -> list[str]
def approve(home, user, sub_pass, now=None) -> None
def renew(home, user, sub_pass, now=None) -> None

# ping/accounts.py
class LoginError(Exception): ...          # "wrong username or password"
class PendingApproval(Exception): ...
class TamperedError(Exception): ...
class CertificateProblem(Exception): ...  # includes "certificate expired: ask the CA to renew"
def signup(home, username, password, confirm_root_fp: Callable[[str], bool]) -> None
def login(home, username, password) -> keystore.Session
```

`messaging` calls `pki.load_cert` and `pki.verify_chain` through the module, with `home` as the first `verify_chain` argument (an amendment to the spec's signature: A's Task 9 switches its two call sites). Person A shows `ChainError` text as `sender certificate invalid: <text>`.

`ChainError` messages (tests match these substrings): `root fingerprint does not match pin`, `bad issuer`, `certificate expired`, `certificate not yet valid`, `not a CA` (Sub-CA or Root without CA=true), `path length`, `leaf is a CA certificate`, `wrong key type`, `wrong key usage`, `wrong subject`.

**Check order** in `verify_chain`: pin → issuer links → validity of all three at `at` → BasicConstraints and path length → key types → KeyUsage for `purpose` → CN and SAN.

**Request file** `requests/<u>.json` (written by `signup`, read by `ca`):
`{"v":1,"user":"alice","csr":"<PEM>","ek":"<b64url ML-KEM-768 SPKI DER>","bind":"<b64url ML-DSA sig>"}`, where `bind = Sign(pki.bind_message(user, ek_der), context=b"ping/v1/kem-bind")` under the CSR's key.

**`account.json`** `users/<u>/account.json` (plain, not secret): `{"v":1,"user":"alice","salt":"<b64url>","verifier":"<b64url>"}`.

---

## File structure

| File | Responsibility |
| --- | --- |
| `ping/pki.py` | Certificate building, loading, chain verification |
| `ping/ca.py` | `init_pki`, `list_pending`, `approve`, `renew` |
| `ping/accounts.py` | `signup`, `login` |
| `ping/cli.py`, `ping/__main__.py` | argparse, menu, rendering; `uv run python -m ping …` |
| `scripts/tamper_demo.py` | The attack demo |
| `tests/real_env.py` | Test helper: a real PKI home with users made through the real flows |
| `tests/test_pki.py`, `test_ca.py`, `test_accounts.py`, `test_cli.py`, `test_tamper_demo.py`, `test_e2e.py` | Tests |

---

### Task 1: `pki`

**Files:**

- Create: `ping/pki.py`, `tests/test_pki.py`

**Interfaces:**

- Produces: the `pki` block above. Builders are used by `ca` and by tests.

- [ ] **Step 1: Write failing tests** in `tests/test_pki.py`. A fixture builds a real chain with the builders and writes `pki/root.crt.pem`, `pki/sub.crt.pem` and `certs/alice/{sign,kem}.crt.pem` into `tmp_home`. Every rejection test has the passing call as its twin (`verify_chain(...)` with the unmodified inputs returns `None`):
  - `test_valid_chain_verifies_for_both_purposes`.
  - `test_rogue_root_rejected`: a leaf from a second, unrelated PKI → `bad issuer`.
  - `test_swapped_root_file_rejected_by_pin`: `pki/root.crt.pem` replaced by another Root, pin = the original fingerprint → `root fingerprint does not match pin`.
  - `test_expired_and_not_yet_valid`: `at` = leaf `not_valid_after_utc` + 1 s → `certificate expired`; `at` = `not_valid_before_utc` − 1 s → `certificate not yet valid`. Also an expired Sub-CA (built with an old `now`) → `certificate expired`.
  - `test_kem_cert_as_signing_cert_and_reverse`: each → `wrong key type` (the key type check comes before KeyUsage).
  - `test_ca_cert_as_leaf`: a leaf built by the Sub-CA key with CA=true (built in the test with `cryptography` directly) → `leaf is a CA certificate`.
  - `test_sub_ca_path_length`: a Sub-CA built with path length 1 → `path length`. A Sub-CA with CA=false → `not a CA`.
  - `test_wrong_cn_and_wrong_san`: expected user `bobby` for alice's cert → `wrong subject`; a cert with the right CN but SAN `ping:user:bobby` → `wrong subject`.
  - `test_cert_properties`: the issued sign cert has KeyUsage `digitalSignature` only, the KEM cert `keyEncipherment` only, both CA=false, SAN `ping:user:alice`, validity 365 days; the Sub-CA has pathlen 0 and 5 y; the Root is self-signed.
  - `test_load_cert_missing_raises_filenotfound`.
  - `test_bind_message_known_value`: `bind_message("alice", b"\x00")` equals the literal canonical JSON bytes with `fingerprint(b"\x00")` computed independently (hashlib) in the test.
- [ ] **Step 2: Run** `uv run pytest tests/test_pki.py -v`. Expected: FAIL (`ModuleNotFoundError`).
- [ ] **Step 3: Implement `ping/pki.py`.** Builders use `x509.CertificateBuilder` signed with `sign(key, None)`, random serials, `not_valid_before = now − 5 min` (clock skew). `verify_chain` uses `verify_directly_issued_by` for each link and `not_valid_before_utc` / `not_valid_after_utc`. Add `util.trace` lines for pin check and each link.
- [ ] **Step 4: Run** the file. Expected: all PASS.
- [ ] **Step 5: Run the full suite** `uv run pytest -q`. Expected: green.

---

### Task 2: `ca`

**Files:**

- Create: `ping/ca.py`, `tests/test_ca.py`

**Interfaces:**

- Consumes: `pki.*`, `keystore.seal`, `keystore.open`, `keystore.kdf_params`, `keystore.kek_from_passphrase`, `util.*`.
- Produces: the `ca` block above. Layout from spec §7: `pki/root.key.json`, `sub.key.json` (roles `root`, `sub`, kdf = scrypt params, `owner` = `ca`), `root.crt.pem`, `sub.crt.pem`.

- [ ] **Step 1: Write failing tests** (`tests/test_ca.py`; helper `make_request(home, name, **tamper)` builds a valid request file the way `signup` will, so it can break one part at a time):
  - `test_init_pki_creates_sealed_keys_and_certs`: files exist; the two key files open only with their own passphrase (the other gives `InvalidTag`); the returned fingerprint equals `pki.root_fingerprint` of the written Root cert; Root key file `pub_fp` matches the Root cert.
  - `test_init_pki_refuses_second_run`: raises `FileExistsError` and the files' bytes are unchanged.
  - `test_init_pki_rejects_short_passphrases`.
  - `test_approve_issues_both_certs_that_verify`: `verify_chain` passes for `sign` and `kem`; the request file is gone; `list_pending` no longer shows the user.
  - `test_approve_ignores_requested_extensions`: a CSR requesting BasicConstraints CA=true and a SAN for another user → issued leaf has CA=false and SAN `ping:user:<u>`.
  - `test_approve_refuses_bad_csr_signature`, `..._bad_bind` (bind signed by a different key, and bind over a different KEM key), `..._csr_cn_mismatch` (CSR CN `bobby` in `requests/alice.json`), `..._name_already_issued`, `..._wrong_sub_passphrase` (→ `CAError`, nothing written), `..._missing_request`. Each asserts no `certs/<u>/` and the request file is still there.
  - `test_approve_refuses_kem_key_of_wrong_type` (an ML-KEM-1024 `ek`).
  - `test_approve_is_all_or_nothing`: if writing the second certificate fails (monkeypatch `util.atomic_write` to raise on the KEM cert), `certs/<u>/` does not exist afterwards and approving again succeeds. (Certificates are written into `certs/<u>.tmp/` and the directory is renamed into place.)
  - `test_list_pending_skips_bad_files`: garbage, empty, oversized and non-`.json` entries do not break the listing of the valid request.
  - `test_renew_keeps_keys_and_extends_validity`: approve with `now` 400 days in the past, so the certificates are expired; `renew` → the public keys equal the old ones, `not_valid_after_utc` is later, `verify_chain` passes now.
  - `test_renew_refuses_unknown_user_and_wrong_passphrase`.
  - `test_every_path_argument_is_validated`: `approve(home, "../x", …)` and `renew(home, "Bob", …)` raise `ValueError`.
- [ ] **Step 2: Run.** Expected: FAIL (`ModuleNotFoundError`).
- [ ] **Step 3: Implement `ping/ca.py`:**
  - `init_pki`: refuse if `pki/` exists; generate Root (`pki.create_root`) and Sub-CA (`create_sub`); seal each private key as PKCS#8 under `kek_from_passphrase(pass, kdf_params(salt))`; write the certs as PEM; return the Root fingerprint. The Root key is not kept after signing the Sub-CA certificate.
  - `approve`: validate the name, read the request with `read_limited(…, 65536)`, check in this order (fail on the first): schema and sizes → `certs/<u>` absent → CSR signature (`is_signature_valid`) and ML-DSA-65 key → CN == user → `ek` is an ML-KEM-768 SPKI → `bind` verifies under the CSR key with `pki.bind_message` and context `ping/v1/kem-bind`. Open the Sub-CA key (`InvalidTag` → `CAError("wrong sub-CA passphrase")`). Issue both certificates with `pki.issue_user_cert`, write into `certs/<u>.tmp/`, `os.rename` to `certs/<u>`, delete the request.
  - `renew`: load the existing certificates' public keys, issue fresh certificates for the same keys, replace each file atomically (two files; a crash between them leaves one renewed and one old, both individually valid).
  - `list_pending`: names of valid-looking `requests/*.json` (name check only; full validation happens at `approve`).
- [ ] **Step 4: Run** the file. Expected: PASS. Then **mutation check**: disable, one at a time, the CSR signature check, the bind check, the CN check, the name-already-issued check and the extension override, and confirm each makes at least one test fail.
- [ ] **Step 5: Run the full suite.** Expected: green.

---

### Task 3: `accounts` (sign-up and login)

**Files:**

- Create: `ping/accounts.py`, `tests/test_accounts.py`, `tests/real_env.py`

**Interfaces:**

- Consumes: `auth.*`, `keystore.*` (including `Session`), `pki.*`, `ca.approve`.
- Produces: the `accounts` block above, and `tests/real_env.py`: `RealEnv(tmp_home)` runs `ca.init_pki` and offers `add_user(name)` (signup + approve + login → `Session`), `ROOT_PASS`, `SUB_PASS`, `PASSWORD`.

- [ ] **Step 1: Write failing tests:**
  - `test_signup_writes_files_and_request`: after signup `users/alice/{account.json,sign.key.json,kem.key.json,trust.json}` and `requests/alice.json` exist; the request's CSR CN is `alice`, its public key equals the sign key's, `bind` verifies; `account.json` contains no password and no `k_file`.
  - `test_signup_shows_root_fingerprint_and_abort_writes_nothing`: the callback receives the fingerprint of `pki/root.crt.pem`; if it returns False nothing exists under `users/`, `requests/`, `certs/`.
  - `test_signup_refuses_taken_names_and_bad_input`: name present as a user dir, a request, or an issued `certs/<u>`; bad username; short password; missing `pki/root.crt.pem`. Each raises and writes nothing.
  - `test_signup_failure_midway_releases_the_name`: make the request write fail (monkeypatch `util.create_exclusive`); afterwards `users/<u>` does not exist and signing up again works.
  - `test_login_before_approval_is_pending`: `PendingApproval`.
  - `test_login_returns_working_session`: after approval, `login` returns a `Session` with the right `user`, `pinned_root_fp` == the confirmed fingerprint, `k_file` of 32 bytes, keys that match the certificates.
  - `test_wrong_password_and_unknown_user_are_indistinguishable`: both raise `LoginError` with identical `str()`, and both call `auth.derive` exactly once (wrap `auth.derive` with a counting spy; it is a dependency, not the unit under test).
  - `test_tampered_key_file_is_reported_as_tampered`: flip one byte in `sign.key.json` (and separately in `trust.json`) → `TamperedError`, not `LoginError`.
  - `test_swapped_key_file_between_users_is_refused`: bob's `sign.key.json` copied over alice's → `TamperedError`.
  - `test_login_with_swapped_root_file_is_refused`: `pki/root.crt.pem` replaced by a rogue Root → `CertificateProblem` mentioning the pin.
  - `test_login_with_expired_certificate`: patch `accounts._now` to 400 days ahead → `CertificateProblem` whose message contains `certificate expired: ask the CA to renew`. After `ca.renew` (with `now` also in the future) login works.
  - `test_login_refuses_certificate_for_other_keys`: replace `certs/alice/sign.crt.pem` with a valid certificate for a different key (issued by the real CA) → `CertificateProblem` ("certificate does not match your key").
  - `test_trace_and_logs_never_contain_secrets` (`capsys` + `caplog`): a full signup and login with `util.set_trace(True)`; the password, `k_file.hex()`, and the DER of the private keys appear nowhere.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement `ping/accounts.py`.** Sign-up order: validate → checks above → confirm fingerprint → claim the name with an exclusive `mkdir` of `users/<u>` → derive keys → `generate_user_keys` → write account, keys, trust → build the CSR (CN = user, signed with the sign key) and `bind` → create the request **last**, exclusively. On any exception after the claim, remove the directory this call created and re-raise. Login: derive with the stored salt (unknown user: derive with a fixed dummy salt, then raise the same `LoginError`) → `check_verifier` → `read_trust`, `load_user_keys` (`InvalidTag`/`ValueError` → `TamperedError`) → certificates present (else `PendingApproval`) → `pki.verify_chain` for both purposes with `at = _now()` → certified keys equal your own → return `Session`.
- [ ] **Step 4: Run** the file. Expected: PASS.
- [ ] **Step 5: Run the full suite.** Expected: green.

---

### Task 4: `cli`

**Files:**

- Create: `ping/cli.py`, `ping/__main__.py`, `tests/test_cli.py`

**Interfaces:**

- Consumes: `accounts`, `ca`, `messaging` (`send`, `open_conversation`, `Message` / `Rejected` / `Warning`), `util.set_trace`.
- Produces: `main(argv=None, *, getpass=getpass.getpass, input_fn=input, out=print) -> int` (0 ok, 1 on any handled error; handled errors print one line, never a traceback), and `render(item) -> str`.

Commands: `init-pki`, `ca list`, `ca approve <u>`, `ca renew <u>`, `signup`, `login`; flags `--home` (default `./ping_data`) and `--trace`. After `login` the menu loop accepts `chats`, `open <peer>`, `fingerprints`, `logout`. `open <peer>` prints the history, then each line you type is sent as a message; `/refresh` reprints, `/back` (or EOF) returns. `fingerprints` shows your sign and KEM key fingerprints and the pinned Root fingerprint. `render`: `Message` → `[YYYY-MM-DD HH:MM] <sender>: <text>`, `Rejected` → `⚠ REJECTED (<file>): <reason>`, `Warning` → its text.

- [ ] **Step 1: Write failing tests** (scripted `getpass` / `input_fn`, captured `out`):
  - `test_render_each_item_type` with exact expected strings (fixed `ts`).
  - `test_full_flow_through_main`: `init-pki`, two `signup`s (the fingerprint prompt answered `y`), `ca approve` both, `login` as alice, `open bobby` and send one line, then bob logs in, `open alice` and the output contains alice's text and her name.
  - `test_chats_lists_only_my_conversations`: a conversation between two other users in `mail/` is not listed; junk directory names are ignored.
  - `test_wrong_login_prints_one_generic_line_and_exits_1`; `test_ca_commands_on_missing_pki`; `test_init_pki_twice_exits_1`.
  - `test_trace_flag_prints_crypto_lines_without_secrets`.
  - `test_unknown_command_and_missing_peer_do_not_traceback`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.** Passphrases and passwords only through the injected `getpass` (never echoed, never in argv). Sign-up asks the password twice. Wire `--trace` to `util.set_trace`.
- [ ] **Step 4: Run** the file, then smoke-test by hand in a scratch directory: `uv run python -m ping --home ./demo init-pki`. Expected: prompts, prints the Root fingerprint.
- [ ] **Step 5: Run the full suite.** Expected: green.

---

### Task 5: `scripts/tamper_demo.py`

**Files:**

- Create: `scripts/tamper_demo.py`, `tests/test_tamper_demo.py`

**Interfaces:**

- Consumes: `RealEnv`, `ca`, `accounts`, `messaging`, and `tests.messaging_helpers.forge` (for the forged-sender attack; the demo imports it from the test helpers on purpose).
- Produces: `run(home=None) -> list[tuple[str, bool, str]]` (name, rejected, reason) and a `main()` that prints `ATTACK <name> → REJECTED: <reason>` per attack and exits 1 if any attack was **not** rejected (`ATTACK <name> → ACCEPTED`).

Attacks (each in a fresh conversation over the real flows): flip a header byte in an envelope; forge a sender (mallory, a real user, claims to be alice); copy an envelope into another conversation; replace Bob's KEM certificate with one from a rogue CA (Alice's send is refused); swap the Root file for a rogue Root; read after all certificates expired (`messaging._now` patched); present Alice's KEM certificate as her signing certificate; wrong password login; flip a byte in a sealed key file; copy Bob's key file over Alice's.

- [ ] **Step 1: Write failing tests:** `test_every_attack_is_rejected` (each tuple has `rejected is True` and a non-empty reason; names are unique and there are exactly ten); `test_main_output_format` (every line matches `^ATTACK .+ → REJECTED: .+$`, exit code 0); `test_demo_reports_failure_when_an_attack_is_accepted` (disable `messaging`'s signature check with `monkeypatch`, and the forged-sender or flipped-byte attack must show `ACCEPTED`, with exit code 1). The last test proves the demo can fail.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.** Use fast Scrypt when `run` is called from tests (`auth.SCRYPT["n"]` is already patched by the autouse fixture); the CLI entry point leaves the real parameters.
- [ ] **Step 4: Run** the file and `uv run python scripts/tamper_demo.py`. Expected: PASS and ten `REJECTED` lines.
- [ ] **Step 5: Run the full suite.** Expected: green.

---

### Task 6: Integration with Person A and end-to-end

**Files:**

- Create: `tests/test_e2e.py`
- Modify (with A): `tests/conftest.py` so the messaging tests can run against `RealEnv` too

- [ ] **Step 1:** Ask A to switch `messaging` to `verify_chain(home, …)` (A's Task 9). Until then B's `pki` and A's call sites disagree, and `test_cli` / `test_e2e` will fail on the first send: expected, and the signal that the hand-off is not done.
- [ ] **Step 2: Write `test_e2e.py`:** sign-up → approve → login → send → read, through `main()`; then `ca renew` after patched expiry and the old history is readable again; then the secrets check (no password, `k_file` hex or private-key DER in `capsys` / `caplog` output with `--trace`).
- [ ] **Step 3:** Run A's messaging suite against the real PKI (A's Task 8 step 1). Expected: the same tests pass. Any difference between A's stand-in and `pki.verify_chain` is a bug in one of them: report it, don't weaken a test.
- [ ] **Step 4: Run the full suite.** Expected: green.

---

## Report (B's sections)

§3 threat model, §6 PKI (levels, who signs what, `verify_chain` checks, trust pin, renewal and why verification is not "as of `ts`"), the sign-up / login / approve / renew flows with `--trace` snapshots (record them after Task 4), and the negative-test section, taken from `tamper_demo` output and the rejection tests. Add the RFC number for ML-DSA in X.509 (spec §16) and check whether the target machine's OpenSSL can display the certificates.

## Self-review

- **Spec coverage:** §6 → Tasks 1–2; §8 sign-up, `ca approve`, login → Tasks 2–3; §9 CLI → Task 4; demo → Task 5; §13 `test_pki` and `test_e2e` → Tasks 1, 6; the `ca renew` flow added to the spec → Task 2. A's `test_*` suites are written by A (TDD); B reviews them (see spec §12).
- **Type consistency:** `Session`, `ChainError` substrings and the request / account file schemas are defined once above and reused by name.
- **Spec gaps this plan filled (confirm with A):** `verify_chain` takes `home`; request and account file schemas; `bind_message` format; `ChainError` message substrings and check order; atomic approve by directory rename; renew replaces files one by one; a new `accounts` module (the spec lists only `cli`; update §9's module list if you keep it).
- **Risks to check early:** ML-DSA `verify_directly_issued_by` and `is_signature_valid` on 50.0.2 (checked once for CSRs; re-check the certificate chain in Task 1); whether `os.rename` of a directory onto an existing one fails on Windows (it must, for the name-taken check to hold: Task 2 step 1 covers it with the "name already issued" test).
