# Ping: secure messenger, bare-bones plan (UC3M crypto project, PQC-only)

## 1. Scope

UC3M cryptography group project (2 students, 4 points). The brief asks for a "simple Python app" with:

- multiple users, sign-up and login
- authenticated encryption of stored data
- digital signatures and/or asymmetric encryption
- a mini-PKI (Root CA → Sub-CA) that certifies every user public key
- a report and an in-person defense

Points: PKI 1.0, report 1.0, AE 0.6, signatures / asymmetric encryption 0.6, key management 0.5, auth 0.3.

**Thesis.** The security of Ping comes from how the pieces are put together: chain verified on every use, encrypt-then-sign, AAD binding, sealed private keys. The post-quantum algorithms are the instantiation, not the point.

Decisions:

- One Python CLI app; users share one data directory on one machine. No network.
- The `cryptography` library for all crypto. Python 3.14, uv.
- **PQC-only.** All asymmetric crypto is NIST post-quantum (ML-DSA, ML-KEM). No classical asymmetric code.
- The CA is an offline admin command (`ping ca …`). No user process ever holds a CA key.
- Two key pairs per user (signing and KEM), each with its own certificate.
- Nothing will be committed (global rule).

## 2. Algorithms

| Role | Choice | Why (goes in the report) |
| --- | --- | --- |
| Root signature | ML-DSA-87 | FIPS 204, NIST category 5, longest-lived key |
| Sub-CA and user signatures | ML-DSA-65 | category 3 |
| KEM | ML-KEM-768 | FIPS 203, category 3 |
| AEAD | AES-256-GCM | Grover only halves it to about 128-bit |
| Password KDF | Scrypt n=2^17, r=8, p=1 | Memory-hard, about 0.3 s measured |
| Derivation / MAC / hash | HKDF-SHA256, HMAC-SHA256, SHA-256 | Domain-separated outputs |

- **Why PQ in a messenger:**
  - Shor's algorithm breaks RSA and ECC.
  - Harvest-now-decrypt-later makes the KEM the urgent part: recorded ciphertext can be decrypted later.
  - Signatures follow for consistency, and because CA keys live for years.
- **Caveat:** ML-KEM and ML-DSA have had far less cryptanalysis than X25519 and Ed25519. Real deployments use hybrids. Ping is PQ-only by scope; the hybrid is listed as an extension.
- **Domain separation:** every signature uses the ML-DSA `context` parameter (e.g. `ping/v1/envelope`). A signature under one context fails under another.

## 3. Threat model

- **Adversary:** anyone with read/write access to the shared data directory (other users, or malware running as them). They can read, modify, delete, copy or add any file in it.
- **Defended:**
  - They can't read anyone else's messages or private keys.
  - They can't forge a message, substitute someone's public key, or change a message undetected. The reader rejects it and says why.
  - Both participants always see the same message: a sender can't put different text in the two encrypted copies.
- **Not defended (stated in the report):**
  - Deleting messages can't be prevented (a shared directory has no replication). It is detected where possible; see the availability row of the CIA table below.
  - Metadata: folder names and file times show who talks to whom, and when.
  - A stolen Sub-CA key and passphrase can certify fake keys. There is no revocation.
  - Offline password guessing against a stolen key file (Scrypt only slows it down).
  - No forward secrecy: a stolen KEM key plus password decrypts that user's past messages.
  - No proof that a user holds their KEM private key. The binding signature ties the KEM key to the signing-key owner, so a user registering someone else's KEM key gains nothing readable. Challenge-response proof is an extension.
  - Python can't reliably wipe secrets from memory.

### CIA triad mapping

| Pillar | Mechanisms | Stated limit |
| --- | --- | --- |
| Confidentiality | ML-KEM-768 + AES-256-GCM per reader; private keys sealed under a Scrypt-derived key; sealed per-user trust pin | Metadata is visible; no forward secrecy |
| Integrity | ML-DSA signature on every envelope, verified before decryption; AES-GCM tags with the header as AAD; certificate chain verified on every use; signed plaintext commitment, so both readers verify they received the same message; sealed key files with metadata as AAD | A stolen Sub-CA key can certify fake keys |
| Availability | **Detection:** a signed per-sender sequence number exposes missing, duplicated or conflicting messages. **Resilience:** every file is checked independently and fails closed, so one malformed or hostile file can't hide or crash the rest; size limits are checked before parsing; atomic writes and exclusive creates leave no partial or overwritten messages; the CA is offline, so there is no live service to take down | Deletion can't be prevented without replication or backups. Deleting the newest message isn't detectable until the sender's next message arrives; then the sealed counter makes the gap show. Deleting the counter file together with the newest message, or restoring an older counter file, hides it |

## 4. Key table

| Key | Type | Purpose | Stored | Protected by | Life |
| --- | --- | --- | --- | --- | --- |
| Root | ML-DSA-87 | Sign Sub-CA cert | `pki/root.key.json` | AES-GCM under Scrypt(root passphrase) | 10 y, used once |
| Sub-CA | ML-DSA-65 | Sign user certs | `pki/sub.key.json` | Scrypt(sub passphrase) | 5 y |
| User sign | ML-DSA-65 | CSR, KEM binding, envelopes | `users/<u>/sign.key.json` | AES-GCM under `K_file` | cert 1 y |
| User KEM | ML-KEM-768 | Decapsulate | `users/<u>/kem.key.json` | `K_file` | cert 1 y |
| `pw_key`, `K_auth`, `K_file` | 32 B | Login verifier / seal user files | memory only | n/a | per login |
| Per-reader message key | 32 B | One message copy | memory only | HKDF from KEM secret | 1 message |

## 5. Key serialization

| Object | Format |
| --- | --- |
| Private keys | PKCS#8 DER (54 B ML-DSA, 86 B ML-KEM), sealed inside the AES-GCM container |
| Public keys | SubjectPublicKeyInfo, inside X.509 PEM certificates |
| Certificates | X.509 v3 PEM. ML-KEM certificates use `keyEncipherment` only (RFC 9935). About 5.5 KB each |
| CSR | PKCS#10 PEM |
| Envelopes | canonical JSON, base64url |

**Why not `BestAvailableEncryption` PEM:** PBES2 uses AES-CBC, which is not authenticated. The container below is AES-GCM with the metadata as AAD, which gives authenticated encryption plus binding.

**Container** (every private key and every sealed file):

```json
{"v":1,"alg":"AES-256-GCM","kdf":{...}|"user-login","owner":"alice",
 "role":"root|sub|user-sign|user-kem|user-trust|user-seq","pub_fp":"…","nonce":"…","ct":"…"}
```

- `ct = AESGCM(kek).encrypt(nonce, pkcs8_der, aad=canon(all other fields))`.
- Changing the owner, role or KDF parameters, or swapping files, breaks the tag.
- After opening, check that the key's public half matches `pub_fp` and its certificate.

## 6. PKI: who is the CA, how many levels, who signs what

- **The CA is a separate offline admin tool** (`ping ca …`), never part of a user's process. Users never hold CA keys. There are no server or system keys (no network).
- **Two levels: Root → Sub-CA.** Root signs only the Sub-CA certificate, then stays sealed and unused. The brief allows Root alone; two levels demonstrates path validation and path length.

| Signer | Signs |
| --- | --- |
| Root (ML-DSA-87) | Its own self-signed cert; the Sub-CA cert (CA=true, pathlen 0) |
| Sub-CA (ML-DSA-65) | Each user's sign cert (`digitalSignature`) and KEM cert (`keyEncipherment`); CA=false, CN=user, SAN `ping:user:<u>`, 1 year |
| User sign key | CSR, KEM binding, message envelopes |
| User KEM key | Signs nothing (it decapsulates) |

- **The CA builds user certificates itself.** It ignores requested extensions and sets subject, SAN, KeyUsage and BasicConstraints.
- `verify_chain(cert, purpose, expected_user, pinned_root_fp, at)` checks:
  - Root fingerprint == the pinned one
  - each link via `verify_directly_issued_by`
  - validity of all three certificates at `at`
  - BasicConstraints and path length
  - KeyUsage matches the purpose (`sign` or `kem`)
  - CN == the expected username
- It is called **every time a public key is used**, never cached as "trusted".
- **Trust pin:** at sign-up the user confirms the Root fingerprint. It is stored in `trust.json`, sealed under `K_file`. A swapped shared `root.crt.pem` doesn't match the pin and is rejected.

## 7. Storage (`--home`, default `./ping_data`)

```text
pki/        root.key.json  sub.key.json  root.crt.pem  sub.crt.pem
users/<u>/  account.json   sign.key.json kem.key.json  trust.json
users/<u>/seq/<peer>.json       # sealed next-seq counter, one per conversation
requests/<u>.json
certs/<u>/  sign.crt.pem   kem.crt.pem
mail/<a>__<b>/<msg_id>.json     # a < b alphabetically
```

- Usernames match `^[a-z0-9_]{3,32}$` (blocks path traversal). Passwords are at least 12 characters.
- Key files are mode 0600. Requests and messages are created exclusively (`O_EXCL`). Every write goes to a temporary file and is moved into place with `os.replace`, so a crash never leaves a partial file.
- Files are size-limited (envelopes 1 MB, message text 4 KB), checked before parsing.

## 8. Flows

**Auth.**

- `pw_key = Scrypt(password, salt)`.
- HKDF splits it into `K_auth` (info `ping/auth`) and `K_file` (info `ping/keyfile`).
- Verifier = `HMAC(K_auth, "ping/login-v1")`, compared with `hmac.compare_digest`.
- Why split: the public verifier gives nothing that opens key files. It also tells a wrong password (verifier fails) from a tampered file (verifier passes, GCM fails).

**`init-pki` (admin).** Refuses if `pki/` exists. Creates Root and Sub-CA, seals each under its own passphrase (`getpass`, at least 12 characters), prints the Root fingerprint.

**Sign-up.**

1. Username, password twice, confirm the Root fingerprint.
2. Derive keys. Generate an ML-DSA-65 pair and an ML-KEM-768 pair.
3. Write `account.json`, the sealed key files and `trust.json`.
4. Write `requests/<u>.json` with:
   - a CSR signed by the sign key (CN = username)
   - the KEM public key `ek`
   - `bind = Sign(canon{user, H(ek)}, context="ping/v1/kem-bind")`

The user stays pending (can't log in fully or receive messages) until the CA approves.

**`ca approve <u>`** (`ca list` shows pending requests).

1. Verify the CSR signature, CN == requested name, and `bind` under the CSR key. Check the name hasn't been issued already.
2. Issue the sign and KEM certificates, write `certs/<u>/`, delete the request.

**`ca renew <u>`** (certificates last 1 year).

1. Re-issue both certificates for the user's **existing** public keys, with a fresh validity period. Refuse if the user has no certificates yet.
2. Old messages verify again, because the sender's key fingerprint in each header is unchanged. A renewal that certifies a *different* signing key does not vouch for old messages (they show "sender key mismatch").
3. Why not verify old messages "as of their timestamp" instead: `ts` is chosen by the sender, so a stolen expired key could backdate messages.
4. While a certificate is expired and not yet renewed, that sender's messages are rejected with "sender certificate invalid".

**Login.**

1. Recompute `pw_key` and check the verifier. Any failure gives a generic "wrong username or password".
2. Open `trust.json`, then the key files. `InvalidTag` here means a tampered file: abort and say so.
3. Certificates missing → "pending approval".
4. Verify your own chain. The certified public keys must equal your own. An expired certificate gives "certificate expired: ask the CA to renew".
5. Build the session with `K_file` in memory; it seals the per-conversation counters.

**Send A→B** (KEM-DEM, one encrypted copy per reader):

1. Load B's certificates and run `verify_chain` (`kem` purpose, user B, pinned Root). Refuse sending to yourself.
2. `seq` = the sender's next counter in this conversation (0, 1, 2, …): the higher of the sealed counter `users/<me>/seq/<peer>.json` and one more than the highest `seq` among the sender's own verified messages. The counter is written **before** the envelope, so a failed send leaves a visible gap and a number is never reused, even after a deletion or an expired certificate. A tampered counter file makes the send fail. Pick `pt_salt` = 32 random bytes and `pt_commit = SHA256("ping/v1/pt" ‖ pt_salt ‖ plaintext)`. Then `header = {v, msg_id, seq, sender, recipient, ts, sender_sign_fp, sender_kem_fp, recipient_kem_fp, pt_commit}`.
3. For each reader R in {B, A}:
   - `ss_R, ct_R = ek_R.encapsulate()`
   - `key_R = HKDF(ss_R, info = "ping/v1/dem" ‖ ct_R ‖ SHA256(ek_R) ‖ SHA256(canon(header)))`
   - `ctext_R = AESGCM(key_R).encrypt(nonce_R, pt_salt ‖ plaintext, aad = canon({header, r: R}))`
4. `sig = Sign(canon{header, to}, context="ping/v1/envelope")`. Encrypt-then-sign.
5. Write `mail/a__b/<msg_id>.json`.

There is no CEK wrapping layer: the KEM secret keys AES-GCM directly. Wrapping a random CEK is the alternative for many recipients. Because each reader gets a separate ciphertext, the signed `pt_commit` is what forces both copies to hold the same message: each reader recomputes it after decrypting (Read, step 6).

**Read `open <peer>`.** For each file, fail-closed, in this order:

1. Schema check (required fields only).
2. Load the sender's sign certificate, run `verify_chain`, check its fingerprint == `sender_sign_fp`.
3. Verify the signature, **before any decryption**.
4. Addressing: {sender, recipient} == {me, peer}, and my KEM fingerprint is in the header.
5. `decapsulate` my copy, HKDF, AES-GCM decrypt.
6. Split the result into `pt_salt` and `plaintext`, and check `SHA256("ping/v1/pt" ‖ pt_salt ‖ plaintext) == header.pt_commit`. A mismatch is rejected as "copies differ".

Messages are sorted by `ts`, then `seq`, then `msg_id` (so quick messages from one sender stay in order). A duplicate `msg_id` is shown once. A message that fails any step shows as `⚠ REJECTED (<file>): <reason>`, never as plaintext.

After all files are processed, check each sender's `seq` values. A gap shows `⚠ MISSING: n message(s) from <sender> before seq k`. Two different messages with the same `seq` show `⚠ CONFLICT`. Each file is processed independently, so one bad file never blocks the others.

## 9. Modules and CLI

Modules: `util` · `auth` · `keystore` · `pki` · `ca` · `messaging` · `cli`. Scripts: `tamper_demo.py`, `pqc_lab.py`.

- `ping init-pki`
- `ping ca list` / `ping ca approve <u>` / `ping ca renew <u>`
- `ping signup` / `ping login`. The logged-in menu has `chats`, `open <peer>`, `fingerprints`, `logout`.
- Flags: `--home`, `--trace`. `--trace` prints one line per crypto step with algorithm and sizes. These lines are the report's terminal snapshots.

## 10. PQC exploration (`scripts/pqc_lab.py`)

The script prints these demos; the report gets a section from them.

1. **Size and speed table** (measured in a sandbox, so re-measure on the target machine):

| | keygen ms | sign / encaps ms | verify / decaps ms | public key B | sig / ct B |
| --- | --- | --- | --- | --- | --- |
| Ed25519 | 0.03 | 0.03 | 0.09 | 32 | 64 |
| ML-DSA-65 | 0.14 | 0.66 | 0.13 | 1952 | 3309 |
| X25519 | 0.03 | 0.03 | 0.03 | 32 | 32 |
| ML-KEM-768 | 0.07 | 0.02 | 0.03 | 1184 | 1088 |

   Takeaway: verification speed is comparable, signatures and public keys are about 50–60× larger, and ML-KEM is as fast as X25519.
2. **Implicit rejection.** Flip a byte in an ML-KEM ciphertext: `decapsulate` does not raise. It returns a different pseudo-random secret, so the AES-GCM tag then fails (and the envelope signature check fires even earlier). A wrong-length ciphertext does raise `ValueError`.
3. **Randomized signing.** Two ML-DSA signatures of the same message differ.
4. **Context separation.** A signature under one context is rejected under another.
5. **Parameter sets.** ML-DSA-44 / 65 / 87 and ML-KEM-768 / 1024 side by side.

## 11. Rubric traceability

| Criterion | Pts | Evidence | Demo proof |
| --- | --- | --- | --- |
| Auth | 0.3 | Scrypt, salt, HKDF split, constant-time verifier, generic errors | wrong password; tampered key file |
| Key management | 0.5 | §4 table, §5 sealed PKCS#8, separate CA passphrases, Root used once, one key per purpose | swapped key file rejected |
| Authenticated encryption | 0.6 | AES-GCM on messages (header as AAD) and on key files (metadata as AAD) | flipped byte → rejected |
| Signatures / asymmetric encryption | 0.6 | ML-DSA on envelopes, CSR and binding; ML-KEM + AES-GCM hybrid public-key encryption | forged sender rejected |
| Mini-PKI | 1.0 | Root → Sub-CA → two certificates per user, CA-set extensions, chain verified on every use, pinned Root | rogue CA, expired cert, wrong-purpose cert |
| Report | 1.0 | Outline below | `--trace` snapshots |

**Report outline:**

1. App and goals
2. Threat model and CIA mapping
3. Architecture diagram
4. Algorithm table with justifications
5. Key table and serialization
6. PKI
7. Flows with code snippets and `--trace` snapshots
8. Negative tests
9. PQC exploration (§10)
10. Limitations and extensions

## 12. Division of work

| | Person A: crypto core + messaging | Person B: PKI + app |
| --- | --- | --- |
| Code | `util`, `auth`, `keystore` (sealed files, per-conversation `seq` counters), `messaging`, `pqc_lab` | `pki`, `ca` (`init-pki`, `approve`, `renew`), `cli`, `tamper_demo` |
| Report | §2, §4, §5, messaging flows (incl. `seq` counter and availability row), §10 | §3, §6, sign-up / login flows, certificate renewal, negative tests |

**Interfaces to agree on day 1**, so the two halves can be built in parallel:

```python
keystore.seal(payload, kek, *, owner, role, pub_fp, kdf) -> dict
keystore.open(container, kek) -> bytes                      # raises InvalidTag
keystore.Session(home, user, keys, pinned_root_fp, k_file)  # built by login, passed to messaging
keystore.read_seq(home, user, peer, k_file) -> int          # sealed per-conversation counter
keystore.write_seq(home, user, peer, next_seq, k_file)
auth.derive(password, salt) -> (k_auth, k_file)
pki.load_cert(home, user, purpose) -> Certificate           # purpose: "sign" | "kem"
pki.verify_chain(home, cert, purpose, user, pinned_root_fp, at)   # raises ChainError
messaging.send(session, peer, text) -> msg_id
messaging.open_conversation(session, peer) -> list[Message | Rejected | Warning]
```

- `messaging` needs the sender's keys, so it takes a `Session` (not `home, me`). `verify_chain` takes `home` because it must find the Sub-CA and Root certificates in `pki/`.
- Each partner writes the tests for the other's modules. In practice the implementer writes tests first, and the partner reviews them and adds the negative cases. Both are responsible for understanding the whole system.
- **Status (Person A):** `util`, `auth`, `keystore`, `messaging` and `pqc_lab` are built and tested against a test-only stand-in for `pki`. Left for A: switch `messaging` to the `home` form of `verify_chain` and run it against B's real `pki` (see `plan-person-a.md`, Tasks 8–9).

## 13. Tests (`uv run pytest`, fast Scrypt parameters)

- **`test_keystore_auth`:**
  - round trip; wrong password → `InvalidTag`
  - changing any field fails; swapping two users' files fails
  - PKCS#8 round trip
  - verifier ok / fail
- **`test_pki`:**
  - the chain verifies
  - rejected: rogue Root, swapped Root file (pin), expired, KEM cert used as signing cert (and the reverse), CA cert as a leaf, wrong CN
  - the CA ignores requested extensions
  - approval refused for a bad CSR signature, a bad `bind`, or a name already issued
- **`test_messaging`** (each case rejected with its reason):
  - round trip; both participants can read
  - flipped header field, ciphertext or signature
  - envelope copied into another conversation
  - signed by mallory's valid certificate under alice's name
  - KEM certificate from a rogue CA swapped in
  - duplicate `msg_id` shown once
  - different plaintext in the two copies (commitment mismatch → rejected)
  - a message deleted from the middle → gap reported; two messages with one `seq` → conflict reported
  - the newest message deleted, then another sent → the `seq` is not reused and the gap shows; a failed send leaves a gap, not a duplicate
  - sealed counter: tampered, or copied to another peer → refused
  - certificate expired → messages rejected; renewed with the same keys → history readable again; renewed with a new signing key → "sender key mismatch"
  - garbage and oversized files don't block the readable messages
- **`test_pqc`:** tampered KEM ciphertext → different secret, no exception; context separation.
- **`test_e2e`:** sign-up → approve → login → send → read. Logs contain no password or key material.

## 14. Build order

1. `util`, `keystore`, `auth` + tests.
2. `pki`, `ca`, sign-up / approve / login. **Checkpoint: two active users.** Start the report skeleton here, not at the end.
3. `messaging`, the chat menu, `--trace`. **Checkpoint: Alice ↔ Bob conversation.**
4. `tamper_demo.py`, `pqc_lab.py`, negative tests.
5. Fill the traceability table, finish the report, rehearse the demo.

**Demo (about 5 minutes):**

1. `init-pki`, two sign-ups, `ca approve` both, log in.
2. Alice ↔ Bob conversation with `--trace`.
3. `tamper_demo.py`: flip a byte in an envelope, swap Bob's KEM certificate for a rogue one, copy an envelope into another conversation, forge a sender. Each prints `ATTACK → REJECTED: <reason>`.

**If time runs short, cut in this order:** duplicate handling → trace polish → `fingerprints` command → parameter-set comparison in `pqc_lab`. **Never cut:** chain verification on every use, the tamper demo, the key table, the plaintext commitment and the `seq` check (they back the CIA claim).

## 15. Extensions (only after step 4)

1. Hybrid X25519 + ML-KEM combiner
2. KEM challenge-response proof of possession (the CA encapsulates to the user's `ek`; the user must decapsulate)
3. TOFU safety numbers between users
4. Password change
5. Revocation list

## 16. To verify before the report

- The RFC number for ML-DSA in X.509 (ML-KEM in X.509 is RFC 9935).
- Whether the OpenSSL on the target machine (3.5+ added PQC, as far as known) can display these certificates, for an extra snapshot.
