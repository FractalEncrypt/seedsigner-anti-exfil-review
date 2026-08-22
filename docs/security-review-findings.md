# Independent security review — findings log

Reviewer: Cascade (AI-assisted review, directed by repository owner)
Started: 2026-08-16
Scope: per `docs/independent-security-review-brief.md` — protocol-v1 construction,
wire format, state machines, and the four implementations at their immutable
review tags. Review-only: no code modifications.

Finding classes: **protocol defect** / **implementation defect** / **hardening** /
**hygiene** / **accepted residual risk** / **verified** (no issue).

## Reviewed inputs

| Component | Commit | Local path |
| --- | --- | --- |
| Reference oracle | `ed3d323e` (working tree, clean) | `Documents/SeedSigner_AntiExfil` |
| SeedSigner | `aa8395e3576379467d795bb05268533e3a2ac082` | `Windsurf/SeedSigner_AntiExfil_Review_Fresh` |
| Sparrow | `c88c5733afca81869aba8614366458e5fa5adb74` | `Windsurf/Sparrow_AntiExfil_Review_Fresh` |
| Drongo | `1250d5a8323f5525236753a8597729c22ce1e5da` | `Windsurf/Drongo_AntiExfil_Review` |
| SeedSignerOS | `0bf1dc92519906c7db265055abfb07e0ee344342` | `Windsurf/SeedSignerOS_AntiExfil_Review_Fresh_LF2` |
| Pinned native source | secp256k1-zkp `2af926dc…` (extracted tree) | `run/native-source` |
| Pinned native DLL (Windows) | per `docs/native-windows-checkpoint.json` | `run/native-build/bin/libsecp256k1-6.dll` |

All four implementation clones were verified with `git rev-parse HEAD` against
the checkpoint JSONs on 2026-08-16.

---

## Phase 1 — Cryptographic construction (brief §4.1)

Method: line-by-line trace of `src/anti_exfil/crypto.py` and
`src/anti_exfil/native.py` against pinned `run/native-source` files
`include/secp256k1_ecdsa_s2c.h`, `src/modules/ecdsa_s2c/main_impl.h`,
`src/eccommit_impl.h`, and `src/secp256k1.c`
(`nonce_function_rfc6979_impl`, `secp256k1_ecdsa_sign_inner`,
`secp256k1_ecdsa_signature_parse_compact`, `secp256k1_ecdsa_verify`);
independent numeric recomputation of the tagged-hash midstates; reference and
native differential test runs.

### Verified (no issue)

- **P1-V1 — Tagged-hash midstates.** Independently recomputed the SHA256
  compression midstate of `SHA256(tag)||SHA256(tag)` (single 64-byte block, no
  padding) with a from-scratch pure-Python SHA256 compression function. Both
  midstates match `main_impl.h` exactly:
  `s2c/ecdsa/point` → `a9b21c7b…8a5bf91c`; `s2c/ecdsa/data` →
  `feefd675…421fc55f`. `crypto.tagged_hash` implements the same BIP340-style
  construction. (Note: a naive `sha256(th||th)` digest comparison is the wrong
  check — finalization padding changes the result; the midstate must be
  extracted after one compression.)
- **P1-V2 — RFC6979 keydata layout.** `nonce_function_rfc6979_impl`
  (secp256k1.c:519–553) reduces `msg32` mod n via
  `scalar_set_b32`/`scalar_get_b32` (`msgmod32`) and builds
  `keydata = key32 || msgmod32 || data32` with `algo16 = NULL` at both call
  sites. `crypto.nonce_candidates` (crypto.py:159–170) matches exactly,
  including the `bits2octets` reduction. The claim in `protocol-v1.md` §4 is
  accurate.
- **P1-V3 — Counter semantics.** Native discards `counter` DRBG output blocks
  and keeps the next (secp256k1.c:545–547); the reference yields successive
  blocks of the same DRBG stream. Candidate sequences are identical.
- **P1-V4 — Signer opening.** First candidate in `[1, n-1]`, opening is the
  compressed `k0·G`; matches `anti_exfil_signer_commit`
  (main_impl.h:146–176). Both pinned `tests_impl.h` fixtures
  (commitment `1bf6fb42…f722` → opening `02df6375…7188`;
  commitment `35199a8f…e24a` → opening `02c04ac7…e0ea`) are reproduced
  byte-for-byte by `tests/reference/test_crypto.py`.
- **P1-V5 — Sign path.** Native `anti_exfil_sign` → `ecdsa_s2c_sign`
  re-derives `ndata = TaggedHash(data-tag, rho)` as RFC6979 additional data and
  tweaks with `t = TaggedHash(point-tag, ser33(R0)||rho)`
  (`ec_commit_seckey`). `crypto.anti_exfil_sign` matches, including low-S
  normalization (`s > n/2 → n − s`, matching `ecdsa_sig_sign`'s conditional
  negation) and retry on invalid nonce / `r = 0` / `s = 0` (native
  `count++` loop, secp256k1.c:585–632).
- **P1-V6 — Host verification is dual and mandatory.**
  `secp256k1_anti_exfil_host_verify` = `s2c_verify_commit &&
  ecdsa_verify` (main_impl.h:182–185). The commit check compares `sig.r`
  against `x(R0 + tG)` reduced mod n without overflow rejection
  (main_impl.h:109–127). `crypto.verify_anti_exfil` (crypto.py:250–270)
  matches, including infinity rejection of `R0 + tG`.
- **P1-V7 — Compact signature parse.** Native `parse_compact` rejects
  `r, s >= n` via the overflow flag (secp256k1.c:442–445);
  `crypto.ecdsa_verify` enforces `1 <= r < n`, `1 <= s < n`. Opening parse is
  strict 33-byte compressed SEC in both (reference additionally rejects
  `x >= p` and non-curve points explicitly; native via `ec_pubkey_parse`).
- **P1-V8 — FFI binding.** `native.py` binds exactly the required symbols with
  correct arity; opaque buffers are 64 bytes, matching
  `sizeof(secp256k1_ecdsa_s2c_opening)` = `sizeof(secp256k1_pubkey)` =
  `sizeof(secp256k1_ecdsa_signature)` = 64; all return codes checked; context
  created once, randomized with `os.urandom(32)`, destroyed in `close()`.
  `_require_length` guards every input length before the FFI call.
- **P1-V9 — Differential run.** `python -m unittest
  tests.reference.test_crypto tests.reference.test_native -v`: 11/11 pass,
  including byte-identical native-vs-reference commitment/opening/signature and
  rejection of changed reveal / changed signature.
- **P1-V10 — Native provenance.** Windows DLL checkpoint
  (`docs/native-windows-checkpoint.json`) records source commit `2af926d…`,
  MSVC Release build, focused S2C suite 14/14, vector-reproducible but not
  byte-reproducible PE output, artifact local-only. The device library is built
  by the SeedSignerOS Buildroot package with source-archive SHA-256 gate
  `40e0858f…` (recorded passed in the OS checkpoint).

### Findings

- **P1-F1 (hardening, negligible probability) — Retry-vs-fail divergence on
  `k0 + t ≡ 0 (mod n)`.** In native `sign_inner`, failure of
  `ec_commit_seckey` (tweak `>= n` **or** `k0 + t == 0`, i.e. `R0 + tG` = ∞)
  sets `ret = 0` and **breaks** — the signing operation fails
  (secp256k1.c:617–621). In `crypto.anti_exfil_sign`, tweak `>= n` raises
  (matches), but `nonce == 0` **continues to the next nonce candidate**
  (crypto.py:208–210; the `final_point is None` check at 212–213 is
  unreachable afterwards since `(k0+t)G = ∞ ⟺ k0+t ≡ 0`). So in this corner
  the reference oracle produces a signature where the native library fails.
  Probability per candidate ≈ 2^-256 (both `k0` and `t` are effectively
  uniform; the ≈ 2^-128 figure applies to the tweak-overflow case `t >= n`,
  which the reference already rejects with a raise — corrected after
  independent re-review). Not reachable by fuzzing. Impact is limited to
  differential-oracle fidelity. Recommendation: make the reference
  model fail (raise) on `nonce == 0` for exact parity, or document the
  divergence as intentional in `crypto.py`'s docstring.
- **P1-F2 (hardening) — Reference verifier accepts high-S; native rejects.**
  `secp256k1_ecdsa_verify` at the pinned commit requires
  `!secp256k1_scalar_is_high(&s)` (secp256k1.c:509), so native
  `host_verify` rejects high-S signatures. `crypto.ecdsa_verify` accepts any
  `s < n`. The wire format mandates compact low-S upstream, so in-protocol
  impact is nil, but an implementation tested only against the Python oracle
  could ship a missing low-S check undetected. Recommendation: enforce
  `s <= n/2` in the oracle's `verify_anti_exfil` boundary, preserving the
  generic `ecdsa_verify` primitive's conventional semantics.
- **P1-F3 (hygiene) — Deprecated context flags.** `native.py`
  `CONTEXT_SIGN_VERIFY = 0x301` uses the deprecated SIGN|VERIFY flag bits; at
  the pinned commit these are treated as `SECP256K1_CONTEXT_NONE` with full
  functionality (secp256k1.h:217–219, 279–285). No functional impact; flag
  for upstreaming cleanup (pass `0x001` / NONE).
- **P1-F4 (verified with caveat) — Pinned-source tree provenance.**
  `run/native-source` is an extracted archive, not a git checkout
  (`git rev-parse` resolves to the enclosing reference repo). Authenticity
  rests on: matching midstates (P1-V1), matching pinned test fixtures (P1-V4),
  the Buildroot archive SHA-256 gate (P1-V10), and the recorded DLL checkpoint.
  Adequate for this review; a byte-hash of the extracted tree against the
  pinned GitHub archive would close the loop for future reviewers.

### Deferred within Phase 1 scope

- Compact→DER conversion with `0x01` sighash suffix occurs at coordinator
  import (Sparrow/Drongo) — covered in Phase 6.
- Independent regeneration of the full canonical vector files — Phase 8.

**Phase 1 status: complete. No protocol or implementation defects found in the
cryptographic construction; two low-severity hardening items (P1-F1, P1-F2)
and one hygiene item (P1-F3).**

---

## Phase 2 — Nonce and secret lifetime (brief §4.2)

Method: trace of base-nonce derivation inputs and every path secret material
can take through the reference coordinator (`coordinator_v1.py`,
`storage.py`), the SeedSigner native binding
(`helpers/anti_exfil.py`), the signer controller
(`helpers/anti_exfil_signer_v1.py`), flow state
(`models/anti_exfil_state.py`), settings persistence, and the pinned native
sources' clearing behavior.

### Verified (no issue)

- **P2-V1 — Base-nonce uniqueness.** `k0 = RFC6979(x32, msgmod32, C)` binds
  key, message, and host commitment. Distinct slots have distinct `(x, m32)`
  pairs: BIP143 `m32` binds the input's own outpoint (differs per input
  index), and same-input multisig slots share `m32` but differ in `x`. Each
  slot draws an independent `os.urandom(32)` rho (coordinator_v1.py:47–48),
  giving a distinct `C`. Retry after interruption re-derives the identical
  `k0` statelessly from the same `(x, m32, C)` — matches the pinned header
  rationale (secp256k1_ecdsa_s2c.h:143–155) and INV-11.
- **P2-V2 — Host-induced reuse (AE-05) is impossible without signer state.**
  On reveal, the signer recomputes `host_commit(rho)` and rejects mismatch
  (anti_exfil_signer_v1.py:137), recomputes the opening from the committed
  `C` and rejects change (:138–139), then signs. A reveal inconsistent with
  the commitment yields a different `k0'` whose recomputed opening cannot
  equal the accepted one. One base nonce can therefore never serve two
  accepted reveals.
- **P2-V3 — SeedSigner binding zeroizes its buffer copies.** `_input_buffer`
  copies caller bytes into ctypes arrays; `_clear` memsets the secret-key,
  opening, and signature opaque buffers in `finally` blocks
  (anti_exfil.py:42–43, 188–190, 217–219); the context-randomization seed is
  likewise cleared (:75–85).
- **P2-V4 — Native library clearing.** Pinned `sign_inner` memclears
  `nonce32` and scalar-clears `msg`, `non`, `sec` (secp256k1.c:637–640);
  `signer_commit` memclears `nonce32` (main_impl.h:174). Secret nonce
  material does not survive the native call inside the library.
- **P2-V5 — No secret leakage via errors, logs, or receipts.** Protocol error
  messages carry input indices and script classifications only; the
  coordinator receipt contains pubkeys, message hashes, and signatures
  (coordinator_v1.py:181–201); message 4 carries opening + signature, never
  rho (wire-format §7.4); messages 2/4 carry no PSBT.
- **P2-V6 — No native bypass or ordinary-signing fallback.** The SeedSigner
  binding has no Python/ordinary-ECDSA path by design (anti_exfil.py:1–5);
  missing library or symbols raise `AntiExfilUnavailableError` before any
  signing; `process()` calls only `signer_commit`/`sign`;
  `validate_request` runs with `backend=None` and performs no cryptography.
- **P2-V7 — Atomicity before and during signing.** The complete request is
  semantically validated (network, PSBT digest, full slot set, per-slot
  sighash context) before any backend call (anti_exfil_signer_v1.py:114–125);
  a mid-loop failure discards the partial output list and constructs no
  response message; `create_response` forces response transport invariants
  via `encode()` before the state transition (anti_exfil_state.py:110–120).
  INV-03/INV-07 hold structurally.
- **P2-V8 — Signer persistence boundary.** `AntiExfilFlowState` is in-memory
  only and holds public request/response data; settings persist solely the
  `Disabled`/`Required` policy enum (settings_definition.py:695–706), so
  INV-12 holds; controller reset drops `anti_exfil_state`
  (controller.py:192, 309).
- **P2-V9 — Coordinator persist-before-reveal and exact retry (reference).**
  State including `message_3` is saved before the reveal package is written
  (coordinator_v1.py:136–140); a retry with different bytes raises
  `RETRY_CONFLICT` (:134–135); changed openings on retry are rejected
  (:107–108); a completed session receiving different signatures is rejected
  (:156–157). Writes are atomic (temp file + fsync + `os.replace`,
  storage.py:66–80) and `write_exact` refuses to replace differing content.
- **P2-V10 — Defense-in-depth on rho reuse.** Even a pathological duplicate
  rho across slots could not reuse a base nonce, because distinct slots have
  distinct `(x, m32)` pairs feeding RFC6979. The wire-format §6 duplicate
  commitment/reveal rejection is still required and is verified in Phase 3.

### Findings

- **P2-F1 (accepted residual risk — disclose) — Python-side secret retention.**
  Per-slot secret keys live on as CPython `bytes` inside the frozen
  `SigningContext` dataclass (`secret_key` field) retained by
  `ControllerResult` and `AntiExfilFlowState` for the ceremony's duration;
  they are not zeroizable and are reclaimed only by GC. The same applies to
  `seed.seed_bytes` and the intermediate embit `HDKey` chain (stock
  SeedSigner behavior). Native-side copies are zeroized (P2-V3/V4), so the
  residual window is the Python heap (and any core dump/swap of the
  process). This is consistent with threat-model §6.4 (side channels out of
  scope) but should be named explicitly in residual-risk disclosure: an
  attacker with memory access to the signer process during a ceremony can
  recover per-input private keys, as with stock SeedSigner signing.
- **P2-F2 (hygiene) — Reference binding does not zeroize.** Reference
  `native.py` declares secret-bearing parameters as `c_char_p`; ctypes then
  passes a pointer into the immutable Python `bytes` buffer (no copy) and no
  clearing is attempted anywhere. The reference coordinator is documented
  test-only tooling, but it has been used as the physical-test coordinator
  with funded testnet keys. Recommendation: adopt the SeedSigner binding's
  copy-and-memset pattern in the reference binding, or document the gap.
- **P2-F3 (accepted residual risk — maintainer decision #5) — Plaintext rho
  at rest (reference coordinator).** Exact retry requires persisting rho
  before message 3; the reference stores hex rhos in plaintext
  `state.json`. An attacker reading coordinator storage before reveal breaks
  host-randomness secrecy for that session (post-reveal reads are harmless:
  rho is public by then). This is the reference implementation; the
  production Sparrow/Drongo persistence, threat surface, and
  encryption-at-rest recommendation are assessed in Phase 5.
- **P2-F4 (hygiene) — No `__del__` context fallback.** Neither binding
  destroys the native context if `close()` is skipped. SeedSigner's flow
  uses `try/finally` (anti_exfil_state.py:100–108) so this is defense in
  depth only; process exit reclaims the memory in practice.
- **P2-F5 (info, upstream behavior) — Uncleared scalar in `signer_commit`.**
  The pinned `signer_commit` memclears `nonce32` but not the stack scalar
  `k` (main_impl.h:146–176). Pinned-upstream behavior, not fork-introduced;
  noted for the upstreaming discussion.

**Phase 2 status: complete. No nonce-reuse, secret-exfiltration, fallback, or
persistence violations found. One residual-risk disclosure (P2-F1), one
open-decision item carried to Phase 5 (P2-F3), and three hygiene items.**

---

## Phase 3 — Transcript and semantic binding (brief §5)

Method: line-by-line comparison of the reference codec/transport/semantic
layers (`protocol_v1_codec.py`, `protocol_v1_transport.py`, `psbt_v1.py`)
against the SeedSigner implementations (`helpers/anti_exfil_protocol_v1.py`,
`helpers/anti_exfil_transport.py`, `helpers/anti_exfil_signer_v1.py`) and the
normative wire format; mapping of the reference test corpus
(`test_protocol_v1_codec.py`, `test_psbt_v1.py`) against wire-format §10.

### Verified (no issue)

- **P3-V1 — AEXB codec is exact in both Python implementations.** 78-byte
  header (`>4sBBBBI32s32sH`), 105-byte common record (`>II33s32s32s`), stage
  record lengths 105/138/170/202, limits (128 slots, 16 per input, 65,536
  bytes), strict ascending `(input_index, pubkey-bytes)` ordering (Python
  tuple order = unsigned lexicographic for the 33-byte key), duplicate
  identifier/conflict/reorder rejection, exact payload-length and total-length
  equality, unknown magic/version/network/stage/flags rejection, explicit
  `SIGHASH_ALL = 0x00000001` only, stage-field presence exactness, and
  codec-level scalar bounds `1 <= r < n`, `1 <= s <= n/2` (this codec check
  closes the in-protocol exposure noted in P1-F2).
- **P3-V2 — Duplicate commitment/reveal rejection.** Both `_validate_message`
  implementations reject duplicate commitments and duplicate reveals across
  the slot set (wire-format §6), with tests
  (`test_commitments_and_reveals_must_be_unique_per_slot`). Closes the item
  deferred from P2-V10.
- **P3-V3 — AEXT envelope invariants on both sides.** Stage↔PSBT presence
  exactness (1/3 require, 2/4 forbid), outer/inner network and stage equality,
  AEXT digest = SHA-256(carried bytes) = AEXB `psbt_digest` for stages 1/3,
  all-zero digest for 2/4, flag/length consistency, 2,000,000-byte PSBT cap,
  `psbt\xff` magic gate, and structural rejection of any PSBT-bearing response
  (`encode()` raises; also pinned by test at test_psbt_v1.py:129–130). The
  reference decoder additionally requires canonical re-encode equality; the
  SeedSigner decoder's field-exact validation implies the same acceptance
  set.
- **P3-V4 — Fail-closed semantic matrix in both semantic layers.** Any
  Taproot script or any Taproot PSBT metadata fails the whole ceremony
  (INV-10); legacy/nonstandard/unsupported scripts fail; missing, mismatched,
  or disagreeing witness/non-witness UTXO data fails; any sighash other than
  `ALL` (including `ALL|ANYONECANPAY`) fails; derivation entries must be
  unique, script-resident, and 4-byte-fingerprinted; the declared path must
  re-derive the exact pubkey; a pre-existing partial signature for a
  controlled/requested key fails; finalized inputs are skipped only after the
  input passes full script/sighash/Taproot validation, so mixed
  supported/unsupported sets still fail; empty, over-limit, and duplicate
  slot sets fail; the signer additionally rejects negative-fee transactions.
- **P3-V5 — Slot-set equality by independent re-derivation.** The signer
  compares its own enumeration against every declared record
  (`validate_request`, anti_exfil_signer_v1.py:122–124); the coordinator-side
  public path re-derives without private material and requires exact set
  equality (`validate_protocol_slots`, psbt_v1.py:127–128). A coordinator
  requesting a key the seed does not control produces a mismatch failure.
- **P3-V6 — Reconstruction boundary (INV-08/INV-14).**
  `reconstruct_signed_psbt_v1` re-verifies every signature (dual check), then
  imports only `partial_sigs[pubkey] = DER(sig) || 0x01` into a fresh parse
  of the frozen original; host-owned unknown maps survive untouched and no
  signer-controlled map is merged (test_psbt_v1.py:116–136). Partial
  response sets and changed contexts fail atomically.
- **P3-V7 — Test corpus maps to wire-format §10.** Covered: all four stages
  with multi-input and multi-key-per-input; ordering/duplicate/conflict
  classes; global and per-input limits; header unknowns, truncation, trailing
  bytes, length disagreement; sighash 0 and 0x81; stage-field presence;
  adjacent-transition context binding incl. opening and commitment changes;
  reveal↔commitment mismatch; testnet3/testnet4 wire distinction and
  outer/inner network mismatch; digest substitution; PSBT-injection in a
  response; semantic mutations (UTXO, scripts, sighash, derivations,
  pre-existing sigs); Taproot/legacy whole-ceremony failure; canonical golden
  binary + UR fountain decode through SeedSigner's vendored UR2; semantic
  golden vector pinning real BIP143 hashes for 5 slots across all four
  supported script kinds. Retry/abort/idempotency items are exercised at the
  coordinator layer (Phase 5 reads `test_coordinator_v1.py`).
- **P3-V8 — Network family rule matches spec §2.** SeedSigner's single
  public-test selection accepts codes 1/3/4 and echoes the exact
  coordinator-supplied code in responses (response built from
  `request.network`); mainnet/regtest require exact match; a mismatched
  active network fails at transport decode with `expected_network`.

### Findings

- **P3-F1 (hardening / test gap) — No pinned cross-implementation vector for
  `x >= p` point rejection.** The reference `parse_point` explicitly rejects
  `x >= FIELD_P` (crypto.py:118–119); SeedSigner delegates opening/pubkey
  validation to embit `ec.PublicKey.parse` (anti_exfil_protocol_v1.py:177–180)
  and the native verifier to `ec_pubkey_parse`. If embit's parser ever
  accepted an out-of-field x (e.g. by implicit reduction), the three
  implementations would diverge on a 33-byte "compressed point" with
  `x in [p, 2^256)`. Recommendation: add a differential negative vector
  (prefix 02/03, x = p and x = 2^256−1) to the shared corpus consumed by all
  implementations. Carried to Phase 4.
- **P3-F2 (hygiene) — `TESTNET = 1` enum alias.** SeedSigner's transport
  defines `TransportNetwork.TESTNET` as an alias of `TESTNET3`
  (anti_exfil_transport.py:28). The wire value is unambiguous and the spec's
  prohibition targets wire-level naming, so this is cosmetic; flag for
  upstreaming cleanup to avoid future misuse.
- **P3-F3 (info) — Reveal↔commitment check placement differs.** The
  reference checks `host_commit(rho) == commitment` inside codec-level
  `validate_transition`; SeedSigner checks it in the signer controller before
  signing (anti_exfil_signer_v1.py:137). Equivalent coverage on both paths;
  noted so future refactors do not drop one assuming the other exists.
- **P3-F4 (info) — Error granularity differs cosmetically.** Reference
  distinguishes bad magic/version/flags; SeedSigner collapses them into one
  header error. No acceptance-behavior difference.

**Phase 3 status: complete. Transcript binding, slot semantics, AEXT
invariants, and the fail-closed matrix substantiate the spec in both Python
implementations. One hardening/test-gap item (P3-F1) carried to Phase 4;
no protocol or implementation defects found.**

---

## Phase 4 — Cross-implementation parser differential (brief §6)

Method: line-by-line comparison of Drongo's Java codec/crypto/PSBT semantics
(`AntiExfilCodec.java`, `AntiExfilCrypto.java`, `AntiExfilPsbt.java`,
`AntiExfilSlot.java`, `AntiExfilSigningSlot.java`, `PSBTInput.java`) and
Sparrow's transport (`io/AntiExfilTransportPackage.java`,
`io/AntiExfilQrCodec.java`) against the Python implementations; empirical
differential tests of point parsing in embit (reference venv) and
BouncyCastle 1.82 (standalone Java 25 harness against the exact dependency
jar); mapping of Java test coverage (`AntiExfilCodecTest`,
`AntiExfilPsbtTest`).

### Verified (no issue)

- **P4-V1 — Out-of-field point rejection is uniform (P3-F1 resolved).**
  Empirical results for compressed SEC inputs with `x >= p`:
  - reference `parse_point`: rejects `x = p`, `x = 2^256−1`, and `x = x0 + p`
    (x0 = 1, a valid point x-coordinate) via the explicit range check;
  - embit `PublicKey.parse` (libsecp256k1 bindings): rejects all three
    (`ECError: Failed parsing public key`), including `x0 + p` — no silent
    reduction;
  - BouncyCastle 1.82 `decodePoint` (Drongo's exact dependency, tested via
    standalone harness): rejects all three with
    `IllegalArgumentException: x value invalid for SecP256K1FieldElement`,
    which `requirePoint` converts to `INVALID_MESSAGE`;
  - native `ec_pubkey_parse`: rejects by construction (and pinned fixtures).
  All four parsers therefore share the same acceptance set for points.
- **P4-V2 — Drongo codec parity.** Header/record layout, limits (128/16/
  65,536), unsigned integer handling (`toUnsignedLong`/`toUnsignedInt` on all
  32/16-bit fields), strict ordering via `Long.compare` +
  `Arrays.compareUnsigned`, per-input limits, duplicate commitment/reveal
  rejection, stage-field presence exactness, scalar bounds `1 <= r < n`,
  `1 <= s <= n/2` (explicit `HALF_CURVE_ORDER` check — the Java verifier
  rejects high-S, matching native; only the Python oracle is lax, P1-F2),
  and `validateTransition` including the reveal↔commitment check at codec
  level (matching the reference placement, P3-F3). Defensive array copying in
  `AntiExfilSlot`/`AntiExfilSigningSlot` prevents caller mutation.
- **P4-V3 — Semantic equivalence is pinned byte-for-byte.** Drongo's
  `AntiExfilPsbtTest` consumes the same
  `protocol-v1-semantic-psbt-vector.json`: identical 5-slot enumeration,
  script kinds, pubkeys, and BIP143 message hashes across embit (Python) and
  drongo (Java); `message_1_hex` re-encoded byte-identically; reconstruction
  produces the pinned `signed_psbt_sha256`.
- **P4-V4 — Script-hash consistency is enforced at PSBT parse time in
  Drongo.** `PSBTInput` rejects redeem-script hash160 mismatch
  (PSBTInput.java:415–420), witness-script sha256 mismatch (:423–434), and
  witness/non-witness UTXO disagreement (:397–400) with
  `PSBTParseException`, which `parseCanonicalV0` wraps as `INVALID_MESSAGE`.
  The consistency checks the Python layers perform in `_classify`/
  `_resolve_utxo` therefore have exact Java counterparts, one layer down.
- **P4-V5 — Sparrow AEXT/UR strictness.** `AntiExfilTransportPackage.decode`
  mirrors the Python envelope rules including canonical re-encode equality
  (line 93) and wraps stray `RuntimeException`s as `INVALID_MESSAGE`;
  `require()` binds expected stage and network at scan time;
  `AntiExfilQrCodec.fromUr` requires the exact `x-btc-anti-exfil` type and
  rejects non-canonical CBOR by re-encode comparison. SeedSigner's
  `_decode_cbor_bytes` independently enforces definite-length shortest-form
  CBOR, rejecting indefinite lengths, 8-byte lengths, non-minimal encodings,
  and trailing data — consistent acceptance sets.
- **P4-V6 — Golden vector cross-implementation runs.** The four canonical
  AEXB messages decode/re-encode byte-identically in Java
  (`AntiExfilCodecTest`), validate through all transitions, and every
  signature passes Java S2C+ECDSA verification; the same vectors pass in
  Python including UR fountain decode through SeedSigner's vendored UR2.

### Acceptance matrix (key differential cases)

| Input case | Reference py | SeedSigner py | Drongo java | Sparrow transport |
| --- | --- | --- | --- | --- |
| Header unknowns / truncation / trailing / length mismatch | reject | reject | reject | reject |
| Point with `x >= p` (P3-F1) | reject | reject (embit) | reject (BC) | n/a (delegates) |
| High-S signature scalar | codec reject; oracle verify accepts (P1-F2) | codec reject | codec + verify reject | codec reject |
| Duplicate commitment or reveal | reject | reject | reject | reject |
| Taproot script or parsed taproot metadata (0x13/0x16/0x17) | reject | reject | reject | reject |
| Unparsed taproot keys (0x14/0x15/0x18) on ECDSA input | reject (embit parses → metadata check) | reject (same) | reject (dropped → canonicality fails) | reject (delegates) |
| Benign unknown input field (future BIP extension) | accept (preserved) | accept (preserved) | **reject** (dropped → canonicality fails) | reject (delegates) |
| Non-canonical CBOR / wrong UR type | n/a (oracle) | reject (shortest-form) | n/a | reject (re-encode compare) |
| Response package carrying PSBT | reject | reject | reject (encode stage rule) | reject |

### Findings

- **P4-F1 (hardening / spec gap) — Unknown PSBT input fields diverge by
  design.** Python/embit preserves unknown input maps and proceeds (pinned by
  the reconstruction test, which keeps a host-owned unknown entry); Drongo
  only `log.warn`s unrecognized key types (PSBTInput.java:375–377), drops
  them, and therefore rejects the PSBT as non-canonical. The divergence is
  fail-closed on the production coordinator side, so the practical effect is
  availability-only (a counterparty PSBT carrying unknown extension fields
  cannot enter the ceremony via Sparrow even though the Python reference
  accepts it). Recommendation: state explicitly in the wire-format spec
  whether PSBTs with unknown input fields are in scope for v1; if they are,
  Drongo must preserve them; if not, the reference should reject them for
  symmetry.
- **P4-F2 (hardening / test gap) — Java negative codec coverage is thinner
  than Python's.** `AntiExfilCodecTest` pins golden bytes, flags, ordering,
  and session substitution, but does not port the Python corpus's
  over-limit counts, duplicate commitment/reveal, per-stage field presence,
  scalar bounds, or truncation/trailing cases. The Java `validate()` logic
  was reviewed line-by-line and matches, so this is a regression-net gap
  rather than a known defect. Recommendation: port the §10 mutation list into
  `AntiExfilCodecTest` (mechanical, high value for upstreaming).
- **P4-F3 (info) — UR fountain differential not exhaustively fuzzed.**
  SeedSigner decodes with its vendored UR2; Sparrow with its own UR library
  (lark). Cross-decoding is pinned by the golden UR parts and Sparrow's
  `QRScanDialogUrDecoderTest`, and stale/mixed-fragment behavior by the
  AE-14 physical gates, but no shared mutation corpus exists at the fountain
  layer. Acceptable for v1 given the digest-and-canonicality gates behind
  it; note for future work.

**Phase 4 status: complete. No exploitable parser differential found. The one
genuine acceptance divergence (P4-F1, unknown PSBT input fields) fails closed
on the production coordinator. Two hardening items (P4-F1 spec clarification,
P4-F2 Java negative-corpus port).**

---

## Phase 5 — Durable coordinator and selective abort (brief §7)

Method: review of Drongo's `AntiExfilCoordinator`, `AntiExfilDurableFiles`,
and `AntiExfilAbortJournal`; Sparrow's session wiring
(`HeadersController` anti-exfil action, `AntiExfilSigningFlow`); reference
coordinator tests (`test_coordinator_v1.py`) and Drongo's
`AntiExfilCoordinatorTest`. Resolves the P2-F3 encryption-at-rest question
for the production path.

### Verified (no issue)

- **P5-V1 — CSPRNG use.** Drongo draws `sessionId` and every per-slot rho
  from `new SecureRandom()` with a duplicate-redraw loop (capped, fail on
  repeat); the reference uses `os.urandom(32)` per slot. No test-only RNG in
  production paths (the injectable `SecureRandom` is package-private and used
  only by tests).
- **P5-V2 — Persist-before-reveal is the security boundary.** Drongo's
  `acceptOpenings` performs the durable state write (including `message3`)
  **before** returning the reveal bytes (AntiExfilCoordinator.java:140–144,
  comment: "no rho is returned before it succeeds"). The reference saves
  state before writing the reveal package. INV-01/INV-04 hold.
- **P5-V3 — Byte-identical retry, including across restarts.** Retry with
  identical message 2 returns the stored message 3; after process restart,
  `load` + `hostRevealMessage` returns the exact persisted bytes (tested:
  `persistsFrozenSessionBeforeReturningExactReveal`); resume in Sparrow's
  flow uses `hostRevealMessage()` from disk, never a regenerated message.
- **P5-V4 — Masquerade resistance.** Changed openings after acceptance →
  `RETRY_CONFLICT` (tested in both Java and Python); different PSBT →
  different session identity (session file is keyed by SHA-256 of the exact
  PSBT bytes in Sparrow, and `_require_state_context`/`validateState` bind
  digest/network/session); subset or reordered slots fail at
  `validateTransition`; fresh-randomness retry is impossible because rhos
  come only from durable state.
- **P5-V5 — Power-loss and tamper behavior fail closed.** Writes are
  temp-file + `force(true)` + `ATOMIC_MOVE` (create-only for new sessions);
  hosts without atomic move raise instead of falling back; reads verify a
  SHA-256 trailer, and `validateState` additionally re-derives the commit
  message from stored rhos + PSBT and byte-compares, checks phase/field
  consistency, replays all transitions, and re-derives the signed PSBT for
  completed sessions (AntiExfilCoordinator.java:201–231). Corruption and
  wrong-wallet tests pass (`failsClosedOnCorruptStateAndWrongWallet`).
- **P5-V6 — Completion idempotency and no broadcast.** `complete` in
  COMPLETE phase returns the stored result only for byte-identical input,
  else `RETRY_CONFLICT` (tested); `Completion.broadcast` is hard `false` and
  Sparrow asserts it before handing the signed PSBT to the normal review
  flow (HeadersController.java:1129). INV-14 holds.
- **P5-V7 — Selective-abort journal attribution and gating.** Journal is
  keyed by wallet-key identity `SHA256(xpub pubkey || chaincode ||
  derivation path)` — independent of device brand/model, so restoring the
  same keys on replacement hardware keeps the history; identity mismatch on
  load fails closed. A fresh session with non-empty post-reveal history
  requires an explicit acknowledgement (create → `RETRY_CONFLICT` → Sparrow
  high-severity warning dialog → opt-in retry), and the count remains
  recorded (tested:
  `recordsPostRevealAbortsAgainstWalletIdentityAndRequiresAcknowledgement`).
  Aborts are recordable only in the OPENINGS_ACCEPTED phase.
- **P5-V8 — Concurrency.** All state and journal operations run under a
  `.lock` file lock, so two Sparrow processes serialize; session creation is
  create-only. Locks and per-session files prevent cross-session races.
- **P5-V9 — Path safety.** Sparrow session/journal paths are built
  exclusively from hex digests (`sha256(walletId)`, wallet-key identity,
  `sha256(PSBT)`) under the state dir — no traversal surface; atomic
  replace targets the path itself (symlink substitution replaces the link,
  and content is validated on read).
- **P5-V10 — Stateless signer demonstrated cross-implementation.** The
  reference cross-implementation test runs each coordinator CLI stage in a
  fresh process and drives SeedSigner's flow with fresh state objects,
  demonstrating stateless message-3 recovery (INV-11) against the real
  Python signer stack.

### Findings

- **P5-F1 (accepted residual risk — recommendation for maintainer decision
  #5) — Unrevealed rho is stored plaintext in production.** Sparrow/Drongo
  session files (`.aexs`) contain per-slot rhos before reveal, protected by
  filesystem permissions (POSIX owner-only where supported; inherited ACLs on
  Windows) plus a checksum — not encryption. A passive reader of the
  coordinator's state directory during an in-flight session could feed rho
  to a malicious signer before it commits, defeating anti-exfil for that
  session (per-session scope only; past sessions' rhos are already public,
  future sessions use fresh randomness). Assessment: acceptable for the
  reviewed prototype under the honest-coordinator assumption, but the threat
  model's "coordinator CSPRNG sound and hidden until acceptance" premise
  materially includes *storage* secrecy. Recommendation: for production,
  either encrypt session state at rest (or store rhos in the OS keychain /
  ephemeral tmpfs where available), or explicitly document that read access
  to the Sparrow state directory during a ceremony is in the trusted base.
  This decision should precede any session-inspection/deletion UX, per the
  brief.
- **P5-F2 (info) — Integrity without authenticity.** State/journal integrity
  rests on the checksum plus full transcript re-derivation, not a MAC. An
  attacker with write access to the session file could fabricate a
  self-consistent *new* session (new rhos/message 1) — but that requires
  write access to the coordinator's filesystem, which already implies
  coordinator-side compromise (outside §3.1). Fail-closed behavior on any
  accidental corruption is verified (P5-V5).
- **P5-F3 (info) — Journal locality.** The abort journal lives in the
  Sparrow state directory. "History survives device replacement" holds for
  signer-hardware changes and wallet re-imports within the same
  installation; a fresh coordinator installation starts an empty journal.
  Since resetting it requires coordinator-side user action (not a
  signer-side attack), this is a disclosure item, not a defect.
- **P5-F4 (info) — Reference coordinator has no abort journal.** The Python
  reference records phase state but not selective-abort history; that duty
  exists only in the production Drongo/Sparrow path. Acceptable for test
  tooling; noted so the reference is not mistaken as journal-complete.

**Phase 5 status: complete. Persist-before-reveal, exact retry, tamper-evident
durable state, key-bound abort journaling, and concurrency controls all
substantiate the spec and are directly tested. One decision-relevant residual
(P5-F1, encryption at rest) with a concrete recommendation; three info
items.**

---

## Phase 6 — Reconstruction and downgrade boundaries (brief §8)

Method: review of Drongo's `AntiExfilKeystorePolicy`/`Keystore` changes,
Sparrow's `transaction/AntiExfilPolicy.java` and its call sites, policy
persistence (`JsonPersistence`, `DbPersistence`, `FileImport`, `SeedSigner`
import, `KeystoreController`, `SettingsWalletForm`), and tests
(`AntiExfilPolicySelectionTest`, `AntiExfilPolicyPersistenceTest`,
`SeedSignerAntiExfilImportTest`). Reconstruction itself was already
substantiated in Phases 3–4 (both Python layers and Drongo rebuild the
signed PSBT exclusively from the frozen original plus verified slots;
pinned by `signed_psbt_sha256` across implementations).

### Verified (no issue)

- **P6-V1 — Return-boundary enforcement in the signing screen.** Returned
  PSBTs/transactions scanned into the transaction tab are gated by
  `violatesAntiExfilPolicy` (AppController.java:3288–3314): a returned
  signature positively attributed to a REQUIRED keystore is rejected;
  unattributable signed returns fail closed when a required signer was
  expected; exceptions during attribution fail closed with an error dialog.
  The ceremony's own completion posts with `antiExfilVerified=true`, the
  only bypass, and `isBroadcast()` is asserted false (INV-14).
- **P6-V2 — Keystore selection cannot silently fall back.** When any
  supported keystore is REQUIRED, the ceremony offers only REQUIRED
  keystores; mixed-policy wallets offer all supported keystores otherwise
  (tested: `requiredCompatibleSignerCannotSilentlyFallBackToOptionalSigner`).
- **P6-V3 — Mixed-policy multisig semantics pinned (scope corrected after
  independent re-review).** Optional signers may sign normally; unattributable
  returns are rejected
  (`unattributableSignedReturnFailsClosedForExpectedRequiredSigner`). The
  stronger clause originally stated here — "a REQUIRED signer's signature is
  only accepted with ceremony provenance" — holds only at the context-PSBT
  scan-back boundary. Ceremony provenance in the pinned code is a
  transaction-wide boolean (`antiExfilVerified`), not signature-scoped, so
  the clause does not hold when a verified ceremony output carries another
  REQUIRED keystore's pre-existing ordinary signature (P6-F1 item 4).
- **P6-V4 — Policy persistence and migration.** Policy persists in the
  wallet JSON (`antiExfilPolicy` enum) and the encrypted DB (dirty-persistable
  update via `KeystoreAntiExfilPoliciesChangedEvent` → `KeystoreDao.
  updateAntiExfilPolicy`). Legacy `antiExfilRequired: true` migrates to
  REQUIRED; SeedSigner-model keystores default to OPTIONAL, all others to
  UNSUPPORTED (JsonPersistence.java:587–597); SeedSigner import applies
  OPTIONAL by default (io/SeedSigner.java); re-importing a keystore retains
  REQUIRED when the import supports the protocol (KeystoreController.java:
  483–489). Covered by `AntiExfilPolicyPersistenceTest` and
  `SeedSignerAntiExfilImportTest`.
- **P6-V5 — Canonical v0 hand-off.** Sparrow may represent PSBTs internally
  as v2, but `getAntiExfilPsbtBytes` exports canonical v0 and the export is
  byte-identical to the pinned fixture
  (`protectedSigningExportsCanonicalV0FromInternalV2`), so the frozen
  digest/slots the ceremony commits to are stable.
- **P6-V6 — Policy-change UX plumbing.** Settings edits propagate through
  `SettingsWalletForm` comparison and post policy-change events that drive
  DB persistence; no silent downgrade path exists in the settings flow.

### Findings

- **P6-F1 (medium, implementation defect) — REQUIRED policy is enforced only
  on the signing-screen scan path.** Several Sparrow paths accept or apply
  signatures for a REQUIRED keystore without any policy check:
  1. *Top-level ingest with no context PSBT*: File > Open Transaction via
     text paste / QR / file routes through
     `addTransactionTab(name, file, string/bytes, contextPsbt=null)`
     (AppController.java:677–694, 1949–1978), which never calls
     `violatesAntiExfilPolicy` — and even the `ViewPSBTEvent` gate
     short-circuits when `contextPsbt` is null because
     `getExpectedSigners(null)` returns empty. A fully signed transaction
     containing a REQUIRED keystore's signature opens in a tab and can be
     broadcast (`broadcastTransaction` has no policy check).
  2. *USB/card device combine*: `signDeviceKeystores` combines the returned
     signed PSBT after `verifyCombinedSignatures` only
     (HeadersController.java:1316–1326) — no attribution gate.
  3. *Scanned-seed software signing*: `signFromSeed` replaces the keystore
     with one derived from the scanned seed (default policy UNSUPPORTED) and
     calls `signUnencryptedKeystores`, which has no policy check
     (HeadersController.java:1175–1189, 1277+).
  4. *Transaction-wide ceremony bypass (added after independent re-review;
     this widens the finding to the primary path)*: `violatesAntiExfilPolicy`
     short-circuits unconditionally on `antiExfilVerified=true`
     (AppController.java:3289). Drongo rejects a pre-existing partial
     signature only for keys of the **selected ceremony keystore**
     (AntiExfilPsbt.java:78–86 — the fingerprint guard at line 79 skips all
     other keystores) and `reconstructSignedPsbt` (lines 154–177) rebuilds
     from the original PSBT, preserving other keystores' partial signatures.
     So in a multisig wallet where keystores A and B are both REQUIRED and
     the original PSBT already carries B's ordinary signature, a ceremony
     completed for A produces an output that is accepted wholesale — B's
     non-ceremony signature is never inspected, even on the primary
     scan-back path.
  Notably, `AntiExfilPolicy.hasRequiredSignature` — the attribution-based
  check that would cover paths 1–3 without needing a context PSBT —
  exists but has **no call sites** in main code. Impact: the deterrent
  property of REQUIRED ("a non-ceremony signature is useless because the
  coordinator rejects it") does not hold on the secondary paths, and does
  not hold per-signature on the primary path. USB/card combine in
  particular is a normal workflow for USB-class signing devices, not an
  unusual action (wording corrected after re-review). Severity remains
  medium; scope is wider than first assessed. Recommendation: replace the
  transaction-wide `antiExfilVerified` boolean with **signature-scoped
  provenance** — record the exact verified slots (input index, pubkey/
  keystore identity, sighash context, exact signature bytes), have the
  ceremony event carry that set, require every REQUIRED-attributed
  signature at every gate to match a provenance entry, grant provenance
  only after a successful verified merge, invalidate/recompute it after
  transaction mutation, merging, finalization, or reopening, and recompute
  the REQUIRED signature set at broadcast. Put the software-signing guard
  in the common signing path (`signUnencryptedKeystores`), not only
  `signFromSeed`.
- **P6-F1a (process note) — First patch draft withdrawn.** The draft at
  `docs/p6-f1-sparrow-required-policy-fix.patch` is superseded: it does not
  apply cleanly (`git apply --check` fails — it was hand-authored and
  labelled as such), it has not been compiled or tested, and independent
  re-review identified design flaws beyond the format problem: it persisted
  the transaction-wide boolean criticized in P6-F1 item 4, set provenance
  before confirming merge success, retained provenance after later merges
  or mutation, lost provenance on cross-window PSBT forwarding (which would
  also have caused verified ceremony results to be *rejected* in the
  receiving window), did not cover saved/reopened ceremony results, guarded
  only `signFromSeed`, and let attribution `RuntimeException`s escape the
  USB combine handler (its try catches only `PSBTSignatureException`). Do
  not apply it; the signature-scoped redesign above is the required shape.

#### P6-F1 redesign clarifications (answers to independent re-review)

1. **Durability of protected signatures.** Yes — a legitimately protected
   signature must remain usable after save/close/reopen; forcing a fresh
   ceremony per session would be a regression. No boolean is persisted or
   trusted: the durable `.aexs` session state already persists
   `originalPsbt`, `message1..4`, `signedPsbt`, `rhos`, and
   `walletIdentity` (AntiExfilCoordinator.java:392–394, encoded at
   259–265), and `revalidate` (207–230) already re-derives the slot set
   from `originalPsbt`, revalidates the full transcript transition,
   re-verifies each reveal against durable `rhos`, and re-runs
   `reconstructSignedPsbt` requiring byte-equality with the stored signed
   PSBT. Provenance is therefore a **pure function of revalidated durable
   state**. Mapping a reopened signed PSBT to its session uses the existing
   filename key (sha256 of the canonical original PSBT,
   HeadersController.java:1095–1105) as an *untrusted lookup hint only* —
   strip the candidate ceremony slots' signatures, match the digest, then
   revalidate; a signedPsbt-digest index may be kept as a second hint under
   the same rule.
2. **Home of the verified-record type: Drongo (agreed).**
   `AntiExfilCoordinator.Completion` should return authoritative immutable
   per-slot verified records built inside `complete()` (161–166) and served
   by `getCompletedResult()` (110–114). `AntiExfilSigningSlot` already
   carries input index, signer pubkey, BIP143 message hash, sighash type,
   derivation, and script kind; the records add the exact verified
   signature bytes plus context/session/wallet identity. Sparrow must not
   reconstruct provenance by diffing PSBTs.
3. **Provenance identity (minimum set, endorsed).** Context digest (sha256
   of the canonical v0 original PSBT — already committed in message 1 and
   used as the session filename key); input index and outpoint; signer
   pubkey; BIP143 message hash; sighash type (always ALL in v1, retained
   for forward compatibility); the exact verified compact 64-byte
   signature (DER form admitted only at the final-transaction boundary);
   session ID; wallet-key identity (`walletIdentity`, already persisted).
   Every element already exists in revalidated durable state — provenance
   adds no new trusted data.
4. **Lifecycle semantics.** Proofs are only ever *added* by a verified
   ceremony completion or a successful verified merge; every other event
   can only invalidate. Retained: BIP174 combine that preserves the
   unsigned transaction and does not touch verified inputs' signature
   fields; forwarding to another window (the proof set travels with the
   event); finalization (the proof maps to the final witness/scriptSig
   signature at the same input). Invalidated: any mutation of the unsigned
   transaction (v1 is SIGHASH_ALL, so all BIP143 hashes change and the
   whole proof set for the transaction dies); input reordering (index-keyed
   identity). Pruned: proofs whose signature was replaced or removed by a
   merge or finalized-field copy. A failed merge grants nothing.
5. **Top-level signed transaction without its wallet: read-only quarantine
   (agreed).** Permit opening for inspection; disable combine, finalize,
   and broadcast until an open valid wallet allows attribution-based policy
   evaluation; re-evaluate when wallets are opened. If evaluation then
   attributes a REQUIRED signature with no provenance, broadcast stays
   disabled with an explicit message. Rejecting the open outright would
   block harmless inspection and forensics.
6. **Software-signing guard is per keystore (agreed).** In
   `signUnencryptedKeystores`, before `wallet.sign(signingNodes)`
   (HeadersController.java:1277–1295), refuse the action if any keystore
   that both carries private material in this wallet and participates in
   the PSBT has REQUIRED policy. Participation is determined by master-
   fingerprint attribution against the PSBT input derivations — the same
   primitive used by `AntiExfilPsbt` slot enumeration (lines 78–79) and
   `Wallet.getSignedKeystores`; `WalletNode` carries no direct keystore
   reference, so fingerprint matching is the mapping. Mixed wallets keep
   software-signing OPTIONAL keystores. `signFromSeed` additionally needs
   its pre-substitution check: the replacement `Keystore.fromSeed` gets the
   default policy, so the *original* policy-bearing keystore must be
   consulted before it is swapped out.
7. **Unknown-field allowlist scope (agreed, byte-level).** "Reject
   unknowns" means an explicit allowlist at global, input, and output map
   levels: BIP174/BIP371 keys required for the four supported script forms
   plus recognized proprietary namespaces; unknown non-proprietary keys are
   rejected. AEXB v1 carries no proprietary PSBT fields (session state is
   out-of-band), so nothing protocol-owned needs allowlisting. The
   reference (embit) gains a strict mode; Drongo upgrades its
   log-and-drop (PSBTInput.java:375–377) to a hard reject. This is decision
   9's recommended resolution.

#### P6-F1 implementation-plan review (independent re-review, second round)

The proposed architecture (Drongo-owned immutable `VerifiedAntiExfilSignature`
record, `Completion` returning verified records with no transaction-wide
flag, proof-set threading and per-signature gating in Sparrow, tests before
implementation, hardening in separate commits, validation then retag) is
endorsed as consistent with the clarifications above, with these material
comments:

1. Removing the transaction-wide *authorization* short-circuit must not
   remove the `isBroadcast()` assertion (INV-14) — completion still must
   never broadcast. The event marker becomes "carries a proof set," not
   "authorized."
2. `originalPsbtDigest` must be specified as sha256 of the **canonical v0
   export** (`getForExport().serialize()`), not of Sparrow's internal v2
   representation (P6-V5), or digests will diverge by construction site.
3. `getCompletedResult()` (AntiExfilCoordinator.java:110–114) must return
   the same records as `complete()`, and a determinism test must pin that
   records rehydrated from revalidated durable state equal the records
   returned at completion.
4. The finalized-merge branch (`copyFinalizedFields`,
   AppController.java:2193–2198) bypasses `verifyCombinedSignatures` and
   needs the same provenance gate as the combine branch.
5. Phase 5's SeedSigner early-backend probe (P7-F1) changes the SeedSigner
   app repo, so accepting it triggers a SeedSigner retag **and** a
   SeedSignerOS image rebuild with physical boot-gate revalidation — the
   only Phase 5 item with cross-repository tag consequences.
6. The unknown-field allowlist (decision 9) changes reference parser
   behavior: the pinned reconstruction fixture that deliberately preserves
   a host-owned unknown input entry (P4-F1) must be updated, so the frozen
   vectors will need regeneration and re-pinning (P8-V1 hashes change).
7. Two additions to the Phase 2 test list: a **shared cross-implementation
   mixed-provenance vector** (REQUIRED A protected + REQUIRED B ordinary in
   one multisig PSBT) consumed by reference, Drongo, and Sparrow suites —
   dovetailing with decision 14 — and a **tampered-session rehydration**
   negative test (modified `.aexs` must fail closed at revalidation,
   extending P5-V5).
8. Phase 5's "reference FFI buffer clearing" commit text should carry the
   P2-F2 caveat honestly: clearing a ctypes copy does not clear the
   original immutable Python `bytes`; it is best-effort hardening plus a
   documented residual, not a fix.


- **P6-F2 (info, UX hardening) — REQUIRED is settable on any airgapped
  keystore model.** `updateAntiExfilPolicy` shows the policy combo for any
  `HW_AIRGAPPED` keystore (KeystoreController.java:393–396). Setting
  REQUIRED on a device without ceremony support (e.g. Passport) makes that
  keystore unspendable until the policy is lowered — self-inflicted, but
  the UI offers no guard. Consider limiting REQUIRED to models with known
  protocol support.
- **P6-F3 (info) — Hand-edited wallet stores can attach REQUIRED to a
  software keystore.** The UI prevents it, but the enforcement model
  assumes policy is only set via UI; a software-signed bypass for such a
  doctored keystore exists for the same reason as P6-F1(3). Editing the
  encrypted wallet store is out of the stated threat model; noted for
  completeness and resolved by the P6-F1 recommendation.

**Phase 6 status: complete (amended after independent re-review).
Frozen-PSBT reconstruction is exclusive and cross-implementation pinned
(Phases 3–4); REQUIRED-policy persistence, migration, and selection are
sound and tested. One medium defect, wider than first assessed: policy
enforcement misses secondary ingest/combine/software-sign/broadcast paths
**and** is transaction-wide rather than signature-scoped on the primary
path, so a verified ceremony output can carry another REQUIRED keystore's
ordinary signature (P6-F1 items 1–4). The first patch draft is withdrawn
(P6-F1a); the required fix is signature-scoped provenance. No new tested
tag should be cut until the redesign and an expanded regression suite
(multisig mixed-provenance cases, failed-merge provenance, mutation/reopen
invalidation, cross-window results, metadata-stripped returns, doctored
REQUIRED software keystore via the normal decrypted path) pass.**

## Phase 7 — SeedSigner + SeedSignerOS specifics

Scope: preflight ordering, stateless message-3 recovery, native loading, and
the OS image boundary. Reviewed clones: SeedSigner at
`SeedSigner_AntiExfil_Review_Fresh` (app commit `f971a64`, tag
`anti-exfil-review-v1-tested-2026-08-14` on `aa8395e`) and SeedSignerOS at
`SeedSignerOS_AntiExfil_Review_Fresh_LF2` (commit `0bf1dc9`, tree
`1ed46cd…`, matching the checkpoint's verified fresh clone). Note: the older
`SeedSignerOS_AntiExfil_Review_Fresh` clone sits at the **rejected**
pre-correction commit `d1fee78` (S01z boot scripts); all OS conclusions below
are drawn from the corrected LF2 clone.

### Verified

- **P7-V1 — Native package pin is exact and hash-gated.**
  `opt/external-packages/seedsigner-anti-exfil/seedsigner-anti-exfil.mk`
  pins `SEEDSIGNER_ANTI_EXFIL_VERSION =
  2af926dc309a673461f0e2da090105c8f05b4505` from
  `BlockstreamResearch/secp256k1-zkp`; the adjacent `.hash` file pins the
  GitHub archive sha256
  `40e0858f5f189a078f2aeee10e1fc0e732f73abb7bc9f8745c63dac3f8d8d4e5`,
  matching the checkpoint's `buildroot_source_gate: passed`. The library
  installs under `/usr/lib/seedsigner` (isolated from embit's bundled
  backend), builds shared-only, and enables **only** the `ecdsa-s2c` module;
  every other module (ecdh, recovery, extrakeys, schnorrsig, musig,
  ellswift, rangeproof, etc.) is explicitly disabled.
- **P7-V2 — Pi Zero artifact gate.** A post-build hook (gated on
  `BR2_arm1176jzf_s`) runs `readelf -A` requiring `Tag_CPU_arch: v6` and
  rejecting any v7/AArch/NEON leakage, and `nm -D` requiring the three
  binding symbols (`secp256k1_ecdsa_anti_exfil_signer_commit`,
  `secp256k1_anti_exfil_sign`, `secp256k1_ecdsa_s2c_opening_serialize`). A
  miscompiled or wrong-arch library cannot ship silently.
- **P7-V3 — Board scope is deliberate and fail-closed.** Only
  `opt/pi0/configs/pi0_defconfig` sets
  `BR2_PACKAGE_SEEDSIGNER_ANTI_EXFIL=y`; pi02w/pi2/pi4 and all dev variants
  do not. `docs/anti-exfil.md` states the package "is currently enabled only
  for the physically validated Pi Zero target." On other boards the app
  binding raises `AntiExfilUnavailableError` (library absent) — availability
  limitation, not a security hole.
- **P7-V4 — Image boundary separation is enforced in `opt/build.sh`.**
  `--anti-exfil-test` requires `--pi0` (exit 3 otherwise); the test overlay
  is injected only into the *generated* `.config` via
  `buildroot/utils/config --set-str BR2_ROOTFS_OVERLAY`, leaving the
  checked-in production defconfig untouched; test images get a distinct
  `.anti-exfil-test.img` filename. The checkpoint's normal-image gate
  confirms the production image boots to the main menu with the test
  receipt absent. The pinned application commit enters the image via
  `--app-commit-id` (`f971a64` in the gated images).
- **P7-V5 — Boot-order correction verified.** The rejected test image
  (`S01z*` ran before `S10mdev` mounted the SD boot partition) was corrected
  to `S11zantiexfil-selftest` / `S11zzantiexfil-file-stage`, which poll
  `/proc/mounts` for the OS-owned `/mnt/microsd` mount rather than mounting
  themselves. Receipts are written via `.tmp` + rename on FAT. The
  file-stage adapter treats any visible result/exit-code/response as
  terminal and refuses retry or overwrite — explicitly preventing
  post-opening retries with fresh host randomness even in the test harness.
- **P7-V6 — Production native binding is fail-closed with no fallback.**
  `helpers/anti_exfil.py` requires an absolute library path, binds all
  required symbols at construction, creates a SIGN|VERIFY context (`0x301`)
  and randomizes it with an `os.urandom(32)` buffer that is cleared
  afterwards. Secret-key, opening, and signature buffers are zeroized in
  `finally` blocks. Any missing library/symbol or native failure raises
  before use — there is no Python or ordinary-ECDSA fallback path.
- **P7-V7 — Preflight ordering: validation precedes the stock parser.** In
  `psbt_views.py`, when `anti_exfil_state` is present,
  `validate_for_review(seed, network)` runs **before** `PSBTParser`
  construction, so hostile or damaged requests reach the controlled
  anti-exfil error view and never SeedSigner's generic system-error screen.
  `validate_request` checks stage, network family, exact PSBT digest
  (sha256, `hmac.compare_digest`), full slot-enumeration equality, and
  per-slot sighash — without invoking the signing backend. The
  `allow_mixed_inputs=True` relaxation passed to `PSBTParser` is safe:
  `derive_signing_contexts`/`_classify` already validated every input
  individually (four supported script forms, consistent redeem/witness
  scripts, Taproot rejected); the parser retains the first policy only for
  conservative display.
- **P7-V8 — Stateless message-3 recovery is structurally sound.**
  `AntiExfilFlowState` (dataclass, `slots=True`) holds only public data —
  request package, parsed PSBT, response package — and explicitly persists
  no secret session state. A fresh `from_package` accepts `HOST_REVEAL`
  without any retained message-2 state; `process()` recomputes the signer
  opening (deterministic RFC6979) and rejects with `AE_OPENING_MISMATCH` if
  it differs from the accepted message-2 opening, and verifies
  `host_commit(rho) == commitment` (`AE_COMMITMENT_MISMATCH`) before
  signing. The UI supports "exit and scan it later"
  (`AntiExfilRoundOneCompleteView`), and the same-ceremony shortcut
  (`ScanAntiExfilHostRevealView`) preserves the already-selected seed via
  `preserve_psbt_seed` while the main-menu path re-asks — matching the
  documented design.
- **P7-V9 — Mode gating is bidirectional at scan time.** An anti-exfil QR
  with the setting not `Required` routes to `AntiExfilModeMismatchView`
  (with a shortcut to the setting); a plain PSBT QR while `Required` routes
  to the inverse mismatch view. The setting is global, Advanced-only,
  default `Disabled`, options `Disabled`/`Required`
  (`settings_definition.py:695–706`).
- **P7-V10 — Single-shot responses and state hygiene.**
  `create_response` raises `WRONG_STAGE` on any second invocation and
  forces all response transport invariants (`response.encode()`) before the
  phase transition. The controller clears `anti_exfil_state` (with
  `psbt`/`psbt_parser`/`psbt_seed`) at startup and on back-stack reset
  (`controller.py:192,306–309`), so no stale ceremony state can reroute a
  later signing flow. `FLOW__ANTI_EXFIL` resume routing through seed
  selection is explicit.
- **P7-V11 — Self-test is pinned and test-image-only.**
  `helpers/anti_exfil_selftest.py` runs the fixed secret/message/host-
  randomness vectors, compares with `hmac.compare_digest`, exits non-zero on
  mismatch, and reports `"production_fallback": false`. It exists only in
  the opt-in test overlay; the checkpoint's corrected-test-image gate
  records exit code 0 with opening and signature matches on hardware.

### Findings

- **P7-F1 (low, availability/UX hardening) — Backend availability is only
  discovered at signing time.** On a board without the native library (or a
  damaged image), the user scans message 1, reviews the transaction, and
  selects a seed before `AntiExfilNativeBackend()` construction fails with
  `AE_NATIVE_BACKEND`. This fails closed and no secret operation occurs, but
  the failure is late. Recommendation: probe backend construction once at
  scan time (or in `validate_for_review`) and route to the failure view
  immediately, so a missing/wrong library is surfaced before review.
- **P7-F2 (info, confirm intent) — Testnet-family network matching on the
  signer.** `protocol_network_matches_setting` accepts wire networks
  TESTNET3/TESTNET4/SIGNET when the device setting is "testnet"; mainnet
  and regtest require exact matches. This is a device-side convenience
  relaxation (no mainnet crossover is possible), but it is wider than the
  coordinator's exact-network binding, so a message committing to testnet4
  is accepted by a device set to generic "testnet". Confirm this family
  semantics is the intended signer-side policy and document it in the
  protocol notes.

**Phase 7 status: complete. The OS image boundary (pin, hash, module
minimization, pi0-only scope, test-overlay separation, corrected boot
ordering) and the app-side properties (fail-closed native binding, preflight
validation before the stock parser, stateless message-3 recovery,
single-shot responses, bidirectional mode gating, state cleanup) are all
verified against the gated clones. One low availability/UX hardening item
(P7-F1) and one intent-confirmation note (P7-F2); no security defects.**

## Phase 8 — Validation runs

Environment: Windows 11, pwsh, repository venv Python, native backend
`run/native-build/bin/libsecp256k1-6.dll`, SeedSigner cross-implementation
source at the tagged clone `SeedSigner_AntiExfil_Review_Fresh/src` (app
commit `aa8395e`, tag `anti-exfil-review-v1-tested-2026-08-14`). All runs
from the reference repository root.

### Results

- **P8-V1 — Vector regeneration is byte-identical.**
  `scripts/generate_protocol_v1_vectors.py` and
  `scripts/generate_protocol_v1_semantic_vectors.py` were re-run into a
  disposable directory. SHA-256 comparison against the pinned fixtures:
  - `fixtures/protocol-v1-multislot-vectors.json` — `BAFD399A…C1BB3`
    (regenerated identical)
  - `fixtures/protocol-v1-semantic-psbt-vector.json` — `F28D572D…A3A4E`
    (regenerated identical)
  The frozen vectors reproduce exactly from the pinned sources.
- **P8-V2 — Focused suites pass.** `test_crypto`, `test_native`,
  `test_protocol_v1_codec`, `test_psbt_v1`, `test_coordinator_v1`,
  `test_transport`: **45 tests, OK** (4.8 s). Includes native-vs-reference
  output equality, golden-vector replay, mutation rejection, and UR2
  round-trip byte-identity under reordering.
- **P8-V3 — Full reference suite passes against the tagged SeedSigner
  source (wording corrected after independent re-review).** With
  `SEEDSIGNER_SRC` pointing at the tagged clone, `python -m unittest
  discover -s tests/reference -t .` runs **82 tests, OK, 0 skipped**;
  `test_seedsigner_adapter` executes against the tagged source (3/3 OK).
  Correction: the run *without* `SEEDSIGNER_SRC` set was **not**
  dependency-free — `test_seedsigner_adapter.py:16–24,27` falls back to a
  local default path (`Windsurf/SeedSigner_AntiExfil/src`, untagged commit
  `663389a`) and skips only if that path is absent, and the local native
  DLL likewise prevents native skips. That second run therefore exercised
  an unpinned SeedSigner clone and is not evidence that the extracted
  reviewer archive runs standalone; a truly standalone run would show the
  adapter tests skipped. The tagged-source run is the meaningful
  cross-implementation gate and it passed.
- **P8-V4 — Adversarial corpora pass.** `test_adversarial` +
  `test_adversarial_device_v1`: **8 tests, OK** (3.5 s). Coverage includes:
  dark-skippy nonce channel detected; nonce-grinding channel detected;
  predetermined-nonce forgery is valid ECDSA but rejected by S2C
  verification; honest signature passes the same harness; selective abort
  requires same session and exact retry; the physical rejection corpus
  reaches the expected SeedSigner rejection for every case; only the three
  documented wire cases bypass the strict reference transport; the corpus
  generator retains manifest text frames and verified PNGs.
- **P8-V5 — Implementation suites were previously executed and relied upon
  from checkpoints; they were not rerun during Phase 8.** Drongo and Sparrow
  focused and full Gradle suites were previously executed by the project and
  recorded in `sparrow-review-series-checkpoint.json` and the Drongo review
  evidence; the SeedSignerOS normal and instrumented image gates (boot to
  main menu, receipt presence/absence, self-test exit 0, opening/signature
  match on hardware) are recorded in
  `seedsigner-os-review-series-checkpoint.json`. Phase 8 reran only the
  reference vectors and Python suites (P8-V1..V4); the implementation and
  image gates stand as previously recorded.

### Findings

No new findings. All automated gates pass against the pinned inputs, and the
regenerated vectors match the frozen fixtures byte-for-byte, confirming the
reviewed test materials are reproducible from the pinned sources.

**Phase 8 status: complete. Validation confirms reproducibility of the
frozen vectors and a fully green reference, cross-implementation, and
adversarial test posture against the tagged inputs.**

---

## Phase 9 — P6-F1 remediation review (2026-08-18)

Scope: `docs/p6-f1-implementation-review-brief.md`. Ranges reviewed:
Drongo `1250d5a..1bbafd94` (branch `codex/p6-f1-signature-provenance`),
Sparrow `c88c573..90c64c9d` (same branch; drongo submodule pin verified
`1250d5a..1bbafd9`), reference/artifacts `ed3d323..6e1b23a`. Method:
full-diff review of main code plus added tests; fixture hash verified
(`protocol-v1-mixed-provenance.psbt` SHA-256 `45e3877a…4daa` matches the
brief); review clones unmodified.

### Property ledger (brief §"Required security review")

1. **Proof authorizes exactly one signature — PASS.** Proof identity binds
   sessionId, canonical-original-v0 digest (sha256 of `state.originalPsbt`,
   AntiExfilCoordinator.java `deriveVerifiedSignatures`), wallet-key
   identity, input index + outpoint (from the original transaction), signer
   pubkey, BIP143 message hash, sighash, and exact compact signature;
   matching is full-field equality (`findMatchingProof`,
   AntiExfilPolicy.java) with DER↔compact normalization via
   `asTransactionSignature` and a separate sighash-flag equality check.
2. **Ceremony for A must not authorize B's ordinary signature — PASS.**
   `AntiExfilMixedProvenanceTest` pins that Drongo preserves B's partial
   signature and emits exactly one proof (A's); Sparrow's
   `mixedRequiredMultisigRejectsOrdinarySignatureNotCoveredByProof` asserts
   `REQUIRED_PROOF_MISSING` with both keystores REQUIRED, `PERMITTED` when B
   is OPTIONAL, and non-PERMITTED after finalization with only A's proof.
3. **Fresh vs `.aexs` reload derive identical records from revalidated
   state — PASS.** All three completion paths (`complete()`, retry,
   `getCompletedResult()`) call `deriveVerifiedSignatures(state)`, which
   re-enumerates slots, re-runs reconstruction, and requires byte-equality
   with the stored signed PSBT; `AntiExfilCoordinatorTest` pins
   fresh == reloaded == retry record sets and record immutability/
   defensive copies. Missing/corrupt/path-escaped candidates grant nothing
   (`reloadsOnlyRevalidatedMatchingProofsAndIgnoresUntrustedIndex`,
   including a corrupted-session tail-byte flip → empty).
4. **Session index is an untrusted hint — PASS.**
   `AntiExfilProvenanceStore.resolve` constrains candidates to the wallet
   session directory with double containment (normalized-path prefix **and**
   `toRealPath` prefix — the Windows symlink/junction defense), requires the
   parent directory to equal the keystore identity, bounds the scan
   (1024 candidates / 4096 index lines), and fully revalidates each
   candidate via `AntiExfilCoordinator.load(...).getCompletedResult()`
   before `retainMatchingProofs` filters to signatures actually present.
5. **Provenance survives only unsigned-tx-preserving flows; pruning —
   PASS.** `handleTransactionMerge` evaluates a *prospective copy* before
   both `combine` and `copyFinalizedFields` (the finalized branch is gated,
   closing plan-review comment 4), and replaces stored proofs with
   `retainMatchingProofs(...)` only after a successful mutation; failed
   merges return early granting nothing. Proofs bind input index, outpoint,
   and message hash, so reordering or any SIGHASH_ALL transaction mutation
   invalidates them structurally; `evaluateSignatureProvenance` also
   rejects input-count mismatch and any proof not matched to a present
   signature (`INVALID_PROVENANCE`).
6. **Gate coverage — PASS.** Primary QR return (`viewPSBT` →
   `violatesAntiExfilPolicy` with proof set), cross-window forwarding
   (repost now carries the proof set — the withdrawn-draft defect is
   fixed), non-final combine and finalized-field copy (prospective
   evaluation in `handleTransactionMerge`), USB/card return
   (`signDeviceKeystores` evaluates before `verifyCombinedSignatures`/
   `combine`), scanned-seed and common software signing (`signFromSeed`
   per-participating-keystore check plus `violatesRequiredSoftwareSigning`
   in `signUnencryptedKeystores`), finalization (`finalizePSBT` gate), and
   broadcast (`broadcastTransaction` gate at method top). Ingest-level
   enforcement moved from refusal to read-only quarantine, consistent with
   the agreed design.
7. **Read-only quarantine without policy context — PASS with one scope
   caveat (R-F1 below).** Signed imports without an attributable open
   wallet remain inspectable; the `FinalizingPSBTWallet` auto-finalize path
   is removed and finalize/broadcast/view-final/show-transaction/save-final
   controls are disabled with an explanatory label (`applyProvenance
   Quarantine`); quarantine lifts via `reloadVerifiedAntiExfilSignatures`
   on signing-wallet assignment.
8. **Per-participating-keystore software guard — PASS.**
   `violatesRequiredSoftwareSigning` scopes by `getSigningKeystores(psbt)`
   (participation) and compares `AntiExfilCoordinator.getWalletKeyIdentity`
   (xpub+fingerprint+derivation identity, not fingerprint-only);
   mixed-policy wallets keep software-signing OPTIONAL keystores, and the
   test asserts both directions.
9. **REQUIRED offered only for verified models — PASS.**
   `supportsRequiredAntiExfil` restricts REQUIRED to
   `WalletModel.SEEDSIGNER`; existing incompatible REQUIRED values remain
   selected, visible, and enforceable with a warning tooltip, and the
   listener refuses re-selection — no silent rewriting. Covered by
   `KeystoreFxmlAntiExfilTest`.
10. **`isBroadcast()` invariant — PASS.** The completion assertion
    (`IllegalStateException` on broadcast) is intact; the event carries a
    proof set, never an authorization boolean.

### Findings

- **R-F1 (low, functional regression; no security impact) — Raw signed
  transactions are unconditionally quarantined, with no lift path.**
  `currentProvenanceStatus()` (HeadersController.java, new head) calls
  `evaluateSignatureProvenance(signingWallet, null, transaction, proofs)`
  for PSBT-less tabs; with `contextPsbt == null` the evaluator returns
  `POLICY_CONTEXT_UNAVAILABLE` for any transaction containing signature
  material (AntiExfilPolicy.java:127–132, `hasSignatures` at 284–292).
  Result: every raw signed transaction tab — sweep results
  (`PrivateKeySweepDialog` → `addTransactionTab(null, null, transaction)`),
  pasted or file-opened signed hex — has finalize/broadcast disabled
  forever, because the rehydration path
  (`reloadVerifiedAntiExfilSignatures`) returns early when there is no
  PSBT. This exceeds property 7's conditioning ("without attributable
  wallet policy context"). **Recommendation, amended after re-review
  (the initial suggestion to permit "when no open wallet attributes" was
  corrected: non-attribution is uncertainty, not safety — a closed REQUIRED
  wallet must never flip quarantine to permission):** in the PSBT-less
  branch, (a) permit only when every signature on every input attributes
  *positively* to an open wallet's keystores with non-REQUIRED policy,
  using prevout-resolved, signature-verifying attribution (missing wallet
  history, ambiguous attribution, or any exception remains fail-closed);
  (b) quarantine when attribution reaches a REQUIRED signer without a
  context PSBT/proofs; (c) retain quarantine when nothing attributes;
  (d) exempt Sparrow-internal sweep results via an explicit origin marker
  set only at the creation site (`PrivateKeySweepDialog` →
  `addTransactionTab`), never parseable from file/clipboard/QR/event input,
  never carried cross-window, and not surviving save/reopen. Alternatively,
  accept and document the restriction — but sweep broadcast breaking
  silently is a user-visible regression that deserves a deliberate decision.

### Confirmations requested by the brief

- **Missing routes:** none found. All ingestion (QR/file/text/event),
  merge (both branches), signing (seed-scan, unencrypted-software, USB/card
  combine), finalization, and broadcast routes pass through
  `evaluateSignatureProvenance` or the quarantine. Sweep/private-key and
  blockTransaction views are unaffected or covered by R-F1.
- **Mixed-provenance regression:** on the pinned pre-fix head the test
  could not pass — the provenance evaluator did not exist and
  `violatesAntiExfilPolicy` returned false unconditionally on
  `antiExfilVerified=true`, accepting B's ordinary signature wholesale.
  It now passes for the intended reason: per-signature exact proof matching
  yields `REQUIRED_PROOF_MISSING` for B.
- **Transaction-wide authorization boolean:** confirmed removed.
  `ViewPSBTEvent` carries `Set<VerifiedAntiExfilSignature>` (default
  `Set.of()`); no boolean bypass remains in `violatesAntiExfilPolicy`,
  merge handling, or broadcast.

### Phase 9 status and tag recommendation

**The remediation correctly implements the agreed signature-scoped
design; all ten security properties pass.** The heads are ready for
immutable tested tags and reviewer-bundle freeze **subject to a decision on
R-F1** (fix the raw-transaction quarantine lift path, or explicitly accept
and document the broadcast restriction). If R-F1 is fixed, re-run the
focused provenance/quarantine suites plus one physical smoke of raw-tx
broadcast; if accepted as-is, document it in the release notes for the tag.

### R-F1 resolution review (2026-08-20)

Range reviewed: Sparrow `90c64c9..7674cec` (six commits, six files;
Drongo unchanged at `1bbafd94`). The fix implements the amended narrow
matrix exactly; all eight requested checks pass:

1. **BlockTransaction metadata grants no authority — PASS.** The old
   `blockTransaction != null → PERMITTED` escape in
   `currentProvenanceStatus` is gone; PSBT-less tabs always evaluate via
   `getRawTransactionProvenance`, and
   `internalSweepExemptionIsLocalEphemeralAndDigestBound` pins that
   attached reference metadata still yields `POLICY_CONTEXT_UNAVAILABLE`.
2. **Fail-closed quarantine without full attribution — PASS.** Quarantine
   applies at initial import (`applyProvenanceQuarantine` at initialize),
   persists through reference fetching, and returns on wallet closure
   (`openWallets` → `refreshRawTransactionPolicyWallet`, which reapplies
   quarantine even when selection yields null).
3. **OPTIONAL lift / REQUIRED precedence — PASS.**
   `evaluateRawTransactionProvenance` requires complete positive
   attribution (`getSignedKeystores(Transaction)` count must equal total
   final-signature count) and any REQUIRED signer yields
   `REQUIRED_PROOF_MISSING`; `selectRawTransactionPolicyWallet` prefers a
   REQUIRED-attributing wallet over a PERMITTED one regardless of order
   (pinned by `rawTransactionQuarantineRequiresPositiveCompleteOptional
   Attribution`).
4. **Re-evaluation hooks — PASS.** `openWallets`, `walletHistoryFinished`
   (attribution arriving only after sync), and `walletHistoryChanged` all
   refresh PSBT-less tabs; wallet close flows through `OpenWalletsEvent`
   (physically verified: quarantine returns automatically).
5. **INTERNAL_SWEEP scope — PASS.** Set only at `PrivateKeySweepDialog`'s
   direct `addTransactionTab` route; in-memory on `TransactionData`;
   digest-bound (`Sha256Hash` of the serialized transaction captured at
   construction, re-verified live); carries only the already computed
   nonnegative fee; all parsing, persistence, and cross-window routes use
   the EXTERNAL constructors.
6. **Mutation/ephemerality — PASS.** Any byte mutation invalidates origin
   and fee (`hasValidInternalSweepOrigin` re-hashes the live transaction);
   saved/reopened and cross-window transactions are EXTERNAL; both are
   pinned by tests.
7. **View Final / fresh broadcast check — PASS.**
   `shouldDisableViewFinal` disables View Final unconditionally for
   PSBT-less tabs; `broadcastTransaction` still evaluates
   `currentProvenanceStatus()` at invocation.
8. **No weakening of prior gates — PASS.** The PSBT branch of
   `currentProvenanceStatus`, the provenance evaluators, and the
   `isBroadcast()` completion assertion (HeadersController.java:1146) are
   unchanged.

**R-F1 is resolved.** No new findings; no missing routes, fail-open
transitions, or precedence issues identified. **Sparrow head `7674cec`
and Drongo head `1bbafd94` are recommended for immutable tested tags and
reviewer-bundle freeze.**

---

## Phase 10 — V12 independent audit triage (2026-08-21)

Inputs: `docs/export.md` (22 findings against Drongo `1bbafd94`; 20
unreviewed, 2 marked invalid by V12) and `docs/v12-findings-verification
-plan.md`. This phase records an independent credibility assessment only;
no V12 proof of concept was executed and no V12 patch is accepted.

### Priority 0: #247985 — duplicate openings expose the signing key

**Source-confirmed reachable; the cryptographic claim independently
re-derived and sound.** At `1bbafd94`:

- `AntiExfilCodec.validate` enforces slot ordering, per-input limits, and
  duplicate host commitments/reveals, but no cross-slot uniqueness of
  signer opening points.
- `AntiExfilCoordinator.acceptOpenings` releases per-slot rho after
  opening acceptance with no opening-uniqueness check.
- `AntiExfilPsbt.enumerateSigningSlots` legitimately permits the same
  signer public key on multiple inputs (slot identity = input index +
  pubkey).
- `AntiExfilCrypto.verify` checks each opening/rho/signature tuple
  independently.

With a reused opening point Q under the same key across two slots, the
effective nonces are k_i = k0 + t_i with t_i = taggedHash(POINT_TAG,
Q ‖ rho_i) publicly computable, so k1 − k2 = t1 − t2 is known and the
private key follows from the two public signatures in one linear
equation. The coordinator emits `VerifiedAntiExfilSignature` evidence for
the leaking ceremony, so the protocol's core covert-channel guarantee is
broken. Critical severity is justified. **This gap was also missed by my
Phase 1/2 review, which verified single-slot S2C soundness but did not
enumerate cross-slot multislot invariants; recorded here for ledger
honesty.**

The Python reference oracle's slot checks cover duplicate slot
*identifiers*, not opening-point reuse across distinct slots, so the
spec/rule gap is shared: the fix requires the same invariant in the
reference plus a shared negative vector, or the implementations will
differentially accept.

### Severity calibration notes

- **247988/247987 (rollback/erasure, V12 Critical/High):** rest on a
  local-filesystem attacker able to replace or roll back coordinator
  state, which decision 5 places in the trusted base. Not accepted as
  Critical/High without a maintainer threat-model decision (Gate 5).
- **247989 (abort gate only at creation, not at reveal boundary):**
  credible **in-model** state-machine defect — no filesystem attacker
  required. Highest priority after 247985.
- **247993 (allocation before size check), 247998 (JVM lock contention),
  247991 (lexical lock identity vs path aliases), 247986 (no parent-dir
  durability barrier):** credible as resource/concurrency/durability
  defects at the stated severities or lower; verifiable with bounded
  fault-injection tests.
- **247996 (foreign partials preserved):** intentional per the P6-F1
  mixed-provenance remediation; disposition is a documented contract
  ("protected slots verified, foreign partials preserved but untrusted"),
  not a fix.
- **247997 (witness-UTXO trust):** standard BIP174 trust assumption;
  availability-only impact; document.

### Endorsed gate order, with two amendments

The plan's Gate 1→5 order is endorsed, amended as follows:

1. **Gate 1 must span both verifiers.** Patch the reference oracle and
   add a shared negative vector (reused opening, same key, two inputs)
   alongside the Drongo fix; regenerate affected corpora.
2. **Gate 1 interacts with #248000.** If `validateTransition` does not
   fully validate both messages (248000's claim), the opening-uniqueness
   check must be guaranteed to execute on the `acceptOpenings` path
   before rho release — either by full validation of the openings message
   in the coordinator or by placing the invariant in the transition path.
   Decide placement deliberately and test that the check cannot be
   bypassed through the transition-only route.

The evidence standard in the verification plan (§"Evidence required for
every accepted finding") is endorsed as written, including no key-recovery
or weaponized demonstrations: the Gate 1 regression only needs "reused
opening rejected before any rho is returned" plus "distinct legitimate
openings still pass".

### Tag disposition

The current Drongo/Sparrow tested tags remain valid immutable evidence of
the reviewed states but **must not be promoted to a release** until Gate 1
is remediated and re-reviewed. New immutable tags only after the Gate 1
diff review, focused+full Drongo suites, reference cross-implementation
vectors, and Sparrow suite (plus the physical gate only if wire behavior
changes — it does not for a validation-only fix, but the multislot
negative vector should reach the physical rejection corpus).

### Gate 1 design decisions and follow-up dispositions (2026-08-21)

GPT's refinement is **verified against source**: `acceptOpenings()` decodes
the incoming message via `AntiExfilCodec.decode()`, which invokes full
`validate()`. The uniqueness invariant placed in `validate()` therefore
executes before rho disclosure on every coordinator path.
`validateTransition()` itself performs transition checks only, so #248000
remains a live finding for direct callers but does not block Gate 1.

**Gate 1 decisions (agreed):** reject repeated opening points only among
slots sharing the same canonical compressed signer public key; compare
canonical encodings (already enforced at parse); return
`OPENING_MISMATCH`; place the invariant in `AntiExfilCodec.validate()`;
apply the equivalent rule to the Python reference; add a shared negative
vector without changing positive vectors or the wire version; no
key-recovery PoC — the rejection regression suffices.

**Physical corpus correction:** my earlier statement that the negative
vector should reach the physical rejection corpus was imprecise. Message 2
(SIGNER_OPENINGS) is signer→host only; SeedSigner never ingests it. The
vector belongs in the host-side Drongo/Sparrow negative corpus and the
shared cross-implementation vector set. No SeedSignerOS rebuild or
physical rejection test is required for Gate 1.

**Follow-up dispositions:**

1. *Abort acknowledgement model:* fail closed — any new journal abort
   appearing between session creation and the reveal boundary permanently
   invalidates the in-flight session. If maintainers later want an
   acknowledgement UX, the session must durably record the journal
   generation/digest at creation; the reveal-time recheck compares the
   current digest; an explicit acknowledgement binds to the exact digest
   observed and is recorded durably, covering only aborts present at that
   digest, never future appends.
2. *Automatic rejection journaling:* journal `SIGNATURE_REJECTED` only
   for failures attributable to signer-supplied data — structural,
   transcript-binding, or cryptographic rejection of message 2 or
   message 4, including verification failure in `complete()`. Local I/O
   failures, corrupt host state, wrong-stage/retry conflicts, and
   programming errors fail closed but are not journaled (they are
   host-side faults; journaling them would poison the nonce-reuse
   defense with false aborts).
3. *Abort deduplication (#248004):* at most one abort event per session,
   first recorded reason retained, repeated calls idempotent no-ops.
   Agreed as the simplest safe rule.
4. *Lock order:* journal → session is the single global order for every
   path that holds both (creation gate, reveal-time recheck, abort
   recording), including cross-process use via `FileChannel` locks.
   Session-only paths are unaffected. Per #247991, lock identity must be
   canonicalized (real path) before this ordering reasoning holds.
5. *Windows durability contract (#247986):* `channel.force(true)` remains
   required for file content. Directory-entry durability after
   create/rename is fsync'd on POSIX; where the platform does not support
   it (Java on Windows), degrade gracefully with a documented
   recovery-grade residual — do **not** fail closed. Coordinator
   persistence already sits inside the decision-5 trusted filesystem, and
   the marginal risk is state loss/rollback after power failure, which is
   detected at revalidation, not a silent security failure.

---

## Phase 11 — V12 Gate 1 implementation review (2026-08-21)

Inputs: `docs/v12-gate1-implementation-review-brief.md`; diffs Reference
`dd7b2b2..eb1542e`, Drongo `1bbafd9..67127fd`, Sparrow
`7674cec..e6e38b9` (Sparrow pins Drongo `67127fd3`). Review is static:
diffs, fixture hashes, and production ingress paths inspected directly;
test results in brief §5 taken as ledger evidence (baseline-failure claim
is internally consistent with the reviewed pre-fix code).

### Ten-property results

1. **Correct scope — PASS.** Both validators group by the canonical
   compressed signer pubkey (`Map<Bytes, Set<Bytes>>` in Drongo;
   `openings_by_signer` dict in the reference). Canonical form is
   enforced by per-slot validation before grouping. Cross-key opening
   equality is explicitly permitted and tested in both suites.
2. **All relevant stages — PASS.** The check fires whenever
   `slot.opening != null`; slot-level validation ties opening presence to
   stage ≥ `SIGNER_OPENINGS`. Messages 2/3/4 all pass through
   `validate()`/`_validate_message` on both encode and decode.
3. **Before-rho enforcement — PASS.** `acceptOpenings()` decodes message 2
   via `AntiExfilCodec.decode` (full `validate()`) before constructing or
   returning message 3; state is written only after validation. The retry
   path returns the cached message 3 only for bytes identical to the
   previously validated message 2. Rehydration (`validateState`) decodes
   message 2, re-running validation. Sparrow's scan boundary
   (`AntiExfilTransportPackage.decode`, line 89) also fully validates.
   No production path constructs message 3 from unvalidated openings.
4. **Complete-message failure — PASS.** The first repeat throws
   `OPENING_MISMATCH` from within the slot loop; no state write, no
   partial reveal, no message-3 construction on that path.
5. **No compatibility regression — PASS.** Same-key/distinct-opening is
   tested as accepted in both suites; positive canonical fixtures are
   untouched by the diffs (stat-verified). Honest signers cannot false-
   reject: same-key slots on distinct inputs have distinct BIP143 message
   hashes, and same-key same-input duplicates are already rejected as
   duplicate slot identifiers.
6. **Reference/Drongo parity — PASS with one observation (O1).**
   Grouping, equality, stage coverage, and error code are identical.
   Within-iteration check ordering diverges: Drongo evaluates the
   per-input slot limit before the opening check; the reference after.
   Only error-code selection for multiply-invalid messages differs; both
   fail closed, and the shared negative vector is unaffected.
7. **Host integration — PASS.** Sparrow's new test decodes the shared
   wrapped AEXT vector through the real package boundary under Drongo
   `67127fd3` and asserts `OPENING_MISMATCH`. All three fixture copies
   are byte-identical (SHA-256 `f5b9d3d2…e97599`, independently
   re-hashed, matching the brief).
8. **No accidental #248000 disposition — PASS.** `validateTransition()`
   is unchanged; no doc claims it performs full object validation. The
   finding stays open for Gate 4. Object-form callers bypassing
   decode/validate would miss the new invariant — currently no such
   production caller exists.
9. **No signer-side scope expansion — PASS.** No SeedSigner/SeedSignerOS
   changes; `shared-vector-index.md` correctly documents the vector as
   host-side only.
10. **No unrelated authorization change — PASS.** Drongo range touches
    codec + codec test + fixture only; Sparrow range is the submodule pin
    + transport test + fixture only. Provenance, R-F1 quarantine, PSBT
    reconstruction, and broadcast policy are untouched.

### Observations (non-blocking)

- **O1 — check-order divergence:** Drongo rejects a slot exceeding the
  per-input limit with `SIGNATURE_SLOT_MISMATCH` before reaching the
  opening check; the reference evaluates the opening check first and
  would return `OPENING_MISMATCH` for a message violating both. Both fail
  closed; severity nil. Align ordering or document the tolerated
  divergence in `shared-vector-index.md`.
- **O2 — Sparrow fixture-growth asymmetry:** the reference test pins the
  exact case-name list and the Drongo test asserts a single
  `message_hex` match, so both fail if the fixture gains cases; Sparrow's
  test reads only `cases[0]` and would silently ignore added cases.
  Recommend iterating all cases (as the reference does) when the fixture
  next grows.

### Disposition

**Gate 1 approved against §6.** No bypass, no false-rejection path, no
fixture mismatch, no missing production path found. Tag hold remains in
effect per brief §7: replacement tested tags only after public CI is
green; the 2026-08-20 tags stay immutable evidence of the vulnerable
state.

### Observation closure review (2026-08-21)

Ranges: Drongo `67127fd..5a7baed` (`5a7baed1a2cad23f0f0a4f007d49cdba44415
b60`), Sparrow `e6e38b9..3eb93d5`; Reference unchanged at `eb1542e`.

- **O1 closed.** Drongo's per-input limit check now runs after the
  commitment/reveal/opening checks, matching the reference iteration
  order exactly (ordering → commitment → reveal → opening → per-input).
  Acceptance is unchanged by construction: all checks are pure predicates
  over slot fields, a throw aborts the whole validation, and the accepted
  set is the conjunction of the same checks in either order. Only
  error-code selection for multiply-invalid messages changed, which was
  the intent.
- **O2 closed.** `AntiExfilTransportPackageTest` now iterates every
  `cases` entry with a non-empty assertion, decoding each `package_hex`
  and asserting its declared error. New fixture cases can no longer be
  silently skipped.
- **Pin verified.** Sparrow's `drongo` submodule points at exactly
  `5a7baed1a2cad23f0f0a4f007d49cdba44415b60`, the Drongo branch head.

**Gate 1 review is complete.** Final Gate 1 heads: Reference `eb1542e`,
Drongo `5a7baed1a2cad23f0f0a4f007d49cdba44415b60`, Sparrow `3eb93d5`.
Replacement tested tags remain gated on public CI per brief §7.

---

## Phase 12 — V12 Gate 2 implementation review (2026-08-22)

Inputs: `docs/v12-gate2-implementation-review-brief.md`, the locked design
record `docs/v12-gate2-abort-state-machine-design.md`; diffs Reference
`eb1542e..3fabb38`, Drongo `5a7baed..0e1d1c3`
(`0e1d1c3abd71ef5d2bd7c02fdd4d09e0ba56a354`), Sparrow
`3eb93d5..9936628`. Static review of git objects at the exact commits;
test results in brief §6 taken as ledger evidence. Note: both review
clones were checked out at Gate 1 heads during review — working-tree
reads reflect Gate 1 code; Gate 2 code was inspected via `git show` at
the pinned commits.

### Twelve-property results

1. **Atomic create gate — PASS.** `create` holds the canonical journal
   lock across the acknowledgement check, digest snapshot, and the nested
   session-locked durable write (coordinator lines 81–91).
2. **Reveal-boundary digest recheck — PASS.** `acceptOpenings` rejects
   with `RETRY_CONFLICT` when the stored digest is null or stale before
   message 2 is decoded or any reveal is constructed; the durable write
   still precedes the return of message 3.
3. **Race closure — PASS.** Create, reveal, and abort append all
   serialize on the canonical journal lock (journal→session nesting).
   Test 9 uses a genuine child-process `FileChannel` lock holder; the
   staging makes the create-gate-before-abort interleaving deterministic
   by construction (the abort contender is submitted only after the
   create thread must already hold the journal lock).
4. **Acknowledged snapshot binding — PASS.** Acknowledged creation binds
   the digest of the nonempty journal; any later append revokes the
   first reveal (Drongo test 2, reference test 2).
5. **Retry/completion usability — PASS.** The exact-retry branch precedes
   the digest gate and returns only the byte-identical cached reveal; a
   changed retry gets `RETRY_CONFLICT` with nothing returned. `complete`
   has no post-reveal digest gate, per the locked design; test 7 covers
   completion after an unrelated later abort.
6. **Narrow rejection classification — PASS.** `isSignerDataRejection`
   is an exhaustive switch matching the design list (8 signer-attributable
   codes true; `WRONG_STAGE`/`RETRY_CONFLICT`/`STATE_INVALID` false; no
   default arm). Journaling happens inside the journal-locked catch
   before rethrow. Host-state reads and validation sit outside the
   classified try blocks, so host faults cannot be relabeled. Sparrow
   applies the same shared predicate at the message-2 and message-4
   boundaries; scan/UR failures remain un-journaled transport
   interruptions.
7. **First-event-wins dedup — PASS.** `LockedJournal.append` returns the
   existing event without a write; the `MAX_EVENTS` check follows the
   dedup check, so idempotent repeats work even on a full journal. Legacy
   duplicates are normalized first-event on load. Byte-stability pinned
   by Drongo test 3 and the updated coordinator test.
8. **Lock order and identity — PASS.** All nested paths are
   journal→session; `getStatus` takes the locks sequentially, not
   nested. Journal paths are canonicalized in the constructor and again
   in `locked` (real parent, real file when present). Symlink-alias test
   8 confirms one identity and one event.
9. **JVM-local registry soundness — PASS.** Reference counts increment
   inside the atomic `compute` before lock acquisition and decrement
   inside `compute` after release; removal occurs only at zero, when no
   holder or waiter can exist. The channel lock closes before the
   finally block, so a fresh lock object after removal cannot meet a
   stale same-JVM file lock — no `OverlappingFileLockException` window,
   no split identity, no leak.
10. **v1 migration split — PASS.** Decode accepts versions 1–2; v1
    yields a null digest. v1 pre-reveal sessions fail closed at the
    reveal gate (test 10); v1 post-reveal sessions keep exact retry and
    completion (test 11); completed v1 evidence revalidates. The test
    downgrade helper produces a genuine v1 encoding (digest blob removed,
    version byte set, trailing checksum recomputed). New writes are
    always v2 with a digest; `acceptOpenings` cannot persist a null
    digest because the gate precedes the write.
11. **Sparrow pin and classification — PASS.** Submodule tree entry at
    Sparrow `9936628` is exactly `0e1d1c3abd71ef5d2bd7c02fdd4d09e0ba56a354`
    (verified via `git ls-tree`). The previous indiscriminate
    journal-on-every-exception in the completion catch is replaced by the
    shared predicate.
12. **No collateral behavior change — PASS.** Reference range is docs,
    the adversarial-model addition, and tests only; no codec or wire
    change. Drongo range is coordinator, journal, durable-files, and
    tests; codec, PSBT reconstruction, provenance, and quarantine are
    untouched. Sparrow range is the signing flow, its test, and the pin.

### Minor notes (non-blocking)

- Message 1 is decoded twice on the reveal path (once inside
  `validateState`, once for the digest gate) — harmless redundancy.
- The reference model permits post-reveal failure recording after
  completion (it has no COMPLETE phase); Drongo refuses with
  `WRONG_STAGE`. Drongo is stricter; the asymmetry is immaterial.
- `#248000` remains correctly untouched; `validateTransition` unchanged.

### Disposition

**Gate 2 approved against the brief's twelve properties.** No false-abort
precedence path, no first-reveal path without a matching digest, no lock
inversion, and no legacy-state path disclosing unbound randomness were
found. Public CI and replacement tested tags remain the remaining gate
per brief §7; Gate 1 heads stay immutable.

---

## Phase 13 — V12 Gate 3 implementation review (2026-08-22)

Inputs: `docs/v12-gate3-implementation-review-brief.md`, the locked design
record `docs/v12-gate3-durable-bounds-design.md`; diffs Reference
`3fabb38..5d2c699` (design doc only), Drongo `0e1d1c3..a3ed65c`
(`ee97f22` durable persistence/bounds/hard-links, `a3ed65c` wire-magic
isolation), Sparrow `9936628..c57b075` (gitlink only, pins exactly
`a3ed65c5dfda9a7a16dabc8b0a206c9beb422eaf`; verified via the range diff).
Drongo working tree was at the Gate 3 head during review; sources read
directly. Test results in brief §4 taken as ledger evidence.

### Twelve-property results

1. **No reveal from a failed durability transition — PASS.** A directory-
   barrier failure invalidates the visible new file before throwing; the
   old inode was already truncated and forced before the move; the write
   precedes any return of message 3, so neither a first nor a cached
   reveal can come from an uncommitted state. Pinned by
   `failedDirectoryBarrierCannotLeaveAReadableUncommittedState`.
2. **Write order — PASS.** Temp content `force(true)` → atomic move →
   parent-directory force is the only successful order, confirmed by the
   injected-barrier observer test (the barrier callback can already read
   the replaced file).
3. **Fail-closed move/barrier — PASS.** `AtomicMoveNotSupportedException`
   and any move `IOException` propagate (temp cleaned in `finally`);
   POSIX directory-force failures rethrow; all surface as `STATE_INVALID`
   at the coordinator boundary. Availability cost is documented.
4. **Bounded reads — PASS.** Size comes from an already-open channel and
   is range-checked before allocation; the read loop reads exactly that
   size and rejects mid-read truncation (`read < 0`) and growth (extra
   byte readable). Sparse-oversize rejection pinned before allocation.
5. **`checkedStateFileLength` exactness — PASS.** Arithmetic verified
   against the v2 AEXS layout: 38-byte fixed header + 7×4 blob lengths +
   2-byte rho count + 32-byte checksum = 100, plus 69 bytes per rho
   record (4 index + 33 key + 32 rho). `encode` self-checks
   `body.length == expected - 32`. Tests pin exact-bound (207 accepted,
   206 rejected) and per-field overflow (16 MiB + 1 signed PSBT).
6. **Write/read limit symmetry — PASS.** Writer per-blob caps equal the
   decoder's `readBlob` caps (`MAX_PSBT_BYTES`, `MAX_MESSAGE_BYTES` ×4,
   `MAX_BLOB_BYTES`, digest ∈ {-1, 32}, rho count 1..`MAX_SLOTS`); both
   reject lengths < 1 for non-null blobs; the total-file cap includes the
   checksum on both sides (`body > maximumBytes - 32` vs channel size >
   `maximumBytes`). Successful write implies reloadability under the same
   limits.
7. **Over-limit completion fails before replacement — PASS.**
   `checkedStateFileLength` runs at the top of `encode`, before any
   filesystem touch; the failure propagates as `STATE_INVALID` and the
   prior `OPENINGS_ACCEPTED` file is never opened for writing. Pinned by
   `overLimitReplacementPreservesPriorValidState`.
8. **Global JVM lock ordering — PASS.** `JVM_DURABLE_LOCK` is a fair,
   reentrant, always-outermost serializer; Gate 2's journal→session
   nesting re-enters it legally, and no lock is ever acquired before it,
   so inversion is structurally impossible and same-thread nesting cannot
   deadlock. The Gate 2 per-path registry is retained beneath it; the
   `OverlappingFileLockException` catch remains as fail-closed defense.
9. **Cross-process alias serialization — PASS (POSIX).** Canonical and
   symlink aliases converge on one pathname `.lock` via `canonicalPath`;
   hard links, which have no canonical name, converge on the
   underlying-inode `FileChannel` lock when the file exists. The
   not-yet-existing create window fails closed for the loser via
   `createOnly`. Verified by the child-process `LockHolder` test.
10. **Detached-alias invalidation — PASS.** `invalidate` truncates and
    forces the old inode before `REPLACE_EXISTING`, while POSIX still
    holds its underlying lock; a detached hard link reads a zero-byte
    file and fails the minimum-size check. Pinned by the alias test's
    post-replacement read assertions.
11. **Windows hard-link residual — PASS (accurate, contained, not
    overclaimed).** Windows retains file forcing, atomic replacement,
    the JVM serializer, and stale-inode invalidation; it skips the
    underlying-file lock because the OS forbids atomically replacing a
    target while this process holds its `FileChannel` lock — the code
    comment states exactly this. The cross-process POSIX test is
    `assumeFalse(isWindows())`-skipped (the 1 skip in the focused run),
    not silently green. The residual stays inside the existing
    trusted-filesystem assumption in both the design doc and the code.
12. **Immutable wire framing — PASS.** `encode`/`decode` use the private
    `WIRE_MAGIC`; the public `MAGIC` is a deprecated clone. The mutation
    test flips a public byte and pins frozen-vector decode and emitted
    framing, restoring the byte in `finally`. No production code (Drongo
    or Sparrow) references `AntiExfilCodec.MAGIC`.

### Minor notes (non-blocking)

- POSIX TOCTOU between `Files.exists(canonical)` and the underlying-file
  open could let a pathname-swapping attacker desynchronize the inode
  lock; such an actor is already inside the trusted-filesystem boundary.
- The reference range adds only the design record; no reference model or
  fixture changes were needed for this gate.

### Disposition

**Gate 3 approved against the brief's twelve properties.** No unchecked
exception path, limit mismatch, lock-order cycle, successful return
before the durability barrier, or surviving-alias path was found. Per
brief §5, public Linux CI must still execute the non-skipped POSIX
parent-directory and cross-process hard-link tests before any new tested
tag is created; Gates 1–2 heads and tags remain immutable.

---

## Phase 14 — V12 Gate 4 implementation review (2026-08-22)

Inputs: `docs/v12-gate4-implementation-review-brief.md`, the locked design
record `docs/v12-gate4-api-contracts-design.md`; diffs Reference
`5d2c699..23b8603` (design doc only), Drongo `a3ed65c..6b9eec6` (9 files,
+98/-17), Sparrow `c57b075..f130d58` (gitlink + one test). Both Drongo
and Sparrow working trees were at their Gate 4 heads; sources read
directly. Pin verified via `git ls-tree`: Sparrow `f130d58` carries
`drongo = 6b9eec662931a1c387d75e21c1e58806d20e9d6e` exactly. Test results
in the brief's validation-evidence section taken as ledger evidence.

### Twelve-property results

1. **Complete transcript — PASS.** `reconstructSignedPsbt` has exactly
   one production signature (original, keystore, commit, openings,
   reveal, signatures, hostRandomness); grep confirms no compatibility
   overload in Drongo and zero Sparrow references. All three coordinator
   call sites (`complete`, `deriveVerifiedSignatures`, `validateState`)
   pass the full durable transcript.
2. **Opening fixation — PASS.** The full `1→2→3→4` chain runs through
   `validateTransition` three times; opening byte-identity is enforced
   from stage 2 onward (`OPENING_MISMATCH`). The new PsbtTest case swaps
   slot 0's opening for slot 1's with otherwise valid later messages and
   expects `OPENING_MISMATCH` before reconstruction.
3. **Durable-rho authority — PASS.** The durable map keyset must equal
   the authoritative slot identifiers; per slot, rho must equal both the
   durable entry and the reveal value, and `hostCommit(rho)` must equal
   the stage-1 commitment. Caller-supplied transcript data cannot
   substitute for durable randomness.
4. **Authoritative semantics — PASS.** Commit `psbtDigest` must equal
   SHA-256 of the original PSBT; `requireSlot` binds input index,
   sighash, signer key, and message hash to the canonical PSBT semantics
   at stages 1 and 4. No provenance/finalization files changed, so
   foreign ordinary multisig signatures remain preserved and proof-less.
5. **Endpoint validation — PASS.** `validateTransition` calls full
   `validate(previous)` then `validate(current)` before adjacency and
   continuity checks. `validate(null)` and structurally malformed
   endpoints produce controlled `INVALID_MESSAGE` failures (null-guarded
   header check), never unchecked exceptions. CodecTest pins malformed-
   previous, malformed-current, null, and valid cases.
6. **Production coverage — PASS.** Grep over Drongo production shows
   reconstruction is reachable only from the three coordinator paths,
   each decoding all four durable messages. No unvalidated reconstruction
   ingress remains.
7. **Admission — PASS.** Both public `create` overloads delegate to the
   single core overload, which rejects `!supportsAntiExfil()` with
   `STATE_INVALID` before randomness generation or any filesystem write.
   CoordinatorTest pins UNSUPPORTED rejection (and absence of the session
   file) plus OPTIONAL/REQUIRED admission.
8. **Migration boundary — PASS.** `load` is untouched: it revalidates the
   durable session in full but does not consult current policy metadata,
   preserving completed historical evidence after a policy downgrade
   (pinned by the new admission/reload test). No new ceremony can be
   created or re-created under UNSUPPORTED because every creation path
   rejects first. Nuance within the documented boundary: a pre-reveal
   session created by pre-Gate-4 code under an UNSUPPORTED policy can
   still advance via `load` + `acceptOpenings`; that is the deliberate
   "historical evidence" carve-out, not a new admission path through the
   corrected API.
9. **Evidence authority — PASS.** The `VerifiedAntiExfilSignature`
   constructor is package-private; the class is not `Serializable` and
   exposes no factory, builder, or deserializer. Minting occurs only in
   `deriveVerifiedSignatures`, after `reconstructSignedPsbt` (which
   cryptographically verifies every signature against durable rhos and
   stage-1 commitments) and byte-equality with the stored signed PSBT.
   A reflection assertion pins zero public constructors.
10. **Value semantics — PASS.** Defensive copies in constructor and
    accessors, field-wise `equals`/`hashCode` — all unchanged by this
    diff; completion, exact retry, and reload derive from the same
    durable bytes, and the identical-evidence test remains green.
11. **Sparrow integration — PASS.** The mixed REQUIRED/OPTIONAL
    regression now mints `proofA` through a real deterministic coordinator
    (`create` → `acceptOpenings(message_2)` → `complete(message_4)`)
    from the frozen mixed-provenance vector, asserts the minted compact
    signature equals the frozen `protected_signature_a_compact` bytes,
    and retains the policy outcome that protected signer A does not bless
    ordinary signer B.
12. **No scope expansion — PASS.** Range stats confirm: no AEXB wire,
    frozen-vector, AEXS format/version, abort-state-machine, provenance,
    quarantine, finalization, broadcast, reference-oracle, or SeedSigner
    changes. Test fixtures only gained explicit policy metadata.

### Reviewer questions

1. No — one reconstruction signature; every caller supplies the durable
   four-message transcript.
2. No — endpoint validation only adds earlier controlled failures.
   Coordinator paths pre-validate host-side messages (via
   `validateState`), so newly-early endpoint failures on the classified
   paths are attributable to signer-supplied bytes and journal correctly;
   revalidation paths still surface `STATE_INVALID`.
3. No — all creation funnels through the rejecting core overload; retries
   and `load` operate only on already-durable sessions.
4. Yes — with the legacy pre-reveal nuance noted in property 8; full
   durable revalidation keeps `load` from minting unverified evidence.
5. No — package-private constructor, reflection-pinned, no serialization
   or public-factory surface in Drongo or Sparrow.
6. Yes — the proof is minted from the frozen vector through a real
   completion and pinned to the frozen protected-signature bytes.
7. Yes — the pin matches exactly; no missing callers or tests identified.

### Disposition

**Gate 4 approved against the brief's twelve properties and all seven
reviewer questions.** Per the hold point, Gate 4 tested tags remain held
until public Linux CI is green; Gate 3 tags stay immutable. All V12 gates
1–4 have now passed independent review; remaining dispositions
(247987/247988/247990/247996/247997) belong to Gate 5.

---

## Phase 15 — V12 Gate 5 implementation review (2026-08-22)

Inputs: `docs/v12-gate5-implementation-review-brief.md`, the locked
disposition record `docs/v12-gate5-trust-contracts-design.md`; diffs
Reference `92ab573..f2dc199` (docs only: design record, threat-model
§6.7/§6.8 + INV-17/INV-18, maintainer decision 15), Drongo
`6b9eec6..bb691c7` (3 files, +58/-1), Sparrow `f130d58..f003bfa`
(gitlink only, pins exactly `bb691c7d77290933b3f7d6c411556c1524a29d98`;
verified via the range diff). Drongo working tree at the Gate 5 head;
sources read directly. Test results in the brief taken as ledger evidence.

### Twelve-property results

1. **Early foreign-signature rejection — PASS.** `parseCanonicalV0` is
   the sole canonical ingress: `enumerateSigningSlots` calls it first,
   and `create` checks policy, then enumerates slots, before any
   randomness generation or AEXS/AEXJ write. The new MixedProvenanceTest
   case doctors the frozen vector's foreign partial to `(r=1, s=1)` and
   asserts `INVALID_MESSAGE` from `create` with neither session nor
   journal file existing.
2. **Controlled failure — PASS.** `new PSBT(raw, true)` routes through
   Drongo's existing `verifySignatures`, which throws
   `PSBTSignatureException` for unverifiable partials;
   `parseCanonicalV0` catches `PSBTParseException | RuntimeException` and
   wraps them as `INVALID_MESSAGE` (rethrowing `AntiExfilException`
   as-is). No unchecked exception escapes; no partial state persists.
3. **Valid multisig compatibility — PASS.** The unchanged mixed-provenance
   byte-preservation assertions remain green against the same frozen
   vector; verification accepts the valid foreign ordinary partial via
   the supplied UTXO context.
4. **Proof isolation — PASS.** Reconstruction and `deriveVerifiedSignatures`
   iterate only authoritative ceremony slots; the foreign partial is
   preserved in the output PSBT but receives no evidence. Gate 4's
   package-private minting remains the only evidence source.
5. **Supported-input compatibility — PASS.** Witness-only SegWit inputs
   verify against `witness_utxo`; the frozen positive vectors stay
   byte-identical and the focused suites green. Documented edge: a
   foreign partial that is *unverifiable because its UTXO context is
   absent* is also rejected — fail-closed and consistent with the
   design's "validity against the supplied signing context" criterion.
6. **Rollback honesty — PASS.** Threat-model §6.7 and the design record
   state checksums detect corruption only and that no same-domain file
   (tombstone, second ledger, random journal identifier) provides
   freshness against joint rollback; a stronger guarantee is explicitly
   deferred to a separately trusted monotonic authority. No partial
   mechanism is represented as complete.
7. **Recovery safety — PASS.** Missing, restored, or reset state is
   documented as not evidence of safety; the response is to stop
   protected signing and migrate funds to a wallet generated from fresh
   independent keys. Backups must not restore session or journal state
   independently. Consistent across the design record, threat model, and
   maintainer decision 15.
8. **Storage honesty — PASS.** POSIX owner-restricted permissions and
   effective inherited Windows DACL dependence are stated; encryption at
   rest is explicitly not claimed, and owner-equivalent/administrator/
   backup exposure is acknowledged rather than papered over.
9. **Witness-only boundary — PASS.** PsbtTest pins that mutating the
   supplied witness amount changes the authoritative BIP143 message hash
   while the unsigned-transaction outpoint stays fixed; §6.8 correctly
   states false context yields a signature invalid for the actual coin
   rather than authorization of a different real prevout, and that
   evidence attests to the supplied context, not chain-state existence.
10. **Standards compatibility — PASS.** The design record's rationale
    (animated-QR payload size and standard hardware-wallet workflows) is
    coherent; non-witness-UTXO consistency checks remain in force when
    present. Retention is an explicit maintainer decision, not silence.
11. **No format expansion — PASS.** No AEXB/AEXS/AEXJ, frozen-vector, or
    SeedSigner wire changes in any range (stat-verified; reference range
    is docs-only, Sparrow is gitlink-only).
12. **No unrelated weakening — PASS.** Only `parseCanonicalV0` changed in
    Drongo production; Gates 1–4 surfaces, provenance, quarantine,
    finalization, and broadcast paths are untouched.

### Reviewer questions

1. Yes — every coordinator ingress (create overloads, reload,
   revalidation, reconstruction) reaches `parseCanonicalV0` with
   verification enabled; pre-fix sessions bearing invalid foreign
   partials now fail closed on load, which is the intended consequence
   since their output was unusable downstream anyway.
2. No — invalid partials fail at parse, before slots, randomness, or
   durable state.
3. Yes — the existing Drongo verifier handles all legitimate forms with
   supplied context; proof attribution remains strictly ceremony-derived.
   (See the missing-context edge noted in property 5.)
4. No — the design correctly argues same-domain mechanisms cannot provide
   freshness against joint rollback and would overstate the guarantee.
5. Yes — stop-and-fresh-key migration is the right substantive control;
   the backup/restore atomicity guidance covers the operational step.
6. Yes — accurate and non-exaggerated.
7. Yes — the BIP143 commitment analysis is correct.
8. Yes — mandatory full previous transactions would materially break
   QR-constrained and standard hardware-wallet workflows; retention is
   explicit and coherent.
9. Yes — the pin is exact and no file outside the stated surface changed.

### Disposition

**Gate 5 approved against the brief's twelve properties and all nine
reviewer questions.** Both review burdens are satisfied: the `#247996`
preventive fix is minimal, correctly placed at the sole canonical
boundary, and regression-pinned; the four dispositions follow from the
pinned implementation and threat model without overstating any guarantee.
Per the hold point, replacement tested tags and the reviewer-bundle
freeze remain gated on public Linux CI. This completes independent review
of all V12 findings (`#247986`–`#248002`).
