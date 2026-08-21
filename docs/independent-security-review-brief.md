# Independent security and cryptographic review brief

Status: frozen reviewed prototype inputs

Protocol: experimental interactive ECDSA anti-exfil v1 (`AEXB-v1-multislot`)

Security claim: when the coordinator is honest and supplies unpredictable host
randomness after accepting the signer's opening, an accepted ECDSA signature
must be bound to the frozen transaction/signing context and to the committed
base public nonce. The implementation is intended to fail closed on malformed,
unsupported, substituted, replayed, downgraded, or incomplete ceremonies.

This prototype has extensive automated and physical interoperability evidence.
It has not received an independent cryptographic or production security audit.

## 1. Requested outcome

The reviewer is asked to determine whether the construction, wire protocol,
state machines, and four implementations substantiate the stated claim and
failure behavior. Findings should identify:

- exploitable violations of confidentiality, key safety, transcript integrity,
  or fail-closed policy;
- construction or compatibility errors relative to the pinned
  `secp256k1-zkp` ECDSA sign-to-contract implementation;
- ambiguous normative language or divergent parser behavior;
- denial-of-service or resource-exhaustion weaknesses at trust boundaries;
- unsafe persistence, retry, cancellation, or downgrade behavior;
- tests needed to prevent regression; and
- residual risks that must be disclosed even if no code change is required.

For each finding, please provide affected component/commit, prerequisites,
impact, reproduction or counterexample where possible, and recommended
remediation. A final report should distinguish protocol defects,
implementation defects, hardening recommendations, and accepted residual risk.

## 2. Immutable implementation inputs

| Component | Public repository | Branch/tag | Reviewed commit |
| --- | --- | --- | --- |
| Drongo | `https://github.com/FractalEncrypt/drongo` | `anti-exfil-review-v1-tested-2026-08-20` | `1bbafd94f08fd9105e20be30a6fdfe9a091fb675` |
| Sparrow | `https://github.com/FractalEncrypt/sparrow` | `anti-exfil-review-v1-tested-2026-08-20` | `7674cecde48335e0b55454f6fa53c8187a459932` |
| SeedSigner | `https://github.com/FractalEncrypt/FractalEncrypt_seedsigner` | `anti-exfil-review-v1` / `anti-exfil-review-v1-tested-2026-08-14` | `aa8395e3576379467d795bb05268533e3a2ac082` |
| SeedSignerOS | `https://github.com/FractalEncrypt/seedsigner-os` | `anti-exfil-review-v1` / `anti-exfil-review-v1-tested-2026-08-12` | `0bf1dc92519906c7db265055abfb07e0ee344342` |

SeedSignerOS pins Buildroot
`bf2a2858aa675a14b60f1f9142c65b32652609c1`. Its native package pins
`BlockstreamResearch/secp256k1-zkp` commit
`2af926dc309a673461f0e2da090105c8f05b4505` with source-archive SHA-256
`40e0858f5f189a078f2aeee10e1fc0e732f73abb7bc9f8745c63dac3f8d8d4e5`.

The reference oracle, generators, tests, normative documents, completed review
ledger, and physical
evidence are supplied as a private review bundle described in
`review-bundle-manifest.md`. Publication of the engineering workspace is not a
prerequisite for review.

Exact clone, dependency, focused/full test, package, OS-image build, and short
physical-smoke commands are in `reviewer-build-and-test-runbook.md`.

## 3. Normative reading order

1. `maintainer-specification.md` — claim boundary and integration contract.
2. `protocol-v1.md` — pinned ECDSA sign-to-contract construction.
3. `protocol-v1-wire-format.md` — canonical multi-slot records and state rules.
4. `transport-aext.md` — AEXT/UR framing and QR-stage invariants.
5. `threat-model.md` — adversaries, attacks, invariants, and residual risks.
6. `shared-vector-index.md` and the two canonical JSON vectors.
7. The implementation commits above and their focused tests.
8. `physical-evidence-index.md` for integration evidence, not proof of
   cryptographic correctness.

Historical single-slot fixtures are explicitly non-normative.

## 4. Cryptographic construction review

### 4.1 Pinned S2C compatibility

Confirm by code tracing and differential tests that the Python/Java verification
and SeedSigner native signing paths implement the exact pinned
`secp256k1-zkp` construction, including:

- tagged hashes and serialization;
- host commitment construction and verification;
- RFC6979 inputs, additional data, counters, and rare retry behavior;
- tweak scalar calculation and zero/overflow handling;
- `R0`, `R = R0 + tG`, parity/point encoding, and infinity rejection;
- compact versus DER signature conversion and low-S normalization; and
- verification that the signature's public nonce is consistent with the
  accepted opening and host reveal.

Derive at least one canonical transcript independently rather than trusting the
reference generator. Compare every intermediate scalar/point/byte string with
the pinned native library.

### 4.2 Nonce and secret lifetime

Review deterministic base-nonce uniqueness across message, private key, host
commitment, slot, retry, and session contexts. Look for any path that can:

- reuse one base nonce with two accepted host reveals;
- expose nonce scalars through Python objects, logs, exceptions, crash output,
  returned metadata, or persistence;
- retain secret nonce material beyond the native signing call;
- bypass the native primitive or invoke an ordinary signing backend; or
- produce a signature after partial semantic failure.

Assess native context allocation/destruction, error paths, FFI length checks,
temporary buffers, zeroization limitations, and compiler/runtime assumptions.

### 4.3 Adversarial nonce strategies

Attempt predetermined-nonce, low-entropy/Dark-Skippy, nonce-grinding, and
post-reveal selective-abort strategies. Determine what leakage is prevented,
what remains possible through repeated aborts, and whether the warning/journal
model accurately bounds or merely detects that residual channel.

## 5. Transcript and semantic binding review

Verify that every accepted signature is unambiguously bound to:

- protocol and transport version;
- network code;
- session identifier;
- exact frozen PSBT bytes/digest;
- input index, outpoint, amount, script form, and BIP143 message hash;
- sighash type;
- signer fingerprint, derivation, and compressed public key;
- canonical slot ordering and complete slot set;
- host commitment, signer opening, and host reveal; and
- expected stage and direction.

Search for cross-input, cross-key, cross-session, cross-network, replay,
reordering, duplicate-slot, truncation, trailing-data, alternate-encoding, and
unknown-field acceptance. Confirm the complete request fails atomically and
produces zero new openings/signatures when any slot is invalid or unsupported.

Review authoritative PSBT-v0 slot enumeration and real BIP143 sighash
construction for native/nested P2WPKH and native/nested standard P2WSH
multisig. Confirm legacy, future witness, nonstandard scripts, unsupported
sighashes, Taproot, and mixed sets fail closed.

## 6. Cross-implementation parser differential

Treat Python, SeedSigner Python, Drongo Java, and Sparrow transport/UI parsing
as independent attack surfaces. Use mutation, fuzzing, and property-based tests
to find inputs accepted differently, especially:

- integer widths, signedness, overflow, and length arithmetic;
- canonical compressed points, compact/DER signatures, and low-S rules;
- CBOR byte-string lengths and UR type/case handling;
- duplicate records, ordering, flags, reserved bytes, and trailing bytes;
- PSBT maps, duplicate keys, UTXO precedence, derivations, scripts, and unknown
  metadata;
- empty/maximum slot counts and oversized QR/package input; and
- stale fountain fragments or mixed animated-QR sessions.

The reviewer should record an explicit acceptance matrix and add any discovered
case to every affected implementation's shared regression corpus.

## 7. Durable coordinator and selective-abort review

Audit Sparrow/Drongo session state from creation through completion,
cancellation, crash, retry, abandonment, and deletion. Verify:

- the OS CSPRNG is used for session IDs and host randomness;
- state is durably committed before message 3 is revealed;
- a post-reveal retry reproduces byte-identical message 3;
- transaction mutation, fee bumping, key substitution, subset retry, or fresh
  randomness cannot masquerade as retry;
- accepted openings cannot be silently replaced;
- power loss and atomic-write failure are fail closed;
- completed/abandoned sessions cannot be replayed as live;
- selective-abort history is attributed to the correct wallet key, survives
  restart, and cannot be silently reset through device-brand changes; and
- concurrency or two Sparrow processes cannot race one session.

Assess filesystem permissions, path traversal/symlink risks, checksums versus
authenticity, rollback/tampering, backup leakage, retention, and deletion. Make
a recommendation on encryption at rest and the minimum metadata needed for
safe retry and abort history. This decision should precede final session
inspection/deletion UX.

## 8. Reconstruction and downgrade boundaries

Confirm Sparrow reconstructs the result only from its frozen original PSBT plus
verified signatures for the exact authoritative slots. Returned PSBT metadata,
unknown maps, altered transaction fields, or unrelated signatures must not be
copied from an untrusted signer response.

For `REQUIRED` keystores, test every ordinary-signature ingress path: camera,
file load, copy/import, multisig partial combination, saved transaction reopen,
and any alternate signer UI. An ordinary or unattributable signature must be
rejected before acceptance, finalization, or broadcast. Confirm policy cannot
be silently lost through database migration, JSON import/export, wallet copy,
keystore replacement, device-brand changes, or downgrade to an older build.

Review mixed `UNSUPPORTED`/`OPTIONAL`/`REQUIRED` multisig behavior and ensure
signature attribution cannot be stripped or reassigned.

## 9. SeedSigner and SeedSignerOS review

Verify semantic preflight occurs before stock transaction-review parsing and
that failures never escape into partial signing or generic parser paths.
Confirm stateless message-3 recovery requires exact PSBT/transcript replay and
that direct continuation retains only the selected seed identity, not secret
nonce/session state.

Audit the native library's isolated path and required-symbol loading, ARMv6
artifact checks, Buildroot source/license hashes, enabled module set, and
absence of fallback. Confirm normal images exclude both test init services and
instrumented images execute them only after the OS-owned SD mount exists.

## 10. Validation expected from the reviewer

At minimum:

- independently regenerate or verify both canonical vectors;
- run all four implementations' focused and complete applicable suites;
- run malformed and adversarial corpora under sanitizers/fuzzers where useful;
- add parser differential/property tests;
- inspect at least one real native/nested P2WPKH and P2WSH multisig transcript;
- exercise exact retry, power-loss boundaries, ordinary-signature downgrade,
  and returned-metadata injection; and
- reproduce the normal/test SeedSignerOS boundary from the immutable tags.

Physical funded transactions already demonstrate interoperability; reviewers
need not spend funds or broadcast transactions unless they independently find
that useful.

## 11. Explicit non-goals and residual scope

Version 1 does not claim to protect:

- Taproot/Schnorr signatures;
- false transaction details displayed by malicious firmware;
- non-signature covert channels or physical side channels;
- denial of service;
- a coordinator compromised after successful verification; or
- both endpoints colluding.

PSBT v2, protocol-version negotiation beyond strict v1 rejection, formal UR
registration, other hardware signers, and production release engineering are
future work. No unsupported case may silently fall back to ordinary signing.

## 12. Review closure

The signature-scoped provenance remediation and the R-F1 raw-transaction
lifecycle correction received focused diff review through Sparrow `7674cec`
and Drongo `1bbafd94`; the completed ledger is included as
`security-review-findings.md`. Future findings must be fixed on new commits
without moving these immutable tested tags. A production or mainnet
recommendation still requires explicit reviewer sign-off; this completed
prototype review is not a production security audit.
