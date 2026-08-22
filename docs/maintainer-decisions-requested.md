# Maintainer decisions requested — post-review summary

Companion to `maintainer-review-index.md` (decisions 1–7) and
`security-review-findings.md` (finding IDs referenced throughout). Each entry
states the decision, the review evidence, and the reviewer's recommendation.
No decision below permits silent fallback to ordinary signing.

## Carry-over decisions from the review brief (1–7) with review evidence

1. **Native S2C construction as the v1 compatibility target; binding location
   upstream.** Evidence: Phase 1 verified tagged hashes, RFC6979 nonce, S2C
   tweak, and low-S normalization line-by-line against the pinned
   secp256k1-zkp sources, with native/reference output equality tested
   (P1-V1..V4, P8-V2). Open residual: oracle parity nits (P1-F1, P1-F2) and
   one uncleared upstream stack scalar (P2-F5) for the upstreaming
   discussion. Recommendation: accept as v1 target; fix oracle parity before
   using the reference as the sole conformance oracle.
2. **`ur:x-btc-anti-exfil` registry coordination.** Evidence: UR2 transport
   round-trips byte-identically under reordering across SeedSigner and
   Sparrow decoders (P3/P4 verified items); fountain differential not
   exhaustively fuzzed (P4-F3). Recommendation: remain explicitly
   experimental through review; coordinate registry after the parser
   hardening items land.
3. **PSBT v0 + SIGHASH_ALL + four SegWit-v0 script forms as first-release
   scope.** Evidence: fail-closed matrix verified on reference, SeedSigner,
   and Drongo (P3); adversarial corpora green (P8-V4). Open scope question:
   unknown PSBT input fields (decision 9 below). Recommendation: scope is
   appropriately narrow.
4. **Selective-abort thresholds and fund-migration language.** Evidence:
   coordinator retry/abort semantics verified (P5); signer UX blocks
   post-opening retries and warns on session history (P5, P7-V5). Decision
   stands with maintainer; no blocking finding.
5. **Encryption at rest for durable coordinator sessions.** Evidence:
   P2-F3/P5-F1 — unrevealed rho is plaintext at rest in both the reference
   and production coordinators; integrity without authenticity is noted
   (P5-F2); journal locality limits (P5-F3). Recommendation: acceptable for
   first review under the stated threat model (coordinator filesystem in the
   trusted base); revisit before any session-inspection/deletion UX ships.
6. **Per-keystore capability storage vs import-format advertisement.**
   Evidence: policy persistence/migration verified (P6-V2..V4); REQUIRED
   enforcement gaps found (P6-F1; first patch draft withdrawn — P6-F1a,
   redesign per decision 8).
   Recommendation: keep per-keystore storage; do not trust imported policy
   claims without user confirmation.
7. **Taproot as a separate reviewed protocol version.** Evidence: Taproot
   rejected fail-closed at every layer in v1 (P3 matrix). Recommendation:
   separate protocol version; do not extend AEXB v1.

## New decisions arising from this review

8. **Adopt a signature-scoped P6-F1 fix (medium defect, scope widened after
   independent re-review).**
   Evidence: P6-F1 — REQUIRED was enforced only on the signing-screen
   scan-back path; top-level paste/QR/file ingest with null context, USB/card
   combine, scanned-seed software signing, and broadcast were ungated; and
   the `antiExfilVerified=true` short-circuit is transaction-wide, so a
   verified ceremony output can carry another REQUIRED keystore's ordinary
   signature (Drongo rejects pre-existing signatures only for the selected
   ceremony keystore and preserves the rest — AntiExfilPsbt.java:78–86,
   154–177). The first patch draft
   (`docs/p6-f1-sparrow-required-policy-fix.patch`) is **withdrawn** (P6-F1a):
   malformed, untested, and its boolean provenance design perpetuates the
   transaction-wide flaw. Required shape: signature-scoped provenance
   (exact verified slots: input index, pubkey/keystore identity, sighash
   context, signature bytes) carried by the ceremony event, matched
   per-signature at every gate, granted only after a successful verified
   merge, invalidated on mutation/merge/finalization/reopen, recomputed at
   broadcast; software-signing guard in the common path. Expanded regression
   suite required: mixed-provenance multisig, failed-merge provenance,
   mutation/reopen invalidation, cross-window results, metadata-stripped
   returns, doctored REQUIRED software keystore via the normal decrypted
   path, and a verified ceremony output with no extra REQUIRED signature
   remaining permitted. No new tested tag until these pass.
   Recommendation: adopt the redesign; this is the only medium-severity
   finding in the review.
9. **Exclude unknown non-proprietary PSBT fields from strict v1.** Evidence:
   P4-F1 — Python/embit preserves unknown input maps and proceeds; Drongo
   logs and drops them. Recommendation: adopt an explicit byte-level
   allowlist at global, input, and output map levels for the BIP174/BIP371
   fields needed by the four supported script forms plus recognized
   proprietary namespaces. Reject all other non-proprietary keys consistently
   in the reference, SeedSigner, and Drongo. This is deferred to the separate
   hardening track because it changes the pinned reconstruction fixture and
   frozen vector hashes.
10. **Confirm signer-side testnet-family network matching.** Evidence:
    P7-F2 — a device set to "testnet" accepts wire networks
    TESTNET3/TESTNET4/SIGNET; the coordinator binds exactly. No mainnet
    crossover is possible. Recommendation: confirm deliberate and document
    in the protocol notes, or tighten to exact match.
11. **Oracle/tooling hygiene batch (low, test-only).** Evidence: P1-F1
    (tweak-zero retry-vs-fail divergence), P1-F2 (oracle accepts high-S,
    native rejects), P2-F2 (reference binding does not zeroize), P2-F4 (no
    `__del__` context fallback), P1-F3 (deprecated context flags).
    Recommendation: fix P1-F1 and enforce low-S at `verify_anti_exfil` before
    the oracle gates future vectors; use copy-and-memset only as best-effort
    FFI hardening because it cannot clear the caller's original immutable
    Python `bytes`; prefer idempotent `close()` plus `weakref.finalize` over
    `__del__`; remainder optional.
12. **REQUIRED policy UI guard on unsupported models.** Evidence: P6-F2 —
    REQUIRED is settable on any airgapped keystore model, bricking spend
    paths for devices without ceremony support (self-inflicted). P6-F3
    (hand-edited stores) is out of model and resolved by decision 8.
    Recommendation: restrict REQUIRED to models with known protocol support.
13. **Fail-fast native-backend probe on SeedSigner (low).** Evidence: P7-F1 —
    a missing/broken library fails closed but only at signing time, after
    review and seed selection. Recommendation: probe backend construction at
    scan time; optional hardening, no security defect.
14. **Shared negative-vector additions.** Evidence: P3-F1 (`x >= p` point
    rejection has no pinned cross-implementation negative vector), P4-F2
    (Java negative codec corpus thinner than Python's). Recommendation:
    add the differential negative vectors to the shared corpus and port the
    §10 mutation list into `AntiExfilCodecTest` — mechanical, high value for
    upstreaming.
15. **V12 Gate 5 trusted-storage and PSBT compatibility dispositions.**
    Evidence: `#247987` and `#247988` correctly demonstrate that authentic
    coordinator state and abort history can be rolled back or erased, but the
    actor controls the decision-5 trusted filesystem and no same-domain file
    can provide monotonic freshness. `#247990` correctly notes plaintext rho
    and inherited Windows ACLs; supported deployment therefore requires an
    owner-restricted state directory and does not claim encryption at rest.
    `#247996` identifies a preventable availability defect: invalid foreign
    partial signatures could survive a protected ceremony even though valid
    foreign multisig partials must be preserved. Drongo now verifies every
    existing partial at canonical anti-exfil ingestion. `#247997` is the
    standard BIP174 witness-only trust boundary: supplied amount/script are
    committed by BIP143 but cannot be authenticated to the outpoint without a
    full previous transaction or external history. Recommendation: accept the
    rollback/ACL/witness-only residuals with the recovery and deployment
    contract in `v12-gate5-trust-contracts-design.md`; retain QR-compatible
    witness-only inputs; reject invalid foreign partials before session
    creation; revisit external monotonic storage and encryption/ACL provisioning
    only as separately designed features.

## Disposition summary

- **Blocking before wider release:** decision 8 (medium defect fix).
- **Spec/documentation decisions:** 2, 3, 9, 10.
- **Hardening batches (can be scheduled):** 11, 12, 13, 14.
- **Trusted-storage/PSBT compatibility contract:** 15.
- **Already accepted as residual risk under the stated threat model:**
  P2-F1 (Python-side secret retention during ceremony), P2-F3/P5-F1
  (plaintext rho at rest, pending decision 5), P5-F2/P5-F3.

Validation posture at time of writing (corrected after independent
re-review): vectors regenerate byte-identical; 82/82 reference tests pass
against the tagged SeedSigner source via `SEEDSIGNER_SRC` (0 skips); the
run without the variable exercised an unpinned local fallback clone and is
not standalone evidence (P8-V3); 8/8 adversarial tests pass; Drongo,
Sparrow, and SeedSignerOS gates were previously executed and are relied
upon from checkpoints — they were not rerun in Phase 8 (P8-V5).
