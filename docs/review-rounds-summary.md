# Security review rounds and remediation history

Date: 2026-08-22

This document summarizes the distinct review rounds applied to the experimental
anti-exfil v1 project. It is an index, not a substitute for the complete
evidence in `security-review-findings.md`, the implementation-review briefs, or
the immutable source ranges.

## Round 1 — owner-directed Kimi K3 / Cascade review

Scope: protocol construction, reference model, Drongo, Sparrow, SeedSigner,
SeedSignerOS, shared vectors, state machines, policy enforcement, and physical
integration evidence through the 2026-08-20 tested inputs.

Material findings:

- **P6-F1 (medium):** transaction-wide authorization and incomplete secondary
  route enforcement could let one protected signer's ceremony bless another
  REQUIRED signer's ordinary signature. The first approximate patch was
  withdrawn. The accepted redesign moved immutable, per-signature proof records
  into Drongo and applied proof-aware gates to every Sparrow ingest, combine,
  signing, finalization, reopen, cross-window, and broadcast route.
- **R-F1 (low functional regression):** an over-broad raw-transaction
  quarantine broke legitimate internal sweeps and lacked a safe lift path. The
  final design requires positive wallet attribution, preserves REQUIRED
  precedence, and grants only a local, ephemeral, digest-bound internal-sweep
  exemption.
- Lower-severity construction, native-binding, parser, storage, model-policy,
  and documentation observations were either corrected, explicitly deferred,
  or recorded as residual risks and maintainer decisions.

Validation included source-range review, focused and complete automated suites,
cross-implementation tests, public Linux CI, deterministic fixtures, packaged
Sparrow tests, Pi Zero image gates, and physical Testnet4 workflows. The review
explicitly did not claim to replace independent cryptographic or production
release review.

## Round 2 — V12 automated audit plus independent triage

Audited input: Drongo `1bbafd94f08fd9105e20be30a6fdfe9a091fb675`.
V12 returned 22 top-level candidates. No V12 patch or weaponized proof of
concept was accepted directly; each credible claim was independently traced,
converted into a safe invariant regression, implemented by the maintainers,
and reviewed as a separate gate.

- **Gate 1 — #247985:** repeated signer opening points for the same key across
  slots could expose the signing key. This critical cross-slot invariant was
  confirmed and fixed in the reference and Drongo before any host randomness
  is returned. A shared host-side negative vector was added.
- **Gate 2 — #247989, #247992, #248004, #248006:** reveal-boundary abort
  revocation, signer-data rejection journaling, idempotent abort recording, and
  atomic journal/session locking were implemented as one state-machine change.
- **Gate 3 — durability/resource/concurrency cluster:** bounded reads and state
  sizes, persistence barriers, path-alias and hard-link handling, lock ordering,
  and immutable wire framing were hardened. Platform-specific residuals remain
  documented.
- **Gate 4 — #247995, #248000, #248001, #248002:** complete-transcript
  reconstruction, endpoint validation, supported-policy admission, and
  coordinator-only proof minting closed API-contract gaps.
- **Gate 5 — #247987, #247988, #247990, #247996, #247997:** invalid foreign
  partial signatures now fail before coordinator state exists. Rollback,
  journal loss, Windows plaintext-storage/ACL dependence, and witness-only UTXO
  behavior received explicit threat-model and recovery dispositions rather than
  overstated same-domain mitigations.

Every gate received an independent static range review. Final Drongo
`bb691c7d77290933b3f7d6c411556c1524a29d98` and Sparrow
`f003bfa9575bc7c67b337f8785b1479fd092641a` passed public Linux CI and were
protected by new immutable Gate 5 tags. The original tags remain immutable
evidence of the states in which findings were discovered.

## Round 3 — 0x static adversarial review

Input: the immutable Gate 5 review hub and all four implementation tags.
The reviewer verified the revision bindings and attempted to revive the prior
critical and policy findings. No Critical or High defect was substantiated.

The report produced four low/hygiene groups:

1. **Finalized controlled-key inputs (credible low specification/defense-in-depth
   defect):** Drongo and SeedSigner both reject controlled partial signatures
   but silently skip a matching controlled key when that input is already
   finalized. This preserves host/signer agreement and Sparrow's REQUIRED
   provenance layer currently rejects the unproved final signature, but it
   contradicts the maintainer specification's whole-ceremony rejection rule.
   A cross-implementation rejection regression and explicit finalized-input
   rule are recommended before broader release claims.
2. **Native differential evidence (hygiene, now locally closed):** the public
   hub run recorded three native tests skipped because the DLL is intentionally
   excluded from the bundle. The checkpointed pinned-source Windows DLL
   (`291046c2979833aa43655c854bb3f9740ada357d96ab8154eeed6be688d6b444`)
   was subsequently supplied to the exact final reference code; all four native
   tests passed, including byte equality, transcript mutation rejection, and
   invalid-scalar handling. Independent artifact rebuilding remains useful
   release evidence.
3. **Public rejection-recording API (non-security API hardening):**
   `recordSignerDataRejection()` is callable by trusted host code. It is needed
   for transport-layer signer-data rejection that occurs before coordinator
   ingestion, uses the shared exhaustive classifier, and is idempotent per
   session. No untrusted call path or concrete misclassification was shown.
   Narrower typed API ergonomics may reduce future misuse but this is not a
   demonstrated trust-boundary bypass.
4. **Documentation/parser notes:** the pre-reveal v1 durable-state migration
   behavior is already pinned in the Gate 2 design/review but should appear in
   release-facing notes. Unknown non-proprietary PSBT fields remain the explicit
   decision-9 hardening item; current Drongo rejection is a safe-direction
   differential, not a newly discovered fail-open path.

The 0x review was static and explicitly did not execute code, exhaustively audit
the large Sparrow controllers, inspect every reference/SeedSigner parser, or
reproduce physical and build evidence. Those limitations define useful targets
for a follow-up pass.

## Cumulative status

- No known Critical or High finding remains open at the Gate 5 immutable heads.
- The finalized controlled-key input rule is the only newly credible code/spec
  correction from Round 3.
- Native differential tests pass with the checkpointed artifact; independent
  rebuilding and execution remain desirable for external release assurance.
- Unknown PSBT-field policy, encryption at rest, monotonic rollback authority,
  formal UR registration, signed release tags, and reproducible release
  artifacts remain explicit decisions or future work—not silent guarantees.
- The project remains an experimental prototype and is not recommended for
  mainnet or production use without further independent cryptographic,
  platform, upstream, and release review.
