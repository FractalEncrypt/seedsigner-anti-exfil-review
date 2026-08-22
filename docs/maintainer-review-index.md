# Maintainer review package

Status: independently reviewed Gate 5 prototype inputs; immutable experimental
implementation tags published and Linux-tested

Recorded: 2026-08-22

Security status: focused review and remediation complete; not a production audit

This page is the entry point for reviewing the interactive ECDSA anti-exfil
prototype shared by SeedSigner, Drongo, and Sparrow. It separates the normative
protocol from implementation choices, test oracles, physical observations, and
historical development notes.

## Review order

1. [Maintainer specification](maintainer-specification.md) — scope, protocol
   contract, repository boundaries, state machine, persistence, and claims.
2. [Cryptographic construction](protocol-v1.md) — pinned ECDSA sign-to-contract
   construction and host verification.
3. [Multi-slot wire format](protocol-v1-wire-format.md) — canonical AEXB v1
   records, PSBT semantics, limits, ordering, retry, and failure rules.
4. [AEXT transport](transport-aext.md) — exact QR envelope and stage/PSBT rules.
5. [Threat model](threat-model.md) — trust assumptions, attacks, invariants,
   residual risks, and validation mapping.
6. [Shared-vector index](shared-vector-index.md) — normative vectors, hashes,
   generators, consumers, and historical fixtures.
7. [Physical-evidence index](physical-evidence-index.md) — device, OS, funded,
   adversarial, Sparrow, multi-input, and multisig gates.
8. [UX proposal](ux-proposal.md) — device-neutral policy, signing ceremony,
   retry/abort language, multisig behavior, and error presentation.
9. [Repository hygiene publication checkpoint](repository-hygiene-publication-checkpoint.json)
   — public-tree hygiene, immutable inputs, and publication disposition.
10. [Drongo review-series checkpoint](drongo-review-series-checkpoint.json) —
    exact three-commit series, tree-equivalence proof, Windows results, and
    clean Linux CI evidence.
11. [Sparrow review-series checkpoint](sparrow-review-series-checkpoint.json) —
    exact four-commit series, recursive clone, Linux CI, and packaged-app gate.
12. [SeedSigner review-series checkpoint](seedsigner-review-series-checkpoint.json)
    — exact three-commit series, tree-equivalence proof, full CI, and clone gate.
13. [SeedSignerOS review-series checkpoint](seedsigner-os-review-series-checkpoint.json)
    and [image gate](seedsigner-os-review-build-gate.md) — exact two-commit
    series, public recursive clone, config separation, and passed image boots.
14. [Independent security-review brief](independent-security-review-brief.md) —
    requested cryptographic, state-machine, persistence, parser-differential,
    downgrade, and native-integration review.
15. [Security-review findings](security-review-findings.md) and
    [maintainer decisions](maintainer-decisions-requested.md) — completed phase
    ledger, remediation reviews, residuals, and explicit dispositions.
16. [Review rounds and remediation history](review-rounds-summary.md) — concise
    provenance for the Kimi/Cascade, V12, and 0x review rounds.
17. [Private review-bundle manifest](review-bundle-manifest.md) — selected
    normative docs, vectors, oracle/tests, evidence, and explicit exclusions.
18. [Final smoke checkpoint](final-smoke-checkpoint.json) — completed xpub,
    duplicate, direct-continuation, stateless-recovery, P6-F1 provenance, and
    R-F1 raw-transaction lifecycle observations.
19. [QR brightness correction gate](qr-brightness-correction-gate.md) — passed
    replacement application/image/physical gate included in the final freeze.

## Implementation snapshots

Clean Drongo, Sparrow, SeedSigner, and SeedSignerOS review branches are
published on personal forks. The reference workspace remains local. Hashes
identify reviewed experimental inputs; they are not upstream endorsements.
Chronological branches and immutable tags preserve the physical evidence while
the review branches present current-upstream maintainer series.

Drongo also has a cleaned maintainer branch, `anti-exfil-review-v1`, based on
current official `master`. Its three commits preserve the exact integrated tree
of the tested chronological branch. The separate `anti-exfil-review-v1-ci`
branch adds only workflow infrastructure and records a clean Linux/Java 25 run;
it is not part of the maintainer patch series.

| Component | Branch | Review head | Responsibility |
| --- | --- | --- | --- |
| Reference/coordinator | `master` | See `BUNDLE-METADATA.json` | Python oracle, generators, adversarial harnesses, camera/file coordinator, evidence |
| SeedSigner | `anti-exfil-review-v1` | `aa8395e3576379467d795bb05268533e3a2ac082` | Strict signer semantics, native S2C signing, stateless QR UX, fail-closed policy, QR-renderer compatibility |
| Drongo | `anti-exfil-review-v1-gate5-tested-2026-08-22` | `bb691c7d77290933b3f7d6c411556c1524a29d98` | Codec, public verification, PSBT semantics, reconstruction, durable coordinator model, signature-scoped proofs, Gates 1–5 state and trust hardening |
| Sparrow | `anti-exfil-review-v1-gate5-tested-2026-08-22` | `f003bfa9575bc7c67b337f8785b1479fd092641a` | AEXT/UR bridge, persistence, policy, ceremony, signature-scoped enforcement, quarantine, and exact Gate 5 Drongo pin |
| SeedSignerOS | `anti-exfil-review-v1` | `0bf1dc92519906c7db265055abfb07e0ee344342` | Native package and opt-in Pi Zero test-image integration |

The chronological SeedSignerOS checkout retains extensive Windows
timestamp/line-ending noise and a dirty Buildroot submodule, but it is now
evidence-only. The clean public review clone contains exactly two commits and a
clean pinned Buildroot checkout. Its static and source-download gates pass;
The normal image build and boot pass. A pre-tag instrumented image exposed and
corrected test-service ordering relative to `S10mdev`; the corrected image then
passed its clean build, normal UI boot, native-vector receipt, and
no-production-fallback gates.

## Normative versus non-normative material

Normative for protocol v1:

- the construction and exact native compatibility target in `protocol-v1.md`;
- AEXB bytes, semantic rules, supported scripts, ordering, and limits in
  `protocol-v1-wire-format.md`;
- AEXT bytes and stage-specific PSBT presence in `transport-aext.md`; and
- the two protocol-v1 golden-vector files identified in
  `shared-vector-index.md`.

Implementation-defined but security constrained:

- encrypted or unencrypted local session-file representation;
- exact UI layout and localized wording;
- selective-abort escalation thresholds;
- camera implementation and QR density controls; and
- how a compatible device brand declares support.

Historical/non-normative:

- the older one-slot Rung B/C/D protocol records;
- `fixtures/transport-v1-vectors.json`, except as a legacy AEXT parser test;
- the original one-round Gemini mockup; and
- terminal “rung” milestone descriptions that predate the native device and
  Sparrow implementations.

## Current validation summary

- Reference semantic/adversarial corpus: canonical four-input/five-slot PSBT,
  native/nested P2WPKH, native/nested P2WSH multisig, malformed transcripts,
  repeated same-key openings, Dark Skippy, predetermined nonce, nonce grinding,
  selective abort, and returned-metadata injection. The final hub run reports
  85 passed and 3 native-library skips with the tagged SeedSigner adapter active.
- SeedSigner: 185 applicable tests pass and 2 skip; the stock Windows
  CompactSeedQR bitmap module remains excluded for the documented Pillow/pyzbar
  issue.
- Sparrow Gate 5: 156 tests discovered, 152 pass; the same four upstream-style Windows
  CRLF/LF export comparisons fail.
- Drongo Gate 5: 484 tests discovered, 481 pass and one POSIX-only test skips on
  Windows; the same two Windows/XDG
  `ApplicationDirTest` cases fail.
- Physical: honest and adversarial SeedSigner QR ceremonies, normal OS image,
  confirmed funded Testnet4 signing, Sparrow-to-SeedSigner ceremony, required
  policy downgrade rejection, exact post-reveal retry, real multi-input
  signing, and real P2WSH 2-of-3 multisig signing.

These results establish prototype interoperability and fail-closed behavior;
they do not replace independent cryptographic review, upstream code review,
reproducible-release review, or a production security audit.

## Requested maintainer decisions

1. Is the pinned `secp256k1-zkp` S2C construction acceptable as the v1 native
   compatibility target, and where should the native binding live upstream?
2. Should the experimental `ur:x-btc-anti-exfil` type proceed toward registry
   coordination, or remain explicitly experimental during review?
3. Is PSBT v0 plus explicit `SIGHASH_ALL` and the four supported SegWit-v0
   script forms an appropriately narrow first release?
4. What selective-abort warning thresholds and fund-migration language should
   be adopted?
5. Should durable coordinator sessions be encrypted at rest, or is filesystem
   integrity plus checksummed atomic state acceptable for the first review?
6. Should the device-neutral `UNSUPPORTED`/`OPTIONAL`/`REQUIRED` capability be
   stored only per keystore, or also advertised by an import format?
7. Is Taproot best handled as a separate reviewed protocol version rather than
   extending AEXB v1?

No unresolved decision permits silent fallback to ordinary signing.
