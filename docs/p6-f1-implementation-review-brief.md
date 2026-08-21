# P6-F1 implementation review brief

Date prepared: 2026-08-18

This review covers the signature-scoped provenance remediation for P6-F1 and
the separate P6-F2 UI restriction. It is a pre-tag review: do not treat these
heads as release tags until the independent remediation review is complete.
The four-part physical gate has passed on the exact implementation heads below.

## Exact review ranges

- Drongo: `1250d5a..1bbafd94f08fd9105e20be30a6fdfe9a091fb675`
- Sparrow: `c88c573..90c64c9d5fc121aa5235627301e35523cf067863`
- Reference and review artifacts:
  `ed3d323..6e1b23aadc4c0feb2cc8516881530f50e4b14fd8`

Implementation branches:

- Drongo: `codex/p6-f1-signature-provenance`
- Sparrow: `codex/p6-f1-signature-provenance`

The Sparrow CI-only branch contains a temporary workflow and is not an
implementation review target.

## Required security review

Please evaluate the code, rather than only the added tests, for these
properties:

1. A proof authorizes exactly one signature. Matching must bind the canonical
   original-v0 PSBT digest, wallet-key identity, input/outpoint, signer pubkey,
   BIP143 message hash, sighash, and exact compact signature.
2. Completing a ceremony for required signer A must not authorize an ordinary
   pre-existing signature from required signer B.
3. Fresh completion and `.aexs` reload must derive identical immutable proof
   records solely from revalidated durable state. A missing, corrupt,
   mismatched, or path-escaped session must grant no proof.
4. The session index is only an untrusted availability hint. Every candidate
   must be constrained to the wallet directory, resolved to a safe real path,
   fully revalidated, and exact-matched before use.
5. Provenance must survive only unsigned-transaction-preserving flows and must
   be pruned when signatures are removed or replaced. Failed merges must add
   no authority.
6. Policy gates must cover primary QR return, cross-window forwarding,
   non-final combine, the finalized-field copy branch, USB/card return,
   scanned-seed and other software signing, finalization, and broadcast.
7. A signed PSBT or raw signed transaction opened without attributable wallet
   policy context must remain inspectable but unable to finalize or broadcast.
8. Software-signing refusal must be per participating private keystore, not a
   wallet-wide block and not fingerprint-only attribution.
9. `Required` must be offered only for SeedSigner. Existing incompatible
   values must remain enforceable and visible with a warning, without silent
   rewriting.
10. The completion `isBroadcast()` invariant must remain intact; carrying a
    proof set must never imply that the device broadcast anything.

Pay particular attention to finalized transaction signature extraction,
DER-to-compact normalization, input reordering, duplicate fingerprints,
cross-window event lifetime, symlink/junction handling on Windows, and any
route that can reach finalization or broadcast without the common evaluator.

## Shared adversarial fixture

`fixtures/protocol-v1-mixed-provenance-vector.json` and
`fixtures/protocol-v1-mixed-provenance.psbt` describe a deterministic 2-of-2
PSBT in which signer B already has an ordinary valid signature and signer A
has a valid protected ceremony. If both keystores are `Required`, A's proof
must not bless B's signature. The fixture PSBT SHA-256 is:

`45e3877ac64ba8b759c646e7a1734072b783f181c340921efa99e007b07b4daa`

## Validation already completed

- Reference: 83 tests passed plus 35 subtests; all three generated vector
  families reproduced byte-for-byte.
- Drongo: focused anti-exfil suite passed. Full local suite passed 456/458;
  the two failures are unchanged Windows-vs-Unix application-directory path
  assumptions. Public Linux CI passed:
  https://github.com/FractalEncrypt/drongo/actions/runs/32074611695
- Sparrow: focused provenance, flow, FXML, and quarantine suites passed. Full
  local suite passed 149/153; the four failures are the unchanged Windows
  CRLF/LF export fixtures. Public Linux CI containing final implementation
  head `90c64c9` passed:
  https://github.com/FractalEncrypt/sparrow/actions/runs/32144398178
- Windows `jpackageImage` completed. The tested JAR SHA-256 is
  `e7633d50cca6f66b15aa07548081ce05859d0b9344958635ff45be0b9f07772c`.
- The physical gate passed all four cases. The initial Gate 3 run on
  `fe4510d` exposed a finalized-PSBT durable-proof reattachment defect. The
  correction at `90c64c9` verifies finalized signatures directly against the
  PSBT derivations and signing digest; a deterministic regression test, Linux
  CI, packaging, and the close/reopen physical gate all passed. Evidence and
  hashes are recorded in `final-smoke-checkpoint.json` and
  `docs/assets/p6-f1-smoke/`. No funded transaction or broadcast was used.

## Reviewer response requested

Please return:

- a finding ledger with file/line evidence and severity;
- an explicit pass/fail judgment for each numbered property above;
- any missing ingestion, merge, signing, finalization, or broadcast route;
- confirmation that the mixed-provenance regression would fail on the pinned
  pre-fix implementation and pass for the intended security reason now;
- confirmation that no transaction-wide authorization boolean or equivalent
  remains; and
- a recommendation on whether these exact heads are ready for immutable tested
  tags and reviewer-bundle freeze.
