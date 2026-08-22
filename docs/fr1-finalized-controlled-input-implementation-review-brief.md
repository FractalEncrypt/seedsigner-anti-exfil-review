# F-R1 finalized controlled-input remediation — implementation review brief

Date: 2026-08-22

Status: implementation complete; independent review and public CI required
before replacement tested tags or reviewer-bundle refreeze.

## 1. Finding and required invariant

The pinned implementations previously rejected a controlled key only when its
signature appeared in the PSBT partial-signature map, then silently skipped an
input carrying final script fields. Sparrow's non-finalized provenance evaluator
also inspected only partial signatures. A PSBT could therefore contain an
ordinary signature for a REQUIRED signer in `final_scriptwitness`, complete a
protected ceremony for the remaining slots, pass the pre-finalization check,
and expose the finalized transaction through View Final, Show QR, or Save.
Sparrow's direct broadcast handler rechecked and blocked, but an exported
transaction could be broadcast elsewhere.

The remediation enforces two independent invariants:

1. A finalized input retaining a signer-attributable BIP32 derivation rejects
   the complete protected-signing ceremony before any opening or host
   randomness is disclosed. A finalized input attributed only to another
   signer remains outside the selected signer's slot set.
2. Sparrow re-evaluates signature-scoped provenance after finalization and
   immediately before every final-transaction view, QR, save, or broadcast
   action. Failure reapplies the read-only quarantine.

## 2. Exact review ranges

- Reference/specification:
  `af738017368f55ee06edcd0b6194aba87217685c..d879f983ad5170f86538b007366fee879c1bfc6a`
- Drongo:
  `a1a9420e774d7b7fa893b6372ef6022fc0df6cc6..e9a692a4ac4eb14901101cd9324e2275a29897cf`
- SeedSigner:
  `aa8395e3576379467d795bb05268533e3a2ac082..214793df4f51466179b792420921b8cdd8d0c1ac`
- Sparrow:
  `c4c086206016d4a388fbe409972d8564c7811612..5b74d94637516aab6d1c79a2e3a3c13c1347b3ea`
- Sparrow's Drongo gitlink at the review head is exactly:
  `e9a692a4ac4eb14901101cd9324e2275a29897cf`.

The base Drongo and Sparrow commits differ from the Gate 5 source heads only by
their previously reviewed CI-workflow commits. The SeedSignerOS repository is
unchanged.

## 3. Production changes

### Reference

`enumerate_signing_slots` and
`enumerate_signing_slots_for_fingerprint` now return
`UNEXPECTED_RETURN_DATA` when a finalized input retains a derivation
attributable to the selected signer. The specification and wire-format text now
state this rule explicitly. Decision 9's evidence is also corrected to use the
actually unassigned input key type `0x19`; `0x15` is assigned by BIP371 to
`PSBT_IN_TAP_LEAF_SCRIPT`.

### Drongo

`AntiExfilPsbt.enumerateSigningSlots` now rejects an attributable finalized
input with `UNEXPECTED_RETURN_DATA`. Because coordinator creation, reload,
message construction, and completion all re-enumerate through this boundary,
the rule covers new and durable sessions.

### SeedSigner

`derive_signing_contexts` now rejects an attributable finalized input with
`SIGNING_MODE_MISMATCH` before a response is created. Finalized inputs carrying
only a different signer's derivation remain skippable. No transport, native
backend, view, or SeedSignerOS code changed.

### Sparrow

- `currentProvenanceStatus` delegates to one package-visible
  `evaluateTransactionProvenance(TransactionData)` boundary used by the
  regression suite.
- `requirePermittedProvenance` performs a fresh evaluation, reapplies
  quarantine on failure, and emits a controlled error.
- Finalization checks before mutation and again after the PSBT becomes final.
- `psbtFinalized` reapplies quarantine after switching the UI to final controls.
- View Final/extract, Show Transaction as QR, Save Final Transaction, and
  Broadcast all invoke the fresh gate at handler entry.

No provenance-record format, durable-session format, AEXB/AEXT wire data,
signature reconstruction, policy persistence, ordinary OPTIONAL behavior, or
internal-sweep authorization changed.

## 4. Regression evidence

The new admission regressions create a deterministic finalized P2WPKH input
that retains the selected signer's derivation and assert whole-request
rejection. Each also changes the same derivation to a different fingerprint and
asserts that the remaining honest slots are still enumerated, preventing an
accidental global ban on unrelated finalized inputs.

Sparrow's mixed-provenance regression now passes a finalized transaction and
its surviving protected proof through
`HeadersController.evaluateTransactionProvenance`, asserting
`REQUIRED_PROOF_MISSING`. Every final-transaction handler calls the common
fresh gate in production, and post-finalization quarantine is explicit.

## 5. Validation performed

- Reference focused PSBT/coordinator: **16 passed, 16 subtests passed**.
- Reference complete scoped suite (`tests/reference`):
  **89 passed, 38 subtests passed**.
- Drongo focused `AntiExfilPsbtTest`: **passed**.
- Drongo complete suite: **485 tests; 482 passed, 2 failed, 1 skipped**.
  The two failures are the unchanged Windows environment-dependent
  `ApplicationDirTest.testXdgDirs` and `testXdgAppliedToMacos` cases.
- SeedSigner anti-exfil suite: **42 passed, 2 skipped**. The skips are the
  native-library-dependent cases when no library path is supplied.
- Sparrow focused policy/FXML tests: **passed**.
- Sparrow complete suite: **156 tests; 152 passed, 4 failed**. The four failures
  are the unchanged Windows CRLF/LF comparisons in Caravan, Coldcard (two),
  and Specter DIY export tests.
- All modified repositories pass `git diff --check`; Drongo, SeedSigner, and
  Sparrow worktrees are clean. The reference worktree contains only two
  unrelated pre-existing untracked feasibility documents.

An accidental unscoped reference `pytest` invocation collected vendored
feasibility sources and failed collection for their absent optional toolchains;
it is not project-suite evidence and is superseded by the explicit
`tests/reference` run above.

## 6. Reviewer questions

1. Does every production path that creates, reloads, advances, or completes a
   ceremony execute the finalized-controlled-input admission rule before any
   new reveal can be returned?
2. Is attribution scoped narrowly to a matching signer fingerprint and derived
   public key, without rejecting finalized inputs belonging only to another
   signer?
3. Can any Sparrow finalization route mutate the PSBT and then enable View,
   Show QR, Save, or Broadcast without the finalized-form evaluator running?
4. Can UI state, a stale enabled button, direct handler invocation, or an
   exception path bypass `requirePermittedProvenance`?
5. Does the second finalization evaluation correctly see signatures moved from
   partial maps into final witness/scriptSig fields and match only exact durable
   proofs?
6. Are OPTIONAL signers, legitimate protected completion, durable proof reload,
   raw-transaction quarantine, and the internal-sweep exemption unchanged?
7. Is `0x19` the correct unassigned PSBT input-field case under the pinned
   parser versions, and is the documented host-stricter differential accurate?
8. Are additional controller-level JavaFX tests needed beyond the common-gate
   regression and explicit handler call sites before tagging?

## 7. Hold points

- Do not move or replace the existing immutable Gate 5 tags.
- Do not create replacement tested tags or refreeze the reviewer bundle until
  independent review approves these ranges and public Linux CI is green.
- No SeedSignerOS rebuild or physical hardware gate is required for this
  validation-only signer change. If maintainers nevertheless roll a new
  SeedSigner application tag into an OS release, the normal image build and
  boot smoke apply to that later release operation.
