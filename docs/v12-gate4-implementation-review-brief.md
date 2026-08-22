# Gate 4 implementation-review brief

Date: 2026-08-22

## Review objective

Independently review the implementation that closes V12 findings `#247995`, `#248000`, `#248001`, and `#248002`. Gate 4 hardens Drongo API contracts without changing AEXB wire bytes, AEXS durable-state bytes, SeedSigner behavior, Sparrow provenance policy, or broadcast behavior.

Do not rely on the implementation notes as proof. Inspect every changed production path, its callers, the regression tests, and the exact Sparrow submodule pin.

## Exact ranges

- Reference design: `5d2c699c6c283113a72f07884a5f2953aed6f82e..23b8603c830ec35ea54666da270e563a8b03c083`
- Drongo: `a3ed65c5dfda9a7a16dabc8b0a206c9beb422eaf..6b9eec662931a1c387d75e21c1e58806d20e9d6e`
- Sparrow: `c57b07584fe9f150a457900c3afbe20e42c7c78e..f130d58e60d055e797de1f2b3201823e8f2d8c07`
- Sparrow must pin Drongo exactly at `6b9eec662931a1c387d75e21c1e58806d20e9d6e`.

The locked design is `docs/v12-gate4-api-contracts-design.md` at the reference head.

## Changed surface

Drongo production:

- `AntiExfilCodec.validateTransition`
- `AntiExfilPsbt.reconstructSignedPsbt`
- `AntiExfilCoordinator.create`, completion, evidence derivation, and durable-state revalidation callers
- `VerifiedAntiExfilSignature` constructor visibility

Drongo tests:

- codec endpoint validation
- complete-transcript reconstruction and opening substitution
- supported-policy admission and historical-evidence reload
- proof-constructor API shape and coordinator-minted proof determinism
- existing coordinator fixtures updated to state their supported policy explicitly

Sparrow:

- exact Drongo gitlink
- mixed-provenance policy test now obtains its proof from a real deterministic coordinator completion instead of invoking the proof constructor

No production SeedSigner, SeedSignerOS, reference-oracle, wire fixture, provenance evaluator, quarantine, finalization, or broadcast file changed.

## Properties to verify

1. **Complete transcript:** reconstruction requires messages 1, 2, 3, and 4; no overload or alternate production path retains the old message-1-plus-message-4 contract.
2. **Opening fixation:** reconstruction fully validates `1→2→3→4`, so the accepted stage-2 opening must remain identical through reveal and signature stages before any signed PSBT is returned.
3. **Durable-rho authority:** every stage-3 rho equals the durable map entry for the authoritative PSBT slot and hashes to the stage-1 commitment; caller-supplied transcript data cannot replace durable host randomness.
4. **Authoritative semantics:** PSBT digest, slot identity, signing hash, signer key, and sighash remain bound to the canonical original PSBT; foreign ordinary multisig signatures remain preserved but receive no protected proof.
5. **Endpoint validation:** public object-form `validateTransition` fully validates previous then current before adjacency checks. Null/malformed endpoints yield controlled protocol errors, not unchecked exceptions.
6. **Production coverage:** all coordinator completion, reload, retry, and evidence-derivation reconstruction calls supply the complete durable transcript; no unvalidated reconstruction ingress remains.
7. **Admission:** all coordinator creation overloads reject `UNSUPPORTED` before randomness generation or filesystem writes. Both `OPTIONAL` and `REQUIRED` remain admitted.
8. **Migration boundary:** `load` deliberately permits a matching historical session after in-memory policy changes to `UNSUPPORTED`, while full durable revalidation remains mandatory. Confirm this cannot create a new unsupported ceremony.
9. **Evidence authority:** `VerifiedAntiExfilSignature` exposes zero public constructors and no public builder/factory/deserializer accepts asserted verified fields. Production instances are minted only after coordinator reconstruction and cryptographic revalidation.
10. **Value semantics:** evidence remains immutable with defensive copies and stable equality/hash behavior; completion, exact retry, and reload produce identical records.
11. **Sparrow integration:** the mixed REQUIRED/OPTIONAL regression uses a genuinely coordinator-minted proof and retains the intended result: protected signer A does not bless ordinary signer B.
12. **No scope expansion:** wire framing, frozen vectors, durable format/version, abort state machine, provenance/quarantine policy, finalization, broadcast, and SeedSigner paths are unchanged.

## Validation evidence

Drongo exact head `6b9eec6`:

- Focused anti-exfil plus keystore ledger: 51 tests, 50 passed, 1 Windows-skipped POSIX test, 0 failures.
- Full suite: 482 tests, 479 passed, 1 skipped, 2 failures.
- The two failures are the unchanged environment-dependent `ApplicationDirTest.testXdgDirs` and `ApplicationDirTest.testXdgAppliedToMacos` cases on Windows.

Sparrow exact head `f130d58` with Drongo exact pin `6b9eec6`:

- Focused policy/signing-flow/transport set: 16/16 passed.
- Full root suite: 156 tests, 152 passed, 4 failures.
- The four failures are the already documented Windows CRLF/LF comparisons in unchanged Caravan, Coldcard (two cases), and Specter DIY export tests.

Frozen fixture hashes remain byte-identical between Drongo and Sparrow:

- Semantic PSBT vector: `F28D572D1AE5D2060EEB52CA9814F37CE5D54258811D3AF18B78C41744E23A4E`
- Mixed-provenance vector: `DC350CC2F4AAFF593EA8D5A9B0145757D9C0370DA9AC3DB31228B1441FE8C2D1`

Both Drongo and Sparrow worktrees were clean after validation and generated-test-artifact removal.

## Reviewer questions

1. Is any public or production-accessible reconstruction path still able to verify message 4 without the exact accepted message 2 and returned message 3?
2. Does any error-ordering change create a false acceptance, an unchecked exception, or signer-data journaling misclassification?
3. Can an unsupported keystore create or advance a new ceremony through any overload, reflection-free caller, retry, or load path?
4. Is allowing historical `load` after policy downgrade the correct provenance-preserving boundary, and does full state revalidation prevent it from becoming an admission bypass?
5. Can any code outside the Drongo anti-exfil package manufacture `VerifiedAntiExfilSignature`, including through serialization or another public factory?
6. Does the Sparrow test prove the policy result using real coordinator evidence for the intended signer, rather than merely satisfying type shape?
7. Is the exact Drongo pin correct, and are any required callers or tests missing?

## Hold point

Do not create Gate 4 tested tags yet. Required remaining gates are independent review approval and public Linux CI. Existing Gate 3 tags remain immutable evidence; the reviewer bundle remains unfrozen.
