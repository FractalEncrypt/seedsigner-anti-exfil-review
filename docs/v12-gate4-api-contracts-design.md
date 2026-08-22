# V12 Gate 4 API-contract design

Date: 2026-08-22

Gate 4 resolves V12 findings `#247995`, `#248000`, `#248001`, and `#248002` as one Drongo-owned API-boundary change. It does not change AEXB wire encoding, durable AEXS encoding, SeedSigner behavior, Sparrow provenance policy, or broadcast behavior.

## Locked contracts

### Complete-transcript reconstruction (`#247995`)

`AntiExfilPsbt.reconstructSignedPsbt` must receive the host commitment, signer openings, host reveal, and signer signatures. It must fully validate each message and every adjacent transition before reconstructing a signed PSBT. The stage-2 opening is therefore fixed before the host randomness is accepted and must remain byte-identical through stages 3 and 4.

The authoritative PSBT slot set and the durable host-randomness map remain independent inputs. Every revealed rho must equal the durable rho for its authoritative slot, and every rho must match the stage-1 host commitment. No compatibility overload may retain the incomplete commit-plus-signatures contract.

### Full endpoint validation (`#248000`)

`AntiExfilCodec.validateTransition(previous, current)` first calls full `validate` on both endpoints, in previous-then-current order, and only then checks adjacency and transcript continuity. Null or malformed object-form messages must produce controlled `AntiExfilException` failures rather than unchecked exceptions.

This deliberately closes the public object-form API even though production byte ingress already passed through `decode`.

### Capability admission (`#248001`)

Every `AntiExfilCoordinator.create` overload rejects a keystore for which `supportsAntiExfil()` is false before session randomness is generated or any session/journal file is written. `OPTIONAL` and `REQUIRED` remain admitted.

`load` continues to accept a matching durable session even if the caller's current policy metadata is `UNSUPPORTED`. Loading is revalidation of historical evidence, not admission to a new ceremony; denying it could destroy usable provenance after a policy/UI change. A loaded pre-reveal session still cannot have been created through the corrected API with unsupported policy.

### Coordinator-minted evidence (`#248002`)

`VerifiedAntiExfilSignature` remains a public immutable value type with defensive accessors, equality, and hashing, but its constructor becomes package-private. Only the revalidating Drongo coordinator package can mint instances in production. No public factory, deserializer, builder, or compatibility constructor will accept caller-asserted verified fields.

Downstream tests that need evidence must obtain it from a real coordinator completion/reload path rather than synthesizing it.

## Regression matrix

1. Reconstruction accepts the frozen valid four-message transcript and produces the unchanged signed-PSBT hash.
2. A stage-2 opening mutation paired with otherwise valid later messages is rejected before reconstruction.
3. Missing, wrong-stage, or discontinuous transcript members fail closed with protocol errors.
4. `validateTransition` rejects a malformed previous endpoint and a malformed current endpoint using controlled validation errors; a valid transition remains accepted.
5. Coordinator creation rejects `UNSUPPORTED` without creating session state, while `OPTIONAL` and `REQUIRED` create normally.
6. A completed session remains revalidatable after the in-memory keystore policy is changed to `UNSUPPORTED`.
7. External Java code cannot invoke the evidence constructor; Drongo completion and reload return identical immutable evidence.
8. Sparrow's mixed-provenance test uses coordinator-minted proof and retains the same REQUIRED/OPTIONAL policy outcomes.
9. Focused Drongo anti-exfil tests, the full Drongo suite, focused Sparrow policy/provenance tests, and the full Sparrow suite pass with Sparrow pinned to the exact reviewed Drongo commit.

## Scope and release gate

The reference repository records this design only. Production changes belong to Drongo; Sparrow changes are limited to consuming the restricted API, tests, and the exact Drongo submodule pin. SeedSigner and SeedSignerOS are out of scope.

No replacement tested tags are created until an independent implementation review and public Linux CI are green. Existing Gate 3 tags remain immutable evidence.
