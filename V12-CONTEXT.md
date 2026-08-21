# V12 context: Drongo anti-exfil v1 diff

## Exact review input

- Repository: `https://github.com/FractalEncrypt/drongo`
- Base: `a47c2b3f58d7cedd504b2bd07833708866614216`
- Target: `1bbafd94f08fd9105e20be30a6fdfe9a091fb675`
- Immutable target tag: `anti-exfil-review-v1-tested-2026-08-20`

Drongo is one component of a four-repository interactive ECDSA anti-exfil
prototype. It owns the protocol codec, public verification, PSBT semantics,
durable coordinator state, signing-slot identity, and immutable
per-signature proof records. Sparrow consumes these APIs; SeedSigner performs
the air-gapped signing ceremony.

## Claimed security behavior

An accepted protected ECDSA signature must be bound to the canonical original
PSBT context, input/outpoint, signer pubkey, BIP143 message hash, sighash, exact
compact signature, wallet identity, and a fully revalidated ceremony session.
One signer's valid ceremony must never authorize another signer's ordinary
signature. Reopened durable state must reproduce the same proof records only
after full transcript and signed-PSBT revalidation.

## Review requests

Prioritize concrete security or correctness defects in:

- scalar/point/signature validation and low-S enforcement;
- AEXB codec canonicality, limits, duplicate/unknown fields, and parser
  differentials;
- canonical PSBT-v0 digest construction;
- per-slot attribution and exact signature matching;
- multisig mixed-provenance rejection;
- durable file containment, lookup-hint handling, revalidation, exact retry,
  and abort behavior;
- prospective combine/reconstruction semantics and failed-merge behavior; and
- policy serialization or attribution helpers used by Sparrow.

For each finding, provide:

1. Exact affected code paths and line references.
2. Preconditions and a technically coherent exploit or failure sequence.
3. A minimal executable proof of concept or regression test where feasible.
4. Impact and a justified severity.
5. Remediation that compiles and preserves legitimate protected signing.
6. Validation showing the original exploit no longer succeeds.

## Historical findings already remediated

P6-F1 previously showed that transaction-wide authorization could allow one
REQUIRED signer's protected ceremony to bless another REQUIRED signer's
ordinary signature. The target replaces that model with immutable,
signature-scoped `VerifiedAntiExfilSignature` records and mixed-provenance
tests. Do not report P6-F1 as currently open unless the final target contains a
demonstrable remaining bypass.

R-F1 concerned Sparrow's PSBT-less raw-transaction UI and did not change Drongo.
Do not attribute that Sparrow UI issue to Drongo without an affected Drongo code
path.

Documented test fixtures intentionally contain public deterministic keys and
mnemonics. Their presence is not a secret leak.
