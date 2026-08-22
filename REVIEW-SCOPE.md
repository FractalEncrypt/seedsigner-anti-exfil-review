# Review scope and immutable inputs

The project crosses four independently maintained repositories. Review claims
apply only to the exact commits below and to the protocol/reference material in
this hub.

| Component | Fork | Upstream base | Immutable tested result |
| --- | --- | --- | --- |
| Drongo | `FractalEncrypt/drongo` | `a47c2b3f58d7cedd504b2bd07833708866614216` | `bb691c7d77290933b3f7d6c411556c1524a29d98` |
| Sparrow | `FractalEncrypt/sparrow` | `b99b880c9fe75565921af9ef438d6314fdd73d6f` | `f003bfa9575bc7c67b337f8785b1479fd092641a` |
| SeedSigner | `FractalEncrypt/FractalEncrypt_seedsigner` | `56637104b90325e1bc47b58f5f5e8154ea56cf37` | `aa8395e3576379467d795bb05268533e3a2ac082` |
| SeedSignerOS | `FractalEncrypt/seedsigner-os` | `d5a1077851a9b41d6637f7317e3f06aaa453bd5d` | `0bf1dc92519906c7db265055abfb07e0ee344342` |

See [repositories.json](repositories.json) for tag names and tag-object hashes.

## Security boundary

The claimed property is that, when the coordinator supplies unpredictable host
randomness after accepting the signer's nonce opening, every accepted ECDSA
signature is bound to the frozen transaction/signing context and the committed
base nonce. Malformed, unsupported, substituted, replayed, downgraded, or
incomplete ceremonies are intended to fail closed.

The review should cover:

- the ECDSA sign-to-contract construction and native binding;
- canonical AEXB v1 and AEXT parsing;
- PSBT v0 canonicalization and reconstruction;
- slot attribution and exact per-signature ceremony provenance;
- multisig mixed-provenance behavior;
- persistence, retry, abort, and rehydration semantics;
- REQUIRED/OPTIONAL/UNSUPPORTED policy enforcement on every signing, combine,
  finalize, import, cross-window, and broadcast route;
- raw signed-transaction quarantine and the narrow internal-sweep exemption;
- resource limits and fail-closed parser behavior; and
- divergence among the reference, Drongo, Sparrow, and SeedSigner consumers.

## Prior review is context, not a waiver

The completed ledger in `docs/security-review-findings.md` records earlier
findings and their dispositions. In particular:

- P6-F1 identified transaction-wide authorization and missing secondary-route
  enforcement. It was replaced by signature-scoped provenance.
- R-F1 identified over-broad quarantine of PSBT-less raw transactions. It was
  fixed with positive wallet attribution and a local, digest-bound internal
  sweep exemption.

A new report may revisit these areas, but should identify a concrete remaining
bypass at the immutable final revisions rather than assuming the historical
behavior is still present. Phases 10–15 additionally record the independent
triage and remediation of V12 findings `#247985` through `#248002`; the Gate 5
tags include all four implementation gates and the explicit trust-boundary
dispositions.

## Out of scope for a production claim

This package does not establish upstream acceptance, reproducible production
release binaries, a general Taproot/Schnorr anti-exfil protocol, or a mainnet
deployment recommendation. Those require separate review and release work.
