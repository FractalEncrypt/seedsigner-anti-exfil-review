# Immutable reviewer bundle

The current public handoff is `seedsigner-anti-exfil-review-bundle-v1.3.zip`,
frozen from the `review-hub-v1.3-2026-08-22` source tag. Its adjacent
`.zip.sha256` asset and GitHub release record provide the authoritative outer
archive hash. The archive also contains `BUNDLE-METADATA.json` and a
`SHA256SUMS.txt` manifest covering every selected payload.

- Source commit: `31f0dcc24a6ae7b676065f244486200d1ee9d713`
- Annotated tag object: `be45b831de7e7f82779ab96b26d973da692bba1c`
- Bytes: `4913228`
- SHA-256: `08984dfdd39604f5470ab708a5d5da4bf6157c0e40dfb2d7f11f5dfdfa5da18a`
- ZIP entries: `131`
- Dirty candidate: `false`
- Release: `https://github.com/FractalEncrypt/seedsigner-anti-exfil-review/releases/tag/review-hub-v1.3-2026-08-22`

Two independently named clean builds were byte-identical. ZIP CRC, entry
ordering, bundle metadata, and all 129 internal payload hashes were verified
before publication. GitHub records the same SHA-256 and byte count for the
uploaded ZIP asset.

The bundle is the cross-repository review context for the entire project. It
contains the normative specification, Python reference oracle, shared vectors,
tests, completed Phase 1–17 findings ledger, Gate 1–5 and F-R1 design and
implementation review records, build/test runbook, and selected physical evidence. It does not
duplicate the four implementation repositories; reviewers clone those at the
exact tags in `repositories.json`.

The current implementation bindings are:

- Drongo `e9a692a4ac4eb14901101cd9324e2275a29897cf`;
- Sparrow `5b74d94637516aab6d1c79a2e3a3c13c1347b3ea`, pinning that exact Drongo;
- SeedSigner `214793df4f51466179b792420921b8cdd8d0c1ac`; and
- SeedSignerOS `0bf1dc92519906c7db265055abfb07e0ee344342`.

The replacement inputs retain Gate 5's foreign-partial validation and add
whole-request rejection for signer-attributable finalized inputs. Sparrow also
rechecks provenance after finalization and at every final-transaction handler.
Pre-fix durable sessions with an attributable finalized input now fail closed
on reload. SeedSignerOS is unchanged; its prior physical image remains the
native/QR integration evidence.

The superseded v1.2 public bundle remains immutable evidence and is retained as
its own GitHub release. The earlier private checkpoint also remains evidence:

- Filename: `anti-exfil-private-review-bundle-v1.zip`
- Reference commit: `dd7b2b26ece992f74daeb3095aa148fc278176ea`
- Bytes: `4686310`
- SHA-256: `08efdaa268e83e0bf6bd12ed5ae248465396a2f2c885c0441fe08345c6042651`

It is superseded because it predates the V12 remediation gates and omitted the
mixed-provenance JSON fixture. Do not supply v1 as the current review input.

This is a reviewed experimental prototype handoff, not a production security
audit or a recommendation to use protected signing with mainnet funds.
