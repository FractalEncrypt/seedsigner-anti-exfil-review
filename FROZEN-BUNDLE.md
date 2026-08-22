# Immutable reviewer bundle

The current public handoff is `seedsigner-anti-exfil-review-bundle-v1.2.zip`,
frozen from the `review-hub-v1.2-2026-08-22` source tag. Its adjacent
`.zip.sha256` asset and GitHub release record provide the authoritative outer
archive hash. The archive also contains `BUNDLE-METADATA.json` and a
`SHA256SUMS.txt` manifest covering every selected payload.

- Source commit: `8df2d3e21e53043fe3cec8b444c9008027876999`
- Annotated tag object: `52a94c082054e8ed049feaf7c6398611b079665c`
- Bytes: `4897532`
- SHA-256: `7f19ea4f0f315f421c915b3c584707d4a48b0f9f5fce9faf9abcd3bf9fbeca34`
- ZIP entries: `128`
- Dirty candidate: `false`
- Release: `https://github.com/FractalEncrypt/seedsigner-anti-exfil-review/releases/tag/review-hub-v1.2-2026-08-22`

Two independently named clean builds were byte-identical. ZIP CRC, entry
ordering, and every internal payload hash were verified by the deterministic
builder before publication.

The bundle is the cross-repository review context for the entire project. It
contains the normative specification, Python reference oracle, shared vectors,
tests, completed Phase 1–15 findings ledger, Gate 1–5 design and implementation
review records, build/test runbook, and selected physical evidence. It does not
duplicate the four implementation repositories; reviewers clone those at the
exact tags in `repositories.json`.

The current implementation bindings are:

- Drongo `bb691c7d77290933b3f7d6c411556c1524a29d98`;
- Sparrow `f003bfa9575bc7c67b337f8785b1479fd092641a`, pinning that exact Drongo;
- SeedSigner `aa8395e3576379467d795bb05268533e3a2ac082`; and
- SeedSignerOS `0bf1dc92519906c7db265055abfb07e0ee344342`.

Gate 5 intentionally rejects a foreign partial signature when its supplied
PSBT lacks enough UTXO context to verify it. Pre-Gate-5 durable sessions that
already contain an invalid foreign partial now fail closed on load; their
resulting PSBTs were already uncombinable downstream.

The previous private checkpoint remains immutable evidence:

- Filename: `anti-exfil-private-review-bundle-v1.zip`
- Reference commit: `dd7b2b26ece992f74daeb3095aa148fc278176ea`
- Bytes: `4686310`
- SHA-256: `08efdaa268e83e0bf6bd12ed5ae248465396a2f2c885c0441fe08345c6042651`

It is superseded because it predates the V12 remediation gates and omitted the
mixed-provenance JSON fixture. Do not supply v1 as the current review input.

This is a reviewed experimental prototype handoff, not a production security
audit or a recommendation to use protected signing with mainnet funds.
