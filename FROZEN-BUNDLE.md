# Private checkpoint bundle

The original private-review handoff was frozen from reference commit
`dd7b2b26ece992f74daeb3095aa148fc278176ea` and local annotated tag
`anti-exfil-tested-2026-08-20`.

- Filename: `anti-exfil-private-review-bundle-v1.zip`
- Bytes: `4686310`
- SHA-256: `08efdaa268e83e0bf6bd12ed5ae248465396a2f2c885c0441fe08345c6042651`
- ZIP entries: `106`
- Internally manifested payloads: `104`
- Dirty candidate: `false`

Two independently named builds were byte-identical. ZIP CRC verification and
all internal payload hashes passed.

During preparation of this public source repository, a clean-room test run
found that the archive included the mixed-provenance test but omitted its public
deterministic JSON fixture. The private checkpoint remains immutable and its
hash remains valid, but it is superseded for public delivery.

Do not publish the checkpoint ZIP as the public release asset. Build a corrected
self-contained archive from a clean commit of this repository with
`scripts/build_private_review_bundle.py`. The corrected builder includes
`fixtures/protocol-v1-mixed-provenance-vector.json` and its byte-pinned
`fixtures/protocol-v1-mixed-provenance.psbt`, and writes an adjacent SHA-256
sidecar. Release archives are deliberately not tracked as opaque Git binaries.
