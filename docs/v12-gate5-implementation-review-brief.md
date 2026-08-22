# Gate 5 implementation-review brief

Date: 2026-08-22

## Review objective

Independently review the resolution of V12 findings `#247987`, `#247988`, `#247990`, `#247996`, and `#247997`. Gate 5 has two distinct review burdens:

1. verify the preventive Drongo fix for invalid pre-existing foreign partial signatures (`#247996`); and
2. challenge the explicit maintainer dispositions for coordinator-state rollback, abort-journal rollback, Windows local-storage confidentiality, and witness-only PSBT inputs (`#247987`, `#247988`, `#247990`, and `#247997`).

Do not treat the documented dispositions as proof. Confirm that each boundary follows from the pinned implementation and threat model, that no incomplete mitigation is represented as complete, and that the recovery guidance is safe.

## Exact ranges

- Reference design and threat model: `92ab573d88802d869dd8d8c05e95c2c1abc66e69..f2dc199c08d3b1bfb444ab74e080aec41b6060cd`
- Drongo: `6b9eec662931a1c387d75e21c1e58806d20e9d6e..bb691c7d77290933b3f7d6c411556c1524a29d98`
- Sparrow: `f130d58e60d055e797de1f2b3201823e8f2d8c07..f003bfa9575bc7c67b337f8785b1479fd092641a`
- Sparrow must pin Drongo exactly at `bb691c7d77290933b3f7d6c411556c1524a29d98`.

The locked disposition record is `docs/v12-gate5-trust-contracts-design.md` at the reference head.

## Changed surface

Reference documentation:

- `docs/v12-gate5-trust-contracts-design.md`
- `docs/threat-model.md`
- `docs/maintainer-decisions-requested.md`

Drongo production:

- `AntiExfilPsbt.parseCanonicalV0` now enables Drongo's existing partial-signature verification at the canonical anti-exfil PSBT ingress.

Drongo tests:

- an invalid pre-existing foreign partial signature is rejected before coordinator state exists;
- the existing valid mixed-provenance ceremony remains accepted and preserves its foreign ordinary signature without minting protected proof for it; and
- a witness-only UTXO amount mutation changes the authoritative BIP143 message hash without changing the unsigned-transaction outpoint.

Sparrow:

- exact Drongo gitlink only.

No AEXB wire, AEXS session-state, AEXJ journal, reference-oracle production, SeedSigner, SeedSignerOS, Sparrow provenance/quarantine, finalization, or broadcast code changed.

## Finding dispositions to review

### `#247996` — preventive implementation

Invalid pre-existing foreign partial signatures are an availability defect: without early verification, a protected ceremony can consume state and return a PSBT that later fails during Sparrow combination. The fix uses the existing Drongo PSBT verifier at the sole canonical anti-exfil PSBT boundary.

Valid foreign multisig partial signatures remain intentionally supported. They must survive reconstruction byte-for-byte, but must never receive `VerifiedAntiExfilSignature` evidence merely because another signer completed a protected ceremony.

### `#247987` and `#247988` — rollback domain

Authentic older AEXS state and erased or rolled-back AEXJ history cannot be given freshness by data stored entirely in the same rollback domain. A complete defense needs a separately trusted monotonic authority. The present product has none, and the coordinator directory remains within the previously declared trusted-filesystem boundary.

The documentation therefore does not claim rollback detection. Suspected state rollback, replacement, journal loss, or unexpected reset makes selective-abort history unreliable: stop protected signing from that state and migrate funds to a wallet generated from fresh independent keys before relying on the guarantee again.

### `#247990` — local-storage confidentiality

Unrevealed rho is plaintext durable state. POSIX permissions are owner-restricted where supported; Java relies on the effective inherited Windows DACL. The deployment contract requires owner-restricted access to the Sparrow state directory. This is explicitly not encryption at rest and does not protect against owner-equivalent malware, administrators, permissive backups, or privileged local actors.

### `#247997` — witness-only PSBT inputs

Protocol v1 retains standard BIP174 witness-only input support. The supplied amount and script are committed by the BIP143 signing hash, but the standalone witness UTXO does not prove external chain state or permit recomputation of the previous transaction txid. False supplied context produces a signature invalid for the actual coin; the evidence attests only to the exact supplied signing context and unsigned-transaction outpoint.

Requiring every full previous transaction was deliberately rejected because it would break standard hardware-wallet workflows and materially enlarge animated-QR payloads. When a non-witness UTXO is supplied, Drongo's existing consistency and outpoint checks remain in force.

## Properties to verify

1. **Early foreign-signature rejection:** every anti-exfil coordinator creation path reaches `parseCanonicalV0`, and an invalid pre-existing partial signature fails before slot enumeration, randomness generation, AEXS persistence, or AEXJ mutation.
2. **Controlled failure:** malformed or cryptographically invalid existing partials yield a controlled protocol rejection rather than an unchecked exception or partially created session.
3. **Valid multisig compatibility:** a valid foreign ordinary partial remains accepted and byte-preserved across reconstruction.
4. **Proof isolation:** a valid foreign partial receives no protected-signing proof; only the signature cryptographically derived from the completed ceremony can receive evidence.
5. **Supported-input compatibility:** enabling Drongo's existing PSBT verification does not reject legitimate supported v1 PSBT forms or change canonical-v0, slot-selection, or signing-hash semantics.
6. **Rollback honesty:** the AEXS/AEXJ dispositions do not imply that checksums, same-directory ledgers, tombstones, random journal identifiers, or backups provide freshness against joint rollback.
7. **Recovery safety:** missing, restored, or unexpectedly reset journal/session history is never treated as evidence of safety; the documented response is to stop and use fresh independent keys for fund migration.
8. **Storage honesty:** Windows support requires an effectively owner-restricted DACL, and the documentation makes no encryption-at-rest or privileged-local-attacker claim.
9. **Witness-only boundary:** changing the supplied witness amount or script changes the exact signed BIP143 context; evidence binds that context and the transaction outpoint but does not attest chain-state existence or correctness.
10. **Standards compatibility:** retaining witness-only inputs is consistent with supported BIP174 SegWit workflows; requiring full previous transactions would be a deliberate compatibility and QR-size change, not a free hardening patch.
11. **No format expansion:** no AEXB, AEXS, AEXJ, frozen-vector, or SeedSigner wire behavior changes occur in these ranges.
12. **No unrelated weakening:** Gate 1 opening uniqueness, Gate 2 abort state, Gate 3 durability/bounds/locking, Gate 4 API contracts, Sparrow signature-scoped provenance, quarantine, finalization, and broadcast policy remain intact.

## Validation evidence

Drongo exact head `bb691c7`:

- Focused anti-exfil plus keystore ledger: 53 tests, 52 passed, 1 Windows-skipped POSIX test, 0 failures.
- Full suite: 484 tests, 481 passed, 1 skipped, 2 failures.
- The two failures are the unchanged environment-dependent `ApplicationDirTest.testXdgDirs` and `ApplicationDirTest.testXdgAppliedToMacos` cases on Windows.

Sparrow exact head `f003bfa` with Drongo exact pin `bb691c7`:

- Focused policy/signing-flow/transport set: 16/16 passed.
- Full root suite: 156 tests, 152 passed, 4 failures.
- The four failures are the already documented Windows CRLF/LF comparisons in unchanged Caravan, Coldcard (two cases), and Specter DIY export tests.

Frozen fixtures remain byte-identical:

- Semantic PSBT vector: `F28D572D1AE5D2060EEB52CA9814F37CE5D54258811D3AF18B78C41744E23A4E`
- Mixed-provenance vector: `DC350CC2F4AAFF593EA8D5A9B0145757D9C0370DA9AC3DB31228B1441FE8C2D1`

Both Drongo and Sparrow worktrees were clean after validation and generated-test-artifact removal.

## Reviewer questions

1. Does every production coordinator ingress use the newly verifying canonical parser, including create overloads, reload/revalidation, and exact-retry paths where relevant?
2. Can any invalid pre-existing partial survive parsing, consume host randomness, create durable state, or reach reconstruction?
3. Does the verifier accept every legitimate foreign partial supported by the protocol while leaving proof attribution strictly ceremony-derived?
4. Is there any same-storage-domain mechanism worth implementing that materially improves `#247987` or `#247988` without overstating rollback resistance or introducing a false sense of freshness?
5. Are the stop-and-fresh-key-migration instructions appropriate after suspected rollback or journal loss, and is any recovery step missing?
6. Does the Windows storage contract accurately describe effective DACL dependence and the residual exposure of plaintext rho?
7. Is the witness-only analysis correct: context manipulation causes invalidity for the actual coin rather than authorization of another real coin, while external chain-state correctness remains outside the evidence claim?
8. Would mandatory full previous transactions materially break supported PSBT/QR workflows, and is retaining witness-only compatibility therefore an explicit, coherent maintainer decision?
9. Is the exact Drongo pin correct, and did any production or test file outside the stated surface change?

## Hold point

Do not create replacement tested tags or freeze the reviewer bundle yet. Required remaining gates are independent Gate 5 review approval and public Linux CI. Existing tested tags remain immutable evidence of their earlier states.
