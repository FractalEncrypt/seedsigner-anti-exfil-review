# Independent review bundle manifest

The engineering reference repository does not need to be public. An external
reviewer can receive a private, immutable archive containing the files below,
while cloning the four implementation repositories from their public tested
tags listed in `independent-security-review-brief.md`.

## Include

Normative and review documents:

- `docs/independent-security-review-brief.md`
- `docs/reviewer-build-and-test-runbook.md`
- `docs/security-review-findings.md`
- `docs/maintainer-decisions-requested.md`
- `docs/maintainer-specification.md`
- `docs/protocol-v1.md`
- `docs/protocol-v1-wire-format.md`
- `docs/transport-aext.md`
- `docs/threat-model.md`
- `docs/shared-vector-index.md`
- `docs/physical-evidence-index.md`
- `docs/ux-proposal.md`
- the four implementation review-series checkpoint JSON files
- the P6-F1 and R-F1 remediation briefs, physical gates, and evidence

Reference oracle and test material:

- `src/anti_exfil/`
- `tests/reference/`
- `scripts/generate_protocol_v1_vectors.py`
- `scripts/generate_protocol_v1_semantic_vectors.py`
- `fixtures/protocol-v1-multislot-vectors.json`
- `fixtures/protocol-v1-mixed-provenance-vector.json`
- `fixtures/protocol-v1-mixed-provenance.psbt`
- `fixtures/protocol-v1-semantic-psbt-vector.json`
- `fixtures/transport-v1-vectors.json`
- project packaging/dependency metadata required to run the reference tests

Evidence:

- checkpoint JSON/Markdown referenced by `physical-evidence-index.md`;
- selected redacted photographs listed there; and
- exact image, executable, branch, tree, CI, and transaction hashes.

The archive is produced by `scripts/build_private_review_bundle.py`. It refuses
to freeze a dirty reference worktree, uses fixed ZIP metadata, writes an
internal `SHA256SUMS.txt`, and prints the outer archive SHA-256. A dirty
`--allow-dirty` build is a candidate only and must not be supplied for review.
For a clean freeze it also writes an adjacent `.zip.sha256` sidecar containing
the outer archive hash.
The reviewer runbook gives exact immutable-tag clone, dependency, focused/full
test, package, SeedSignerOS normal/instrumented build, and physical-smoke steps.

## Exclude

- private wallet files, Sparrow profiles/databases, and persistent settings;
- mnemonics or descriptors other than explicitly public deterministic fixtures;
- funded PSBT working directories unless independently reviewed and sanitized;
- Docker/Buildroot caches, generated images, Gradle output, virtual
  environments, QR frame directories, camera recordings, and logs;
- machine-specific paths except where clearly labeled historical evidence; and
- the historical non-normative single-slot fixture unless requested for
  compatibility analysis.

## Delivery

A password-protected archive or private file share is sufficient for the first
review. Provide an outer SHA-256 out of band and include a generated manifest of
every internal file hash. Preserve the exact archive supplied to the reviewer.

The final freeze gate passed on 2026-08-20. The QR-renderer correction and Pi
Zero image passed static and animated brightness checks including animation
resumption. Sparrow's signature-scoped provenance remediation and narrow R-F1
raw-transaction lifecycle fix passed focused review, automated validation,
public Linux CI, packaging, and the documented physical UI gates. This is a
reviewed experimental prototype result, not a production security-audit claim.

Create a clean public docs/vector repository only if the selected reviewer
requires a cloneable Git source of record or if broader public review is later
desired. Do not publish the full engineering workspace merely to begin an
independent review.
