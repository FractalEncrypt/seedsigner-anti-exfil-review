# Review bundle v2 manifest and exclusions

The deterministic v2 archive is built by
`scripts/build_review_bundle_v2.py` from exact committed Git blob bytes, not
from line-ending-filtered working-tree files. Its verifier can bind every
payload back to the source commit with `--repo`. It contains:

- exact repository/evidence bindings and current review scope;
- the bounded M8 closure summary with every retained limitation;
- the P1–P3 integration summary;
- normative protocol, wire-format, transport, and threat-model documents;
- the reference oracle, public fixtures, generators, and tests;
- clean third-party build/test instructions and a reproduction checklist; and
- archive verification and sanitization tools.

It intentionally excludes:

- raw M8 campaign directories and physical/camera/serial captures;
- wallet profiles, databases, persistent settings, coordinator state, `.aexs`
  or `.aexj` files, and non-public secrets;
- Gradle, Docker, Buildroot, ESP-IDF, simulator, virtual-environment, and package
  build outputs or caches;
- local test logs and machine-specific absolute paths;
- firmware/images/application distributions; and
- the P5 review result, which does not exist when P4 is frozen.

Authenticated raw evidence stays local and is bound by the inventory hashes in
`docs/m9-evidence-bindings.json`. The earlier public v1.3 release remains the
historical detailed-review bundle; v2 need not duplicate every legacy image or
machine transcript.

The external P4.1 receipt records final Git identity, archive bytes/hash,
cross-line-ending-checkout determinism, Git-blob verification, internal
verification, and sanitization results. Publication is a separate
owner-authorized step after an accepted proportional P5 repair review.
