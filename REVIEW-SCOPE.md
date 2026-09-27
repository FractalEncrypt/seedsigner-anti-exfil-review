# Review scope and immutable inputs

The current review set binds five implementation repositories and this
reference hub. Drongo, Sparrow, SeedSigner, and SeedSignerOS retain their v2
identities. Kern advances from its original v2 identity through a separately
accepted six-commit post-M9 line.
Exact commits and trees are authoritative; branch and tag names are discovery
aids only. The later M9 hardening identities are separately identified below;
this local closure update does not publish them.

| Component | Candidate commit | Candidate tree | Basis |
| --- | --- | --- | --- |
| Drongo | `948f586f0e523e0ef67d973a72eac67aa8148968` | `d5943708b3cb71779e7c2cd5fbf931dcf67e54d4` | August hardened head plus all five M8 changes |
| Sparrow | `cc760814c855dfaf3d27890d10ba86b635e3a033` | `6ce0ff0953560008e1832929540e5c2ebdb5b042` | August hardened head plus all thirteen M7/M8 changes; pins P1 Drongo |
| SeedSigner | `214793df4f51466179b792420921b8cdd8d0c1ac` | `97308cf847e0415737f72e64a60c8aa6c745a0bc` | Existing accepted public tag |
| SeedSignerOS | `0bf1dc92519906c7db265055abfb07e0ee344342` | `1ed46cd81f95c9b372c5248e30b883ac33c13a0c` | Existing accepted public tag; Buildroot `bf2a2858…` |
| Kern | `6894087db687e7febf7ccafe4429d8a0446a3ba5` | `fb38f6d2b25b588f8f8db0d2d9103f5ce8d6f393` | Original v2 candidate plus accepted sanitizer/formatter, dependency, and Wave 7B remediation line |

The review-hub commit and tree are recorded by `BUNDLE-METADATA.json` and the
external P4 candidate receipt because a file cannot recursively contain its own
final Git identity.

## Claims to review

- The sign-to-contract construction and canonical AEXB/AEXT framing remain
  fail-closed across supported parsing and transition paths.
- PSBT slot attribution, frozen-context binding, signature provenance,
  persistence, retry/abort handling, and final-action quarantine retain both the
  August hardening and M8 changes in the integrated Drongo/Sparrow trees.
- SeedSigner and Kern implement the bounded signer-side protocol described by
  their exact sources and test evidence.
- The documented source, test, and build procedures are sufficient for a clean
  third-party reproduction without the campaign workstation.
- M8 closure is accurately summarized without expanding any bounded claim.

## Explicit non-claims

- No upstream acceptance, production readiness, mainnet recommendation, formal
  proof, or complete independent production security audit.
- No automatic transfer of physical M8 credit to the new integrated trees.
- No threshold-completion claim for M8 P04/P05, physical C3 claim for D/P01, or
  all-campaign zero-finalization/zero-broadcast claim.
- No bit-for-bit firmware/image reproducibility claim across uncontrolled hosts.
- No Jade implementation is included or evaluated by this bundle; issue #1 is
  coordination context for later work.

The public v1.3 release remains immutable historical context. P5/P5.1 accepted
the v2 integration and portability repair with no blocker. Outside reviewers
are invited to reassess any new or older area when they identify a concrete
risk; those model-based reviews are not a substitute for community scrutiny.

## Kern identity history and post-publication work

The original public v2 Kern identity was `bc382c2c…`, tree `196a182…`. It
remains immutable historical context. The current accepted source candidate is
its linear six-commit descendant `6894087…`, tree `fb38f6d…`:

| Commit | Tree | Purpose |
| --- | --- | --- |
| `ddd95c4db62f04d2e52f38a99bdd93ceb8eab024` | `bf286659113327868af7062ba2c33afa13e1b9a8` | Pin and qualify host sanitizer toolchains. |
| `d393a2c74c7649034a19723eeadf5e6c1e2c3e07` | `2e47a4b9b4c8f5b6885737377113cdeb9b086f59` | Pin clang-format 18.1.8. |
| `868e3573aa2429e0759ed6c537e4cd6a3be375db` | `9eb0f8f76a3d51c782063ca78394efd1e8ea1f96` | Apply the separately verified mechanical formatting pass. |
| `88a1a4b792e23330d086bd04ca0b49dc4d9615b2` | `2dbb992e424b3d1d850200ebcddb799bf10f73af` | Apply the accepted `esp_video` 2.5 dependency repair. |
| `0e0f853fc2ebca3e7f6901b0ec3934bea3639d68` | `e6e709085fe98898ea59cff7560b2136c2d5cf66` | Select the Wave 7B 32 MB image header and remove duplicate brightness initialization. |
| `6894087db687e7febf7ccafe4429d8a0446a3ba5` | `fb38f6d2b25b588f8f8db0d2d9103f5ce8d6f393` | Reject uninstrumented simple-suite sanitizer binaries. |

The independent follow-up review accepted `6894087…` with no low-or-higher
finding. The hash-bound remediation manifest is
`ffa0d7a241ba165c3fa9eafc1e43cc4cc17fa5a8e1033b5c05c0927aa40390ae`;
the accepted review report is
`e570af3b807e6424c2e277646fbf6d4348d9c2c841664dfae4109c40b8789d0d`.
See the [accepted update record](docs/post-m9-kern-ci-formatting-accepted-update.md).

The earlier hardening campaign also used three distinct identities:

| Purpose | Commit | Tree | Publication status |
| --- | --- | --- | --- |
| H3 dependency repair candidate | `ac2f1382d62072e3dd150d7626d04b96ff4af89a` | `44413413d87ebb495764307f59ac983a12311adb` | Historical sibling candidate; its two-file repair is carried on the accepted line by `88a1a4b…`. |
| H25/H26/H27/H30 telemetry | `1def1b9a6049f3f57f19205e5b20aed4abb13374` | `4193a00544107bea480086febdc762f5cd16a574` | Source-modifying measurement branch; evidence only, not a product/publication candidate. |
| H30 case-4 diagnostic | `5bddd829ae9e284b055b2ea5d9778afdd7fd014c` | `68c3ba177d50df42033a29c83426badfb0083a84` | Compile-time-off-by-default diagnostic; evidence only, not a product/publication candidate. |

The historical H3 diff from the original v2 Kern commit is exactly
`dependencies.lock` plus `main/idf_component.yml`. Its accepted claim is a
six-board ESP-IDF 6.0.2 tested-build boundary, not physical camera/screen
behavior. See the [M9 hardening closure](docs/m9-hardening-closure.md) for the
full H01–H33 disposition and all retained limitations.
