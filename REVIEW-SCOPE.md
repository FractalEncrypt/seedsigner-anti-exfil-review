# Review scope and immutable inputs

The v2 candidate binds five implementation repositories and this reference hub.
Exact commits and trees are authoritative; local branch names are descriptive
only. New P1–P3 candidates are not yet public tags.

| Component | Candidate commit | Candidate tree | Basis |
| --- | --- | --- | --- |
| Drongo | `948f586f0e523e0ef67d973a72eac67aa8148968` | `d5943708b3cb71779e7c2cd5fbf931dcf67e54d4` | August hardened head plus all five M8 changes |
| Sparrow | `cc760814c855dfaf3d27890d10ba86b635e3a033` | `6ce0ff0953560008e1832929540e5c2ebdb5b042` | August hardened head plus all thirteen M7/M8 changes; pins P1 Drongo |
| SeedSigner | `214793df4f51466179b792420921b8cdd8d0c1ac` | `97308cf847e0415737f72e64a60c8aa6c745a0bc` | Existing accepted public tag |
| SeedSignerOS | `0bf1dc92519906c7db265055abfb07e0ee344342` | `1ed46cd81f95c9b372c5248e30b883ac33c13a0c` | Existing accepted public tag; Buildroot `bf2a2858…` |
| Kern | `bc382c2c458e81230b5c0c434cd5b2219eef76b6` | `196a182647ded7825d0f3e524d72a611add70950` | M8-accepted product commit plus P3 fixture-byte portability fix |

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

The public v1.3 release remains immutable historical context. P5 should assess
the new v2 delta and may revisit older areas when it identifies a concrete risk.
