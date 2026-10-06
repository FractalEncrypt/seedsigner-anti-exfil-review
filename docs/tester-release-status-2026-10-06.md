# Windows tester release status

The reviewed Sparrow repair closes the sequential protected multisig blocker.
The retained SeedSigner and Kern firmware packages are unchanged. The current
Windows tester set pairs post-sync firmware with repaired Sparrow; the original
frozen set is archival material with known limitations.

## Source identity

The application was built and physically tested at Sparrow
`a132668f8f5db0bfacaf075c9dc958caaaadfecc`, with Drongo
`bdc8029fd970dec938630e5d9406261b791bf8d8` and Lark
`b15a676e592f82914c1bc662481ea8d8f0c90cd0`.
Its public source commit is
`bdca675348dc701eff4d5c29eb1f2fcf1780a934` on
`codex/sync-2026-09-sparrow`. The Git source trees are identical. Only commit
email metadata changed to a public noreply identity after GitHub rejected the
original private-email push. The binary was not rebuilt or relabelled as built
from a different commit.

## Qualification

The final automated suite recorded 1,098 tests, 1,096 passes, zero failures and
two platform/permission skips. Independent review covered the production change
at f622e720; the final a132668f changes were test-only. The Windows 10 laptop run
completed singlesig controls, all six 2-of-2 cells (both orders with RR/RO/OR),
explicit finalization, signed-PSBT reopen/proof restoration, and restart/policy
persistence. The operator confirms both QR rounds for every fresh matrix signer.
Saved signatures and transaction identities were independently checked.
Missing-proof and invalid-finalized negatives were photographed; the corrected
ordinary cross-tab scan passed. Firmware boot identity and interruption sequence
credit remain operator-reported, not reconstructed from signed PSBT files.

The operator confirmed the repaired application/transfer ZIP checksum on October
6. The unchanged application ZIP SHA-256 is
`ae64ce30762f278bae7fd18e1e497723409be61901cf3eae091df78d56719e51`.
Its fresh-profile addon SHA-256 is
`296400a683fe672ecdbba265a63905adcdf737a76cfcb3d4d044484d025cd7e5`.
Any convenience packaging must verify its contained files against these inputs.

The earlier V2.2 post-sync and frozen-firmware offline cycles also report passing
singlesig, rejection and recovery checks. M1 passed with repaired Sparrow and
both firmware sets. It remains blocked in the original, unfixed Sparrow bytes.
No repeated physical cycle is required solely to transcribe screen wording.

Physical 2-of-3 with this candidate, stale protected/foreign-context returns,
and duplicate-tab UI paths are not claimed as completed. Corresponding automated
coverage does not substitute for physical credit. Repaired Linux Sparrow has
not been packaged/qualified and is excluded from the current Windows tester set.

## Publication gates

Source integration is complete. Final asset integrity, corresponding sources,
native dependency mapping/notices, and draft completeness must pass before
publishing immutable experimental prereleases. GitHub release attestations are
the selected authentication mechanism; no personal OpenPGP or GitHub Actions
build-provenance claim is made for these local builds.

The original dated reviews/results remain intact. See the
[frozen baseline erratum](frozen-sparrow-erratum-2026-10-06.md) for archival scope.
