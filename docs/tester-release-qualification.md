# Historical package qualification record

October 6 successor update: [current repaired Windows qualification](tester-release-status-2026-10-06.md) closes the M1 blocker for a132668f with either firmware set. The table below retains the October 4 original-package observations; it does not describe the repaired successor. [Frozen erratum](frozen-sparrow-erratum-2026-10-06.md) applies to original Sparrow.

These checks qualify exact downloaded packages, separately for the frozen and post-sync sets. Historical results and successful source builds are references, not substitutes. Publication follows successful qualification and completion of license/source records. Use disposable public test data; never share production seeds or live wallet/session files.

## Record before testing

Record the set, every package filename and SHA-256, manifest version, computer OS/version, SeedSigner model, Kern chip/revision, camera, QR density, and isolated profile path. Keep the original ZIPs unchanged. If a package changes, record the new hash and repeat affected tests.

## October 4 Windows checks (original application)

October 4 V2.2 update: the operator reports completing the post-sync
offline cycle using unchanged October 3 application/firmware ZIPs and verified
v2.2 fixtures. The previous old-kit observations remain historical evidence;
the following results describe the new run. Original notes and photos are
retained in the local V2.2 evidence assessment. Photos support individual
screens; interruption sequences are credited to the operator's report.

| Check | Frozen result | Post-sync result |
| --- | --- | --- |
| ZIP checksums and v2.2 kit verification | Pending | Reported Pass |
| Testnet4 offline; matching A/B identities; Required settings | Pending | Reported Pass |
| SeedSigner and Kern first protected singlesig | Pending | Reported Pass; medium QR, no retries |
| Kern next fresh ceremony | Pending | Reported Pass |
| 2-of-2 sequential protected multisig | Pending; matching source issue | Blocked: second-cosigner proof integration |
| Ordinary request/protection-off request rejection | Pending | Reported Pass on both devices |
| Wrong-network/wrong-stage/slot mismatch | Pending | Reported and photographed rejection; earlier Kern gates noted |
| Additional rejection corpus | Pending | Reported refusals; complete individual code coverage not independently established |
| Ordinary signed return under Required policy | Pending | Reported and photographed REQUIRED_PROOF_MISSING |
| Pre-reveal cancellation/restart A and B | Pending | Reported Pass; B completion photographed |
| Exact post-reveal retry A and B | Pending | Reported Pass; completions photographed |
| Abandon/reopen retained session A and B | Pending | Reported Pass; completions photographed |
| Clean install/profile isolation, ordinary Sparrow home unchanged, flash verification | Pending | Earlier setup reported working; individual checklist evidence incomplete |
| Restart retains Required policy and correct profile | Pending | Not separately recorded |

SeedSigner slugs 05–09 and 11 refused after entering review; 12/13 refused
after Approve Protected Signature. Kern rejected these upon scanning. This
does not establish that Kern reached each named deeper validation check.
The photo named Malicious nonce Protection documents ordinary-return rejection,
not a physical malicious-nonce test.

This table is retained historical evidence, not a current testing checklist.
Use the [current coverage record](tester-release-status-2026-10-06.md) for the repaired application. New standalone result forms accept Pass/Fail/Blocked and optional
photo references. Post-sync publication remains blocked on multisig.

## Linux checks

The Linux builds passed `jpackageImage` and `--version`. Linux desktop startup, native libraries, cameras, profile isolation, USB flashing, and the signing/rejection checks above are still pending. Record the tested distribution and architecture. If Linux packages are shipped before this trial, label their Linux qualification as pending; do not imply Windows results cover them.

## Publication checks

Before publishing each immutable experimental prerelease:

1. Attach complete matching assets, exact source/build manifests, checksums, licenses, dependency notices, and required corresponding sources to a draft.
2. Resolve missing-license warnings and distinguish unmodified originals from new builds. Record the historical Kern source/binary distinction and the instrumented SeedSigner image.
3. Retain laptop qualification results bound to exact package hashes. A failed required signing/rejection case blocks that set.
4. Verify the tag's commit, asset list, and immutability setting. Publish the draft only when its contents are complete.
5. Download the published assets again and run `gh release verify` and `gh release verify-asset`. Record attestation verification and the immutable marker.

GitHub attestations are the selected signature mechanism. Do not invent PGP signatures or describe locally built files as having GitHub Actions build provenance. An immutable release attestation binds the release identity and assets.
