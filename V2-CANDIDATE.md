# Review-hub v2 reviewed publication candidate

Date: 2026-09-27
Status: **PUBLISHED V2 IDENTITY RETAINED; LOCAL POST-M9 KERN BINDING UPDATE AWAITS INDEPENDENT REVIEW AND SEPARATE PUBLICATION AUTHORIZATION**

This candidate incorporates the closed M8 result and retained limitations, the
P1 Drongo synthesis, P2 Sparrow synthesis, P3 signer/build work, exact repository
bindings, and a sanitized reproduction bundle.

The final review-hub commit/tree and archive bytes/SHA-256 are recorded outside
the Git tree in the publication-candidate receipt and inside the archive's generated
`BUNDLE-METADATA.json`. The archive contains an internal `SHA256SUMS.txt` and is
deterministically generated with fixed ZIP metadata.

P5 accepted the integrated candidate; P5.1 accepted the Git-blob portability
repair. P4.2 updates publication-facing status and reviewer guidance without
changing product identities, protocol behavior, or accepted limitations. These
fresh-context model-based reviews are evidence inputs, not a replacement for
the outside human and community review this repository now requests.

Model-review provenance spans Kimi K3 High, DeepSeek v4.1 Flash, and GLM 5.3
Flash used through Devin/Windsurf at different times, plus V12 reviewer-AI work
on Drongo. The final P5/P5.1 gates used DeepSeek 4.1 Flash in fresh Devin
conversations. None is represented as an independent human audit.

The earlier v1 bundle also received outside review input from BitcoinShooter
and an anonymous reviewer identified as “Joe.” They are acknowledged for that
historical contribution without implying review or endorsement of v2.

No additional publication, tag, push, release, issue update, upstream PR,
device activity, signing, funding, finalization, or broadcast is authorized by
this document. Publication of this closure update remains a separate
owner-authorized operation.

The previously published v1.3 bundle remains immutable historical evidence:
SHA-256 `08984dfdd39604f5470ab708a5d5da4bf6157c0e40dfb2d7f11f5dfdfa5da18a`.

## Post-publication M9 hardening closure update

The v2 review identity was subsequently published at review-hub commit
`88c92b062e6abb7aba5190235d4b2ec8de9c1a6f`. M9 then completed a separate
hardening track. A fresh H31 independent review accepted the consolidated
33-row ledger and made M9 eligible for bounded closure; the owner separately
authorized that closure on 2026-09-26.

The complete result is in [docs/m9-hardening-closure.md](docs/m9-hardening-closure.md).
It retains every finding, limitation, informational observation, resolved
packaging defect, and explicit residual required by H31. The update also keeps
the published Kern identity, H3 product-repair candidate, telemetry evidence
branch, and H30 diagnostic branch distinct.

This new commit is a local reviewer candidate only. It does not amend the
already-published commit, push itself, create a tag/release, or authorize
production, Mainnet, hardware, signing, finalization, broadcast, or upstream
activity.

## Accepted post-M9 Kern CI and formatting update

After bounded M9 closure, Kern's CI/formatting work proceeded on a clean linear
branch from the original v2 Kern identity. Independent review and follow-up
remediation accepted exact candidate
`6894087db687e7febf7ccafe4429d8a0446a3ba5`, tree
`fb38f6d2b25b588f8f8db0d2d9103f5ce8d6f393`, with no low-or-higher finding.
The source branch was separately authorized and published.

This review-hub candidate updates the current Kern binding and reviewer
instructions while retaining the original v2 identity and earlier M9 evidence
branches as historical layers. It introduces no protocol or reference-oracle
change and requires no new physical test. See the
[accepted update record](docs/post-m9-kern-ci-formatting-accepted-update.md) for
the six-commit ancestry, hash-bound evidence, build/flash observation, and
retained limitations.
