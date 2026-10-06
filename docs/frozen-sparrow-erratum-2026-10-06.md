# Frozen Sparrow limitations and repaired successor

October 6, 2026. The original review baseline and its evidence remain unchanged.
This notice updates their scope; it does not replace their artifacts or rewrite
historical test results.

Frozen Sparrow `cc760814c855dfaf3d27890d10ba86b635e3a033` and original post-sync
Sparrow `9eba0b9f3e8e682c16e0bbef2dfb035ddfc68a83` contain the sequential protected
multisig proof-integration defect: the early completion gate checks the second
return without the first cosigner's retained proofs and can reject with
REQUIRED_PROOF_MISSING before the validated merge is reached. The original
frozen laptop M1 record is Blocked. Its later Pass is explicitly **only with
repaired Sparrow**, not the original frozen application ZIP.

The repaired successor was built/tested at a132668f; its identical public source
tree is published at bdca6753. Physical tests support the 2-of-2 Windows paths
listed in [current qualification](tester-release-status-2026-10-06.md), paired
with unchanged firmware. This does not retroactively qualify the old binaries.

An exploratory frozen companion backport was excluded after independent review
found a pre-existing invalid-finalized Optional-signature acceptance in the
older Drongo path. That backport is not a qualified release and must not be
substituted for the reviewed successor. The frozen archive is for historical
review/reproduction, not the recommended signing application.

Normal frozen SeedSigner is a rebuild from frozen sources. The unchanged
instrumented campaign image is separately labelled. Preserved frozen Kern was
built at 5180dbb, with review-source binding bc382c2 containing later fixture
changes. These distinctions and exact hashes remain in the release manifests.

Use the current repaired Windows tester set for new tests, or deliberately pair
its repaired application with frozen device firmware to investigate compatibility.
Keep that mixed pairing explicit in results. Immutable releases retain original
assets/tags; a successor and this dated notice provide the correction.
