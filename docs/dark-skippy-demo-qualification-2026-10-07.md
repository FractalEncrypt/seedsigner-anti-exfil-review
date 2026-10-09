# Dark Skippy-style demo: qualification and scope

The novice instructions demonstrate Sparrow rejecting a public simulated
malicious signer. They use attack A first, then optional A2/A3 for fresh-session
repeats. The honest control remains in the automated checks and source fixture
set; it is not a required step in the novice guide.

The maintainer supplied two screenshots on October 7, 2026. The control shows
**Protected signatures verified. PSBT not finalized.** The attack shows
**Protected signing stopped** and
**SIGNATURE_INVALID: Anti-exfil signature verification failed** with no accepted
signature displayed. Their transaction IDs match the independently parsed
control and attack A PSBTs exactly. These are maintainer-observed camera/Sparrow
UI results, not an agent-performed camera or GUI test.

A2/A3 have fresh transaction IDs and pass the packaged coordinator checks.
Separate physical A2/A3 trials are not claimed. The current fixture generator
reproduces all four PSBTs byte-for-byte; their exact hashes are in
Test-cases/dark-skippy-simulator/public-fixtures.json.

The simulator accepts only the four configured PSBT hashes and matching fixed
message hashes, public seed A's key, input 0, SIGHASH_ALL and Testnet4. It checks
session, opening and host reveal continuity. The attack is an ECDSA adaptation
of a seed-encoding nonce technique; no malicious firmware or seed-recovery
exercise is claimed. The 13 signer-side rejection cases remain unchanged and
test malformed/malicious coordinator requests in the reverse direction.

Automated checks use the unchanged packaged Sparrow/Drongo signing flow and
UR codecs. Frontend checks exercise the actual bundle's current camera buttons
with synthetic video frames and verify stream release, reset and case switching.
That model does not substitute for physical camera or browser permissions.

Existing application/firmware qualification remains intact. Single-device
multisig walkthroughs, other boards and macOS/Linux downloadable packages are
not newly physically qualified by this demo. Release publication remains subject
to source/notice gates, Devin's review, maintainer review and explicit approval.
