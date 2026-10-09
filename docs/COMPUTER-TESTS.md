# Optional computer and camera checks

These checks use Sparrow and a computer-connected camera. Device signing is not
needed for the malicious-signer simulation or the supplied ordinary return. Set up
public seed A's singlesig wallet using the [offline guide](offline-public-fixture-testing.html)
first; use the hardware route matching your device. Keep personal seeds out of this test.
Save results in [FEEDBACK.html](../FEEDBACK.html). All checks on this page are optional
for public testers; a single protected signing result is already useful.

## Launcher

Double-click the top-level **Start-Sparrow.cmd**. Confirm Sparrow opens with
**Testnet4** shown at the top right. On first launch the dedicated test profile
has no wallets. On later launches it retains its own wallets. The nested command
file is the helper called by Start-Sparrow.cmd, not a second tester entry point.

## Camera scans and cancel/reopen

Open [Camera-Check.html](../Test-cases/Camera-Check.html). Keep Sparrow offline and
public wallet A's **Protected signing Required**. Open **singlesig-A-first.psbt**,
click **Finalize Transaction for Signing**, and use the ordinary **Scan QR**.
Follow the instructions beside the QR. Record static, animated low, medium and
high separately. A successful decode gives **REQUIRED_PROOF_MISSING**: the
ordinary signature was read and rejected because Required demands protected proof.
High density is optional. A camera/decode error is not a policy-rejection pass.
For cancel/reopen, face the scanner away, cancel it, reopen it, then scan the low
QR and confirm the expected rejection and that camera access resumes.

## Required policy and restart

In public seed A's wallet **Settings**, set its keystore **Protected signing
Required → Apply**. Use the ordinary-return scan above and confirm
**Protected signature rejected / REQUIRED_PROOF_MISSING**, with no signature accepted.
Close Sparrow, relaunch with **Start-Sparrow.cmd**, reopen the same wallet, and
confirm Required remains selected. Repeat the ordinary scan and expect the same
refusal. Record the ordinary-refusal and policy-after-restart results separately.
Keep the signing history; no policy downgrade or history reset is needed.

## Dark Skippy-style malicious signer

Open [Open-Test-Cases.html](../Test-cases/Open-Test-Cases.html), choose
**Sparrow — Dark Skippy-style malicious signer**, and follow its **Run the test**
steps beside the controls. The maintainer tested the browser exchange in Brave
and Firefox. If your browser blocks camera access for local files, try another
desktop browser and report its name/version and the exact error.

Run this demo last, after all signing, recovery and live tests. It deliberately replaces the public Seed A transaction session. Run this demo last, after all signing, recovery and live tests. It deliberately replaces the public Seed A transaction session. There is one attack mode. **A, A2 and A3** are distinct fabricated transactions
for that same attack. Start with an unused transaction and use its matching PSBT
in Sparrow. Each two-round QR exchange must end with Sparrow refusing the valid
ordinary ECDSA signature as **SIGNATURE_INVALID: Anti-exfil signature verification
failed**. Camera, decoding and session-mismatch errors do not demonstrate attack
rejection. One successful rejection is enough; A2/A3 are reserves if needed.
Do not repeat an already used transaction just to fill every feedback field.
SeedSigner and Kern are not used; this page plays the malicious signing device.

## Public server and UTXOs

For live connectivity, follow [Connect Sparrow to Testnet4](end-to-end-testnet-testing.html#1-connect-sparrow-to-testnet4).
Use its public-server settings; a local Core/Knots node is not required. Connect
and confirm the status indicates a connection. In a funded disposable test wallet,
confirm expected UTXOs. If the wallet is unfunded, record connection status and
leave the UTXO part Partial or Not run rather than claiming a funded-wallet pass.

## Network toggle and views

After configuring the server in **Settings**, switch the bottom-right connection
toggle off and on. Confirm disconnection and reconnection. In the disposable wallet,
open **Receive** and confirm an address appears; open **Send** and confirm the
transaction controls load. No additional spend is required for this view check.
