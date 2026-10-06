# Offline laptop tests in execution order

This is the complete test procedure for a laptop with the candidate packages
already installed. **Start here and follow sections 0–11 in order.** You do
not need the quickstart or the separate recovery document during this run;
all recovery instructions are included below.

Use the current repaired Sparrow application with the chosen device firmware.
Most testers need one post-sync run. A deliberate frozen-device compatibility
run uses frozen firmware and a separate repaired-app profile; it does not use
the original unfixed frozen Sparrow. Keep each pairing's result separate.

Stay offline on Testnet4 throughout. No server, faucet, funded wallet, Docker,
WSL, Git, or Java installation is needed. Open the kit's **Open-Test-Cases.html**
locally for seed QRs and rejection QRs. These are public seeds and synthetic
transactions: never use them for mainnet funds or broadcast these PSBTs.

**public-offline-test-kit-v2.2.zip** corrects the PSBT parent transactions
that Sparrow rejected in v2/v2.1, and regenerates their matching ordinary
signed return. Extract it into its own folder and use its PSBTs throughout.
Seeds, fingerprints, descriptors, rejection QR payloads, application packages,
and firmware are unchanged. Existing seed/wallet setup can be kept only when
the fingerprints and derivations below match; the older kit used seed A on
both devices, whereas this kit uses seed B on Kern.

## 0. Open the correct application and prepare a results file

1. Use **Start-PostSync-Sparrow.cmd** from the current repaired Windows package.
   Confirm **Testnet4**, connection off, and profile
   `%LOCALAPPDATA%\AexTest\post-sync-p-a132668f`. Both devices must be flashed
   with the chosen firmware set. For deliberate frozen-device compatibility,
   use repaired **Start-Anti-Exfil.exe** in the application subfolder instead;
   its separate profile is `%LOCALAPPDATA%\AexTest\repair-p-a132668f`.
   Record the repaired application hash with whichever firmware set you use.
2. Extract the v2.2 kit completely into a new folder. Use its corrected
   PSBTs and updated guide. Verify its ZIP against the accompanying
   **SHA256SUMS-v2.2** file using the same checksum method as before.
3. Copy the simplified [post-sync results template](results-post-sync-template.md)
   or [frozen results template](results-frozen-template.md), matching your set,
   to a working folder. Name the copy **results-post-sync.md** or
   **results-frozen.md**, then open it in Notepad or any text editor. Keep the
   original template unchanged.
4. Fill the short setup fields once: date, Windows version, devices, and camera.
   Its firmware hashes identify the retained October 3 images; its application
   hash identifies the repaired convenience ZIP. Confirm they match the packages
   you verified; otherwise stop.
   Keep the verified **SHA256SUMS-v2.2** file beside your results file so you
   do not have to type the kit's long hash by hand.
5. After each test, replace that row's **Not run** with **Pass**, **Fail**, or
   **Blocked**, and optionally add a photo filename or brief note. Press
   **Ctrl+S**. You do not need to export logs, wallet files, or session files.

“Sanitized result” simply means this plain results file contains test outcomes
without private information. Public kit seed fingerprints and fixture names
are fine. Do not include production seeds, private wallet files, live session
secrets, or full personal paths. Optional photos should show only test screens;
record their filenames in Notes. You do not need to copy screen wording.
For an unexpected result, photograph the error if practical and record the
last step; brief wording from memory is enough if no photo is available.

Each PSBT is a different transaction. If you have already completed a named
v2 fixture, record that prior result rather than rerunning it and claiming a
fresh ceremony: Sparrow can reuse a completed result. The earlier October 3
kit's PSBT is different from these v2 fixtures. Do not delete session files
or journals to force a fresh challenge.

Intentional abandonment is at the end because it leaves durable history that
can affect later fresh sessions. If **Selective-abort history exists** already
appears, choose **No**, mark the affected test **Blocked**, and report it.

## 1. Load seed A on SeedSigner and seed B on Kern

Choose **A — SeedSigner** or **B — Kern** in the HTML seed dropdown. Scan that
seed QR on the device's seed-import screen, not its transaction-signing screen.
Use an empty BIP39 passphrase. Verify the fingerprint shown in the HTML and
`fixture-manifest.json` against the device.

| Device | Public seed | Singlesig derivation | Multisig derivation |
| --- | --- | --- | --- |
| SeedSigner | A; fingerprint `0fb882ff` | `m/84'/1'/0'` | `m/48'/1'/0'/2'` |
| Kern | B; fingerprint `05d027a5` | `m/84'/1'/0'` | `m/48'/1'/0'/2'` |

For SeedSigner, load seed A using **Scan**, confirm the seed, choose the test
network in Settings, and set anti-exfil signing to **Required**. Export the
loaded seed's xpub using **Single Sig → Native Segwit → Sparrow**, account 0.
Verify the export's fingerprint and path before importing it.

For Kern, choose **Load Mnemonic → From QR Code**, scan seed B, and complete
the empty-passphrase flow. In wallet settings choose **Network → Testnet**
and turn **Anti-exfil signing** on. From Home choose **Extended Public Key**,
select **Singlesig**, **Native SegWit**, and account **0**. Display its
key-origin/xpub QR and verify the fingerprint and `m/84'/1'/0'` derivation.
The signer test-network family supports the coordinator's Testnet4 key format.

Continue to section 2 below.

## 2. Create or verify the two named singlesig wallets

If these named wallets already exist with the same fingerprints, derivations,
and Required settings, verify them and keep them. Otherwise create them below.

Import only the account xpub into Sparrow. Do not import either mnemonic as
a Sparrow software wallet for these hardware-signing tests.

1. Confirm **Testnet4** and Sparrow's server connection is off.
2. Choose **File → New Wallet** and name it **Offline SeedSigner A** or
   **Offline Kern B**.
3. Select **Single Signature** and **Native Segwit**.
4. Choose **Airgapped Hardware Wallet**, then the matching **SeedSigner** or
   **Kern** import route. Use **Scan** to read the device's exported xpub QR.
5. Verify its fingerprint and derivation against the HTML seed display.
6. Set **Protected signing → Required** for that keystore, then **Apply**.
   Maximize the window or scroll the keystore pane if the dropdown is clipped.
   Reopen Settings to verify the saved value; a clipped dropdown is not a pass.
7. Save the wallet. Any wallet password used here must be disposable too.

Repeat for the other device using its separate seed and named wallet.

## 3. Complete protected singlesig signing on both devices

Do this first with SeedSigner A, then with Kern B.

Choose `singlesig-A-first.psbt` with SeedSigner A, or
`singlesig-B-first.psbt` with Kern B. The input is 100,000 sats, payment
20,000 sats, change 79,500 sats, and fee 500 sats. Check those values on the
signer. Stop if its displayed fee or change differs; do not approve blindly.

1. Choose **File → Open Transaction → File** and open the matching PSBT.
2. Click **Finalize Transaction for Signing**, selecting the matching wallet
   when asked. The **Protected QR** button then becomes available.
3. Click **Protected QR**. Scan Sparrow's **Step 1 of 2** on the device.
4. Review and approve the transaction. Sparrow scans the device's opening QR.
5. Scan Sparrow's **Step 2 of 2** on the device. Review and approve the second
   request. Sparrow scans the device's protected-signature response.
6. Confirm **Protected signatures verified**. A message saying **PSBT not
   finalized** can be expected at this point. Do not broadcast.
7. In your results file, fill rows **S1** and **S2**, one for each device.
   For example: `Pass — Protected signatures verified; payment 20,000;
   change 79,500; fee 500; medium QR; no scan retries.` Use the setting
   actually used, not this example's density. Record a warning if one appeared.

Continue to section 4 below. Do not open another guide.


## 4. Complete Kern's next fresh ceremony

Keep seed B loaded on Kern and use **Offline Kern B**. You have just completed
`singlesig-B-first.psbt` in section 3.

1. Keep Kern's final response visible until Sparrow verifies it. Then exit
   Kern's response viewer, acknowledge its completion message, and return to
   its scanning/home flow. Keep Anti-exfil signing on.
2. In Sparrow choose **File → Open Transaction → File** and open
   `singlesig-B-next.psbt`. Check payment **24,000**, change **75,500**, fee
   **500 sats**. This is a different transaction from the first ceremony.
3. Click **Finalize Transaction for Signing**, choose **Offline Kern B** if
   asked, and click **Protected QR**. Confirm it starts at **Step 1 of 2**.
4. Scan Step 1 on Kern, review/approve, and scan Kern's openings into Sparrow.
   Scan Sparrow's Step 2 on Kern, review/approve, and scan Kern's protected
   signatures into Sparrow.
5. Confirm **Protected signatures verified**. Fill **K2** with the fresh Step 1
   and completion observations. Continue to section 5 below.

## 5. Complete offline 2-of-2 multisig

Keep seed A on SeedSigner and seed B on Kern. Export each account again using
**Multisig**, native SegWit P2WSH, account 0, with `m/48'/1'/0'/2'`.
Do not substitute the singlesig xpubs.

1. In Sparrow create **Offline 2of2 A-B**, select **Multi Signature**, **2 of
   2**, and native SegWit P2WSH.
2. Import A through SeedSigner and B through Kern, using the same hardware
   import routes as above. Verify both fingerprints and BIP48 derivations.
   Set each keystore's **Protected signing → Required**, then **Apply**.
3. Export the wallet's output descriptor. Compare its keys, threshold, paths,
   and sortedmulti policy with `multisig-A-B-descriptor.txt`. The kit also
   supplies `multisig-A-B-descriptor-qr.png` for descriptor import/review.
   Register/verify the wallet policy on the devices when prompted. Stop on a
   policy, fingerprint, or change-verification mismatch.
4. Open `multisig-A-B.psbt` and click **Finalize Transaction for Signing**,
   choosing **Offline 2of2 A-B**. Check payment 25,000 sats, change 74,500
   sats, and fee 500 sats.
5. Use **Protected QR**, select A, and complete both rounds with SeedSigner.
6. Use **Protected QR**, select B, and complete both rounds with Kern, using
   the same transaction. Do not replace it with the original unsigned file
   between signers.
7. Confirm both signatures are accepted with protected evidence and the quorum
   is complete. Do not broadcast the fixture. Record each signer separately.

8. Fill results row **M1**, recording the observed result for each cosigner. Continue to section 6 below.


## 6. Test device configuration mistakes and request rejections

Open **Open-Test-Cases.html**. Start with the configuration checks below, then
the dropdown corpus. Keep Sparrow offline and its keystores Required.

1. **Ordinary request while device protection is on (D1):** use Sparrow's
   ordinary unsigned transaction QR, if available, and scan it with device
   protection enabled. Expect a signing-mode rejection. Do not approve ordinary
   signing. If this QR export is unavailable under your Required settings,
   record **Not run — ordinary QR export unavailable**; do not disable Sparrow's
   Required policy to make it available.
2. **Protected request while device protection is off (D2):** keep the seed
   matching that device's singlesig wallet loaded. Open its
   `singlesig-A-pre-reveal.psbt` or `singlesig-B-pre-reveal.psbt`, prepare it
   for signing, and display **Protected QR → Step 1 of 2**. Turn protected
   signing off on the device, scan Step 1, and expect a request to enable it.
   Restore the device to Required/on. Close Sparrow's Step 1 QR **before
   accepting any nonce-opening response**, so no host reveal is displayed.
   The same retained Step 1 can be used later in section 8.
3. **Dropdown corpus (D3–D6):** load **seed A on each device you test**, including
   Kern, with no passphrase. Set the device's test network and protected
   signing Required/on. Use the device's Scan action to scan each selected
   rejection case below.

Start with the wrong-network, wrong-stage, and duplicate-slot dropdown cases.
Before scanning these cases, expect different refusal timing: SeedSigner
slugs **05–09 and 11** can enter transaction review before refusing on the next
screen. For **12/13**, follow review through **Approve Protected Signature**
to reach the refusal. Kern can reject these immediately on scan. This is the
reported post-sync v2.2 behavior; frozen behavior still needs qualification.

For each, use the device's **Scan**, confirm refusal with no signature, and
mark Pass or record an unexpected result. A photo can supply the wording.
SeedSigner can show a specific `AE_...` code; Kern can reject earlier with
**testnet-only**, **Wrong protected signing stage**, or **Invalid protected
signing request**. No signature may be produced. Later corpus cases may stop
at earlier validation gates; a generic rejection does not prove that every
deeper check was reached. The corpus's named expectations are SeedSigner
expectations, not a claim of identical Kern UI coverage.

Choose **medium** density first. It reduces a common 110-frame loop to
42 frames; **high** uses 22. Fewer frames do not guarantee faster camera
scanning: try **low**, slower frame rate, different distance, or less glare if
progress stalls. Record the density actually used. New densities still need
physical camera qualification.

Fill **D1–D6** as you go. For example: `Pass — Kern displayed Wrong protected
signing stage; no response/signature QR.` For other dropdown cases you try,
list the slugs tried and Pass/Fail/Blocked. Photo filenames are optional. Leave untried cases as Not run.

After the rejection checks, restore **seed B (05d027a5) on Kern**, with the
empty passphrase and Anti-exfil signing on. Keep seed A on SeedSigner.
This restores the seeds matching your named wallets for the recovery tests.
Continue to section 7 below.


## 7. Confirm Sparrow rejects an ordinary signed return

This checks Sparrow's Required-policy return path once; it is not a test that
each physical device generated an ordinary signature.

1. Open `singlesig-A-first.psbt` with **Offline SeedSigner A** and prepare it
   using **Finalize Transaction for Signing**.
2. Do not click Protected QR. Use **Scan QR** to scan the ordinary signed-return
   QR shown in the HTML. It has a valid ordinary ECDSA signature and no
   matching protected-ceremony proof.
3. Expect **Protected signature rejected** / `REQUIRED_PROOF_MISSING`, with
   no accepted signature and no fallback. Record the result.

4. Mark **P1** Pass/Fail/Blocked; a photo can supply the error wording. Continue to section 8 below.


## 8. Cancel before the reveal, then restart

Do the following with SeedSigner A, then Kern B. Use **Offline SeedSigner A**
and `singlesig-A-pre-reveal.psbt` for A; use **Offline Kern B** and
`singlesig-B-pre-reveal.psbt` for B. Keep Required protected signing enabled.

1. Open the matching PSBT with **File → Open Transaction → File**. Click
   **Finalize Transaction for Signing**, choose the matching wallet if asked,
   then click **Protected QR**.
2. Confirm Sparrow shows **Step 1 of 2**. Close that QR window with its **X**,
   before scanning it on the device. Do not advance to Step 2.
3. Confirm Sparrow has not accepted a signature.
4. Click **Protected QR** again on the same transaction. Complete both rounds:
   scan Step 1 on the device, return its openings to Sparrow, scan Step 2 on
   the device, then return its protected signatures to Sparrow.
5. Confirm **Protected signatures verified**, without ordinary-signing fallback.
   Fill **R1-A** or **R1-B**: `Cancelled at Step 1; restarted; verified` plus
   an optional photo filename. After both devices, continue to section 9 below.

## 9. Interrupt after the reveal and retry the exact session

Do this with SeedSigner A, then Kern B, using `singlesig-A-post-reveal.psbt`
or `singlesig-B-post-reveal.psbt` and its matching singlesig wallet.
Pause the device before it scans Step 2. This avoids asking Kern to recreate
signatures after its completed response viewer has been dismissed.

1. Open the matching PSBT. Click **Finalize Transaction for Signing**, choose
   the matching wallet if asked, then **Protected QR**.
2. Scan Step 1 on the device, review and approve, then scan its openings into
   Sparrow. Confirm Sparrow displays **Step 2 of 2**.
3. **Do not scan Step 2 on the device yet.** Leave it ready for the second
   request. Close Sparrow's Step 2 QR window with its **X**.
4. In **Protected signing is incomplete**, choose **Retry exact session**.
5. Confirm Sparrow returns directly to **Step 2 of 2**, rather than a fresh
   Step 1. Scan this retained Step 2 on the device, review and approve, then
   scan its protected signatures into Sparrow.
6. Confirm **Protected signatures verified**. Fill **R2-A** or **R2-B** with
   Pass/Fail/Blocked; optionally note the chosen button or a photo filename. After both
   devices, continue to section 10 below.

Post-sync Kern's second-round disclosure about coordinator-held session
continuity is expected. Keep the same transaction/session; do not switch to
ordinary signing or start a fresh challenge.

## 10. Abandon after the reveal and reopen the retained transaction

This is the last signing check for each key. Do it with SeedSigner A, then
Kern B, using `singlesig-A-abandon.psbt` or `singlesig-B-abandon.psbt`.
Do not delete coordinator state afterward; the recorded history is expected.

1. Open the matching PSBT. Click **Finalize Transaction for Signing**, choose
   the matching singlesig wallet if asked, then **Protected QR**.
2. Scan Step 1 on the device, review and approve, and scan its openings into
   Sparrow. Confirm Sparrow displays **Step 2 of 2**.
3. Do not scan Step 2 on the device yet. Close Sparrow's Step 2 QR with its
   **X**. In **Protected signing is incomplete**, choose **Abandon session**.
4. Confirm no signature was accepted. Close the transaction tab.
5. Reopen the **same** abandonment PSBT, prepare it for signing with the
   **same** wallet, and click **Protected QR**.
6. Confirm the retained ceremony resumes at **Step 2 of 2**. Scan that reveal
   on the device, review and approve, then return its protected signatures
   to Sparrow. Confirm verification and fill **R3-A** or **R3-B**.

An unexpected fresh Step 1 for that retained transaction, lost session, or
ordinary fallback fails this test. Stop and record the first failure.
Starting a different transaction after recorded abandonment can show
**Selective-abort history exists**, even after the retained ceremony completes.
If it appears, choose **No** and record it; do not bypass it or erase history.

## 11. Save this run

Save results and keep the application profile and journals intact. Leave
untried cases Not run. Send the results and verified checksum file, with
optional photos; do not send wallet databases or the entire profile.

For another firmware pairing, close Sparrow, verify and flash that firmware
using the download guide, then use the matching isolated repaired launcher
from section 0. Record a separate result with the repaired Sparrow package
identity. Do not substitute the original, unfixed frozen Sparrow.
## Optional explanation of the malicious nonce model

The HTML includes a reproducible Python cryptographic model example: an
ordinary valid ECDSA signature with a small chosen nonce fails the anti-exfil
opening check, while the honest control passes both checks. Values are in
`malicious-nonce-model.json`. This illustrates a check relevant to malicious
nonce attacks. It is not a physical Dark Skippy test or a full attack simulator.
A fixed response QR from a different session would mostly test session
rejection, so it would not establish that the live malicious-nonce check ran.
