# Offline signing tests

**Optional additional checks: [Additional device, policy and recovery tests](DEVICE-TESTS.html).**
The single page supplies fresh PSBTs and complete steps/QRs. Completed
A→B/B→A and r4 restart checks are credited; all runtime and firmware bytes match r4.


Use this guide after [Start Here](download-and-test.md) setup, with Sparrow on **Testnet4** and its
server connection off. Open **Test-cases/Open-Test-Cases.html** in a browser
and keep it beside Sparrow. It supplies seeds, the multisig descriptor, the
malicious-coordinator rejection QRs (the signer side), and Sparrow's ordinary
signed-return QR. Every PSBT named below
is in the extracted kit's **Test-cases** folder.

Choose [**I have SeedSigner**](#i-have-seedsigner), [**I have Kern**](#i-have-kern),
or [**I have both**](#i-have-both) below. In the
HTML guide, the hardware selector shows just that route. In Markdown, jump to
your matching heading. Both devices use **public seed A** for singlesig;
**seed B is introduced only for optional multisig**.

Open **[FEEDBACK.html](../FEEDBACK-OFFLINE.html)** and click **Save feedback HTML** to keep an editable copy. Mark only
the tests you try; photos can replace typed error messages.

**Returning testers:** Sparrow retains completed fixtures and session history.
A restored result is not a fresh ceremony on another device. Keep the history
intact and report what you actually performed. Changing the hardware selector
only changes the instructions; it does not reset Sparrow or its profile.

Device rejection QRs are scanned by the signing device's camera. Sparrow's
computer camera scans the QR shown by the signing device. The separate
**ordinary signed-return** check needs a second screen or movable webcam.
The optional **Dark Skippy-style test** needs a movable webcam or DroidCam
that can read both Sparrow's QRs and this page's response QRs on your screen.

## I have SeedSigner

### Load seed A on SeedSigner

On SeedSigner choose **Scan** and scan **seed A** from **Open-Test-Cases.html**'s
seed dropdown. Load it without a passphrase and confirm fingerprint **0fb882ff**.
[Start Here](download-and-test.md) already configured Testnet and Required signing.

### Create Offline SeedSigner A in Sparrow

1. On SeedSigner, choose **Export xpub → Single Sig → Native Segwit**, then **Animated** or **Static**
   (either works), then **I understand → Export xpub** to show the QR.
2. In Sparrow choose **File → New Wallet**, name it **Offline SeedSigner A**, and select
   **Single Signature / Native Segwit (P2WPKH)**.
3. Choose **Airgapped Hardware Wallet → SeedSigner → Scan** and scan the
   device's account QR.
4. Confirm fingerprint **0fb882ff** and derivation **m/84'/1'/0'**.
5. Set **Protected signing → Required**, then click **Apply**. With Settings
   still visible, confirm Required remains selected. Keep this wallet open.

If this named wallet already exists with those keys, use it and confirm Required.

### Sign with SeedSigner

1. In Sparrow choose **File → Open Transaction → File**. Browse to the extracted
   kit's **Test-cases** folder and open **singlesig-A-first.psbt**.
2. Click **Finalize Transaction for Signing**.
   Click **Protected QR** to show **Step 1 of 2**.
3. On SeedSigner choose **Scan** and scan Step 1. Review payment **20,000 sats**,
   change **79,500 sats**, and fee **500 sats**, then approve.
4. Scan the device's first response into Sparrow's protected signing window.
   Wait for Sparrow to display **Step 2 of 2**.
5. On SeedSigner choose **Done → Scan host reveal**. Scan Step 2, follow the
   review/approval screens, and scan its final response into Sparrow.
6. Confirm **Protected signatures verified**. Keep the final device QR visible
   until Sparrow accepts it, then exit the QR viewer and return to the main menu.

A separate **PSBT not finalized** notice can appear; the result to record is
verification of protected signing. Mark **Singlesig — SeedSigner** in your feedback.
This is enough for a first report. The following tests are optional.

### Optional: 2-of-2 multisig

Keep A and B loaded together on your SeedSigner; choose the matching
seed for each signature.

These single-device steps are newly documented and have not yet received
end-to-end physical qualification. Two seeds on one device test the workflow;
they do not represent two independent physical signers.


### Create accounts A and B and the wallet

1. Get A ready on **SeedSigner**. Keep public seed **A** loaded and confirm **0fb882ff**.
2. Export A's multisig account: choose **Export xpub → Multisig → Native Segwit**, then **Animated** or **Static**
   (either works), then **I understand → Export xpub** to show the QR.
3. In Sparrow choose **File → New Wallet**, name it **Offline 2of2 A-B**, select
   **Multi Signature / 2 of 2 / Native Segwit (P2WSH)**. Import the first key
   through **Airgapped Hardware Wallet → SeedSigner → Scan**. Label it **A**
   and set **Protected signing → Required**.
4. Get B ready on **SeedSigner**. On SeedSigner choose **Scan** and scan **seed B** from **Open-Test-Cases.html**'s
   seed dropdown. Load it without a passphrase and confirm fingerprint **05d027a5**.
   [Start Here](download-and-test.md) already configured Testnet and Required signing.
   Export its multisig account: choose **Export xpub → Multisig → Native Segwit**, then **Animated** or **Static**
   (either works), then **I understand → Export xpub** to show the QR.
5. Import B into the second keystore through **Airgapped Hardware Wallet →
   SeedSigner → Scan**. Label it **B**, set **Protected signing → Required**,
   and click **Apply**.
6. With Settings still visible, confirm **2 of 2**, the two fingerprints, and
   **m/48'/1'/0'/2'** on both keystores.
   A is **0fb882ff** and B is **05d027a5**. Under **Descriptor → Edit**,
   compare the public keys/origins and `wsh(sortedmulti(2,...))` policy with
   the full descriptor text shown below its QR in **Open-Test-Cases.html**.

### Prepare the transaction and descriptor

1. In **Open-Test-Cases.html**, find **Multisig wallet descriptor**. Its QR is on the
   same page as the seed/rejection QRs; leave it available for signing.
2. Open **Test-cases/multisig-A-B.psbt** in Sparrow, click **Finalize Transaction
   for Signing**. Payment is **25,000**, change
   **74,500**, and fee **500 sats**.

### Get the signers ready

Keep **A selected on SeedSigner**.

SeedSigner loads the descriptor during transaction review when requested:
choose **Scan descriptor**, scan the policy QR, check its fingerprints/threshold,
then choose **Return to transaction**. Keep the QR available for later ceremonies.


### Sign A, then B

1. In the prepared transaction tab click **Protected QR**, select **A**, and
   scan Step 1 on **SeedSigner** with seed A selected. Review/approve the payment,
   change, and fee; load the descriptor during review if requested.
2. Scan the first device response into Sparrow. When it displays Step 2,
   choose **Done → Scan host reveal** on the device, scan Step 2, approve,
   and return the final QR to Sparrow. Wait for A's signature to be accepted.
3. Keep this transaction tab open; it holds A's signature. Select the loaded seed **B** on SeedSigner.
4. In the same transaction click **Protected QR**, select **B**, and complete
   both rounds on **SeedSigner**, including **Done → Scan host reveal** between
   rounds. Check the same payment, change, and fee.
5. Wait for Sparrow to accept B's protected signature before leaving its final
   QR viewer.
6. Confirm both signatures are accepted and Sparrow can finalize the transaction.
   Mark **Multisig** and your hardware arrangement in the feedback.

### Optional: Try the rejection QRs

These cases use **seed A**. After multisig, restore A without a passphrase,
confirm **0fb882ff**, and keep protection on. Select the loaded A seed on SeedSigner.

1. In **Open-Test-Cases.html**, find **Signer rejects a malicious coordinator request**. Choose the
   wrong-mainnet case from **Case**. Leave **Density** at **medium** initially.
2. On the device choose **Scan** and scan the animated QR through a full loop.
3. Follow any transaction-review screens until the device refuses the request.
   The test passes if there is a refusal and no signature response.
4. Try **wrong stage** and **duplicate slot** next. You may also try the other
   dropdown cases. Record case numbers and Pass/Fail; a photo supplies wording.

SeedSigner can enter review for cases **05–09 and 11** before showing refusal.
For **12/13**, continue through **Approve Protected Signature** to see it.
Messages differ between devices; an
earlier generic rejection does not demonstrate that every deeper check ran.

If scanning stalls, adjust distance/glare or lower the animation speed.
**High** density uses fewer frames but smaller QR modules; **low** makes the
modules easier to see. Use whichever your camera reads reliably.

**Open-Test-Cases.html** also explains two configuration mistakes: an ordinary request with
device protection on, and a protected request with device protection off.
If you try the second check, use the matching **pre-reveal** PSBT, stop before
Sparrow displays Step 2, and restore protection before continuing.

### Optional: Sparrow rejects a signed return without proof

Use your **Offline SeedSigner A** wallet with Required
signing. This checks Sparrow and uses its computer camera. Display **Open-Test-Cases.html**'s
**ordinary signed return** on a second screen/device, or aim a movable USB webcam
at your screen. A fixed laptop webcam cannot face its own screen: open the
extracted kit's viewer on a second computer, or copy **ordinary-signed-return-A-qr.png**
to a phone/tablet and display it there. This QR contains public test data only.

1. Open **singlesig-A-first.psbt** and click **Finalize Transaction for Signing**,
   with the existing seed-A wallet open.
2. Use the transaction's separate **Scan QR** button to scan the **ordinary
   signed return** displayed in **Open-Test-Cases.html**. Do not click Protected QR for this check.
3. Expect **Protected signature rejected** / **REQUIRED_PROOF_MISSING** and
   no accepted ordinary signature. Mark **Missing-proof rejection**.



### Optional: Cancel before the second round, then restart

Use **Test-cases/singlesig-A-pre-reveal.psbt** and your wallet for seed A.

1. Open the file, click **Finalize Transaction for Signing**, then click **Protected QR**.
2. At **Step 1 of 2**, close the QR window using **X** before scanning it on
   the device. No signature should have been accepted.
3. Click **Protected QR** again on the same transaction. Complete both rounds
   as in the first signing test.
4. Confirm **Protected signatures verified**. Mark **Cancel and restart**.


### Optional: Interrupt the second round and retry

Use **Test-cases/singlesig-A-post-reveal.psbt**, seed A, and its singlesig wallet. Keep the device ready for Step 2.

1. Open and prepare the file. Click **Protected QR**, scan Step 1 on the device,
   approve, and scan its opening response into Sparrow.
2. Choose **Done → Scan host reveal** on the device so it is ready for the
   second round. Sparrow now displays **Step 2 of 2**. **Do not scan it yet.**
   Close that QR window with **X**.
3. In **Protected signing is incomplete**, choose **Retry exact session**.
4. Confirm Sparrow returns directly to **Step 2 of 2**. Scan it on the waiting
   device, approve, and scan its final response into Sparrow.
5. Confirm **Protected signatures verified**. Mark **Retry second round**.


### Optional: Abandon and reopen — final device recovery check

Finish the device recovery checks here; this leaves a durable history entry.
The optional Sparrow-only demo follows.
Use **Test-cases/singlesig-A-abandon.psbt**, seed A, and its singlesig wallet. Leave the device waiting for the second round.

1. Open and prepare the file. Scan Step 1 on the device, approve, and return
   its opening response to Sparrow.
2. Choose **Done → Scan host reveal** on the device and leave it waiting.
   When Sparrow displays **Step 2 of 2**, leave it unscanned and close the QR
   window with **X**. Choose **Abandon session**.
3. Confirm no signature was accepted. Close the transaction tab.
4. Reopen the **same abandonment PSBT**, prepare it with the **same wallet**,
   and click **Protected QR**.
5. Expect the retained **Step 2 of 2**, not a new first round. Scan it on the
   waiting device and scan the final response back into Sparrow.
6. Confirm verification and mark **Abandon and reopen**.

Outside the deliberate public demo below, if a different transaction shows **Selective-abort history exists**,
choose **No** and record that warning. Leave Sparrow's history intact. These
files are separate transactions so each recovery check gets its own session;
reopening a completed file does not count as a new signing ceremony.

### Optional: See Sparrow reject a Dark Skippy-style signer — run last

This test uses **Open-Test-Cases.html** as a simulated malicious signer for up
to three fabricated Dark Skippy transactions using public test Seed A
(**0fb882ff**). You will use your computer camera to scan QRs from both Sparrow
and the page. SeedSigner and Kern are not used: the signing device is the
attacker here, and Sparrow must detect the malicious signature and reject it. A
malformed request sent to an honest device checks a different condition (the
device rejection cases above).

A fixed malicious response would not match Sparrow's fresh session and host
randomness. The page reads Sparrow's real two-round QRs and returns a valid
ECDSA signature for that exact session, using eight bytes of public seed A's
entropy as its nonce. The rejection must appear in **Sparrow itself**.

Run this **Dark Skippy test last**, after your other signing/recovery tests; the
deliberate rejection adds a durable history entry. Keep Sparrow offline on
Testnet4 and use your wallet for **seed A**, with **Protected signing →
Required**. You will need a computer-connected camera that can read this screen:
a movable USB webcam or DroidCam (a fixed laptop webcam cannot read its own
screen).

Open **Open-Test-Cases.html** in a desktop browser. The maintainer completed these tests in **Brave and Firefox**. Some browsers block
camera access for pages opened directly from disk; if the camera will not start,
try another desktop browser and report which one and version you used.

1. In **Open-Test-Cases.html**, choose **Sparrow — Dark Skippy-style malicious
   signer** in the **Case** dropdown.
2. In Sparrow choose **File → Open Transaction → File**, browse to the kit's
   **Test-cases** folder, and open **dark-skippy-attack-A.psbt**. Click
   **Finalize Transaction for Signing** and click **Protected QR**. Payment is
   **27,000 sats**, change **72,500**, and fee **500**. Leave **Step 1 of 2**
   visible. If **Selective-abort history exists** appears from an earlier
   recovery test, read it and choose **Yes** for this last deliberate public
   test; keep the history intact.
3. On **Open-Test-Cases.html**, click **Grant camera access** and allow the
   browser permission. **Read Sparrow Step 1** stays disabled until access is
   granted. Choose your movable camera in **Camera to use for reading
   Sparrow**, then click **Read Sparrow Step 1** and aim it at Sparrow's open
   animated Step 1 QR. Wait for a response QR; the page releases the camera
   automatically.
4. In Sparrow's open **Step 1 of 2** QR window click **Scan QR** and aim the
   camera at the page's animated response QR. Once Sparrow accepts it, Sparrow
   shows a new animated QR, **Step 2 of 2**.
5. On **Open-Test-Cases.html**, click **Read Sparrow Step 2** and aim the camera
   at Sparrow's Step 2 QR. The final response QR appears on the page; the page
   releases the camera again.
6. In Sparrow's Step 2 window click **Scan QR** and aim the camera at the page's
   final animated response QR. Expect Sparrow's **Protected signing stopped**
   dialog with **SIGNATURE_INVALID: Anti-exfil signature verification failed**.
   No signature from this attempt should be accepted.
7. In **FEEDBACK-OFFLINE.html**, mark the **Dark Skippy-style Sparrow QR test** Pass or
   Fail. A screenshot of **Sparrow's** dialog is optional supporting evidence.

**Congrats!** You've just defeated a (simulated) Dark Skippy attack trying to
steal your private key and all your bitcoin!

An invalid-QR, wrong-stage, session-mismatch, or camera error does not count as
the nonce-defense result. Report it if it occurs. The page's response-ready
message cannot see Sparrow's outcome and is not a pass result.

**Repeating the test:** Sparrow retains the session for each transaction;
reopening a used PSBT may resume Step 2. Click **Start over** on the page, then
open the next unused transaction: **dark-skippy-attack-A2.psbt**, followed by
**dark-skippy-attack-A3.psbt**. Each has a different transaction ID. Start over
clears only this page, and Sparrow keeps its history. After using all three,
stop here and report your results.

This demonstrates rejection of an **ECDSA adaptation of the [Dark Skippy nonce
technique](https://darkskippy.com/)** through the live coordinator exchange.
It uses a public browser simulator rather than malicious device firmware and
does not perform seed recovery. Its source and transaction identities are
included. The automated checks cover the shipped signing flow, transport,
ordinary signature validity, proof rejection, and durable non-completion; the
expected rejection has been observed in Sparrow.


## I have Kern

### Load seed A on Kern

From Kern's unloaded screen choose **Load Mnemonic → From QR Code**,
scan **seed A** from **Open-Test-Cases.html**, and finish loading without a passphrase.
Confirm fingerprint **0fb882ff**. Tap the orange circled **i** at the upper-left
of Home; in **Wallet Settings**, confirm **Network → Testnet** and **Anti-exfil
signing** on, then return Home. For a longer session, you can set the
seed-unload timer to **30 minutes**.

### Create Offline Kern A in Sparrow

1. On Kern, choose **Extended Public Key**. Confirm the default **Singlesig → Native
   SegWit**, account **0**. The account QR is ready to scan. After importing,
   **Show xpub** lets you compare the text with Sparrow; **OK** exits.
2. In Sparrow choose **File → New Wallet**, name it **Offline Kern A**, and select
   **Single Signature / Native Segwit (P2WPKH)**.
3. Choose **Airgapped Hardware Wallet → Kern → Scan** and scan the
   device's account QR.
4. Confirm fingerprint **0fb882ff** and derivation **m/84'/1'/0'**.
5. Set **Protected signing → Required**, then click **Apply**. With Settings
   still visible, confirm Required remains selected. Keep this wallet open.

If this named wallet already exists with those keys, use it and confirm Required.

### Sign with Kern

1. In Sparrow choose **File → Open Transaction → File**. Browse to the extracted
   kit's **Test-cases** folder and open **singlesig-A-first.psbt**.
2. Click **Finalize Transaction for Signing**.
   Click **Protected QR** to show **Step 1 of 2**.
3. On Kern choose **Scan** and scan Step 1. Review payment **20,000 sats**,
   change **79,500 sats**, and fee **500 sats**, then approve.
4. Scan the device's first response into Sparrow's protected signing window.
   Wait for Sparrow to display **Step 2 of 2**.
5. On Kern choose **Done → Scan host reveal**. Scan Step 2, follow the
   review/approval screens, and scan its final response into Sparrow.
6. Confirm **Protected signatures verified**. Keep the final device QR visible
   until Sparrow accepts it, then exit the QR viewer and return to the main menu.

A separate **PSBT not finalized** notice can appear; the result to record is
verification of protected signing. Mark **Singlesig — Kern** in your feedback.
This is enough for a first report. The following tests are optional.

### Optional: 2-of-2 multisig

Kern holds one seed at a time. After exporting A, unload/restart Kern
and load B to export it; reload A for signing, then B for its signature.

These single-device steps are newly documented and have not yet received
end-to-end physical qualification. Two seeds on one device test the workflow;
they do not represent two independent physical signers.


### Create accounts A and B and the wallet

1. Get A ready on **Kern**. Keep public seed **A** loaded and confirm **0fb882ff**.
2. Export A's multisig account: choose **Extended Public Key → Multisig**. Confirm the default **Native
   SegWit** and **m/48'/1'/0'/2'**, account **0**, and show the account QR.
3. In Sparrow choose **File → New Wallet**, name it **Offline 2of2 A-B**, select
   **Multi Signature / 2 of 2 / Native Segwit (P2WSH)**. Import the first key
   through **Airgapped Hardware Wallet → Kern → Scan**. Label it **A**
   and set **Protected signing → Required**.
4. Get B ready on **Kern**. Unload/restart Kern before loading B. From Kern's unloaded screen choose **Load Mnemonic → From QR Code**,
   scan **seed B** from **Open-Test-Cases.html**, and finish loading without a passphrase.
   Confirm fingerprint **05d027a5**. Tap the orange circled **i** at the upper-left
   of Home; in **Wallet Settings**, confirm **Network → Testnet** and **Anti-exfil
   signing** on, then return Home. For a longer session, you can set the
   seed-unload timer to **30 minutes**.
   Export its multisig account: choose **Extended Public Key → Multisig**. Confirm the default **Native
   SegWit** and **m/48'/1'/0'/2'**, account **0**, and show the account QR.
5. Import B into the second keystore through **Airgapped Hardware Wallet →
   Kern → Scan**. Label it **B**, set **Protected signing → Required**,
   and click **Apply**.
6. With Settings still visible, confirm **2 of 2**, the two fingerprints, and
   **m/48'/1'/0'/2'** on both keystores.
   A is **0fb882ff** and B is **05d027a5**. Under **Descriptor → Edit**,
   compare the public keys/origins and `wsh(sortedmulti(2,...))` policy with
   the full descriptor text shown below its QR in **Open-Test-Cases.html**.

### Prepare the transaction and descriptor

1. In **Open-Test-Cases.html**, find **Multisig wallet descriptor**. Its QR is on the
   same page as the seed/rejection QRs; leave it available for signing.
2. Open **Test-cases/multisig-A-B.psbt** in Sparrow, click **Finalize Transaction
   for Signing**. Payment is **25,000**, change
   **74,500**, and fee **500 sats**.

### Get the signers ready

Reload **A on Kern** from its seed QR in **Open-Test-Cases.html**.

On Kern, tap the orange **i**, confirm Testnet and anti-exfil on, then open
**Wallet Settings → Descriptors → Load Descriptor** (or **Load Other Descriptor**)
**→ From QR Code**. Scan the policy QR, check both fingerprints and **2 of 2**,
and choose **Keep for this session only**. Repeat this after any seed change
or timer unload.


### Sign A, then B

1. In the prepared transaction tab click **Protected QR**, select **A**, and
   scan Step 1 on **Kern** with seed A selected. Review/approve the payment,
   change, and fee; load the descriptor during review if requested.
2. Scan the first device response into Sparrow. When it displays Step 2,
   choose **Done → Scan host reveal** on the device, scan Step 2, approve,
   and return the final QR to Sparrow. Wait for A's signature to be accepted.
3. Keep this transaction tab open; it holds A's signature. Unload/restart Kern, load **B**, confirm Testnet/anti-exfil on, and
   load the same descriptor again using the policy-loading steps above.
4. In the same transaction click **Protected QR**, select **B**, and complete
   both rounds on **Kern**, including **Done → Scan host reveal** between
   rounds. Check the same payment, change, and fee.
5. Wait for Sparrow to accept B's protected signature before leaving its final
   QR viewer.
6. Confirm both signatures are accepted and Sparrow can finalize the transaction.
   Mark **Multisig** and your hardware arrangement in the feedback.

### Optional: Try the rejection QRs

These cases use **seed A**. After multisig, restore A without a passphrase,
confirm **0fb882ff**, and keep protection on. Unload/restart Kern and load A from **Open-Test-Cases.html**.

1. In **Open-Test-Cases.html**, find **Signer rejects a malicious coordinator request**. Choose the
   wrong-mainnet case from **Case**. Leave **Density** at **medium** initially.
2. On the device choose **Scan** and scan the animated QR through a full loop.
3. Follow any transaction-review screens until the device refuses the request.
   The test passes if there is a refusal and no signature response.
4. Try **wrong stage** and **duplicate slot** next. You may also try the other
   dropdown cases. Record case numbers and Pass/Fail; a photo supplies wording.

Kern may refuse immediately on scan; an
earlier generic rejection does not demonstrate that every deeper check ran.

If scanning stalls, adjust distance/glare or lower the animation speed.
**High** density uses fewer frames but smaller QR modules; **low** makes the
modules easier to see. Use whichever your camera reads reliably.

**Open-Test-Cases.html** also explains two configuration mistakes: an ordinary request with
device protection on, and a protected request with device protection off.
If you try the second check, use the matching **pre-reveal** PSBT, stop before
Sparrow displays Step 2, and restore protection before continuing.

### Optional: Sparrow rejects a signed return without proof

Use your **Offline Kern A** wallet with Required
signing. This checks Sparrow and uses its computer camera. Display **Open-Test-Cases.html**'s
**ordinary signed return** on a second screen/device, or aim a movable USB webcam
at your screen. A fixed laptop webcam cannot face its own screen: open the
extracted kit's viewer on a second computer, or copy **ordinary-signed-return-A-qr.png**
to a phone/tablet and display it there. This QR contains public test data only.

1. Open **singlesig-A-first.psbt** and click **Finalize Transaction for Signing**,
   with the existing seed-A wallet open.
2. Use the transaction's separate **Scan QR** button to scan the **ordinary
   signed return** displayed in **Open-Test-Cases.html**. Do not click Protected QR for this check.
3. Expect **Protected signature rejected** / **REQUIRED_PROOF_MISSING** and
   no accepted ordinary signature. Mark **Missing-proof rejection**.



### Optional: Cancel before the second round, then restart

Use **Test-cases/singlesig-A-pre-reveal.psbt** and your wallet for seed A.

1. Open the file, click **Finalize Transaction for Signing**, then click **Protected QR**.
2. At **Step 1 of 2**, close the QR window using **X** before scanning it on
   the device. No signature should have been accepted.
3. Click **Protected QR** again on the same transaction. Complete both rounds
   as in the first signing test.
4. Confirm **Protected signatures verified**. Mark **Cancel and restart**.


### Optional: Interrupt the second round and retry

Use **Test-cases/singlesig-A-post-reveal.psbt**, seed A, and its singlesig wallet. Keep the device ready for Step 2.

1. Open and prepare the file. Click **Protected QR**, scan Step 1 on the device,
   approve, and scan its opening response into Sparrow.
2. Choose **Done → Scan host reveal** on the device so it is ready for the
   second round. Sparrow now displays **Step 2 of 2**. **Do not scan it yet.**
   Close that QR window with **X**.
3. In **Protected signing is incomplete**, choose **Retry exact session**.
4. Confirm Sparrow returns directly to **Step 2 of 2**. Scan it on the waiting
   device, approve, and scan its final response into Sparrow.
5. Confirm **Protected signatures verified**. Mark **Retry second round**.

Kern may explain that the coordinator maintains first-round session continuity.
Keep the same transaction and session for this check.


### Optional: Abandon and reopen — final device recovery check

Finish the device recovery checks here; this leaves a durable history entry.
The optional Sparrow-only demo follows.
Use **Test-cases/singlesig-A-abandon.psbt**, seed A, and its singlesig wallet. Leave the device waiting for the second round.

1. Open and prepare the file. Scan Step 1 on the device, approve, and return
   its opening response to Sparrow.
2. Choose **Done → Scan host reveal** on the device and leave it waiting.
   When Sparrow displays **Step 2 of 2**, leave it unscanned and close the QR
   window with **X**. Choose **Abandon session**.
3. Confirm no signature was accepted. Close the transaction tab.
4. Reopen the **same abandonment PSBT**, prepare it with the **same wallet**,
   and click **Protected QR**.
5. Expect the retained **Step 2 of 2**, not a new first round. Scan it on the
   waiting device and scan the final response back into Sparrow.
6. Confirm verification and mark **Abandon and reopen**.

Outside the deliberate public demo below, if a different transaction shows **Selective-abort history exists**,
choose **No** and record that warning. Leave Sparrow's history intact. These
files are separate transactions so each recovery check gets its own session;
reopening a completed file does not count as a new signing ceremony.

### Optional: See Sparrow reject a Dark Skippy-style signer — run last

This test uses **Open-Test-Cases.html** as a simulated malicious signer for up
to three fabricated Dark Skippy transactions using public test Seed A
(**0fb882ff**). You will use your computer camera to scan QRs from both Sparrow
and the page. SeedSigner and Kern are not used: the signing device is the
attacker here, and Sparrow must detect the malicious signature and reject it. A
malformed request sent to an honest device checks a different condition (the
device rejection cases above).

A fixed malicious response would not match Sparrow's fresh session and host
randomness. The page reads Sparrow's real two-round QRs and returns a valid
ECDSA signature for that exact session, using eight bytes of public seed A's
entropy as its nonce. The rejection must appear in **Sparrow itself**.

Run this **Dark Skippy test last**, after your other signing/recovery tests; the
deliberate rejection adds a durable history entry. Keep Sparrow offline on
Testnet4 and use your wallet for **seed A**, with **Protected signing →
Required**. You will need a computer-connected camera that can read this screen:
a movable USB webcam or DroidCam (a fixed laptop webcam cannot read its own
screen).

Open **Open-Test-Cases.html** in a desktop browser. The maintainer completed these tests in **Brave and Firefox**. Some browsers block
camera access for pages opened directly from disk; if the camera will not start,
try another desktop browser and report which one and version you used.

1. In **Open-Test-Cases.html**, choose **Sparrow — Dark Skippy-style malicious
   signer** in the **Case** dropdown.
2. In Sparrow choose **File → Open Transaction → File**, browse to the kit's
   **Test-cases** folder, and open **dark-skippy-attack-A.psbt**. Click
   **Finalize Transaction for Signing** and click **Protected QR**. Payment is
   **27,000 sats**, change **72,500**, and fee **500**. Leave **Step 1 of 2**
   visible. If **Selective-abort history exists** appears from an earlier
   recovery test, read it and choose **Yes** for this last deliberate public
   test; keep the history intact.
3. On **Open-Test-Cases.html**, click **Grant camera access** and allow the
   browser permission. **Read Sparrow Step 1** stays disabled until access is
   granted. Choose your movable camera in **Camera to use for reading
   Sparrow**, then click **Read Sparrow Step 1** and aim it at Sparrow's open
   animated Step 1 QR. Wait for a response QR; the page releases the camera
   automatically.
4. In Sparrow's open **Step 1 of 2** QR window click **Scan QR** and aim the
   camera at the page's animated response QR. Once Sparrow accepts it, Sparrow
   shows a new animated QR, **Step 2 of 2**.
5. On **Open-Test-Cases.html**, click **Read Sparrow Step 2** and aim the camera
   at Sparrow's Step 2 QR. The final response QR appears on the page; the page
   releases the camera again.
6. In Sparrow's Step 2 window click **Scan QR** and aim the camera at the page's
   final animated response QR. Expect Sparrow's **Protected signing stopped**
   dialog with **SIGNATURE_INVALID: Anti-exfil signature verification failed**.
   No signature from this attempt should be accepted.
7. In **FEEDBACK-OFFLINE.html**, mark the **Dark Skippy-style Sparrow QR test** Pass or
   Fail. A screenshot of **Sparrow's** dialog is optional supporting evidence.

**Congrats!** You've just defeated a (simulated) Dark Skippy attack trying to
steal your private key and all your bitcoin!

An invalid-QR, wrong-stage, session-mismatch, or camera error does not count as
the nonce-defense result. Report it if it occurs. The page's response-ready
message cannot see Sparrow's outcome and is not a pass result.

**Repeating the test:** Sparrow retains the session for each transaction;
reopening a used PSBT may resume Step 2. Click **Start over** on the page, then
open the next unused transaction: **dark-skippy-attack-A2.psbt**, followed by
**dark-skippy-attack-A3.psbt**. Each has a different transaction ID. Start over
clears only this page, and Sparrow keeps its history. After using all three,
stop here and report your results.

This demonstrates rejection of an **ECDSA adaptation of the [Dark Skippy nonce
technique](https://darkskippy.com/)** through the live coordinator exchange.
It uses a public browser simulator rather than malicious device firmware and
does not perform seed recovery. Its source and transaction identities are
included. The automated checks cover the shipped signing flow, transport,
ordinary signature validity, proof rejection, and durable non-completion; the
expected rejection has been observed in Sparrow.


## I have both

Use **seed A on both devices**. Complete SeedSigner with **singlesig-A-first.psbt**,
then Kern with **singlesig-A-next.psbt**. These distinct transactions let Sparrow
perform a fresh ceremony for each device instead of restoring the first result.

### Load seed A on SeedSigner

On SeedSigner choose **Scan** and scan **seed A** from **Open-Test-Cases.html**'s
seed dropdown. Load it without a passphrase and confirm fingerprint **0fb882ff**.
[Start Here](download-and-test.md) already configured Testnet and Required signing.

### Create Offline SeedSigner A in Sparrow

1. On SeedSigner, choose **Export xpub → Single Sig → Native Segwit**, then **Animated** or **Static**
   (either works), then **I understand → Export xpub** to show the QR.
2. In Sparrow choose **File → New Wallet**, name it **Offline SeedSigner A**, and select
   **Single Signature / Native Segwit (P2WPKH)**.
3. Choose **Airgapped Hardware Wallet → SeedSigner → Scan** and scan the
   device's account QR.
4. Confirm fingerprint **0fb882ff** and derivation **m/84'/1'/0'**.
5. Set **Protected signing → Required**, then click **Apply**. With Settings
   still visible, confirm Required remains selected. Keep this wallet open.

If this named wallet already exists with those keys, use it and confirm Required.

### Sign with SeedSigner

1. In Sparrow choose **File → Open Transaction → File**. Browse to the extracted
   kit's **Test-cases** folder and open **singlesig-A-first.psbt**.
2. Click **Finalize Transaction for Signing**.
   Click **Protected QR** to show **Step 1 of 2**.
3. On SeedSigner choose **Scan** and scan Step 1. Review payment **20,000 sats**,
   change **79,500 sats**, and fee **500 sats**, then approve.
4. Scan the device's first response into Sparrow's protected signing window.
   Wait for Sparrow to display **Step 2 of 2**.
5. On SeedSigner choose **Done → Scan host reveal**. Scan Step 2, follow the
   review/approval screens, and scan its final response into Sparrow.
6. Confirm **Protected signatures verified**. Keep the final device QR visible
   until Sparrow accepts it, then exit the QR viewer and return to the main menu.

A separate **PSBT not finalized** notice can appear; the result to record is
verification of protected signing. Mark **Singlesig — SeedSigner** in your feedback.
This is enough for a first report. The following tests are optional.

### Load seed A on Kern

From Kern's unloaded screen choose **Load Mnemonic → From QR Code**,
scan **seed A** from **Open-Test-Cases.html**, and finish loading without a passphrase.
Confirm fingerprint **0fb882ff**. Tap the orange circled **i** at the upper-left
of Home; in **Wallet Settings**, confirm **Network → Testnet** and **Anti-exfil
signing** on, then return Home. For a longer session, you can set the
seed-unload timer to **30 minutes**.

### Create Offline Kern A in Sparrow

1. On Kern, choose **Extended Public Key**. Confirm the default **Singlesig → Native
   SegWit**, account **0**. The account QR is ready to scan. After importing,
   **Show xpub** lets you compare the text with Sparrow; **OK** exits.
2. In Sparrow choose **File → New Wallet**, name it **Offline Kern A**, and select
   **Single Signature / Native Segwit (P2WPKH)**.
3. Choose **Airgapped Hardware Wallet → Kern → Scan** and scan the
   device's account QR.
4. Confirm fingerprint **0fb882ff** and derivation **m/84'/1'/0'**.
5. Set **Protected signing → Required**, then click **Apply**. With Settings
   still visible, confirm Required remains selected. Keep this wallet open.

If this named wallet already exists with those keys, use it and confirm Required.

### Sign with Kern

1. In Sparrow choose **File → Open Transaction → File**. Browse to the extracted
   kit's **Test-cases** folder and open **singlesig-A-next.psbt**.
2. Click **Finalize Transaction for Signing**.
   Click **Protected QR** to show **Step 1 of 2**.
3. On Kern choose **Scan** and scan Step 1. Review payment **24,000 sats**,
   change **75,500 sats**, and fee **500 sats**, then approve.
4. Scan the device's first response into Sparrow's protected signing window.
   Wait for Sparrow to display **Step 2 of 2**.
5. On Kern choose **Done → Scan host reveal**. Scan Step 2, follow the
   review/approval screens, and scan its final response into Sparrow.
6. Confirm **Protected signatures verified**. Keep the final device QR visible
   until Sparrow accepts it, then exit the QR viewer and return to the main menu.

A separate **PSBT not finalized** notice can appear; the result to record is
verification of protected signing. Mark **Singlesig — Kern** in your feedback.
This is enough for a first report. The following tests are optional.

### Optional: 2-of-2 multisig

Keep **A on SeedSigner** and **B on Kern** for this multisig test.


### Create accounts A and B and the wallet

1. Get A ready on **SeedSigner**. Keep public seed **A** loaded and confirm **0fb882ff**.
2. Export A's multisig account: choose **Export xpub → Multisig → Native Segwit**, then **Animated** or **Static**
   (either works), then **I understand → Export xpub** to show the QR.
3. In Sparrow choose **File → New Wallet**, name it **Offline 2of2 A-B**, select
   **Multi Signature / 2 of 2 / Native Segwit (P2WSH)**. Import the first key
   through **Airgapped Hardware Wallet → SeedSigner → Scan**. Label it **A**
   and set **Protected signing → Required**.
4. Get B ready on **Kern**. Unload/restart Kern and replace its singlesig seed A with seed B:
   From Kern's unloaded screen choose **Load Mnemonic → From QR Code**,
   scan **seed B** from **Open-Test-Cases.html**, and finish loading without a passphrase.
   Confirm fingerprint **05d027a5**. Tap the orange circled **i** at the upper-left
   of Home; in **Wallet Settings**, confirm **Network → Testnet** and **Anti-exfil
   signing** on, then return Home. For a longer session, you can set the
   seed-unload timer to **30 minutes**.
   Export its multisig account: choose **Extended Public Key → Multisig**. Confirm the default **Native
   SegWit** and **m/48'/1'/0'/2'**, account **0**, and show the account QR.
5. Import B into the second keystore through **Airgapped Hardware Wallet →
   Kern → Scan**. Label it **B**, set **Protected signing → Required**,
   and click **Apply**.
6. With Settings still visible, confirm **2 of 2**, the two fingerprints, and
   **m/48'/1'/0'/2'** on both keystores.
   A is **0fb882ff** and B is **05d027a5**. Under **Descriptor → Edit**,
   compare the public keys/origins and `wsh(sortedmulti(2,...))` policy with
   the full descriptor text shown below its QR in **Open-Test-Cases.html**.

### Prepare the transaction and descriptor

1. In **Open-Test-Cases.html**, find **Multisig wallet descriptor**. Its QR is on the
   same page as the seed/rejection QRs; leave it available for signing.
2. Open **Test-cases/multisig-A-B.psbt** in Sparrow, click **Finalize Transaction
   for Signing**. Payment is **25,000**, change
   **74,500**, and fee **500 sats**.

### Get the signers ready

Keep **A selected on SeedSigner**.

On Kern, tap the orange **i**, confirm Testnet and anti-exfil on, then open
**Wallet Settings → Descriptors → Load Descriptor** (or **Load Other Descriptor**)
**→ From QR Code**. Scan the policy QR, check both fingerprints and **2 of 2**,
and choose **Keep for this session only**. Repeat this after any seed change
or timer unload.

SeedSigner loads the descriptor during transaction review when requested:
choose **Scan descriptor**, scan the policy QR, check its fingerprints/threshold,
then choose **Return to transaction**. Keep the QR available for later ceremonies.


### Sign A, then B

1. In the prepared transaction tab click **Protected QR**, select **A**, and
   scan Step 1 on **SeedSigner** with seed A selected. Review/approve the payment,
   change, and fee; load the descriptor during review if requested.
2. Scan the first device response into Sparrow. When it displays Step 2,
   choose **Done → Scan host reveal** on the device, scan Step 2, approve,
   and return the final QR to Sparrow. Wait for A's signature to be accepted.
3. Keep this transaction tab open; it holds A's signature. Use Kern with **B** loaded and the wallet policy loaded.
4. In the same transaction click **Protected QR**, select **B**, and complete
   both rounds on **Kern**, including **Done → Scan host reveal** between
   rounds. Check the same payment, change, and fee.
5. Wait for Sparrow to accept B's protected signature before leaving its final
   QR viewer.
6. Confirm both signatures are accepted and Sparrow can finalize the transaction.
   Mark **Multisig** and your hardware arrangement in the feedback.

For the recovery PSBTs below, choose **one** device with seed A and its
matching singlesig wallet. Each recovery file is used once; replaying it on
the other device would reuse the retained session rather than start a fresh test.
You can scan the device rejection cases on both devices.

### Optional: Try the rejection QRs

These cases use **seed A**. After multisig, restore A without a passphrase,
confirm **0fb882ff**, and keep protection on. On Kern unload/restart and load
A from **Open-Test-Cases.html**; on SeedSigner select its loaded A seed.

1. In **Open-Test-Cases.html**, find **Signer rejects a malicious coordinator request**. Choose the
   wrong-mainnet case from **Case**. Leave **Density** at **medium** initially.
2. On the device choose **Scan** and scan the animated QR through a full loop.
3. Follow any transaction-review screens until the device refuses the request.
   The test passes if there is a refusal and no signature response.
4. Try **wrong stage** and **duplicate slot** next. You may also try the other
   dropdown cases. Record case numbers and Pass/Fail; a photo supplies wording.

SeedSigner can enter review for cases **05–09 and 11** before showing refusal.
For **12/13**, continue through **Approve Protected Signature** to see it.
Kern may refuse immediately on scan. Messages differ between devices; an
earlier generic rejection does not demonstrate that every deeper check ran.

If scanning stalls, adjust distance/glare or lower the animation speed.
**High** density uses fewer frames but smaller QR modules; **low** makes the
modules easier to see. Use whichever your camera reads reliably.

**Open-Test-Cases.html** also explains two configuration mistakes: an ordinary request with
device protection on, and a protected request with device protection off.
If you try the second check, use the matching **pre-reveal** PSBT, stop before
Sparrow displays Step 2, and restore protection before continuing.

### Optional: Sparrow rejects a signed return without proof

Use your **Offline SeedSigner A** or **Offline Kern A** wallet with Required
signing. This checks Sparrow and uses its computer camera. Display **Open-Test-Cases.html**'s
**ordinary signed return** on a second screen/device, or aim a movable USB webcam
at your screen. A fixed laptop webcam cannot face its own screen: open the
extracted kit's viewer on a second computer, or copy **ordinary-signed-return-A-qr.png**
to a phone/tablet and display it there. This QR contains public test data only.

1. Open **singlesig-A-first.psbt** and click **Finalize Transaction for Signing**,
   with the existing seed-A wallet open.
2. Use the transaction's separate **Scan QR** button to scan the **ordinary
   signed return** displayed in **Open-Test-Cases.html**. Do not click Protected QR for this check.
3. Expect **Protected signature rejected** / **REQUIRED_PROOF_MISSING** and
   no accepted ordinary signature. Mark **Missing-proof rejection**.



### Optional: Cancel before the second round, then restart

Use **Test-cases/singlesig-A-pre-reveal.psbt** and your wallet for seed A.

1. Open the file, click **Finalize Transaction for Signing**, then click **Protected QR**.
2. At **Step 1 of 2**, close the QR window using **X** before scanning it on
   the device. No signature should have been accepted.
3. Click **Protected QR** again on the same transaction. Complete both rounds
   as in the first signing test.
4. Confirm **Protected signatures verified**. Mark **Cancel and restart**.


### Optional: Interrupt the second round and retry

Use **Test-cases/singlesig-A-post-reveal.psbt**, seed A, and its singlesig wallet. Keep the device ready for Step 2.

1. Open and prepare the file. Click **Protected QR**, scan Step 1 on the device,
   approve, and scan its opening response into Sparrow.
2. Choose **Done → Scan host reveal** on the device so it is ready for the
   second round. Sparrow now displays **Step 2 of 2**. **Do not scan it yet.**
   Close that QR window with **X**.
3. In **Protected signing is incomplete**, choose **Retry exact session**.
4. Confirm Sparrow returns directly to **Step 2 of 2**. Scan it on the waiting
   device, approve, and scan its final response into Sparrow.
5. Confirm **Protected signatures verified**. Mark **Retry second round**.

Kern may explain that the coordinator maintains first-round session continuity.
Keep the same transaction and session for this check.


### Optional: Abandon and reopen — final device recovery check

Finish the device recovery checks here; this leaves a durable history entry.
The optional Sparrow-only demo follows.
Use **Test-cases/singlesig-A-abandon.psbt**, seed A, and its singlesig wallet. Leave the device waiting for the second round.

1. Open and prepare the file. Scan Step 1 on the device, approve, and return
   its opening response to Sparrow.
2. Choose **Done → Scan host reveal** on the device and leave it waiting.
   When Sparrow displays **Step 2 of 2**, leave it unscanned and close the QR
   window with **X**. Choose **Abandon session**.
3. Confirm no signature was accepted. Close the transaction tab.
4. Reopen the **same abandonment PSBT**, prepare it with the **same wallet**,
   and click **Protected QR**.
5. Expect the retained **Step 2 of 2**, not a new first round. Scan it on the
   waiting device and scan the final response back into Sparrow.
6. Confirm verification and mark **Abandon and reopen**.

Outside the deliberate public demo below, if a different transaction shows **Selective-abort history exists**,
choose **No** and record that warning. Leave Sparrow's history intact. These
files are separate transactions so each recovery check gets its own session;
reopening a completed file does not count as a new signing ceremony.

### Optional: See Sparrow reject a Dark Skippy-style signer — run last

This test uses **Open-Test-Cases.html** as a simulated malicious signer for up
to three fabricated Dark Skippy transactions using public test Seed A
(**0fb882ff**). You will use your computer camera to scan QRs from both Sparrow
and the page. SeedSigner and Kern are not used: the signing device is the
attacker here, and Sparrow must detect the malicious signature and reject it. A
malformed request sent to an honest device checks a different condition (the
device rejection cases above).

A fixed malicious response would not match Sparrow's fresh session and host
randomness. The page reads Sparrow's real two-round QRs and returns a valid
ECDSA signature for that exact session, using eight bytes of public seed A's
entropy as its nonce. The rejection must appear in **Sparrow itself**.

Run this **Dark Skippy test last**, after your other signing/recovery tests; the
deliberate rejection adds a durable history entry. Keep Sparrow offline on
Testnet4 and use your wallet for **seed A**, with **Protected signing →
Required**. You will need a computer-connected camera that can read this screen:
a movable USB webcam or DroidCam (a fixed laptop webcam cannot read its own
screen).

Open **Open-Test-Cases.html** in a desktop browser. The maintainer completed these tests in **Brave and Firefox**. Some browsers block
camera access for pages opened directly from disk; if the camera will not start,
try another desktop browser and report which one and version you used.

1. In **Open-Test-Cases.html**, choose **Sparrow — Dark Skippy-style malicious
   signer** in the **Case** dropdown.
2. In Sparrow choose **File → Open Transaction → File**, browse to the kit's
   **Test-cases** folder, and open **dark-skippy-attack-A.psbt**. Click
   **Finalize Transaction for Signing** and click **Protected QR**. Payment is
   **27,000 sats**, change **72,500**, and fee **500**. Leave **Step 1 of 2**
   visible. If **Selective-abort history exists** appears from an earlier
   recovery test, read it and choose **Yes** for this last deliberate public
   test; keep the history intact.
3. On **Open-Test-Cases.html**, click **Grant camera access** and allow the
   browser permission. **Read Sparrow Step 1** stays disabled until access is
   granted. Choose your movable camera in **Camera to use for reading
   Sparrow**, then click **Read Sparrow Step 1** and aim it at Sparrow's open
   animated Step 1 QR. Wait for a response QR; the page releases the camera
   automatically.
4. In Sparrow's open **Step 1 of 2** QR window click **Scan QR** and aim the
   camera at the page's animated response QR. Once Sparrow accepts it, Sparrow
   shows a new animated QR, **Step 2 of 2**.
5. On **Open-Test-Cases.html**, click **Read Sparrow Step 2** and aim the camera
   at Sparrow's Step 2 QR. The final response QR appears on the page; the page
   releases the camera again.
6. In Sparrow's Step 2 window click **Scan QR** and aim the camera at the page's
   final animated response QR. Expect Sparrow's **Protected signing stopped**
   dialog with **SIGNATURE_INVALID: Anti-exfil signature verification failed**.
   No signature from this attempt should be accepted.
7. In **FEEDBACK-OFFLINE.html**, mark the **Dark Skippy-style Sparrow QR test** Pass or
   Fail. A screenshot of **Sparrow's** dialog is optional supporting evidence.

**Congrats!** You've just defeated a (simulated) Dark Skippy attack trying to
steal your private key and all your bitcoin!

An invalid-QR, wrong-stage, session-mismatch, or camera error does not count as
the nonce-defense result. Report it if it occurs. The page's response-ready
message cannot see Sparrow's outcome and is not a pass result.

**Repeating the test:** Sparrow retains the session for each transaction;
reopening a used PSBT may resume Step 2. Click **Start over** on the page, then
open the next unused transaction: **dark-skippy-attack-A2.psbt**, followed by
**dark-skippy-attack-A3.psbt**. Each has a different transaction ID. Start over
clears only this page, and Sparrow keeps its history. After using all three,
stop here and report your results.

This demonstrates rejection of an **ECDSA adaptation of the [Dark Skippy nonce
technique](https://darkskippy.com/)** through the live coordinator exchange.
It uses a public browser simulator rather than malicious device firmware and
does not perform seed recovery. Its source and transaction identities are
included. The automated checks cover the shipped signing flow, transport,
ordinary signature validity, proof rejection, and durable non-completion; the
expected rejection has been observed in Sparrow.

## Send a short report

Save **FEEDBACK-OFFLINE.html** with the tests you tried. Leave other tests **Not tried**.
One clear photo of an unexpected screen and the step where it appeared are
more useful than a transcript of every screen. Include the kit version and
your device; source hashes and developer tool versions are not required.

You can paste the report into a [GitHub issue](https://github.com/FractalEncrypt/seedsigner-anti-exfil-review/issues)
or send it to the maintainer who supplied the kit. For a potentially exploitable
failure, use the private reporting route in **SECURITY.md**. Share test screens
and this report; keep personal seeds and wallet/profile files private.
