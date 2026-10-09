# Additional signing tests (optional)

These checks are optional for public testers. Complete the [offline signing guide](offline-public-fixture-testing.html) first to set up the public-seed singlesig and, if needed, A/B multisig wallets. Each case below has its own supplied transaction and complete steps. Use [FEEDBACK.html](../FEEDBACK.html) and save your editable results.

## Cases and supplied files

All signing files below are in **Test-cases**. Each unsigned file has its
own transaction ID. Signed companions deliberately match their unsigned case.

| Case | Feedback field | File |
| --- | --- | --- |
| 1. Ordinary A and B refused with both Required | Required / Required fails closed for ordinary returns | multisig-required-required.psbt |
| 2. Ordinary A refused, ordinary B accepted | Required / Optional: Required signer fails closed | multisig-required-optional.psbt |
| 3. Preserve A's proof across restart; add B | Restart after first protected proof; retain it, add second, finalize | multisig-restart-proof.psbt |
| 4. Interrupted second round, retry exact session | Interruption / recovery: each device | singlesig-retry-SS.psbt; singlesig-retry-Kern.psbt |
| 5. Opening from a different transaction refused | Stale reply refused: each device | Separate stale-origin/target files per device below |
| 6. All 13 rejection cases per device | Individual numbered rejection fields | QRs displayed on this page below |
| 7. Device setting on/off; restore on | Protection on/off: each device | Separate ordinary/protected files per device below |
| 8. Live Testnet3 protected 2-of-2 | Testnet3 multisig | Create a fresh live spend from your funded wallet |

The order-A-B/order-B-A reserve PSBTs provide distinct transactions for optional signer-order checks.
 The cancel/abandon reserve files
are optional additional coverage, not hidden requirements for the recovery fields.
All supplied fixtures are fabricated: stay offline and do not broadcast them.
They are not used for the live spend in step 8.

## Prepare once

Sparrow **Testnet4**, connection **off**. Open your existing Native Segwit P2WSH
**2-of-2 A/B** wallet: **A 0fb882ff**, **B 05d027a5**, both **m/48'/1'/0'/2'**.
Close other open multisig wallets with identical keys so transactions associate
with this wallet. **Finalize Transaction for Signing** does not ask for a wallet;
**Protected QR** may ask for the keystore A or B.

For multisig, use **A on SeedSigner** and **B on Kern**, no passphrase. Confirm
fingerprints. SeedSigner: **Settings → Advanced → Anti-exfil signing → Required**.
Kern: orange circled **i → Wallet Settings → Anti-exfil signing → on**, **Network
→ Testnet**. Steps 1–2 do not require changes to device protection.

<details><summary>Public seed A/B QRs and words</summary><div class="two"><div><h4>Public seed A — 0fb882ff</h4><p>model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast</p><img src="../Test-cases/seed-A-qr.png" alt="Public seed A QR"></div><div><h4>Public seed B — 05d027a5</h4><p>abandon amount liar amount expire adjust cage candy arch gather drum buyer</p><img src="../Test-cases/seed-B-qr.png" alt="Public seed B QR"></div></div></details>

<details id="descriptor"><summary>2-of-2 A/B descriptor QR and full text</summary><img src="../Test-cases/multisig-A-B-descriptor-qr.png" alt="A/B multisig descriptor QR" style="max-width:560px"><pre>wsh(sortedmulti(2,[0fb882ff/48h/1h/0h/2h]tpubDF3QYaRazZ44jHz3jaSPRGCLVYj7D8j4mVVUTCr3CHsfuvoV2Z73eTcvHc8sP3Dj58yEfkG57iBpKTuHv3dNAUcFufCxx26SAbrWque5gts/&lt;0;1&gt;/*,[05d027a5/48h/1h/0h/2h]tpubDFDkaAUidyzsbPUCXrxA4LRKYHkg9kKdsosWCX6ZS3JGaNL1N5ShsmGZkPC581AaEf917J2az9cLd5cqbKqc3nRq49ZpPwuj91XmXu8YD8y/&lt;0;1&gt;/*))#wh02qs99</pre></details>

For step 3, Kern loads this policy under **Wallet Settings → Descriptors → Load
Descriptor** (or **Load Other Descriptor**) **→ From QR Code**. Check both
fingerprints and **2 of 2**, then **Keep for this session only**. Reload after
seed change/timer unload. SeedSigner, if requested during transaction review:
**Scan descriptor**, scan it, check policy, then **Return to transaction**.

If **Selective-abort history exists** appears for these explicitly public fixtures,
keep the history. **Yes** permits a new challenge for this deliberate public test;
record that warning. Prefer **Retry exact session** for recovery. This instruction
is not for a personal wallet.

## Signer order: A then B, or B then A

If you already completed protected 2-of-2 A then B in the offline guide, record that same result in the combined A-then-B field; do not repeat it. The A-then-B reserve is only for a run you still need. B then A is a separate optional order check.

After the [offline guide's two-device wallet setup](offline-public-fixture-testing.html#optional-2-of-2-multisig_2),
keep the public A/B wallet on Testnet4, offline, with both keystores Required and
device protection on. Load A on SeedSigner and B on Kern; have the descriptor
above available. Close other open wallets with the same keys.

- For **A then B**, open **Test-cases/multisig-order-A-B-reserve.psbt**.
- For **B then A**, open **Test-cases/multisig-order-B-A-reserve.psbt**.

Click **Finalize Transaction for Signing → Protected QR**. Select the first
keystore and complete both QR rounds on its device. Confirm its protected
signature was accepted. Click **Protected QR** again, select the other keystore,
and complete both rounds on that device. Confirm both signatures were accepted
and finalization succeeds. Record the order you actually ran. These distinct
transactions permit both orders without reusing a previously completed PSBT.

## 1. Required / Required

1. In the existing A/B wallet's **Settings**, set **both keystores A and B →
   Protected signing Required**, click **Apply** and confirm both remain Required.
2. Open **Test-cases/multisig-required-required.psbt** with **File → Open
   Transaction → File** and click **Finalize Transaction for Signing**. Expect
   payment **30,100**, change **69,400**, fee **500 sats** and no signatures. Do not start a Protected QR ceremony.
3. Choose **A** in the ordinary-return selector beside these steps. In Sparrow's
   transaction pane click ordinary **Scan QR** and read this page's return QR.
   Expect **Protected signature rejected / REQUIRED_PROOF_MISSING**, no A signature accepted.
4. Close the error/scanner, select **B** here and repeat on the same transaction.
   Expect the same rejection, no B signature accepted.
5. Mark **Required / Required fails closed for ordinary returns** Pass only if
   both refused. Note **A Required; B Required; ordinary A/B refused**. Close the
   transaction tab. No physical signing/finalization is needed for this policy case.

Both supplied returns are valid ordinary ECDSA signatures from public seeds,
without protected proof. A decode/wrong-transaction error is not this result.
If dense QRs are difficult to read, the **same prepared transaction's Load
Transaction** button can import the matching **-ordinary-A.psbt** or
**-ordinary-B.psbt** below through the shared policy gate. Record **file import**
if used. Do not open a signed companion as an unrelated transaction.


## 2. Required / Optional

1. Close the previous transaction. In the same A/B wallet's **Settings**, keep
   **A 0fb882ff Required**, set **B 05d027a5 Optional → Apply**, and confirm policies.
   Device protection remains on; this is Sparrow's keystore policy.
2. Open **Test-cases/multisig-required-optional.psbt**, click **Finalize
   Transaction for Signing**. Expect payment **30,200**, change **69,300**, fee **500 sats**, no signatures.
3. Choose **A** here and use the transaction's ordinary **Scan QR**. Expect
   **Protected signature rejected / REQUIRED_PROOF_MISSING**. A must not become
   accepted just because B is Optional.
4. Close the error/scanner, choose **B** here and scan it on the same transaction.
   B's valid **ordinary** signature should be accepted: only **1 of 2** signatures,
   A still unsigned. B is not a protected-signature pass.
5. Mark **Required / Optional: Required signer fails closed** Pass only after A
   refused and B accepted. Note **A Required; B Optional; ordinary A refused,
   ordinary B accepted**. This case ends here; no extra physical signing is needed.
6. Close the transaction, restore **B → Required → Apply**, and confirm **both
   Required** before the restart-proof case.

If scanning is difficult, use the same transaction's **Load Transaction** with
its matching signed companion below, and record that route. These companions
belong to this new transaction. Do not reverse the Required/Optional assignment.


## 3. Restart after first protected proof

Use **Test-cases/multisig-restart-proof.psbt**: payment **30,300**, change **69,200**, fee **500 sats**.
Both Sparrow keystores **Required**; device protection enabled.

1. Open this new PSBT with **File → Open Transaction → File**, then **Finalize
   Transaction for Signing**. Do not reuse multisig-A-B.psbt.
2. Click **Protected QR**, select **A 0fb882ff**, and scan Step 1 on SeedSigner/A.
   Review payment/change/fee above, load the descriptor if requested, and approve.
3. In Sparrow's protected window use **Scan QR** to read the opening response.
   Sparrow shows **Step 2 of 2**. On SeedSigner choose **Done → Scan host reveal**,
   scan Step 2, follow approval, and scan the final response back into Sparrow.
   Wait for A's protected signature to be accepted. Do not add B yet.
4. In the transaction's main pane click **Save Transaction**. Save the partially
   signed PSBT in your evidence folder as **restart-after-A.psbt**. Remember
   this path. Close Sparrow and relaunch with this kit's **Start-Sparrow.cmd**.
5. Open the **same original A/B wallet**. Open the saved **restart-after-A.psbt**
   using **File → Open Transaction → File**, not the original unsigned fixture.
   A's signature must remain accepted as protected, without missing-proof rejection.
   Do not re-sign A. Wallet visibility alone is not proof persistence.
6. Click **Protected QR**, select **B 05d027a5**, and complete both QR rounds on
   Kern/B: scan Step 1, return opening; **Done → Scan host reveal**, scan Step 2,
   return final response. Keep Kern's final QR visible until accepted.
7. Confirm both protected signatures accepted; click **Finalize Transaction** when
   offered. Save the result. Mark **Restart after first protected proof; retain
   it, add second, finalize** Pass. A lost proof is Fail; do not reset or bypass Required.

## 4. Interruption / recovery

Both devices now use **seed A 0fb882ff** and their existing singlesig A wallet,
**m/84'/1'/0'**, Sparrow **Required**. Change Kern from B to A and confirm its
fingerprint. Keep only the intended singlesig A wallet open if others have identical
keys. Keep device protection on and the device powered through this check.

| Device | Fresh PSBT in Test-cases | Payment / change / fee |
| --- | --- | --- |
| SeedSigner | singlesig-retry-SS.psbt | 30,600 / 68,900 / 500 sats |
| Kern | singlesig-retry-Kern.psbt | 31,300 / 68,200 / 500 sats |

Run this once on each device using its own file:

1. Open its PSBT, **Finalize Transaction for Signing → Protected QR**. Scan Step 1
   on the device, approve, and return the opening QR to Sparrow.
2. Sparrow displays **Step 2 of 2**. On the device choose **Done → Scan host reveal**
   and leave it waiting. **Do not scan Step 2 yet.** Close Sparrow's QR window with X.
3. In **Protected signing is incomplete**, choose **Retry exact session**.
4. Expect **Step 2 of 2** directly. Scan it on the waiting device, approve and
   return the final QR to Sparrow. Expect **Protected signatures verified**.
5. Mark **Interruption / recovery: SeedSigner** or **Interruption / recovery: Kern**
   Pass; note **second-round interruption; Retry exact session**. A device reboot
   discards volatile state and does not qualify as restoring this ceremony.

## 5. Stale replies

Keep seed A, its singlesig A wallet and protection on. Separate pairs are supplied:

| Device | Origin | Target |
| --- | --- | --- |
| SeedSigner | singlesig-stale-origin-SS.psbt | singlesig-stale-target-SS.psbt |
| Kern | singlesig-stale-origin-Kern.psbt | singlesig-stale-target-Kern.psbt |

All are in **Test-cases**. The device holds the old QR while you switch
Sparrow transactions; no photograph or second screen is needed.

1. Open the device's **origin** PSBT, prepare it, and click **Protected QR**. Scan
   Step 1 on that device and approve review. Leave its opening-response QR visible.
2. **Do not scan this response into the origin ceremony.** Close Sparrow's origin
   QR window with X. No opening was accepted and no host reveal was sent.
3. Open the device's **target** PSBT, prepare it, and click **Protected QR**. Do
   not scan this target request on the device.
4. In the target's Step 1 window click **Scan QR** and read the device's still
   visible **origin** opening QR.
5. Expect **Protected signing stopped / SESSION_MISMATCH**, or explicit transcript/
   transaction mismatch. No signature or accepted advance to host reveal is allowed.
   Camera decoding failure is not a stale-response pass.
6. Exit the old device QR/session and return Home. Keep histories. Mark the
   device's **Stale reply refused** field with the actual error. Do not reuse this
   target fixture for another signing case.

## 6. Rejection cases 01–13

Seed A, no passphrase, test network family, device protection Required/on.
The **signing device** scans this page; Sparrow's camera is not used.

1. Select **01** here; on SeedSigner or Kern use **Scan**. Scan a full animation
   loop; continue any review screens until expected refusal. No signature may be produced.
2. Record **01** in that device's feedback field with its actual error. Select
   **02**, repeat, then continue through **13**. Run the same list on the other
   device, using its separate numbered fields. No Sparrow PSBT is opened for these cases.
3. SeedSigner can enter review for **05–09 and 11**. For **12/13**, continue through
   **Approve Protected Signature** to reach the intended check. Kern may refuse
   earlier. A camera/wrong-screen failure is incomplete, not a payload-rejection pass.
4. After each refusal return to Scan/Home. Keep seed A and protection Required/on.
   Adjust distance/glare or lower density if scanning stalls.

The HTML version has the complete animated case selector here.


## 7. Device protection on/off

Keep Sparrow's singlesig A keystore **Required** throughout. These are device
settings checks; they are separate from the Sparrow policy checks in steps 1–2.

| Device | Ordinary unsigned request | Protected Step 1 request |
| --- | --- | --- |
| SeedSigner | singlesig-protection-ordinary-SS.psbt | singlesig-protection-protected-SS.psbt |
| Kern | singlesig-protection-ordinary-Kern.psbt | singlesig-protection-protected-Kern.psbt |

All files are in **Test-cases**. Run both parts on each device:

1. With device protection **Required/on**, open its **ordinary** PSBT in Sparrow,
   click **Finalize Transaction for Signing**, then **Show QR**, the ordinary PSBT
   export. Use the device's **Scan**. Expect a signing-mode refusal requiring a
   protected request, with no ordinary signature. Record the message; exit to Home.
2. Turn protection off **on that device only**. SeedSigner: **Settings → Advanced
   → Anti-exfil signing → Disabled**. Kern: orange **i → Wallet Settings → Anti-exfil
   signing → off**.
3. Open its separate **protected** PSBT, prepare it, and click **Protected QR**.
   Scan **Step 1 of 2** on the device. Expect refusal/a prompt to enable protected
   signing. Do not approve ordinary signing or progress to Sparrow Step 2.
4. Exit/cancel this request on both sides. Restore SeedSigner **Required** / Kern
   **on**, and confirm that setting before leaving the case.
5. Mark **Protection on/off cases: [device]; restored on** Pass only after both
   refusals and restoration. Note both messages.

## 8. Testnet3 multisig

This is the **live** case, using your funded wallet. The offline fixtures above
are not used. Testnet3 signing is separate from faucet receipt and Testnet4 coverage.

1. **Tools → Restart In → Testnet3**. Open your funded public-seed A/B **2-of-2 Testnet3** wallet. Confirm both fingerprints/accounts match the signing seeds;
   set both Sparrow keystores **Required → Apply**.
2. SeedSigner A, Kern B, no passphrase: confirm **0fb882ff**, **05d027a5**; device
   protection on, network **Testnet**. Load the live wallet descriptor on Kern if
   needed. The descriptor above applies if the live wallet has the same A/B policy.
3. Connect to your existing public Testnet3 server and confirm the faucet UTXO.
   In **Receive**, copy a new wallet receive address. In **Send**, send a small
   testnet amount back to it, choose an available fee, then **Create Transaction**.
   Save the unsigned PSBT in your evidence folder.
4. Click **Protected QR** for each matching keystore/device and complete both QR
   rounds, checking the actual live amounts/fee. Both protected signatures must
   be accepted and finalization must succeed. Save final PSBT and screenshot.
5. Mark **Testnet3 multisig** Pass with the devices and network. Broadcast is not
   required for this signing/finalization field. Faucet receipt alone is not this
   result. Turn the connection off afterward.

## 9. Testnet3 singlesig

This optional live case is independent of the supplied offline PSBTs. Run it on
one device at a time; use disposable testnet coins only.

1. In Sparrow choose **Tools → Restart In → Testnet3**. Open your Testnet3 Native
   Segwit singlesig wallet for the intended device. If you need a wallet, follow
   the live guide's account export/import steps for your device, using
   **m/84'/1'/0'** and a disposable seed; keep Sparrow on **Testnet3** throughout.
   Do not follow that guide's Testnet4 restart instruction for this case.
2. On that device confirm the seed fingerprint matches the wallet; set its network
   **Testnet** and protection **Required** (SeedSigner) or **on** (Kern). In Sparrow
   set its keystore **Protected signing Required → Apply**.
3. In Sparrow's **Settings** choose a public Testnet3 server and connect. Copy a
   wallet Receive address, obtain disposable Testnet3 coins from a faucet, and
   wait for the wallet to show its UTXO. A Core/Knots node is not required.
4. Copy a fresh Receive address. In **Send**, create a small self-payment to that
   address using the available UTXO and a suitable fee, then **Create Transaction**.
5. Click **Protected QR**, scan Step 1 on the device, review and approve, scan its
   opening QR back into Sparrow, then scan Sparrow Step 2 on the same device and
   return its final QR. Expect protected signatures verified, then finalize.
   Save the signed/final PSBT and record the actual network/device.
6. Mark the matching **Testnet3 protected singlesig** field. Signing/finalization
   does not by itself prove broadcast or confirmation. Broadcasting is optional
   for this additional field. Disconnect when finished.

## Save your record

Record only the tests you tried; leave other results Not run. Record results/messages/policy assignment in
[the feedback form](../FEEDBACK.html) and **Save feedback HTML**.
Name the package you actually used for these cases.
Reopen the newest downloaded HTML to continue later. A failure is a finding to
resolve, not a reason to reset histories or downgrade Required.
