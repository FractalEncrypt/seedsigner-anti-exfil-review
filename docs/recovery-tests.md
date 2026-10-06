# Protected-signing recovery reference

For the complete laptop run, read
[Offline laptop tests in execution order](offline-public-fixture-testing.md)
from start to finish. It includes these checks inline; you do not need to
switch to this reference during that run.

This reference is for someone repeating just the recovery checks. Use the
isolated Sparrow launcher, Testnet4, offline mode, and Required signing.
Complete positive singlesig and multisig first. Below, Kern's fresh ceremony
comes first and intentional abandonment comes last. Abort history is durable.
Use seed A / Offline SeedSigner A, or seed B / Offline Kern B and substitute
`B` for `A` in filenames. Do not reuse completed PSBTs to claim a fresh run,
and do not delete session files or journals to force a fresh challenge.

## Starting a transaction

1. Choose **File → Open Transaction → File** and open the named PSBT.
2. Click **Finalize Transaction for Signing**. Choose the matching wallet if
   Sparrow asks. This prepares signing; it does not broadcast or finish the
   transaction.
3. Click **Protected QR**. In multisig, select the intended cosigner.

Sparrow's **Step 1 of 2** QR is the host commitment. The device returns nonce
openings, which Sparrow scans. Sparrow's **Step 2 of 2** QR is the host reveal.
The device then returns protected signatures, which Sparrow scans and verifies.
The boundary for these recovery checks is the first display of **Step 2**.
Treat that reveal as exposed even if the device has not scanned it yet.

## 1. Kern's next fresh ceremony

Run this before the intentional abandonment check. Load seed B with no
passphrase and use **Offline Kern B**. If you already have an abort-history
warning for this key, record it and stop; do not erase its journal or bypass
the warning to claim a clean next-ceremony result.

1. Complete `singlesig-B-first.psbt` if it has not already been completed in
   this profile. Keep Kern's final response visible until Sparrow verifies it.
2. Exit Kern's response viewer, acknowledge its completion message, and return
   to its normal scanning/home flow. Keep seed B loaded and anti-exfil enabled.
3. Open `singlesig-B-next.psbt` in Sparrow. This is a distinct transaction;
   its recipient amount is 24,000 sats rather than 20,000 sats.
4. Prepare it for signing and click **Protected QR**. Confirm the fresh
   transaction starts at **Step 1 of 2**.
5. Complete both request/response rounds and record the second verified result.

## 2. Cancel before the reveal, then restart

Use `singlesig-A-pre-reveal.psbt`.

1. Start the transaction as above. Confirm Sparrow shows **Step 1 of 2**.
2. Close that QR window with its **X**, before scanning it on the device.
   Do not advance to Step 2 for this check.
3. Confirm Sparrow has not accepted a signature. Record the cancellation.
4. Click **Protected QR** again on the same transaction.
5. Complete both rounds: scan Step 1 on the device, scan its openings into
   Sparrow, scan Step 2 on the device, then scan its signatures into Sparrow.
6. Pass when Sparrow reports **Protected signatures verified**, with no
   ordinary-signing fallback. Record the displayed wording and device used.

## 3. Interrupt after the reveal and retry the exact session

Use `singlesig-A-post-reveal.psbt`. Keep the signer ready, but pause it before
it scans Step 2. This avoids asking Kern to regenerate a response after its
completed response viewer has been dismissed.

1. Start the transaction. Scan Step 1 on the device and review the transaction.
2. Scan the device's nonce-opening response into Sparrow.
3. Confirm Sparrow displays **Step 2 of 2**. Do not scan this QR on the device
   yet. Leave the device ready for its second request.
4. Close Sparrow's Step 2 QR window with its **X**.
5. In **Protected signing is incomplete**, choose **Retry exact session**.
6. Confirm Sparrow returns directly to **Step 2 of 2**, rather than starting
   Step 1 or creating a fresh challenge.
7. Scan that retained Step 2 on the device, review and approve it, then scan
   the device's protected-signature response into Sparrow.
8. Pass when Sparrow reports **Protected signatures verified**. Record that
   the retry stayed at Step 2 and that no ordinary signature was substituted.

Post-sync Kern's second-round disclosure says it validates the request but does not
retain first-round session continuity; the coordinator maintains that binding.
This disclosure is expected. Keep the same Sparrow transaction and session.

## 4. Abandon after the reveal and reopen the retained transaction

Use `singlesig-A-abandon.psbt` for this separate check. Run it last for this key,
after positive signing, multisig, next-ceremony, and exact-retry checks.

1. Follow steps 1–4 of section 3, stopping before the device scans
   Step 2.
2. In **Protected signing is incomplete**, choose **Abandon session**.
3. Confirm no protected signature was accepted. Close the transaction tab.
4. Reopen the **same** `singlesig-A-abandon.psbt`, prepare it for signing with
   the same wallet, and click **Protected QR**.
5. Confirm the retained ceremony resumes at **Step 2 of 2**. Complete that
   exact session and record the verification result.

Starting a different transaction after a recorded post-reveal abandonment
can display **Selective-abort history exists**, including after the retained
ceremony completes. The history remains recorded. Choose **No** and record
the warning; return to the retained transaction if it is incomplete. Do not accept
a fresh challenge to get past the warning. A silent fresh Step 1 for the
retained transaction, loss of the retained session, or an ordinary fallback
fails this check. Preserve the first failure and report it.
