# Live Testnet4 signing: fund, sign, and broadcast

Start with the Windows tester kit extracted, the device flashed and configured,
and Sparrow open through **Start-Sparrow.cmd**. [Download and test](download-and-test.md)
covers that setup. All wallet creation, funding, and signing steps for this live
test are below; you do not need the offline fixture or recovery guides during it.

Use your own **disposable Testnet4 seed**. You can generate one on the device,
or load an existing test seed, including one already funded with Testnet4 coins.
This path creates real transactions and broadcasts them. The public kit seeds
and fabricated PSBTs belong to the separate offline tests.

Choose [**I have SeedSigner**](#i-have-seedsigner),
[**I have Kern**](#i-have-kern), or [**I have both**](#i-have-both).
The HTML selector shows only the matching route;
the Markdown copy has a heading for each. With both devices, try a singlesig
wallet on each, then optionally a wallet requiring both signatures.

## I have SeedSigner

### 1. Connect Sparrow to Testnet4

1. Confirm **Testnet4** at the top-right of Sparrow.
2. Open **Tools → Preferences → Server**. Choose a public server for Testnet4
   or enter your own Testnet4 Electrum server. Close Preferences.
3. Turn on the server connection switch at the bottom-right. Wait for its
   connected status before creating or funding the wallet.


### 2. Generate or load a seed on SeedSigner

1. To create a seed, choose **Tools → New seed** with the camera icon. Follow
   the entropy and confirmation screens, then finish loading it. For a new
   test seed, leave the passphrase empty. To use an existing test seed, choose
   **Scan** for its seed QR or enter its words through the seed-loading menu.
2. Note the loaded seed's fingerprint. **Testnet** and **Required** signing
   were configured in Start Here before seed loading; keep those settings.
3. In the loaded seed's menu choose **Export xpub → Single Sig → Native
   Segwit**, then **Animated** or **Static → I understand →
   Export xpub**. Leave the account QR visible.

The singlesig derivation should be **m/84'/1'/0'**. Keep the disposable
seed backup handy.


### 3. Create the singlesig wallet in Sparrow

1. Choose **File → New Wallet**, name it **Live SeedSigner**,
   and select **Single Signature / Native Segwit (P2WPKH)**.
2. Choose **Airgapped Hardware Wallet → SeedSigner**, then **Scan**
   the device's account QR.
3. Check the fingerprint against the one you noted and the derivation against
   **m/84'/1'/0'**. Set **Protected signing → Required**, then click **Apply**.
4. With **Settings** still visible, confirm **Required** remains selected.
   Keep this wallet tab open and click **Receive** for the next step.



### 4. Fund the wallet

If this seed's account already has confirmed Testnet4 coins, continue to section 5.

1. In **Receive**, label the displayed address **Receive from faucet 1**, then
   copy the address.
2. Open the [mempool.space Testnet4 faucet](https://mempool.space/testnet4/faucet)
   and follow its instructions to request a small amount to that address.
3. Return to Sparrow and wait for the deposit to appear and confirm. The
   transaction will carry your receive-address label. Faucet availability
   and confirmation time vary; that wait is separate from signing.


### 5. Create a small self-payment


1. In **Receive**, get another unused address in the same wallet and copy it.
2. Open **Send**, paste that address, and enter an amount smaller than your
   confirmed balance so there is room for change and the fee.
3. Choose a fee using Sparrow's displayed estimate. Click **Create
   Transaction**, then **Finalize Transaction for Signing** if shown.
4. Review the payment, change, and fee in Sparrow before signing.


### 6. Complete protected singlesig and broadcast

1. Click **Protected QR**. Scan Sparrow's **Step 1 of 2** on the device using
   its **Scan** action.
2. Review the transaction on the device. Check the payment and fee against
   Sparrow, approve, and scan the device's first response into Sparrow's
   protected signing window. Wait until Sparrow displays **Step 2 of 2**.
3. On the device choose **Done**, then **Scan host reveal**. Scan Sparrow's
   **Step 2 of 2** on that same device, follow its review/approval screens,
   and scan the final device response into Sparrow.
4. Confirm **Protected signatures verified**. Keep SeedSigner's final QR visible
   until Sparrow accepts it, then exit that QR screen and return Home.
5. Finalize the fully signed transaction if Sparrow offers **Finalize**.
   Review it once more and click **Broadcast Transaction**.
6. Wait for Sparrow to show the broadcast transaction. If a signature is
   rejected, stop at that result and keep the test transaction for diagnosis.

You can copy the **TXID** from Sparrow's transaction view and include it in a
[project issue](https://github.com/FractalEncrypt/seedsigner-anti-exfil-review/issues)
with your device and whether signing and broadcast worked. Successful reports
help us collect real-world results; confusing steps and failures are useful too.

Optional timing: start when Step 1 first appears and stop when Sparrow verifies
the final protected signature. A rough time or comment about QR retries is enough.


### Optional: 2-of-2 multisig

Keep A and B loaded together on your SeedSigner; choose the matching
seed for each signature.

These single-device steps are newly documented and have not yet received
end-to-end physical qualification. Two seeds on one device test the workflow;
they do not represent two independent physical signers.


### Create accounts A and B and the wallet

1. Get A ready on **SeedSigner**. Generate or load disposable seed **A** using the seed menus above.
   Record its fingerprint.
2. Export A's multisig account: choose **Export xpub → Multisig → Native Segwit**, then **Animated** or **Static**
   (either works), then **I understand → Export xpub** to show the QR.
3. In Sparrow choose **File → New Wallet**, name it **Live 2of2 A-B**, select
   **Multi Signature / 2 of 2 / Native Segwit (P2WSH)**. Import the first key
   through **Airgapped Hardware Wallet → SeedSigner → Scan**. Label it **A**
   and set **Protected signing → Required**.
4. Get B ready on **SeedSigner**. Generate or load a different disposable seed **B** and note its
   fingerprint. Keep both private backups.
   Export its multisig account: choose **Export xpub → Multisig → Native Segwit**, then **Animated** or **Static**
   (either works), then **I understand → Export xpub** to show the QR.
5. Import B into the second keystore through **Airgapped Hardware Wallet →
   SeedSigner → Scan**. Label it **B**, set **Protected signing → Required**,
   and click **Apply**.
6. With Settings still visible, confirm **2 of 2**, the two fingerprints, and
   **m/48'/1'/0'/2'** on both keystores.

### Fund and prepare the transaction

Keep both seed backups handy during the faucet wait. Kern may unload after
its timer expires; SeedSigner keeps loaded seeds while powered on. Load the
Kern wallet descriptor after funding, close to signing.

1. In **Live 2of2 A-B → Receive**, label the address **Receive from faucet 1**,
   copy it, and request a small Testnet4 deposit from the
   [faucet](https://mempool.space/testnet4/faucet). Wait for confirmation.
2. Copy another unused Receive address in this same wallet. In **Send**, create
   a self-payment leaving room for change and fee, then choose **Finalize
   Transaction for Signing** if shown.
3. Open the wallet's **Settings** and click the QR icon beside **Descriptor**.
   Keep this policy QR available for signing.

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
6. Confirm both signatures are accepted and finalize if offered. Click
   **Broadcast Transaction**, then record the hardware arrangement, whether
   both signatures and broadcast succeeded, and optionally the **TXID**.


## I have Kern

### 1. Connect Sparrow to Testnet4

1. Confirm **Testnet4** at the top-right of Sparrow.
2. Open **Tools → Preferences → Server**. Choose a public server for Testnet4
   or enter your own Testnet4 Electrum server. Close Preferences.
3. Turn on the server connection switch at the bottom-right. Wait for its
   connected status before creating or funding the wallet.


### 2. Generate or load a seed on Kern

1. To create a seed, from the unloaded screen choose **New Mnemonic → From
   Camera**. Follow creation and confirmation; for a new test seed, leave the
   passphrase empty. You can choose another creation method instead. To load
   an existing test seed, use **Load Mnemonic → From QR Code** or word entry.
2. Note its fingerprint. Tap the orange circled **i** at the upper-left of Home
   to open **Wallet Settings**. Confirm **Network → Testnet** and **Anti-exfil
   signing** on. They may already be selected; change them only if needed.
   For a longer session, you can set the seed-unload timer to **30 minutes**.
   Return Home.
3. Choose **Extended Public Key**. It defaults to **Singlesig → Native
   SegWit**, account **0**, and displays the key-origin/xpub QR. Confirm those
   values and leave the QR ready for Sparrow.

The singlesig derivation should be **m/84'/1'/0'**. Keep the disposable
seed backup handy.


### 3. Create the singlesig wallet in Sparrow

1. Choose **File → New Wallet**, name it **Live Kern**,
   and select **Single Signature / Native Segwit (P2WPKH)**.
2. Choose **Airgapped Hardware Wallet → Kern**, then **Scan**
   the device's account QR.
3. Check the fingerprint against the one you noted and the derivation against
   **m/84'/1'/0'**. Set **Protected signing → Required**, then click **Apply**.
4. With **Settings** still visible, confirm **Required** remains selected.
   Keep this wallet tab open and click **Receive** for the next step.

On Kern, after importing, you can click **Show xpub** to compare the key text
with Sparrow's imported key. Click **OK** to leave the export screen.


### 4. Fund the wallet

If this seed's account already has confirmed Testnet4 coins, continue to section 5.

1. In **Receive**, label the displayed address **Receive from faucet 1**, then
   copy the address.
2. Open the [mempool.space Testnet4 faucet](https://mempool.space/testnet4/faucet)
   and follow its instructions to request a small amount to that address.
3. Return to Sparrow and wait for the deposit to appear and confirm. The
   transaction will carry your receive-address label. Faucet availability
   and confirmation time vary; that wait is separate from signing.


### 5. Create a small self-payment

If Kern unloaded its seed during the wait, reload the same seed from its
backup and confirm Testnet and anti-exfil on through the orange **i** first.

1. In **Receive**, get another unused address in the same wallet and copy it.
2. Open **Send**, paste that address, and enter an amount smaller than your
   confirmed balance so there is room for change and the fee.
3. Choose a fee using Sparrow's displayed estimate. Click **Create
   Transaction**, then **Finalize Transaction for Signing** if shown.
4. Review the payment, change, and fee in Sparrow before signing.


### 6. Complete protected singlesig and broadcast

1. Click **Protected QR**. Scan Sparrow's **Step 1 of 2** on the device using
   its **Scan** action.
2. Review the transaction on the device. Check the payment and fee against
   Sparrow, approve, and scan the device's first response into Sparrow's
   protected signing window. Wait until Sparrow displays **Step 2 of 2**.
3. On the device choose **Done**, then **Scan host reveal**. Scan Sparrow's
   **Step 2 of 2** on that same device, follow its review/approval screens,
   and scan the final device response into Sparrow.
4. Confirm **Protected signatures verified**. Keep Kern's final QR visible
   until Sparrow accepts it, then exit that QR screen and return Home.
5. Finalize the fully signed transaction if Sparrow offers **Finalize**.
   Review it once more and click **Broadcast Transaction**.
6. Wait for Sparrow to show the broadcast transaction. If a signature is
   rejected, stop at that result and keep the test transaction for diagnosis.

You can copy the **TXID** from Sparrow's transaction view and include it in a
[project issue](https://github.com/FractalEncrypt/seedsigner-anti-exfil-review/issues)
with your device and whether signing and broadcast worked. Successful reports
help us collect real-world results; confusing steps and failures are useful too.

Optional timing: start when Step 1 first appears and stop when Sparrow verifies
the final protected signature. A rough time or comment about QR retries is enough.


### Optional: 2-of-2 multisig

Kern holds one seed at a time. After exporting A, unload/restart Kern
and load B to export it; reload A for signing, then B for its signature.

These single-device steps are newly documented and have not yet received
end-to-end physical qualification. Two seeds on one device test the workflow;
they do not represent two independent physical signers.


### Create accounts A and B and the wallet

1. Get A ready on **Kern**. Generate or load disposable seed **A** using the seed menus above.
   Record its fingerprint.
2. Export A's multisig account: choose **Extended Public Key → Multisig**. Confirm the default **Native
   SegWit** and **m/48'/1'/0'/2'**, account **0**, and show the account QR.
3. In Sparrow choose **File → New Wallet**, name it **Live 2of2 A-B**, select
   **Multi Signature / 2 of 2 / Native Segwit (P2WSH)**. Import the first key
   through **Airgapped Hardware Wallet → Kern → Scan**. Label it **A**
   and set **Protected signing → Required**.
4. Get B ready on **Kern**. Unload/restart Kern before loading B. Generate or load a different disposable seed **B** and note its
   fingerprint. Keep both private backups.
   Export its multisig account: choose **Extended Public Key → Multisig**. Confirm the default **Native
   SegWit** and **m/48'/1'/0'/2'**, account **0**, and show the account QR.
5. Import B into the second keystore through **Airgapped Hardware Wallet →
   Kern → Scan**. Label it **B**, set **Protected signing → Required**,
   and click **Apply**.
6. With Settings still visible, confirm **2 of 2**, the two fingerprints, and
   **m/48'/1'/0'/2'** on both keystores.

### Fund and prepare the transaction

Keep both seed backups handy during the faucet wait. Kern may unload after
its timer expires; SeedSigner keeps loaded seeds while powered on. Load the
Kern wallet descriptor after funding, close to signing.

1. In **Live 2of2 A-B → Receive**, label the address **Receive from faucet 1**,
   copy it, and request a small Testnet4 deposit from the
   [faucet](https://mempool.space/testnet4/faucet). Wait for confirmation.
2. Copy another unused Receive address in this same wallet. In **Send**, create
   a self-payment leaving room for change and fee, then choose **Finalize
   Transaction for Signing** if shown.
3. Open the wallet's **Settings** and click the QR icon beside **Descriptor**.
   Keep this policy QR available for signing.

### Get the signers ready

Reload **A on Kern** from its backup.

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
6. Confirm both signatures are accepted and finalize if offered. Click
   **Broadcast Transaction**, then record the hardware arrangement, whether
   both signatures and broadcast succeeded, and optionally the **TXID**.


## I have both

Complete the SeedSigner singlesig route first, then the Kern route. Use
your own disposable test seeds for these live wallets; each transaction you
create is fresh. Leave both wallet tabs available if you want to try multisig.

### 1. Connect Sparrow to Testnet4

1. Confirm **Testnet4** at the top-right of Sparrow.
2. Open **Tools → Preferences → Server**. Choose a public server for Testnet4
   or enter your own Testnet4 Electrum server. Close Preferences.
3. Turn on the server connection switch at the bottom-right. Wait for its
   connected status before creating or funding the wallet.


### 2. Generate or load a seed on SeedSigner

1. To create a seed, choose **Tools → New seed** with the camera icon. Follow
   the entropy and confirmation screens, then finish loading it. For a new
   test seed, leave the passphrase empty. To use an existing test seed, choose
   **Scan** for its seed QR or enter its words through the seed-loading menu.
2. Note the loaded seed's fingerprint. **Testnet** and **Required** signing
   were configured in Start Here before seed loading; keep those settings.
3. In the loaded seed's menu choose **Export xpub → Single Sig → Native
   Segwit**, then **Animated** or **Static → I understand →
   Export xpub**. Leave the account QR visible.

The singlesig derivation should be **m/84'/1'/0'**. Keep the disposable
seed backup handy.


### 3. Create the singlesig wallet in Sparrow

1. Choose **File → New Wallet**, name it **Live SeedSigner**,
   and select **Single Signature / Native Segwit (P2WPKH)**.
2. Choose **Airgapped Hardware Wallet → SeedSigner**, then **Scan**
   the device's account QR.
3. Check the fingerprint against the one you noted and the derivation against
   **m/84'/1'/0'**. Set **Protected signing → Required**, then click **Apply**.
4. With **Settings** still visible, confirm **Required** remains selected.
   Keep this wallet tab open and click **Receive** for the next step.



### 4. Fund the wallet

If this seed's account already has confirmed Testnet4 coins, continue to section 5.

1. In **Receive**, label the displayed address **Receive from faucet 1**, then
   copy the address.
2. Open the [mempool.space Testnet4 faucet](https://mempool.space/testnet4/faucet)
   and follow its instructions to request a small amount to that address.
3. Return to Sparrow and wait for the deposit to appear and confirm. The
   transaction will carry your receive-address label. Faucet availability
   and confirmation time vary; that wait is separate from signing.


### 5. Create a small self-payment


1. In **Receive**, get another unused address in the same wallet and copy it.
2. Open **Send**, paste that address, and enter an amount smaller than your
   confirmed balance so there is room for change and the fee.
3. Choose a fee using Sparrow's displayed estimate. Click **Create
   Transaction**, then **Finalize Transaction for Signing** if shown.
4. Review the payment, change, and fee in Sparrow before signing.


### 6. Complete protected singlesig and broadcast

1. Click **Protected QR**. Scan Sparrow's **Step 1 of 2** on the device using
   its **Scan** action.
2. Review the transaction on the device. Check the payment and fee against
   Sparrow, approve, and scan the device's first response into Sparrow's
   protected signing window. Wait until Sparrow displays **Step 2 of 2**.
3. On the device choose **Done**, then **Scan host reveal**. Scan Sparrow's
   **Step 2 of 2** on that same device, follow its review/approval screens,
   and scan the final device response into Sparrow.
4. Confirm **Protected signatures verified**. Keep SeedSigner's final QR visible
   until Sparrow accepts it, then exit that QR screen and return Home.
5. Finalize the fully signed transaction if Sparrow offers **Finalize**.
   Review it once more and click **Broadcast Transaction**.
6. Wait for Sparrow to show the broadcast transaction. If a signature is
   rejected, stop at that result and keep the test transaction for diagnosis.

You can copy the **TXID** from Sparrow's transaction view and include it in a
[project issue](https://github.com/FractalEncrypt/seedsigner-anti-exfil-review/issues)
with your device and whether signing and broadcast worked. Successful reports
help us collect real-world results; confusing steps and failures are useful too.

Optional timing: start when Step 1 first appears and stop when Sparrow verifies
the final protected signature. A rough time or comment about QR retries is enough.


### 1. Connect Sparrow to Testnet4

1. Confirm **Testnet4** at the top-right of Sparrow.
2. Open **Tools → Preferences → Server**. Choose a public server for Testnet4
   or enter your own Testnet4 Electrum server. Close Preferences.
3. Turn on the server connection switch at the bottom-right. Wait for its
   connected status before creating or funding the wallet.


### 2. Generate or load a seed on Kern

1. To create a seed, from the unloaded screen choose **New Mnemonic → From
   Camera**. Follow creation and confirmation; for a new test seed, leave the
   passphrase empty. You can choose another creation method instead. To load
   an existing test seed, use **Load Mnemonic → From QR Code** or word entry.
2. Note its fingerprint. Tap the orange circled **i** at the upper-left of Home
   to open **Wallet Settings**. Confirm **Network → Testnet** and **Anti-exfil
   signing** on. They may already be selected; change them only if needed.
   For a longer session, you can set the seed-unload timer to **30 minutes**.
   Return Home.
3. Choose **Extended Public Key**. It defaults to **Singlesig → Native
   SegWit**, account **0**, and displays the key-origin/xpub QR. Confirm those
   values and leave the QR ready for Sparrow.

The singlesig derivation should be **m/84'/1'/0'**. Keep the disposable
seed backup handy.


### 3. Create the singlesig wallet in Sparrow

1. Choose **File → New Wallet**, name it **Live Kern**,
   and select **Single Signature / Native Segwit (P2WPKH)**.
2. Choose **Airgapped Hardware Wallet → Kern**, then **Scan**
   the device's account QR.
3. Check the fingerprint against the one you noted and the derivation against
   **m/84'/1'/0'**. Set **Protected signing → Required**, then click **Apply**.
4. With **Settings** still visible, confirm **Required** remains selected.
   Keep this wallet tab open and click **Receive** for the next step.

On Kern, after importing, you can click **Show xpub** to compare the key text
with Sparrow's imported key. Click **OK** to leave the export screen.


### 4. Fund the wallet

If this seed's account already has confirmed Testnet4 coins, continue to section 5.

1. In **Receive**, label the displayed address **Receive from faucet 1**, then
   copy the address.
2. Open the [mempool.space Testnet4 faucet](https://mempool.space/testnet4/faucet)
   and follow its instructions to request a small amount to that address.
3. Return to Sparrow and wait for the deposit to appear and confirm. The
   transaction will carry your receive-address label. Faucet availability
   and confirmation time vary; that wait is separate from signing.


### 5. Create a small self-payment

If Kern unloaded its seed during the wait, reload the same seed from its
backup and confirm Testnet and anti-exfil on through the orange **i** first.

1. In **Receive**, get another unused address in the same wallet and copy it.
2. Open **Send**, paste that address, and enter an amount smaller than your
   confirmed balance so there is room for change and the fee.
3. Choose a fee using Sparrow's displayed estimate. Click **Create
   Transaction**, then **Finalize Transaction for Signing** if shown.
4. Review the payment, change, and fee in Sparrow before signing.


### 6. Complete protected singlesig and broadcast

1. Click **Protected QR**. Scan Sparrow's **Step 1 of 2** on the device using
   its **Scan** action.
2. Review the transaction on the device. Check the payment and fee against
   Sparrow, approve, and scan the device's first response into Sparrow's
   protected signing window. Wait until Sparrow displays **Step 2 of 2**.
3. On the device choose **Done**, then **Scan host reveal**. Scan Sparrow's
   **Step 2 of 2** on that same device, follow its review/approval screens,
   and scan the final device response into Sparrow.
4. Confirm **Protected signatures verified**. Keep Kern's final QR visible
   until Sparrow accepts it, then exit that QR screen and return Home.
5. Finalize the fully signed transaction if Sparrow offers **Finalize**.
   Review it once more and click **Broadcast Transaction**.
6. Wait for Sparrow to show the broadcast transaction. If a signature is
   rejected, stop at that result and keep the test transaction for diagnosis.

You can copy the **TXID** from Sparrow's transaction view and include it in a
[project issue](https://github.com/FractalEncrypt/seedsigner-anti-exfil-review/issues)
with your device and whether signing and broadcast worked. Successful reports
help us collect real-world results; confusing steps and failures are useful too.

Optional timing: start when Step 1 first appears and stop when Sparrow verifies
the final protected signature. A rough time or comment about QR retries is enough.


### Optional: 2-of-2 multisig

Keep **A on SeedSigner** and **B on Kern** for this multisig test.


### Create accounts A and B and the wallet

1. Get A ready on **SeedSigner**. Generate or load disposable seed **A** using the seed menus above.
   Record its fingerprint.
2. Export A's multisig account: choose **Export xpub → Multisig → Native Segwit**, then **Animated** or **Static**
   (either works), then **I understand → Export xpub** to show the QR.
3. In Sparrow choose **File → New Wallet**, name it **Live 2of2 A-B**, select
   **Multi Signature / 2 of 2 / Native Segwit (P2WSH)**. Import the first key
   through **Airgapped Hardware Wallet → SeedSigner → Scan**. Label it **A**
   and set **Protected signing → Required**.
4. Get B ready on **Kern**. Generate or load a different disposable seed **B** and note its
   fingerprint. Keep both private backups.
   Export its multisig account: choose **Extended Public Key → Multisig**. Confirm the default **Native
   SegWit** and **m/48'/1'/0'/2'**, account **0**, and show the account QR.
5. Import B into the second keystore through **Airgapped Hardware Wallet →
   Kern → Scan**. Label it **B**, set **Protected signing → Required**,
   and click **Apply**.
6. With Settings still visible, confirm **2 of 2**, the two fingerprints, and
   **m/48'/1'/0'/2'** on both keystores.

### Fund and prepare the transaction

Keep both seed backups handy during the faucet wait. Kern may unload after
its timer expires; SeedSigner keeps loaded seeds while powered on. Load the
Kern wallet descriptor after funding, close to signing.

1. In **Live 2of2 A-B → Receive**, label the address **Receive from faucet 1**,
   copy it, and request a small Testnet4 deposit from the
   [faucet](https://mempool.space/testnet4/faucet). Wait for confirmation.
2. Copy another unused Receive address in this same wallet. In **Send**, create
   a self-payment leaving room for change and fee, then choose **Finalize
   Transaction for Signing** if shown.
3. Open the wallet's **Settings** and click the QR icon beside **Descriptor**.
   Keep this policy QR available for signing.

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
6. Confirm both signatures are accepted and finalize if offered. Click
   **Broadcast Transaction**, then record the hardware arrangement, whether
   both signatures and broadcast succeeded, and optionally the **TXID**.

## Finish and report

Record broadcast separately from protected signing: after finalization, click
**Broadcast Transaction** and confirm the public server accepts it. For the optional
confirmation field, wait for the transaction to show at least one confirmation
in the wallet history. Leave confirmation **Not run** if you did not wait.


Close Sparrow normally. When you have finished using the funded test wallet,
unload its seed or power off the device. Keep its backup if you intend to spend
the remaining testnet coins later.

Use **FEEDBACK-LIVE.html** in the kit or the [full form](../FEEDBACK.html).
Add **Testnet4**, whether broadcast succeeded, your multisig arrangement if
used, and optionally the TXID. Submit through a
[project issue](https://github.com/FractalEncrypt/seedsigner-anti-exfil-review/issues).
A photo and the step where something failed are enough. Keep private seed
backups and wallet/profile files out of the report.

Rejection and recovery experiments are a separate optional **offline** session
with public fixtures. They are not required to complete this live test.
