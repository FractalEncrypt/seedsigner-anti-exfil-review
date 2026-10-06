# Singlesig and multisig testnet ceremonies

Complete the [novice quickstart](../TESTING-QUICKSTART.md), signer preparation,
and [isolated Sparrow setup](sparrow-isolated-test-profile.md) first.

This is the live funded-testnet path. For offline public fixtures, use
[Offline public-fixture testing](offline-public-fixture-testing.md) instead.
Never broadcast the kit's synthetic PSBTs.

Use only device-generated disposable seeds and testnet coins. Keep Testnet3 and
Testnet4 funds separate even though their addresses share test encodings.

## Before timing anything

Record:

- Sparrow network and exact commit;
- dedicated Sparrow home path (sanitize your username when reporting);
- signer type and exact SeedSigner/Kern identity;
- computer OS/version, CPU architecture, display resolution/scaling;
- camera model/backend and signer board/display;
- approximate ambient lighting and display-to-camera distance; and
- whether this is singlesig or multisig.

Practice navigating the menus once without signing if needed. Measure the
ceremony itself separately from installation, wallet creation, faucet waiting,
and block confirmation.

## Singlesig path

1. On the signer, create one fresh disposable seed using camera or dice entropy.
2. In the isolated Sparrow profile, create a wallet on the selected test
   network and import the signer's account xpub through the correct SeedSigner
   or Kern air-gapped-wallet path.
3. Confirm the signer model/profile is correct. Set protected signing to
   **Required** on the Sparrow keystore. On SeedSigner choose the test network
   and Required anti-exfil signing; on Kern choose Testnet and enable Anti-exfil
   signing. Use the named hardware-wallet creation steps in the
   [offline guide](offline-public-fixture-testing.md#2-create-named-hardware-wallets-in-sparrow),
   substituting your fresh device-generated seed/account and a distinct live
   wallet name. Verify its fingerprint and `m/84'/1'/0'` derivation.
4. Display a fresh receiving address in Sparrow and verify it on the signer
   when the device workflow supports address verification.
5. For this live path only, turn Sparrow's server connection on and configure
   a server for the selected network. Obtain a small amount of matching-network
   test BTC:
   - Testnet4: <https://mempool.space/testnet4/faucet>
   - Testnet3: <https://coinfaucet.eu/en/btc-testnet/>
6. Wait for Sparrow to see the UTXO. Confirm the explorer and Sparrow show the
   same test network.
7. Create a small self-spend to a new address in the same disposable wallet.
   Do not use Mainnet and do not reuse a faucet deposit address as a permanent
   identity.
8. In Send, create the transaction, then choose **Finalize Transaction for
   Signing** if shown before the signing actions. Click **Protected QR**.
   Start a stopwatch when Sparrow first
   presents the signing QR.
9. Follow the labeled rounds without switching to ordinary **Show QR** signing:
   scan Sparrow's request on the signer, return the signer opening/commitment,
   scan Sparrow's challenge, and return the final response as prompted.
10. Stop timing when Sparrow accepts and verifies the protected signature.
11. Record total protected ceremony time and, if practical, the time attributable
    to the added exchange. Record every retry, timeout, or repositioning.
12. Inspect the transaction state. Broadcast only if you intentionally want to
    test Testnet3/Testnet4 broadcast and have reconfirmed the network. A signing
    UX report does not require broadcast.

## Multisig path

The simplest community test is 2-of-2 or 2-of-3 with separate disposable
cosigner seeds. At least one cosigner must use the protected SeedSigner/Kern
path. The others may be additional disposable air-gapped signers or explicitly
test-only software cosigners; report exactly which is which.

1. Generate each seed independently. Label them A, B, and optionally C without
   recording the mnemonic in the report.
2. Create a named wallet in isolated Sparrow: **File → New Wallet**, **Multi
   Signature**, **2 of 2**, native SegWit P2WSH. On each device export the
   multisig native SegWit account 0 at `m/48'/1'/0'/2'`. Import through each
   matching hardware-brand route. Verify fingerprints and paths, set both
   keystores to **Required**, and **Apply**. The offline guide walks through
   these menus; use your fresh disposable accounts instead of its public ones.
3. Export and verify the multisig wallet policy on every participating hardware
   signer before funding it.
4. Record the quorum, script type, cosigner order, and which signer policies are
   **Optional**, **Required**, or unsupported.
5. Fund one verified receiving address with matching-network test BTC.
6. Create a small self-spend. Sign with the protected signer through the full
   protected QR exchange.
7. Add the remaining signature or signatures without changing cosigner order,
   network, wallet policy, or transaction.
8. Confirm Sparrow attributes protected evidence only to the signature that
   completed the protected ceremony. An ordinary cosigner must not inherit that
   status.
9. Record timing separately for each signer and for the complete quorum.
10. Finalize or broadcast only on the intended test network and only if that is
    part of the declared test.

Using one physical device sequentially with several disposable seeds can test
workflow shape, but it is not evidence about concurrent ownership by distinct
people or independent devices. State that limitation in the report.

## Useful negative checks

After one successful run, optionally test one condition at a time:

- follow the exact [recovery walkthrough](recovery-tests.md), using separate
  synthetic fixtures rather than improvising with a funded PSBT;
- scan an unrelated or stale QR;
- try an ordinary signature against a **Required** protected policy;
- close and reopen the isolated profile during the documented recovery stage;
- change camera distance or lighting; or
- repeat on a second OS, camera, display, or supported board.

Never improvise with real funds. If Sparrow accepts an ordinary or mismatched
signature where a required protected signature should fail closed, do not
broadcast; preserve sanitized logs and follow [SECURITY.md](../SECURITY.md).

## Cleanup

1. Close Sparrow and record whether a normal shutdown succeeded.
2. Return the signer to Seedless/Unloaded.
3. Remove any device microSD used only for the test.
4. Do not upload the Sparrow home, wallet database, coordinator state, seed,
   mnemonic, private descriptor, or unredacted logs.
5. Complete the [feedback template](user-test-feedback-template.md).
