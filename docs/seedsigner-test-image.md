# SeedSigner test image and initial setup

Use the **normal** Pi Zero image from your chosen frozen or post-sync set.
Verify the ZIP first using [Download and verify](download-and-test.md#2-verify-before-opening-applications-or-flashing).
No source build or Docker is needed for this route.

## Flash the dedicated microSD card

Flashing overwrites the selected card. Remove unrelated removable drives and
confirm the target's identity/capacity before clicking Flash. If balenaEtcher
already opens, skip installation. Otherwise install it from
[balena](https://etcher.balena.io/); Windows with WinGet can use:

```powershell
winget install --exact --id Balena.Etcher --source winget
```

1. Extract `seedsigner-pi0-SET-normal.zip` completely.
2. Power off SeedSigner and insert its dedicated card into the computer.
3. In Etcher choose **Flash from file** and the extracted `.img`.
4. Choose the dedicated microSD card, flash, and wait for successful validation.
5. Eject safely, insert the card into the powered-off Pi Zero, then power on.
6. Confirm Home, camera, and buttons work.

## Prepare the offline test wallet

1. Extract the v2 public kit and open **Open-Test-Cases.html**.
2. Select seed **A**, use SeedSigner's **Scan** to load its seed QR, and confirm
   fingerprint **0fb882ff**. Use no BIP39 passphrase.
3. In Settings select the test network; under **Advanced → Anti-exfil signing**
   select **Required**. Recheck the setting after a restart.
4. With seed A loaded, choose **Export xpub**, **Single Sig**, **Native Segwit**,
   and the Sparrow QR format. Use account 0; verify `m/84'/1'/0'` and fingerprint.
5. Follow [Offline public-fixture testing](offline-public-fixture-testing.md)
   to import it into the named Sparrow hardware wallet and complete signing.

For 2-of-2, export again with **Multisig**, native SegWit P2WSH, account 0,
`m/48'/1'/0'/2'`, following the multisig section of that guide.

## Frozen artifact distinction

The normal frozen image is a new build from the frozen source versions.
`seedsigner-pi0-frozen-campaign-instrumented.zip` contains the unchanged
historical instrumented image with SHA-256
`adc2b58ae9dd57e884ec33b0e39ebf608ee8cc468d3fa7c563a1f1f808550fb3`.
It is for campaign review, not this novice interactive workflow. The normal
image needs its own physical qualification and cannot inherit that old result.

For the complete source-build route, use [Windows](build-from-source-windows.md)
or [Linux](build-from-source-linux.md). For funded testnet transactions, use the
[live guide](end-to-end-testnet-testing.md) with a fresh disposable seed.
