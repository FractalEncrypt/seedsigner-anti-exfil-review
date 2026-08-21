# Clean Sparrow sequential-xpub import smoke test

Purpose: physically confirm the final camera-drain and duplicate-cosigner
hardening. This is unfunded and does not create a usable production wallet.

## Launch the tested packaged review build

```powershell
$repo = "C:\Users\FractalEncrypt\Documents\Windsurf\Sparrow_AntiExfil_Review_Fresh"
$exe = "$repo\build\jpackage\Sparrow\Sparrow.exe"
$profile = "$repo\run\xpub-import-smoke-20260812"

Test-Path $exe
Test-Path $profile
& $exe --dir $profile --network testnet4
```

The first command must return `True`; the second should return `False` before
the first launch. Verify the UI says **Testnet4**, starts with no wallets, and
uses no installed-Sparrow wallets.

Gradle fallback, using the already installed JDK:

```powershell
Set-Location $repo
$env:JAVA_HOME = "C:\Users\FractalEncrypt\Documents\Windsurf\Sparrow_AntiExfil\.tools\jdk-25.0.2+10"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
.\gradlew.bat run --args="--dir $profile --network testnet4"
```

## Prepare three public keys

Load three distinct disposable seeds into SeedSigner. For each, export the
native-SegWit multisig xpub at `m/48'/1'/0'/2'`. Record only their distinct
fingerprints; never record the mnemonics.

## Test sequence

1. In Sparrow create a new **2 of 3**, **Native Segwit (P2WSH)** wallet.
2. Display seed 1's xpub before opening cosigner 1's **SeedSigner > Scan**.
   Confirm cosigner 1 receives seed 1's fingerprint and tpub.
3. Display seed 2's xpub before opening cosigner 2's scan. Confirm it receives
   seed 2—not the previously scanned seed 1.
4. For cosigner 3, deliberately scan seed 2 again. Sparrow must show
   **Duplicate Keystore** and must not populate or replace cosigner 3.
5. Display seed 3 and scan again. Confirm all three fingerprints/tpubs are
   distinct and retain **Airgapped Wallet (SeedSigner)** without brand changes.
6. Cancel or discard the wallet. Do not fund it.

Pass criteria: the first camera opening for each cosigner captures the currently
displayed xpub, duplicate input is explicitly rejected, and no stale/duplicate
xpub silently populates another cosigner.

## Result — 2026-08-12

Passed physically in the packaged clean Sparrow review build. The deliberate
duplicate scan produced the **Duplicate Keystore** modal and did not populate
cosigner 3. The subsequent scan produced three distinct fingerprints/tpubs,
all retaining **Airgapped Wallet (SeedSigner)**.

The repeat confirmed all three generic tpub-field camera imports remain
**Unsupported**, as required. Only **Import > SeedSigner > Scan** declares
compatibility and should default every resulting keystore to **Optional**. A
final explicit-import observation must confirm the policies—not merely the
displayed SeedSigner device type—before this checkpoint is frozen. No wallet
was funded.

The repeat also confirmed that the camera preview briefly displayed buffered
frames from the previous scan before switching to the live view. Decoder input
was already suppressed during the 500 ms drain window, so stale data was not
accepted. The clean Sparrow worktree now suppresses the preview during that
same interval; its focused regression passes and awaits one visual smoke check.
