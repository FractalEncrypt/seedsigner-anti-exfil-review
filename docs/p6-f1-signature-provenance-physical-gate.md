# P6-F1 signature-provenance physical gate

Date prepared: 2026-08-17

Gate completed: 2026-08-18

This is an unfunded Testnet4 regression gate for the signature-scoped
provenance remediation. Do not broadcast the synthetic transaction.

## Build under test

- Sparrow implementation head: `90c64c9d5fc121aa5235627301e35523cf067863`
- Drongo implementation head: `1bbafd94f08fd9105e20be30a6fdfe9a091fb675`
- Packaged executable:
  `C:\Users\FractalEncrypt\Documents\Windsurf\Sparrow_AntiExfil_Review_Fresh\build\jpackage\Sparrow\Sparrow.exe`
- Executable SHA-256:
  `66892bc6067c4efe111f20f24abc4651724dc04d70ecbcc162a3a43703294160`
- Application JAR SHA-256 (`build\libs\sparrow-2.5.4.jar`):
  `e7633d50cca6f66b15aa07548081ce05859d0b9344958635ff45be0b9f07772c`
- Synthetic PSBT:
  `C:\Users\FractalEncrypt\Documents\SeedSigner_AntiExfil\fixtures\protocol-v1-mixed-provenance.psbt`
- Synthetic PSBT SHA-256:
  `45e3877ac64ba8b759c646e7a1734072b783f181c340921efa99e007b07b4daa`

The Windows `jpackageImage` task completed. The subsequent optional MSI step
failed only because WiX is not installed; the executable above is complete.

## Launch an isolated profile

```powershell
$repo = "C:\Users\FractalEncrypt\Documents\Windsurf\Sparrow_AntiExfil_Review_Fresh"
$exe = "$repo\build\jpackage\Sparrow\Sparrow.exe"
$profile = "$repo\run\p6-f1-provenance-smoke-20260817"
Test-Path $exe
& $exe --dir $profile --network testnet4
```

Never use a production Sparrow profile for this gate.

## Create the 2-of-2 test wallet

Create a native-SegWit 2-of-2 multisig wallet. Import both keystores as
SeedSigner air-gapped devices so the UI permits the reviewed `Required`
policy.

Signer A:

- Label: `Required A`
- Fingerprint: `0fb882ff`
- Derivation: `m/48'/1'/0'/2'`
- Account xpub:
  `tpubDF3QYaRazZ44jHz3jaSPRGCLVYj7D8j4mVVUTCr3CHsfuvoV2Z73eTcvHc8sP3Dj58yEfkG57iBpKTuHv3dNAUcFufCxx26SAbrWque5gts`
- Protected signing: `Required`

Signer B:

- Label: `Required B`
- Fingerprint: `73c5da0a`
- Derivation: `m/48'/1'/1'/2'`
- Test mnemonic:
  `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`
- Standard numeric SeedQR:
  `docs/assets/p6-f1-signer-b-standard-seedqr.png`
- SeedQR PNG SHA-256:
  `f6c86e09b8b6e0b42181923a19f5034419f6279386b6408928167d27c72bed1b`
- Account xpub:
  `tpubDEYM1BmQ5rp2PWKvCgvQxNeUrEv8gu5819xRdmu6S23fYpS8x2icwAeoVaBTLyN3fGWJQcWoaiKMduTXWKtG9bXNpVrZPRF7XVxrANtAEcR`
- Protected signing: `Required`

The PSBT already contains a valid ordinary signature from signer B. It still
needs signer A's signature.

To make Sparrow classify signer B as a SeedSigner, first scan the signer-B
SeedQR into SeedSigner. `Custom Derivation` is disabled by default: first open
`Settings` > `Advanced` > `Script types`, enable `Custom Derivation`, and
confirm the setting. Then choose `Export Xpub` > `Multisig` >
`Custom Derivation`, enter `m/48'/1'/1'/2'`, and import the displayed xpub
through Sparrow's SeedSigner air-gapped-wallet entry point. Do not use the
default account-0 multisig export (`m/48'/1'/0'/2'`) for signer B. Sparrow's
derivation field is intentionally read-only; the derivation must arrive with
the exported xpub. Before continuing, verify Sparrow shows both the expected
derivation and the expected `tpubDEYM...` account xpub above. Merely pasting
the xpub or descriptor creates a generic import and does not expose the
protected-signing policy. After the wallet is configured, discard signer B
from SeedSigner and load signer A for the actual protected ceremony.

## SeedSigner setup

Use the already-tested corrected instrumented SeedSigner image. After signer
B's xpub has been imported into Sparrow, discard B and load signer A's test
mnemonic for the ceremony:

`model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast`

Keep SeedSigner on testnet. No funded UTXO or broadcast is involved.

## Gate 1: mixed provenance must be rejected

1. Open `protocol-v1-mixed-provenance.psbt` in the isolated Sparrow profile.
2. Select the `Required A` keystore and run `Protected QR (Required)`.
3. Complete the four-stage QR exchange with SeedSigner.
4. Expected: Sparrow rejects the returned PSBT because signer B's ordinary
   signature has no matching verified ceremony proof. A proof for signer A
   must not authorize signer B.
5. Expected: the original PSBT remains available for inspection and is not
   finalized or broadcast.

## Gate 2: legitimate protected signature remains usable

1. Change signer B's policy from `Required` to `Optional`.
2. Run the protected action for signer A again. Sparrow may reuse the exact
   completed durable session instead of repeating the QR exchange.
3. Expected: Sparrow accepts and combines signer A's protected signature.
4. Expected: the PSBT now has both valid signatures and does not freeze or
   lose the ceremony result.

## Gate 3: proof survives close and reopen

1. Save the accepted signed PSBT to the isolated profile directory.
2. Close Sparrow normally and relaunch the same isolated profile.
3. Open the test wallet, then reopen the saved signed PSBT.
4. Expected: Sparrow revalidates the retained `.aexs` session, restores only
   signer A's matching proof, and permits finalization with signer B still
   `Optional`.
5. Expected: there is no read-only quarantine warning and the final
   transaction can be displayed or saved. Do **not** broadcast it.

The first physical run at `fe4510d` exposed a finalized-PSBT reattachment
defect: signature attribution incorrectly depended on wallet transaction-history
nodes, leaving `View Final Transaction` disabled after reopen. `90c64c9` now
verifies finalized signatures directly against the PSBT derivations and signing
digest. It also renders quarantine status as visible text and disables offline
final-transaction display/export while quarantined. Gate 3 must be rerun on the
corrected head; Gates 1, 2, and 4 passed on the preceding head.

The corrected Gate 3 run passed at `90c64c9`: after closing Sparrow, reopening
the same isolated profile and wallet, and loading the saved signed PSBT,
Sparrow revalidated the durable session, restored signer A's exact proof,
enabled `View Final Transaction`, displayed the extracted raw transaction, and
enabled `Broadcast Transaction`. The synthetic transaction was not broadcast.

## Gate 4: unsupported-model UI guard

Inspect an air-gapped keystore whose model is Passport or Specter DIY.
Expected: `Required` is not offered. A pre-existing incompatible `Required`
value, if loaded, is preserved with a warning and can be lowered; Sparrow
does not silently rewrite it.

Record pass/fail, Sparrow commit, executable hash, and any screenshots in the
final smoke checkpoint before tagging.

## Completed result

All four gates passed. Evidence and the saved finalized PSBT are retained in
`docs/assets/p6-f1-smoke/` and indexed with SHA-256 hashes in
`final-smoke-checkpoint.json`.
