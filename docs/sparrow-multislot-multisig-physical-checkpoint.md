# Sparrow multi-input and multisig physical checkpoint

Recorded 2026-08-10 on Testnet4 with the isolated Sparrow development profile
and the physical SeedSigner protocol-v1 image.

## Result

The frozen multi-slot protocol completed and broadcast two new real transaction
shapes:

1. A native-SegWit single-signature transaction with 3 inputs and 6 outputs.
   Two outputs funded the multisig wallet and other outputs retained disposable
   self-spend UTXOs. Txid:
   `fb10ca40e72a4b90b0cc442bb2ff84b3b5a2c01c09124e1ad49dd5e748988f81`.
2. A native-SegWit P2WSH 2-of-3 transaction with 2 inputs and 3 outputs. Two
   separate SeedSigner keystores completed independent protected ceremonies,
   Sparrow reconstructed both verified signatures into the original PSBT, and
   the final transaction was broadcast successfully. Txid:
   `3a77ac86b4b96272b16ab105380f08f24d98c71994e7ebbe119c93da3a1b48d3`.

All three multisig keystores were configured as **Protected signing:
Required**. The wallet used:

```text
wsh(sortedmulti(2,[6f9abf05/48h/1h/0h/2h]tpubDERA5QNj2uyC2m5fKy6xVM6CBb7dWHiCJWn1qUocxxw9zA2cqaf1A6bDnnxZbw9vbcX9KeCBMAaU6XV352yuVqpe4gmMiLyTytBtC1SkXpL/<0;1>/*,[0fb882ff/48h/1h/0h/2h]tpubDF3QYaRazZ44jHz3jaSPRGCLVYj7D8j4mVVUTCr3CHsfuvoV2Z73eTcvHc8sP3Dj58yEfkG57iBpKTuHv3dNAUcFufCxx26SAbrWque5gts/<0;1>/*,[b4899a09/48h/1h/0h/2h]tpubDEqAYCKA9YjD4bKZM2Y35oAegmWV5MGAC3LE2K9x9yRSETgDEnouGTQiyv2PxhLWdsHtz3vZcotrS83xzYjNnqsQ7B4QXHG9q5rnfSuy2tn/<0;1>/*))#keuesawg
```

The descriptor and extended public keys are Testnet4 public data; no seed words
or private keys are retained here.

## Interruption behavior

During the second cosigner ceremony, the operator left SeedSigner at its
descriptor prompt to verify the multisig addresses. Sparrow had not yet
accepted that signer opening or released the host reveal. Reopening Protected
QR therefore resumed step 1 and accepted the already pending signer response.
This is a valid pre-reveal resume, not a selective-abort retry. The ceremony
then completed normally.

An older incomplete history for another wallet key produced Sparrow's
selective-abort warning before a new session, as required.

## Defects found and local corrections

Two consecutive SeedSigner keystore imports initially decoded the immediately
preceding xpub, temporarily duplicating another cosigner. Intervening scans
cleared the condition and the correct keys were ultimately applied. Sparrow now:

- drains the first 500 ms of camera results after a scanner opens;
- retains the existing early fountain-stream conflict recovery;
- rejects an imported xpub if another cosigner slot already contains it; and
- unregisters a keystore import dialog whenever it is hidden.

The uninterrupted SeedSigner shortcut also asked for the same seed again after
message 3. `ScanAntiExfilHostRevealView` now preserves the selected seed only
for that direct continuation. Exiting to the main menu still clears the seed,
so the already-tested stateless recovery path remains unchanged.

Automated verification after these fixes:

- 15 focused SeedSigner anti-exfil view tests pass.
- The applicable SeedSigner suite passes 185 tests with 2 skipped; the known
  stock Windows CompactSeedQR bitmap module remains excluded.
- Sparrow's focused scanner and duplicate-keystore tests pass.
- The complete Sparrow application task discovers 147 tests: 143 pass and only
  the same four Windows CRLF/LF export comparisons fail.

The scanner/import correction can be physically checked on the next Sparrow
launch without rebuilding SeedSignerOS. The uninterrupted seed-continuation
change should be included in the next combined SeedSigner image rather than
triggering a standalone 40-minute build.
