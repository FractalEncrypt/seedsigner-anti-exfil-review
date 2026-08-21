# Sparrow phase-7 no-broadcast physical gates

These checks use Testnet4 and must not broadcast. Use only the isolated Sparrow
development profile and disposable signing material for the abandonment test.

## Recorded result

The phase-7 physical security gates passed on 2026-08-10:

- the copied phase-6 profile migrated with the SeedSigner brand, xpub, UTXOs,
  and `REQUIRED` policy intact;
- the disposable post-reveal interruption displayed the exact-session warning,
  restored message 3, and accepted the already-produced matching message 4;
- an ordinary SeedSigner signature returned to a `REQUIRED` keystore was
  rejected with **Protected signature rejected** and never became an accepted
  finalized/broadcast-ready transaction.

The first downgrade attempt exposed a fail-open attribution defect: an ordinary
hardware-wallet return could finalize and strip the UTXO/derivation metadata
needed to attribute its signature. The corrected gate uses the original PSBT as
authoritative signer context and fails closed when a signed return for an
eligible required signer cannot be attributed. A focused animated-UR regression
also covers recovery from one stale camera-buffer fragment; first-open physical
camera behavior remains an explicit observation item below.

## 1. Migration and capability smoke test

1. Make a filesystem copy of `run/profile-phase6-01` while Sparrow is closed.
2. Launch the phase-7 Sparrow worktree with that isolated profile and
   `--network testnet4`, using the command in
   `docs/sparrow-isolated-development-profile.md`.
3. Open the phase-6 wallet. Its SeedSigner brand, xpub, UTXOs, and protected
   policy must remain intact. Settings must show **Protected signing: Required**.
4. Optional non-SeedSigner UI smoke test: if another air-gapped device is
   available, import its keystore under its real device brand. Settings must
   offer **Unsupported**, **Optional**, and **Required** without changing that
   brand. Leave devices that do not implement AEXT set to **Unsupported**. A
   plain xpub/watch-only import does not represent an air-gapped device and is
   therefore not expected to show this selector. Do not deliberately import a
   SeedSigner xpub under a false device brand merely to satisfy this smoke test;
   the automated phase-7 suite already covers device-neutral policy metadata.

Opening the old profile with phase 7 applies database migration V12. Use the
copied profile to return to the older phase-6 build if necessary.

## 2. Ordinary-signature downgrade rejection

1. In a Testnet4 wallet whose matching keystore is **Required**, create a fresh
   unsigned self-spend but do not select **Protected QR**.
2. Export the ordinary PSBT with **Show QR** and sign it on the matching device
   through its ordinary signing path. If the device itself requires protected
   signing, use disposable matching material with the device policy temporarily
   optional; Sparrow's keystore policy must remain **Required**.
3. Return the ordinary signed PSBT with Sparrow's **Scan QR** action.
4. Sparrow must show **Protected signature rejected** and must not accept,
   finalize, or broadcast the returned signature.
5. Close the transaction tab. Retain only screenshots/logs; do not broadcast.

If Sparrow instead accepts a finalized return, stop without broadcasting. A
hardware wallet may remove UTXO and derivation metadata while finalizing its
PSBT; the required-policy gate must use the original unsigned PSBT as its
authoritative signer context and reject an otherwise unattributable signed
return fail-closed.

Acceptance: the signature is attributable to the required keystore, lacks
internally verified AEXT provenance, and is rejected before it can become the
wallet's accepted signed transaction.

## 3. Disposable-key post-reveal abandonment

1. Generate the existing public SeedSigner-compatible single-input fixture.
   This command also exercises an older terminal transcript, but only its
   unsigned `seedsigner-p2wpkh.psbt` and public mnemonic are used here:

   ```powershell
   cd C:\Users\FractalEncrypt\Documents\SeedSigner_AntiExfil
   $env:PYTHONPATH = "$PWD\src"
   $py = "$PWD\.venv\Scripts\python.exe"
   $sssrc = "C:\Users\FractalEncrypt\Documents\Windsurf\SeedSigner_AntiExfil\src"
   $fixtureRun = "$PWD\run\sparrow-phase7-disposable-01"

   & $py -m anti_exfil demo-rung-d `
     --run-dir $fixtureRun `
     --seedsigner-src $sssrc
   ```

   The public fixture mnemonic is:

   ```text
   model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast
   ```

   Never send funds to this mnemonic.
2. Load that public mnemonic on SeedSigner and export its native-SegWit Testnet
   xpub (`m/84'/1'/0'`). In the isolated Testnet4 Sparrow profile, create a new
   wallet and import the xpub through the real **SeedSigner** air-gapped-device
   route. Mark its keystore **Required**. The wallet does not need to synchronize
   or contain a blockchain UTXO.
3. In Sparrow use **File > Open Transaction > File** and open:

   ```text
   C:\Users\FractalEncrypt\Documents\SeedSigner_AntiExfil\run\sparrow-phase7-disposable-01\fixtures\seedsigner-p2wpkh.psbt
   ```

   The PSBT spends a fabricated outpoint but includes a 100,000-sat witness
   UTXO, a 90,000-sat output, SIGHASH_ALL, and the matching BIP32 derivation.
   It can exercise signing but cannot spend a real coin or be broadcast as a
   valid transaction.
4. Start **Protected QR** and complete messages 1 and 2.
5. Let Sparrow accept message 2 and display message 3. This is the post-reveal
   boundary: the host randomness has now been released and the durable session
   must be retained.
6. After SeedSigner has scanned message 3 and is displaying message 4, close
   Sparrow's message-4 scanner without returning message 4. Then reopen
   **Protected QR** for the same PSBT.
7. Sparrow must warn about/resume the retained session and offer the exact retry
   path. It must not silently create a fresh challenge. Redisplayed message 3
   must be byte-identical to the retained reveal.
8. If SeedSigner is already displaying message 4, it is valid to scan that
   retained response into Sparrow's restored step-2 scanner; do not regenerate
   a signature. Otherwise end the disposable test without importing a
   signature. Never broadcast this fabricated-outpoint transaction.

Acceptance: abandonment is journaled, exact-session retry remains available,
fresh-challenge risk is explicit, and no signed transaction or broadcast is
produced.

## Evidence to retain

- phase-7 Sparrow and Drongo commit identities;
- isolated profile path and Testnet4 indicator;
- migrated keystore brand and three-state policy screenshots;
- ordinary-signature rejection screenshot;
- post-reveal warning/retry screenshot;
- hashes of the retained `.aexs` and `.aexj` files;
- explicit statements that both tests used disposable/testnet data and did not
  broadcast.
- whether each SeedSigner animated QR completed on the scanner's first opening;
  a scanner that remains at only a few percent until it is closed and reopened
  indicates a stale camera-buffer fragment and fails the first-open UX check.
