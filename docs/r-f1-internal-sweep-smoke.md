# R-F1 internal-sweep physical smoke

Date prepared: 2026-08-20

This is a short Testnet4 UI gate for the narrowly scoped raw-transaction
quarantine correction. Do not use a mainnet key and do not broadcast the test
transaction.

## Build under test

- Sparrow implementation head: `7674cecde48335e0b55454f6fa53c8187a459932`
- Linux CI-only merge: `2c5d768efd86d2fca624ea35ecbe23635ab7be41`
- Public Linux CI: `https://github.com/FractalEncrypt/sparrow/actions/runs/32305165978`
- Packaged executable:
  `C:\Users\FractalEncrypt\Documents\Windsurf\Sparrow_AntiExfil_Review_Fresh\build\jpackage\Sparrow\Sparrow.exe`
- Executable SHA-256:
  `66892bc6067c4efe111f20f24abc4651724dc04d70ecbcc162a3a43703294160`
- Application JAR SHA-256 (`build\libs\sparrow-2.5.4.jar`):
  `e012ab79c5c21f2c2fd63f0ff710850e22bfc3546657f03edcb906ab28964d8e`

The first physical attempt at implementation head `2fc2bc2` opened the
internally generated sweep without a quarantine warning, confirming that its
source-scoped authorization worked. However, the signatures and broadcast
controls were not displayed after Sparrow's redundant funding-transaction
refetch failed. Head `623ae5b` carries the sweep's already-known fee into the
transaction tab and initializes the signed-transaction controls immediately;
the internal sweep no longer depends on that refetch for its usable UI state.

The second physical attempt at head `623ae5b` passed Gate A but exposed a
fail-open state transition in Gate B: the reopened file began without the
ephemeral sweep origin, but a successful reference fetch attached a
`BlockTransaction` display object and the policy code incorrectly treated that
metadata as authorization. Head `2b36ba4` removes that shortcut. Fetched block
metadata grants no provenance; only positive wallet/signature attribution or
the still-valid, source-scoped internal-sweep origin can permit a signed raw
transaction.

The third physical attempt at head `2b36ba4` confirmed that the external file
was fail-closed, but the signed-transaction section itself remained hidden
while reference fetching was pending or unavailable, so neither the reason nor
the disabled controls were visible. Head `87d4232` initializes that section
immediately for every signed raw import. The provenance warning and disabled
controls no longer depend on network reference fetching.

The final physical Gate B run at head `87d4232` passed once the attributable
source wallet was closed: both controls were disabled and the visible warning
reported `POLICY_CONTEXT_UNAVAILABLE`. Reopening the non-Required source wallet
correctly lifted quarantine through positive signature attribution; that is a
separate permitted route, not persistence of the internal-sweep exemption.
Clicking `View Final Transaction` while that raw transaction was permitted
exposed an unrelated null-pointer path. Head `4d56a16` keeps this PSBT-only
action disabled for all raw transactions while leaving legitimate Broadcast
availability unchanged.

A subsequent lifecycle check at head `4d56a16` showed that importing the source
wallet after the raw transaction did not lift quarantine: the existing
`OpenWalletsEvent` path refreshed PSBT tabs only, and the wallet could announce
itself before its transaction history was available for signature attribution.
Head `7674cec` refreshes raw policy on wallet-open, wallet-history-finished, and
wallet-history-changed events. If multiple open wallets fully attribute the
signature, a `Required` policy takes precedence over a permitting Optional or
Unsupported wallet.

The final three-state lifecycle gate passed physically on head `7674cec`:

1. With the source wallet closed, the imported raw transaction displayed
   `POLICY_CONTEXT_UNAVAILABLE`; Broadcast and View Final were disabled.
2. Opening and synchronizing the attributable SeedSigner source wallet removed
   the warning and enabled Broadcast while View Final remained disabled.
3. Closing the source wallet restored the same visible quarantine as step 1.

No transaction was broadcast.

## Launch an isolated profile

```powershell
$repo = "C:\Users\FractalEncrypt\Documents\Windsurf\Sparrow_AntiExfil_Review_Fresh"
$exe = "$repo\build\jpackage\Sparrow\Sparrow.exe"
$profile = "$repo\run\r5"
Test-Path $exe
& $exe --dir $profile --network testnet4
```

Do not use a production Sparrow profile.

## Prerequisite

Sparrow's sweep dialog discovers UTXOs from the connected server before it can
construct a signed transaction. Use a disposable Testnet4 private key that has
at least one spendable Testnet4 output worth more than dust plus the selected
fee. No mainnet or economically valuable funds are required.

## Gate A: internal sweep remains usable

1. Connect Sparrow to Testnet4 and open or create a disposable destination
   wallet.
2. Select `Tools` > `Sweep Private Key`.
3. Enter the disposable Testnet4 private key, select the script type matching
   its funded address, and select a destination address from the disposable
   wallet.
4. Let Sparrow construct and sign the sweep transaction. The controls must
   initialize from the locally constructed signed transaction even if a later
   funding-transaction refetch fails.
5. Expected: the signed raw-transaction tab opens without a read-only
   protected-signing warning.
6. Expected: `Broadcast Transaction` is enabled.
7. Capture a screenshot, but **do not click Broadcast Transaction**.

## Gate B: the exemption is ephemeral

1. Save the raw transaction from Gate A.
2. Close its transaction tab.
3. Close the source wallet that owns the swept input. Merely closing the
   transaction tab is not sufficient: an open source wallet can positively
   attribute its ordinary signature and legitimately permit the raw
   transaction when no `Required` policy participates.
4. Reopen the saved raw transaction through `File` > `Open Transaction` >
   `File`.
5. Expected: the reopened transaction is read-only because it has no
   attributable policy context.
6. Expected: the visible provenance warning is present and
   `Broadcast Transaction` is disabled.
7. Expected: `View Final Transaction` remains disabled because the imported
   payload is already a final raw transaction, not a PSBT.

This negative gate confirms the internal authorization is not serialized into
the transaction and cannot be reacquired through a file import. Cross-window
loss and byte-mutation invalidation are covered by automated regressions.

## Automated evidence

- Complete focused Sparrow anti-exfil suite: 20 passed, 0 failed, 0 skipped.
- Full Windows Sparrow suite: 151 passed; four unchanged CRLF-vs-LF
  golden-export comparisons failed (Caravan 1, Coldcard 2, Specter DIY 1).
- Public Linux CI: passed.
- `jpackageImage`: passed.

## Physical evidence

- `assets/r-f1-smoke/gate-b-source-wallet-closed.png`
  - SHA-256: `8686f76e9d87abd6ea92aaf0ca6df6df2810aa3f0351517d4228baad49a00146`
- `assets/r-f1-smoke/gate-b-source-wallet-open.png`
  - SHA-256: `8b469d1a5e60dbfc38787e4551cb62ccad4436e31e2efadcba6642415201a8cb`
- `assets/r-f1-smoke/gate-b-signed-sweep.txn`
  - SHA-256: `fc08587773f5e1840616199a53092bf5e9181faf45a4058a19733f2ed460e473`

The closed-wallet screenshot also represents the identical state restored in
step 3.
