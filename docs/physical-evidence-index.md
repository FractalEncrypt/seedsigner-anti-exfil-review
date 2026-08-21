# Physical and integration evidence index

Status: maintainer evidence inventory through 2026-08-20

This index distinguishes deterministic test artifacts from operator-observed
physical behavior. Testnet coins and published fixture keys have no monetary or
secrecy value. No mainnet signing was performed.

## Evidence chain

| Gate | Evidence | What it establishes |
| --- | --- | --- |
| Native Windows compatibility | `native-windows-checkpoint.json` | Pinned native symbols and differential checkpoint on Windows |
| First physical four-message ceremony | `protocol-v1-physical-checkpoint.json` | SeedSigner camera/display path and one-slot prototype ceremony |
| Frozen multi-slot device ceremony | `device-ui-qr-test-commands.md` and project status | Four-input/five-slot AEXT exchange, stateful and stateless message-3 recovery |
| Physical rejection matrix | `protocol-v1-physical-rejection-checkpoint.json` | Parser, semantic, stage, transcript, reveal, and opening failures stop signing |
| Focused parser/UX retest | `protocol-v1-next-image-physical-checkpoint.json` | Missing-UTXO/broken-script errors stop before stock parser; seed-first route works |
| Formal SeedSignerOS integration | `seedsigner-os-integration-checkpoint.json` | Selective OS package/config integration and normal build boundary |
| Funded coordinator ceremony | `protocol-v1-funded-testnet4-checkpoint.json` | Physical SeedSigner signature, coordinator reconstruction, manual Sparrow broadcast, confirmation |
| Sparrow ceremony | `sparrow-phase6-testnet4-checkpoint.json` | Durable Sparrow coordinator, four QR stages, exact retry, reconstructed PSBT, manual broadcast |
| Phase-7 negative gates | `sparrow-phase7-physical-negative-gates.md` | Required ordinary-signature rejection and disposable post-reveal exact retry |
| Multi-input and multisig | `sparrow-multislot-multisig-physical-checkpoint.md` and JSON | Real 3-input signing; real 2-input P2WSH 2-of-3 signing across two protected keystores |
| Packaged Sparrow launcher | `sparrow-packaged-app-smoke-checkpoint.json` | Portable jpackage app starts with an isolated empty profile on Testnet4 and exposes installed-app restart controls |
| Final UX smoke observations | `final-smoke-checkpoint.json` | Sequential xpub freshness/duplicate rejection and direct/stateless message-3 continuation |
| R-F1 raw-transaction lifecycle | `r-f1-internal-sweep-smoke.md` and `assets/r-f1-smoke/` | Internal sweep remains usable; reopened raw transaction quarantines without attribution; opening/closing the source wallet dynamically lifts/restores quarantine |

## Public Testnet4 transaction evidence

### Temporary coordinator funded gate

- Txid: `1e44fb484b17318a5702bbce80fbf5565e4765d49074bfb31401a0182aec0cbe`
- Result: reconstructed from the frozen PSBT, broadcast manually through
  unmodified Sparrow, and observed confirmed.
- Explorer: <https://mempool.space/testnet4/tx/1e44fb484b17318a5702bbce80fbf5565e4765d49074bfb31401a0182aec0cbe>

### Sparrow protected-signing gate

- Txid: `e2dca8df04aade59dc9abaa38c18f0535410c9907a96478a442d0c94fd772a2c`
- Result: complete Sparrow/SeedSigner four-message ceremony, exact post-reveal
  retry after camera interruption, manual broadcast, confirmation observed.
- Explorer: <https://mempool.space/testnet4/tx/e2dca8df04aade59dc9abaa38c18f0535410c9907a96478a442d0c94fd772a2c>

### Multi-input funding transaction

- Txid: `fb10ca40e72a4b90b0cc442bb2ff84b3b5a2c01c09124e1ad49dd5e748988f81`
- Shape: native-SegWit single-signature, 3 inputs, 6 outputs.
- Result: broadcast accepted; confirmation was not separately recorded in the
  checkpoint JSON.

### Protected multisig spend

- Txid: `3a77ac86b4b96272b16ab105380f08f24d98c71994e7ebbe119c93da3a1b48d3`
- Shape: native P2WSH 2-of-3, 2 inputs, 3 outputs, two independent protected
  signer sessions.
- Result: broadcast accepted; confirmation was not separately recorded in the
  checkpoint JSON.

## Checked-in photographs

Directory: `docs/img/anti-exfil-checkpoints`

| File | SHA-256 | Meaning |
| --- | --- | --- |
| `case-05-old-system-error.png` | `e90b09bc6e2079d3a5816d812d8037dc22b2d9ccc2a3eeb662cae9b7ee35297d` | Original missing-UTXO parser escape before the fail-closed fix |
| `case-06-old-system-error.png` | `2901c753c7ec64f9a7324f7d9083e77924e607f1c3bb7ae103e74a06708b010b` | Original broken-witness-script parser escape |
| `next-image-seed-first-protected-signing.png` | `83063c540c6d62d96ddbec83e798de73741cbb70b33ec7b2c58b75e78fd3186d` | Correct seed-first protected transaction review |
| `next-image-protected-signing-stopped.png` | `379bcf932c8c1162f415adae7c3d90942c46de68cc5e4ee6fcf6c96d17b1badc` | Correct fail-closed anti-exfil error presentation |
| `funded-testnet4-broadcast.png` | `6a208ec67fed4b73f452fbfe42da4167294ed5bd7667188167b59834005dc841` | Funded transaction visible on Testnet4 explorer |
| `funded-testnet4-confirmed.png` | `4dc7fce657892201e8e5c5ffc05f08906e38fc0b9ef5cf618046568de154b855` | Testnet4 confirmation evidence |

## R-F1 raw-transaction lifecycle evidence

Directory: `docs/assets/r-f1-smoke`

| File | SHA-256 | Meaning |
| --- | --- | --- |
| `gate-b-source-wallet-closed.png` | `8686f76e9d87abd6ea92aaf0ca6df6df2810aa3f0351517d4228baad49a00146` | Reopened signed raw transaction visibly quarantined with no attributable source wallet open |
| `gate-b-source-wallet-open.png` | `8b469d1a5e60dbfc38787e4551cb62ccad4436e31e2efadcba6642415201a8cb` | Synced SeedSigner source wallet positively attributes the signature; Broadcast enabled while raw View Final remains disabled |
| `gate-b-signed-sweep.txn` | `fc08587773f5e1840616199a53092bf5e9181faf45a4058a19733f2ed460e473` | Exact signed Testnet4 sweep used for the three-state lifecycle gate; not broadcast |

Later Sparrow policy, downgrade, selective-abort, multi-input, and multisig
screenshots were observed during the operator sessions but are not all copied
into this repository. Their durable evidence is the checkpoint narrative,
transaction IDs, state hashes where available, and automated regression record.
Maintainers should not infer a stronger photographic chain than is checked in.

## Reproducibility boundaries

- The canonical protocol and semantic vectors are deterministic and should be
  reproduced byte-for-byte.
- Camera timing, QR focus, and first-open buffering are physical observations,
  not deterministic test outputs.
- Testnet confirmation timing and fee estimates are external network behavior.
- The SeedSignerOS image recorded for the funded gate has SHA-256
  `952eaa05697d20af7b0e270831cd2810db663ba2dcc935c16b5ecd40290a18f4`.
- Coordinator and Sparrow completions do not broadcast automatically; operator
  review remains part of every funded evidence gate.

## Final smoke disposition

Both previously pending observations passed on 2026-08-12. Sequential
SeedSigner xpub imports captured the currently displayed keys, duplicate input
was explicitly rejected, and three distinct cosigners retained their device
brand. Direct message-3 continuation retained the selected seed; ordinary
main-menu recovery remained stateless.

Policy-path repetition confirmed generic tpub-field camera imports remain
`UNSUPPORTED`. **Import > SeedSigner > Scan** now physically passes with
**Airgapped Wallet (SeedSigner)** branding and `OPTIONAL` protected signing.

The repeat exposed a brief stale visual preview during Sparrow's existing
500 ms decoder-rejection window. The identical ending-frame behavior was then
reproduced in installed stock Sparrow 2.4.0. It is therefore recorded as a
Windows/DroidCam capture-backend presentation quirk, not an anti-exfil
regression. Stale QR data was never accepted. Preview blackout and active-drain
experiments were removed, restoring ordinary Sparrow presentation behavior.

The same device session exposed a non-protocol QR-brightness regression inherited
from current upstream's switch from native `qrencode` to `python-qrcode`.
SeedSigner failed to forward and normalize the background color in its fallback
renderer. The corrected 50 MiB image has SHA-256
`05bf333f3342d3b1229ed2565bf6f4492901ad8962251bf5d6e34a63d375d17e`.
Static and animated QR brightness pass in both directions. The animated
sequence continues normally after the brightness tip closes, with no freeze.
