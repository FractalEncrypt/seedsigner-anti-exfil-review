# post-sync laptop results

Date:
Windows version:
SeedSigner model:
Kern board/revision:
Computer camera:
Package checksums matched the table below: Yes / No (stop if No)
Kit ZIP verified against accompanying SHA256SUMS-v2.2: Yes / No
Keep a copy of SHA256SUMS-v2.2 with this results file.
Sparrow Testnet4 and connection off confirmed: Yes / No
Seed A fingerprint 0fb882ff and seed B fingerprint 05d027a5 confirmed: Yes / No
Required signing settings confirmed: Yes / No

## Package identities — unchanged firmware and repaired Sparrow

| File | SHA-256 |
| --- | --- |
| `kern-wave_7b-post-sync-windows-x64.zip` | `3da6fc04cc6bc0462a2dcd3fbb36e4c2a7f335218c10679a6cbf28dfd45da715` |
| `seedsigner-pi0-post-sync-normal.zip` | `acbf3a9ba819d230d4b4f02cd8b916396a3d0e5d5e28cc061540a1457defda3b` |
| `sparrow-anti-exfil-post-sync-windows-x64.zip` | `8f846210f1ee998a3a382aa2d0be82062ea606816436d0dd346c71d9c11ebb73` |

## Results — fill in execution order

Replace Not run with Pass, Fail, or Blocked, then save with Ctrl+S.
For expected results, that mark is enough. Photos and notes are optional;
a photo filename can replace transcribed device wording. For unexpected
results, add the last clear step and a photo if practical. Record QR density
once below, and note only changes/retries. Keep device outcomes separate when
they differ. You do not need to recopy an already completed results file.

QR density used (unless noted otherwise):
Photos folder (optional):
Do not mark Pass solely because the expected message below was in the guide.

| ID | Test | Fixture | Result | Notes / optional photo filename |
| --- | --- | --- | --- | --- |
| S1 | SeedSigner first protected signing | `singlesig-A-first.psbt` | Not run | |
| S2 | Kern first protected signing | `singlesig-B-first.psbt` | Not run | |
| K2 | Kern second fresh ceremony | `singlesig-B-next.psbt` | Not run | |
| M1 | 2-of-2 protected multisig; note each signer | `multisig-A-B.psbt` | Not run | |
| D1 | Ordinary unsigned QR rejected with protection enabled | `Sparrow ordinary QR; note devices` | Not run | |
| D2 | Protected Step 1 rejected with device protection disabled; restore on | `Sparrow protected QR; note devices` | Not run | |
| D3 | Wrong network request rejected | `01-wrong-mainnet; note devices` | Not run | |
| D4 | Wrong stage request rejected | `02-wrong-stage-message-2; note devices` | Not run | |
| D5 | Duplicate slot request rejected | `10-duplicate-slot-record; note devices` | Not run | |
| D6 | Additional corpus cases tried | `List slugs or leave Not run` | Not run | |
| P1 | Sparrow ordinary signed-return rejection | `ordinary-signed-return-A-qr.png` | Not run | |
| R1-A | SeedSigner pre-reveal cancel/restart | `singlesig-A-pre-reveal.psbt` | Not run | |
| R1-B | Kern pre-reveal cancel/restart | `singlesig-B-pre-reveal.psbt` | Not run | |
| R2-A | SeedSigner exact post-reveal retry | `singlesig-A-post-reveal.psbt` | Not run | |
| R2-B | Kern exact post-reveal retry | `singlesig-B-post-reveal.psbt` | Not run | |
| R3-A | SeedSigner abandon/reopen retained session | `singlesig-A-abandon.psbt` | Not run | |
| R3-B | Kern abandon/reopen retained session | `singlesig-B-abandon.psbt` | Not run | |

## Any unexpected behavior

Last clear step:
Expected:
Observed:
Did a signature appear unexpectedly:

This file contains public test data only. Do not attach wallet databases,
production seeds, live session secrets, or an entire Sparrow profile.
