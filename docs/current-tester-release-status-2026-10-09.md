# Current Windows tester kit — October 9, 2026

**AexTest-20261009.zip** contains the current Windows x64 runtime, supported
SeedSigner/Kern firmware, public QR fixtures, current guides and editable HTML
feedback. **AexSource-20261009.zip** supplies the full matching source/reviewer
delivery; its catalog identifies current source versus historical records.

The r5 physical series reports every required check Pass: singlesig on both
devices, A/B and B/A multisig, Required/Required and Required/Optional enforcement,
proof persistence across restart, exact-session retry, stale replies, protection
settings, all 13 rejection cases on both devices, profile/network restart, and
Testnet3 singlesig/multisig. Optional Dark Skippy A3 was unused; A and A2 passed.
Saved signatures and the two completed Testnet3 protected transcripts were
revalidated with the packaged runtime. Broadcast/confirmation is a separate
observation; the Testnet3 multisig field covered signing and finalization.

The final presentation revision changes no Sparrow engine, native DLL, launcher,
firmware, PSBT, simulator JavaScript or QR image. All 248 engine files and all
7080 accepted notice files match r5. Helper launcher chaining is intentional.
Physical browser tests were performed by the maintainer in Brave and Firefox;
automated HTML checks on Edge do not claim physical Chrome/Edge qualification.

Microsoft and Tor notice closure was independently accepted on October 8.
Retained caveats: UCRT identification is family/directory-level, not a web-list
byte-match; Tor's exact historical MinGW package is not established, with the
matching governing runtime exception text supplied. Those reviews accepted the
notice route. No new native or notice issue was introduced by presentation work.

Current Sparrow source is commit **78ebc9a2aca4998267c0647944f49c51f265037f**,
including baseline 74e438d7 plus the reviewed restart change,
exported at tree **2823ac1b19b8840c0905319b60197bbc5d8d70ec**. Drongo is
**1c88f61ef3ca4dac54c0ca44a06bdc0808e0ad36**; Lark is
**b15a676e592f82914c1bc662481ea8d8f0c90cd0**. See the adjacent machine-readable
source identities and the source bundle for the full current source and build
inputs. The committed Sparrow source tree matches the independently reviewed
restart source and tested Windows runtime.

Jade and macOS packaging remain separate and are not qualified by this release.
The single-device multisig walkthroughs remain unqualified end to end.
AI review and device checks are not an independent human security audit; the
experimental/testnet-only disclosure remains visible. Historical frozen
scope/pins remain unchanged and retain their Sparrow erratum.

## Final asset identities

- **AexTest-20261009.zip** — 213261784 bytes; SHA-256 `85d74ac4ea746cb733f100903f7e3937cbb6667de2dd70e72870d8f30029a9eb`.
- **AexSource-20261009.zip** — 2096570709 bytes; SHA-256 `acb4938fb3804ba3018274b9b89253728f31a0d9f14b489efd5152d2e8bafbf2`.

The machine-readable asset record is [current-tester-release-assets-2026-10-09.json](current-tester-release-assets-2026-10-09.json).
