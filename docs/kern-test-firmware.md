# Kern wave_7b firmware reference

The Windows kit includes a flasher for **wave_7b, ESP32-P4 revision v1.3**.
For a first test, [Download and test](download-and-test.md) covers flashing
and setup, then links to complete offline or live Testnet4 signing guides. This page is an
optional device reference.

## Flash on Windows

Flashing replaces the installed firmware. Use this package only for its stated
board/revision. The tool includes esptool.

1. Open **Kern** in the extracted kit. Run **Check-Package.cmd**; every check
   must pass.
2. Connect Kern with a USB data cable. In **Device Manager → Ports (COM & LPT)**,
   identify the newly appearing port.
3. Run **Flash-Kern.cmd** and enter that port. The tool requires detection of
   **ESP32-P4 revision v1.3** before offering to flash; it stops without writing
   if that check fails. At its confirmation prompt, type **FLASH**.
4. Wait for write/hash verification and check the boot screen, touch, and camera.

Load the kit's seed B with **Load Mnemonic → From QR Code**, no passphrase;
check fingerprint **05d027a5**. Tap the orange circled **i** at the upper-left
of Home for **Wallet Settings**. Confirm **Network → Testnet** and **Anti-exfil
signing** on, changing them only if needed. Return Home and choose **Extended
Public Key**; confirm its default **Singlesig → Native SegWit**, account 0,
then scan the displayed account QR into Sparrow.

For longer tests, you can set Kern's seed-unload timer to **30 minutes**. Keep
the disposable seed backup handy to reload if that timer expires.

Kern holds one seed at a time. For multisig using two seeds on Kern, the full
tester guide includes the unload/reload steps and wallet-descriptor reload.
Loaded descriptors stay available in the loaded-key session; reloading a seed
requires rechecking protection/network and loading the wallet policy again.

## Firmware identities for reviewers

The current tester firmware uses Kern `0c2446a6`. The frozen accepted binary
was built at `5180dbb`; its review-source binding `bc382c2` adds fixture changes.
Keep their source and binary identities separate. See
[tester coverage](tester-release-status-2026-10-06.md) and the source-build
guides for [Windows](build-from-source-windows.md) and
[Linux](build-from-source-linux.md).
