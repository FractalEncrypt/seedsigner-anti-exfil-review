# Kern test firmware and initial setup

The downloadable Windows flasher targets **wave_7b, ESP32-P4 revision v1.3**.
Confirm the physical board first. Other boards and the `_v3` target require
their own matching firmware; do not guess or override the identification gate.
Verify the ZIP using [Download and verify](download-and-test.md#2-verify-before-opening-applications-or-flashing).

Flashing replaces firmware. Use a test device containing only disposable data.
The package includes esptool; no Python, ESP-IDF, WSL, or Docker installation
is needed. Disconnect other serial devices where practical.

## Windows flash

1. Extract `kern-wave_7b-SET-windows-x64.zip` completely.
2. Double-click **Check-Package.cmd**; all file checks must pass.
3. Connect Kern using a USB **data** cable. In Device Manager identify the
   newly appearing **Ports (COM & LPT)** entry and its COM number.
4. Double-click **Flash-Kern.cmd**, enter that port, and read the chip/revision
   output. Type **FLASH** only when it identifies the expected device.
5. Wait for all four writes to verify. Stop on identification or write failure.
   A board-specific serial driver or documented BOOT/reset procedure may be
   needed if identification does not work.
6. Boot and confirm display, touch, and camera operation.

The script uses a per-process PowerShell execution-policy option; it does not
change the machine policy or perform whole-device erase/eFuse provisioning.

## Load the public seed and export the account

1. Open the v2 kit's **Open-Test-Cases.html** and select **B — Kern**.
2. On Kern choose **Load Mnemonic → From QR Code**, scan the seed QR, and
   finish loading with an empty BIP39 passphrase. Verify fingerprint **05d027a5**.
   Manual input of the 12 words in `seed-B.txt` is an alternative.
3. In wallet settings select **Network → Testnet** and turn **Anti-exfil
   signing** on. Recheck after restarting.
4. From Home choose **Extended Public Key**. Select **Singlesig**, **Native
   SegWit**, and account **0**. Verify `m/84'/1'/0'` and the fingerprint.
5. Display the key-origin/xpub QR. In isolated Sparrow choose **File → New
   Wallet**, name it **Offline Kern B**, select **Single Signature / Native
   Segwit**, then **Airgapped Hardware Wallet → Kern → Scan**.
6. Scan the account QR, verify fingerprint/path, set **Protected signing →
   Required**, and click **Apply**. Maximize/scroll the keystore pane if needed;
   reopen Settings to confirm the saved Required value.

Continue with [Offline public-fixture testing](offline-public-fixture-testing.md)
and the explicit [recovery/next-ceremony walkthrough](recovery-tests.md).
Kern's second-round continuity disclosure is expected; retain the same Sparrow
session and scan the final protected response before dismissing its viewer.

For 2-of-2, export the same seed's **Multisig**, native SegWit account 0 using
`m/48'/1'/0'/2'`. Follow the offline guide's separate multisig wallet setup.

## Sources and frozen binary identity

Frozen Kern preserves the accepted product binary built at `5180dbb`; its
review source binding `bc382c2` adds test-fixture changes. The manifest records
both identities. Post-sync firmware uses `0c2446a`. No new physical test result
is implied for frozen by a successful post-sync trial.

Use [Windows](build-from-source-windows.md) or [Linux](build-from-source-linux.md)
for the full source build and other board targets. Linux USB qualification is
pending. Use the [live guide](end-to-end-testnet-testing.md) for funded testnet
transactions with a fresh disposable seed.
