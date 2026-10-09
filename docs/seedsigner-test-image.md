# SeedSigner Pi Zero image reference

For a first test, [Download and test](download-and-test.md) covers flashing
and setup, then links to the offline or live Testnet4 signing guide. This page
is a device reference; you do not need to visit it during that guide.

## Flash with balenaEtcher

Use the `.img` in the Windows kit's **SeedSigner** folder. Flashing replaces
everything on the target microSD card. Select the test card carefully.
If you already have balenaEtcher installed, open it now. Otherwise install
[balenaEtcher](https://etcher.balena.io/).

1. Disconnect SeedSigner power, **remove its microSD card**, and insert the card
   into the computer's reader.
2. In Etcher choose **Flash from file**, select the kit's `.img`, then choose
   the test microSD card with **Select target**.
3. Click **Flash** and wait for successful validation.
4. Safely eject the card, remove it from the reader, insert it in SeedSigner,
   and reconnect power. Check menu/buttons/camera operation.
5. Open **Settings → Persistent Settings** and enable persistent settings.
6. Open **Settings → Advanced**. For a **Plus**, select **Hardware → Display
   type → st7789 320x240**, then return to **Advanced**.
7. Select **Advanced → Bitcoin Network → Testnet**, then **Advanced →
   Anti-exfil signing → Required**. Return to the main menu.

For public offline tests, load seed A without a passphrase and confirm
**0fb882ff**. Export its account with **Export xpub → Single Sig → Native
Segwit**, account 0, then **Animated** or **Static → I understand → Export xpub**.
The [offline guide](offline-public-fixture-testing.md) includes Sparrow import
and optional multisig; the [live guide](end-to-end-testnet-testing.md) uses your
own disposable Testnet4 seed.

## Image identities for reviewers

The current interactive image uses SeedSigner `821a5102` and SeedSignerOS
`d841a5e5`. The image SHA-256 is
`73e4085c5a674cf5b05a22001cad5aa71e8ea87489aef27dc5c4817c1a9fd67a`.

The frozen normal image is a separate build from frozen source. The historical
campaign instrumented image is another distinct artifact, SHA-256
`adc2b58ae9dd57e884ec33b0e39ebf608ee8cc468d3fa7c563a1f1f808550fb3`.
These identities and their results must not be interchanged. The novice tester
kit uses the current normal image; it does not ask users to qualify two sets.

Source-build instructions remain available for [Windows](build-from-source-windows.md)
and [Linux](build-from-source-linux.md).
