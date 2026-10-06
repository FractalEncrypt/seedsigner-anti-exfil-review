# Isolated Sparrow application and profile

For the current Windows tester application, verify and extract
`sparrow-anti-exfil-post-sync-windows-x64.zip` completely. Close other experimental
Sparrow instances, then double-click **Start-PostSync-Sparrow.cmd** at the top
of the extracted folder. Keep that entire folder intact and use the same
launcher on every restart. Its Java runtime is included.

Choose **Later or Offline Mode** at onboarding. Confirm **Testnet4**, leave the
server connection off for public fixtures, and grant Windows camera access if
asked. The dedicated profile is `%LOCALAPPDATA%\AexTest\post-sync-p-a132668f`.
Your test wallets and ceremony state persist there. Do not load production seeds
or ordinary wallets, copy another profile/journal into it, or launch the internal
`engine\Sparrow.exe` directly.

The launcher installs no file associations and replaces no official Sparrow.
The package combines the exact tested repaired app and post-sync profile addon;
[qualification](tester-release-status-2026-10-06.md) records their identities.

For deliberate frozen-device compatibility tests, use the repaired application's
**Start-Anti-Exfil.exe** inside its application subfolder. Its distinct profile is
`%LOCALAPPDATA%\AexTest\repair-p-a132668f`. Record the repaired application hash
with the frozen firmware hashes. Preserve all existing journals.

The original frozen Sparrow package uses a different profile but remains unfixed;
see the [erratum](frozen-sparrow-erratum-2026-10-06.md). Repaired Linux binaries
are not included in this Windows tester set. Use the [Linux source guide](build-from-source-linux.md)
for development builds; their desktop/camera qualification remains pending.

Follow [Download and test](download-and-test.md) for full setup, then the
[offline procedure](offline-public-fixture-testing.md) in order.