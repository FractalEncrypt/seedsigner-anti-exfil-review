# How the tester's Sparrow application stays separate

Double-click **Start-Sparrow.cmd** in the Windows tester kit. Java is included;
there is no installation step. The launcher selects the dedicated test profile
automatically and keeps its wallets/session history between restarts. It does
not replace your regular Sparrow installation or register file associations.

At first launch, close the welcome dialog with its top-right **X**. Keep the
server connection off for offline fixtures. [Download and test](download-and-test.md)
covers setup, then links to complete offline and live Testnet4 testing guides.

## Technical details

The top-level launcher delegates to the unchanged **Start-PostSync-Sparrow.cmd**
inside the `Sparrow` folder. That launches the tested **Start-PostSync.exe**.
The retained profile path is `%LOCALAPPDATA%\AexTest\post-sync-p-a132668f`.
The historical name is retained to preserve existing journals. Use the kit's
launcher on every restart; the internal `engine\Sparrow.exe` does not select
this profile on its own.

The application bytes are unchanged from the repaired, physically tested
Windows package. See [identities and coverage](tester-release-status-2026-10-06.md).
For historical frozen-firmware comparisons, the separate repaired
**Start-Anti-Exfil.exe** profile is `%LOCALAPPDATA%\AexTest\repair-p-a132668f`;
that research workflow is outside the novice kit procedure. Original frozen
Sparrow retains its [known limitations](frozen-sparrow-erratum-2026-10-06.md).
