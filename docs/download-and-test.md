# Download and test anti exfil signing

Use ready-made packages to test the experimental SeedSigner Pi Zero, Kern `wave_7b` ESP32-P4 revision **v1.3**, and Sparrow forks. Windows testers need a browser, balenaEtcher, a microSD reader, a USB data cable, and a camera. The Sparrow ZIP includes Java; the Kern Windows ZIP includes its flashing tool. This route requires no Git, JDK, Python, Gradle, Docker, WSL, or BIOS changes.

**Candidate status:** these packages are staged locally for qualification. The two immutable prereleases have not been published. Until qualification is complete, obtain the matching package set from the maintainer; do not substitute an upstream firmware download. The final assembly is in `run/sparrow-release-resumption-2026-10-06/release-assets`; [remaining publication checks](tester-release-publication-gates-2026-10-06.md) describe its current status.

## 1 Choose the current Windows tester set

Use the **post-sync Windows tester release**, with repaired Sparrow and unchanged
post-sync SeedSigner/Kern firmware. Download these files and **SHA256SUMS**:

| Download | Purpose |
| --- | --- |
| `seedsigner-pi0-post-sync-normal.zip` | Normal Pi Zero image for Etcher |
| `kern-wave_7b-post-sync-windows-x64.zip` | Kern revision v1.3 firmware and USB flasher |
| `sparrow-anti-exfil-post-sync-windows-x64.zip` | Repaired Sparrow, bundled Java, isolated post-sync launcher and fresh matrix fixtures |
| `public-offline-test-kit-v2.2.zip` | Public seed QRs, baseline offline PSBTs and rejection viewer |

Sources, dependency/legal bundles and manifests are for reviewers/builders;
novice testers do not need them to run these packages. Repaired Linux Sparrow
is deferred; use the separate source-build guide if you want to build on Linux.

The **frozen archive** retains the original review source/binary identities.
Its original Sparrow is unfixed and is not the recommended application. See the
[dated erratum](frozen-sparrow-erratum-2026-10-06.md). The separately labelled
instrumented SeedSigner campaign image is historical; use the normal image for
interactive QR tests. Frozen Kern's preserved binary was built at 5180dbb; its
review-source binding bc382c2 adds fixture changes.

For deliberate frozen-firmware compatibility tests, verify/flash
`seedsigner-pi0-frozen-normal.zip` and `kern-wave_7b-frozen-windows-x64.zip`
using sections 4/5 below, but keep the repaired Sparrow application. Record this
mixed pairing explicitly. Do not claim the original frozen Sparrow passed.
Keep corrected v2.2 fixtures; do not substitute the old staging test kit.

## 2 Verify before opening applications or flashing

Save all files from one set in one new folder, such as **Downloads\AntiExfilPostSync**. Open normal PowerShell in that folder. These commands check the bytes against the supplied checksum file; a checksum file copied alongside an untrusted download does not independently authenticate its publisher.

```powershell
$checks = Get-Content -LiteralPath .\SHA256SUMS
foreach ($line in $checks) {
    if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw 'Invalid checksum entry' }
    $expected = $Matches[1]
    $name = $Matches[2]
    if (-not (Test-Path -LiteralPath $name)) { continue }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $name).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "Checksum mismatch: $name. Stop." }
    Write-Host "Verified $name"
}
```

After publication, download from the [project's GitHub releases](https://github.com/FractalEncrypt/seedsigner-anti-exfil-review/releases) and confirm the chosen release is labelled **Immutable** and **Pre-release**. An immutable GitHub release automatically receives a cryptographic release attestation binding its tag, commit, and assets. This authenticates release identity; it does not establish a security audit or prove that a local binary was built from its stated source. [GitHub's explanation](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).

For cryptographic verification, install GitHub CLI only if you want to use this additional check. If `gh --version` works and `gh release verify --help` lists that command, skip installation. Otherwise install/update [GitHub CLI](https://cli.github.com/). On Windows with WinGet, installation is `winget install --exact --id GitHub.cli --source winget`; for an existing package use `winget upgrade --exact --id GitHub.cli --source winget`. Reopen PowerShell afterward.

**Only after publication**, replace `RELEASE_TAG` and `PACKAGE.zip` with the tag shown on the chosen release and the file you downloaded. These checks must succeed before relying on its attestation:

```powershell
gh release verify RELEASE_TAG --repo FractalEncrypt/seedsigner-anti-exfil-review
gh release verify-asset RELEASE_TAG .\PACKAGE.zip --repo FractalEncrypt/seedsigner-anti-exfil-review
```

Repeat `verify-asset` for each package you will use. No OpenPGP `.asc` files are provided for these first releases. The Windows launcher is not Authenticode signed; a Windows reputation prompt is separate from GitHub release verification. If verification fails, stop and report the exact output.

## 3 Prepare the devices and Etcher

Use devices reserved for experimental testnet work and disposable seeds. Never load a production seed or ordinary Sparrow wallet. A public test seed gives everyone control of any testnet coins associated with it. Flashing overwrites the selected card or firmware. Remove unrelated removable drives before selecting a target.

If **balenaEtcher** is installed and opens, skip installation. Otherwise install it from [balena's download page](https://etcher.balena.io/). With WinGet available, use:

```powershell
winget install --exact --id Balena.Etcher --source winget
```

Extract each ZIP using **Extract All**. Keep each extracted folder intact; do not move just an `.exe`. Extract the test kit too. On Linux use `tar -xzf` for the Sparrow archive to preserve its executable permissions and runtime license links.

## 4 Flash SeedSigner

This step overwrites the selected microSD card. Confirm its capacity and identity before clicking Flash.

1. Power off SeedSigner and insert its microSD card in the computer's reader.
2. Open Etcher, select **Flash from file**, and select the `.img` extracted from the **normal** SeedSigner ZIP for your chosen set.
3. Select that microSD card as the target. Flash and wait for validation to finish successfully.
4. Eject the card safely, insert it into the powered-off Pi Zero, and power on.
5. Confirm the app starts and its camera/buttons work. Set **Settings → Advanced → Anti-exfil signing → Required** and the test network. Recheck after restarting.

Do not continue if flashing validation fails or the device does not boot.

## 5 Flash Kern on Windows

Use only the supplied `wave_7b` package for **ESP32-P4 revision v1.3**. The `_v3` board build is a different target. This step replaces firmware; retain only disposable test data on the device. A board-specific USB serial driver may be needed if Windows cannot see its port.

1. In the extracted Kern folder, double-click **Check-Package.cmd**. It must report matching file hashes.
2. Connect Kern with a USB **data** cable. In Device Manager, find the newly appearing **Ports (COM & LPT)** entry. Record its COM number.
3. Double-click **Flash-Kern.cmd** and enter that COM port. The script checks the chip and revision before offering to write.
4. Read the identification output. Type **FLASH** only when it names the expected device. Wait for each write's hash verification.
5. Confirm Kern reaches Home and its display/touch/camera work. If identification fails, stop; use the board's documented BOOT/reset procedure and retry identification.

The supplied script uses a per-process PowerShell execution-policy option. It does not change the machine's policy. No Python, ESP-IDF, eFuse provisioning, or whole-device erase command is required.

## 6 Launch the isolated repaired Sparrow application

Close other experimental Sparrow instances. After **Extract All**, open the
extracted folder and double-click **Start-PostSync-Sparrow.cmd**. It launches
the included **Start-PostSync.exe** in the application subfolder. Use this
entry point for every restart; keep the complete extracted folder intact.
Do not run the internal `engine\Sparrow.exe` directly.

Confirm **Testnet4**, choose **Later or Offline Mode** during onboarding, and
keep the server connection off. Grant Windows camera access if asked. The
dedicated profile is `%LOCALAPPDATA%\AexTest\post-sync-p-a132668f`; it retains
your test wallets and ceremony state between restarts. Keep ordinary wallet
files and production seeds out of this experimental profile.

The package contains the exact tested repaired application and profile addon;
its outer ZIP has a new checksum because they are combined for one extraction.
No Java installation, file association or replacement of official Sparrow is
needed. The launcher is unsigned; verify the supplied hashes before opening.

## 7 Perform the offline signing and rejection tests

Follow [Offline laptop tests in execution order](offline-public-fixture-testing.md) from start to finish. Recovery checks are included inline. The v2 kit has two
seed QRs, fingerprints/derivations, named hardware-wallet setup, low-fee change
transactions, distinct recovery PSBTs, and a 2-of-2 test. Stay offline and never
broadcast its synthetic transactions. Record v2 results separately from the
unchanged October 3 kit you tested earlier.

A public seed's testnet funds can be spent by anyone. Later spending does not
change retained transaction bytes, signatures, transcripts, hashes, or dated
historical results. New live broadcast runs need currently unspent UTXOs and
their own evidence. Use the separate [live testnet guide](end-to-end-testnet-testing.md).

## Build the same forks yourself

Use [Build from source on Windows](build-from-source-windows.md) or [Build from source on Linux](build-from-source-linux.md) for the full development-tool installation, clone, build, and flash route.
