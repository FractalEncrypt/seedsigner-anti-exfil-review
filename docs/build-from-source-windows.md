# Build from source on Windows

For ready-made packages, use [Download and test](download-and-test.md). This source-build route needs development tools and substantially more time.

Use this guide to launch the Sparrow fork and build the SeedSigner Pi Zero and Kern `wave_7b` images on your laptop. Your recorded Kern device is ESP32-P4 revision **v1.3**, so use `wave_7b`, without `_v3`. Its COM port can change on the laptop.

## Source versions

These commits define the repaired source set. Repaired Linux desktop/package qualification remains pending; building it yourself does not inherit Windows physical qualification. Verify them after cloning; branch names can move.

| Repository | Branch | Commit |
| --- | --- | --- |
| Drongo | `codex/sync-2026-09-drongo` | `bdc8029fd970dec938630e5d9406261b791bf8d8` |
| Sparrow | `codex/sync-2026-09-sparrow` | `bdca675348dc701eff4d5c29eb1f2fcf1780a934` |
| SeedSigner | `codex/sync-2026-09-seedsigner-anti-exfil` | `821a5102cbb87061b44a018d2fb95b05b410cc5f` |
| SeedSignerOS | `codex/sync-2026-09-seedsigner-os` | `d841a5e5a6d74b66b8bf1ba1b2e78d4e7db9fa74` |
| Kern | `codex/kern-continuous-ceremony` | `0c2446a6e9ecee2914122cd858bdebd86da0894e` |

All five versions are published on the GitHub branches above. The October Sparrow and Kern sync commits were pushed to the maintained September Sparrow branch and continuous-ceremony Kern branch on October 1, 2026. Clone those branches using the commands below; no Git bundle or transfer from the desktop is needed. The earlier frozen review commits retain their historical test evidence; this is a new physical test cycle.

## Prepare the laptop

Commands marked **PowerShell** run in Windows; commands marked **Ubuntu** run in Ubuntu. Work through the checks first, then run only the installation or update commands that apply to your results. A diagnostic check may report that something is missing; the instructions immediately below explain what to do. Stop if an installation or build fails.

Keep the laptop plugged in and prevent sleep during builds. Allow space for sources, containers, and outputs: SeedSignerOS alone estimates 20–30 GB for its build. Keep Linux firmware sources in Ubuntu's home directory to preserve executable bits and symlinks.

### 1. Check Windows tools and install what is missing

Open normal **PowerShell** from Start. First check whether WinGet is available:

```powershell
Get-Command winget -ErrorAction SilentlyContinue
```

- **A command is listed:** run `winget --version`, then continue to the inventory below.
- **Nothing is listed:** install or update Microsoft's [App Installer](https://apps.microsoft.com/detail/9NBLGGH4NNS1), close PowerShell, open it again, and repeat the check.

Now check the installed packages. These commands only list software; they do not install anything. If WinGet requests source agreements, accept them to perform the checks. “No installed package found” means that package was not detected; follow the individual checks below if you installed it another way.

```powershell
winget list --exact --id Git.Git --source winget
winget list --exact --id EclipseAdoptium.Temurin.25.JDK --source winget
winget list --exact --id Python.Python.3.11 --source winget
winget list --exact --id Balena.Etcher --source winget
winget list --exact --id Docker.DockerDesktop --source winget
```

Use the results to work through **Git → Java → Python → Etcher** below. Docker is handled after WSL in section 3. The **Version** column shows what is installed; an **Available** column indicates a catalog update. See Microsoft's [WinGet list reference](https://learn.microsoft.com/en-us/windows/package-manager/winget/list) and [update command reference](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade).

#### Git for Windows

If Git is already installed, confirm it works by running `git --version`. If it prints a version and the inventory shows no available update, skip to Java. If Git was just installed but is not recognized, reopen PowerShell before deciding it is missing.

**Git is missing:** run this installation command and allow any administrator prompt:

```powershell
winget install --exact --id Git.Git --source winget
```

**Git is installed and the inventory shows an available update:** run this update command instead:

```powershell
winget upgrade --exact --id Git.Git --source winget
```

After installing or updating, reopen PowerShell and verify `git --version` before proceeding.

#### Java JDK 25

This guide uses the tested Windows x64 Temurin JDK **25.0.4.7**. The JDK includes both Java and its compiler. Check the exact installation used by the later launch command:

```powershell
$jdkPath = 'C:\Program Files\Eclipse Adoptium\jdk-25.0.4.7-hotspot'
Test-Path "$jdkPath\bin\javac.exe"
```

- **True:** verify the following commands print Java and javac **25.0.4**, then skip Java installation.
- **False:** follow the missing/older-package instructions below. Another installed Java version does not satisfy this exact check.

Only when the path check returned **True**, run:

```powershell
& "$jdkPath\bin\java.exe" --version
& "$jdkPath\bin\javac.exe" --version
```

Before choosing an installation or update command: if a newer Temurin 25 version is already installed, or the inventory lists 25.0.4.7 but the path check is False, resolve the JDK path/version first. The older-version update command below is not a downgrade command. The later JAVA_HOME setting must point to the tested JDK.

**Temurin 25 is missing from the inventory:** install the tested x64 version:

```powershell
winget install --exact --id EclipseAdoptium.Temurin.25.JDK --version 25.0.4.7 --architecture x64 --source winget
```

**An older Temurin 25 version is listed:** update it to the tested version instead:

```powershell
winget upgrade --exact --id EclipseAdoptium.Temurin.25.JDK --version 25.0.4.7 --architecture x64 --source winget
```

After installing or updating, reopen PowerShell and repeat the exact-path checks above. [Adoptium's installation instructions](https://adoptium.net/installation) describe the Temurin packages.

#### Python for flashing Kern

Check whether the Windows Python launcher exists:

```powershell
Get-Command py -ErrorAction SilentlyContinue
```

If a command is listed, check the required Python series:

```powershell
py -3.11 --version
```

**Python 3.11.9 or a later 3.11 patch version is reported:** skip Python installation. If only another Python series is installed, install 3.11 alongside it so the later `py -3.11` commands work.

**The launcher or Python 3.11 is missing:** run:

```powershell
winget install --exact --id Python.Python.3.11 --version 3.11.9 --architecture x64 --source winget
```

**Python 3.11 is present but older than 3.11.9:** run this update command instead:

```powershell
winget upgrade --exact --id Python.Python.3.11 --version 3.11.9 --architecture x64 --source winget
```

After installing or updating, reopen PowerShell and verify `py -3.11 --version` before continuing.

#### balenaEtcher

Check the inventory and search Start for **balenaEtcher**. If it is installed and opens, skip installation, even if it was not detected by WinGet. This guide does not require a particular Etcher version.

**Etcher is missing:** install it:

```powershell
winget install --exact --id Balena.Etcher --source winget
```

If Etcher is installed but fails to open and the inventory offers an update, close Etcher and update it:

```powershell
winget upgrade --exact --id Balena.Etcher --source winget
```

Verify Etcher opens before moving on.

### 2. Check WSL and Ubuntu before installing or updating

The image builds use **WSL 2 with Ubuntu 24.04**. Before changing the laptop, check its Windows version using `winver` and check **Task Manager → Performance → CPU → Virtualization**. Docker's Windows requirements include Windows 10 22H2 build 19045, WSL 2.1.5 or later, and 8 GB RAM; check the [Docker Windows requirements](https://docs.docker.com/desktop/setup/install/windows-install/) for your Windows edition and servicing status. If virtualization is disabled, enable it in the laptop's BIOS/UEFI before continuing.

In normal **PowerShell**, first check whether the WSL command is available:

```powershell
Get-Command wsl -ErrorAction SilentlyContinue
```

If a command is listed, run these diagnostic checks. A `wsl` command can exist even when WSL has not been enabled, so read its output rather than treating the command's presence as proof of a working installation.

```powershell
wsl --version
wsl --status
wsl --list --verbose
```

Choose the matching case **before** running any installation command:

| What the checks show | Next action |
| --- | --- |
| WSL version is at least 2.1.5 and `Ubuntu-24.04` is listed with VERSION 2 | Skip installation and conversion; continue to the Ubuntu check below. |
| WSL works, but its version is older than 2.1.5 or `--version` is unsupported | Update WSL using the update command below, then repeat the checks. |
| WSL works, but `Ubuntu-24.04` is absent | Install Ubuntu 24.04 using the installation command below. An existing other distribution can remain installed. |
| `Ubuntu-24.04` is listed with VERSION 1 | Convert that distribution using the conversion command below. |
| No `wsl` command, or the output says WSL is not installed/enabled | Install WSL and Ubuntu using the installation command below. |
| Another error appears | Stop and resolve it using the [Microsoft WSL installation instructions](https://learn.microsoft.com/en-us/windows/wsl/install) before building. |

More than one action may apply: for example, update WSL, then install the missing Ubuntu distribution. The version from `wsl --version` is the WSL software version; the VERSION column in the distribution list identifies whether that distribution uses WSL 1 or 2. See the [Microsoft WSL command reference](https://learn.microsoft.com/en-us/windows/wsl/basic-commands).

For the applicable action below, open **PowerShell as administrator** from Start.

**WSL needs updating:** run:

```powershell
wsl --update
```

**WSL or Ubuntu 24.04 needs installing:** run:

```powershell
wsl --install -d Ubuntu-24.04
```

Restart Windows if requested. On a newly installed Ubuntu distribution, open **Ubuntu 24.04** from Start and finish its first-run setup by choosing a Linux username and password. Password characters are invisible while typing. This account is separate from your Windows account. Existing configured installations do not need this setup again.

**An existing Ubuntu-24.04 uses WSL 1:** back up any important files in that distribution before conversion, then run:

```powershell
wsl --set-version Ubuntu-24.04 2
```

After the applicable changes, repeat `wsl --version` and `wsl --list --verbose`. Continue once WSL is at least 2.1.5 and Ubuntu-24.04 shows VERSION 2.

#### Check the Ubuntu release and Linux tools

To open the exact distribution used here, run this command in normal **PowerShell**. The terminal will switch to Ubuntu; subsequent Linux commands run there.

```powershell
wsl -d Ubuntu-24.04
```

In **Ubuntu**, check the release and whether Linux Git and certificate support are installed:

```bash
cat /etc/os-release
dpkg-query -W -f='${Package}: ${Status}\n' git ca-certificates
```

Expect `VERSION_ID="24.04"` and `install ok installed` for both packages. Windows Git is separate from Ubuntu Git. If the release differs, stop before building and use an Ubuntu 24.04 distribution.

- **Both packages are installed:** run `git --version`; if it works, skip installation and continue to Docker.
- **Either package is absent or not fully installed:** run the following commands in Ubuntu to install the missing prerequisites. The package manager keeps already installed dependencies.

```bash
sudo apt-get update
sudo apt-get install -y git ca-certificates
git --version
```

### 3. Check Docker Desktop and start the Linux engine

Docker Desktop supplies the containers used for both image builds. Use the Docker inventory result from section 1 and search Start for **Docker Desktop** before running an installer.

- **Installed:** open Docker Desktop, wait for its engine to start, and perform the checks below.
- **Missing:** run the following command in **PowerShell**, allow any administrator prompt, restart if requested, and open Docker Desktop from Start.

Only if Docker Desktop is missing, run:

```powershell
winget install --exact --id Docker.DockerDesktop --source winget
```

Complete any first-run prompts. Before checking the engine, open Docker Desktop settings and confirm **Use the WSL 2 based engine**. Under **Resources → WSL Integration**, enable **Ubuntu-24.04** and apply/restart if you changed anything. Use Linux containers; if the tray menu offers “Switch to Linux containers,” select it.

In a new normal **PowerShell** window, check:

```powershell
docker version
docker compose version
docker info --format '{{.OSType}}'
```

**Ready:** both Client and Server information appear without a connection error, Compose reports a v2 version, and the last command prints `linux`. Skip the troubleshooting and update instructions; go directly to **Verify Docker access from Ubuntu** below.

**Not ready:** choose the matching correction before trying a build:

| Result | Correction |
| --- | --- |
| Docker command is not recognized | If Desktop is installed, reopen PowerShell after starting it; otherwise use the missing-installation step above. |
| Client appears but Server has a connection error | Start Docker Desktop and wait for its engine; resolve any startup error in Desktop. |
| The engine type is `windows` | Switch Docker Desktop to Linux containers and repeat the checks. |
| Compose is absent or older than v2 | If WinGet lists an available Docker Desktop update, use the update command below, then repeat the checks. If already current, resolve its installation before continuing. |

A working installation with Compose v2 and a Linux engine can be used as-is. **Only if an update is needed**, close builds and containers first, then run in PowerShell:

```powershell
winget upgrade --exact --id Docker.DockerDesktop --source winget
```

If you updated Docker Desktop, restart it and repeat the Windows checks before continuing.

#### Verify Docker access from Ubuntu

Perform this check even if Docker already worked in PowerShell. In **PowerShell**, open the Ubuntu distribution:

```powershell
wsl -d Ubuntu-24.04
```

The terminal is now running **Ubuntu**. Run:

```bash
docker version
docker compose version
docker info --format '{{.OSType}}'
```

Expect Client and Server information without a connection error, Compose v2, and `linux` again. If Ubuntu cannot access Docker, recheck **Resources → WSL Integration → Ubuntu-24.04** and reopen Ubuntu. Once all three checks pass, preparation is complete; continue to **Clone and launch Sparrow** in a normal Windows PowerShell window. Keep Docker Desktop running during both builds.

### What gets downloaded during builds

The setup steps above install the tools. Sparrow's first `gradlew.bat` command downloads the repository's Gradle version and Java libraries; it does not install Java, Git, or Docker. You do not need a separate Gradle installation. The Docker builds download container images and firmware/OS dependencies. Keep internet access available for the first builds. You do not need a separate Windows ESP-IDF installation.

## Clone and launch Sparrow

Use a fresh test profile and public, unfunded test fixtures. These clone commands are for new folders. If an earlier attempt already created `drongo` or `sparrow` under `Documents\AntiExfilTest`, inspect those checkouts before repeating the clone commands.

In normal **PowerShell**, clone the sources and print their versions. Before building, compare the two HEAD values with the source table. Stop if they differ; that means the branch has moved since this test cycle. The Sparrow Drongo submodule must be `bdc8029fd970dec938630e5d9406261b791bf8d8`; the separate Drongo clone is useful for inspection, but Sparrow builds its own submodule.

```powershell
$repos = Join-Path $env:USERPROFILE 'Documents\AntiExfilTest'
New-Item -ItemType Directory -Path $repos -Force | Out-Null
Set-Location -LiteralPath $repos
git clone --branch codex/sync-2026-09-drongo https://github.com/FractalEncrypt/drongo.git drongo
git clone --branch codex/sync-2026-09-sparrow --recurse-submodules https://github.com/FractalEncrypt/sparrow.git sparrow
git -C drongo rev-parse HEAD
git -C sparrow rev-parse HEAD
git -C sparrow submodule status --recursive
```

Once the source versions match, select the JDK checked during preparation and build. The first build downloads dependencies and can take time. Wait for `BUILD SUCCESSFUL` before proceeding to the separate launch command below.

```powershell
Set-Location -LiteralPath (Join-Path $repos 'sparrow')
$env:JAVA_HOME = 'C:\Program Files\Eclipse Adoptium\jdk-25.0.4.7-hotspot'
if (-not (Test-Path "$env:JAVA_HOME\bin\javac.exe")) { throw 'Expected JDK is missing; check the installation' }
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
java -version
.\gradlew.bat --no-daemon check installDist
if ($LASTEXITCODE -ne 0) { throw 'Sparrow checks or build failed' }
```

After the build succeeds, launch using the following command. It uses a short dedicated profile under `%LOCALAPPDATA%\AexTest\source-post` and disables the shared ordinary-Sparrow instance pointer. Keep the launching terminal open while Sparrow runs. Do not choose an ordinary wallet home or import production wallets. This Gradle launch avoids a Windows command-length failure observed with the generated distribution batch launcher in long directory paths.

```powershell
$env:SPARROW_NO_LOCK_FILE_LINK = 'true'
$testProfile = Join-Path $env:LOCALAPPDATA 'AexTest\source-post'
.\gradlew.bat --no-daemon run --args="--dir=`"$testProfile`" --network=testnet4"
```

To launch again, open normal PowerShell, repeat the directory/JAVA_HOME/PATH lines above, and run the same `run` command. After downloads are cached, you can add `--offline` to the Gradle commands.

Select the laptop's camera in Sparrow and grant Windows camera access if prompted. For each test wallet's SeedSigner or Kern keystore, open **Settings**, select that signer, set **Protected signing → Required**, and apply the change. Check the hardware model is SeedSigner or Kern so this setting is available.

## Build and flash SeedSigner

Open **Ubuntu**. Clone both application and OS sources with LF endings. These commands need new `seedsigner` and `seedsigner-os` folders. Before proceeding to the build block, compare both printed HEAD values with the source table; stop if either differs.

```bash
mkdir -p ~/anti-exfil-test
cd ~/anti-exfil-test
git -c core.autocrlf=false clone --branch codex/sync-2026-09-seedsigner-anti-exfil --recurse-submodules https://github.com/FractalEncrypt/FractalEncrypt_seedsigner.git seedsigner
git -c core.autocrlf=false clone --branch codex/sync-2026-09-seedsigner-os --recurse-submodules https://github.com/FractalEncrypt/seedsigner-os.git seedsigner-os
git -C seedsigner rev-parse HEAD
git -C seedsigner-os rev-parse HEAD
```

Once both versions match, build the ordinary Pi Zero image for interactive QR testing. The explicit `--app-repo` selects this fork, and `--app-commit-id` selects the intended application version. Keep Docker Desktop running. The OS source includes CRLF text files; the following preparation normalizes UTF-8 OS text to LF, skipping symlinks, binaries, and Buildroot. Record the resulting diff. If Docker reports a build error, stop and save its output; do not flash a leftover image. Wait for the build to finish successfully before running the following image-hash and Explorer commands.

```bash
cd ~/anti-exfil-test/seedsigner-os
python3 - <<'PY'
from pathlib import Path
for path in Path('opt').rglob('*'):
    if 'buildroot' in path.parts or path.is_symlink() or not path.is_file():
        continue
    data = path.read_bytes()
    if b'\r\n' not in data or b'\0' in data:
        continue
    try:
        data.decode('utf-8')
    except UnicodeDecodeError:
        continue
    path.write_bytes(data.replace(b'\r\n', b'\n'))
    print(path)
PY
git diff --stat
export DOCKER_DEFAULT_PLATFORM=linux/amd64
export SS_ARGS='--pi0 --app-repo=https://github.com/FractalEncrypt/FractalEncrypt_seedsigner.git --app-commit-id=821a5102cbb87061b44a018d2fb95b05b410cc5f'
docker compose up --force-recreate --build --abort-on-container-exit --exit-code-from build-images
```

Only after the build finishes successfully, record the image hash and open the output directory:

```bash
sha256sum images/*.img
explorer.exe .
```

`explorer.exe .` opens the Linux source directory in Windows Explorer. Open its `images` folder and find `seedsigner_os.821a5102cbb87061b44a018d2fb95b05b410cc5f.pi0.img`. Copy that image into your Windows **Downloads** folder so Etcher can open it easily.

The following flash step overwrites the selected microSD card. Identify the SeedSigner card by capacity and drive identity before choosing the target.

1. Power off SeedSigner and put its microSD card in the laptop's card reader.
2. Open **balenaEtcher**, choose **Flash from file**, and select the copied `.img`.
3. Choose **Select target** and select the identified SeedSigner microSD card.
4. Choose **Flash**, allow any administrator prompt, and wait for flashing and validation to finish successfully.
5. Eject the card through Windows, return it to the powered-off Pi Zero, and power on.

Confirm the application version; enable **Settings → Advanced → Anti-exfil signing → Required** before protected-signing tests. Recheck the setting after restarting.

## Build Kern for the same device

In **Ubuntu**, clone into a new `kern` folder and print the source version. Before proceeding to the build block, compare Kern's HEAD with the table and confirm the decoder submodule pin is `85cd38c2e10714f262ce16a33239469684e5aa45`. Stop if they differ.

```bash
cd ~/anti-exfil-test
git -c core.autocrlf=false clone --branch codex/kern-continuous-ceremony --recurse-submodules https://github.com/FractalEncrypt/Kern.git kern
git -C kern rev-parse HEAD
git -C kern submodule status --recursive
```

Once the source versions match, build using the same ESP-IDF image used for this sync. Keep Docker Desktop running. The initial build retrieves locked managed components; preserve `dependencies.lock`. Wait for a successful build before running the hash and lockfile checks below. If the lockfile check reports changes, stop before flashing and save the output.

The clone generates its own ignored development signing key. Its signed image hash will differ from the desktop build; record your laptop image hash and keep the key local for compatible future SD updates.

```bash
cd ~/anti-exfil-test/kern
docker run --rm -v "$PWD:/project" -w /project \
  espressif/idf@sha256:81893c71bb5e570088901f21def8684c25cd2a9020281bd01b843a7655edb18c \
  idf.py -B build_wave_7b \
    -D SDKCONFIG=build_wave_7b/sdkconfig \
    -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.wave_7b' build
```

Only after the build succeeds, record its image hash and check the lockfile. A successful lockfile check prints nothing; if it prints a diff or an error, stop before flashing.

```bash
sha256sum build_wave_7b/kern.bin
git diff --exit-code -- dependencies.lock
```

Once the lockfile check passes, open the Kern source directory in Windows Explorer:

```bash
explorer.exe .
```

## Flash Kern from Windows

Wait for a successful Kern build before proceeding. In **normal PowerShell**, make a Windows folder for its output files:

```powershell
$flashDir = Join-Path $env:USERPROFILE 'Documents\KernFlash'
New-Item -ItemType Directory -Path $flashDir -Force | Out-Null
explorer.exe $flashDir
```

The Ubuntu build's `explorer.exe .` opened the Kern source folder. Using those two Explorer windows, copy these four files into **Documents\KernFlash**, all directly in that folder:

| File in the Linux Kern source folder | Windows filename |
| --- | --- |
| `build_wave_7b/bootloader/bootloader.bin` | `bootloader.bin` |
| `build_wave_7b/partition_table/partition-table.bin` | `partition-table.bin` |
| `build_wave_7b/ota_data_initial.bin` | `ota_data_initial.bin` |
| `build_wave_7b/kern.bin` | `kern.bin` |

Also open `build_wave_7b/flash_args` in a text editor to compare its options and offsets with the flashing command below.

Python was installed during preparation. Create an isolated flashing environment in the same **PowerShell** window:

```powershell
py -3.11 -m venv "$env:USERPROFILE\kern-flash-venv"
$flashPython = "$env:USERPROFILE\kern-flash-venv\Scripts\python.exe"
& $flashPython -m pip install esptool==5.3.1
& $flashPython -m serial.tools.list_ports
```

Connect Kern using a USB data cable. Rerun the port-list command and identify the newly appearing COM port, also visible in **Device Manager → Ports (COM & LPT)**. Replace `COM_REPLACE` below with that port, for example `COM3`. The desktop used COM6, but that does not identify the laptop port. If no port appears, check the cable and USB port; use the board vendor's driver instructions if Windows requires a serial driver.

```powershell
$kernPort = 'COM_REPLACE'
& $flashPython -m esptool --chip esp32p4 --port $kernPort chip-id
if ($LASTEXITCODE -ne 0) { throw 'Could not identify Kern; check port and USB connection' }
```

Before running the following flash command, confirm the connected device is the expected ESP32-P4 revision **v1.3** and compare the options and offsets with `build_wave_7b/flash_args`. Flashing replaces the existing firmware. Keep each PowerShell backtick at the very end of its line, without spaces afterward. Use the built fork image; the upstream web flasher's latest build does not include this fork's anti-exfil changes.

Once those checks match, flash your build:

```powershell
Set-Location -LiteralPath $flashDir
& $flashPython -m esptool --chip esp32p4 --port $kernPort write-flash `
  --flash-mode dio --flash-freq 80m --flash-size keep `
  0x2000 bootloader.bin `
  0x10000 partition-table.bin `
  0x1e000 ota_data_initial.bin `
  0x20000 kern.bin
if ($LASTEXITCODE -ne 0) { throw 'Kern flash failed' }
Get-FileHash -Algorithm SHA256 kern.bin
```

Check each write reports hash verification and the device reaches Home after reset. If connection stalls, use the board's BOOT/reset procedure and retry the identification command before flashing.

## Run the new test cycle

Use public, unfunded fixtures and disposable test seeds. Record the five commit SHAs, submodule pins, both image hashes, board/chip identity, Sparrow profile, QR density, and observations in a new test log.

1. Boot the new SeedSigner and Kern builds. Check display, touch/buttons, and camera scanning.
2. Run one complete Sparrow protected-signing success with SeedSigner, and one with Kern. Confirm every request/response stage completes and that Sparrow accepts the protected result. Exercise Kern's next-ceremony continuation with a second fresh session.
3. Run the established missing-protection or mismatched-response rejection for each signer. With policy **Required**, confirm there is no ordinary-signing fallback or successful unprotected completion.
4. Exercise Sparrow's QR density choices with the laptop screen and both cameras. The upstream standard QR dialog now has low, medium, and high choices. Record the density that scans reliably and any difference in scan behavior with Kern's decoder fix.
5. Verify restart/abort recovery with a fresh session. Stop and preserve the first unexpected result for diagnosis.

Source sync and automated tests do not establish physical interoperability on the new images. Mark this cycle complete only after recording the device results. The fresh-laptop procedure is ready for that trial; it has not yet been executed end to end on the laptop.

The [review repository](https://github.com/FractalEncrypt/seedsigner-anti-exfil-review) contains the reference fixtures and historical operator records. Its [reviewer runbook](https://github.com/FractalEncrypt/seedsigner-anti-exfil-review/blob/main/docs/reviewer-build-and-test-runbook.md) describes the frozen review inputs; use those records as fixture references, while keeping the five synced source versions from this guide. Do not replace these sources with the runbook's older frozen tags.
