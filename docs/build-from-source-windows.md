# Build from source on Windows

## Current October 9 Windows source

The Windows tester uses rebuilt native components and the reviewed restart
repair. For its exact source, use **AexSource-20261009.zip**, then extract
**current/sparrow-final-source.zip**. It contains the full Sparrow, Drongo and
Lark sources at the identities recorded in SOURCE-IDENTITIES.json, with no Git
history required. Sparrow commit **78ebc9a2aca4998267c0647944f49c51f265037f** has tree
2823ac1b19b8840c0905319b60197bbc5d8d70ec;
Drongo is 1c88f61ef3ca4dac54c0ca44a06bdc0808e0ad36. The clone steps below select this exact committed source. These commits must
be reachable on the public remotes before this guide is published.

Use the pinned JDK 25.0.2+10 and the included Gradle wrapper to check/build the
exported source. Native corresponding sources, Cargo vendor inputs, patches,
relinking inputs and build records are in the bundled baseline archive's
previous-native-reviewer/sources/windows-native-corresponding-source-2026-10-08.zip.
The baseline's original historical device and Java dependency sources remain
applicable to unchanged components; the bundle README maps each source packet.
CRT deployment and exact packaged identities are in the baseline crt-candidate
records plus the accepted notice-closure delta and current restart records.
Follow those packaging records when comparing a Windows image; a Gradle source
build alone does not establish byte-for-byte reproduction of the tester image.
No exact bit-reproducibility or separately built Linux image qualification is
claimed by this source delivery.

## Build the current source

For ready-made packages, use [Download and test](download-and-test.md). This source-build route needs development tools and substantially more time.

Use this guide to build the pinned Sparrow fork and your SeedSigner/Kern
device images. Firmware builds run in Ubuntu under WSL; Sparrow runs in Windows.
Choose your hardware target below before building.

## Source versions

These are the current tester kit's source identities. Sparrow is pinned to
**78ebc9a2aca4998267c0647944f49c51f265037f**, including the tested proof-handling
changes, with Drongo **1c88f61ef3ca4dac54c0ca44a06bdc0808e0ad36**. This guide checks
out the exact commits; moving branch tips are not the build identity.

| Repository | Branch | Commit |
| --- | --- | --- |
| Drongo | `codex/final-release-20261009` | `1c88f61ef3ca4dac54c0ca44a06bdc0808e0ad36` |
| Sparrow | `codex/final-release-20261009` | `78ebc9a2aca4998267c0647944f49c51f265037f` |
| SeedSigner | `codex/sync-2026-09-seedsigner-anti-exfil` | `821a5102cbb87061b44a018d2fb95b05b410cc5f` |
| SeedSignerOS | `codex/sync-2026-09-seedsigner-os` | `d841a5e5a6d74b66b8bf1ba1b2e78d4e7db9fa74` |
| Kern | `codex/kern-continuous-ceremony` | `0c2446a6e9ecee2914122cd858bdebd86da0894e` |

The source commits are published with this release; no Git bundle is needed.
Sparrow commit 78ebc9a2aca4998267c0647944f49c51f265037f binds the reviewed source tree used by the
Windows tester. Your source build creates a new artifact;
record its own hash and test results rather than inheriting release-binary credit.

## Choose the device build target

The downloadable kit covers Pi Zero revision 1.3 and Kern Wave7B ESP32-P4
revision v1.3. Source builds can select the targets available in these pinned
repositories. Those target options do not imply physical anti-exfil qualification
on every board; record the board and your own results.

| SeedSigner board family | `ss_board` value | Image suffix |
| --- | --- | --- |
| Pi Zero / Pi Zero W | `pi0` | `pi0.img` |
| Pi Zero 2 W / Pi 3 | `pi02w` | `pi02w.img` |
| Pi 2 | `pi2` | `pi2.img` |
| Pi 4 / Pi 4 Compute Module IO | `pi4` | `pi4.img` |

These are the pinned OS builder's targets. Use the camera, display, and controls
supported by your SeedSigner configuration. The OS also accepts `--all` for
building all listed images; the steps below select one target at a time.

| Kern board | `kern_board` value |
| --- | --- |
| Waveshare ESP32-P4 Touch LCD 4B | `wave_4b` |
| Waveshare ESP32-P4 Touch LCD 3.5 | `wave_35` |
| Waveshare ESP32-P4 Touch LCD 5 | `wave_5` |
| Waveshare ESP32-P4 Touch LCD 4.3 | `wave_43` |
| Waveshare ESP32-P4 Touch LCD 7B | `wave_7b` |
| Elecrow CrowPanel Advanced ESP32-P4 7 / 10.1 | `crowpanel` |

All listed Kern targets use ESP32-P4. Use `kern_revision='v1'` for the normal
v0.x/v1.x target, or `kern_revision='v3'` for v3.x silicon. The build block adds
the pinned `sdkconfig.rev3` overlay and a separate `_v3` output directory when
selected. Identify your chip before selecting that revision and before flashing.
Keep the board's supported camera attached for QR tests.

## Prepare the computer

Commands marked **PowerShell** run in Windows; commands marked **Ubuntu** run in Ubuntu. Work through the checks first, then run only the installation or update commands that apply to your results. A diagnostic check may report that something is missing; the instructions immediately below explain what to do. Stop if an installation or build fails.

Keep the computer connected to power and prevent sleep during builds. Allow space for sources, containers, and outputs: SeedSignerOS alone estimates 20–30 GB for its build. Keep Linux firmware sources in Ubuntu's home directory to preserve executable bits and symlinks.

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

The current Windows native/restart build records use Temurin **25.0.2+10**.
Use that exact JDK to compare with the recorded builds. If it is already installed,
set **$jdkPath** below to its actual directory and verify both version commands.
Otherwise get the Windows x64 HotSpot JDK ZIP from the official
[Temurin 25.0.2+10 release](https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.2%2B10),
check its SHA-256 against the release's matching checksum file, and extract it
into a new tools directory. It does not require replacing another installed JDK.

For example, after extracting `OpenJDK25U-jdk_x64_windows_hotspot_25.0.2_10.zip`
under `C:\AntiExfilTools`, use:

```powershell
$jdkPath = 'C:\AntiExfilTools\jdk-25.0.2+10'
if (-not (Test-Path -LiteralPath "$jdkPath\bin\javac.exe")) { throw 'Set jdkPath to the extracted JDK directory' }
& "$jdkPath\bin\java.exe" --version
& "$jdkPath\bin\javac.exe" -version
```

Expect Java and javac **25.0.2** and the Java build **25.0.2+10**. Keep the actual
JDK path for the build and launch commands below. This is the JDK, not only a JRE.

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

The image builds use **WSL 2 with Ubuntu 24.04**. Before changing the computer, check its Windows version using `winver` and check **Task Manager → Performance → CPU → Virtualization**. Docker's Windows requirements include Windows 10 22H2 build 19045, WSL 2.1.5 or later, and 8 GB RAM; check the [Docker Windows requirements](https://docs.docker.com/desktop/setup/install/windows-install/) for your Windows edition and servicing status. If virtualization is disabled, enable it in the computer's BIOS/UEFI before continuing.

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

In normal **PowerShell**, clone the sources and print their versions. Before building, compare the two HEAD values with the source table. Stop if they differ from the pinned commits. The Sparrow Drongo submodule must be `1c88f61ef3ca4dac54c0ca44a06bdc0808e0ad36`; the separate Drongo clone is useful for inspection, but Sparrow builds its own submodule.

```powershell
$repos = Join-Path $env:USERPROFILE 'Documents\AntiExfilTest'
New-Item -ItemType Directory -Path $repos -Force | Out-Null
Set-Location -LiteralPath $repos
git clone https://github.com/FractalEncrypt/drongo.git drongo
git clone --recurse-submodules https://github.com/FractalEncrypt/sparrow.git sparrow
git -C drongo checkout --detach 1c88f61ef3ca4dac54c0ca44a06bdc0808e0ad36
git -C drongo rev-parse HEAD
git -C sparrow checkout --detach 78ebc9a2aca4998267c0647944f49c51f265037f
git -C sparrow submodule update --init --recursive
git -C sparrow rev-parse HEAD
git -C sparrow submodule status --recursive
```

Once the source versions match, select the JDK checked during preparation and build. The first build downloads dependencies and can take time. Wait for `BUILD SUCCESSFUL` before proceeding to the separate launch command below.

```powershell
Set-Location -LiteralPath (Join-Path $repos 'sparrow')
$env:JAVA_HOME = 'C:\AntiExfilTools\jdk-25.0.2+10' # Use your actual verified JDK path
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

Close the welcome dialog with its top-right **X** and confirm **Testnet4**.
If the camera will not open during scanning, check Windows Privacy → Camera
and desktop-app access; a permission prompt is not necessarily shown. For each test wallet's SeedSigner or Kern keystore, open **Settings**, select that signer, set **Protected signing → Required**, and apply the change. Check the hardware model is SeedSigner or Kern so this setting is available.

## Build and flash SeedSigner

Open **Ubuntu**. Clone both application and OS sources with LF endings. These commands need new `seedsigner` and `seedsigner-os` folders. Before proceeding to the build block, compare both printed HEAD values with the source table; stop if either differs.

```bash
mkdir -p ~/anti-exfil-test
cd ~/anti-exfil-test
git -c core.autocrlf=false clone --branch codex/sync-2026-09-seedsigner-anti-exfil --recurse-submodules https://github.com/FractalEncrypt/FractalEncrypt_seedsigner.git seedsigner
git -c core.autocrlf=false clone --branch codex/sync-2026-09-seedsigner-os --recurse-submodules https://github.com/FractalEncrypt/seedsigner-os.git seedsigner-os
git -C seedsigner checkout --detach 821a5102cbb87061b44a018d2fb95b05b410cc5f
git -C seedsigner submodule update --init --recursive
git -C seedsigner rev-parse HEAD
git -C seedsigner-os checkout --detach d841a5e5a6d74b66b8bf1ba1b2e78d4e7db9fa74
git -C seedsigner-os submodule update --init --recursive
git -C seedsigner-os rev-parse HEAD
```

Once both versions match, build the normal image for your chosen SeedSigner target. The explicit `--app-repo` selects this fork, and `--app-commit-id` selects the intended application version. Keep Docker Desktop running. The OS source includes CRLF text files; the following preparation normalizes UTF-8 OS text to LF, skipping symlinks, binaries, and Buildroot. Record the resulting diff. If Docker reports a build error, stop and save its output; do not flash a leftover image. Wait for the build to finish successfully before running the following image-hash and Explorer commands.

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
ss_board='pi0'  # Choose pi0, pi02w, pi2, or pi4 from the table above.
case "$ss_board" in pi0|pi02w|pi2|pi4) ;; *) echo 'Unknown SeedSigner target'; exit 1 ;; esac
export SS_ARGS="--$ss_board --app-repo=https://github.com/FractalEncrypt/FractalEncrypt_seedsigner.git --app-commit-id=821a5102cbb87061b44a018d2fb95b05b410cc5f"
docker compose up --force-recreate --build --abort-on-container-exit --exit-code-from build-images
```

Only after the build finishes successfully, record the image hash and open the output directory:

```bash
sha256sum images/*.img
explorer.exe .
```

`explorer.exe .` opens the Linux source directory in Windows Explorer. Open its `images` folder and find `seedsigner_os.821a5102cbb87061b44a018d2fb95b05b410cc5f.<your ss_board>.img`. Copy that image into your Windows **Downloads** folder so Etcher can open it easily.

The following flash step overwrites the selected microSD card. Identify the SeedSigner card by capacity and drive identity before choosing the target.

1. Power off SeedSigner and put its microSD card in the computer's card reader.
2. Open **balenaEtcher**, choose **Flash from file**, and select the copied `.img`.
3. Choose **Select target** and select the identified SeedSigner microSD card.
4. Choose **Flash**, allow any administrator prompt, and wait for flashing and validation to finish successfully.
5. Eject the card through Windows, return it to the powered-off SeedSigner, and power on.

After boot, enable **Settings → Persistent Settings**. In **Settings →
Advanced**, configure the display if needed (Plus: **Hardware → Display type →
st7789 320x240**), then **Bitcoin Network → Testnet** and **Anti-exfil signing →
Required**. These settings do not require a loaded seed.


## Build Kern for your board

In **Ubuntu**, clone into a new `kern` folder and print the source version. Before proceeding to the build block, compare Kern's HEAD with the table and confirm the decoder submodule pin is `85cd38c2e10714f262ce16a33239469684e5aa45`. Stop if they differ.

```bash
cd ~/anti-exfil-test
git -c core.autocrlf=false clone --branch codex/kern-continuous-ceremony --recurse-submodules https://github.com/FractalEncrypt/Kern.git kern
git -C kern checkout --detach 0c2446a6e9ecee2914122cd858bdebd86da0894e
git -C kern submodule update --init --recursive
git -C kern rev-parse HEAD
git -C kern submodule status --recursive
```

Once the source versions match, build using the same ESP-IDF image used for this sync. Keep Docker Desktop running. The initial build retrieves locked managed components; preserve `dependencies.lock`. Wait for a successful build before running the hash and lockfile checks below. If the lockfile check reports changes, stop before flashing and save the output.

The clone generates its own ignored development signing key. Its signed image hash will differ from the desktop build; record your computer image hash and keep the key local for compatible future SD updates.

```bash
cd ~/anti-exfil-test/kern
# Choose from the target table above; defaults match the downloadable kit.
kern_board='wave_7b'
kern_revision='v1'
kern_target="$kern_board"
kern_defaults="sdkconfig.defaults;sdkconfig.defaults.$kern_board"
case "$kern_board" in
  wave_4b|wave_35|wave_5|wave_43|wave_7b|crowpanel) ;;
  *) echo 'Unknown Kern board target'; exit 1 ;;
esac
case "$kern_revision" in
  v1) ;;
  v3) kern_target="${kern_board}_v3"; kern_defaults="$kern_defaults;sdkconfig.rev3" ;;
  *) echo 'Use v1 or v3 for kern_revision'; exit 1 ;;
esac
docker run --rm -v "$PWD:/project" -w /project \
  espressif/idf@sha256:81893c71bb5e570088901f21def8684c25cd2a9020281bd01b843a7655edb18c \
  idf.py -B "build_$kern_target" \
    -D "SDKCONFIG=build_$kern_target/sdkconfig" \
    -D "SDKCONFIG_DEFAULTS=$kern_defaults" build
```

Only after the build succeeds, record its image hash and check the lockfile. A successful lockfile check prints nothing; if it prints a diff or an error, stop before flashing.

```bash
sha256sum "build_$kern_target/kern.bin"
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

The Ubuntu Explorer window shows Kern's source. Open **build_<your kern_target>**
(for example **build_wave_7b** or **build_wave_43_v3**). Copy these items into
**Documents/KernFlash**, keeping the subfolders:

- `flash_args`
- `bootloader` folder
- `partition_table` folder
- `ota_data_initial.bin`
- `kern.bin`

The generated `flash_args` supplies your board build's options and offsets.
It refers to the subfolders above; keep their layout intact.

Python was installed during preparation. Create an isolated flashing environment in the same **PowerShell** window:

```powershell
py -3.11 -m venv "$env:USERPROFILE\kern-flash-venv"
$flashPython = "$env:USERPROFILE\kern-flash-venv\Scripts\python.exe"
& $flashPython -m pip install esptool==5.3.1
& $flashPython -m serial.tools.list_ports
```

Connect Kern using a USB data cable. Rerun the port-list command and identify the newly appearing COM port, also visible in **Device Manager → Ports (COM & LPT)**. Replace `COM_REPLACE` below with that port, for example `COM3`. If no port appears, check the cable and USB port; use the board vendor's driver instructions if Windows requires a serial driver.

```powershell
$kernPort = 'COM_REPLACE'
& $flashPython -m esptool --chip esp32p4 --port $kernPort chip-id
if ($LASTEXITCODE -ne 0) { throw 'Could not identify Kern; check port and USB connection' }
```

Confirm the chip-id output matches the **v0.x/v1.x** or **v3.x** revision
selected for this build. Flashing replaces the installed firmware. Use the
generated options/offsets from your own build, then flash in PowerShell:

```powershell
Set-Location -LiteralPath $flashDir
$flashArgs = ((Get-Content -LiteralPath .\flash_args -Raw) -split '\s+') | Where-Object { $_ }
& $flashPython -m esptool --chip esp32p4 --port $kernPort write-flash @flashArgs
if ($LASTEXITCODE -ne 0) { throw 'Kern flash failed' }
Get-FileHash -Algorithm SHA256 kern.bin
```

Check that each write reports hash verification and Kern reaches Home after
reset. If connection stalls, use the board's BOOT/reset procedure and repeat
chip identification. Load your disposable seed, then use the orange **i** to
confirm Testnet and anti-exfil on.

## Test your source build

Record source commits, image hashes, board/chip revision, and operating system
with your results. Your launch command selects a dedicated source-build profile;
it is separate from the packaged kit's profile and retains its own sessions.

Use [offline signing tests](offline-public-fixture-testing.md) with the public
fixtures in the tester kit, or [live Testnet4 signing](end-to-end-testnet-testing.md)
with your own disposable test seeds. Keep the source-built Sparrow launch
command above instead of the kit's **Start-Sparrow.cmd**. The wallet/device
steps are the same after launch; configure your own board's display and camera.
Test successes, rejection, and recovery on your actual build. New hardware
results do not inherit qualification from the downloadable firmware.
