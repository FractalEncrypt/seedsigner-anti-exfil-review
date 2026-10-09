# Build from source on Linux

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

This guide targets a native **Ubuntu 24.04 x64 desktop** and the 2026-10-09 tester source versions: Sparrow `78ebc9a2aca4998267c0647944f49c51f265037f`, Drongo `1c88f61ef3ca4dac54c0ca44a06bdc0808e0ad36`, SeedSigner `821a5102cbb87061b44a018d2fb95b05b410cc5f`, SeedSignerOS `d841a5e5a6d74b66b8bf1ba1b2e78d4e7db9fa74`, and Kern `0c2446a6e9ecee2914122cd858bdebd86da0894e`. It is a source-build procedure; native Linux end-to-end qualification is still pending. For prebuilt packages use [Download and test](download-and-test.md).

Keep sources on a Linux filesystem, allow at least 30 GB free plus downloads,
and stop on a failed command. These clone steps need new directories; inspect
existing checkouts before repeating them.

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

## Check and prepare the computer

Run these read-only checks in a terminal first:

```bash
cat /etc/os-release
uname -m
git --version
java --version
javac --version
docker version
docker compose version
python3 --version
```

Continue with this guide only on Ubuntu 24.04 x86_64. Missing commands are handled below. If Git, Python, and desktop libraries are already present, skip their installation. Otherwise install them:

```bash
sudo apt update
sudo apt install git curl ca-certificates python3 python3-venv libgtk-3-0t64 libasound2t64
```

### Java

The package builds used JDK 25.0.2+10. If you already have this JDK, set `JAVA_HOME` to its actual directory and skip the download. Otherwise download it from the official [Temurin release](https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.2%2B10), verify its upstream checksum, and extract into a new tools directory. The commands stop if that destination already exists.

```bash
mkdir -p ~/anti-exfil-tools
cd ~/anti-exfil-tools
test ! -e jdk-25.0.2+10 || { echo 'JDK directory already exists; inspect it first'; exit 1; }
base='https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.2%2B10'
archive='OpenJDK25U-jdk_x64_linux_hotspot_25.0.2_10.tar.gz'
curl -fL "$base/$archive" -o "$archive"
curl -fL "$base/$archive.sha256.txt" -o "$archive.sha256.txt"
expected=$(awk '{print $1}' "$archive.sha256.txt")
printf '%s  %s\n' "$expected" "$archive" | sha256sum -c - || exit 1
tar -xzf "$archive"
export JAVA_HOME="$HOME/anti-exfil-tools/jdk-25.0.2+10"
export PATH="$JAVA_HOME/bin:$PATH"
java --version
javac --version
```

Repeat the two export lines when opening a new terminal for Sparrow. The repository wrapper downloads Gradle and Java dependencies; no separate Gradle installation is required.

### Docker

If `docker version` shows Client and Server without a connection error and `docker compose version` shows v2, skip installation. If installed but unavailable, start the existing Docker service or resolve its permissions before installing another Docker distribution.

For a computer without Docker, use Docker's [Ubuntu installation procedure](https://docs.docker.com/engine/install/ubuntu/). Check its conflicting-package list before changing an existing container installation. For a fresh computer, the repository setup and install commands are:

```bash
sudo apt update
sudo apt install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: noble
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.asc
EOF
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl start docker
sudo docker run --rm hello-world
sudo docker compose version
```

The firmware commands below use `sudo docker`; Docker Desktop and WSL are not required on native Linux. First builds download container images and firmware dependencies.

### Etcher and USB access

If balenaEtcher is installed and opens, skip installation. Otherwise use [balena's Linux download](https://etcher.balena.io/) and its distribution-specific installation instructions. Test that it opens before starting a firmware build.

For USB serial flashing, list your groups with `id`. If `dialout` is present, skip the following command. Otherwise add your user, then **log out and back in** before continuing:

```bash
sudo usermod -aG dialout "$USER"
```

## Clone and launch Sparrow

Clone into a new folder, select the exact source commit, then initialize its pinned dependencies. Stop if the printed Sparrow or Drongo SHA differs from the opening paragraph.

```bash
mkdir -p ~/anti-exfil-test
cd ~/anti-exfil-test
git -c core.autocrlf=false clone https://github.com/FractalEncrypt/sparrow.git sparrow
git -C sparrow checkout --detach 78ebc9a2aca4998267c0647944f49c51f265037f
git -C sparrow submodule update --init --recursive
git -C sparrow rev-parse HEAD
git -C sparrow/drongo rev-parse HEAD
git -C sparrow submodule status --recursive
```

Once the identities match, build and run checks. Wait for **BUILD SUCCESSFUL**; do not launch after a failure.

```bash
cd ~/anti-exfil-test/sparrow
export JAVA_HOME="$HOME/anti-exfil-tools/jdk-25.0.2+10"
export PATH="$JAVA_HOME/bin:$PATH"
bash ./gradlew --no-daemon check jpackageImage -PskipInstallers=true
```

Launch with a short dedicated profile and the shared pointer disabled. Keep this terminal open. Do not change to an ordinary wallet home or import production wallets.

```bash
export SPARROW_NO_LOCK_FILE_LINK=true
build/jpackage/Sparrow/bin/Sparrow --dir "$HOME/.aex-test/source-post" --network testnet4
```

Confirm Testnet4 and select the desktop camera. For each matching hardware keystore, apply **Protected signing → Required**.

## Build and flash SeedSigner

Clone both repositories and select their exact commits. Initialize submodules after checkout. Stop if either printed source SHA differs from the opening paragraph, or the Buildroot pin is not `bf2a2858aa675a14b60f1f9142c65b32652609c1`.

```bash
cd ~/anti-exfil-test
git -c core.autocrlf=false clone https://github.com/FractalEncrypt/FractalEncrypt_seedsigner.git seedsigner
git -C seedsigner checkout --detach 821a5102cbb87061b44a018d2fb95b05b410cc5f
git -C seedsigner submodule update --init --recursive
git -c core.autocrlf=false clone https://github.com/FractalEncrypt/seedsigner-os.git seedsigner-os
git -C seedsigner-os checkout --detach d841a5e5a6d74b66b8bf1ba1b2e78d4e7db9fa74
git -C seedsigner-os submodule update --init --recursive
git -C seedsigner rev-parse HEAD
git -C seedsigner-os rev-parse HEAD
git -C seedsigner-os/opt/buildroot rev-parse HEAD
```

The OS source includes CRLF text files. Before building, normalize its UTF-8 text files to LF and record the resulting diff. This changes line endings only, skips symlinks/binary files and Buildroot, and matches the candidate builder's recorded OS normalization.

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
ss_board='pi0'  # Choose pi0, pi02w, pi2, or pi4 from the table above.
case "$ss_board" in pi0|pi02w|pi2|pi4) ;; *) echo 'Unknown SeedSigner target'; exit 1 ;; esac
export SS_ARGS="--$ss_board --app-repo=https://github.com/FractalEncrypt/FractalEncrypt_seedsigner.git --app-commit-id=821a5102cbb87061b44a018d2fb95b05b410cc5f"
sudo env SS_ARGS="$SS_ARGS" DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose up --force-recreate --build --abort-on-container-exit --exit-code-from build-images
```

Only after a successful build, record the image identity:

```bash
sha256sum "images/seedsigner_os.821a5102cbb87061b44a018d2fb95b05b410cc5f.$ss_board.img"
```

Flashing overwrites the selected microSD card. Disconnect SeedSigner power,
remove its card, and insert it in the reader. In Etcher select the image for your
chosen board, select the test card, and flash. Wait for validation, safely eject,
return the card to SeedSigner, and reconnect power. Check camera/buttons.

After boot, enable **Settings → Persistent Settings**. In **Settings →
Advanced**, configure the display if needed (Plus: **Hardware → Display type →
st7789 320x240**), then **Bitcoin Network → Testnet** and **Anti-exfil signing →
Required**. These settings do not require a loaded seed.


## Build Kern

Clone and verify the exact revision and decoder submodule. Stop if the decoder pin differs from `85cd38c2e10714f262ce16a33239469684e5aa45`.

```bash
cd ~/anti-exfil-test
git -c core.autocrlf=false clone https://github.com/FractalEncrypt/Kern.git kern
git -C kern checkout --detach 0c2446a6e9ecee2914122cd858bdebd86da0894e
git -C kern submodule update --init --recursive
git -C kern rev-parse HEAD
git -C kern submodule status --recursive
```

This build generates an ignored development signing key. Keep it local; its signed firmware bytes can differ from the distributed binary. Wait for build success, then check the dependency lockfile and record the hash. Stop on a lockfile diff.

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
sudo docker run --rm -v "$PWD:/project" -w /project \
  espressif/idf@sha256:81893c71bb5e570088901f21def8684c25cd2a9020281bd01b843a7655edb18c \
  idf.py -B "build_$kern_target" \
    -D "SDKCONFIG=build_$kern_target/sdkconfig" \
    -D "SDKCONFIG_DEFAULTS=$kern_defaults" build
git diff --exit-code -- dependencies.lock
sha256sum "build_$kern_target/kern.bin"
cat "build_$kern_target/flash_args"
```

## Flash Kern

Create an isolated Python environment only if it does not already exist.

```bash
python3 -m venv ~/anti-exfil-tools/kern-flash
flash_python="$HOME/anti-exfil-tools/kern-flash/bin/python"
"$flash_python" -m pip install esptool==5.3.1
"$flash_python" -m serial.tools.list_ports
```

Connect the device with a USB data cable and identify its newly appearing port. Replace `/dev/ttyACM_REPLACE` with that port. Identify the chip before writing:

```bash
kern_port='/dev/ttyACM_REPLACE'
"$flash_python" -m esptool --chip esp32p4 --port "$kern_port" chip-id
```

Continue only when the identified **v0.x/v1.x** or **v3.x** silicon matches
the revision chosen for your build. Flashing replaces firmware. Enter its output
directory and use its generated options/offsets:

```bash
cd "build_$kern_target"
"$flash_python" - "$kern_port" <<'PY'
from pathlib import Path
import shlex, subprocess, sys
args = shlex.split(Path('flash_args').read_text())
subprocess.run([sys.executable, '-m', 'esptool', '--chip', 'esp32p4',
                '--port', sys.argv[1], 'write-flash', *args], check=True)
PY
```

Confirm each write reports hash verification and Kern boots to Home. After
loading your disposable seed, use the orange **i** to confirm Testnet and
anti-exfil on.

## Test your source build

Use [offline signing tests](offline-public-fixture-testing.md) with the kit's
public fixtures or [live Testnet4 signing](end-to-end-testnet-testing.md) with
your own disposable seeds. Keep the source-built Sparrow launch command above
instead of **Start-Sparrow.cmd**. Configure your board's display/camera, and
record actual source/build hashes, board/chip revision, and Linux version with
your results. Native Linux end-to-end qualification remains pending.
