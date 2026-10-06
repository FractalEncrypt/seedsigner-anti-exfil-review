# Build from source on Linux

This guide targets a native **Ubuntu 24.04 x64 desktop** and the post-sync forks: Sparrow `bdca675348dc701eff4d5c29eb1f2fcf1780a934`, Drongo `bdc8029fd970dec938630e5d9406261b791bf8d8`, SeedSigner `821a5102cbb87061b44a018d2fb95b05b410cc5f`, SeedSignerOS `d841a5e5a6d74b66b8bf1ba1b2e78d4e7db9fa74`, and Kern `0c2446a6e9ecee2914122cd858bdebd86da0894e`. It is a source-build procedure; native Linux end-to-end qualification is still pending. For prebuilt packages use [Download and test](download-and-test.md).

The devices are SeedSigner Pi Zero and Kern `wave_7b`, ESP32-P4 revision **v1.3**. Keep builds on a Linux filesystem, allow at least 30 GB free plus downloads, keep power connected, and stop on any failed command. These cloning steps need new directories. Inspect existing checkouts before repeating them.

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
git -C sparrow checkout --detach bdca675348dc701eff4d5c29eb1f2fcf1780a934
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
export SS_ARGS='--pi0 --app-repo=https://github.com/FractalEncrypt/FractalEncrypt_seedsigner.git --app-commit-id=821a5102cbb87061b44a018d2fb95b05b410cc5f'
sudo env SS_ARGS="$SS_ARGS" DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose up --force-recreate --build --abort-on-container-exit --exit-code-from build-images
```

Only after a successful build, record the image identity:

```bash
sha256sum images/seedsigner_os.821a5102cbb87061b44a018d2fb95b05b410cc5f.pi0.img
```

Flashing overwrites the selected microSD card. Power off SeedSigner, insert its card into the computer, use Etcher to select this `.img`, identify the card by capacity/device, and flash. Wait for validation, eject safely, return it to the powered-off Pi Zero, and boot. Confirm camera/buttons and **Advanced → Anti-exfil signing → Required**. This is the normal QR image; no instrumented overlay is requested.

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
sudo docker run --rm -v "$PWD:/project" -w /project \
  espressif/idf@sha256:81893c71bb5e570088901f21def8684c25cd2a9020281bd01b843a7655edb18c \
  idf.py -B build_wave_7b -D SDKCONFIG=build_wave_7b/sdkconfig \
  -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.wave_7b' build
git diff --exit-code -- dependencies.lock
sha256sum build_wave_7b/kern.bin
cat build_wave_7b/flash_args
```

## Flash Kern

Create an isolated Python environment only if it does not already exist. For downloaded firmware, use the four files in the extracted Kern package and skip source-build commands.

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

Continue only when it reports **ESP32-P4 revision v1.3**. Flashing replaces firmware. For your source build, compare options/offsets with `build_wave_7b/flash_args`, then run from the Kern source directory:

```bash
"$flash_python" -m esptool --chip esp32p4 --port "$kern_port" write-flash \
  --flash-mode dio --flash-freq 80m --flash-size keep \
  0x2000 build_wave_7b/bootloader/bootloader.bin \
  0x10000 build_wave_7b/partition_table/partition-table.bin \
  0x1e000 build_wave_7b/ota_data_initial.bin \
  0x20000 build_wave_7b/kern.bin
```

For a downloaded package, change into its extracted directory and use `bootloader.bin`, `partition-table.bin`, `ota_data_initial.bin`, and `kern.bin` at the same offsets. Verify package checksums before this step. Confirm each write reports hash verification and Kern boots to Home. Do not erase the whole device or provision eFuses.

Complete the offline signing, rejection, and restart tests in [Download and test](download-and-test.md#7-perform-the-offline-signing-and-rejection-tests), recording your actual source-build hashes separately from release-package results.
