# Build Sparrow and keep the test profile isolated

The reviewed Sparrow fork supports a dedicated home folder through `--dir`.
This is the primary isolation boundary between the experimental build and an
ordinary installed Sparrow profile. A different executable alone is not
enough: without `--dir`, both applications can select the platform-default
Sparrow home.

## Exact reviewed source

```sh
git clone --recursive https://github.com/FractalEncrypt/sparrow.git sparrow-airgap-anti-exfil
git -C sparrow-airgap-anti-exfil checkout --detach cc760814c855dfaf3d27890d10ba86b635e3a033
git -C sparrow-airgap-anti-exfil submodule update --init --recursive
git -C sparrow-airgap-anti-exfil rev-parse HEAD^{commit}
git -C sparrow-airgap-anti-exfil rev-parse HEAD:drongo
```

Expected values:

```text
cc760814c855dfaf3d27890d10ba86b635e3a033
948f586f0e523e0ef67d973a72eac67aa8148968
```

Stop on a mismatch. Use JDK 25 and the committed Gradle wrapper.

## Build a non-installing application image

Windows PowerShell:

```powershell
Set-Location .\sparrow-airgap-anti-exfil
.\gradlew.bat --no-daemon clean jpackageImage
```

Linux or macOS:

```sh
cd sparrow-airgap-anti-exfil
./gradlew --no-daemon clean jpackageImage
```

This creates an application image under `build/jpackage`; it does not require
installing over a normal Sparrow application. Preserve the complete build log.

## Create a new home folder

Use a new empty path that is not inside a normal Sparrow home. Examples:

Windows PowerShell:

```powershell
$testHome = 'C:\airgap-anti-exfil-test\sparrow-home'
New-Item -ItemType Directory -Path $testHome -ErrorAction Stop
```

Linux or macOS:

```sh
mkdir -m 700 -p "$HOME/airgap-anti-exfil-test/sparrow-home"
```

Do not use `%APPDATA%\Sparrow`, `~/.sparrow`, or an existing wallet directory.

## Launch on the selected network

Testnet4 is recommended for new tests.

Windows packaged image:

```powershell
.\build\jpackage\Sparrow\Sparrow.exe --dir $testHome --network testnet4
```

Linux packaged image:

```sh
./build/jpackage/Sparrow/bin/Sparrow \
  --dir "$HOME/airgap-anti-exfil-test/sparrow-home" \
  --network testnet4
```

macOS packaged image:

```sh
./build/jpackage/Sparrow.app/Contents/MacOS/Sparrow \
  --dir "$HOME/airgap-anti-exfil-test/sparrow-home" \
  --network testnet4
```

For Testnet3, replace `testnet4` with `testnet`. Sparrow's `testnet` label means
Testnet3. Do not infer the network from the `tb1`, `m`, `n`, or `2` address
prefix because Testnet3 and Testnet4 share test-address encodings.

As a development-launch alternative:

```sh
./gradlew --no-daemon run --args="--dir /absolute/new/test-home --network testnet4"
```

On Windows use `gradlew.bat` and a Windows absolute path.

## Prove isolation before importing anything

1. Confirm the selected network in the Sparrow UI.
2. Confirm first-run onboarding appears.
3. Confirm no ordinary wallets are listed.
4. Open **Help → About** and record the build version.
5. Close Sparrow and confirm new files appeared only below the dedicated test
   home.
6. Relaunch with the same explicit `--dir` and `--network` arguments.

If an existing wallet appears unexpectedly, close Sparrow immediately and
report the exact command and paths without opening the wallet.

## After the test

Close the review build before opening ordinary Sparrow. Preserve the isolated
folder only if needed for a sanitized report. It can contain wallet metadata,
public descriptors, logs, server details, and anti-exfil coordinator state;
never upload it wholesale. When no longer needed, remove it using normal
operating-system file management only after checking the exact path.
