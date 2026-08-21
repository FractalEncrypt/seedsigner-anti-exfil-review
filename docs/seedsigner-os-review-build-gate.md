# Clean SeedSignerOS review-series image gate

Status: normal and corrected test image gates passed

This gate validates the public, current-upstream SeedSignerOS review branch
against the public SeedSigner review head. Run the two builds separately. Do
not add `--no-clean`: each image must regenerate its Buildroot output
configuration from the checked-in Pi Zero defconfig.

## Pinned inputs

| Input | Pin |
| --- | --- |
| SeedSignerOS fork | `https://github.com/FractalEncrypt/seedsigner-os.git` |
| SeedSignerOS branch | `anti-exfil-review-v1` |
| SeedSignerOS head | `0bf1dc92519906c7db265055abfb07e0ee344342` |
| SeedSignerOS tree | `1ed46cd81f95c9b372c5248e30b883ac33c13a0c` |
| Official OS base | `d5a1077851a9b41d6637f7317e3f06aaa453bd5d` |
| Buildroot submodule | `bf2a2858aa675a14b60f1f9142c65b32652609c1` |
| SeedSigner fork | `https://github.com/FractalEncrypt/FractalEncrypt_seedsigner.git` |
| SeedSigner head | `f971a645ce3cd8519adba62e92e3365b03fb48ab` |
| secp256k1-zkp source | `2af926dc309a673461f0e2da090105c8f05b4505` |
| secp256k1-zkp archive SHA-256 | `40e0858f5f189a078f2aeee10e1fc0e732f73abb7bc9f8745c63dac3f8d8d4e5` |

The prepared LF-safe fresh clone on this machine is:

```text
C:\Users\FractalEncrypt\Documents\Windsurf\SeedSignerOS_AntiExfil_Review_Fresh_LF2
```

Do not use the older siblings ending in `Review_Fresh` or `Review_Fresh_LF`.
The first exposed a CRLF Buildroot checkout. The second produced the valid
normal image and the pre-correction test image, whose boot services ran before
`S10mdev` could create and mount the SD partition.

## 1. Preflight

Open a new PowerShell window:

```powershell
$os = "C:\Users\FractalEncrypt\Documents\Windsurf\SeedSignerOS_AntiExfil_Review_Fresh_LF"
$appRepo = "https://github.com/FractalEncrypt/FractalEncrypt_seedsigner.git"
$appCommit = "f971a645ce3cd8519adba62e92e3365b03fb48ab"

Set-Location $os
git status --short --branch
git rev-parse HEAD
git rev-parse 'HEAD^{tree}'
git -C opt/buildroot rev-parse HEAD
Get-Item opt/buildroot/package/gcc/gcc-initial/gcc-initial.hash |
  Select-Object LinkType, Target
```

Expected:

- the status has no changed or untracked source files;
- HEAD is `0bf1dc92519906c7db265055abfb07e0ee344342`;
- the tree is `1ed46cd81f95c9b372c5248e30b883ac33c13a0c`;
- Buildroot is `bf2a2858aa675a14b60f1f9142c65b32652609c1`;
- `gcc-initial.hash` is a symbolic link to `../gcc.hash`.

Docker Desktop must be running:

```powershell
$env:DOCKER_DEFAULT_PLATFORM = "linux/amd64"
```

## 2. Completed normal production-style image gate

The image built from the same unchanged native-package commit contains the
isolated native ECDSA S2C library but no boot self-test or file-exchange
service. It reached the normal SeedSigner main menu and created no test receipt.

Recorded image:

```text
Length:  52428800
SHA-256: C96C8B5A00ED0281D9AA65F979F8ED59D52D2B320FDBD05B725193017F77E485
```

The FAT boot partition did not gain either test-only file:

```text
anti-exfil-selftest.json
anti-exfil-selftest.exit-code
```

The correction after this gate changes only test-overlay service names, their
test-only mount handling, and the corresponding conditional chmod paths. Those
paths do not exist in normal images, so the passed production boundary is not
invalidated and the normal image does not require rebuilding.

## 3. Completed corrected instrumented test-image gate

The corrected `Fresh_LF2` clone built without `--no-clean` and left source
status empty. The resulting image is 52,428,800 bytes with SHA-256
`E8E93EB527469E1708D6DB0735B2857F52F6F91276A9BD679D5141507FD48F85`.

```powershell
Set-Location $os
$env:SS_ARGS = "--pi0 --anti-exfil-test --app-repo=$appRepo --app-commit-id=$appCommit"
docker compose up --force-recreate --build
```

The expected output is:

```text
images\seedsigner_os.f971a645ce3cd8519adba62e92e3365b03fb48ab.pi0.anti-exfil-test.img
```

Record it:

```powershell
$test = Join-Path $os "images\seedsigner_os.$appCommit.pi0.anti-exfil-test.img"
Get-Item $test | Select-Object FullName, Length, LastWriteTime
Get-FileHash $test -Algorithm SHA256
git status --short
```

Again, the source status must remain empty.

The corrected image differs from the rejected pre-correction image
`AC53E3C9B16AF6D9316244296E0167A24E36F90A3D976E464061F78F9C825E14`,
as required.

## 4. Completed corrected test-image boot gate

Flash the test image and let SeedSigner reach its main menu. Shut it down
normally, return the SD card to Windows, and identify its FAT boot drive. If it
is `G:`, run:

```powershell
$boot = "G:\"
Get-Content (Join-Path $boot "anti-exfil-selftest.exit-code")
Get-Content (Join-Path $boot "anti-exfil-selftest.json") -Raw
```

The files appeared at the root of the boot partition. The exit-code file
contained `0`; the JSON receipt reported the native secp256k1-zkp backend,
matching opening and signature vectors, and `production_fallback: false`. The
ordinary SeedSigner UI started after the boot-time test.

The file-exchange adapter remains available beneath `aex-physical` when a
fixture is deliberately staged, but the already completed physical corpus does
not need to be repeated for this clean-series gate.

## 5. Report the gate

Return:

- confirmation that the already recorded normal gate remains accepted;
- the test image filename, size, and SHA-256;
- the self-test exit code and JSON receipt;
- confirmation that both post-build `git status --short` outputs were empty;
- the last 50 terminal lines if either build fails.

Both image/runtime gates passed. Review head `0bf1dc9` is protected by annotated
tag `anti-exfil-review-v1-tested-2026-08-12`.
