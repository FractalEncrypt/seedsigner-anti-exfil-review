# Reviewer build and test runbook — v2 candidate

This runbook is for independent reviewers of the experimental/testnet-only
anti-exfil work. It covers the reference oracle, Drongo, Sparrow, SeedSigner,
SeedSignerOS, and Kern. It does not require a campaign workspace, private
fixture, funded transaction, production coordinator profile, device, camera, or
network/chain access after repositories and build dependencies are obtained.

Use a case-sensitive native Linux filesystem for authoritative test and build
results. Do not build inside `/mnt/c` under WSL: Windows checkout conversion can
change bytes in hash-pinned fixtures. Never use production seeds or wallet
profiles with these review builds.

## 1. What can and cannot be reproduced

The Git object identities, fixture hashes, generated-fixture freshness checks,
and automated test outcomes are deterministic gates. Toolchain-dependent images
and binaries are build observations: record the source identity, dependency
identity, configuration, tool versions, byte size, and SHA-256 for every output.

Do **not** infer that a different complete-image hash is a failure unless the
build environment itself was controlled to a reproducible-build specification.
SeedSignerOS/Buildroot, ESP-IDF-generated development signing keys, debug paths,
timestamps, container layers, and host libraries can affect bytes. This package
makes no cross-host bit-for-bit image claim.

Flashing, booting, cameras, QR scanning, serial monitoring, and physical signer
observations are hardware gates. The build and software-test sections below do
not prove them.

## 2. Clone and bind the exact sources

Drongo, Sparrow, and Kern are local P4 candidates until publication is separately
authorized. SeedSigner and SeedSignerOS are existing public immutable tags. The Kern review
branch is based on the M8-accepted product commit and adds one P3 test-only fix
which preserves the original byte streams of three already-hash-pinned public
JSON corpora. That commit changes no C product source or build configuration.

```sh
git clone --recursive https://github.com/FractalEncrypt/sparrow.git sparrow
git -C sparrow checkout --detach cc760814c855dfaf3d27890d10ba86b635e3a033
git -C sparrow submodule update --init --recursive

git clone https://github.com/FractalEncrypt/drongo.git drongo
git -C drongo checkout --detach 948f586f0e523e0ef67d973a72eac67aa8148968

git clone https://github.com/FractalEncrypt/FractalEncrypt_seedsigner.git seedsigner
git -C seedsigner checkout --detach anti-exfil-review-v1-finalized-input-tested-2026-08-22

git clone --recursive https://github.com/FractalEncrypt/seedsigner-os.git seedsigner-os
git -C seedsigner-os checkout --detach anti-exfil-review-v1-tested-2026-08-12
git -C seedsigner-os submodule update --init --recursive

# Available after the later publication step. Until then obtain the local bundle
# or patch set from the owner; do not substitute a moving branch silently.
git clone --recursive https://github.com/FractalEncrypt/Kern.git kern
git -C kern checkout --detach bc382c2c458e81230b5c0c434cd5b2219eef76b6
git -C kern submodule update --init --recursive
```

Verify all bindings:

```sh
test "$(git -C drongo rev-parse HEAD^{commit})" = 948f586f0e523e0ef67d973a72eac67aa8148968
test "$(git -C drongo rev-parse HEAD^{tree})" = d5943708b3cb71779e7c2cd5fbf931dcf67e54d4
test "$(git -C sparrow rev-parse HEAD^{commit})" = cc760814c855dfaf3d27890d10ba86b635e3a033
test "$(git -C sparrow rev-parse HEAD^{tree})" = 6ce0ff0953560008e1832929540e5c2ebdb5b042
test "$(git -C sparrow rev-parse HEAD:drongo)" = 948f586f0e523e0ef67d973a72eac67aa8148968
test "$(git -C sparrow rev-parse HEAD:lark)" = ddffe556f0d1ba6a138be3b362ce74219fed0710
test "$(git -C seedsigner rev-parse HEAD^{commit})" = 214793df4f51466179b792420921b8cdd8d0c1ac
test "$(git -C seedsigner rev-parse HEAD^{tree})" = 97308cf847e0415737f72e64a60c8aa6c745a0bc
test "$(git -C seedsigner-os rev-parse HEAD^{commit})" = 0bf1dc92519906c7db265055abfb07e0ee344342
test "$(git -C seedsigner-os rev-parse HEAD^{tree})" = 1ed46cd81f95c9b372c5248e30b883ac33c13a0c
test "$(git -C seedsigner-os rev-parse HEAD:opt/buildroot)" = bf2a2858aa675a14b60f1f9142c65b32652609c1
test "$(git -C kern rev-parse HEAD^{commit})" = bc382c2c458e81230b5c0c434cd5b2219eef76b6
test "$(git -C kern rev-parse HEAD^{tree})" = 196a182647ded7825d0f3e524d72a611add70950
test "$(git -C kern rev-parse HEAD^1)" = 5180dbb603e01e33698bb388a400f92bff722d4c
git -C kern diff --exit-code 5180dbb603e01e33698bb388a400f92bff722d4c..HEAD -- \
  ':(exclude).gitattributes' \
  ':(exclude)main/core/test/fixtures/anti_exfil/semantic_protocol/protocol-v1-negative-vectors.json' \
  ':(exclude)main/core/test/fixtures/anti_exfil/semantic_protocol/protocol-v1-semantic-psbt-vector.json' \
  ':(exclude)main/core/test/fixtures/anti_exfil/transport/protocol-v1-multislot-vectors.json'
git -C kern submodule status --recursive
```

Expected Kern submodule commits are:

```text
components/cUR                                      09724a010622460733e5e5d60f9505f5989b2fe8
components/k_quirc                                  f1887f25baee9603027302ef50d382509d6e977b
components/libwally-core/upstream                   247f2001f0e751f9fb79e12a7908ee7d5f765800
components/libwally-core/upstream/src/secp256k1     45f6f0f158c5ae80a2c8a53398ea4adbf19af6dc
```

The three pinned Kern fixture SHA-256 values must be, on Linux and Windows:

```text
f5b9d3d21210173bb35da0a0de15705b3bc1d3a3d8ab42a14183c2cd7ee97599  protocol-v1-negative-vectors.json
f28d572d1ae5d2060eeb52ca9814f37ce5d54258811d3af18b78c41744e23a4e  protocol-v1-semantic-psbt-vector.json
bafd399a342e1be965666d4efca970b50218a2fb2e2820c418ad64686bac1bb3  protocol-v1-multislot-vectors.json
```

## 3. Verify the review archive and reference oracle

Preserve the supplied ZIP, verify its separately supplied outer SHA-256, and
then verify every internal payload:

```sh
sha256sum -c seedsigner-anti-exfil-review-bundle-v2-candidate.zip.sha256
mkdir review-v2
cd review-v2
unzip ../seedsigner-anti-exfil-review-bundle-v2-candidate.zip
sha256sum -c SHA256SUMS.txt
python3 scripts/verify_review_bundle_v2.py ../seedsigner-anti-exfil-review-bundle-v2-candidate.zip

python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests/reference -t . -v
```

Regenerate vectors in a disposable copy and compare bytes/hashes with the
archive. Set `SEEDSIGNER_SRC` to the separately cloned SeedSigner `src`
directory to activate cross-implementation adapter checks.

## 4. Drongo tests

Use JDK 25 and the committed wrapper:

```sh
cd ../drongo
./gradlew --no-daemon test \
  --tests '*AntiExfilCodecTest' \
  --tests '*AntiExfilCoordinatorTest' \
  --tests '*AntiExfilPsbtTest' \
  --tests '*KeystoreTest'
./gradlew --no-daemon clean test
```

On Windows, preserve the unfiltered result before any platform exclusion. The
P1 record has exactly two known non-Windows XDG-method failures; exclusions are
not portable permission to ignore a different failure.

## 5. Sparrow tests and packaging

Use JDK 25, the committed wrapper, and recursively initialized submodules:

```sh
cd ../sparrow
./gradlew --no-daemon :test \
  --tests 'com.sparrowwallet.sparrow.control.QRScanDialogUrDecoderTest' \
  --tests '*AntiExfilPolicyPersistenceTest' \
  --tests '*AntiExfilTransportPackageTest' \
  --tests '*SeedSignerAntiExfilImportTest' \
  --tests '*SeedSignerImportPolicyTest' \
  --tests '*AntiExfilPolicySelectionTest' \
  --tests '*AntiExfilSigningFlowTest' \
  --tests '*HeadersFxmlAntiExfilTest' \
  --tests '*KeystoreFxmlAntiExfilTest'
./gradlew --no-daemon clean test
./gradlew --no-daemon clean installDist
./gradlew --no-daemon clean jpackageImage
```

Run packaging from a clean repository root. On Windows, preserve the four known
CRLF/LF export-comparison failures from the unfiltered P2 result before applying
exact-method exclusions. Launch only with a new disposable testnet profile; do
not point the review build at a production wallet profile.

## 6. SeedSigner application tests

The authoritative environment is Ubuntu with Python 3.10 or 3.12. Install the
native barcode library before Python dependencies:

```sh
cd seedsigner
sudo apt-get update
sudo apt-get install -y libzbar0 python3-venv
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt -r tests/requirements.txt \
  -r l10n/requirements-l10n.txt
python -m pip install -e .
python setup.py compile_catalog

python -m pytest -vv \
  tests/test_anti_exfil_protocol.py \
  tests/test_anti_exfil_native.py \
  tests/test_anti_exfil_selftest.py \
  tests/test_anti_exfil_state.py \
  tests/test_anti_exfil_views.py \
  tests/test_decode_anti_exfil_qr.py \
  tests/test_seedqr.py
python -m pytest -vv
```

The accepted focused-suite record at this exact commit is 42 passed and 2
native-library-dependent skips. P3 also reran the dependency-complete protocol,
native-wrapper, and self-test subset on Windows: 14 passed, 2 skipped. The latter
is a setup smoke check, not a substitute for the Linux command above.

## 7. SeedSignerOS normal and instrumented Pi Zero images

Use a Linux Docker host with at least 20 GB free space and support for
`linux/amd64` containers. The Buildroot gitlink is part of the identity gate.
Run the modes from separate clean clones, or run normal first and reset the
worktree/submodule before the instrumented build. Do not use `--no-clean` for a
review artifact.

Normal image—the anti-exfil physical-test overlay must be absent:

```sh
cd seedsigner-os
export DOCKER_DEFAULT_PLATFORM=linux/amd64
export SS_ARGS='--pi0 --app-repo=https://github.com/FractalEncrypt/FractalEncrypt_seedsigner.git --app-commit-id=214793df4f51466179b792420921b8cdd8d0c1ac'
docker compose up --force-recreate --build
```

Instrumented test image—the test services are explicitly opted in and Pi
Zero-only:

```sh
export DOCKER_DEFAULT_PLATFORM=linux/amd64
export SS_ARGS='--pi0 --anti-exfil-test --app-repo=https://github.com/FractalEncrypt/FractalEncrypt_seedsigner.git --app-commit-id=214793df4f51466179b792420921b8cdd8d0c1ac'
docker compose up --force-recreate --build
```

For each image, preserve the complete console log and record:

```sh
git rev-parse HEAD^{commit} HEAD^{tree} HEAD:opt/buildroot
docker version
docker compose version
find images -maxdepth 1 -type f -name '*.img' -print0 | sort -z | xargs -0 sha256sum
find images -maxdepth 1 -type f -name '*.img' -printf '%s  %p\n' | sort -k2
git status --short
```

Inspect the generated Buildroot configuration. The normal build must not include
`anti-exfil-test-overlay`; the instrumented build must include it alongside the
normal rootfs overlay. Confirm that only the instrumented output name contains
`.anti-exfil-test.img`.

The M8 hardware campaign used an instrumented image bound to SeedSigner
`214793df...`, SeedSignerOS `0bf1dc...`, with SHA-256
`adc2b58ae9dd57e884ec33b0e39ebf608ee8cc468d3fa7c563a1f1f808550fb3`.
That is a historical accepted observation, not a promised rebuild hash.

## 8. Kern host tests

Prerequisites on Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y build-essential python3 zlib1g-dev
```

Run the repository suites directly (this avoids depending on the executable bit
or line ending of a wrapper script):

```sh
cd kern
make -C components/deflate_codec/test run
make -C components/bbqr/test run
make -C main/core/test run
```

The final command includes fixture freshness, independent collaboration-corpus
checks, production anti-exfil semantics, authoritative slot enumeration, signer,
transport, and response tests. P3 ran all three commands successfully from a
fresh native-Linux checkout of `bc382c2...`; see `logs/kern-host-tests-linux.log`.

## 9. Kern simulator build (no camera required)

The simulator is useful for UI inspection but is non-trusted and uses host
mbedTLS. It is not proof of ESP-IDF firmware behavior. Use a machine without
sensitive credentials.

```sh
sudo apt-get install -y build-essential cmake libsdl2-dev libmbedtls-dev
cd kern/simulator
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug -DSIM_BOARD=wave_4b
cmake --build build -- -j"$(nproc)"
sha256sum build/kern_simulator
wc -c build/kern_simulator
./build/kern_simulator --help
```

CMake fetches its pinned LVGL source during first configuration unless it is
already cached. Record that network/dependency acquisition separately from the
offline compile. P3 began this configuration, observed the explicit LVGL GitHub
fetch, and stopped it rather than mislabeling the build as offline; no simulator
success claim is made in this package.

## 10. Kern ESP-IDF firmware builds

Use Espressif ESP-IDF **v6.0.2** and a recursive clone. The repository pins
managed component versions in its dependency lock. Network may be required on a
fresh machine to install the toolchain and populate the managed-component cache;
after that, repeat with network disabled if you want an offline-build claim.

Build one board or the full six-board matrix with separate build directories:

```sh
. "$IDF_PATH/export.sh"
idf.py --version
for board in wave_4b wave_35 wave_5 wave_43 crowpanel wave_7b; do
  idf.py -B "build_${board}" \
    -D "SDKCONFIG=build_${board}/sdkconfig" \
    -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.${board}" \
    build all size-components size 2>&1 | tee "build_${board}.log"
done
```

Each clone creates a development signing key. It is not a release identity and
means cross-clone firmware hashes can differ. Never publish the private key.
Record its public fingerprint using the project/toolchain-supported public-key
inspection method, and record all flashable artifacts:

```sh
for board in wave_4b wave_35 wave_5 wave_43 crowpanel wave_7b; do
  find "build_${board}" -type f \
    \( -name '*.bin' -o -name '*.elf' -o -name '*.map' -o -name 'flasher_args.json' -o -name 'flash_args' -o -name 'sdkconfig' \) \
    -print0 | sort -z | xargs -0 sha256sum > "build_${board}.sha256"
  find "build_${board}" -type f \
    \( -name '*.bin' -o -name '*.elf' -o -name '*.map' -o -name 'flasher_args.json' -o -name 'flash_args' -o -name 'sdkconfig' \) \
    -printf '%s  %p\n' | sort -k2 > "build_${board}.sizes"
done
git status --short
```

The accepted M8 lineage previously produced a wave_7b `kern.bin` of 1,970,176
bytes with SHA-256 `ed344a28...17d563` under pinned ESP-IDF 6.0.2. It predates
the P3 fixture-byte commit and is historical evidence only. Since P3 changes no
compiled source/configuration, it should not change product behavior, but a
reviewer must record rather than assume the new output.

## 11. Optional physical checks—separate gate

Do not perform this section merely to reproduce software gates. If a reviewer
chooses to use dedicated test hardware, use only disposable/testnet material.

Flash an explicitly selected board and port:

```sh
idf.py -B build_wave_7b -p /dev/ttyACM0 flash
idf.py -B build_wave_7b -p /dev/ttyACM0 monitor
```

Record board model, port, source and submodule commits, ESP-IDF/tool versions,
all flashed artifact hashes, signing-key public fingerprint, boot log, displayed
version, self-test outcome, and whether any camera/QR exercise was performed.
Never merge this observation into a deterministic source/build claim.

## 12. Reviewer result checklist

- All Git commit, tree, tag, and submodule identities match.
- SeedSigner focused and full suites pass on supported Linux/Python.
- SeedSignerOS normal/test overlay boundary is demonstrated from separate clean
  builds and both image inventories are preserved.
- Kern fixture hashes match on a native Linux checkout and every host suite
  passes.
- Any simulator result discloses the fetched/cached LVGL identity and host
  libraries.
- Every ESP-IDF result records v6.0.2, board config, managed dependencies,
  signing-key public identity, log, byte sizes, and hashes.
- Hardware observations, if any, are clearly separated and use no production
  secret or funded transaction.
- Differences are reported; no expected-hash claim is invented for uncontrolled
  image builds.
