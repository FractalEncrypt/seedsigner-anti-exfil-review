# Reviewer build and test runbook

This runbook reconstructs the reviewed inputs from immutable public tags and
runs the principal automated gates. Use a case-sensitive native Linux host for
the authoritative result. Windows is useful for packaged-app smoke testing but
has the documented line-ending and XDG test exceptions in the checkpoint JSON.

The protocol is experimental and unaudited. Use testnet data only. No funded
transaction or broadcast is required to reproduce these gates.

## 1. Verify and unpack the private bundle

Verify the outer SHA-256 supplied separately, preserve the original ZIP, and
then verify every internal file before running code:

```sh
sha256sum seedsigner-anti-exfil-review-bundle-v1.2.zip
mkdir anti-exfil-reference
cd anti-exfil-reference
unzip ../seedsigner-anti-exfil-review-bundle-v1.2.zip
sha256sum --check SHA256SUMS.txt
```

`BUNDLE-METADATA.json` identifies the reference commit used to freeze the
archive. `independent-security-review-brief.md` identifies every implementation
commit and tag.

## 2. Clone and verify immutable implementation inputs

```sh
cd ..
git clone --branch anti-exfil-review-v1-tested-2026-08-14 \
  https://github.com/FractalEncrypt/FractalEncrypt_seedsigner.git seedsigner
git clone --recursive --branch anti-exfil-review-v1-gate5-tested-2026-08-22 \
  https://github.com/FractalEncrypt/sparrow.git sparrow
git clone --branch anti-exfil-review-v1-gate5-tested-2026-08-22 \
  https://github.com/FractalEncrypt/drongo.git drongo
git clone --recursive --branch anti-exfil-review-v1-tested-2026-08-12 \
  https://github.com/FractalEncrypt/seedsigner-os.git seedsigner-os

test "$(git -C seedsigner rev-parse HEAD)" = aa8395e3576379467d795bb05268533e3a2ac082
test "$(git -C sparrow rev-parse HEAD)" = f003bfa9575bc7c67b337f8785b1479fd092641a
test "$(git -C drongo rev-parse HEAD)" = bb691c7d77290933b3f7d6c411556c1524a29d98
test "$(git -C sparrow rev-parse HEAD:drongo)" = bb691c7d77290933b3f7d6c411556c1524a29d98
test "$(git -C seedsigner-os rev-parse HEAD)" = 0bf1dc92519906c7db265055abfb07e0ee344342
git -C sparrow submodule status --recursive
git -C seedsigner-os submodule status --recursive
```

Do not substitute the moving review branches for the tags. These annotated tags
identify immutable objects but are not asserted here to be cryptographically
signed.

## 3. Reference oracle and vectors

Python 3.10 or newer is required. The core suite runs without an implementation
checkout. Cross-implementation tests become active when `SEEDSIGNER_SRC` points
to the tagged SeedSigner `src` directory.

```sh
cd anti-exfil-reference
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m unittest discover -s tests/reference -t . -v

export SEEDSIGNER_SRC="$(cd ../seedsigner/src && pwd)"
python -m unittest discover -s tests/reference -t . -v
```

Regenerate vectors in a disposable copy and compare them with the supplied
files and internal hashes:

```sh
python scripts/generate_protocol_v1_vectors.py
python scripts/generate_protocol_v1_semantic_vectors.py
python scripts/generate_protocol_v1_negative_vectors.py
```

The extracted archive is not itself a Git checkout, so use `cmp`, `sha256sum`,
or a reviewer-owned Git worktree for the comparison.

## 4. SeedSigner

The authoritative public CI matrix uses Ubuntu with Python 3.10 and 3.12.

```sh
cd ../seedsigner
sudo apt-get update
sudo apt-get install -y libzbar0
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

Run the repository's screenshot workflow as shown in its pinned GitHub Actions
workflow if visual snapshots are in scope.

## 5. Drongo

Use JDK 25 and the committed Gradle wrapper:

```sh
cd ../drongo
./gradlew --no-daemon test \
  --tests '*AntiExfilCodecTest' \
  --tests '*AntiExfilCoordinatorTest' \
  --tests '*AntiExfilPsbtTest' \
  --tests '*KeystoreTest'
./gradlew --no-daemon clean test
```

## 6. Sparrow

Use JDK 25, the committed Gradle wrapper, and a recursive clone. The focused
command targets Sparrow's root test task so the filter is not incorrectly
propagated into Drongo.

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
./gradlew --no-daemon clean jpackageImage
```

Launch the packaged app with a new testnet profile; never point a review build
at a production profile. On Windows, some camera backends may briefly display
retained frames before the new stream arrives. The same behavior was reproduced
in stock Sparrow and is recorded as a backend quirk, not a fork regression.

## 7. SeedSignerOS normal and instrumented images

Use a Linux Docker host capable of `linux/amd64` containers. A Pi Zero build can
take 30–40 minutes. Build the two modes from separate clean clones or run the
normal build first. Do not use `--no-clean` for review artifacts.

Normal image (must exclude anti-exfil test init services):

```sh
cd ../seedsigner-os
export DOCKER_DEFAULT_PLATFORM=linux/amd64
export SS_ARGS='--pi0 --app-repo=https://github.com/FractalEncrypt/FractalEncrypt_seedsigner.git --app-commit-id=aa8395e3576379467d795bb05268533e3a2ac082'
docker compose up --force-recreate --build
```

Instrumented physical-test image:

```sh
export SS_ARGS='--pi0 --anti-exfil-test --app-repo=https://github.com/FractalEncrypt/FractalEncrypt_seedsigner.git --app-commit-id=aa8395e3576379467d795bb05268533e3a2ac082'
docker compose up --force-recreate --build
```

The physically tested Pi Zero instrumented image was
`seedsigner_os.aa8395e3576379467d795bb05268533e3a2ac082.pi0.anti-exfil-test.img`,
52,428,800 bytes, SHA-256
`05bf333f3342d3b1229ed2565bf6f4492901ad8962251bf5d6e34a63d375d17e`.
Assess reproducibility against the pinned inputs and Buildroot artifacts; do not
assume the complete image is bit-for-bit reproducible across uncontrolled hosts.

## 8. Short physical smoke gate

On the instrumented Pi Zero image and packaged Sparrow testnet profile:

1. Display a static SeedSigner QR and verify brightness decreases and increases.
2. Display an animated QR, change brightness both ways, and verify animation
   continues without freezing or restarting.
3. Import an explicit SeedSigner xpub QR in Sparrow and verify protected signing
   defaults to `Optional`.

These are release/UX checks. They do not replace the cryptographic, parser,
state-machine, downgrade, retry, and adversarial review requested in the brief.
