# Prepare a SeedSigner test image

This path builds the reviewed Pi Zero SeedSignerOS image with the reviewed
SeedSigner application. It requires a Linux Docker host, at least 20 GB free,
and a dedicated microSD card whose existing contents may be overwritten.

Use the normal image for community signing tests. The separately instrumented
campaign image adds evidence-collection services and is not needed for an
ordinary user trial.

## Exact reviewed sources

```sh
git clone --recursive https://github.com/FractalEncrypt/seedsigner-os.git seedsigner-os-airgap-anti-exfil
git -C seedsigner-os-airgap-anti-exfil checkout --detach anti-exfil-review-v1-tested-2026-08-12
git -C seedsigner-os-airgap-anti-exfil submodule update --init --recursive
git -C seedsigner-os-airgap-anti-exfil rev-parse HEAD^{commit}
git -C seedsigner-os-airgap-anti-exfil rev-parse HEAD:opt/buildroot
```

Expected values:

```text
0bf1dc92519906c7db265055abfb07e0ee344342
bf2a2858aa675a14b60f1f9142c65b32652609c1
```

The image must use SeedSigner application commit:

```text
214793df4f51466179b792420921b8cdd8d0c1ac
```

## Build the normal image

```sh
cd seedsigner-os-airgap-anti-exfil
export DOCKER_DEFAULT_PLATFORM=linux/amd64
export SS_ARGS='--pi0 --app-repo=https://github.com/FractalEncrypt/FractalEncrypt_seedsigner.git --app-commit-id=214793df4f51466179b792420921b8cdd8d0c1ac'
docker compose up --force-recreate --build
```

Preserve the console log, then locate and record the output:

```sh
find images -maxdepth 1 -type f -name '*.img' -print
find images -maxdepth 1 -type f -name '*.img' -print0 | sort -z | xargs -0 sha256sum
find images -maxdepth 1 -type f -name '*.img' -printf '%s  %p\n' | sort -k2
git status --short
```

The filename must not contain `.anti-exfil-test.img`; that name is reserved for
the instrumented campaign mode. Image bytes can vary with the toolchain and
host, so record the observed size and SHA-256 instead of expecting a universal
image hash.

## Write the microSD card

1. Shut down or unmount any sensitive removable media.
2. Insert only the dedicated SeedSigner test microSD card.
3. Use Raspberry Pi Imager's **Use custom** option, balenaEtcher, or another
   image writer that accepts the generated `.img`.
4. Select the exact generated image and the exact removable card. Writing the
   wrong target destroys its contents.
5. Write and use the application's verification/read-back option when
   available.
6. Eject the card safely and boot the Pi Zero SeedSigner from it.

Do not publish the card image as though it were a reproducible release
artifact. For a report, publish the source identities, build environment,
image size, SHA-256, and whether the card booted.

## Prepare disposable signing material

1. Confirm Sparrow is already on the intended test network.
2. On SeedSigner, create a fresh seed using the camera or dice workflow.
3. Use only that seed for this test. Never import a production mnemonic.
4. Export the account xpub/descriptor needed by the selected singlesig or
   multisig setup.
5. After testing, return the device to its seedless state and remove the card
   if that is your normal storage practice.

SeedSigner does not tell Testnet3 and Testnet4 apart at the QR signing boundary.
Sparrow's selected network, server, faucet, and UTXOs must agree.
