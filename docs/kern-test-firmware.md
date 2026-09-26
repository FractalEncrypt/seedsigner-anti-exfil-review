# Prepare Kern test firmware

This path builds and flashes the reviewed Kern source with Espressif ESP-IDF
6.0.2. Supported build names in the reviewed tree are `wave_4b`, `wave_35`,
`wave_5`, `wave_43`, `crowpanel`, and `wave_7b`. Select the value matching the
physical board; do not guess.

Flashing overwrites the selected device firmware. Disconnect other serial
devices where practical and identify the exact port before proceeding.

## Exact reviewed source

```sh
git clone --recursive https://github.com/FractalEncrypt/Kern.git kern-airgap-anti-exfil
git -C kern-airgap-anti-exfil checkout --detach bc382c2c458e81230b5c0c434cd5b2219eef76b6
git -C kern-airgap-anti-exfil submodule update --init --recursive
git -C kern-airgap-anti-exfil rev-parse HEAD^{commit}
git -C kern-airgap-anti-exfil rev-parse HEAD^{tree}
git -C kern-airgap-anti-exfil submodule status --recursive
```

Expected commit and tree:

```text
bc382c2c458e81230b5c0c434cd5b2219eef76b6
196a182647ded7825d0f3e524d72a611add70950
```

Expected submodules are recorded in [REVIEW-SCOPE.md](../REVIEW-SCOPE.md) and
`repositories.json`. Stop on any mismatch.

## Build one board

Install and activate Espressif ESP-IDF 6.0.2 using Espressif's instructions.
Network access may be required to install the toolchain and populate managed
components. In the activated ESP-IDF shell:

```sh
cd kern-airgap-anti-exfil
. "$IDF_PATH/export.sh"
idf.py --version

board=wave_7b  # replace with the exact physical board name
idf.py -B "build_${board}" \
  -D "SDKCONFIG=build_${board}/sdkconfig" \
  -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.${board}" \
  build all size-components size 2>&1 | tee "build_${board}.log"
```

On Windows, run the equivalent commands inside the ESP-IDF PowerShell or
Command Prompt environment and set `$board`/`%board%` using normal shell syntax.

Each clean clone may create a development signing key, so firmware hashes can
differ between controlled source-identical builds. Never publish a private
signing key. Record the source commit, submodules, ESP-IDF version, board,
configuration, flash manifest, binary sizes, SHA-256 values, and the supported
public-key fingerprint.

## Identify the port and flash

List serial ports before and after connecting Kern and identify the newly
appearing port. Examples are `/dev/ttyACM0`, `/dev/ttyUSB0`, or `COM5`; these
are examples only.

```sh
idf.py -B "build_${board}" -p /dev/ttyACM0 flash
idf.py -B "build_${board}" -p /dev/ttyACM0 monitor
```

Replace the port with the observed device port. Record the boot log and visible
version. Exit the monitor using the ESP-IDF monitor shortcut shown on screen.

## Prepare disposable signing material

1. Confirm Sparrow is already on the intended test network.
2. On Kern, create a fresh disposable seed using a supported camera or dice
   workflow.
3. Never import a production mnemonic or use a funded wallet.
4. Export only the account xpub/descriptor needed by the selected singlesig or
   multisig test.
5. After testing, return Kern to Seedless/Unloaded and remove any microSD card.

Kern does not disambiguate Testnet3 from Testnet4 at the QR signing boundary.
Sparrow's selected network, server, faucet, and UTXOs must agree.

If flashing, boot, camera, or display behavior differs from this guide, stop
and report the board, port, operating system, ESP-IDF version, exact command,
and last successful step. That is useful cross-board evidence.
