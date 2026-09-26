# Airgap Anti-Exfil novice testing quickstart

This guide is for an individual tester with a SeedSigner or supported Kern
device who wants to try protected signing over animated QR. It deliberately
uses a separate Sparrow build, a separate Sparrow home folder, disposable
device-generated seeds, and Bitcoin test networks.

No real bitcoin is needed. Testnet coins have no monetary value. Never enter a
production seed, reuse a test seed for real funds, or point the review build at
your normal Sparrow home folder.

## What you will test

Ordinary air-gapped signing is one QR round: Sparrow shows a transaction and
the signer returns a signature. Protected signing adds a challenge/response
exchange so Sparrow contributes fresh randomness and verifies that the final
signature is bound to the same ceremony.

There is no project performance claim for the extra exchange. Its duration
depends on how closely a person examines each screen, familiarity, camera and
display behavior, distance, lighting, and retries. The community question is
whether people experience the additional round as objectionable friction, a
reasonable tradeoff for stronger signing assurance, reassuring in its own
right, or something else. Timing is useful context, but perception and reasons
matter just as much.

## What you need

- A computer able to build the reviewed Sparrow fork with JDK 25.
- One of:
  - a Raspberry Pi Zero SeedSigner setup and a dedicated microSD card; or
  - a supported Kern board: `wave_4b`, `wave_35`, `wave_5`, `wave_43`,
    `crowpanel`, or `wave_7b`.
- A computer camera usable by Sparrow.
- Device entropy input: the device-supported camera or dice workflow.
- Internet access for initial clones, dependencies, an Electrum server, and a
  faucet. The signer itself remains air-gapped during signing.
- Time for builds. SeedSignerOS needs a Linux Docker host and at least 20 GB
  free. Kern needs Espressif ESP-IDF 6.0.2.

If you are using an AI assistant, give it this guide and the linked exact-source
instructions. Ask it to stop on any commit mismatch, unexpected Mainnet label,
or command that would reuse your ordinary Sparrow data.

A useful starting prompt is:

> Help me follow the Airgap Anti-Exfil novice testing quickstart one verified
> step at a time. Use only the exact commits in the guide, a new dedicated
> Sparrow `--dir`, and Testnet4 unless I explicitly choose Testnet3. Never use
> my normal Sparrow profile, Mainnet, real funds, or an existing seed. Before
> writing an SD card or flashing a device, show me the exact image/build, board,
> port, and target and wait for my confirmation. Stop on any identity, network,
> or device ambiguity. Help me produce a sanitized feedback report at the end.

An AI assistant can reduce setup friction, but it cannot see a physical label,
verify a removable-drive target, or decide whether a seed is truly disposable
unless you provide and check that information.

## 1. Pick exactly one Bitcoin test network

Prefer **Testnet4** for new testing. Testnet3 is retained because the project
also exercised it and some infrastructure still supports it.

The signer-side QR data uses Bitcoin test-key/address conventions and does not
identify Testnet3 versus Testnet4. Sparrow and its server selection do make
that distinction. The Sparrow network you launch, the wallet receiving
address, the faucet, the block explorer, and the coins must all be on the same
network.

Tested starting points as of 2026-09-26:

- Testnet4: [mempool.space Testnet4 faucet](https://mempool.space/testnet4/faucet)
- Testnet3: [CoinFaucet Testnet3](https://coinfaucet.eu/en/btc-testnet/)

These are independent third-party services, not project dependencies or
endorsements. Availability, login, rate limits, privacy practices, and balances
can change. CoinFaucet states that it stores the requesting IP address for
abuse prevention. Never pay for test coins and never paste a seed or private
key into a faucet.

## 2. Prepare a signer

Follow one path:

- [Build and write the reviewed SeedSigner test image](docs/seedsigner-test-image.md)
- [Build and flash the reviewed Kern test firmware](docs/kern-test-firmware.md)

Create a fresh disposable seed on the device using its camera or dice workflow.
Do not photograph, transcribe into a cloud service, or retain that seed after
testing. Export only the account information the selected wallet setup needs.

## 3. Build and isolate Sparrow

Follow [the isolated Sparrow guide](docs/sparrow-isolated-test-profile.md).
The critical invariant is that every launch includes both:

```text
--dir <new-dedicated-folder> --network <testnet4-or-testnet>
```

Confirm that first-run onboarding appears and that no ordinary wallets are
visible. Stop if the review build opens an existing profile.

## 4. Choose a test path

- **Singlesig:** quickest first experience; one disposable device seed and one
  protected signer.
- **Multisig:** create separate disposable cosigner seeds and record which
  signatures are protected. A 2-of-2 or 2-of-3 test is sufficient; do not reuse
  a real cosigner or coordinator profile.

Follow the complete
[singlesig and multisig ceremonies](docs/end-to-end-testnet-testing.md).

## 5. Report the experience

Please report success as carefully as failure. A useful report distinguishes:

- installation/build time from signing-ceremony time;
- total signing time from the added challenge/response time;
- automatic scans from retries, timeouts, or manual repositioning;
- signer model/board and Sparrow camera/display details;
- singlesig from multisig and Testnet3 from Testnet4; and
- a genuine protected completion from an ordinary-signing fallback.

Copy the [user-test feedback template](docs/user-test-feedback-template.md).
Remove seeds, private keys, wallet files, descriptors you do not intend to
publish, IP addresses, usernames, and machine-specific secrets before posting.
Use [SECURITY.md](SECURITY.md) for anything potentially exploitable.

## Stop conditions

Stop without signing or broadcasting if:

- Sparrow says Mainnet or the intended network is uncertain;
- the Sparrow home folder is your ordinary profile;
- any source commit differs from the documented reviewed identity;
- a real seed, real wallet, or real funds appear anywhere;
- protected signing silently becomes ordinary signing;
- the returned signature is accepted despite a protected-signing rejection;
- the device, wallet, or camera behaves differently enough that you cannot
  tell which step you are completing.

An incomplete run is still useful feedback. Record the last unambiguous step
and what prevented progress.
