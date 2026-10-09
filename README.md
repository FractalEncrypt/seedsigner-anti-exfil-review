# Airgap Anti-Exfil

> Experimental anti-exfil Bitcoin signing over animated QR for DIY air-gapped
> signers. Formerly the SeedSigner Anti-Exfil Review Hub.

This repository is the cross-project review hub for an experimental ECDSA anti-exfil signing protocol spanning SeedSigner, SeedSignerOS, Kern, Drongo, and Sparrow Wallet.

It gives outside reviewers one place to find:

- the protocol, wire format, transport, and threat model;
- exact implementation commits, trees, dependencies, and upstream bases;
- a Python reference oracle, shared public vectors, and adversarial tests;
- reproducible build and test instructions for every implementation;
- the completed internal campaign, findings, remediation, and limitations; and
- interoperability checks that reviewers can repeat on their own systems.

The implementation code remains in the linked project forks. This hub binds those repositories and supplies common review material; it is not a monorepo.

## Read this before running

Most of this project's new anti-exfil code and documentation were written with OpenAI GPT-5.6 and GPT-6.1 under my direction. I tested the workflows extensively on physical devices, but I cannot personally audit all of the source code or cryptography.

Adversarial AI review of the work included V12, DeepSeek v4.1 Flash, GLM 5.3 (High and Flash Max), and Kimi K3 High. Those reviews and the device tests can miss subtle mistakes. **They are not an independent human security audit.** This disclosure describes our anti-exfil additions, not the authorship of the upstream projects.

I am sharing this experimental work for testing and independent review. Use disposable test seeds and testnet coins. Successful device tests are not a guarantee of security.

If you can review the code, challenge the assumptions and report what you find by [creating an issue in the repo](https://github.com/FractalEncrypt/seedsigner-anti-exfil-review/issues).


## On-Device Testing

**Ready-to-test** binaries are available for Windows 10/11 (x64) users with at least one supported device:

- **SeedSigner:** Pi Zero revision 1.3.
- **Kern:** Wave7B, ESP32-P4 revision v1.3.

The current Windows download is **AexTest-20261009.zip**, with a matching checksum file; **AexSource-20261009.zip** is the separate source/reviewer delivery.

Follow the [Download and test](https://github.com/FractalEncrypt/seedsigner-anti-exfil-review/blob/main/docs/download-and-test.md) guide to test the new anti-exfil signing functionality and even defend against a simulated Dark Skippy attack.

**Other supported boards, or Linux:** use [Build from source on Windows](docs/build-from-source-windows.md) or [Build from source on Linux](docs/build-from-source-linux.md). Those guides pin the same Sparrow source and include target choices for the boards available in the pinned firmware repositories. Other boards need their own device testing; the included Windows images are for the two configurations above. macOS download support is planned for a later package.

**Technical review:** begin with [current tester identities and coverage](docs/current-tester-release-status-2026-10-09.md) for the current kit, or [review scope](REVIEW-SCOPE.md) for the historical frozen baseline. The frozen archive retains its [Sparrow erratum](docs/frozen-sparrow-erratum-2026-10-06.md). Specifications, source bindings, and campaign records follow below.

**Feedback:** the kit includes [offline](FEEDBACK-OFFLINE.html), [live](FEEDBACK-LIVE.html), and [full](FEEDBACK.html) HTML forms. Record what you tried, click **Save feedback HTML**, and reopen the downloaded copy to continue editing. Each result has a Steps link. Photos, confusing steps, and successful live transactions are welcome; include the TXID and network if you want to share a live result.

## Why anti-exfil?

A malicious or compromised hardware signer can produce mathematically valid ECDSA signatures while manipulating the normally random signing nonce. In principle, those nonce choices can become a covert channel that leaks private key material a few bits at a time. The transaction still verifies, so ordinary signature validation alone does not reveal the leak.

Anti-exfil signing makes the wallet and signer jointly influence the nonce. In this prototype, the signer first commits to its contribution, the host then reveals fresh randomness, and the host verifies that the returned signature is cryptographically bound to that transcript. A signer that tries to choose a different leakage-friendly nonce should be detected and the signing flow should fail closed.

This is defense in depth, not a universal cure. It does not make compromised host software trustworthy, prevent physical key extraction, prove firmware authenticity, or protect signing paths that do not complete the protocol. The details—and the boundaries—are why outside review matters.

## Historical frozen review status

- The bounded M8 campaign is closed for its frozen public-test execution
  identities. Its completion rule passed and `F-IDENTITY-BRIDGE-01` was
  resolved.
- The M9 hardening track is closed for the bounded experimental,
  Testnet/public-test-only, off-by-default scope after an accepted fresh H31
  independent review. The exact dispositions, residuals, findings, and
  post-publication Kern identities are in the
  [M9 hardening closure](docs/m9-hardening-closure.md).
- The integrated v2 Drongo, Sparrow, SeedSigner, SeedSignerOS, and Kern source
  identities are pinned in [REVIEW-SCOPE.md](REVIEW-SCOPE.md) and
  [repositories.json](repositories.json).
- Kern's accepted post-M9 CI/formatting line now ends at `6894087…`. Its six
  linear commits preserve the v2 anti-exfil base while qualifying sanitizer
  lanes, pinning formatting, applying the mechanical rewrite, repairing the
  firmware dependency boundary, and resolving two Wave 7B boot warnings. The
  exact evidence and retained limitations are in the
  [accepted update record](docs/post-m9-kern-ci-formatting-accepted-update.md).
- The deterministic review archive is assembled from exact committed Git blobs
  and has reproduced byte-for-byte across CRLF and LF checkout policies.
- The campaign artifacts and publication candidate received structured local
  review plus fresh-context model-based review with Devin/DeepSeek. Those checks
  are documented evidence, not a substitute for independent human or community
  security review.
- We are now explicitly seeking outside reviewers before deciding whether to
  prepare maintainer-facing upstream pull requests.

This remains an **experimental, testnet/public-test-only, off-by-default prototype**. It is not a production security audit or a recommendation to use protected signing with mainnet funds.

### Model-review provenance

Different review rounds used Kimi K3 High, DeepSeek v4.1 Flash, and GLM 5.3 (High and Flash Max) through Devin/Windsurf at different times. Drongo also received review from the V12 reviewer AI model. The final P5 and P5.1 publication-candidate gates used DeepSeek 4.1 Flash in fresh Devin conversations. These were model-based reviews: their transcripts, findings, and accepted dispositions are useful evidence and review leads, but they are not independent human audits. That is why this release is now asking outside reviewers to reproduce and challenge the work.

## How you can review this work

You do not need to review everything. Useful contributions include:

1. **Reproduce builds and tests.** Follow the
   [reviewer runbook](docs/reviewer-build-and-test-runbook.md), record your OS,
   tool versions, exact Git identities, results, output sizes, and hashes, and
   report any undocumented dependency or host assumption.
2. **Review the design.** Challenge the
   [protocol](docs/protocol-v1.md),
   [wire format and state rules](docs/protocol-v1-wire-format.md), and
   [threat model](docs/threat-model.md). Look especially for replay,
   substitution, downgrade, persistence, abort, and mixed-provenance failures.
3. **Inspect implementation diffs.** Compare each pinned fork with its recorded
   upstream base. Check that ordinary signing remains isolated, protected paths
   fail closed, and coordinator state cannot be silently reused or crossed.
4. **Test interoperability.** Use the public fixtures and
   [interoperability checklist](docs/interoperability-reproduction-checklist.md)
   to compare SeedSigner and Kern with Sparrow/Drongo. Hardware work is welcome
   but optional; never use production seeds or funded wallets.
5. **Report what you find.** Reproduction reports, UX observations, design
   criticism, and failed assumptions are valuable. For exploitable findings,
   follow [SECURITY.md](SECURITY.md) rather than posting details publicly first.

## Technical review reading order

For a technical review:

1. [Review scope and immutable revisions](REVIEW-SCOPE.md)
2. [Repository bindings](repositories.json)
3. [Reviewer build and test runbook](docs/reviewer-build-and-test-runbook.md)
4. [Interoperability and reproduction checklist](docs/interoperability-reproduction-checklist.md)
5. [M8 closure summary and retained limitations](docs/m8-campaign-closure-summary.md)
6. [M9 bounded hardening closure](docs/m9-hardening-closure.md)
7. [M9 integration summary](docs/m9-integration-candidate.md)
8. [Security-review findings](docs/security-review-findings.md)
9. [Maintainer decisions and open questions](docs/maintainer-decisions-requested.md)
10. [Review rounds and remediation history](docs/review-rounds-summary.md)
11. [Review snapshot and branch guide](docs/review-versions.md)

The normative reading order is:

1. [Maintainer specification](docs/maintainer-specification.md)
2. [Cryptographic construction](docs/protocol-v1.md)
3. [Wire format and state rules](docs/protocol-v1-wire-format.md)
4. [AEXT transport](docs/transport-aext.md)
5. [Threat model](docs/threat-model.md)

## Historical frozen implementation inputs

| Component | Reviewed commit | Role |
| --- | --- | --- |
| Drongo | `948f586f0e523e0ef67d973a72eac67aa8148968` | Protocol, PSBT, signature verification, and durable coordinator primitives |
| Sparrow | `cc760814c855dfaf3d27890d10ba86b635e3a033` | Wallet UI, policy, protected workflow, persistence, and export quarantine |
| SeedSigner | `214793df4f51466179b792420921b8cdd8d0c1ac` | Air-gapped signer implementation and QR workflow |
| SeedSignerOS | `0bf1dc92519906c7db265055abfb07e0ee344342` | Opt-in review/test image integration |
| Kern | `6894087db687e7febf7ccafe4429d8a0446a3ba5` | Second air-gapped signer implementation; accepted post-M9 CI/formatting and Wave 7B remediation line |

Commits and trees—not moving branch names—are authoritative. See [repositories.json](repositories.json) for trees, bases, submodules, and evidence bindings.

## Run the reference tests

Python 3.11 or newer is recommended.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests/reference -t . -v
```

Some cross-implementation tests require the separately cloned implementation repositories described in the runbook.

## Repository layout

```text
docs/              Specifications, review history, findings, and instructions
fixtures/          Frozen public protocol, PSBT, and transport vectors
scripts/           Vector, deterministic-bundle, verification, and scan tools
src/anti_exfil/    Python reference oracle and coordinator model
tests/reference/   Reference, cross-implementation, and adversarial tests
repositories.json  Machine-readable repository and revision bindings
```

All private keys, mnemonics, PSBTs, and transactions committed here are explicitly public deterministic test fixtures. Never fund fixture addresses or reuse fixture keys.

## Important limitations

The bundle preserves the complete limitation record. In particular, it does not claim threshold completion for the bounded M8 P04/P05 cells, physical C3 for D/P01, an all-campaign absence of funding/finalization/broadcast, automatic physical-test credit for the newer integrated trees, or bit-for-bit firmware image reproducibility across uncontrolled hosts. Start with the [M8 closure summary](docs/m8-campaign-closure-summary.md) for the six retained residuals and historical disclosure.

The later M9 hardening closure adds further bounded results and explicit residuals; it does not erase or supersede the M8 limitations. Review [its complete closure record](docs/m9-hardening-closure.md), especially the identity separation and informational-observation register.

No Jade implementation is included or evaluated here. Jade work is relevant cross-implementation context tracked in [Issue #1](https://github.com/FractalEncrypt/seedsigner-anti-exfil-review/issues/1).

## Acknowledgements

Thank you to BitcoinShooter and to the anonymous reviewer “Joe” for review input on the earlier v1 bundle. Their feedback is part of the project’s review history and helped inform the continuing work. This acknowledgement does not claim that either reviewer has reviewed or endorsed the v2 candidate.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not publish exploitable details in a normal issue before a private reporting channel has been established.

## Licensing

The reference implementation and review-hub material are distributed under the Apache License 2.0 in [LICENSE](LICENSE). Each linked implementation fork keeps the license of its upstream project.
