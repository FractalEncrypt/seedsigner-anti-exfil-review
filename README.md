# SeedSigner Anti-Exfil Review Hub

This repository is the cross-repository review hub for an experimental,
interactive ECDSA anti-exfil signing protocol implemented across SeedSigner,
SeedSignerOS, Drongo, and Sparrow Wallet.

It gives reviewers one concise source for:

- the protocol and threat model;
- immutable implementation revisions and upstream comparison bases;
- the Python reference oracle, shared vectors, and adversarial tests;
- build and test instructions for each implementation repository;
- the completed review and remediation ledger; and
- selected physical interoperability evidence.

The implementation code remains in the four linked repositories. This hub does
not duplicate their source trees and is not a monorepo.

## Status

The reviewed prototype inputs were frozen on 2026-08-20. Automated suites,
public Linux CI, deterministic vectors, Pi Zero image gates, and unfunded or
Testnet4 physical workflows have been exercised. Signature-scoped provenance
and raw-transaction lifecycle remediations received focused diff review.

This is a reviewed experimental prototype, not a production security audit or
a recommendation to use protected signing with mainnet funds.

## Start here

1. [Review scope and immutable revisions](REVIEW-SCOPE.md)
2. [Maintainer review index](docs/maintainer-review-index.md)
3. [Independent security-review brief](docs/independent-security-review-brief.md)
4. [Reviewer build and test runbook](docs/reviewer-build-and-test-runbook.md)
5. [Security-review findings](docs/security-review-findings.md)
6. [Maintainer decisions](docs/maintainer-decisions-requested.md)
7. [Frozen bundle record](FROZEN-BUNDLE.md)

The normative reading order is:

1. [Maintainer specification](docs/maintainer-specification.md)
2. [Cryptographic construction](docs/protocol-v1.md)
3. [Wire format and state rules](docs/protocol-v1-wire-format.md)
4. [AEXT transport](docs/transport-aext.md)
5. [Threat model](docs/threat-model.md)

## Repository layout

```text
docs/              Normative documents, review ledger, checkpoints, evidence
fixtures/          Frozen shared protocol and transport vectors
scripts/           Vector generators and deterministic bundle builder
src/anti_exfil/    Python reference oracle and coordinator model
tests/reference/   Reference, cross-implementation, and adversarial tests
repositories.json  Machine-readable repository and revision bindings
V12-CONTEXT.md     Concise context for repository-scanning tools
```

All mnemonics, private keys, PSBTs, and transactions committed here are
explicitly public deterministic test fixtures. Never send funds to fixture
addresses or reuse fixture keys.

## Run the reference tests

Python 3.11 or newer is recommended.

```bash
python -m venv .venv
python -m pip install -e .
python -m unittest discover -s tests/reference -t . -v
```

Cross-implementation SeedSigner adapter tests require the separately cloned,
tagged SeedSigner source described in the reviewer runbook.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not publish exploitable details in a
normal issue before a private reporting channel has been established.

## Licensing

The reference implementation and review-hub material are distributed under the
Apache License 2.0 in [LICENSE](LICENSE). Each linked implementation fork keeps
the license of its upstream project.
