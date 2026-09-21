# SeedSigner Anti-Exfil Review Hub

This repository is the cross-project review hub for an experimental,
testnet/public-test-only ECDSA anti-exfil prototype spanning SeedSigner,
SeedSignerOS, Kern, Drongo, and Sparrow Wallet.

The v2 candidate adds the closed Kern M8 campaign result, integrates the August
hardening and M8 coordinator histories into new Drongo/Sparrow candidates, adds
Kern as a second signer, and gives independent reviewers clean build and test
instructions. It remains a prototype—not a production security audit, mainnet
recommendation, upstream release, or assertion that complete firmware/images
are bit-for-bit reproducible across uncontrolled hosts.

## Current status

- M8 is closed for its frozen execution identities. Its completion rule passed
  and `F-IDENTITY-BRIDGE-01` was resolved.
- The v2 Drongo, Sparrow, and Kern candidates are new local identities. They do
  not inherit M8 physical-execution credit automatically.
- SeedSigner and SeedSignerOS remain at their previously accepted public tags.
- This branch and its deterministic v2 archive are local P4 candidates pending
  independent P5 review. Nothing is published or pushed by P4.

## Start here

1. [Review scope and exact inputs](REVIEW-SCOPE.md)
2. [Repository bindings](repositories.json)
3. [M8 closure summary](docs/m8-campaign-closure-summary.md)
4. [M9 integration candidate](docs/m9-integration-candidate.md)
5. [Reviewer build and test runbook](docs/reviewer-build-and-test-runbook.md)
6. [Interoperability and reproduction checklist](docs/interoperability-reproduction-checklist.md)
7. [Publication boundary](docs/p4-publication-boundary.md)

The normative protocol reading order remains:

1. [Maintainer specification](docs/maintainer-specification.md)
2. [Cryptographic construction](docs/protocol-v1.md)
3. [Wire format and state rules](docs/protocol-v1-wire-format.md)
4. [AEXT transport](docs/transport-aext.md)
5. [Threat model](docs/threat-model.md)

## Reference tests

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests/reference -t . -v
```

All private keys, mnemonics, PSBTs, and transactions committed here are
explicitly public deterministic fixtures. Never fund or reuse fixture keys.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.
