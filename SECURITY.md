# Security policy

## Supported targets

Only the immutable revisions in [REVIEW-SCOPE.md](REVIEW-SCOPE.md) constitute
the frozen reviewed prototype. A report may affect this review hub, one linked
implementation, or a cross-repository interaction. Identify every affected
repository and exact commit. Later development heads may be incomplete and
must not be assumed equivalent to the frozen revisions.

## Report privately

**Do not open a public issue containing an unfixed vulnerability or proof of
concept.** Use GitHub's private vulnerability-reporting form:

[Report a vulnerability privately](https://github.com/FractalEncrypt/seedsigner-anti-exfil-review/security/advisories/new)

The private report is visible only to repository maintainers and invited
security collaborators. Use a normal public issue only for documentation,
build, test, or usability problems that do not disclose an exploitable defect.

## What to include

A useful report contains:

- the affected repository or repositories and exact commit hashes;
- the violated protocol rule or security invariant;
- prerequisites, attacker capabilities, and impact;
- minimal reproduction steps or a deterministic test fixture;
- an executable regression test or proof of concept when safe;
- whether the issue affects REQUIRED, OPTIONAL, or unsupported signing; and
- any proposed remediation and compatibility consequences.

If the report revisits a historical item from
[the findings ledger](docs/security-review-findings.md), explain why the final
immutable revision remains vulnerable despite the recorded remediation.

## Safe testing and disclosure

Do not use real funds, production wallet material, or third-party systems when
testing a report. The published deterministic fixtures are the intended test
inputs.

Do not include real mnemonics, private keys, wallet databases, API credentials,
or other secrets. Published fixture keys and mnemonics must be clearly labeled
as public test material.
