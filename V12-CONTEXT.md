# Independent review context: anti-exfil v1 final Gate 5 inputs

## Exact immutable inputs

- Drongo: `bb691c7d77290933b3f7d6c411556c1524a29d98`, tag
  `anti-exfil-review-v1-gate5-tested-2026-08-22`
- Sparrow: `f003bfa9575bc7c67b337f8785b1479fd092641a`, tag
  `anti-exfil-review-v1-gate5-tested-2026-08-22`
- Sparrow Drongo pin: `bb691c7d77290933b3f7d6c411556c1524a29d98`
- SeedSigner: `aa8395e3576379467d795bb05268533e3a2ac082`
- SeedSignerOS: `0bf1dc92519906c7db265055abfb07e0ee344342`

The repository is a cross-project review hub containing the reference oracle,
normative documents, shared vectors, tests, physical evidence, and completed
review ledger. Implementation code remains in the four linked forks.

## Claimed security behavior

An accepted protected ECDSA signature must be bound to the canonical original
PSBT context, input/outpoint, signer pubkey, BIP143 message hash, sighash, exact
compact signature, wallet identity, and a fully revalidated ceremony session.
One signer's ceremony must never authorize another signer's ordinary signature.
Malformed, substituted, replayed, downgraded, incomplete, stale, or
policy-incompatible ceremonies must fail closed.

## Requested review output

For every proposed finding, provide:

1. exact affected code paths and immutable revision;
2. a reachable failure sequence within the documented threat model;
3. a safe regression or counterexample that fails for the claimed reason;
4. impact and justified severity;
5. remediation that compiles and preserves legitimate protected signing; and
6. validation that the original invariant violation is closed.

Distinguish implementation defects from documented residual risks and
maintainer compatibility decisions. Do not treat public deterministic fixture
keys as secrets.

## Previously reviewed remediation

The ledger records P6-F1 and R-F1 plus V12 findings `#247985`–`#248002`.
Gates 1–5 added per-key opening uniqueness, a wallet-wide abort state machine,
durable-state bounds and locking, complete-transcript/API enforcement, invalid
foreign-signature rejection, and explicit storage/rollback/witness-UTXO trust
contracts. Re-report one of these as open only with a concrete bypass at the
immutable heads above.

The project remains an experimental prototype. The completed reviews do not
replace independent cryptographic review, upstream review, reproducible-release
review, or a production/mainnet security audit.
