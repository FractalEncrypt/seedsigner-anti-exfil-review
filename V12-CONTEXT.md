# Independent review context: anti-exfil v1 finalized-input replacement inputs

## Exact immutable inputs

- Drongo: `e9a692a4ac4eb14901101cd9324e2275a29897cf`, tag
  `anti-exfil-review-v1-finalized-input-tested-2026-08-22`
- Sparrow: `5b74d94637516aab6d1c79a2e3a3c13c1347b3ea`, tag
  `anti-exfil-review-v1-finalized-input-tested-2026-08-22`
- Sparrow Drongo pin: `e9a692a4ac4eb14901101cd9324e2275a29897cf`
- SeedSigner: `214793df4f51466179b792420921b8cdd8d0c1ac`, tag
  `anti-exfil-review-v1-finalized-input-tested-2026-08-22`
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

Phases 16–17 additionally close F-R1: signer-attributable finalized inputs are
rejected at every protocol admission boundary, and Sparrow re-evaluates
provenance after finalization and immediately before every final-transaction
view, QR, save, or broadcast action. Re-report it as open only with a concrete
bypass at the replacement heads.

The project remains an experimental prototype. The completed reviews do not
replace independent cryptographic review, upstream review, reproducible-release
review, or a production/mainnet security audit.
