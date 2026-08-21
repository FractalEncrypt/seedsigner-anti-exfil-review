# R-F1 final review request

Date: 2026-08-20

This is the final narrow Sparrow review requested before immutable retagging and
reviewer-bundle freeze. Drongo remains pinned at
`1bbafd94f08fd9105e20be30a6fdfe9a091fb675`; this review changes Sparrow only.

## Review range

- Base: `90c64c9d` (`Restore finalized anti-exfil provenance`)
- Head: `7674cecde48335e0b55454f6fa53c8187a459932`
- Command: `git diff 90c64c9..7674cec`

Commits in order:

1. `2fc2bc2` - Preserve raw transaction policy and internal sweeps
2. `623ae5b` - Initialize internal sweep broadcast controls
3. `2b36ba4` - Keep fetched raw imports quarantined
4. `87d4232` - Show raw transaction quarantine immediately
5. `4d56a16` - Keep final-view disabled for raw transactions
6. `7674cec` - Refresh raw policy when wallets become attributable

The aggregate range changes six files: 297 insertions and 42 deletions.

## Requested security checks

1. Confirm an externally parsed signed raw transaction receives no authority
   from `BlockTransaction` reference/display metadata.
2. Confirm no fully attributing open wallet means visible fail-closed quarantine
   at initial import, after reference fetching, and after source-wallet closure.
3. Confirm a fully attributing open wallet with no participating `Required`
   policy may permit Broadcast, while a fully attributing `Required` wallet
   takes precedence over permitting Optional/Unsupported alternatives.
4. Confirm raw policy is re-evaluated on wallet open, wallet history completion,
   wallet history change, and wallet close, including the case where attribution
   becomes available only after synchronization.
5. Confirm `INTERNAL_SWEEP` is set only at `PrivateKeySweepDialog`'s direct
   creation route, remains in-memory and digest-bound, carries only the already
   computed nonnegative fee, and is not serialized, parsed, or forwarded.
6. Confirm mutation invalidates the internal origin and fee, while a saved,
   reopened, or cross-window raw transaction defaults to `EXTERNAL`.
7. Confirm raw transactions never enable the PSBT-only View Final action, and
   Broadcast still performs a fresh provenance check at invocation.
8. Confirm the changes do not weaken the previously reviewed per-signature PSBT
   provenance gates or the `isBroadcast()` ceremony invariant.

Please report whether this range is ready for immutable tags, and record any
missing route, fail-open transition, policy-precedence issue, or regression.

## Validation ledger

- Focused Sparrow anti-exfil suite: 20 passed, 0 failed, 0 skipped.
- Full Windows Sparrow suite: 151/155 passed. The same four unchanged CRLF/LF
  golden-export comparisons failed: Caravan 1, Coldcard 2, Specter DIY 1.
- Linux CI-only merge: `2c5d768efd86d2fca624ea35ecbe23635ab7be41`.
- Public Linux CI: <https://github.com/FractalEncrypt/sparrow/actions/runs/32305165978>
  - Result: passed.
- `clean jpackageImage`: passed.
- Packaged executable SHA-256:
  `66892bc6067c4efe111f20f24abc4651724dc04d70ecbcc162a3a43703294160`
- Application JAR SHA-256:
  `e012ab79c5c21f2c2fd63f0ff710850e22bfc3546657f03edcb906ab28964d8e`

## Physical lifecycle gate

The final Testnet4 gate passed on Sparrow head `7674cec` without broadcasting:

1. Source wallet closed: visible `POLICY_CONTEXT_UNAVAILABLE`; Broadcast and
   View Final disabled.
2. Attributable SeedSigner source wallet opened and synchronized: warning
   cleared; Broadcast enabled; View Final remained disabled.
3. Source wallet closed: the same visible quarantine returned automatically.

Evidence:

- `docs/assets/r-f1-smoke/gate-b-source-wallet-closed.png`
  - SHA-256: `8686f76e9d87abd6ea92aaf0ca6df6df2810aa3f0351517d4228baad49a00146`
- `docs/assets/r-f1-smoke/gate-b-source-wallet-open.png`
  - SHA-256: `8b469d1a5e60dbfc38787e4551cb62ccad4436e31e2efadcba6642415201a8cb`
- `docs/assets/r-f1-smoke/gate-b-signed-sweep.txn`
  - SHA-256: `fc08587773f5e1840616199a53092bf5e9181faf45a4058a19733f2ed460e473`

The full physical history and intermediate corrections are recorded in
`docs/r-f1-internal-sweep-smoke.md`.
