# Community test feedback template

Copy this template into a GitHub issue or discussion. Positive results are
valuable when they include enough detail to distinguish a smooth protected
ceremony from ordinary-signing fallback. Failures, confusion, and incomplete
runs are equally useful.

For a potentially exploitable failure, do not open a public issue; follow
[SECURITY.md](../SECURITY.md).

Remove seeds, private keys, xpubs, receiving/change addresses, wallet files,
private descriptors, coordinator state, IP addresses, usernames, and unrelated
log contents before posting.

```markdown
## Outcome

- Result: SUCCESS / FAILURE / INCOMPLETE
- Test date and timezone:
- Singlesig or multisig:
- Quorum if multisig:
- Test network: Testnet4 / Testnet3
- Broadcast performed: yes / no
- Protected signature visibly verified by Sparrow: yes / no / uncertain
- Ordinary-signing fallback observed: no / yes / uncertain

## Exact software identities

- Review-hub commit/tag:
- Sparrow commit:
- Sparrow Drongo submodule commit:
- SeedSigner commit and SeedSignerOS commit, or Kern commit:
- Kern board and submodule identities if applicable:
- Build commands changed from the guide: no / yes (explain)

## Host and hardware

- Computer OS and version:
- CPU architecture:
- Java version:
- Docker version, if SeedSignerOS was built:
- ESP-IDF version, if Kern was built:
- Signer model/board and display:
- Computer display resolution and scaling:
- Camera model/backend and resolution:
- Approximate display-to-camera distance:
- Ambient lighting/glare notes:

## Isolation and safety checks

- New dedicated Sparrow `--dir` used:
- First-run onboarding appeared:
- Existing Sparrow wallets absent:
- Sparrow network label checked before funding and signing:
- Seeds created on device with camera or dice:
- Only disposable seeds and testnet coins used:
- Signer returned to Seedless/Unloaded after test:

## Wallet and transaction

- Signer: SeedSigner / Kern
- Script type: P2WPKH / P2WSH / other
- Derivation shown by wallet:
- Protected policy: Optional / Required
- Multisig cosigner types and protected policy per cosigner:
- Faucet used: mempool.space Testnet4 / CoinFaucet Testnet3 / other
- Transaction shape: self-spend / other
- Number of inputs and outputs:

## Timing and QR experience

- Installation/build time (not part of ceremony):
- Wallet setup/funding time (not part of ceremony):
- Ordinary signing baseline, if measured:
- Total protected signing ceremony time:
- Estimated added challenge/response time:
- QR rounds completed:
- Automatic scans on first presentation:
- Rescans/retries:
- Timeouts or zero-progress scans:
- Manual distance, brightness, angle, or focus changes:
- Most confusing screen or instruction:
- Before testing, what did you expect the extra exchange to feel like?
- After testing, did it feel objectionable, acceptable, reassuring, or
  something else? Why?
- Did familiarity change your perception on a repeat attempt?
- Did the security benefit feel concrete during the interaction, or abstract?

## Result details

- Last unambiguous successful step:
- Expected result:
- Actual result:
- Exact visible error text, if any:
- Reproducible on a second attempt:
- Sanitized log/screenshot links:
- Anything an AI assistant misunderstood or had to infer:

## Suggested improvement

- Documentation change:
- UI wording/change:
- Camera/QR behavior change:
- Build or packaging change:
- Other:
```

Do not turn one person's reaction into a universal claim. “The extra exchange
felt acceptable because each screen explained why it was needed; this setup
completed with no retries” is more useful than “QR anti-exfil is easy.”
Likewise, “the second round felt burdensome after two glare-related timeouts on
this camera” is more useful than “QR anti-exfil does not work.” Raw timings can
help interpret both reports, but they do not define the UX by themselves.
