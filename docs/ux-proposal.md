# Protected signing UX proposal

Status: maintainer review proposal based on implemented physical prototype

## 1. Product principles

1. **Policy is enforceable, not decorative.** Required mode rejects ordinary
   signatures; it does not merely highlight Protected QR.
2. **Protocol capability is device-neutral.** AEXT recognition does not depend
   on the SeedSigner brand. Compatibility is explicit keystore metadata.
3. **The transaction is reviewed before nonce commitment.** The signer does not
   emit message 2 until the user approves the exact transaction context.
4. **Post-reveal retries are exact.** The UI distinguishes transport retry from
   starting a fresh challenge.
5. **No automatic broadcast.** Verified completion returns to the existing
   final transaction review and manual broadcast action.
6. **Failure is visible and atomic.** Unsupported, malformed, mismatched, or
   downgraded requests produce no partial signature.

## 2. Keystore policy

For an air-gapped keystore, Wallet Settings shows **Protected signing** with:

- **Unsupported** — no compatible protocol is declared;
- **Optional** — Protected QR is available; ordinary signing remains permitted;
- **Required** — compatible supported signatures must complete through
  Protected QR.

SeedSigner imports default to **Optional**. Another device retains its real
brand and begins **Unsupported** unless its importer or the user explicitly
declares compatibility. A plain xpub/watch-only import does not claim the
existence of a compatible signing device.

Changing **Required** to a weaker state should require an explicit wallet
settings action. Importing an ordinary signature must never downgrade policy.
Replacing or rederiving the same public keystore preserves policy; replacing it
with different key material requires an explicit new choice.

## 3. Sparrow transaction actions

When at least one eligible keystore is optional, Sparrow offers **Protected
QR** alongside ordinary actions. When an eligible signer is required:

- label the action **Protected QR (Required)**;
- make it the primary/default signing action;
- disable or reject ordinary signing for that required signature;
- retain Save Transaction and transaction inspection; and
- reject an ordinary returned PSBT/final transaction before accepting its
  signatures.

For multisig, selecting Protected QR opens a chooser listing compatible
keystores by user label and master fingerprint. Already verified signatures are
shown distinctly. Required unsigned keystores remain selectable until the
wallet threshold is satisfied; incompatible/unsupported keystores are never
silently substituted.

## 4. Sparrow four-stage ceremony

### Step 1: host commitment

Title: **Protected signing — Step 1 of 2**

Instruction: **Scan this commitment with your signing device.**

Show the animated message-1 QR, selected keystore label/fingerprint, transaction
identifier, and a short statement that no signature exists yet. **Scan QR**
opens a scanner restricted to message 2 for the exact session/network.

Cancellation before accepting message 2 may offer **Discard unused session**.
It must not create a selective-abort warning.

### Step 2: host reveal and verified signatures

After atomically accepting message 2 and persisting the session, display the
exact message-3 QR.

Title: **Protected signing — Step 2 of 2**

Instruction: **Scan this reveal with the same signing device, then scan its
verified signatures.**

The message-4 scanner is restricted to the exact session, network, PSBT digest,
slot set, and opening set. Completion closes the modal and populates only the
verified signer bar in Sparrow's normal transaction view.

### Camera behavior

- Ignore a short startup buffer before accepting a decoded symbol.
- If the first meaningful fountain fragment conflicts before useful progress,
  reset to the live stream; never switch after meaningful progress.
- Show both reconstruction percentage and a plain diagnostic such as **Waiting
  for a new QR frame** when progress is not changing.
- Preserve camera/resolution choice across the two scans.
- Reject a duplicate cosigner xpub with **Duplicate Keystore — This key is
  already present. Scan the intended signer again.**

## 5. SeedSigner ceremony

### Message 1

Recognize AEXT through the normal Scan router when protected signing is enabled.
Before generating openings, show:

- **Anti-exfil Signing**;
- **Protected signing 1 of 2**;
- transaction review; and
- explicit language that this round creates a nonce commitment and does not
  sign the transaction.

After seed/key selection and transaction approval, display message 2.

### Direct continuation

After the message-2 QR is dismissed, show **Step 1 of 2 complete** with:

- **Scan host reveal**; and
- **Exit to main menu**.

The direct shortcut preserves the selected seed for that uninterrupted
ceremony and restricts scanning to message 3. It must not ask for the same seed
again. Exiting to the main menu clears volatile signer selection; scanning
message 3 later through ordinary Scan remains stateless and asks the user to
select/restore the matching seed.

### Message 3

The signer repeats transaction and slot validation, checks every reveal and
recomputed opening, and only then signs. Multisig descriptor/address verification
may interrupt the UI without changing protocol state. On success, display
message 4 and state that the coordinator must still verify it.

## 6. Retry and selective-abort language

If message 3 has not been shown, ordinary cancellation copy is sufficient.

If message 3 has been shown and completion is absent, reopening the action must
offer:

- **Retry exact session** — redisplay the retained byte-identical message 3 and
  accept the already-produced matching message 4; and
- **Abandon session** — retain the event and explain that starting fresh after
  repeated signer failures can create a nonce-bias channel.

Suggested first-warning copy:

> The host reveal has already been shown. Retry this exact transaction and
> session. Starting fresh challenges after repeated signer failures can leak
> information through selective aborts.

If prior post-reveal history exists for the same wallet key, starting a fresh
session requires a separate high-severity acknowledgement. Thresholds and
fund-migration wording remain a maintainer/security-review decision.

## 7. Error presentation

Use a stable title such as **Protected signing stopped**. Do not expose Python,
Java, parser, or stack-trace details in the normal UI.

| Class | User meaning |
| --- | --- |
| Policy mismatch | Coordinator and signer protected-signing modes differ |
| Unsupported transaction | Script, sighash, PSBT version, or Taproot is outside v1 |
| Transaction mismatch | PSBT or signing context changed between stages |
| Commitment mismatch | Host reveal does not match its commitment |
| Opening mismatch | Signer opening is not the one committed before reveal |
| Signature verification failed | Ordinary ECDSA or S2C verification failed |
| Protected signature rejected | An ordinary signature was returned for a required keystore |
| Duplicate keystore | Another cosigner already contains the imported xpub |
| Session state invalid | Durable state is missing, corrupt, or belongs to another wallet/session |

Security failures should advise returning to the main menu/transaction and not
continuing with changed data. Recoverable camera errors should offer same-session
retry without implying a cryptographic failure.

## 8. Network presentation

Do not modify SeedSigner's stock network-selection screen solely for Testnet4.
Its Testnet selection covers the shared public-test address/key family, while
AEXT preserves the exact testnet3, signet, or testnet4 code. Sparrow continues
to display its exact active network, including Testnet4.

## 9. Accessibility and localization

- Keep **protected signing**, **commitment**, **reveal**, and **exact session**
  terminology consistent across products.
- Do not rely only on color for required policy, signer completion, or errors.
- Keep fingerprints selectable/readable in multisig choosers.
- Mark all new UI strings for translation and avoid concatenated grammar.
- Provide a concise help link explaining why the ceremony has four QR scans
  and why exact retry matters.

## 10. Acceptance scenarios

Maintainer UX acceptance should cover:

1. optional single-signature honest completion;
2. required single-signature ordinary-return rejection;
3. direct message-3 continuation without seed reselection;
4. stateless main-menu message-3 recovery with seed selection;
5. two required cosigners completing a 2-of-3 wallet sequentially;
6. pre-reveal cancellation and resume;
7. post-reveal exact retry with an already displayed message 4;
8. prior selective-abort history warning;
9. duplicate/stale xpub import rejection;
10. wrong stage/network/session and unsupported Taproot errors; and
11. completion returning to review with broadcasting still manual.
