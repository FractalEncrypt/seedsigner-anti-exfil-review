# V12 Gate 2 abort-state-machine design

Date locked: 2026-08-22  
Scope: V12 findings `#247989`, `#247992`, `#248004`, and `#248006`  
Baseline: reference `eb1542e`; Drongo `5a7baed1`

Gate 2 is one fail-closed coordinator state-machine correction, not four
independent local patches. It does not change AEXB wire bytes or signer-side
behavior.

## Security invariants

1. **Atomic creation gate.** Session creation holds the canonical wallet abort
   journal lock while checking the accepted journal snapshot and durably
   creating the session. If a session lock is also needed, the order is always
   journal then session.
2. **Durable snapshot binding.** Every new session stores the SHA-256 digest of
   the canonical journal state accepted at creation. This permits an explicitly
   acknowledged session to start after existing abort history without allowing
   later aborts to go unnoticed.
3. **Reveal-boundary revocation.** Before the first message-3 host reveal is
   persisted or returned, the coordinator holds journal then session and
   requires the current canonical journal digest to equal the session's stored
   digest. Any intervening abort permanently invalidates that in-flight session.
4. **No new-randomness retry regression.** Once message 3 was durably accepted,
   an exact message-2 retry may return the already-disclosed cached message 3.
   It never generates or authorizes new host randomness.
5. **Automatic signer-rejection journal.** Structural, transcript-binding, or
   cryptographic rejection attributable to signer-supplied message 2 or message
   4 records `SIGNATURE_REJECTED` atomically before the original rejection is
   returned. Null input, wrong-stage calls, changed exact retries, corrupt host
   state, local I/O failures, and programming errors fail closed without
   poisoning the journal.
6. **One event per session.** The first abort event for a session ID is retained.
   Repeated recording is an idempotent no-op returning that first event; it does
   not change the reason, timestamp, count, or journal bytes.
7. **Complete sessions remain complete.** A valid message 4 still completes and
   rehydrates normally. An exact completed-message retry remains usable. A
   failed merge or failed verification grants no completion evidence.
8. **Canonical lock identity.** Durable-state lock targets resolve through the
   real parent path (and the real file path when it exists), so aliases and
   Windows junctions cannot create distinct locks for the same journal. A
   reference-counted JVM-local mutex serializes threads before the existing
   `FileChannel` lock provides cross-process exclusion; Java otherwise throws
   `OverlappingFileLockException` for same-JVM contenders instead of waiting.

## Failure classification

Signer-attributable codes eligible for automatic `SIGNATURE_REJECTED`
journaling are:

- `INVALID_MESSAGE`
- `TRANSACTION_MISMATCH`
- `SIGNATURE_SLOT_MISMATCH`
- `COMMITMENT_MISMATCH`
- `OPENING_MISMATCH`
- `SIGNATURE_INVALID`
- `UNEXPECTED_RETURN_DATA`
- `SESSION_MISMATCH`

The following are deliberately not automatic abort reasons:

- `WRONG_STAGE`
- `RETRY_CONFLICT`
- `STATE_INVALID`

The coordinator must already hold the validated session state before applying
this classification. An exception while reading or validating durable host
state is never reclassified as signer misconduct.

## Regression gates

- a session created before another session's abort cannot disclose its first
  message 3 afterward;
- create-vs-abort concurrency cannot leave a usable unacknowledged session;
- an acknowledged session binds to its accepted nonempty journal snapshot and
  is revoked by a later append;
- invalid signer message 4 records exactly one `SIGNATURE_REJECTED` event;
- invalid signer message 2 records exactly one event and returns no message 3;
- repeated manual or automatic abort recording preserves the first event and
  journal bytes;
- wrong-stage, retry-conflict, corrupt-state, and local-failure cases do not
  append events;
- exact message-2 retry, exact completion retry, reload, and legitimate
  completion remain green;
- aliased paths serialize on one lock identity where the platform supports the
  alias used by the test.

## Scope boundaries

- No SeedSigner or SeedSignerOS change.
- No AEXB/AEXT wire-version change.
- No key-recovery or nonce-grinding proof of concept.
- `#248000` (public transition API full-validation contract) remains a later
  gate unless Gate 2 source evidence requires touching it.
- Directory-entry durability and bounded-allocation work remain separate later
  gates. Gate 2 necessarily addresses the same-JVM overlap portion of
  `#247998`; broader contention and resource analysis remains separately
  reviewable.
