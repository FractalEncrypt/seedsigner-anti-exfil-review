# V12 Gate 2 implementation-review brief

Date prepared: 2026-08-22  
Scope: abort-state cluster `#247989`, `#247992`, `#248004`, `#248006`  
Status: implementation complete; independent review and public CI required

## 1. Review ranges

| Component | Base | Head | Branch |
| --- | --- | --- | --- |
| Reference/spec | `eb1542e228fc8ab6904810b1eeef79bb47b3f5dd` | `3fabb3872d5ee11918b8c52a9959bdf67c31b965` | `codex/v12-gate2-abort-state-machine` |
| Drongo | `5a7baed1a2cad23f0f0a4f007d49cdba44415b60` | `0e1d1c3abd71ef5d2bd7c02fdd4d09e0ba56a354` | `codex/v12-gate2-abort-state-machine` |
| Sparrow | `3eb93d52f856a1851b144e7523aeb658386b1122` | `9936628683d6d8e1ce436e97d21d2096c3cd1a36` | `codex/v12-gate2-abort-state-machine` |

Suggested review commands:

```text
git diff eb1542e..3fabb38
git diff 5a7baed..0e1d1c3
git diff 3eb93d5..9936628
```

Sparrow pins Drongo exactly at
`0e1d1c3abd71ef5d2bd7c02fdd4d09e0ba56a354`.

## 2. Findings remediated as one state transition

- `#247989`: an abort recorded after session creation did not revoke the
  session before its first host reveal.
- `#247992`: signer-data rejection after reveal was not necessarily journaled
  by Drongo.
- `#248004`: repeated abort calls appended duplicate events until the bounded
  journal was exhausted.
- `#248006`: create checked the journal and created the session under separate
  locks, permitting a stale-check race.

The implementation follows the locked design record in
`docs/v12-gate2-abort-state-machine-design.md`.

## 3. Production design

### Atomic snapshot binding

`AntiExfilCoordinator.create` now holds the canonical abort-journal lock while
checking acknowledgement policy, hashing the canonical journal state, and
durably creating the session under the nested session lock. The only nested
order is journal then session.

Coordinator state format v2 stores that 32-byte journal digest. Immediately
before the first message-3 disclosure, `acceptOpenings` reacquires journal then
session and compares the current digest. A mismatch returns `RETRY_CONFLICT`
before message 3 is written or returned.

Once message 3 was durably accepted, an exact message-2 retry returns only the
cached reveal. It does not repeat the first-disclosure gate or generate new
randomness. A valid message 4 can still complete after unrelated later aborts.

### Narrow automatic rejection journal

Drongo records `SIGNATURE_REJECTED` for these signer-attributable codes:

- `INVALID_MESSAGE`
- `TRANSACTION_MISMATCH`
- `SIGNATURE_SLOT_MISMATCH`
- `COMMITMENT_MISMATCH`
- `OPENING_MISMATCH`
- `SIGNATURE_INVALID`
- `UNEXPECTED_RETURN_DATA`
- `SESSION_MISMATCH`

It does not automatically record `WRONG_STAGE`, `RETRY_CONFLICT`, or
`STATE_INVALID`. Durable host-state validation occurs before this
classification, so host-state failures are not relabeled as signer behavior.

`recordSignerDataRejection()` exposes the same idempotent operation for a host
transport boundary that rejects signer data before handing AEXB bytes to the
coordinator. Sparrow uses the shared Drongo predicate and no longer journals
every `AntiExfilException` indiscriminately.

Sparrow's QR exchange continues to treat scan/UR decoding failure as a
transport interruption: before reveal it may cancel without a selective-abort
event; after reveal it permits only exact retry or explicit abandonment, and
abandonment records `TRANSPORT_FAILED`. The narrow signer-rejection predicate
applies once a decoded protocol package reaches the signing-flow boundary.

### First event wins

The journal retains one event per `session_id`. The first reason and timestamp
remain authoritative. Repeated automatic or manual recording returns the
existing event without rewriting the file or increasing the count. Existing
legacy duplicate records are interpreted with first-event semantics.

### Canonical two-level locks

Durable paths resolve through the real parent and, when present, the real file.
A canonical-path keyed, fair JVM-local `ReentrantLock` serializes threads before
the existing `FileChannel` lock supplies cross-process exclusion. Entries are
reference-counted and removed after the final holder/waiter releases them.

This same-JVM layer is required because Java throws
`OverlappingFileLockException` instead of waiting when another thread in the
same process holds the file lock. It necessarily resolves the overlapping-lock
portion of `#247998`; broader resource/contention review remains separate.

## 4. Coordinator-state compatibility

New states are AEXS version 2. Version 1 remains readable:

- a v1 `COMMITMENTS_CREATED` session has no bound journal digest and therefore
  fails closed before first reveal;
- a v1 `OPENINGS_ACCEPTED` session may return only its cached exact message 3
  and may complete its existing transcript;
- completed v1 evidence remains revalidatable.

No AEXB or AEXT wire byte changed.

## 5. Tests-first evidence

The initial six-test Gate 2 class compiled against Drongo `5a7baed1`:

- five security regressions failed for the intended missing protections;
- the negative control proving wrong-stage/retry failures do not poison the
  journal passed.

The final class contains eleven tests covering:

1. pre-created session revocation before first reveal;
2. acknowledged nonempty snapshot plus later revocation;
3. cryptographic signature rejection and byte-stable deduplication;
4. structural message-2 rejection before any reveal;
5. transport-boundary rejection before reveal;
6. wrong-stage and changed-retry non-poisoning;
7. legitimate completion after an unrelated later abort;
8. aliased journal path serialization and deduplication;
9. deterministic cross-process create-vs-abort race closure;
10. fail-closed v1 pre-reveal migration; and
11. usable v1 post-reveal exact retry and completion.

The reference model adds three wallet/session snapshot tests in addition to the
existing selective-abort test. Sparrow tests pin narrow classification at both
message-2 and message-4 boundaries and ensure a wrong-stage response is not
journaled.

## 6. Validation evidence

### Reference

With `SEEDSIGNER_SRC` explicitly bound to tagged SeedSigner `aa8395e`:

```text
.venv\Scripts\python.exe -m unittest discover -s tests\reference -t . -v
```

Result: **88/88 passed**. All three cross-implementation SeedSigner adapter
tests ran.

### Drongo

Focused Gate 2 class: **11/11 passed**.

Full Windows suite: **469/471 passed**. The only failures are the unchanged,
environment-dependent `ApplicationDirTest.testXdgDirs` and
`ApplicationDirTest.testXdgAppliedToMacos` assertions previously recorded in
the review ledger.

### Sparrow

Focused `AntiExfilSigningFlowTest` plus `AntiExfilPolicySelectionTest`:
**passed**.

Full Windows suite: **152/156 passed**. The four failures are the unchanged
CRLF/LF fixture comparisons in Caravan, Coldcard, and Specter DIY export tests.

Public Linux CI was intentionally deferred until this diff received independent
review. Section 9 records the completed review, CI, and immutable tags.

## 7. Requested security properties

Please approve or reject each property independently:

1. create's journal decision and session write are one journal-locked action;
2. every first reveal compares the exact accepted digest before any `rho`
   leaves the coordinator;
3. an abort racing create or reveal cannot leave a usable unacknowledged
   pre-reveal session;
4. acknowledged existing history works, but only for the exact accepted
   snapshot;
5. exact cached reveal retry and legitimate completion remain usable;
6. signer-attributable rejection is journaled at Drongo and Sparrow boundaries,
   while wrong-stage/retry/state/I/O faults are not;
7. manual and automatic repeats preserve the first event and cannot exhaust the
   journal with duplicates;
8. all nested paths follow journal then session with one canonical lock
   identity across aliases and processes;
9. the JVM-local lock registry cannot split an active lock identity or leak an
   entry after the final reference releases;
10. v1 state migration follows the fail-closed/continue-existing-transcript
    split described above;
11. Sparrow pins the exact Drongo head and does not reintroduce broad exception
    journaling; and
12. no signer-side, wire-format, provenance, quarantine, reconstruction, or
    broadcast-policy behavior changed.

Please specifically report any exception-precedence path that can append a
false abort, any path returning a first reveal without a matching journal
digest, any journal/session lock inversion, or any legacy-state path that can
disclose unbound fresh host randomness.

## 8. Explicit non-goals

- No key-recovery, nonce-grinding, or weaponized proof of concept.
- No SeedSigner or SeedSignerOS change or rebuild.
- No physical gate; wire and signer behavior are unchanged.
- `#248000`, directory-entry durability, allocation bounds, filesystem rollback
  policy, and remaining V12 Gates 3–5 stay open.
- The Gate 1 tested tags remain immutable evidence and are not moved.

## 9. Review and release-gate closure

Kimi K3 independently reviewed the exact ranges in section 1 and approved all
twelve requested security properties. The full assessment is recorded as Phase
12 in `security-review-findings.md`. No false-abort precedence path, first-reveal
digest bypass, lock inversion, or legacy-state path disclosing unbound
randomness was found. Two cosmetic observations were accepted as non-blocking:
message 1 is decoded twice on the reveal path, and the reference model permits
post-completion abort recording where Drongo is stricter.

After approval, workflow-only child commits were created solely to run the full
public Linux suites. Each child has the independently reviewed head as its exact
parent and adds only `.github/workflows/gate2-ci.yml`:

- Drongo CI child: `5ce588f738a4c8ffd77956b1713f46bc70c0a0a2`
  (parent `0e1d1c3abd71ef5d2bd7c02fdd4d09e0ba56a354`).
- Sparrow CI child: `be34d94685d75e1227ee28324b50aaa03c670663`
  (parent `9936628683d6d8e1ce436e97d21d2096c3cd1a36`).

Both public Linux runs passed on 2026-08-22:

- Drongo, full suite: GitHub Actions run `32578291028`, success.
- Sparrow, full suite under Xvfb: GitHub Actions run `32578288950`, success.

New annotated immutable tags were then created on the reviewed parents, not the
workflow-only children:

- Reference (local): `anti-exfil-tested-2026-08-22` ->
  `3fabb3872d5ee11918b8c52a9959bdf67c31b965`.
- Drongo (published): `anti-exfil-review-v1-tested-2026-08-22` ->
  `0e1d1c3abd71ef5d2bd7c02fdd4d09e0ba56a354`.
- Sparrow (published): `anti-exfil-review-v1-tested-2026-08-22` ->
  `9936628683d6d8e1ce436e97d21d2096c3cd1a36`.

The 2026-08-20 vulnerable-state tags and 2026-08-21 Gate 1 tags remain
unchanged as immutable evidence. Gates 1 and 2 are closed; V12 Gates 3–5 and
`#248000` remain open, so the final reviewer bundle is not yet frozen.
