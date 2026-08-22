# V12 Gate 3 durable-files and bounded-resource design

Date: 2026-08-22

Gate 3 addresses V12 findings 247986, 247991, 247993, 247994, 247998,
and 247999 as one durable-storage boundary. It does not change the AEXB wire
format, signer behavior, PSBT reconstruction, policy provenance, or the Gate 2
abort-state machine. Finding 248000 remains explicitly deferred to Gate 4.

## Locked invariants

1. A durable-file write returns only after the temporary file contents are
   forced, the atomic namespace replacement succeeds, and the parent directory
   is forced where Java exposes that operation. Windows retains file forcing
   and atomic replacement but treats unsupported directory forcing as a
   documented recovery-grade residual rather than a protocol failure.
2. A durable-file read obtains the file size from an already-open channel,
   rejects out-of-range metadata before allocation, reads exactly that bounded
   size, and rejects truncation or growth observed during the read.
3. The writer and reader use one file-size definition, including the checksum.
   Coordinator encoding validates every blob and the exact aggregate encoded
   size before modifying the prior durable state. Therefore successful write
   implies reloadability under the same limits.
4. Same-JVM calls serialize before acquiring operating-system file locks. The
   existing Gate 2 lock-registry behavior and cross-process FileChannel locking
   remain regression-tested.
5. Symlink and junction aliases resolve through the real parent path. Existing
   state is additionally locked by its underlying file on POSIX, which
   serializes hard-link aliases across processes. Before atomic replacement,
   the old file is forced into an invalid state so a detached alias cannot
   retain a valid pre-transition session or journal. Windows uses the global
   JVM serializer plus invalidation; cross-process hard-link aliasing remains a
   trusted-filesystem residual because Java cannot hold the target lock and
   atomically replace that target on Windows.
6. `AntiExfilCodec.MAGIC` remains as a source-compatibility array, but encoding
   and decoding use an unexposed canonical constant. Mutating the compatibility
   array cannot change the accepted or emitted AEXB framing.

## Failure behavior

- Any unsupported atomic replacement, POSIX directory-force failure, bounded
  read inconsistency, per-field overflow, or aggregate overflow fails closed as
  `STATE_INVALID` at the public coordinator boundary.
- If the old file has been invalidated but replacement or directory forcing
  subsequently fails, availability can be lost, but the old randomness-bearing
  state cannot remain valid through an alias. No host reveal is returned from a
  failed `acceptOpenings` write.
- Windows directory-entry persistence across sudden power loss remains a
  documented residual within the trusted-filesystem assumption. Revalidation
  detects absent, truncated, or rolled-back state after restart.
- A Windows actor able to create hard links and coordinate a second process is
  also inside that trusted-filesystem residual. Normal callers, symlink/junction
  aliases, and same-JVM hard-link aliases remain serialized.

## Required regressions

- A write-observer test pins replacement-before-directory-barrier ordering.
- Oversized sparse files are rejected from channel metadata before allocation;
  exact-bound and one-byte-over files exercise the same cap definition.
- State-length arithmetic has exact-bound, aggregate-overflow, and per-field
  overflow cases; an over-limit replacement leaves the prior valid file intact.
- A hard-link alias cannot retain a valid old state after replacement.
- Existing same-JVM and cross-process lock tests remain green.
- Mutating the public compatibility magic does not alter canonical encode or
  decode, and the mutation is restored in `finally` for test isolation.

No security exploit, secret recovery, memory-exhaustion run, or power-cycle PoC
is required. The evidence is bounded fault injection plus source-level ordering
and full-suite regression validation.
