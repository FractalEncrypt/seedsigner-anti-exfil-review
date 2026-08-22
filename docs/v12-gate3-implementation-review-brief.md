# V12 Gate 3 implementation-review brief

Date: 2026-08-22

This brief requests an independent source-level review of Gate 3: durable-file
ordering, bounded allocation, reloadable state limits, path-alias concurrency,
and immutable wire framing. No V12 patch was applied. The implementation and
tests were designed locally from the verified invariants in
`v12-gate3-durable-bounds-design.md`.

## 1. Exact review ranges

### Reference/design

- Repository: `C:\Users\FractalEncrypt\Documents\SeedSigner_AntiExfil`
- Base: `3fabb3872d5ee11918b8c52a9959bdf67c31b965`
- Head: `5d2c699c6c283113a72f07884a5f2953aed6f82e`
- Range: `3fabb3872d5ee11918b8c52a9959bdf67c31b965..5d2c699c6c283113a72f07884a5f2953aed6f82e`

### Drongo

- Repository: `C:\Users\FractalEncrypt\Documents\Windsurf\Drongo_AntiExfil_Review`
- Base: `0e1d1c3abd71ef5d2bd7c02fdd4d09e0ba56a354`
- Head: `a3ed65c5dfda9a7a16dabc8b0a206c9beb422eaf`
- Range: `0e1d1c3abd71ef5d2bd7c02fdd4d09e0ba56a354..a3ed65c5dfda9a7a16dabc8b0a206c9beb422eaf`
- Commits:
  - `ee97f22` — durable persistence, allocation bounds, aggregate bounds,
    hard-link handling, and tests;
  - `a3ed65c` — canonical wire-magic isolation and regression.

### Sparrow

- Repository: `C:\Users\FractalEncrypt\Documents\Windsurf\Sparrow_AntiExfil_Review_Fresh`
- Base: `9936628683d6d8e1ce436e97d21d2096c3cd1a36`
- Head: `c57b07584fe9f150a457900c3afbe20e42c7c78e`
- Range: `9936628683d6d8e1ce436e97d21d2096c3cd1a36..c57b07584fe9f150a457900c3afbe20e42c7c78e`
- The range changes only the Drongo gitlink and pins exactly
  `a3ed65c5dfda9a7a16dabc8b0a206c9beb422eaf`.

## 2. Finding dispositions

- **247986 — parent-directory durability:** fixed on POSIX. The temporary file
  is forced, atomically moved, and the parent directory is forced before return.
  An injected barrier failure invalidates the visible file before throwing, so
  no exact retry can disclose a reveal from an uncommitted state. Windows keeps
  file forcing and atomic replacement but records directory-entry persistence
  across sudden power loss as a trusted-filesystem recovery residual.
- **247991 — alias state forks:** symlink/junction parents remain resolved with
  `toRealPath`. A JVM-global fair lock serializes every in-process alias before
  any FileChannel lock. POSIX additionally locks the existing underlying file,
  serializing hard links across processes. Before replacement the old inode is
  truncated and forced, so detached aliases fail checksum/length validation.
  Windows cannot atomically replace a target while Java holds its FileChannel
  lock; same-JVM aliases and stale-inode invalidation are covered, while a
  cooperating second process that can create hard links remains explicitly in
  the trusted-filesystem residual.
- **247993 — allocation before size validation:** fixed. Reads open a channel,
  inspect its size, reject outside the configured total-file cap before
  allocation, read exactly that size, and reject observed truncation or growth.
- **247994 — successful but unreloadable completion:** fixed. All seven blob
  lengths, rho count, exact schema overhead, checksum, signed-PSBT cap, and
  aggregate file cap are checked before encoding or modifying the old state.
  Writer and reader now share the same total-file cap definition.
- **247998 — same-JVM lock contention:** already fixed in Gate 2. Gate 3 retains
  the ref-counted path registry and strengthens the outer JVM serializer;
  Gate 2 same-JVM and real child-process lock tests remain green.
- **247999 — mutable codec magic:** fixed without breaking source compatibility.
  The deprecated public array is a clone; encode/decode use a private canonical
  `AEXB` constant. Mutation cannot affect framing.

## 3. Security and failure invariants to verify

Please approve or reject each independently:

1. no first or cached host reveal can return from a failed POSIX durability
   transition;
2. file content force → atomic move → parent-directory force is the only
   successful write order;
3. any move or POSIX directory-force failure is fail-closed, even if that costs
   availability;
4. bounded reads allocate only after checking an already-open channel's size
   and cannot silently accept growth/truncation during the read;
5. `checkedStateFileLength` exactly matches the v2 AEXS encoding, including the
   checksum and 69 bytes per rho record;
6. every blob accepted for writing is accepted by the corresponding decoder,
   and successful write implies reloadability under the same limits;
7. an over-limit completion fails before replacement, leaving the prior
   `OPENINGS_ACCEPTED` file usable;
8. the global JVM lock cannot invert Gate 2's journal → session order or
   deadlock nested reentrant calls;
9. POSIX pathname locks plus underlying-file locks serialize canonical,
   symlink, and hard-link callers across processes;
10. invalidating the old inode before replacement makes every detached alias
    fail closed rather than retain a valid pre-transition state;
11. the stated Windows hard-link limitation is accurate, contained within the
    existing trusted-filesystem assumption, and not overclaimed as fixed; and
12. mutating `AntiExfilCodec.MAGIC` cannot alter frozen positive vectors,
    accepted framing, or emitted framing.

Also report any unchecked exception, limit mismatch, lock-order cycle,
successful-return path before the durability barrier, or path by which a valid
old alias survives a completed replacement.

## 4. Validation evidence

### Pre-fix regression

The new focused test class initially failed to compile because the bounded
writer and exact state-length contract did not exist. This pins that the test
surface was introduced before the implementation rather than merely exercising
old behavior.

### Drongo focused

Command:

```text
.\gradlew.bat test --tests com.sparrowwallet.drongo.antiexfil.AntiExfilDurableFilesTest --tests com.sparrowwallet.drongo.antiexfil.AntiExfilCodecTest --tests com.sparrowwallet.drongo.antiexfil.AntiExfilAbortStateMachineTest --rerun-tasks
```

Result: **25 passed, 1 skipped**. The skip is the explicitly POSIX-only
cross-process hard-link lock test on Windows. All 11 Gate 2 abort-state tests
passed.

### Drongo full Windows suite

Result: **480 total; 477 passed, 1 skipped, 2 failed**. The only failures are
the unchanged environment-dependent `ApplicationDirTest.testXdgDirs` and
`ApplicationDirTest.testXdgAppliedToMacos` assertions.

### Sparrow focused

Root `:test` task covering `AntiExfilSigningFlowTest`,
`AntiExfilPolicySelectionTest`, and `AntiExfilTransportPackageTest`: **16/16
passed**.

### Sparrow full Windows suite

Result: **152/156 passed**. The only failures are the four unchanged CRLF/LF
fixture comparisons in Caravan, Coldcard, and Specter DIY export tests. H2
shutdown messages concern already-removed JUnit temporary directories and are
not test failures.

Public Linux CI is intentionally deferred until independent review. The POSIX
CI run must execute the non-skipped parent-directory and cross-process
hard-link behavior before any new tested tag is created.

## 5. Explicit non-goals

- No memory-exhaustion, nonce-recovery, power-cycle, or weaponized PoC.
- No AEXB format/version or frozen-vector change.
- No SeedSigner or SeedSignerOS change or physical test.
- No provenance, quarantine, reconstruction, broadcast, or policy behavior
  change.
- No disposition of 247987/247988/247990/247996/247997 (Gate 5).
- No change to 247995/248000/248001/248002 (Gate 4).
- No tags until this exact diff is independently approved and public Linux CI
  passes.

## 6. Review and release-gate closure

Kimi K3 independently reviewed every range in section 1 and approved all twelve
properties in section 3. The full assessment is recorded as Phase 13 in
`security-review-findings.md`. No unchecked exception path, limit mismatch,
lock-order cycle, successful return before the durability barrier, or surviving
valid-alias path was found. The POSIX pathname-swap TOCTOU observation was
classified non-blocking because the required actor is already inside the
trusted-filesystem boundary.

Workflow-only child commits were then created solely for public Linux testing.
Each has the reviewed head as its exact parent and adds only
`.github/workflows/gate3-ci.yml`:

- Drongo CI child: `e8043a92e6aaa5f1cb5ac72bb381ebec9597f1f6`
  (parent `a3ed65c5dfda9a7a16dabc8b0a206c9beb422eaf`).
- Sparrow CI child: `e8de74686383f44d697a468da42d8c67bcda0266`
  (parent `c57b07584fe9f150a457900c3afbe20e42c7c78e`).

Both public Linux jobs passed on 2026-08-22:

- Drongo run `32580787325`: the explicit Gate 3 POSIX regression step passed,
  including the non-skipped parent-directory and cross-process hard-link tests;
  the subsequent full Drongo suite also passed.
- Sparrow run `32580788920`: the full Sparrow suite passed under Xvfb.

New annotated immutable tags were created on the reviewed parents, not on the
workflow-only children:

- Reference (local): `anti-exfil-gate3-tested-2026-08-22` ->
  `5d2c699c6c283113a72f07884a5f2953aed6f82e`.
- Drongo (published): `anti-exfil-review-v1-gate3-tested-2026-08-22` ->
  `a3ed65c5dfda9a7a16dabc8b0a206c9beb422eaf`.
- Sparrow (published): `anti-exfil-review-v1-gate3-tested-2026-08-22` ->
  `c57b07584fe9f150a457900c3afbe20e42c7c78e`.

All Gate 1 and Gate 2 tags remain unchanged as immutable evidence. Gates 1–3
are closed. Gate 4 (`247995`, `248000`, `248001`, `248002`) is next; Gate 5
threat-model dispositions remain open. The final reviewer bundle is therefore
not yet frozen.
