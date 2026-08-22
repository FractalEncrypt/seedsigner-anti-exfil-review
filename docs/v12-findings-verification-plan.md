# V12 Drongo findings — independent verification plan

Status: triage plan; no V12 remediation accepted and no V12 proof of concept
executed.

Audited input: Drongo `1bbafd94f08fd9105e20be30a6fdfe9a091fb675`.

Source reports:

- V12 run export: `export.md` (22 top-level findings: 20 unreviewed and two
  marked invalid by V12).
- V12 audit-context artifact: `Artifacts.txt` / `v12.md`.
- Project threat model and prior ledger: `independent-security-review-brief.md`,
  `maintainer-decisions-requested.md`, and `security-review-findings.md`.

This document converts the automated report into maintainer-verifiable work.
It deliberately does not reproduce private-key recovery, nonce-exfiltration,
or other offensive demonstrations. Security claims are verified through source
tracing, invariant-focused regression tests, bounded fault injection, and
ordinary unit/integration validation.

## Evidence required for every accepted finding

A finding is not actionable merely because its generated test ran. Its ledger
entry must contain all of the following:

1. Exact pinned source path and control-flow reachability from a supported
   Drongo or Sparrow entry point.
2. The violated protocol, API, persistence, or policy invariant.
3. Preconditions and the responsible trust boundary.
4. A minimal regression test that demonstrates the invariant violation without
   extracting a secret or weaponizing the behavior.
5. Baseline evidence that the test fails for the intended reason at
   `1bbafd94`, not because the harness or generated patch is broken.
6. A maintainer-designed fix and a focused diff review. V12 patches are design
   suggestions only.
7. Focused and full Drongo tests after the fix, plus Sparrow tests whenever a
   public API, returned PSBT, evidence record, exception, or session lifecycle
   changes.
8. A final disposition: confirmed defect, hardening, accepted residual,
   specification decision, duplicate, or invalid.

## Initial verification matrix

The dispositions below are provisional until their required checks are
complete.

| ID | V12 claim | Initial treatment | Safe verification needed | Likely action if confirmed |
| --- | --- | --- | --- | --- |
| 247985 | Duplicate openings expose the signing key | **Priority 0, credible key-safety invariant.** Drongo checks duplicate host commitments/reveals but reportedly not reuse of one signer opening by the same signing key across slots. | Trace slot validation and transition validation. Add a regression containing two slots for the same signer public key and assert that a repeated opening is rejected before any host reveal is returned. Also assert that legitimate distinct openings still pass. Do not calculate or print a recovered key. | Enforce opening uniqueness per signer public key across the complete slot set. Do not use V12's broader one-line global uniqueness rule unless compatibility analysis proves it correct for distinct signer keys. Add shared negative-vector coverage. |
| 247986 | Rename is not durable before randomness disclosure | **Credible durability gap; platform/filesystem dependent.** Atomic rename is not necessarily durable without syncing the parent directory. | Inspect `AntiExfilDurableFiles.write` on every supported OS. Use a filesystem abstraction or mocked operation ledger to assert the order: write, file force, atomic replace, parent-directory durability barrier, then return. Record platforms where directory forcing is unsupported. | Add the strongest supported parent-directory sync and fail closed before revealing rho when the required durability contract cannot be met; document the Windows guarantee precisely. |
| 247987 | Rollbackable state permits randomness reuse | **Threat-model/design decision, not automatically High.** Prior decision 5 places the coordinator filesystem in the trusted base, while the review brief explicitly asks reviewers to assess rollback. | Confirm that an authentic older session state cannot be distinguished from current state. Decide whether accidental backup rollback and a malicious local filesystem actor are in scope. Model which external monotonic authority would be trustworthy and deployable. | If rollback is in scope, design a separate authenticated monotonic consumption ledger before changing the format. Otherwise record this as an accepted residual with recovery guidance and no Critical/High vulnerability claim. |
| 247988 | Abort history can be erased or rolled back | **Same trust-model cluster as 247987; V12's Critical rating is not yet justified.** The journal is a warning/control, not a cryptographic secret. | Confirm deletion creates an empty journal and old valid journals cannot be distinguished. Reconcile with the trusted-filesystem assumption and selective-abort UX claim. Determine whether the application can anchor journal state outside the same rollback domain. | Authenticated/monotonic journal only if that authority is in scope. At minimum distinguish “missing” from first creation where a wallet/session already exists and document backup/restore behavior. |
| 247989 | Abort gate cannot revoke pre-created sessions | **Credible state-machine defect.** The wallet-wide abort gate reportedly runs only at session creation, not immediately before rho disclosure. | Create two normal pre-reveal sessions through supported APIs. Record a post-reveal abort for one, then assert the other cannot transition to host reveal without explicit acknowledgement. No malformed signatures or secret extraction is needed. | Recheck abort state atomically at the reveal boundary and define how acknowledgement applies to an already-created session. Combine lock design with 248006. |
| 247990 | Inherited ACLs expose unrevealed host randomness | **Credible hardening/residual; severity depends on local-user threat model.** Plaintext rho at rest is already recorded under decisions 5 and P2-F3/P5-F1. | On supported Windows configurations, inspect the effective DACL of the session directory, temp file, and replaced target. Establish the installer/profile directory assumptions and whether another principal actually receives read access. | Prefer owner-restricted directory/file ACLs or defer rho persistence until openings are durably accepted. If other local principals remain out of scope, document the residual rather than accepting High severity. |
| 247991 | File aliases fork protected-signing state | **Credible path/locking hardening if aliases can reach public coordinator paths.** | Inventory all production construction sites and path containment rules. Add safe concurrency tests showing that canonical and alias paths cannot obtain independent locks for the same state. Cover symlinks/junctions where supported; separately assess hard links. | Canonicalize and contain paths before deriving lock identity, reject aliases outside the session root, and document residual hard-link behavior if reliable file identity locking is unavailable. |
| 247992 | Signature rejection is not journaled automatically | **Credible selective-abort lifecycle defect.** | Enumerate every post-reveal `complete` failure. Add tests asserting signer-controlled protocol/cryptographic rejection records exactly one `SIGNATURE_REJECTED` event, while local I/O/programming failures are not mislabeled. Confirm repeated calls are idempotent. | Journal validated signer-caused rejection before returning the original error, with explicit behavior if journaling itself fails. Coordinate with 248004. |
| 247993 | State size cap does not bound allocation | **Credible resource-bound defect.** | Inspect whether `Files.readAllBytes` precedes size validation. Add a bounded test using a sparse/oversized file and assert rejection from metadata or a capped stream before full allocation. Avoid memory-exhaustion testing. | Check file size first and read through a bounded channel/stream while defending against size changes during the read. Convert failures to the domain exception. |
| 247994 | Successful completion writes unreloadable state | **Credible boundary/availability defect.** | Derive the maximum encoded-state equation from every length field. Add small configurable-limit tests proving every successful write can be decoded and reloaded under the same limits. Test exact-boundary and one-byte-over cases without constructing multi-megabyte fixtures. | Enforce aggregate and per-field limits before committing `COMPLETE`, or choose consistent limits that guarantee `write success => reload success`. Preserve the old valid range where possible. |
| 247995 | Standalone verifier omits opening commitment | **Credible public-API contract defect; coordinator path may remain safe.** | Inventory all callers of `reconstructSignedPsbt`. Confirm coordinator validates stage 2→3→4 but the public standalone API cannot prove pre-reveal opening fixation. Add a contract test that the public verification boundary requires the accepted-opening/reveal transcript. | Narrow visibility or redesign the API to require and validate the complete transcript/evidence. Do not weaken mixed-provenance reconstruction. |
| 247996 | Invalid foreign signatures survive completion | **Specification/integration decision.** Preserving foreign multisig signatures is intentional and was required by P6-F1 remediation. | Confirm Drongo does not label foreign signatures as protected evidence. Trace Sparrow combine/finalize/broadcast verification and assert an invalid foreign signature cannot count toward finalization or authorization. Test valid foreign signatures remain preserved. | Reject invalid foreign signatures if it can be done without breaking valid partial workflows; otherwise explicitly define completion as “protected slots verified, foreign partials preserved but untrusted” and require downstream verification. |
| 247997 | Witness UTXO is not bound to outpoint | **Likely standard PSBT trust assumption / availability issue, not Medium confidentiality impact.** | Compare behavior with BIP174 SegWit-v0 signing expectations. Confirm a false witness amount/script produces a signature invalid for the actual coin and cannot authorize a different transaction or forge protected evidence for a wallet-owned prevout. Review whether Sparrow independently knows the prevout. | Document the PSBT-data trust boundary or require non-witness UTXO/wallet-history corroboration when available. Do not reject standard witness-only PSBTs without a compatibility decision. |
| 247998 | Same-JVM contention aborts coordinator operations | **Credible functional/concurrency defect.** | Add a deterministic two-thread test on the same resolved state path and assert serialization or a controlled domain error, never an unchecked `OverlappingFileLockException`. Exercise session and journal paths. | Add a per-canonical-path JVM mutex around the OS lock or translate contention into a bounded controlled result. Verify cross-process locking remains intact and lock ordering is consistent. |
| 247999 | Mutable magic corrupts the global codec | **Clearly valid low-severity API defect.** | Add a reflection/API test establishing callers cannot obtain a mutable reference to framing bytes. Confirm wire vectors remain byte-identical. | Make magic private and immutable in effect; write/compare a private literal or defensive copy. |
| 248000 | Transition validator accepts malformed messages | **Credible public-API validation defect; current byte-ingress coordinator reportedly protected.** | Inventory direct object-form callers. Add tests that each transition validates both complete messages before adjacency/equality checks and returns controlled protocol errors for malformed objects. | Have `validateTransition` invoke full validation (or make the precondition explicit and restrict visibility). Confirm exception precedence and existing negative vectors. |
| 248001 | Unsupported keystores enter anti-exfil sessions | **Credible capability/policy defect, primarily availability.** | Define precisely what `supportsAntiExfil` means for UNSUPPORTED, OPTIONAL, and REQUIRED. Test coordinator creation for capable SeedSigner policies and incompatible models through real call sites. | Reject session creation for a keystore that cannot perform AEXB, while preserving OPTIONAL SeedSigner use. Ensure Sparrow UI and imported-policy behavior remain consistent. |
| 248002 | Verified evidence can be freely forged | **Valid type/API hardening; exploitability depends on trusted in-process callers.** | Inventory every constructor and consumer. Confirm Sparrow accepts proofs only from revalidated coordinator/session paths and never from deserialized or arbitrary plugin input. Add an API-level test preventing external construction. | Use a non-public constructor/factory owned by the verified coordinator path. Keep defensive copies and full equality semantics. |
| 248003 | Journal path drift silently resets history | **V12 marked invalid; retain as configuration-hardening question.** | Verify Sparrow always derives one stable wallet-bound journal path and migrations cannot silently change it. Test the production path derivation rather than hostile direct API callers. | If stable in production, close as invalid/out-of-model. Otherwise add path identity to durable configuration and surface migration explicitly. |
| 248004 | Duplicate aborts exhaust the journal | **Credible bounded-resource/idempotency defect.** | Repeatedly record the same abort through the ordinary API and assert one logical event/count. Verify distinct sessions still count separately and the capacity applies to distinct retained events. | Deduplicate by wallet identity + session ID + PSBT digest + reason, or make recording idempotent per session with clear reason precedence. |
| 248005 | Malformed messages crash equality and hashing | **V12 marked invalid; optional value-object hardening.** | Confirm decoded/untrusted bytes cannot construct such objects and no production caller compares unvalidated object-form messages. | Close as invalid if unreachable. Independently making value objects null-safe or constructor-valid is acceptable cleanup but should not be presented as a security fix. |
| 248006 | Abort check races fresh session creation | **Credible concurrency defect and same root as 247989.** | Add a deterministic barrier-based test around journal check, session creation, and abort append. The invariant is that a fresh unacknowledged session cannot be committed after a wallet abort becomes durable. | Serialize wallet journal check + session creation and abort recording under a documented global lock order (journal before session). Test deadlock freedom and cross-process behavior. |

## Recommended verification and remediation order

### Gate 1 — key-safety blocker

Review and regression-test 247985 first. If confirmed, the existing tested tag
remains immutable evidence but must not be promoted. Implement the narrow
same-signer opening-uniqueness invariant, regenerate any affected shared
negative vectors, and obtain independent review of that isolated diff.

### Gate 2 — reveal/abort state machine

Treat 247989, 247992, 248004, and 248006 as one design cluster. Define these
invariants before editing:

- no rho is returned after an unacknowledged wallet abort;
- the abort check and fresh-session creation cannot race;
- signer-caused post-reveal rejection is durably recorded once; and
- lock ordering is journal → session everywhere.

One coherent design is safer than four local patches.

### Gate 3 — durable files and bounded resources

Address 247986, 247993, 247994, 247998, and 247999. These can be verified with
fault-injection and boundary tests without security PoCs. Reassess 247991 in
the same pass because canonical path identity determines both locking and file
durability behavior.

### Gate 4 — API contracts and integration

Review 247995, 248000, 248001, and 248002 together. Search public and test
callers before changing visibility or signatures. Run the full Sparrow suite
after every Drongo API change and verify the Drongo submodule pin deliberately.

### Gate 5 — explicit threat-model dispositions

Do not silently accept V12's severities for 247987, 247988, 247990, 247996, or
247997. Each requires a maintainer decision about trusted local storage,
rollback, partial-signature preservation, and standard PSBT inputs. Record the
decision in `maintainer-decisions-requested.md` and the residual risk in the
review brief. Close 248003 and 248005 only after their production reachability
checks are recorded.

## Validation and release gates

For each implementation batch:

1. Add regression tests first and record their expected baseline failure.
2. Implement the smallest coherent fix without applying generated V12 diffs.
3. Run focused Drongo anti-exfil tests.
4. Run the complete Drongo suite.
5. Update Sparrow's Drongo pin and run focused provenance/quarantine tests
   whenever behavior or API crosses the repository boundary.
6. Run the complete Sparrow suite, preserving the already documented Windows
   CRLF/LF exception audit if it remains unchanged.
7. Re-run reference/vector cross-implementation tests if wire acceptance,
   slot validation, evidence fields, or PSBT rules change.
8. Ask the independent reviewer to review the exact new commit ranges.
9. Only then create new immutable tested tags and rebuild/freeze the reviewer
   bundle. Existing tags must not move.

No funded transaction or private-key recovery demonstration is required for
these gates. A physical SeedSigner/Sparrow smoke is required only if wire
behavior, the ceremony lifecycle, or coordinator-visible UI behavior changes.
