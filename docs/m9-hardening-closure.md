# M9 bounded hardening closure

Date: 2026-09-26
Status: **CLOSED — BOUNDED COMPLETION RULE MET**

## Scope of this closure

M9 is closed for the experimental, Testnet/public-test-only, off-by-default
anti-exfil review scope. This is an evidence-backed engineering closure, not a
production-security certification, Mainnet recommendation, universal hardware
claim, or assertion that every proposed physical test was run.

The closure was recorded only after a fresh independent hardening review
authenticated the six-file H31 request package, 17 external bindings, the
33-row H01–H33 ledger, and the complete 190-entry H29 evidence inventory. Its
verifier exited 0 with `failures=0` and `RESULT: PASS`.

Independent H31 report:

- bytes: `35522`
- SHA-256: `9129f8dd62a092078e4123033913a8fc3e1a516f277027e9e700e73a10f5fe11`
- verdict: `M9 H31 INDEPENDENT HARDENING REVIEW ACCEPTED — M9 ELIGIBLE FOR SEPARATE OWNER-AUTHORIZED BOUNDED CLOSURE`

Companion H31 identities:

- review inventory: 1,402 bytes; SHA-256
  `57c57e4d2a780f6279e7696676791be95c8f86557c8144f01542482379291350`;
- verifier: 8,446 bytes; SHA-256
  `be98f60e6ef20edad1ca5fc3e9e0d8d1d1d6c8c6562437ea93c50e15509db361`;
- saved verifier stdout: 566 bytes; SHA-256
  `acf3a1c976f393e4dbde7970ca054a417806afd48935873c63834886bf71ed4a`.

The owner then separately authorized this bounded closure and preparation of a
local reviewer-hub update commit. Push and publication remain separately gated.

## Identity separation

These identities serve different purposes and must not be collapsed:

| Layer | Commit | Tree | Meaning |
| --- | --- | --- | --- |
| Published Kern v2 review source | `bc382c2c458e81230b5c0c434cd5b2219eef76b6` | `196a182647ded7825d0f3e524d72a611add70950` | Frozen public starting identity. |
| H3 product-repair candidate | `ac2f1382d62072e3dd150d7626d04b96ff4af89a` | `44413413d87ebb495764307f59ac983a12311adb` | Parent `bc382c2…`; changes only `dependencies.lock` and `main/idf_component.yml`; narrow `esp_video 2.5.*` repair and six-board ESP-IDF 6.0.2 tested-build boundary. This is the only post-publication product-repair candidate. |
| Telemetry evidence child | `1def1b9a6049f3f57f19205e5b20aed4abb13374` | `4193a00544107bea480086febdc762f5cd16a574` | Source-modifying measurement instrumentation for H25/H26/H27/H30; retained for evidence and not proposed for production or publication. |
| H30 case-4 diagnostic child | `5bddd829ae9e284b055b2ea5d9778afdd7fd014c` | `68c3ba177d50df42033a29c83426badfb0083a84` | Compile-time-off-by-default deterministic diagnostic; retained for evidence and not proposed for production or publication. Case 4 was not physically run. |

“Evidence-only” therefore means *not proposed for production/publication*; it
does not mean that the telemetry or diagnostic commits contain no source
changes.

## Final H01–H33 disposition

| IDs | Closure disposition | Exact boundary |
| --- | --- | --- |
| H01–H05 | `SATISFIED_IMMUTABLE` | Published identities, M8 conformance/cell evidence, bounded Gate-5 soak, and Kern baseline retained. |
| H06 | `PASS_WITH_LIMITATION` | GCC 11.4.0 ASan/LSan accepted; Clang 14 address-layout instability remains. |
| H07 | `FINDING` | 51 UBSan misaligned-pointer reports are in vendored libwally ccan SHA/Ripemd code; zero first-party sites. |
| H08–H13 | `PASS_WITH_LIMITATION` | Bounded million-execution fuzz/sentinel campaigns, frozen corpora/settings, and disclosed oracle/whitelist/single-frame limitations. |
| H14 | `PASS_WITH_LIMITATION` | 854 inputs per mode; implementation-informed reference limitation retained. |
| H15 | `FINDING` | Repository format check remains version-dependent. |
| H16–H17 | `PASS_WITH_INFORMATIONAL` | Four clang-tidy widening warnings; two cppcheck style findings. |
| H18–H19 | `PASS_WITH_RESIDUAL` | Simulator/representative builds and headless checks pass; rendered-screen/QR/error-corpus inspection was not run. |
| H20–H21 | `PASS_TESTED_BUILD_BOUNDARY` | H3 supports six ESP-IDF 6.0.2 board builds, 42 firmware/sdkconfig identities, and image-fit evidence; no physical behavior or cross-host identical-image claim. |
| H22 | `FINDING` | Response UR-part strings are freed without explicit zeroing while canonical CBOR is wiped. |
| H23–H24 | `PASS_WITH_LIMITATION` | Bounded source/log audit found no secret/transcript/PSBT/signature logging or new radio/network initialization; not exhaustive runtime/RF proof. |
| H25–H26 | `SUPPORTED_BOUNDED` | One telemetry binary and one offline session support normal-path cleanup and phase/timing coverage only. |
| H27 | `ACCEPTED_BOUNDED_MIXED` | Exact-M3 matrix: 15 complete, 5 timeout non-completions, 32 policy skips; setup-specific M3-200 bracket complete at 208.60 cm and not complete at 213.60 cm; both reviewed 10% occlusions timed out. |
| H28 | `NOT_RUN_OWNER_ACCEPTED_RESIDUAL` | Power/USB fault-injection matrix held; no fault-injection credit. |
| H29 | `PASS_BOUNDED` | One owner-confirmed SD-absent M1–M4 session returned Seedless Home; no card-present/storage claim. |
| H30 | `PARTIAL_PASS_WITH_RESIDUAL` | Cases 1–3 supported; case 4 not run. Diagnostic evidence does not reproduce a genuine setting-change race. |
| H31 | `SATISFIED_INDEPENDENT` | Fresh independent hardening review accepted the consolidated synthesis. |
| H32–H33 | `DEFERRED_LATER_GATE` | Upstream work and Mainnet protected signing require later, separate authorization and review. |

## Retained findings and limitations

Product/source findings remain visible:

- `H1-F-001`: canonical-CBOR empty-byte-string adapter/API hygiene;
- `H1-F-002`: response UR-part wiping policy;
- `H1-F-003`: vendored libwally alignment;
- `H1-F-004`: format-gate/tool-version behavior;
- `H1.2-R-001`: differential reference is implementation-informed;
- `H1.2-R-002`: disclosed H1-F-001 CBOR-fuzz whitelist;
- `H1.2-R-003` / `H2-F-001`: Clang 14 ASan address-layout instability.

`H1-F-005` / `H2-D-LOCK-01` was remedied only for the tested H3 dependency
boundary. The closure also retains all six historical M8 residual limitations:
`R-EVIDENCE-FORM-02`, `R-P04-P05-SCOPE-03`, `R-GATE6-LIMITS-04`,
`R-HISTORY-05`, `R-INTERMEDIATE-TREE-06`, and `R-D-P01-07`.

Physical/evidence limitations remain controlling: H25/H26 cover one binary and
session; H27 geometry and observations are setup-specific and partly
operator-attested; H29 proves SD absent only; H30 case 3 lacks a dialog still;
H28 and H30 case 4 were not run; and H18/H19 rendered inspection was not run.

## Informational observations and resolved packaging defects

These non-blocking items are included for completeness:

- `H3.1-O-001`: the narrow dependency pin is minimal relative to deliberately
  holding ten unrelated components at their frozen versions; newer registry
  versions also existed.
- `H3.1-O-002`: four simulator builds contain two pre-existing host format
  warnings; the zero-warning claim applies only to the six-board firmware
  matrix.
- H25/H26 `F1`: the viewer-resident heap drop is transient and recovered after
  viewer destruction; `F2`: stack high-water marks cover QR-decode and UI
  tasks, not one task; `F3`: one M2 fountain symbol was benignly rejected;
  `F4`: three startup warnings pre-existed; `F5`: source-to-build binding is
  retrospective while device-to-reviewed-binary binding is direct; `F6`:
  `min_free` is cumulative; `F7`: the pre-M1 baseline is correctly excluded;
  `F8`: serial does not carry the ASCII session ID.
- H27 `A-2`: one post-matrix Kern software-reset marker was recorded without
  inventing its human/software cause. H27 `L-1`–`L-6` retain the device-free
  review, operator-prepared geometry/progress attestations, negative nature of
  timeouts, setup-specific bracket, evidence-only hardware identity checks, and
  separation from later gates/publication.
- H30 `O1`: case-3 dialog was not visually captured; `O2`: toggle states are
  operator-reported but dialog-gated; `O3`: the device emitted a 9-hex ELF SHA
  prefix; `O4`: TF untouched/USB retained are operator-reported with serial
  corroboration for USB; `O5`: the observed `POWERON` reset reason is
  consistent with the ordinary EN/RESET-button action.
- `H1.1-F-EVIDENCE-001` is resolved: the stale historical verifier transcript
  is preserved, hashed, and disambiguated by the corrected wrapper/package.
- `H2.1-F-FREEZE-001` is resolved: the previously unlisted content manifest is
  covered by the corrected complete inventory. `H2.1-F-FREEZE-002` (overbroad
  basename exclusion) and `H2.1-F-FREEZE-003` (self-redaction disabling the
  live cross-check) were caught, disclosed, and corrected before acceptance.

## Closure and publication boundary

M9 closure does not authorize or imply:

- production readiness, formal proof, a complete independent human audit, or
  Mainnet/funded use;
- H28, H30 case 4, H18/H19 rendered-inspection, card-present storage, or a
  universal optical/hardware PASS;
- promotion of telemetry or diagnostic branches into product history;
- a push, tag, release, publication, issue comment, upstream submission,
  signing, finalization, broadcast, hardware access, or M4 operation.

This reviewer-hub update is a local committed candidate for independent review.
Its eventual push/publication requires a new exact authorization after that
review.
