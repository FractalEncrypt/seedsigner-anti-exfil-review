# V12 Gate 1 implementation review brief

Status: primary implementation approved in Phase 11; two non-blocking review
observations closed in isolated follow-up commits; narrow follow-up review
requested; no new tested tags authorized yet.

Date: 2026-08-21

Finding: V12 `#247985` — duplicate signer openings across slots using the same
signing key.

No private-key recovery proof of concept was created or executed. The review
and regression evidence is limited to the required fail-closed invariant:
unsafe message 2 is rejected before the coordinator can return host
randomness.

## 1. Exact review ranges

| Component | Base | Head | Branch | Commits in range |
| --- | --- | --- | --- | --- |
| Reference/spec/vectors | `dd7b2b26ece992f74daeb3095aa148fc278176ea` | `eb1542e228fc8ab6904810b1eeef79bb47b3f5dd` | `codex/v12-gate1-opening-uniqueness` | `eb1542e Reject repeated signer openings per key` |
| Drongo | `1bbafd94f08fd9105e20be30a6fdfe9a091fb675` | `67127fd3d88cc1f448c202ec82e824c1fe0c5f54` | `codex/v12-gate1-opening-uniqueness` | `67127fd Reject repeated signer openings per key` |
| Sparrow | `7674cecde48335e0b55454f6fa53c8187a459932` | `e6e38b9153d96387b850109d58a34ea8653951a6` | `codex/v12-gate1-opening-uniqueness` | `e6e38b9 Pin repeated-opening rejection` |

Suggested review commands:

```powershell
git diff dd7b2b2..eb1542e
git diff 1bbafd9..67127fd
git diff 7674cec..e6e38b9
```

The Sparrow head pins Drongo exactly at
`67127fd3d88cc1f448c202ec82e824c1fe0c5f54`.

## 2. Confirmed defect and required invariant

At the reviewed Drongo base, message validation enforced unique slot
identifiers, host commitments, and host reveals, but did not enforce signer
opening uniqueness across slots. The same canonical signer public key may
legitimately occur on multiple input slots. If a signer repeats one opening
point for two such slots, the coordinator previously accepted the complete
message and proceeded to construct message 3 with distinct per-slot host
randomness.

The agreed v1 invariant is now:

> Within one complete message at stage `SIGNER_OPENINGS` or later, opening
> encodings MUST be unique among slots sharing the same canonical compressed
> signer public key. Reuse under that key is `OPENING_MISMATCH`, and the entire
> message is rejected before any host randomness is returned.

The uniqueness scope is deliberately per signer key. Equal opening bytes under
different signer public keys remain structurally permitted because the
confirmed key-safety failure requires reuse under the same private key. A
global rule would add a restriction without a corresponding security benefit.

## 3. Implementation summary

### 3.1 Reference/spec/vectors

Range: `dd7b2b2..eb1542e` — seven files, 236 insertions.

- `src/anti_exfil/protocol_v1_codec.py`
  - `_validate_message` maintains a set of openings per canonical signer
    public key.
  - A repeated opening in one key's set raises
    `ErrorCode.OPENING_MISMATCH`.
  - The check runs for message 2 and every later stage carrying openings.
- `docs/protocol-v1.md` and `docs/protocol-v1-wire-format.md`
  - add the normative per-key uniqueness and before-rho rejection rule;
  - explicitly avoid global cross-key uniqueness.
- `tests/reference/test_protocol_v1_codec.py`
  - rejects same-key/repeated-opening input;
  - accepts same-key/distinct-opening input;
  - accepts cross-key opening equality;
  - consumes the shared raw AEXB and wrapped AEXT negative vector.
- `scripts/generate_protocol_v1_negative_vectors.py`
  - deterministically generates one host-side, signer-to-host negative case;
  - starts with a structurally valid same-key/two-input message and replaces
    the second opening with the first;
  - records expected `OPENING_MISMATCH`, lengths, and SHA-256 values for both
    raw AEXB and AEXT package bytes.
- `fixtures/protocol-v1-negative-vectors.json`
  - new shared negative-vector file;
  - SHA-256:
    `f5b9d3d21210173bb35da0a0de15705b3bc1d3a3d8ab42a14183c2cd7ee97599`.

The existing positive canonical files were not modified.

### 3.2 Drongo

Range: `1bbafd9..67127fd` — three files, 81 insertions.

- `AntiExfilCodec.validate`
  - groups openings by the already-validated canonical compressed signer
    public key;
  - rejects a repeat within one key's group with `OPENING_MISMATCH`;
  - continues to allow equality between distinct signer keys.
- `AntiExfilCodecTest`
  - pins the same-key repeated/distinct and cross-key cases;
  - consumes the byte-identical shared negative vector.
- Drongo's copied negative fixture hashes byte-identically to the reference
  source of record.

`AntiExfilCoordinator.acceptOpenings()` already calls
`AntiExfilCodec.decode(encodedOpenings)`, and `decode()` calls full
`validate()` before returning. The new invariant therefore executes before
`acceptOpenings()` constructs or returns message 3. No coordinator bypass was
added.

`validateTransition()` was deliberately not changed. V12 `#248000` remains a
separate live API-contract finding for direct object-form callers; it does not
bypass the coordinator path because coordinator ingress is decoded and fully
validated first.

### 3.3 Sparrow

Range: `7674cec..e6e38b9` — Drongo submodule update plus two test files.

- pins Drongo from `1bbafd94` to `67127fd3`;
- adds the byte-identical shared negative vector to Sparrow's host-side test
  resources; and
- verifies `AntiExfilTransportPackage.decode` rejects the wrapped AEXT case
  with `OPENING_MISMATCH`.

This exercises the actual signer-to-host package boundary used by Sparrow's QR
exchange. No Sparrow production class required modification beyond the Drongo
pin.

## 4. Baseline-failure evidence

Before either validator was changed, the new non-exploit regressions failed for
the intended reason:

- Python reference:
  `AssertionError: AntiExfilError not raised` in
  `test_openings_must_be_unique_per_signer_key`.
- Drongo:
  `AntiExfilCodecTest.openingsMustBeUniquePerSignerKey` failed because
  `OPENING_MISMATCH` was not raised.

These baseline failures establish that the tests exercise the missing
invariant rather than an unrelated harness failure. No test calculated or
displayed a recovered signing key.

## 5. Validation evidence

### 5.1 Reference and cross-implementation

Focused command:

```powershell
& .\.venv\Scripts\python.exe -m unittest tests.reference.test_protocol_v1_codec
```

Result: **13 tests, OK**.

Full command with the immutable SeedSigner source explicitly selected:

```powershell
$env:SEEDSIGNER_SRC = "C:\Users\FractalEncrypt\Documents\Windsurf\SeedSigner_AntiExfil_Review_Fresh\src"
& .\.venv\Scripts\python.exe -m unittest discover -s .\tests\reference
```

SeedSigner source head:
`aa8395e3576379467d795bb05268533e3a2ac082`.

Result: **85 tests, OK**.

Vector regeneration:

- positive multi-slot vector, checked in and regenerated:
  `bafd399a342e1be965666d4efca970b50218a2fb2e2820c418ad64686bac1bb3`;
- new negative vector, checked in and regenerated:
  `f5b9d3d21210173bb35da0a0de15705b3bc1d3a3d8ab42a14183c2cd7ee97599`.

Both pairs were byte-identical. The positive semantic fixture was not changed.

### 5.2 Drongo

Focused codec suite:

```powershell
.\gradlew.bat test --tests 'com.sparrowwallet.drongo.antiexfil.AntiExfilCodecTest' --no-daemon
```

Result: **PASS**.

Complete anti-exfil package:

```powershell
.\gradlew.bat test --tests 'com.sparrowwallet.drongo.antiexfil.*' --no-daemon
```

Result: **21/21 passed, 0 skipped**.

Full Drongo suite:

```powershell
.\gradlew.bat test --no-daemon
```

Result: **458/460 passed**. The two failures are unchanged Windows path
expectations in `ApplicationDirTest.testXdgDirs` and
`ApplicationDirTest.testXdgAppliedToMacos`. No anti-exfil test failed, and the
Gate 1 range does not modify `ApplicationDir` or its tests.

### 5.3 Sparrow

Focused host-side package test, forced fresh:

```powershell
.\gradlew.bat :test `
  --tests 'com.sparrowwallet.sparrow.io.AntiExfilTransportPackageTest' `
  --rerun-tasks --no-daemon
```

Result: **PASS**.

Full Sparrow root suite, forced fresh:

```powershell
.\gradlew.bat :test --rerun-tasks --no-daemon
```

Result: **152/156 passed**. The four failures are the previously documented
Windows CRLF/LF fixture comparisons in unchanged tests:

- `CaravanMultisigTest.exportWallet1`;
- `ColdcardMultisigTest.exportWallet1`;
- `ColdcardMultisigTest.exportWalletMultiDeriv`; and
- `SpecterDIYTest.testExport`.

No anti-exfil, transport, policy, provenance, or signing-flow test failed.

## 6. Review properties requested

Please confirm each property explicitly:

1. **Correct scope:** opening uniqueness is per canonical signer public key,
   not global across unrelated keys.
2. **All relevant stages:** message 2, message 3, and message 4 cannot contain
   repeated openings for one key.
3. **Before-rho enforcement:** every production `acceptOpenings` path decodes
   and fully validates message 2 before constructing or returning message 3.
4. **Complete-message failure:** one repeated opening rejects the entire
   message with `OPENING_MISMATCH`; no partial reveal is produced.
5. **No compatibility regression:** legitimate same-key/distinct-opening
   multislot messages pass, and the frozen positive vectors remain
   byte-identical.
6. **Reference/Drongo parity:** both validators implement the same grouping,
   equality, stage, and error-code semantics.
7. **Host integration:** Sparrow rejects the shared wrapped AEXT vector at its
   package boundary under Drongo `67127fd3`.
8. **No accidental #248000 disposition:** the diff does not claim that public
   `validateTransition()` performs full object validation; that finding stays
   open for Gate 4.
9. **No signer-side scope expansion:** SeedSigner does not ingest message 2;
   no SeedSigner/SeedSignerOS code or physical gate is required for this fix.
10. **No unrelated authorization change:** signature-scoped provenance,
    R-F1 quarantine behavior, PSBT reconstruction, and broadcast policy are
    unchanged.

Please report any missing production path, alternate message construction that
bypasses full validation, error-precedence concern, cross-key false rejection,
or fixture mismatch.

## 7. Explicit non-goals and tag disposition

This review covers only V12 Gate 1 / finding `#247985`. It does not remediate
the abort-state cluster, durability/resource findings, public API-contract
findings, or threat-model decisions identified for Gates 2–5.

The immutable 2026-08-20 tested tags remain evidence of the vulnerable reviewed
state and must not move. Do not create or promote replacement tested tags until
this exact Gate 1 diff receives independent approval and public CI is green.

No funded transaction, SeedSignerOS rebuild, or physical test is required for
this validation-only host-side fix.

## 8. Phase 11 observation follow-up

The primary ranges above were approved against all ten §6 properties. The
review recorded two non-blocking observations. Both are closed in isolated
follow-up commits; the reference implementation remains unchanged.

### O1 — cross-implementation check ordering

Follow-up range: Drongo `67127fd..5a7baed`.

Commit:
`5a7baed Align anti-exfil validation precedence`.

Drongo now evaluates commitment uniqueness, reveal uniqueness, and per-key
opening uniqueness before the per-input slot-count limit, matching the
reference order. The change moves the existing two-line per-input check; it
does not change any acceptance condition. A multiply-invalid message now
selects the same first error in both implementations.

Focused validation after the change:

```powershell
.\gradlew.bat test `
  --tests 'com.sparrowwallet.drongo.antiexfil.AntiExfilCodecTest' `
  --rerun-tasks --no-daemon
```

Result: **PASS**.

### O2 — Sparrow fixture growth

Follow-up range: Sparrow `e6e38b9..3eb93d5`.

Commit:
`3eb93d5 Close Gate 1 review observations`.

Sparrow now asserts that the shared `cases` array is nonempty and iterates
every case, decoding each `package_hex` and asserting its declared
`expected_error`. The same commit advances the Drongo submodule from
`67127fd3` to `5a7baed`.

Focused validation against the final pin:

```powershell
.\gradlew.bat :test `
  --tests 'com.sparrowwallet.sparrow.io.AntiExfilTransportPackageTest' `
  --rerun-tasks --no-daemon
```

Result: **PASS**.

### Final candidate heads after observation closure

| Component | Final candidate head |
| --- | --- |
| Reference/spec/vectors | `eb1542e228fc8ab6904810b1eeef79bb47b3f5dd` |
| Drongo | `5a7baed1a2cad23f0f0a4f007d49cdba44415b60` |
| Sparrow | `3eb93d52f856a1851b144e7523aeb658386b1122` |

Narrow follow-up review requested:

1. confirm Drongo's moved check matches the reference error precedence and
   changes no acceptance condition;
2. confirm Sparrow consumes every present/future shared negative case; and
3. confirm Sparrow pins the exact reviewed Drongo follow-up head.

## 9. Review closure, public CI, and immutable tags

Independent follow-up review confirmed both observations closed and approved
the final candidate heads on 2026-08-21. Public Linux CI then ran from
workflow-only child commits so the reviewed candidate hashes remained
unchanged:

| Component | Reviewed source head | CI-only child | GitHub Actions run | Result |
| --- | --- | --- | --- | --- |
| Drongo | `5a7baed1a2cad23f0f0a4f007d49cdba44415b60` | `ac588981f9a0d5502876c849b7de6e26ad754541` | `32528044624` | full suite passed |
| Sparrow | `3eb93d52f856a1851b144e7523aeb658386b1122` | `a2b710f4a4144d38faa894877da35c0f29e833fa` | `32528044427` | full suite passed |

Each CI child differs from its reviewed parent only by
`.github/workflows/gate1-ci.yml`. The tested tags deliberately resolve to the
reviewed source heads, not the CI-only children:

| Component | Immutable tested tag | Tagged commit |
| --- | --- | --- |
| Reference/spec/vectors | `anti-exfil-tested-2026-08-21` (local; the engineering repository has no remote) | `eb1542e228fc8ab6904810b1eeef79bb47b3f5dd` |
| Drongo | `anti-exfil-review-v1-tested-2026-08-21` | `5a7baed1a2cad23f0f0a4f007d49cdba44415b60` |
| Sparrow | `anti-exfil-review-v1-tested-2026-08-21` | `3eb93d52f856a1851b144e7523aeb658386b1122` |

Gate 1 is closed. These tags are an immutable remediation checkpoint; they do
not close the acknowledged V12 Gates 2–5 and are not a production-release
claim.
