# Interoperability and reproduction checklist

Record the reviewer, date, operating system, architecture, and tool versions.
Attach logs and hashes; do not replace discrepancies with inherited PASS labels.

## Source identity

- [ ] Verify every commit/tree in `repositories.json`.
- [ ] Verify Sparrow pins Drongo `948f586…` and Lark `ddffe55…`.
- [ ] Verify SeedSignerOS pins Buildroot `bf2a285…`.
- [ ] Verify all four Kern submodules.
- [ ] Verify Kern candidate `6894087…` is exactly six linear commits after the
      original v2 candidate `bc382c2…`, with the chain recorded in
      `REVIEW-SCOPE.md`.
- [ ] Verify those JSON objects and LF-normalized bytes are unchanged.

## Automated gates

- [ ] Run reference tests and regenerate public vectors in a disposable copy.
- [ ] Run focused and full SeedSigner suites on supported Linux/Python.
- [ ] Run Drongo focused/full tests with JDK 25.
- [ ] Run Sparrow focused/full tests, `installDist`, and `jpackageImage`.
- [ ] Run all Kern host suites, including fixture freshness and independent
      collaboration-corpus checks.
- [ ] Run Kern's pinned clang-format 18.1.8 check and both two-repeat sanitizer
      lanes; require positive-control detection, real-target `main` markers,
      and non-zero instrumentation symbols.
- [ ] Record any platform exclusions by exact method; do not hide the unfiltered
      result.

## Builds

- [ ] Build normal SeedSignerOS Pi Zero image from a clean clone and prove the
      test overlay is absent.
- [ ] Build the explicit instrumented SeedSignerOS image separately and prove
      the test overlay is present.
- [ ] Build Kern simulator without camera; record pinned/fetched LVGL identity
      and host SDL2/mbedTLS versions.
- [ ] Build the relevant Kern board, or the six-board matrix, with ESP-IDF
      v6.0.2 and record managed dependencies/configuration.
- [ ] Record relative artifact name, byte size, and SHA-256 for every image,
      binary, ELF, map, flash manifest, and packaged application.
- [ ] Treat historical hashes as observations unless the entire reproducible
      environment is controlled.

## Protocol interoperability

- [ ] Confirm SeedSigner ↔ reference and Kern ↔ reference against the published
      semantic and transport vectors.
- [ ] Confirm SeedSigner ↔ Sparrow and Kern ↔ Sparrow on disposable public-test
      inputs if physical/UI reproduction is in scope.
- [ ] Confirm wrong profile, wrong network, malformed/trailing data, changed
      session, changed context, duplicate/replayed stage, and invalid signature
      inputs fail closed.
- [ ] Confirm protected completion remains quarantined from export, extraction,
      finalization, and broadcast until verified evidence is present.
- [ ] Confirm no OPTIONAL/UNSUPPORTED route silently becomes REQUIRED-success or
      unprotected fallback.

## Claim discipline

- [ ] Keep deterministic/source results separate from simulator, build, and
      physical observations.
- [ ] Use no production seed, wallet profile, funded mainnet transaction, or
      fixture key reuse.
- [ ] Preserve every M8 residual in the public conclusion.
- [ ] State that M9 candidates are new identities without automatic M8 physical
      execution credit.
- [ ] Report blockers, majors, minors, and residual uncertainty explicitly.
