# M9 P1–P3 integration candidate

This document summarizes the local integration work incorporated into the v2
review-hub candidate. The authenticated P1/P2/P3 packages remain the detailed
evidence; this file intentionally excludes raw local logs and private paths.

## P1 — Drongo synthesis

Candidate `948f586f0e523e0ef67d973a72eac67aa8148968`, tree
`d5943708b3cb71779e7c2cd5fbf931dcf67e54d4`, starts at the August hardened
head and integrates all five M8/Kern Drongo changes. Four are patch-equivalent
cherry-picks; the foreign-session rejection change is a semantic cherry-pick in
the already-hardened validation context.

Verification: focused anti-exfil plus `KeystoreTest` 58 pass / 1 skip; unfiltered
Windows 487 pass / 2 known platform-only XDG failures / 1 skip; exact applicable
Windows run 487 pass / 0 fail / 1 skip. P1 inventory SHA-256:
`8636e54c2128fc671ca7ef7ff42078abf9d54c166b55a6c9dbd4f4fea353d27b`.

## P2 — Sparrow synthesis

Candidate `cc760814c855dfaf3d27890d10ba86b635e3a033`, tree
`6ce0ff0953560008e1832929540e5c2ebdb5b042`, starts at the August hardened
head, integrates all thirteen M7/M8 Sparrow changes, pins P1 Drongo, and retains
Lark `ddffe556f0d1ba6a138be3b362ce74219fed0710`.

Two conflicts retained both safety layers: final-action provenance plus PSBT
egress quarantine, and pending-completion blocking plus provenance validation.
A test-only compatibility repair obtains genuine proof through the deterministic
coordinator and does not restore Drongo's removed public proof constructor.

Verification: focused protected suite 73/73; applicable Sparrow 192/192;
applicable Drongo 487 pass / 1 skip; Lark 1/1; `installDist` and clean-root
`jpackageImage` pass. The four unfiltered Sparrow Windows failures are exact
CRLF/LF export comparisons; the two unfiltered Drongo failures are the known
non-Windows XDG tests. P2 inventory SHA-256:
`8c1a50fdff38381c7d735c1ffeae21034789d7ed5da8345cc3e8329dd86f993c`.

## P3 — signer repositories and reviewer builds

SeedSigner and SeedSignerOS remain at accepted public tags. Kern candidate
`bc382c2c458e81230b5c0c434cd5b2219eef76b6`, tree
`196a182647ded7825d0f3e524d72a611add70950`, has parent
`5180dbb603e01e33698bb388a400f92bff722d4c`, the M8-accepted product source.

P3 found that three public JSON corpora were historically pinned by SHA-256 over
their original CRLF bytes while Git stored LF-normalized blobs. The test-only
Kern commit adds path-specific `-text` attributes and commits the already-pinned
original bytes. JSON objects and LF-normalized content are identical; no C
product source or build configuration changes. A clean Linux checkout passes
all fixture-freshness and host suites. P3 manifest SHA-256:
`f78099d7ae6b5468e95f8ec066414906181ee276a673cde0e78c7be5310b12b7`.

## Publication and later hardening state

The reviewed v2 identities were subsequently published, with the review hub at
commit `88c92b062e6abb7aba5190235d4b2ec8de9c1a6f`. This document remains the
historical P1–P3 integration record.

Later M9 hardening did not rewrite those public identities. It introduced an
H3 Kern dependency-repair candidate and separate source-modifying telemetry and
diagnostic evidence branches. Their identities and the bounded closure are in
[m9-hardening-closure.md](m9-hardening-closure.md). Only H3 is a product-repair
candidate; the measurement and diagnostic branches are not proposed for
production or publication.
