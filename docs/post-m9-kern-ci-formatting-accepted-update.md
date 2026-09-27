# Accepted post-M9 Kern CI, formatting, and Wave 7B update

Date: 2026-09-27
Status: Kern source accepted and branch published; this review-hub metadata update remains local and requires independent review before publication

## Identity and ancestry

The original review-hub v2 Kern identity remains immutable historical context:

- commit `bc382c2c458e81230b5c0c434cd5b2219eef76b6`;
- tree `196a182647ded7825d0f3e524d72a611add70950`; and
- parent `5180dbb603e01e33698bb388a400f92bff722d4c`, the M8-accepted product source.

The current accepted Kern source is:

- branch `codex/post-m9-kern-ci-formatting`;
- commit `6894087db687e7febf7ccafe4429d8a0446a3ba5`;
- tree `fb38f6d2b25b588f8f8db0d2d9103f5ce8d6f393`; and
- parent `0e0f853fc2ebca3e7f6901b0ec3934bea3639d68`.

It is exactly six linear commits after `bc382c2…`:

1. `ddd95c4…` — pin and qualify Clang/GCC host sanitizer lanes;
2. `d393a2c…` — pin clang-format 18.1.8;
3. `868e357…` — apply the pinned formatter mechanically;
4. `88a1a4b…` — carry the accepted `esp_video` 2.5 dependency repair;
5. `0e0f853…` — correct the Wave 7B 32 MB image header and remove duplicate
   brightness initialization; and
6. `6894087…` — reject simple-suite sanitizer binaries that lack ASan/LSan
   instrumentation symbols.

No merge commit or telemetry/diagnostic evidence branch is included.

## Accepted evidence

The final independent follow-up review returned **ACCEPTED** with no critical,
high, medium, or low finding.

| Item | Identity |
| --- | --- |
| Remediation evidence manifest | 24,798 bytes; 139 entries; SHA-256 `ffa0d7a241ba165c3fa9eafc1e43cc4cc17fa5a8e1033b5c05c0927aa40390ae` |
| Independent review report | 11,710 bytes; SHA-256 `e570af3b807e6424c2e277646fbf6d4348d9c2c841664dfae4109c40b8789d0d` |
| Independent review inventory | 2,091 bytes; SHA-256 `c1e9510bf438e88f538d7567adf055330524f7bc6c9be4b7a7b76c08e81de18f` |
| Review verifier | SHA-256 `63a04e0600535965d6979912228693698c0ab0eb8179befa8691ce45f08fe6be` |
| Frozen verifier output | SHA-256 `db0a84adbd82cb594fcf781c2e43bb48d7f102cab6e5f28a7b8d8d2a3dd083d9` |

The review independently rechecked Git identities, the complete evidence
manifest, formatter behavior, sanitizer controls/results, generated
configuration, firmware signature, flash log, boot log, artifact hashes, and
absence of private-key material.

## Qualified results

- Pinned clang-format 18.1.8 check: PASS over 377 declared first-party files.
- Mechanical rewrite: token-aware comparison and idempotence checks passed.
- Clang 18.1.8 ASan/LSan: 52 PASS records, zero failures, two repeats.
- GCC 11.4.0 ASan/LSan continuity lane: 52 PASS records, zero failures, two
  repeats.
- Positive controls detected heap out-of-bounds, use-after-free, and leak
  faults in both lanes.
- Every real sanitizer target entered `main` and reported non-zero
  instrumentation symbols.
- Full host tests and pinned formatter recheck passed at the final tip.
- Signed Wave 7B firmware build passed under ESP-IDF 6.0.2.
- `kern.bin`: 1,970,176 bytes; SHA-256
  `0145126b844bee0a6a5dab208ca2834547fe010f2361987e1f5d512c0ff2e283`.
- RSA firmware signature block 0 verified successfully.
- All four flashed regions reported `Hash of data verified.`
- Fresh boot reported 32 MB flash with no image-header size warning and no
  duplicate LEDC/GPIO32 warning.
- Display, GT911 touch, OV5647 camera, 50% backlight, and the anti-exfil
  cryptographic self-test succeeded.

## Retained limitations

- Sanitizer coverage is host-only. It does not cover ESP32-only, camera,
  display, board-driver, or firmware paths.
- The remediation rebuild and physical check covered Wave 7B only; Wave 4B was
  not rebuilt because the semantic remediation touched Wave 7B configuration.
- No cross-host bit-for-bit firmware-image reproducibility is claimed. The
  ordinary per-checkout RSA-3072 firmware-authentication development key was
  used only for local build/verification and was excluded from evidence.
- Physical evidence is one Wave 7B flash/boot session, proportionate to the
  board-specific delta.
- This update changes no M8 interoperability claim and does not transfer old
  physical execution credit to unrelated future source trees.

No additional device testing is required for this review-hub metadata update.
The hub update must be verified device-free and independently reviewed before
its own push/publication is requested.
