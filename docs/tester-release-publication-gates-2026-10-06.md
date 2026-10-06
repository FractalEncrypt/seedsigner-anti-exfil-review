# Remaining release publication checks

The repaired Sparrow source is integrated and the Windows package contents
match the physically tested application and launcher. Original firmware and
review artifacts remain unchanged. The final prereleases are being assembled;
they are not yet public.

## Completed

- Reviewed/tested source tree published at Sparrow bdca6753, identical to built
  a132668f. The original three commits remain local because GitHub rejected their
  private email metadata; publication copies use the public noreply identity.
- Repaired application ZIP and fresh-profile addon authenticated; the operator
  confirmed the laptop checksum. Convenience ZIP contains only those exact bytes.
- Both firmware sets' M1 results reconciled with the repaired app, without
  assigning success to original frozen Sparrow. Earlier signing/rejection/recovery
  evidence retained. Current physical matrix limits explicitly recorded.
- Exact fork/submodule source exports refreshed for repaired Sparrow.
- Tor resource 408.21.0 source plus all five pinned native source archives collected.
- ESP-IDF v6.1/v6.0.2 retained source and submodule inventories collected; Java
  dependency source JARs and inherited POM license records collected where available.

## Still open

1. Complete the native/shaded dependency mapping: bokmakierie 1.0 includes
   minimized BoofCV dependencies; bwt-jni 0.1.8 and Sparrow's hid4java 0.8.1 have
   no published Maven source JAR; fetched upstream snapshots must not be
   represented as authenticated exact binary sources without further mapping.
   USB4Java's native dependency notices/source and the Tern notice must also be
   reconciled. Public project license texts alone do not identify every bundled
   native/shaded component.
2. Recover the JavaCSV 2.0 LGPL source/notices. The original project's currently
   listed SourceForge download is 2.1; attempted guessed 2.0 URLs returned 404.
   Do not silently substitute 2.1 source for 2.0.
3. Bind Kern's managed-component source/notice export and exact IDF versions to
   the frozen and post-sync firmware build records. An exported toolchain image
   is useful evidence, not by itself proof of the firmware's build identity.
4. Finish the final source/license inventory, asset manifest/checksums and guide
   consistency checks, then verify the complete draft before immutable publication.

These are release-artifact checks, not a request to repeat the physical test
campaign. No personal signing key or GitHub Actions build provenance is claimed.
GitHub immutable-release/asset attestation verification follows actual publication.
