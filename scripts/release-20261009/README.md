# October 9 tester fixture generation records

These are the exact scripts used to generate and validate the fresh public
fixtures. They refer to the original staged r4/r5 run directories; they are
preserved as build provenance, not a standalone portable regeneration command.
The full source/reviewer archive retains those inputs and native checks.

The corresponding signing fixtures and their manifest are committed under
fixtures/tester-20261009. The tester package exposes these files directly under
Test-cases. All PSBT and QR payloads are the physically tested r5 bytes.
The manifest also contains optional reserves; no physical result is claimed for
an unused reserve merely because it is included. Existing protocol sources and
frozen vectors retain their earlier repository identities.
