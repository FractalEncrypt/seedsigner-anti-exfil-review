# Public optional device, policy and recovery fixtures

Use these with the current tester kit's DEVICE-TESTS.html instructions.
The package places every signing PSBT directly in Test-cases. The manifest
records each fixture's SHA-256 and transaction identity. No funds are involved;
these fabricated outpoints cannot be broadcast. Public test seeds are identified
in the kit's fixture-manifest.json and accounts TSV.

This archive preserves the r5 PSBT/QR bytes. Synthetic parent .tx references
remain available in the source/reviewer ZIP; they are not signing inputs.
