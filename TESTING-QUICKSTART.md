# Novice testing quickstart

Start with [Download and test](docs/download-and-test.md). It walks through
verification, SeedSigner flashing, Kern flashing, repaired Sparrow startup,
and offline public-fixture tests in order. Windows testers do not need Git,
Java, Docker, WSL, a server connection, or testnet coins for this route.

Use the current repaired **post-sync Windows** tester set. The frozen archive
preserves historical artifacts with [known Sparrow limitations](docs/frozen-sparrow-erratum-2026-10-06.md);
it is not the recommended application for new tests. See
[current qualification](docs/tester-release-status-2026-10-06.md).

If devices are flashed and the repaired application is already set up, continue
with [Offline laptop tests in execution order](docs/offline-public-fixture-testing.md).
It includes recovery tests inline. Use public seeds only; never broadcast its
synthetic transactions. A result mark and optional photo are enough.

For tests with actual disposable testnet coins and broadcast, use the separate
[singlesig and multisig live guide](docs/end-to-end-testnet-testing.md) after setup.
Full source builds remain documented for [Windows](docs/build-from-source-windows.md)
and [Linux](docs/build-from-source-linux.md); repaired Linux desktop/package
qualification is still pending.

[Publication status](docs/tester-release-publication-gates-2026-10-06.md) distinguishes
completed testing from remaining release-artifact checks.