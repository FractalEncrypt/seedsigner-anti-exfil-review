# Experimental Windows tester kit

This Windows tester kit uses exactly the Sparrow engine, native DLLs,
launchers, SeedSigner image and Kern firmware that completed the r5 physical series.
The public presentation and package layout were updated after that series.

Reported coverage includes protected singlesig on both devices, multisig in both
signer orders, Required/Required and Required/Optional policy enforcement, proof
persistence across restart, exact-session retry, stale responses, protection
settings, all 13 device rejection cases on both devices, network/profile restart,
and Testnet3 singlesig and multisig. Saved signatures and completed Testnet3
protected transcripts were revalidated using the packaged runtime. These results
are maintainer observations and local verification; they are not an independent
human security audit or evidence of Jade compatibility. Jade integration remains
separate from this release.

Public seed fixtures are fabricated offline transactions; do not broadcast them.
Use public seeds only with disposable testnet coins and never with real funds.
For live tests follow the live guide.

The source, build inputs and detailed review records belong in the separate
reviewer/source delivery. This tester ZIP is not a corresponding-source archive.
Its manifest binds that source delivery to the tester assets.

Microsoft and Tor notice closure was independently accepted on October 8, 2026.
The complete accepted licenses directory is retained byte for byte, including
Microsoft terms and the Tor historical-toolchain caveat. No IDE installation or
additional license dialog is needed to run this package. See the Microsoft and Tor directories under licenses/.

The launcher stores its test profile outside the extracted ZIP at
%LOCALAPPDATA%/AexTest/native-crt-20261008. Preserve that entire directory when
cleaning old Downloads packages: it contains wallets, history and signing state.
