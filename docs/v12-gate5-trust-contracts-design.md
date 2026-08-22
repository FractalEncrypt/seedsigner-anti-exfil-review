# V12 Gate 5 trust and compatibility contracts

Date: 2026-08-22

Gate 5 resolves V12 findings `#247987`, `#247988`, `#247990`, `#247996`, and `#247997`. These reports do not share one implementation root: three depend on the already-declared trusted coordinator filesystem, one concerns intentionally preserved multisig state, and one is the standard SegWit witness-UTXO trust model. The dispositions below are explicit maintainer decisions, not silent severity downgrades.

## `#247987` — rollbackable coordinator state

Disposition: **confirmed mechanism; accepted trusted-filesystem residual, not an in-model High vulnerability**.

An authentic older AEXS state cannot be distinguished from the current state using data stored in the same rollback domain. Checksums, authenticated files, tombstones, or a second ledger beside the session file cannot provide freshness against an actor able to roll all of them back together. A complete fix requires a separately trusted monotonic authority with its own lifecycle, recovery, and cross-device design; none is presently available in the product model.

The coordinator state directory therefore remains in the trusted computing base. Backups must not restore AEXS state independently or reintroduce pre-reveal sessions. If rollback or unauthorized replacement is suspected, do not resume protected signing from that state. Treat selective-abort history as unreliable and migrate funds to a wallet generated from fresh independent keys before relying on anti-exfil guarantees again.

## `#247988` — abort-journal deletion or rollback

Disposition: **confirmed mechanism; same accepted trusted-filesystem residual as `#247987`, not Critical**.

Deleting or rolling back AEXJ can erase historical warnings. A random journal identifier could detect deletion only while a non-rolled-back session still binds it; it cannot detect joint rollback or protect the next session after all same-domain evidence is removed. Adding such a partial mechanism would overstate the guarantee.

The abort journal is a wallet-lifetime safety control whose storage must be backed up and restored atomically with the wallet and coordinator state. Missing, restored, or unexpectedly reset history is not evidence of safety. Suspected loss requires the same fresh-key migration response as suspected session rollback.

## `#247990` — inherited Windows ACLs and plaintext rho

Disposition: **confirmed confidentiality precondition; accepted local-storage configuration residual under decision 5**.

Unrevealed host randomness is plaintext durable state. POSIX files are restricted to owner read/write where supported; Java relies on the effective inherited Windows DACL. The supported deployment contract requires the Sparrow state directory to be accessible only to the owning user and trusted system/administrator principals. A different local principal able to read, replace, or roll back that directory is inside the already-excluded filesystem-compromise boundary.

This is not claimed to be encryption at rest. Backups, sync tools, administrator access, malware under the user account, and permissive parent ACLs can expose rho. Maintainers should revisit OS-keystore-backed encryption and explicit Windows ACL provisioning before shipping session inspection/export UX, but an ACL-only patch is not represented as protection from an owner-equivalent or privileged local actor.

## `#247996` — invalid foreign partial signatures

Disposition: **confirmed availability defect; fix in Drongo ingestion**.

Valid foreign multisig partial signatures must remain byte-preserved and must not receive protected-signing evidence. Invalid foreign partial signatures need not be preserved: accepting them consumes a completed ceremony and returns a PSBT that Sparrow later rejects during combine.

`AntiExfilPsbt.parseCanonicalV0` will therefore enable Drongo's existing partial-signature verification at the sole canonical anti-exfil PSBT boundary. An invalid existing partial fails before slot enumeration, randomness generation, or session-file creation. The frozen mixed-provenance vector pins that a valid foreign ordinary signature survives byte-identically while only the protected signer receives evidence.

This does not ask Drongo to authorize the foreign signature or label it protected; it establishes only cryptographic validity against the supplied PSBT signing context.

## `#247997` — witness-only UTXO trust

Disposition: **confirmed standard PSBT trust assumption and availability residual; retain compatibility**.

BIP174 permits SegWit inputs to carry only `witness_utxo`; the previous transaction txid cannot be recomputed from that standalone output. The supplied amount and script are committed by the BIP143 signature hash. If they are false, the resulting signature is invalid for the actual coin; it cannot authorize a different real prevout or forge a valid signature for the wallet's coin.

Protocol v1 retains witness-only PSBT support because requiring every full previous transaction would materially enlarge animated QR payloads and break standard hardware-wallet workflows. When a non-witness UTXO is present, Drongo already binds it to the outpoint and checks consistency with witness UTXO. Sparrow or another caller may corroborate witness-only data with wallet history when available, but absence of such history is not a protocol-v1 rejection condition.

The evidence identity continues to contain the real unsigned-transaction outpoint and the exact supplied BIP143 message hash. It attests to the verified ceremony for that context, not to external chain-state existence.

## Regression and review matrix

1. Invalid pre-existing foreign partial signatures are rejected before coordinator state is created.
2. The valid mixed-provenance fixture still completes; its foreign signature remains present and receives no protected proof.
3. Changing a witness-only amount changes the authoritative BIP143 message hash while leaving the unsigned-transaction outpoint unchanged.
4. The frozen positive vectors remain byte-identical.
5. No AEXB, AEXS, or AEXJ format changes are made.
6. No monotonicity, encryption-at-rest, Windows ACL, chain-state, or fund-safety guarantee is claimed beyond what is implemented.
7. Recovery guidance for rollback, journal loss, permissive storage, and backups is present in maintainer/reviewer documentation.

## Release gate

Gate 5 requires independent review of both the code change and the four threat-model dispositions, followed by public Linux CI. Existing tested tags remain immutable evidence. No final reviewer bundle freeze occurs until these dispositions and validation hashes are recorded.
