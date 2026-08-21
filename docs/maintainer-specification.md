# Maintainer specification and integration contract

Status: protocol-v1 review candidate

Audience: SeedSigner, Drongo, Sparrow, UR, and cryptography maintainers

## 1. Objective and claim boundary

Protocol v1 constrains an ECDSA signer's final nonce by combining a
deterministic signer opening with host randomness that is hidden until the
opening is fixed. An honest coordinator accepts a signature only when it is
both ordinary-ECDSA valid and sign-to-contract consistent with the opening and
host reveal.

The intended claim is narrow: a malicious signer cannot freely choose the
accepted final ECDSA nonce when the coordinator is honest, its CSPRNG is sound,
and it follows the four-message state machine. The protocol does not protect a
malicious display, general timing/failure channels, physical side channels,
transaction construction by a malicious coordinator, or colluding endpoints.

The prototype is not a new cryptographic construction. It targets the
Blockstream Research `secp256k1-zkp` ECDSA S2C implementation pinned in
`protocol-v1.md` and requires differential compatibility with it.

## 2. Supported transaction contract

An implementation MUST accept canonical PSBT v0 only and MUST process the
transaction atomically. Protocol v1 supports:

- native P2WPKH;
- P2SH-P2WPKH;
- native P2WSH standard `m-of-n` multisig; and
- P2SH-P2WSH standard `m-of-n` multisig.

Every new protected signature MUST use explicit wire-level ECDSA
`SIGHASH_ALL` (`0x00000001`). A missing BIP 174 sighash field is interpreted as
`SIGHASH_ALL`, but the AEXB record still encodes it explicitly.

Legacy inputs, Taproot, future witness versions, nonstandard witness scripts,
unsupported sighashes, inconsistent UTXO/script data, missing derivations,
pre-existing signatures for a controlled key, or a mixed supported/unsupported
transaction MUST fail the complete ceremony and produce zero new openings or
signatures. There is no partial or ordinary-signing fallback.

## 3. Authoritative signing slots

One slot is `(input_index, signer_pubkey)`, where the public key is the exact
33-byte compressed SEC key derived from PSBT BIP32 metadata. Each implementation
independently derives and validates:

- the prevout amount and script;
- redeem and witness scripts and their hashes;
- full public key and BIP32 origin/path;
- supported script kind;
- `SIGHASH_ALL`; and
- the authoritative BIP143 message hash.

Records are ordered by numeric input index and then unsigned lexicographic
public-key bytes. Duplicate, conflicting, reordered, partial, or extra slots
fail atomically. Limits are 128 slots per ceremony, 16 slots per input, a
65,536-byte AEXB message, and a 2,000,000-byte AEXT PSBT.

## 4. Four-message state machine

| Message | Direction | Required contents | Forbidden contents |
| --- | --- | --- | --- |
| 1 `HOST_COMMIT` | coordinator → signer | frozen PSBT, complete slot set, one host commitment per slot | openings, reveals, signatures |
| 2 `SIGNER_OPENINGS` | signer → coordinator | complete slot set, one canonical opening per slot | PSBT, reveals, signatures |
| 3 `HOST_REVEAL` | coordinator → signer | byte-identical frozen PSBT, accepted openings, exact per-slot host randomness | signatures |
| 4 `SIGNER_SIGNATURES` | signer → coordinator | exact openings and compact low-S signatures | PSBT, host randomness, arbitrary metadata |

Every stage repeats and binds version, network, session ID, PSBT digest, slot
identifiers, public keys, sighash types, message hashes, and host commitments.
Adjacent stages may differ only in their defined stage-specific fields.

The signer validates all of message 1 before emitting message 2 and validates
all of message 3 before emitting message 4. The coordinator atomically accepts
all openings before revealing any host randomness and verifies all signatures
before importing any of them.

## 5. Cryptographic checks

For each slot, the host generates an independent 32-byte `rho` with a CSPRNG
and commits with `TaggedHash("s2c/ecdsa/data", rho)`. The signer derives its
base nonce with the pinned libsecp256k1 RFC6979 procedure using that commitment
as additional data and returns `R0` before learning `rho`.

After reveal, the signer recomputes the commitment and deterministic opening,
then signs with the S2C tweak defined in `protocol-v1.md`. The coordinator MUST:

1. parse the canonical compact low-S signature and compressed opening;
2. verify the S2C relation between `R0`, `rho`, and signature `r`; and
3. perform ordinary ECDSA verification for the authoritative message hash and
   public key.

Passing only one of the two signature checks is insufficient.

## 6. Frozen transaction and reconstruction boundary

The coordinator freezes the exact PSBT-v0 bytes before message 1. Messages 1
and 3 carry those identical bytes and their SHA-256 digest. Messages 2 and 4
carry no PSBT. A signer-returned PSBT is structurally invalid rather than a
candidate for sanitization.

Completion starts from a copy of the frozen original. The coordinator adds only
the verified DER-encoded signatures plus sighash byte `0x01` for the expected
slots. It never merges signer-controlled maps, unknown records, changed UTXOs,
scripts, outputs, derivations, or final transaction data. Completion MUST NOT
broadcast; it returns to the coordinator's normal final-review and manual
broadcast boundary.

## 7. Retry and selective-abort contract

Before message 2 is accepted, an unused session MAY be cancelled and replaced;
that is recorded as pre-reveal and is not a selective-abort event.

After accepting message 2, the coordinator MUST durably persist the immutable
session before showing message 3. Every retry reuses byte-identical message 3:
same PSBT, session ID, ordered slots, commitments, openings, and `rho` values.
Mutation, fee bumping, key replacement, subset retry, or a nominally new
session is not a retry.

After message 3 has been disclosed, failure to receive and verify message 4 is
a post-reveal abort. The coordinator retains the exact session, journals the
event against wallet-key identity rather than device instance, and warns before
allowing a fresh challenge. Restoring the same keys on another device does not
erase the history. Repeated failures require escalating guidance toward moving
funds to independently generated keys.

## 8. Network and transport contract

AEXB and AEXT use explicit codes for mainnet, testnet3, regtest, signet, and
testnet4. The outer and inner values MUST match. Because SeedSigner's stock UI
uses one public-test-family selection, it may accept testnet3, signet, or
testnet4 while preserving the exact coordinator code in responses; no network
menu modification is required.

AEXT is a definite-length canonical CBOR byte string transported as
`ur:x-btc-anti-exfil`. The receiver validates UR/fountain framing, canonical
CBOR, AEXT lengths and digest, AEXB codec and stage, network, and finally PSBT
semantics. Unknown versions or ordinary PSBT QR types never downgrade.

## 9. Device-neutral capability and policy

Protocol recognition is based on AEXT bytes, not a hardware brand. Each
air-gapped keystore has one policy:

- `UNSUPPORTED`: the signer is not declared compatible; Protected QR is not
  offered for it.
- `OPTIONAL`: the signer is compatible and Protected QR is available.
- `REQUIRED`: every attributable supported signature must arrive through a
  verified protected session; ordinary signed returns are rejected.

SeedSigner imports default to `OPTIONAL`. Other brands remain unchanged and
must be explicitly marked compatible; this is a user/implementation declaration,
not automatic device discovery. Existing required SeedSigner wallets migrate
without losing their policy. A required signed return that cannot be attributed
from its stripped metadata MUST fail closed using the original unsigned PSBT as
the authoritative signer context.

## 10. Repository ownership

Drongo owns protocol truth: AEXB codec, public cryptographic verification,
PSBT-v0 semantics, slot enumeration, sighashes, reconstruction, and durable
coordinator state primitives. It has no JavaFX, camera, or broadcast dependency.

Sparrow owns host interaction: CSPRNG use, session/journal file placement, AEXT
and UR, camera/display dialogs, wallet persistence and migrations, chooser and
policy UX, final review, and its existing manual broadcast action.

SeedSigner owns signer interaction: policy enforcement, transaction review,
matching seed/key selection, native secret-key S2C operations, stateless
message-3 recovery, and QR display/scanning. SeedSignerOS owns the pinned native
package and image integration.

The Python workspace is an oracle and test coordinator. Its pure-Python crypto
is test-only and non-constant-time; production signing uses the native library.

## 11. Error and downgrade requirements

Codec, semantic, policy, transcript, cryptographic, or durable-state errors
MUST stop the protected flow and produce no partial result. Required policy
MUST disable ordinary-signature acceptance, not merely prefer the protected
button. A system exception is a defect: malformed adversarial inputs should
reach a stable protected-signing error before stock transaction-review parsing.

Transport noise may be retried only within the same transcript. Scanner startup
frames from a previous dialog are ignored, incompatible early fountain streams
may reset before meaningful progress, and duplicate cosigner xpub imports are
rejected independently.

## 12. Interoperability and release gates

An implementation is interoperable only if it reproduces the canonical files
in `shared-vector-index.md` byte-for-byte and passes semantic mutation tests.
A release additionally requires:

- native-library and supported-platform review;
- complete project regressions without unexplained new failures;
- physical honest and rejection ceremonies;
- exact post-reveal retry and ordinary-signature downgrade gates;
- normal production-image boot;
- manual review before any Testnet4 broadcast; and
- independent maintainer/security review of the construction and integration.

The current prototype meets the recorded local and physical gates. It is not
presented as production-ready or independently audited.
