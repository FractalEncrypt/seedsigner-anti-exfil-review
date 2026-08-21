# AEXT v1 QR Transport

Status: frozen for protocol v1; experimental and not a registered public standard

UR type: `ur:x-btc-anti-exfil`  
Purpose: carry the four anti-exfil protocol messages over animated QR without allowing the signer to replace the coordinator's transaction

## 1. UR and CBOR envelope

The QR payload MUST use UR v2 with the user-defined type `x-btc-anti-exfil`. The
top-level CBOR item MUST be one definite-length byte string containing exactly one
`AEXT` package. The byte-string length MUST use the shortest CBOR representation;
indefinite-length strings, tags, maps, arrays, and trailing CBOR data are rejected.

`x-*` is intentionally used while the protocol is experimental. `ur:bytes` is not
used because BCR-2020-005 reserves it for UR implementation testing. A future
registered type and CBOR tag require coordination with the UR registry maintainers
and must not be introduced as a silent alias for this candidate type.

UR text is case-insensitive. Encoders emit uppercase text for QR alphanumeric mode;
documentation uses lowercase type names.

## 2. AEXT binary package

All integers are unsigned and big-endian.

| Offset | Field | Size | Meaning |
| ---: | --- | ---: | --- |
| 0 | magic | 4 | ASCII `AEXT` |
| 4 | version | 1 | `1` |
| 5 | network | 1 | network code below |
| 6 | stage | 1 | protocol stage `1` through `4` |
| 7 | flags | 1 | bit 0 means PSBT present; all other bits forbidden |
| 8 | message length | 4 | exact length of embedded canonical `AEXB` bytes |
| 12 | PSBT length | 4 | zero when absent |
| 16 | PSBT SHA-256 | 32 | digest of exact PSBT bytes, or 32 zero bytes when absent |
| 48 | message | variable | exact canonical `AEXB` protocol message |
| after message | PSBT | variable | exact frozen PSBT bytes when required |

Network codes are `0` mainnet, `1` testnet3, `2` regtest, `3` signet, and `4`
testnet4. The ambiguous name `testnet` is not a wire-level alias. The
coordinator and signer MUST reject a package whose network differs from the active
user-visible mode. The canonical protocol-v1 vectors and current physical
coordinator use testnet4. The historical single-slot transport fixture retains
its older `testnet` label and is not normative for network semantics.

The outer stage MUST equal the embedded AEXB stage. Unknown networks, stages,
versions, or flag bits are rejected. Message length is limited to 65,536 bytes and
PSBT length to 2,000,000 bytes. Implementations MAY impose a lower operational QR
limit, but must report it as an explicit error.

When present, PSBT bytes MUST begin with `70 73 62 74 ff` (`psbt` plus `0xff`).
The SHA-256 field detects substitution and corruption before PSBT parsing. The PSBT
parser remains responsible for canonical PSBT and transaction validation.

## 3. Stage/context invariant

| Stage | Direction | PSBT rule |
| --- | --- | --- |
| 1 `HOST_COMMIT` | coordinator to signer | MUST be present |
| 2 `SIGNER_OPENINGS` | signer to coordinator | MUST be absent |
| 3 `HOST_REVEAL` | coordinator to signer | MUST be present |
| 4 `SIGNER_SIGNATURES` | signer to coordinator | MUST be absent |

The signer therefore never returns a PSBT or transaction for the coordinator to
trust. After stage 4, the coordinator verifies the anti-exfil opening and ordinary
ECDSA signature, then imports only the expected signature into its own frozen
original PSBT. A response containing a PSBT is structurally invalid.

This transport rule complements, but does not replace, transcript validation:
session, sighash, signer key, commitment, opening, reveal, signature, and stage are
validated by the protocol controller.

## 4. Animated QR behavior

SeedSigner's vendored UR2 fountain implementation is the reference codec for the
prototype. Density fragment sizes are 10 bytes (low), 30 bytes (medium), and 120
bytes (high), matching SeedSigner's existing fountain QR settings.

An animated sender MUST continue producing fountain parts until the receiver
confirms completion or the user cancels. It MUST NOT stop after the first pure
fragment sequence: missed, reordered, and duplicated scans can require later mixed
recovery parts. The terminal helper emits two fountain windows to model this; the UI
will use a live encoder rather than a finite list.

The receiver MUST lock onto the first valid UR type and reject mixed types. It then
performs, in order: UR/Bytewords/fountain validation, canonical CBOR byte-string
validation, AEXT header and length validation, digest validation, AEXB validation,
stage/context validation, active-network validation, and finally PSBT parsing.

## 5. Retry and downgrade rules

Transport or scan failure MUST bubble up to the user. The coordinator MUST NOT
automatically create a new anti-exfil session, new host randomness, or a modified
transaction. Retrying the same scan may continue the same UR fountain stream and
the same protocol transcript.

A regular signing path MUST route a recognized `x-btc-anti-exfil` package only
into the protected flow when policy permits it; it MUST NOT reinterpret it as an
ordinary PSBT. A stage-restricted protected scanner MUST reject ordinary PSBT QR
types. Unknown versions are not downgraded.

## 6. Interoperability vectors

`fixtures/transport-v1-vectors.json` preserves historical single-slot
physical-prototype packages and is not normative for current slot/network
semantics. `fixtures/protocol-v1-multislot-vectors.json` pins all four canonical
multi-slot AEXB messages, PSBT-present and PSBT-absent AEXT packages, SHA-256
digests, canonical CBOR, and complete first-window medium-density UR2 parts. A
Sparrow/Java implementation must reproduce those bytes exactly before integration
is considered interoperable.
