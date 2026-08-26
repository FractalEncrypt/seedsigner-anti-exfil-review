# Anti-exfil conformance matrix

Two implementations of the same sign-to-contract construction, plus a device
survey. This records what is actually verified today and what is still empty.
Nothing is filled in speculatively.

**Reconstruction notice.** Sections 2 and 4 were lost when the original was
posted as a comment — the render swallowed them and the source is gone. They are
rebuilt here from the underlying work rather than recovered, so treat their
wording as new and their claims as needing a second look. Section 1 and section 5
are the original text with corrections applied. Section 3 was always empty.

**Evidence columns.** Every claim carries how it is known:

| code | meaning |
|---|---|
| C | claimed by the implementer |
| I | code-inspected |
| V | vector-tested |
| S | simulator-tested |
| P | physically tested on hardware |
| X | cross-implementation tested |

A claim with only **C** is an assertion. A claim reaching **X** is settled.

## Implementations

- **J** — Jade firmware + lark + Sparrow (bitcoinshooter). ECDSA, libwally
  (`wally_ae_*`) on device, Java verifier host-side. In-PSBT `0xFC` carrier.
- **F** — FractalEncrypt reference oracle + SeedSigner/drongo/Sparrow forks.
  ECDSA, pure-Python reference plus a native secp256k1-zkp backend. Detached
  AEXT/AEXB carrier.

---

## 1. Crypto layer (s2c construction)

| behaviour | J | F | agree? |
|---|---|---|---|
| `tagged_hash("s2c/ecdsa/data", rho)` = host commitment | yes (I,V) | yes (I,V) | yes |
| `t = tagged_hash("s2c/ecdsa/point", R0‖rho)` | yes (I,V) | yes (I,V) | yes |
| `R = R0 + t*G`, accept iff `sig.r == R.x mod n` | yes (I,V,P) | yes (I,V,P) | yes |
| tweak >= n rejected, not reduced | yes (I,V) — `9a73487` | yes (I) | yes |
| tweak == 0 rejected | yes (I,V) | (C) | pending |
| host entropy must be 32 bytes | yes (I,V) | yes (I) | yes |
| opening must be a valid curve point | yes (I,V) | yes (I) | yes |
| full ECDSA validity required before accepting | yes (I) — at protocol layer | yes (I) — in the verifier | semantics agree, placement differs |
| signature encoding | DER, strict, low-S enforced (I,V) | compact `r‖s`, reconstructed to strict DER with sighash byte (C) | profile difference over the same semantics |
| scalar ranges `r` and `s` each in the range 1 to n-1 | yes (I,V) | yes (C) | yes |
| low-S required | yes (I,V) | yes (C) | yes |

**Corrections against the previous version of this table.** The tweak fix is
pushed, not unpushed. The ECDSA-validity row is no longer a disagreement: both
require it before accepting, and what differs is whether the check sits inside
the verifier entry point or one layer above it. The signature-encoding row is no
longer a disagreement either — compact and DER are two encodings of the same
`(r, s)`, and the scalar rules match.

**J's published corpus:** `vectors/lark-ae-ecdsa-crypto-v1.json` at `17232c7` on
`bitcoinshooter/lark`, branch `jade-anti-exfil-airgap`. 18 crypto-layer cases —
8 honest, 8 signer-ignored-entropy, 2 mismatched pairings — plus 4 tweak
boundary cases. `expected_ecdsa` and `expected_combined` are null throughout,
because these came from libwally primitives rather than a signed transaction and
carry no pubkey or message hash.

An independent checker ships in the same commit at `vectors/check_vectors.py`,
sharing no code with the Java verifier.

**F's corpus:** to be extracted from inline cases into a standalone fixture,
carrying the full tuple including `message_hash` and `pubkey`. Not yet
published.

---

## 2. Protocol layer (session semantics)

*Reconstructed section — wording is new, claims need checking.*

| behaviour | J | F | agree? |
|---|---|---|---|
| message count | 4 (two rounds, host-first) | 4 | yes |
| signer stateless across messages | yes (I,P) — R0 deterministic in (privkey, sighash, host_commitment) | yes (C) — message 3 re-carries the frozen request | yes |
| host commitment re-sent at reveal | yes (I,V) | yes (C) | yes |
| signer rejects mismatched commitment at reveal | yes (I) | (C) | pending |
| signing during the commitment round rejected | yes (I,V) | (C) | pending |
| host entropy pinned per session, never redrawn on retry | yes (I,V) | yes (C) | yes |
| changed signer opening on retry rejected | yes (I,V) | yes (C) | yes |
| identical reply on retry accepted | yes (I,V) | (C) | pending |
| transaction binding | txid pinning (I,V) | `SHA256(frozen PSBT bytes)` (C) | **no — F is stricter** |
| transcript binding across messages | no | (C) | not yet defined jointly |
| reply missing AE fields fails closed | yes (I,V) | yes (C) | yes |
| all-or-nothing per session | yes (I) | (C) | pending |
| multisig: multiple signers per input | untested | yes (P) | pending |
| mixed protected / unprotected inputs | untested | (C) | pending |
| coordinator session survives restart | no — in-memory, capped at 16 | no — resets on restart | both incomplete |

**J's session evidence:** `AntiExfilSessionTest`, 12 tests, fixtures are the
recorded testnet4 PSBTs rather than synthesised. Covers transaction pinning on
both replies, signing during round 1, a reply with no commitment, entropy
stability across rebuilds, changed-commitment-on-retry rejection, identical-reply
acceptance, round 2 field contents, a signature bound to different entropy, an
honest full-session replay with the recorded entropy injected, and the same
replay with altered entropy required to fail.

**The persistence row is the significant gap on both sides.** Neither coordinator
survives a restart before entropy reveal. Agreed direction: fail closed before
revealing host entropy when secure persistence is unavailable. Four sub-problems
named and unresolved — unencrypted wallet files, crash-atomic writes, backup
rollback presenting stale state as current, and what evidence of an aborted
session is safe to discard and when.

---

## 3. Vector exchange

Empty. Fills in when both corpora exist and both implementations have run both.

| step | status |
|---|---|
| J publishes 18 crypto vectors as JSON | done — `17232c7` |
| F extracts crypto-layer fixtures | pending |
| J runs F's corpus | blocked on the above |
| F runs J's corpus | unblocked |
| results merged here | pending |

The layer mismatch that blocked this is resolved by agreement rather than by
code: F's published fixtures were protocol-layer AEXB envelope hex with error
codes, which J cannot run without an AEXB parser. Corpora are now split into
crypto, semantic-protocol, transport, and integration-evidence tiers.

---

## 4. Device survey

*Reconstructed section — the criteria and findings are from the original code
review; the table is rebuilt.*

Three criteria: does the device parse the PSBT itself, does its library preserve
unknown proprietary fields, and does anything discard them after signing.

| device | PSBT plumbing | evidence | needs |
|---|---|---|---|
| Jade | works | P — round-trip proven on hardware | done for ECDSA |
| Coldcard Mk4 | works | I — own parser stores `self.unknown`, re-emits | protocol only |
| Keystone 3 Pro | works | I — `rust-bitcoin` `Psbt`, no trim step | protocol only |
| Passport Core | works | I — MicroPython parser, store and re-emit | protocol only |
| SeedSigner | strips | I — `PSBTParser.trim` rebuilds from raw tx | trim fix + protocol |
| Krux | strips | I — `sign(trim=True)` allow-list | trim fix + protocol |
| Specter-DIY | strips | I — `clear_metadata` via `compress=` | compress change + protocol |
| BitBox02 | not applicable | I — host decomposes to protobuf | nothing; has anti-klepto over its RPC |

**Not checked:** Trezor, Ledger (both believed host-decomposing like BitBox02,
both have RPCs), SafePal S1, NGRAVE ZERO, Tangem. Passport Prime is a separate
codebase from Passport Core and was not reviewed.

**Pattern worth noting:** the three devices that strip unknowns are the three
most constrained ones, and all three strip for QR density rather than by policy.
Which means the carriage question and the hardware-constraint question are the
same question.

**F's SeedSigner adapter**, offered rather than landed, would recognise and
validate specifically the `ae` fields and preserve only those, rather than
passing unknown data through generically. Both parties agree generic passthrough
is the wrong default for a signing device.

---

## 5. Taproot / Schnorr

Empty, for everyone. secp256k1-zkp has `ecdsa_s2c`; `schnorrsig` has no s2c, no
anti-exfil entry points, no opening type. libwally's `wally_ae_*` is ECDSA-only.
No public proposal found in zkp issues or on Delving.

**Out of scope for ECDSA anti-exfil v1**, by agreement. No shared semantics are
reserved for it here — reserving structure for a construction nobody has
evaluated would be specifying against a guess. J's carrier keeps a reserved
subtype range as a local implementation detail, withdrawn as a proposal for
anything shared.

---

## What would fill this in

1. F extracts crypto-layer fixtures carrying the full tuple.
2. Both implementations run both corpora; section 1 completes and rows reach **X**.
3. The transport-neutral four-stage state machine is drafted, so section 2 has
   something to be conformant *to* rather than two implementations compared to
   each other.
4. Transaction binding is settled — txid pinning versus frozen-request hash.
5. Persistence semantics are specified, and the restart gap closes on both sides.
6. F's SeedSigner adapter lands; J's carrier gets tested on a second device and
   section 4 gains a **P** outside Jade.
7. Multisig and mixed-coverage rows gain evidence; both are currently untested
   on J.
