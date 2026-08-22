# Threat Model: Air-Gapped Interactive Anti-Exfil v1

Status: maintainer review candidate; implemented prototype, not independently audited

Scope: ECDSA transaction signatures exchanged by QR between a coordinator and an explicitly compatible air-gapped signer

## 1. Security goal

When at least the coordinator is honest and its randomness remains hidden until
the signer has fixed its base public nonce, a malicious signer must not be able
to freely choose the final ECDSA nonce while still producing a response accepted
by the coordinator.

Acceptance by the coordinator requires all of the following:

1. The response belongs to the exact transaction, input, sighash type, signing key, protocol version, and session expected by the coordinator.
2. The ECDSA signature is valid.
3. The signature nonce is consistent with the signer opening accepted before the host randomness was revealed.
4. The returned data contains no unexpected signature or metadata changes that the coordinator imports into its original PSBT.

## 2. Assets

### Primary assets

- Seed entropy and derived private keys.
- Per-signature secret nonce scalars.
- Coordinator randomness before reveal.
- Integrity of the transaction the user approved.

### Secondary assets

- Integrity of the protocol transcript.
- Correct association between an input, signing key, opening, reveal, and signature.
- Coordinator unfinished-session state.
- The user's expectation that anti-exfil is required rather than optional.
- Availability of funds and signing functionality.

## 3. Trust assumptions

### 3.1 Honest coordinator, malicious signer

This is the principal anti-exfil scenario. A compatible signer, including
SeedSigner, may run arbitrary malicious firmware and may know the user's entire
seed. The coordinator is assumed to:

- generate unpredictable host randomness;
- keep it secret until accepting the signer opening;
- verify the complete transcript;
- reject failed or missing verification;
- prevent downgrade; and
- sanitize the returned PSBT.

### 3.2 Malicious coordinator, honest signer

The coordinator may choose malformed commitments, change transactions between rounds, replay sessions, or attempt to induce nonce reuse. An honest signer must:

- derive its base nonce deterministically from the exact signing context and host commitment;
- recompute the opening during the reveal round;
- produce no signature if the transaction, commitment, reveal, key, sighash, or protocol stage is inconsistent; and
- never reuse one base nonce with two different valid host revelations.

This protocol does not make a malicious coordinator safe to use for transaction construction. The user still relies on SeedSigner's transaction review and address verification.

### 3.3 Both endpoints malicious

No protection is claimed when the coordinator and signer collude. They can exchange or disclose the seed directly or through arbitrary channels.

### 3.4 QR transport

The camera, display, and QR transport are untrusted byte channels. They provide no confidentiality, authenticity, replay protection, or message ordering by themselves.

## 4. Adversary capabilities

A malicious signer may:

- choose arbitrary nonce algorithms;
- use low-entropy, predetermined, or ground nonces;
- return malformed or adversarial curve points;
- return a valid signature for a different input or key;
- add, remove, reorder, or mutate PSBT metadata;
- return partial results for selected inputs;
- abort based on hidden properties of candidate nonces;
- behave honestly except on selected transactions or invocation counts;
- lose or pretend to lose state; and
- attempt downgrade into ordinary signing.

A malicious coordinator may:

- choose non-random or repeated host values;
- reveal a value that does not match its commitment;
- send different PSBTs in the two rounds;
- change UTXO, script, derivation, sighash, or key data;
- replay an opening from another transaction or key;
- omit or duplicate protocol records;
- request unsupported or mixed protected/unprotected signing; and
- repeatedly restart after receiving an opening.

An active transport attacker may perform any QR payload mutation, truncation, duplication, replay, reordering, or substitution available to either endpoint.

## 5. In-scope attacks

### AE-01: Dark Skippy low-entropy nonce

The signer encodes seed material into small nonce scalars recoverable from public signatures. The final host contribution must make the accepted nonce computationally unpredictable to the signer when it fixes its opening.

### AE-02: Predetermined nonce

The signer and a remote attacker share nonce values or a nonce derivation backdoor. The host contribution must prevent the predetermined final nonce from being accepted.

### AE-03: Nonce grinding

The signer searches candidate nonces until public nonce bits encode secret material. The signer must commit to its opening before learning the host reveal. Selective abort remains a residual channel and is handled separately.

### AE-04: Selective abort

The signer commits normally but aborts after the host reveal depending on the resulting nonce or signature. The coordinator must reuse the same host randomness and require the same opening for retry, track failed sessions, and warn rather than silently generating fresh challenges.

The tracking model is tied to the lifetime of the wallet keys, not merely one hardware unit or application installation. Retrying a slightly modified transaction, restoring the same seed into replacement hardware, or switching signer implementations does not by itself defeat accumulated selective-abort bias. After repeated post-opening failures, the safe remediation is migration to a wallet generated from fresh independent keys.

### AE-05: Host-induced nonce reuse

The host obtains one base opening and attempts to produce two signatures with different reveals. The signer binds deterministic base-nonce derivation to the host commitment and recomputes it from the reveal-round transcript. A reveal inconsistent with the commitment cannot produce an accepted opening/signature pair.

### AE-06: Transcript substitution

Either endpoint substitutes a different transaction, input, signing key, sighash, or session between rounds. All signature-slot records and the session digest must bind to the exact signing context.

### AE-07: Cross-input or cross-key confusion

An opening or signature for one input/key is attached to another, especially in multisig. Every record is keyed by input index and full signing public key and is verified against the authoritative sighash for that slot.

### AE-08: Protocol downgrade

An anti-exfil-required signer or coordinator receives an ordinary PSBT or
incomplete protocol data and proceeds with ordinary signing. The signer uses an
explicit required/disabled mode; the coordinator uses per-keystore
`UNSUPPORTED`/`OPTIONAL`/`REQUIRED` capability and policy. Required paths fail
closed on mismatches.

### AE-09: Stage confusion and replay

A stage-1 opening response is treated as a signed response, a stage-2 request is replayed in another session, or messages arrive out of order. Protocol version, message type, transaction/session binding, and required-field sets are validated before cryptographic work.

### AE-10: Returned-PSBT exfiltration

A compromised signer adds secret-dependent unknown fields or mutates public transaction metadata in the QR response. The coordinator reconstructs the result from its original PSBT and imports only the exact expected signatures and validated anti-exfil data.

### AE-11: Malformed cryptographic objects

Invalid, non-canonical, infinity, or off-curve points and malformed DER signatures trigger parser or arithmetic faults. Strict parsing rejects them before use, with bounded resource consumption and no partial signing.

### AE-12: Mixed protection

Some signatures expected from a protected signer are anti-exfil and others
silently use ordinary ECDSA. In `REQUIRED` mode, every attributable supported
signature from that keystore must participate or the entire signing operation
fails.

### AE-13: Signature-attribution stripping

An ordinary hardware-wallet return finalizes or strips its PSBT maps so the
coordinator can no longer attribute the signature to a required keystore. Empty
attribution must not be treated as permission. The coordinator uses its original
unsigned PSBT as authoritative signer context and rejects an unattributable
signed return whenever an eligible signer is `REQUIRED`.

### AE-14: Buffered cross-session camera result

A camera backend delivers a symbol or fountain fragment from the preceding
dialog before the currently displayed QR. Stage/session/network validation
rejects stale protocol messages. Keystore imports lack a protocol session, so
the UI additionally drains startup frames and rejects duplicate xpubs.

### AE-15: Duplicate cosigner substitution

A stale or mistaken scan populates a multisig slot with key material already
used by another cosigner, making the displayed policy differ from the intended
independent-key policy. Import must reject an exact duplicate extended public
key before mutating the destination keystore.

## 6. Out-of-scope or residual attacks

### 6.1 False device display

Malicious firmware can show transaction details different from those it processes. Anti-exfil protects nonce construction, not display integrity.

### 6.2 Non-signature covert channels

Timing, failure patterns, QR animation choices, arbitrary UI behavior, and data outside the sanitized response may carry information. The implementation reduces obvious returned-data channels but does not claim general covert-channel elimination.

### 6.3 Coordinator compromise after successful verification

A coordinator that is compromised after verification can replace the completed transaction before broadcast. Existing coordinator and user verification controls remain necessary.

### 6.4 Side-channel extraction on SeedSigner

Power, electromagnetic, cache, interpreter, camera, or physical side channels are not solved by this protocol. Native constant-time cryptography remains a production requirement where secret scalars are processed.

### 6.5 Denial of service

A malicious endpoint can always refuse to sign or continue. The goal is to make failures safe and diagnosable, not to guarantee availability.

### 6.6 Taproot/Schnorr

Version 1 does not protect or sign Taproot inputs through this protocol. Required-mode Taproot signature slots fail closed until a reviewed Schnorr construction is specified.

### 6.7 Trusted coordinator storage

Durable AEXS session state contains plaintext unrevealed host randomness, and
AEXJ contains wallet-lifetime selective-abort history. The coordinator state
directory is in the trusted computing base. Checksums detect corruption but do
not provide freshness, encryption at rest, or protection from a local actor
who can read, delete, replace, or roll back the complete storage domain.

The supported deployment requires owner-restricted storage. POSIX files are
set to owner read/write where supported; Windows relies on the effective parent
DACL. Backups must not restore session or journal state independently. Missing
or suspected rolled-back state is not evidence of safety: stop protected
signing and migrate funds to fresh independently generated wallet keys before
relying on the anti-exfil guarantee again. A stronger rollback guarantee would
require a separately trusted monotonic authority; encryption at rest remains a
separate maintainer decision.

### 6.8 Witness-only PSBT input data

SegWit-v0 protocol slots accept standard BIP174 witness-only UTXO data. A
standalone `witness_utxo` cannot be authenticated against the unsigned
transaction outpoint without the full previous transaction or external wallet
history. Its amount and script are nevertheless committed by the BIP143
message hash: false data produces a signature invalid for the actual coin, not
a signature authorizing a different real prevout. Verified evidence attests to
the exact supplied signing hash and unsigned-transaction outpoint; it does not
attest that external chain state exists. Requiring every full previous
transaction is intentionally outside v1 because it would break standard and
QR-constrained workflows.

## 7. Security invariants

The implementation and tests must enforce these invariants:

- **INV-01:** No host reveal is emitted before the corresponding signer opening has been parsed and accepted.
- **INV-02:** No SeedSigner ECDSA signature is emitted in protocol round 1.
- **INV-03:** No signature is emitted in round 2 unless the commitment, reveal, recomputed opening, transaction, sighash, and signing key all match.
- **INV-04:** After accepting an opening, retries reuse the same host randomness and require the same opening.
- **INV-05:** A `REQUIRED` compatible keystore never accepts or invokes the ordinary signing path for one of its supported expected signature slots.
- **INV-06:** Disabled mode never interprets an anti-exfil request as an ordinary PSBT.
- **INV-07:** A malformed or mixed request produces zero new signatures.
- **INV-08:** The coordinator never merges arbitrary returned PSBT maps into the original PSBT.
- **INV-09:** Every accepted signature has both ordinary ECDSA verification and anti-exfil opening verification.
- **INV-10:** Unsupported Taproot signature slots produce no signatures in v1.
- **INV-11:** Power loss between rounds does not require SeedSigner to persist secret nonce state.
- **INV-12:** Persistent settings may retain only the user's anti-exfil policy through the existing settings mechanism, not nonce/session secrets.
- **INV-13:** A required signed return that cannot be attributed after metadata stripping is rejected using the original unsigned PSBT as signer context.
- **INV-14:** The coordinator imports only verified expected signatures and never broadcasts as a completion side effect.
- **INV-15:** An imported cosigner xpub cannot duplicate another keystore in the same wallet.
- **INV-16:** Scanner startup buffering cannot silently change stage/session context or populate a duplicate cosigner.
- **INV-17:** Every pre-existing partial signature in an anti-exfil input PSBT is ordinarily verified before coordinator state is created; valid foreign signatures may be preserved but receive no protected evidence.
- **INV-18:** Witness-only UTXO amount/script changes necessarily change the bound signing hash; protected evidence never upgrades supplied PSBT data into an external chain-state attestation.

## 8. Failure classes and user-facing meaning

| Failure class | Meaning | Signer behavior |
| --- | --- | --- |
| Policy mismatch | Request type conflicts with Disabled/Required setting | Explain how to align SeedSigner and coordinator; do not sign |
| Unsupported signing type | Example: Taproot in v1 | Explain unsupported anti-exfil input; do not sign |
| Invalid protocol message | Missing, duplicate, mixed, oversized, or wrong-stage fields | Report invalid/incomplete request; do not sign |
| Transaction mismatch | Round-2 transaction or signing context differs | High-severity warning; do not sign |
| Commitment/reveal mismatch | Host reveal does not match the round-1 commitment | High-severity warning; do not sign |
| Opening mismatch | Recomputed signer opening differs | High-severity warning; do not sign |
| No matching seed/key | Existing SeedSigner key-selection failure | Keep distinct from protocol errors |
| Coordinator verification failure | Returned signature/opening is invalid | Coordinator blocks completion/export/broadcast |
| Repeated abort | Signer repeatedly fails after an opening is accepted | Coordinator warns that repeated failures may be security relevant |
| Required-signature downgrade | Ordinary or unattributable signature returned for a required keystore | Reject before accepting/finalizing the returned signature |
| Buffered or duplicate import | Camera returns the preceding xpub or an already-used cosigner | Ignore startup buffer and reject duplicate key material |

The UI explains that retrying the same transcript with the same host randomness
is safe for transport failures, while repeatedly abandoning protected sessions
and starting fresh challenges is not. Warning severity escalates with durable
wallet-key history; exact thresholds remain a maintainer/security-review choice.

## 9. Validation strategy

Every in-scope attack receives at least one deterministic negative vector or adversarial integration test. Every invariant receives a direct test or a documented argument explaining why it is enforced structurally.

The original Gemini one-round construction is retained only as a negative-control model: a malicious signer that learns host randomness before fixing its opening must be able to demonstrate why consistency verification alone is insufficient.

| Attack group | Primary validation |
| --- | --- |
| AE-01 through AE-03 | `tests/reference/test_adversarial.py`, native differential vectors, S2C plus ordinary ECDSA verification |
| AE-04 and AE-05 | exact-retry coordinator tests, durable abort journal, disposable post-reveal physical gate |
| AE-06 through AE-09 | multi-slot codec transitions, session/network/stage/PSBT mutation corpus, physical rejection matrix |
| AE-10 | reconstruction from frozen original and returned-metadata injection test |
| AE-11 and AE-12 | strict point/signature parsers, atomic slot-set tests, mixed-input and mixed-policy tests |
| AE-13 | ordinary finalized-return regression and physical **Protected signature rejected** gate |
| AE-14 and AE-15 | stale-fountain regression, camera startup-drain test, duplicate-keystore unit tests, pending first-open smoke observation |
| Storage and PSBT trust residuals | Gate 5 foreign-partial rejection, witness-only sighash-binding test, and explicit rollback/ACL recovery contract |

## 10. Resolved v1 decisions and review questions

Protocol v1 resolves the earlier design questions as follows:

- pin `secp256k1-zkp` commit
  `2af926dc309a673461f0e2da090105c8f05b4505` for cryptographic compatibility;
- use native signer operations and public coordinator verification;
- support PSBT v0, SegWit-v0 native/nested P2WPKH and standard P2WSH multisig,
  and explicit `SIGHASH_ALL` only;
- use versioned outer AEXT plus canonical AEXB records rather than signer-returned
  PSBT proprietary maps;
- bind the session to a CSPRNG identifier, SHA-256 of exact frozen PSBT bytes,
  and the complete canonical slot set;
- persist exact post-opening state and journal aborts by wallet-key identity;
- store device-neutral capability/policy per keystore; and
- fail the entire ceremony on Taproot or unsupported mixed inputs.

Maintainer/security review is still requested for:

- native-library upstreaming and reproducible packaging strategy;
- encryption and retention policy for durable host sessions;
- selective-abort warning thresholds and fund-migration language;
- formal UR type registration and naming;
- mixed optional/required cosigner presentation beyond the implemented chooser;
- independent analysis of residual timing/failure channels; and
- a separate Taproot/Schnorr protocol rather than extension of v1.

None of these questions may be resolved through silent fallback.
