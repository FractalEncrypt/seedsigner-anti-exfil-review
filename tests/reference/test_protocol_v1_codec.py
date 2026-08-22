from dataclasses import replace
from pathlib import Path
import hashlib
import json
import os
import unittest

from anti_exfil.crypto import (
    anti_exfil_sign,
    host_commit,
    public_key,
    signer_opening,
    verify_anti_exfil,
)
from anti_exfil.errors import AntiExfilError, ErrorCode
from anti_exfil.protocol_v1_codec import (
    HEADER,
    MAX_SLOTS,
    MAX_SLOTS_PER_INPUT,
    Network,
    ProtocolMessage,
    SIGHASH_ALL,
    SigningSlot,
    Stage,
    decode_message,
    validate_transition,
)
from anti_exfil.protocol_v1_transport import ProtocolV1Package
from anti_exfil.transport import decode_ur_frames


SEEDSIGNER_SRC = Path(
    os.environ.get(
        "SEEDSIGNER_SRC",
        Path(__file__).resolve().parents[3]
        / "Windsurf"
        / "SeedSigner_AntiExfil"
        / "src",
    )
)
FIXTURE = (
    Path(__file__).resolve().parents[2] / "fixtures" / "protocol-v1-multislot-vectors.json"
)
NEGATIVE_FIXTURE = (
    Path(__file__).resolve().parents[2] / "fixtures" / "protocol-v1-negative-vectors.json"
)


class ProtocolV1CodecTest(unittest.TestCase):
    SESSION = bytes.fromhex("c3" * 32)
    PSBT = b"psbt\xff" + b"protocol-v1-synthetic-wire-fixture"
    PSBT_DIGEST = hashlib.sha256(PSBT).digest()
    SECRETS = (
        bytes.fromhex("11" * 32),
        bytes.fromhex("22" * 32),
        bytes.fromhex("33" * 32),
    )
    RHOS = (
        bytes.fromhex("a1" * 32),
        bytes.fromhex("a2" * 32),
        bytes.fromhex("a3" * 32),
    )
    HASHES = (
        bytes.fromhex("81" * 32),
        bytes.fromhex("82" * 32),
        bytes.fromhex("83" * 32),
    )

    def message(self, stage: Stage) -> ProtocolMessage:
        raw = []
        for input_index, secret, rho, message_hash in (
            (0, self.SECRETS[0], self.RHOS[0], self.HASHES[0]),
            (1, self.SECRETS[1], self.RHOS[1], self.HASHES[1]),
            (1, self.SECRETS[2], self.RHOS[2], self.HASHES[2]),
        ):
            pubkey = public_key(secret)
            commitment = host_commit(rho)
            opening = None
            revealed = None
            signature = None
            if stage >= Stage.SIGNER_OPENINGS:
                opening = signer_opening(secret, message_hash, commitment)
            if stage == Stage.HOST_REVEAL:
                revealed = rho
            if stage == Stage.SIGNER_SIGNATURES:
                signature, signing_opening = anti_exfil_sign(secret, message_hash, rho)
                self.assertEqual(signing_opening, opening)
            raw.append(
                SigningSlot(
                    input_index=input_index,
                    signer_pubkey=pubkey,
                    message_hash=message_hash,
                    sighash_type=SIGHASH_ALL,
                    commitment=commitment,
                    opening=opening,
                    rho=revealed,
                    signature=signature,
                )
            )
        raw.sort(key=lambda slot: slot.identifier)
        return ProtocolMessage(
            network=Network.TESTNET4,
            stage=stage,
            session_id=self.SESSION,
            psbt_digest=self.PSBT_DIGEST,
            slots=tuple(raw),
        )

    def test_all_stages_round_trip_canonically(self):
        expected_record_lengths = {
            Stage.HOST_COMMIT: 105,
            Stage.SIGNER_OPENINGS: 138,
            Stage.HOST_REVEAL: 170,
            Stage.SIGNER_SIGNATURES: 202,
        }
        for stage, record_length in expected_record_lengths.items():
            with self.subTest(stage=stage.name):
                message = self.message(stage)
                encoded = message.encode()
                self.assertEqual(len(encoded), HEADER.size + 3 * record_length)
                self.assertEqual(decode_message(encoded), message)
                self.assertEqual(decode_message(encoded).encode(), encoded)

    def test_slot_order_duplicates_and_conflicts_are_rejected(self):
        message = self.message(Stage.HOST_COMMIT)
        with self.assertRaises(AntiExfilError) as reordered:
            replace(message, slots=tuple(reversed(message.slots))).encode()
        self.assertEqual(reordered.exception.code, ErrorCode.SIGNATURE_SLOT_MISMATCH)

        duplicate = (message.slots[0], message.slots[0], *message.slots[1:])
        with self.assertRaises(AntiExfilError) as exact_duplicate:
            replace(message, slots=duplicate).encode()
        self.assertEqual(exact_duplicate.exception.code, ErrorCode.SIGNATURE_SLOT_MISMATCH)

        conflict = replace(message.slots[0], message_hash=bytes.fromhex("ff" * 32))
        with self.assertRaises(AntiExfilError) as conflicting_duplicate:
            replace(message, slots=(message.slots[0], conflict, *message.slots[1:])).encode()
        self.assertEqual(conflicting_duplicate.exception.code, ErrorCode.SIGNATURE_SLOT_MISMATCH)

    def test_header_unknowns_lengths_and_trailing_data_are_rejected(self):
        valid = self.message(Stage.HOST_COMMIT).encode()
        for offset in (4, 5, 6, 7):
            with self.subTest(offset=offset):
                mutated = bytearray(valid)
                mutated[offset] = 0xFF
                with self.assertRaises(AntiExfilError):
                    decode_message(bytes(mutated))
        with self.assertRaises(AntiExfilError):
            decode_message(valid + b"trailing")
        with self.assertRaises(AntiExfilError):
            decode_message(valid[:-1])
        mutated = bytearray(valid)
        mutated[8:12] = (1).to_bytes(4, "big")
        with self.assertRaises(AntiExfilError):
            decode_message(bytes(mutated))

    def test_only_explicit_sighash_all_is_accepted(self):
        message = self.message(Stage.HOST_COMMIT)
        bad_slot = replace(message.slots[0], sighash_type=0)
        with self.assertRaises(AntiExfilError):
            replace(message, slots=(bad_slot, *message.slots[1:])).encode()

    def test_commitments_and_reveals_must_be_unique_per_slot(self):
        message = self.message(Stage.HOST_COMMIT)
        duplicate_commitment = replace(
            message.slots[1], commitment=message.slots[0].commitment
        )
        with self.assertRaises(AntiExfilError) as commitment:
            replace(
                message,
                slots=(message.slots[0], duplicate_commitment, *message.slots[2:]),
            ).encode()
        self.assertEqual(commitment.exception.code, ErrorCode.COMMITMENT_MISMATCH)

        reveal = self.message(Stage.HOST_REVEAL)
        duplicate_reveal = replace(reveal.slots[1], rho=reveal.slots[0].rho)
        with self.assertRaises(AntiExfilError) as rho:
            replace(
                reveal,
                slots=(reveal.slots[0], duplicate_reveal, *reveal.slots[2:]),
            ).encode()
        self.assertEqual(rho.exception.code, ErrorCode.COMMITMENT_MISMATCH)
        bad_slot = replace(message.slots[0], sighash_type=0x81)
        with self.assertRaises(AntiExfilError):
            replace(message, slots=(bad_slot, *message.slots[1:])).encode()

    def test_openings_must_be_unique_per_signer_key(self):
        openings = self.message(Stage.SIGNER_OPENINGS)

        reused_for_same_key = replace(
            openings.slots[1],
            signer_pubkey=openings.slots[0].signer_pubkey,
            opening=openings.slots[0].opening,
        )
        same_key_slots = tuple(
            sorted(
                (openings.slots[0], reused_for_same_key, *openings.slots[2:]),
                key=lambda slot: slot.identifier,
            )
        )
        with self.assertRaises(AntiExfilError) as repeated:
            replace(openings, slots=same_key_slots).encode()
        self.assertEqual(repeated.exception.code, ErrorCode.OPENING_MISMATCH)

        distinct_for_same_key = replace(
            openings.slots[1],
            signer_pubkey=openings.slots[0].signer_pubkey,
            opening=signer_opening(
                self.SECRETS[0],
                openings.slots[1].message_hash,
                openings.slots[1].commitment,
            ),
        )
        distinct_same_key_slots = tuple(
            sorted(
                (openings.slots[0], distinct_for_same_key, *openings.slots[2:]),
                key=lambda slot: slot.identifier,
            )
        )
        replace(openings, slots=distinct_same_key_slots).encode()

        reused_across_different_keys = replace(
            openings.slots[1], opening=openings.slots[0].opening
        )
        replace(
            openings,
            slots=(openings.slots[0], reused_across_different_keys, *openings.slots[2:]),
        ).encode()

    def test_shared_host_negative_vectors(self):
        cases = json.loads(NEGATIVE_FIXTURE.read_text(encoding="utf-8"))["cases"]
        self.assertEqual(
            ["same-signer-opening-reused-across-inputs"],
            [case["name"] for case in cases],
        )
        for case in cases:
            with self.subTest(case=case["name"]):
                encoded = bytes.fromhex(case["message_hex"])
                self.assertEqual(case["message_length"], len(encoded))
                self.assertEqual(case["message_sha256"], hashlib.sha256(encoded).hexdigest())
                with self.assertRaises(AntiExfilError) as rejected:
                    decode_message(encoded)
                self.assertEqual(case["expected_error"], rejected.exception.code.name)
                package = bytes.fromhex(case["package_hex"])
                self.assertEqual(case["package_length"], len(package))
                self.assertEqual(
                    case["package_sha256"], hashlib.sha256(package).hexdigest()
                )
                with self.assertRaises(AntiExfilError) as package_rejected:
                    ProtocolV1Package.decode(package)
                self.assertEqual(
                    case["expected_error"], package_rejected.exception.code.name
                )

    def test_stage_specific_fields_are_exact(self):
        commit = self.message(Stage.HOST_COMMIT)
        with self.assertRaises(AntiExfilError):
            replace(
                commit,
                slots=(replace(commit.slots[0], opening=public_key(self.SECRETS[2])), *commit.slots[1:]),
            ).encode()
        openings = self.message(Stage.SIGNER_OPENINGS)
        with self.assertRaises(AntiExfilError):
            replace(
                openings,
                slots=(replace(openings.slots[0], rho=self.RHOS[0]), *openings.slots[1:]),
            ).encode()
        signatures = self.message(Stage.SIGNER_SIGNATURES)
        with self.assertRaises(AntiExfilError):
            replace(
                signatures,
                slots=(replace(signatures.slots[0], rho=self.RHOS[0]), *signatures.slots[1:]),
            ).encode()

    def test_adjacent_transitions_bind_complete_context(self):
        messages = [self.message(stage) for stage in Stage]
        for previous, current in zip(messages[:-1], messages[1:], strict=True):
            validate_transition(previous, current)

        with self.assertRaises(AntiExfilError) as skipped:
            validate_transition(messages[0], messages[2])
        self.assertEqual(skipped.exception.code, ErrorCode.WRONG_STAGE)

        changed_hash = replace(
            messages[1].slots[0], message_hash=bytes.fromhex("ff" * 32)
        )
        with self.assertRaises(AntiExfilError) as context:
            validate_transition(
                messages[0], replace(messages[1], slots=(changed_hash, *messages[1].slots[1:]))
            )
        self.assertEqual(context.exception.code, ErrorCode.TRANSACTION_MISMATCH)

        changed_opening = replace(
            messages[2].slots[0], opening=public_key(bytes.fromhex("44" * 32))
        )
        with self.assertRaises(AntiExfilError) as opening:
            validate_transition(
                messages[1], replace(messages[2], slots=(changed_opening, *messages[2].slots[1:]))
            )
        self.assertEqual(opening.exception.code, ErrorCode.OPENING_MISMATCH)

    def test_reveal_must_match_every_commitment(self):
        openings = self.message(Stage.SIGNER_OPENINGS)
        reveal = self.message(Stage.HOST_REVEAL)
        changed = replace(reveal.slots[0], rho=bytes.fromhex("fe" * 32))
        with self.assertRaises(AntiExfilError) as mismatch:
            validate_transition(openings, replace(reveal, slots=(changed, *reveal.slots[1:])))
        self.assertEqual(mismatch.exception.code, ErrorCode.COMMITMENT_MISMATCH)

    def test_global_and_per_input_slot_limits(self):
        message = self.message(Stage.HOST_COMMIT)
        with self.assertRaises(AntiExfilError):
            replace(message, slots=(message.slots[0],) * (MAX_SLOTS + 1)).encode()

        many = []
        for scalar in range(1, MAX_SLOTS_PER_INPUT + 2):
            many.append(
                SigningSlot(
                    input_index=0,
                    signer_pubkey=public_key(scalar.to_bytes(32, "big")),
                    message_hash=hashlib.sha256(bytes([scalar])).digest(),
                    sighash_type=SIGHASH_ALL,
                    commitment=hashlib.sha256(b"commitment" + bytes([scalar])).digest(),
                )
            )
        many.sort(key=lambda slot: slot.identifier)
        with self.assertRaises(AntiExfilError) as too_many:
            replace(message, slots=tuple(many)).encode()
        self.assertEqual(too_many.exception.code, ErrorCode.SIGNATURE_SLOT_MISMATCH)

    def test_testnet4_transport_binds_psbt_network_stage_and_direction(self):
        for stage in Stage:
            message = self.message(stage)
            psbt = self.PSBT if stage in (Stage.HOST_COMMIT, Stage.HOST_REVEAL) else None
            package = ProtocolV1Package(message, psbt)
            encoded = package.encode()
            self.assertEqual(ProtocolV1Package.decode(encoded), package)
            self.assertEqual(encoded[5], int(Network.TESTNET4))

        with self.assertRaises(AntiExfilError):
            ProtocolV1Package(self.message(Stage.HOST_COMMIT), None).encode()
        with self.assertRaises(AntiExfilError):
            ProtocolV1Package(self.message(Stage.SIGNER_OPENINGS), self.PSBT).encode()
        with self.assertRaises(AntiExfilError) as digest:
            ProtocolV1Package(self.message(Stage.HOST_COMMIT), self.PSBT + b"changed").encode()
        self.assertEqual(digest.exception.code, ErrorCode.TRANSACTION_MISMATCH)

        encoded = bytearray(
            ProtocolV1Package(self.message(Stage.HOST_COMMIT), self.PSBT).encode()
        )
        encoded[5] = int(Network.TESTNET3)
        with self.assertRaises(AntiExfilError) as network:
            ProtocolV1Package.decode(bytes(encoded))
        self.assertEqual(network.exception.code, ErrorCode.TRANSACTION_MISMATCH)

    @unittest.skipUnless(FIXTURE.exists(), "multi-slot golden vector is unavailable")
    def test_golden_binary_and_qr_vectors(self):
        document = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(document["network"], "testnet4")
        self.assertEqual(document["slot_count"], 3)
        decoded_messages = []
        for vector in document["messages"]:
            message_bytes = bytes.fromhex(vector["message_hex"])
            package_bytes = bytes.fromhex(vector["package_hex"])
            message = decode_message(message_bytes)
            decoded_messages.append(message)
            package = ProtocolV1Package.decode(package_bytes)
            self.assertEqual(message.encode(), message_bytes)
            self.assertEqual(package.message, message)
            self.assertEqual(hashlib.sha256(message_bytes).hexdigest(), vector["message_sha256"])
            self.assertEqual(hashlib.sha256(package_bytes).hexdigest(), vector["package_sha256"])
            if SEEDSIGNER_SRC.exists():
                self.assertEqual(
                    decode_ur_frames(vector["medium_ur_parts"], seedsigner_src=SEEDSIGNER_SRC),
                    package_bytes,
                )
        for previous, current in zip(
            decoded_messages[:-1], decoded_messages[1:], strict=True
        ):
            validate_transition(previous, current)
        signatures = decoded_messages[-1]
        rho_by_pubkey = {
            public_key(secret): rho for secret, rho in zip(self.SECRETS, self.RHOS, strict=True)
        }
        for slot in signatures.slots:
            self.assertTrue(
                verify_anti_exfil(
                    slot.signer_pubkey,
                    slot.message_hash,
                    rho_by_pubkey[slot.signer_pubkey],
                    slot.opening,
                    slot.signature,
                )
            )


if __name__ == "__main__":
    unittest.main()
