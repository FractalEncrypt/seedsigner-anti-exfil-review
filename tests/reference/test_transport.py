from pathlib import Path
import os
import hashlib
import json
import tempfile
import unittest

from anti_exfil.crypto import host_commit, public_key
from anti_exfil.errors import AntiExfilError, ErrorCode
from anti_exfil.messages import RungBMessage, Stage
from anti_exfil.psbt_tools import build_seedsigner_p2wpkh_fixture
from anti_exfil.qr_bitmap import extract_qr_frame, render_qr_frame
from anti_exfil.transport import (
    TransportNetwork,
    TransportPackage,
    UR_TYPE,
    decode_ur_frames,
    encode_ur_frames,
)


SEEDSIGNER_SRC = Path(
    os.environ.get(
        "SEEDSIGNER_SRC",
        Path(__file__).resolve().parents[3]
        / "Windsurf"
        / "SeedSigner_AntiExfil"
        / "src",
    )
)


def message_for(stage: Stage) -> bytes:
    rho = bytes.fromhex("a5" * 32)
    fields = {
        "stage": stage,
        "session_id": bytes.fromhex("c3" * 32),
        "message_hash": bytes.fromhex("88" * 32),
        "signer_pubkey": public_key(bytes.fromhex("55" * 32)),
        "commitment": host_commit(rho),
    }
    if stage >= Stage.SIGNER_OPENINGS:
        fields["opening"] = public_key(bytes.fromhex("44" * 32))
    if stage >= Stage.HOST_REVEAL:
        fields["rho"] = rho
    if stage >= Stage.SIGNER_SIGNATURES:
        fields["signature"] = bytes.fromhex("11" * 64)
    return RungBMessage(**fields).encode()


class RungETransportPackageTest(unittest.TestCase):
    def setUp(self):
        self.psbt, _ = build_seedsigner_p2wpkh_fixture()

    def test_requests_require_psbt_and_responses_forbid_it(self):
        for stage in (Stage.HOST_COMMIT, Stage.HOST_REVEAL):
            with self.assertRaises(AntiExfilError):
                TransportPackage(message_for(stage), TransportNetwork.TESTNET).encode()
        for stage in (Stage.SIGNER_OPENINGS, Stage.SIGNER_SIGNATURES):
            with self.assertRaises(AntiExfilError):
                TransportPackage(
                    message_for(stage), TransportNetwork.TESTNET, self.psbt
                ).encode()

    def test_response_cannot_return_a_replacement_transaction(self):
        malicious = TransportPackage(
            message_for(Stage.SIGNER_SIGNATURES), TransportNetwork.TESTNET, self.psbt
        )
        with self.assertRaises(AntiExfilError) as raised:
            malicious.encode()
        self.assertEqual(raised.exception.code, ErrorCode.INVALID_MESSAGE)

    def test_digest_and_trailing_data_are_rejected(self):
        encoded = bytearray(
            TransportPackage(
                message_for(Stage.HOST_COMMIT), TransportNetwork.TESTNET, self.psbt
            ).encode()
        )
        encoded[-1] ^= 1
        with self.assertRaises(AntiExfilError) as raised:
            TransportPackage.decode(bytes(encoded))
        self.assertEqual(raised.exception.code, ErrorCode.TRANSACTION_MISMATCH)
        valid = TransportPackage(
            message_for(Stage.HOST_COMMIT), TransportNetwork.TESTNET, self.psbt
        ).encode()
        with self.assertRaises(AntiExfilError):
            TransportPackage.decode(valid + b"trailing")

    @unittest.skipUnless(SEEDSIGNER_SRC.exists(), "SeedSigner UR2 implementation is unavailable")
    def test_seedsigner_ur2_round_trip_is_byte_identical_when_reordered(self):
        encoded = TransportPackage(
            message_for(Stage.HOST_REVEAL), TransportNetwork.TESTNET, self.psbt
        ).encode()
        frames = encode_ur_frames(
            encoded, seedsigner_src=SEEDSIGNER_SRC, max_fragment_len=40
        )
        self.assertGreater(len(frames), 1)
        received = [frames[-1], *reversed(frames)]
        decoded = decode_ur_frames(received, seedsigner_src=SEEDSIGNER_SRC)
        self.assertEqual(decoded, encoded)
        recovered = TransportPackage.decode(decoded)
        self.assertEqual(recovered.psbt, self.psbt)
        self.assertEqual(recovered.network, TransportNetwork.TESTNET)
        self.assertTrue(frames[0].lower().startswith(f"ur:{UR_TYPE}/"))

    @unittest.skipUnless(SEEDSIGNER_SRC.exists(), "SeedSigner UR2 implementation is unavailable")
    def test_medium_density_full_request_tolerates_order_and_duplicates(self):
        encoded = TransportPackage(
            message_for(Stage.HOST_REVEAL), TransportNetwork.TESTNET, self.psbt
        ).encode()
        frames = encode_ur_frames(
            encoded, seedsigner_src=SEEDSIGNER_SRC, max_fragment_len=30
        )
        self.assertEqual(
            decode_ur_frames(list(reversed(frames)), seedsigner_src=SEEDSIGNER_SRC),
            encoded,
        )
        self.assertEqual(
            decode_ur_frames(
                [frames[-1], *reversed(frames), *frames],
                seedsigner_src=SEEDSIGNER_SRC,
            ),
            encoded,
        )

    def test_network_and_redundant_stage_are_strict(self):
        encoded = bytearray(
            TransportPackage(
                message_for(Stage.HOST_COMMIT), TransportNetwork.TESTNET, self.psbt
            ).encode()
        )
        encoded[5] = 255
        with self.assertRaises(AntiExfilError):
            TransportPackage.decode(bytes(encoded))

        encoded = bytearray(
            TransportPackage(
                message_for(Stage.HOST_COMMIT), TransportNetwork.TESTNET, self.psbt
            ).encode()
        )
        encoded[6] = int(Stage.HOST_REVEAL)
        with self.assertRaises(AntiExfilError) as raised:
            TransportPackage.decode(bytes(encoded))
        self.assertEqual(raised.exception.code, ErrorCode.WRONG_STAGE)

    def test_psbt_magic_is_checked(self):
        with self.assertRaises(AntiExfilError):
            TransportPackage(
                message_for(Stage.HOST_COMMIT),
                TransportNetwork.TESTNET,
                b"not-a-psbt",
            ).encode()

    def test_pinned_cross_language_vectors(self):
        vector_path = Path(__file__).resolve().parents[2] / "fixtures" / "transport-v1-vectors.json"
        document = json.loads(vector_path.read_text(encoding="utf-8"))
        self.assertEqual(document["ur_type"], UR_TYPE)
        for vector in document["vectors"]:
            encoded = bytes.fromhex(vector["package_hex"])
            self.assertEqual(len(encoded), vector["package_length"])
            self.assertEqual(hashlib.sha256(encoded).hexdigest(), vector["package_sha256"])
            package = TransportPackage.decode(encoded)
            self.assertEqual(package.encode(), encoded)
            self.assertEqual(int(package.network), int(TransportNetwork.TESTNET))
            self.assertEqual(int(package.message[5]), vector["stage"])

        if not SEEDSIGNER_SRC.is_dir():
            return
        first = document["vectors"][0]
        frames = encode_ur_frames(
            bytes.fromhex(first["package_hex"]),
            seedsigner_src=SEEDSIGNER_SRC,
            max_fragment_len=30,
        )
        self.assertEqual(frames[0], first["medium_ur_part_1"])
        self.assertEqual(frames[13], first["medium_ur_part_14"])

    @unittest.skipUnless(SEEDSIGNER_SRC.exists(), "SeedSigner QR implementation is unavailable")
    def test_medium_density_frame_survives_240px_bitmap(self):
        vector_path = Path(__file__).resolve().parents[2] / "fixtures" / "transport-v1-vectors.json"
        document = json.loads(vector_path.read_text(encoding="utf-8"))
        frame = document["vectors"][0]["medium_ur_part_1"]
        with tempfile.TemporaryDirectory() as temporary:
            image_path = Path(temporary) / "frame.png"
            render_qr_frame(frame, image_path, seedsigner_src=SEEDSIGNER_SRC)
            self.assertEqual(
                extract_qr_frame(image_path, seedsigner_src=SEEDSIGNER_SRC),
                frame,
            )


if __name__ == "__main__":
    unittest.main()
