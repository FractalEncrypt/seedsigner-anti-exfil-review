from pathlib import Path
import base64
import os
import unittest

from anti_exfil.camera_receiver import (
    CameraInfo,
    format_duration,
    fountain_candidate_key,
    parse_bridge_line,
    safe_fountain_metadata,
)
from anti_exfil.crypto import host_commit, public_key
from anti_exfil.messages import RungBMessage, Stage
from anti_exfil.transport import (
    TransportNetwork,
    TransportPackage,
    URPackageAccumulator,
    inspect_ur_fountain_part,
    encode_ur_frames,
)

SEEDSIGNER_SRC = Path(
    os.environ.get(
        "SEEDSIGNER_SRC",
        Path(__file__).resolve().parents[2] / "patches" / "seedsigner-qr" / "src",
    )
)


def b64(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


@unittest.skipUnless(SEEDSIGNER_SRC.is_dir(), "SeedSigner QR implementation is unavailable")
class CameraBridgeProtocolTest(unittest.TestCase):
    def test_malformed_anti_exfil_fountain_header_is_rejected_without_escape(self):
        malformed = "ur:x-btc-anti-exfil/1-2/ae"
        self.assertIsNone(
            safe_fountain_metadata(malformed, seedsigner_src=SEEDSIGNER_SRC)
        )

    def test_inspect_ur_fountain_part_reports_non_payload_metadata(self):
        rho = bytes.fromhex("a5" * 32)
        message = RungBMessage(
            stage=Stage.SIGNER_OPENINGS,
            session_id=bytes.fromhex("c3" * 32),
            message_hash=bytes.fromhex("88" * 32),
            signer_pubkey=public_key(bytes.fromhex("55" * 32)),
            commitment=host_commit(rho),
            opening=public_key(bytes.fromhex("44" * 32)),
        ).encode()
        package = TransportPackage(message, TransportNetwork.TESTNET)
        frame = encode_ur_frames(
            package.encode(), seedsigner_src=SEEDSIGNER_SRC, max_fragment_len=30
        )[0]
        metadata = inspect_ur_fountain_part(frame, seedsigner_src=SEEDSIGNER_SRC)
        self.assertEqual(metadata["type"], "x-btc-anti-exfil")
        self.assertEqual(metadata["form"], "multipart")
        self.assertEqual(metadata["seq_num"], 1)
        self.assertGreater(metadata["seq_len"], 1)
        self.assertGreaterEqual(metadata["message_len"], len(package.encode()))

    def test_stale_and_current_fountain_streams_have_distinct_candidates(self):
        def first_frame(stage: Stage) -> tuple[str, dict[str, int | str]]:
            rho = bytes.fromhex("a5" * 32)
            message = RungBMessage(
                stage=stage,
                session_id=bytes.fromhex("c3" * 32),
                message_hash=bytes.fromhex("88" * 32),
                signer_pubkey=public_key(bytes.fromhex("55" * 32)),
                commitment=host_commit(rho),
                opening=public_key(bytes.fromhex("44" * 32)),
                rho=rho if stage >= Stage.HOST_REVEAL else None,
                signature=bytes.fromhex("11" * 64)
                if stage >= Stage.SIGNER_SIGNATURES
                else None,
            ).encode()
            encoded = TransportPackage(message, TransportNetwork.TESTNET).encode()
            frame = encode_ur_frames(
                encoded, seedsigner_src=SEEDSIGNER_SRC, max_fragment_len=30
            )[0]
            return frame, inspect_ur_fountain_part(frame, seedsigner_src=SEEDSIGNER_SRC)

        stale_frame, stale_metadata = first_frame(Stage.SIGNER_OPENINGS)
        current_frame, current_metadata = first_frame(Stage.SIGNER_SIGNATURES)
        self.assertNotEqual(
            fountain_candidate_key(stale_metadata, stale_frame),
            fountain_candidate_key(current_metadata, current_frame),
        )

    def test_elapsed_duration_is_stable(self):
        self.assertEqual(format_duration(0), "00:00:00")
        self.assertEqual(format_duration(65.9), "00:01:05")
        self.assertEqual(format_duration(3661), "01:01:01")

    def test_camera_and_qr_records_are_strictly_decoded(self):
        kind, values = parse_bridge_line(f"CAMERA\t2\t{b64('OBS Virtual Camera')}\t{b64('obs-id')}\n")
        self.assertEqual(kind, "CAMERA")
        self.assertEqual(values, (CameraInfo(2, "OBS Virtual Camera", "obs-id"),))
        self.assertEqual(parse_bridge_line(f"QR\t{b64('UR:X-BTC-ANTI-EXFIL/TEST')}"), ("QR", ("UR:X-BTC-ANTI-EXFIL/TEST",)))
        self.assertEqual(
            parse_bridge_line("STATUS\t25\t3\t2"),
            ("STATUS", (25, 3, 2)),
        )

    def test_live_accumulator_ignores_other_qr_types_and_completes(self):
        rho = bytes.fromhex("a5" * 32)
        message = RungBMessage(
            stage=Stage.SIGNER_OPENINGS,
            session_id=bytes.fromhex("c3" * 32),
            message_hash=bytes.fromhex("88" * 32),
            signer_pubkey=public_key(bytes.fromhex("55" * 32)),
            commitment=host_commit(rho),
            opening=public_key(bytes.fromhex("44" * 32)),
        ).encode()
        encoded = TransportPackage(message, TransportNetwork.TESTNET).encode()
        frames = encode_ur_frames(encoded, seedsigner_src=SEEDSIGNER_SRC, max_fragment_len=30)
        accumulator = URPackageAccumulator(seedsigner_src=SEEDSIGNER_SRC)
        self.assertFalse(accumulator.receive("ur:crypto-psbt/not-ours"))
        for frame in reversed(frames):
            accumulator.receive(frame)
            if accumulator.is_complete:
                break
        self.assertTrue(accumulator.is_complete)
        self.assertGreater(accumulator.expected_parts or 0, 0)
        self.assertEqual(accumulator.payload, encoded)
        self.assertEqual(TransportPackage.decode(accumulator.payload).network, TransportNetwork.TESTNET)


if __name__ == "__main__":
    unittest.main()
