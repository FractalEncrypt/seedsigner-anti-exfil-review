import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from anti_exfil.crypto import host_commit, public_key
from anti_exfil.errors import AntiExfilError, ErrorCode
from anti_exfil.messages import RungBMessage, Stage, decode_message
from anti_exfil.workflow import host_init, host_reveal, host_verify, signer_commit, signer_sign


class RungBWorkflowTest(unittest.TestCase):
    SECRET = bytes.fromhex("55" * 32)
    MESSAGE = bytes.fromhex("88" * 32)
    RHO = bytes.fromhex("a5" * 32)
    SESSION = bytes.fromhex("c3" * 32)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.host_private = self.root / "host-private"
        self.exchange = self.root / "exchange"
        self.output = self.root / "output"
        self.paths = [self.exchange / f"message-{number}.aex" for number in range(1, 5)]

    def tearDown(self):
        self.temporary.cleanup()

    def _complete_to_message_two(self):
        host_init(
            message_hash=self.MESSAGE,
            signer_pubkey=public_key(self.SECRET),
            session_dir=self.host_private,
            output_path=self.paths[0],
            rho=self.RHO,
            session_id=self.SESSION,
        )
        signer_commit(
            input_path=self.paths[0], test_secret_key=self.SECRET, output_path=self.paths[1]
        )

    def _complete_transcript(self):
        self._complete_to_message_two()
        host_reveal(
            session_dir=self.host_private,
            input_path=self.paths[1],
            output_path=self.paths[2],
        )
        signer_sign(
            input_path=self.paths[2], test_secret_key=self.SECRET, output_path=self.paths[3]
        )
        return host_verify(
            session_dir=self.host_private,
            input_path=self.paths[3],
            receipt_path=self.output / "receipt.json",
        )

    def test_complete_four_message_transcript(self):
        receipt = self._complete_transcript()
        self.assertEqual(receipt["status"], "verified")
        self.assertTrue(receipt["ordinary_ecdsa_verified"])
        self.assertTrue(receipt["anti_exfil_opening_verified"])
        for expected_stage, path in zip(Stage, self.paths):
            self.assertEqual(decode_message(path.read_bytes()).stage, expected_stage)
        state = json.loads((self.host_private / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["phase"], "COMPLETE")

    def test_host_reveal_and_verify_are_idempotent(self):
        receipt = self._complete_transcript()
        message_three_before = self.paths[2].read_bytes()
        receipt_before = (self.output / "receipt.json").read_bytes()
        host_reveal(
            session_dir=self.host_private,
            input_path=self.paths[1],
            output_path=self.paths[2],
        )
        repeated = host_verify(
            session_dir=self.host_private,
            input_path=self.paths[3],
            receipt_path=self.output / "receipt.json",
        )
        self.assertEqual(repeated, receipt)
        self.assertEqual(self.paths[2].read_bytes(), message_three_before)
        self.assertEqual((self.output / "receipt.json").read_bytes(), receipt_before)

    def test_changed_opening_on_retry_is_rejected(self):
        self._complete_to_message_two()
        host_reveal(
            session_dir=self.host_private,
            input_path=self.paths[1],
            output_path=self.paths[2],
        )
        accepted = decode_message(self.paths[1].read_bytes())
        conflicting = RungBMessage(
            stage=Stage.SIGNER_OPENINGS,
            session_id=accepted.session_id,
            message_hash=accepted.message_hash,
            signer_pubkey=accepted.signer_pubkey,
            commitment=accepted.commitment,
            opening=public_key(bytes.fromhex("44" * 32)),
        )
        conflict_path = self.exchange / "conflicting-message-2.aex"
        conflict_path.write_bytes(conflicting.encode())
        with self.assertRaises(AntiExfilError) as raised:
            host_reveal(
                session_dir=self.host_private,
                input_path=conflict_path,
                output_path=self.exchange / "conflicting-message-3.aex",
            )
        self.assertEqual(raised.exception.code, ErrorCode.RETRY_CONFLICT)

    def test_changed_reveal_is_rejected_without_signature(self):
        self._complete_to_message_two()
        host_reveal(
            session_dir=self.host_private,
            input_path=self.paths[1],
            output_path=self.paths[2],
        )
        reveal = decode_message(self.paths[2].read_bytes())
        changed_rho = reveal.rho[:-1] + bytes([reveal.rho[-1] ^ 1])
        tampered = RungBMessage(
            stage=Stage.HOST_REVEAL,
            session_id=reveal.session_id,
            message_hash=reveal.message_hash,
            signer_pubkey=reveal.signer_pubkey,
            commitment=reveal.commitment,
            opening=reveal.opening,
            rho=changed_rho,
        )
        tampered_path = self.exchange / "tampered-message-3.aex"
        tampered_path.write_bytes(tampered.encode())
        destination = self.exchange / "must-not-exist-message-4.aex"
        with self.assertRaises(AntiExfilError) as raised:
            signer_sign(
                input_path=tampered_path,
                test_secret_key=self.SECRET,
                output_path=destination,
            )
        self.assertEqual(raised.exception.code, ErrorCode.COMMITMENT_MISMATCH)
        self.assertFalse(destination.exists())

    def test_each_cli_stage_runs_in_a_fresh_process(self):
        key_path = self.root / "test-key.json"
        key_path.write_text(json.dumps({"secret_key": self.SECRET.hex()}), encoding="utf-8")
        environment = os.environ.copy()
        source_root = str(Path(__file__).resolve().parents[2] / "src")
        environment["PYTHONPATH"] = source_root

        commands = [
            [
                "host-init",
                "--message-hash",
                self.MESSAGE.hex(),
                "--signer-pubkey",
                public_key(self.SECRET).hex(),
                "--session",
                str(self.host_private),
                "--out",
                str(self.paths[0]),
                "--test-rho",
                self.RHO.hex(),
                "--test-session-id",
                self.SESSION.hex(),
            ],
            ["signer-commit", "--in", str(self.paths[0]), "--test-key", str(key_path), "--out", str(self.paths[1])],
            ["host-reveal", "--session", str(self.host_private), "--in", str(self.paths[1]), "--out", str(self.paths[2])],
            ["signer-sign", "--in", str(self.paths[2]), "--test-key", str(key_path), "--out", str(self.paths[3])],
            [
                "host-verify",
                "--session",
                str(self.host_private),
                "--in",
                str(self.paths[3]),
                "--receipt",
                str(self.output / "receipt.json"),
            ],
        ]
        for command in commands:
            completed = subprocess.run(
                [sys.executable, "-m", "anti_exfil", *command],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
        receipt = json.loads((self.output / "receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "verified")


if __name__ == "__main__":
    unittest.main()
