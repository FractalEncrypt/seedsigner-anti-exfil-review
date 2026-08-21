import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from embit.psbt import PSBT

from anti_exfil.crypto import public_key
from anti_exfil.errors import AntiExfilError, ErrorCode
from anti_exfil.psbt_tools import build_single_p2wpkh_fixture
from anti_exfil.psbt_workflow import (
    host_init_psbt,
    host_verify_psbt,
    signer_commit_psbt,
    signer_sign_psbt,
)
from anti_exfil.workflow import host_reveal


class RungCPsbtWorkflowTest(unittest.TestCase):
    RHO = bytes.fromhex("a5" * 32)
    SESSION = bytes.fromhex("c3" * 32)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.host_private = self.root / "host-private"
        self.exchange = self.root / "exchange"
        self.output = self.root / "output"
        self.paths = [self.exchange / f"message-{number}.aex" for number in range(1, 5)]
        self.original, self.secret = build_single_p2wpkh_fixture()
        self.psbt_path = self.root / "original.psbt"
        self.psbt_path.write_bytes(self.original)

    def tearDown(self):
        self.temporary.cleanup()

    def _initialize(self):
        return host_init_psbt(
            psbt_path=self.psbt_path,
            signer_pubkey=public_key(self.secret),
            session_dir=self.host_private,
            output_path=self.paths[0],
            rho=self.RHO,
            session_id=self.SESSION,
        )

    def test_complete_psbt_transcript_reconstructs_without_broadcast(self):
        _, slot = self._initialize()
        signer_commit_psbt(
            psbt_path=self.psbt_path,
            input_path=self.paths[0],
            test_secret_key=self.secret,
            output_path=self.paths[1],
        )
        host_reveal(
            session_dir=self.host_private,
            input_path=self.paths[1],
            output_path=self.paths[2],
        )
        signer_sign_psbt(
            psbt_path=self.psbt_path,
            input_path=self.paths[2],
            test_secret_key=self.secret,
            output_path=self.paths[3],
        )
        receipt = host_verify_psbt(
            session_dir=self.host_private,
            input_path=self.paths[3],
            signed_psbt_path=self.output / "signed.psbt",
            raw_transaction_path=self.output / "transaction.raw",
            receipt_path=self.output / "receipt.json",
        )
        self.assertEqual(receipt["message_hash"], slot.message_hash.hex())
        self.assertTrue(receipt["psbt_reconstructed_from_original"])
        self.assertFalse(receipt["broadcast"])
        self.assertTrue((self.output / "signed.psbt").exists())
        self.assertTrue((self.output / "transaction.raw").exists())

    def test_transaction_changed_before_opening_is_rejected(self):
        self._initialize()
        changed = PSBT.parse(self.original)
        # PSBTv2 stores the authoritative output fields in its OutputScope.
        changed.outputs[0].value -= 1
        changed_path = self.root / "changed.psbt"
        changed_path.write_bytes(changed.serialize())
        with self.assertRaises(AntiExfilError) as raised:
            signer_commit_psbt(
                psbt_path=changed_path,
                input_path=self.paths[0],
                test_secret_key=self.secret,
                output_path=self.paths[1],
            )
        self.assertEqual(raised.exception.code, ErrorCode.TRANSACTION_MISMATCH)
        self.assertFalse(self.paths[1].exists())

    def test_transaction_changed_after_reveal_is_rejected_without_signature(self):
        self._initialize()
        signer_commit_psbt(
            psbt_path=self.psbt_path,
            input_path=self.paths[0],
            test_secret_key=self.secret,
            output_path=self.paths[1],
        )
        host_reveal(
            session_dir=self.host_private,
            input_path=self.paths[1],
            output_path=self.paths[2],
        )
        changed = PSBT.parse(self.original)
        changed.outputs[0].value -= 1
        changed_path = self.root / "changed.psbt"
        changed_path.write_bytes(changed.serialize())
        with self.assertRaises(AntiExfilError) as raised:
            signer_sign_psbt(
                psbt_path=changed_path,
                input_path=self.paths[2],
                test_secret_key=self.secret,
                output_path=self.paths[3],
            )
        self.assertEqual(raised.exception.code, ErrorCode.TRANSACTION_MISMATCH)
        self.assertFalse(self.paths[3].exists())

    def test_host_rejects_changed_stored_original(self):
        self._initialize()
        stored = self.host_private / "original.psbt"
        stored.write_bytes(self.original + b"changed")
        with self.assertRaises(AntiExfilError) as raised:
            host_verify_psbt(
                session_dir=self.host_private,
                input_path=self.paths[3],
                signed_psbt_path=self.output / "signed.psbt",
                raw_transaction_path=self.output / "transaction.raw",
                receipt_path=self.output / "receipt.json",
            )
        self.assertEqual(raised.exception.code, ErrorCode.TRANSACTION_MISMATCH)

    def test_each_psbt_cli_stage_runs_in_a_fresh_process(self):
        key_path = self.root / "test-key.json"
        key_path.write_text(json.dumps({"secret_key": self.secret.hex()}), encoding="utf-8")
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
        commands = [
            [
                "host-init-psbt",
                "--psbt", str(self.psbt_path),
                "--signer-pubkey", public_key(self.secret).hex(),
                "--session", str(self.host_private),
                "--out", str(self.paths[0]),
                "--test-rho", self.RHO.hex(),
                "--test-session-id", self.SESSION.hex(),
            ],
            [
                "signer-commit-psbt",
                "--psbt", str(self.psbt_path),
                "--in", str(self.paths[0]),
                "--test-key", str(key_path),
                "--out", str(self.paths[1]),
            ],
            [
                "host-reveal",
                "--session", str(self.host_private),
                "--in", str(self.paths[1]),
                "--out", str(self.paths[2]),
            ],
            [
                "signer-sign-psbt",
                "--psbt", str(self.psbt_path),
                "--in", str(self.paths[2]),
                "--test-key", str(key_path),
                "--out", str(self.paths[3]),
            ],
            [
                "host-verify-psbt",
                "--session", str(self.host_private),
                "--in", str(self.paths[3]),
                "--signed-psbt", str(self.output / "signed.psbt"),
                "--raw-transaction", str(self.output / "transaction.raw"),
                "--receipt", str(self.output / "receipt.json"),
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
        self.assertTrue(receipt["anti_exfil_opening_verified"])
        self.assertFalse(receipt["broadcast"])


if __name__ == "__main__":
    unittest.main()
