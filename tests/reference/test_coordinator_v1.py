import json
import os
from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from embit.psbt import PSBT

from anti_exfil.coordinator_v1 import host_accept_openings_v1, host_complete_v1, host_init_v1
from anti_exfil.crypto import anti_exfil_sign, host_commit, public_key, signer_opening
from anti_exfil.errors import AntiExfilError, ErrorCode
from anti_exfil.protocol_v1_codec import Network, Stage
from anti_exfil.protocol_v1_transport import ProtocolV1Package
from anti_exfil.psbt_v1_fixtures import build_multiscript_fixture
from anti_exfil.qr_workflow_v1 import prepare_protocol_v1_qr
from anti_exfil.storage import write_exact
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
if not SEEDSIGNER_SRC.is_dir():
    raise unittest.SkipTest(
        "SeedSigner source is unavailable; set SEEDSIGNER_SRC to its src directory"
    )
if str(SEEDSIGNER_SRC) not in sys.path:
    sys.path.insert(0, str(SEEDSIGNER_SRC))

from seedsigner.helpers.anti_exfil_transport import AntiExfilTransportPackage
from seedsigner.models.anti_exfil_state import AntiExfilFlowState
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants
from anti_exfil.psbt_tools import SEEDSIGNER_TEST_MNEMONIC


class ReferenceNativeBackend:
    def host_commit(self, rho):
        return host_commit(rho)

    def signer_commit(self, secret_key, message_hash, commitment):
        return signer_opening(secret_key, message_hash, commitment)

    def sign(self, secret_key, message_hash, rho):
        return anti_exfil_sign(secret_key, message_hash, rho)[0]


class CoordinatorV1CrossImplementationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.session = self.base / "host-private"
        self.fixture = build_multiscript_fixture()
        self.psbt_path = self.base / "original.psbt"
        write_exact(self.psbt_path, self.fixture.psbt)
        self.paths = [self.base / f"message-{i}.aext" for i in range(1, 5)]
        self.rhos = {}

    def tearDown(self):
        self.temporary.cleanup()

    def initialize(self):
        from anti_exfil.psbt_v1 import enumerate_signing_slots
        slots = enumerate_signing_slots(self.fixture.psbt, self.fixture.root)
        self.rhos = {slot.identifier: bytes([0xa0 + i]) * 32 for i, slot in enumerate(slots)}
        return host_init_v1(
            psbt_path=self.psbt_path,
            root=self.fixture.root,
            network=Network.REGTEST,
            session_dir=self.session,
            output_package_path=self.paths[0],
            session_id=bytes.fromhex("c3" * 32),
            rhos=self.rhos,
        )

    def seedsigner_response(self, request_path, response_path):
        decoded = AntiExfilTransportPackage.decode(
            request_path.read_bytes(), expected_network=SettingsConstants.REGTEST
        )
        state = AntiExfilFlowState.from_package(decoded)
        response = state.create_response(
            seed=Seed(SEEDSIGNER_TEST_MNEMONIC.split()),
            network=SettingsConstants.REGTEST,
            backend=ReferenceNativeBackend(),
        )
        write_exact(response_path, response.encode())
        return response

    def test_complete_stateless_cross_implementation_transcript(self):
        self.initialize()
        message_2 = self.seedsigner_response(self.paths[0], self.paths[1])
        message_3 = host_accept_openings_v1(
            session_dir=self.session,
            input_package_path=self.paths[1],
            output_package_path=self.paths[2],
        )
        self.assertIsNone(message_2.psbt)
        self.assertEqual(message_3.psbt, self.fixture.psbt)

        # New state object and fresh seed object model stateless message-3 recovery.
        message_4 = self.seedsigner_response(self.paths[2], self.paths[3])
        self.assertIsNone(message_4.psbt)
        receipt = host_complete_v1(
            session_dir=self.session,
            input_package_path=self.paths[3],
            signed_psbt_path=self.base / "signed.psbt",
            receipt_path=self.base / "receipt.json",
        )
        self.assertEqual(receipt["slot_count"], 5)
        self.assertTrue(all(slot["anti_exfil_verified"] for slot in receipt["slots"]))
        self.assertFalse(receipt["broadcast"])
        signed = PSBT.parse((self.base / "signed.psbt").read_bytes())
        self.assertEqual(sum(len(scope.partial_sigs) for scope in signed.inputs), 5)

    def test_host_packages_render_as_seed_signer_qr_frames(self):
        self.initialize()
        message_1_qr = prepare_protocol_v1_qr(
            input_package_path=self.paths[0], output_dir=self.base / "message-1-qr",
            seedsigner_src=SEEDSIGNER_SRC, expected_stage=Stage.HOST_COMMIT,
            expected_network=Network.REGTEST, fragment_size=30, render_qr=True,
        )
        frame_texts = [
            path.read_text(encoding="ascii").strip()
            for path in sorted((self.base / "message-1-qr" / "frames").glob("frame-*.txt"))
        ]
        self.assertEqual(
            decode_ur_frames(frame_texts, seedsigner_src=SEEDSIGNER_SRC),
            self.paths[0].read_bytes(),
        )
        self.assertEqual(message_1_qr["slot_count"], 5)
        self.assertGreater(message_1_qr["animation_frames"], 1)
        self.assertEqual(
            ProtocolV1Package.decode(self.paths[0].read_bytes()).network,
            Network.REGTEST,
        )

    def test_opening_and_signature_retries_are_exact(self):
        self.initialize()
        self.seedsigner_response(self.paths[0], self.paths[1])
        first = host_accept_openings_v1(
            session_dir=self.session, input_package_path=self.paths[1], output_package_path=self.paths[2]
        )
        second = host_accept_openings_v1(
            session_dir=self.session, input_package_path=self.paths[1], output_package_path=self.paths[2]
        )
        self.assertEqual(first, second)
        self.seedsigner_response(self.paths[2], self.paths[3])
        first_receipt = host_complete_v1(
            session_dir=self.session, input_package_path=self.paths[3],
            signed_psbt_path=self.base / "signed.psbt", receipt_path=self.base / "receipt.json"
        )
        second_receipt = host_complete_v1(
            session_dir=self.session, input_package_path=self.paths[3],
            signed_psbt_path=self.base / "signed.psbt", receipt_path=self.base / "receipt.json"
        )
        self.assertEqual(first_receipt, second_receipt)

    def test_changed_opening_retry_is_rejected(self):
        self.initialize()
        self.seedsigner_response(self.paths[0], self.paths[1])
        host_accept_openings_v1(
            session_dir=self.session, input_package_path=self.paths[1], output_package_path=self.paths[2]
        )
        original = ProtocolV1Package.decode(self.paths[1].read_bytes())
        changed_slot = replace(original.message.slots[0], opening=public_key(bytes.fromhex("44" * 32)))
        changed_message = replace(
            original.message, slots=(changed_slot, *original.message.slots[1:])
        )
        changed_path = self.base / "changed-message-2.aext"
        write_exact(changed_path, ProtocolV1Package(changed_message, None).encode())
        with self.assertRaises(AntiExfilError) as raised:
            host_accept_openings_v1(
                session_dir=self.session,
                input_package_path=changed_path,
                output_package_path=self.base / "must-not-exist.aext",
            )
        self.assertEqual(raised.exception.code, ErrorCode.RETRY_CONFLICT)
        self.assertFalse((self.base / "must-not-exist.aext").exists())

    def test_changed_stored_original_fails_closed(self):
        self.initialize()
        self.seedsigner_response(self.paths[0], self.paths[1])
        host_accept_openings_v1(
            session_dir=self.session, input_package_path=self.paths[1], output_package_path=self.paths[2]
        )
        self.seedsigner_response(self.paths[2], self.paths[3])
        (self.session / "original.psbt").write_bytes(self.fixture.psbt + b"changed")
        with self.assertRaises(AntiExfilError) as raised:
            host_complete_v1(
                session_dir=self.session, input_package_path=self.paths[3],
                signed_psbt_path=self.base / "signed.psbt", receipt_path=self.base / "receipt.json"
            )
        self.assertEqual(raised.exception.code, ErrorCode.TRANSACTION_MISMATCH)

    def test_each_coordinator_cli_stage_runs_in_a_fresh_process(self):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")

        def run(*arguments):
            completed = subprocess.run(
                [sys.executable, "-m", "anti_exfil", *arguments],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

        run(
            "v1-host-init", "--psbt", str(self.psbt_path),
            "--signer-fingerprint", self.fixture.root.my_fingerprint.hex(),
            "--network", "REGTEST",
            "--session", str(self.session), "--out-package", str(self.paths[0]),
            "--test-session-id", ("c3" * 32),
        )
        self.seedsigner_response(self.paths[0], self.paths[1])
        run(
            "v1-host-reveal", "--session", str(self.session),
            "--in-package", str(self.paths[1]), "--out-package", str(self.paths[2]),
        )
        self.seedsigner_response(self.paths[2], self.paths[3])
        run(
            "v1-host-complete", "--session", str(self.session),
            "--in-package", str(self.paths[3]),
            "--signed-psbt", str(self.base / "cli-signed.psbt"),
            "--receipt", str(self.base / "cli-receipt.json"),
        )
        receipt = json.loads((self.base / "cli-receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["slot_count"], 5)
        self.assertFalse(receipt["broadcast"])


if __name__ == "__main__":
    unittest.main()
