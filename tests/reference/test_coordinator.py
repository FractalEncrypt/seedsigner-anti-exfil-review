from pathlib import Path
import os
import tempfile
import unittest

from anti_exfil.coordinator import prepare_message_3
from anti_exfil.crypto import public_key
from anti_exfil.errors import AntiExfilError, ErrorCode
from anti_exfil.messages import Stage, decode_message
from anti_exfil.psbt_tools import build_single_p2wpkh_fixture
from anti_exfil.psbt_workflow import host_init_psbt, signer_commit_psbt
from anti_exfil.storage import write_exact
from anti_exfil.transport import TransportNetwork, TransportPackage


SEEDSIGNER_SRC = Path(
    os.environ.get(
        "SEEDSIGNER_SRC",
        Path(__file__).resolve().parents[2] / "patches" / "seedsigner-qr" / "src",
    )
)


@unittest.skipUnless(SEEDSIGNER_SRC.is_dir(), "SeedSigner source is unavailable")
class CoordinatorRevealTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.psbt_path = self.root / "fixture.psbt"
        self.message_1_path = self.root / "message-1.aex"
        self.message_2_path = self.root / "signer-message-2.aex"
        self.package_2_path = self.root / "message-2.aext"
        self.session = self.root / "host-private"
        self.output = self.root / "live"
        psbt, self.secret = build_single_p2wpkh_fixture()
        write_exact(self.psbt_path, psbt)
        self.message_1, _ = host_init_psbt(
            psbt_path=self.psbt_path,
            signer_pubkey=public_key(self.secret),
            session_dir=self.session,
            output_path=self.message_1_path,
            rho=bytes.fromhex("a5" * 32),
            session_id=bytes.fromhex("c3" * 32),
        )
        self.message_2 = signer_commit_psbt(
            psbt_path=self.psbt_path,
            input_path=self.message_1_path,
            test_secret_key=self.secret,
            output_path=self.message_2_path,
        )
        write_exact(
            self.package_2_path,
            TransportPackage(
                self.message_2.encode(), TransportNetwork.TESTNET
            ).encode(),
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_message_2_prepares_strict_message_3_idempotently(self):
        first = prepare_message_3(
            input_package_path=self.package_2_path,
            session_dir=self.session,
            output_dir=self.output,
            seedsigner_src=SEEDSIGNER_SRC,
            expected_network=TransportNetwork.TESTNET,
            fragment_size=30,
            render_qr=False,
        )
        second = prepare_message_3(
            input_package_path=self.package_2_path,
            session_dir=self.session,
            output_dir=self.output,
            seedsigner_src=SEEDSIGNER_SRC,
            expected_network=TransportNetwork.TESTNET,
            fragment_size=30,
            render_qr=False,
        )
        self.assertEqual(first, second)
        package = TransportPackage.decode((self.output / "message-3.aext").read_bytes())
        self.assertEqual(decode_message(package.message).stage, Stage.HOST_REVEAL)
        self.assertEqual(package.psbt, self.psbt_path.read_bytes())
        self.assertGreater(first["animation_frames"], 1)

    def test_wrong_network_and_stage_fail_before_reveal(self):
        with self.assertRaises(AntiExfilError) as raised:
            prepare_message_3(
                input_package_path=self.package_2_path,
                session_dir=self.session,
                output_dir=self.output,
                seedsigner_src=SEEDSIGNER_SRC,
                expected_network=TransportNetwork.SIGNET,
                render_qr=False,
            )
        self.assertEqual(raised.exception.code, ErrorCode.TRANSACTION_MISMATCH)

        package_1 = self.root / "message-1.aext"
        write_exact(
            package_1,
            TransportPackage(
                self.message_1.encode(),
                TransportNetwork.TESTNET,
                self.psbt_path.read_bytes(),
            ).encode(),
        )
        with self.assertRaises(AntiExfilError) as raised:
            prepare_message_3(
                input_package_path=package_1,
                session_dir=self.session,
                output_dir=self.output,
                seedsigner_src=SEEDSIGNER_SRC,
                expected_network=TransportNetwork.TESTNET,
                render_qr=False,
            )
        self.assertEqual(raised.exception.code, ErrorCode.WRONG_STAGE)


if __name__ == "__main__":
    unittest.main()
