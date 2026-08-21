import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from anti_exfil.adversarial_device_v1 import (
    build_adversarial_cases_v1,
    generate_adversarial_device_corpus_v1,
)
from anti_exfil.crypto import anti_exfil_sign, host_commit, signer_opening
from anti_exfil.psbt_tools import SEEDSIGNER_TEST_MNEMONIC
from anti_exfil.protocol_v1_transport import ProtocolV1Package
from anti_exfil.qr_bitmap import extract_qr_frame


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

from seedsigner.helpers.anti_exfil_protocol import AntiExfilProtocolError
from seedsigner.helpers.anti_exfil_transport import AntiExfilTransportPackage
from seedsigner.models.anti_exfil_state import AntiExfilFlowState
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants


class ReferenceBackend:
    def host_commit(self, rho):
        return host_commit(rho)

    def signer_commit(self, secret_key, message_hash, commitment):
        return signer_opening(secret_key, message_hash, commitment)

    def sign(self, secret_key, message_hash, rho):
        return anti_exfil_sign(secret_key, message_hash, rho)[0]


class PhysicalRejectionCorpusV1Test(unittest.TestCase):
    def test_all_cases_reach_the_expected_seedsigner_rejection(self):
        seed = Seed(SEEDSIGNER_TEST_MNEMONIC.split())
        cases = build_adversarial_cases_v1()
        self.assertEqual(len(cases), 13)
        self.assertEqual(len({case.slug for case in cases}), len(cases))

        for case in cases:
            with self.subTest(case=case.slug):
                with self.assertRaises(AntiExfilProtocolError) as failure:
                    package = AntiExfilTransportPackage.decode(
                        case.payload,
                        expected_network=SettingsConstants.TESTNET4,
                    )
                    state = AntiExfilFlowState.from_package(package)
                    state.create_response(
                        seed=seed,
                        network=SettingsConstants.TESTNET4,
                        backend=ReferenceBackend(),
                    )
                self.assertEqual(failure.exception.code.value, case.expected_code)

    def test_only_the_three_wire_cases_bypass_the_strict_reference_transport(self):
        rejected = []
        for case in build_adversarial_cases_v1():
            try:
                ProtocolV1Package.decode(case.payload)
            except Exception:
                rejected.append(case.slug)
        self.assertEqual(rejected, [
            "03-outer-inner-network-mismatch",
            "10-duplicate-slot-record",
            "11-reordered-slot-records",
        ])

    def test_generator_retains_manifest_text_frames_and_verified_pngs(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "corpus"
            result = generate_adversarial_device_corpus_v1(
                output_dir=output,
                seedsigner_src=SEEDSIGNER_SRC,
                fragment_size=80,
                fountain_windows=1,
            )
            manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
            self.assertEqual(manifest["case_count"], 13)
            for case in manifest["cases"]:
                qr_paths = sorted(Path(case["qr_directory"]).glob("frame-*.png"))
                text_paths = sorted(
                    (Path(case["qr_directory"]).parent / "frames").glob("frame-*.txt")
                )
                self.assertEqual(len(qr_paths), case["animation_frames"])
                self.assertEqual(len(text_paths), len(qr_paths))
                self.assertEqual(
                    extract_qr_frame(qr_paths[0], seedsigner_src=SEEDSIGNER_SRC),
                    text_paths[0].read_text(encoding="ascii").strip(),
                )


if __name__ == "__main__":
    unittest.main()
