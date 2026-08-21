from pathlib import Path
import os
import tempfile
import unittest

from embit.psbt import PSBT

from anti_exfil.crypto import public_key
from anti_exfil.errors import AntiExfilError, ErrorCode
from anti_exfil.messages import RungBMessage, Stage
from anti_exfil.psbt_tools import build_seedsigner_p2wpkh_fixture
from anti_exfil.seedsigner_adapter import derive_seedsigner_context, signer_commit_seedsigner
from anti_exfil.crypto import host_commit


SEEDSIGNER_SRC = Path(
    os.environ.get(
        "SEEDSIGNER_SRC",
        Path(__file__).resolve().parents[3]
        / "Windsurf"
        / "SeedSigner_AntiExfil"
        / "src",
    )
)


@unittest.skipUnless(SEEDSIGNER_SRC.exists(), "SeedSigner anti-exfil worktree is unavailable")
class RungDSeedSignerAdapterTest(unittest.TestCase):
    def setUp(self):
        self.raw, self.mnemonic = build_seedsigner_p2wpkh_fixture()

    def test_real_seedsigner_parser_and_derivation_select_the_slot(self):
        context = derive_seedsigner_context(
            psbt=PSBT.parse(self.raw),
            mnemonic=self.mnemonic,
            seedsigner_src=SEEDSIGNER_SRC,
        )
        self.assertEqual(context.fingerprint, "0fb882ff")
        self.assertEqual(context.derivation, "m/84h/1h/0h/0/0")
        self.assertEqual(context.input_amount, 100_000)
        self.assertEqual(context.spend_amount, 90_000)
        self.assertEqual(context.fee_amount, 10_000)
        self.assertEqual(context.slot.signer_pubkey, public_key(context.secret_key))

    def test_wrong_mnemonic_produces_no_signature_slot(self):
        wrong = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        with self.assertRaises(AntiExfilError) as raised:
            derive_seedsigner_context(
                psbt=PSBT.parse(self.raw), mnemonic=wrong, seedsigner_src=SEEDSIGNER_SRC
            )
        self.assertEqual(raised.exception.code, ErrorCode.SIGNATURE_SLOT_MISMATCH)

    def test_transcript_key_must_match_seedsigner_derived_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            psbt_path = root / "request.psbt"
            message_one = root / "message-1.aex"
            psbt_path.write_bytes(self.raw)
            context = derive_seedsigner_context(
                psbt=PSBT.parse(self.raw),
                mnemonic=self.mnemonic,
                seedsigner_src=SEEDSIGNER_SRC,
            )
            rho = bytes.fromhex("a5" * 32)
            request = RungBMessage(
                stage=Stage.HOST_COMMIT,
                session_id=bytes.fromhex("c3" * 32),
                message_hash=context.slot.message_hash,
                signer_pubkey=public_key(bytes.fromhex("55" * 32)),
                commitment=host_commit(rho),
            )
            message_one.write_bytes(request.encode())
            with self.assertRaises(AntiExfilError) as raised:
                signer_commit_seedsigner(
                    psbt_path=psbt_path,
                    input_path=message_one,
                    mnemonic=self.mnemonic,
                    seedsigner_src=SEEDSIGNER_SRC,
                    output_path=root / "message-2.aex",
                )
            self.assertEqual(raised.exception.code, ErrorCode.SIGNATURE_SLOT_MISMATCH)


if __name__ == "__main__":
    unittest.main()
