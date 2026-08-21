import unittest

from embit import ec
from embit.psbt import PSBT
from embit.transaction import SIGHASH

from anti_exfil.crypto import public_key
from anti_exfil.errors import AntiExfilError, ErrorCode
from anti_exfil.psbt_tools import (
    build_single_p2wpkh_fixture,
    find_single_p2wpkh_slot,
    reconstruct_signed_psbt,
)
from anti_exfil.crypto import anti_exfil_sign


class RungCPsbtToolsTest(unittest.TestCase):
    RHO = bytes.fromhex("a5" * 32)

    def setUp(self):
        self.original, self.secret = build_single_p2wpkh_fixture()
        self.pubkey = public_key(self.secret)
        self.psbt = PSBT.parse(self.original)
        self.slot = find_single_p2wpkh_slot(self.psbt, self.pubkey)

    def test_fixture_has_one_authoritative_p2wpkh_slot(self):
        self.assertEqual(self.slot.input_index, 0)
        self.assertEqual(self.slot.sighash_type, SIGHASH.ALL)
        self.assertEqual(len(self.slot.message_hash), 32)

    def test_signature_is_imported_and_transaction_finalizes(self):
        signature, _ = anti_exfil_sign(self.secret, self.slot.message_hash, self.RHO)
        signed_psbt, raw_transaction, txid = reconstruct_signed_psbt(
            self.original, self.slot, signature
        )
        parsed = PSBT.parse(signed_psbt)
        signer = ec.PublicKey.parse(self.pubkey)
        self.assertIn(signer, parsed.inputs[0].partial_sigs)
        self.assertGreater(len(raw_transaction), 0)
        self.assertEqual(len(txid), 64)

    def test_wrong_signer_is_rejected(self):
        with self.assertRaises(AntiExfilError) as raised:
            find_single_p2wpkh_slot(self.psbt, public_key(bytes.fromhex("44" * 32)))
        self.assertEqual(raised.exception.code, ErrorCode.SIGNATURE_SLOT_MISMATCH)

    def test_unsupported_sighash_is_rejected(self):
        self.psbt.inputs[0].sighash_type = SIGHASH.NONE
        with self.assertRaises(AntiExfilError) as raised:
            find_single_p2wpkh_slot(self.psbt, self.pubkey)
        self.assertEqual(raised.exception.code, ErrorCode.SIGNATURE_SLOT_MISMATCH)

    def test_existing_signature_is_not_silently_replaced(self):
        signature, _ = anti_exfil_sign(self.secret, self.slot.message_hash, self.RHO)
        signed_psbt, _, _ = reconstruct_signed_psbt(self.original, self.slot, signature)
        with self.assertRaises(AntiExfilError) as raised:
            reconstruct_signed_psbt(signed_psbt, self.slot, signature)
        self.assertEqual(raised.exception.code, ErrorCode.UNEXPECTED_RETURN_DATA)


if __name__ == "__main__":
    unittest.main()
