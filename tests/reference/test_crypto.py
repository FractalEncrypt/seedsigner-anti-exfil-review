import unittest

from anti_exfil.crypto import (
    CryptoModelError,
    anti_exfil_sign,
    host_commit,
    parse_point,
    public_key,
    signer_opening,
    verify_anti_exfil,
)


class PinnedSecp256k1ZkpVectorsTest(unittest.TestCase):
    """Vectors from secp256k1-zkp tests_impl.h at pinned commit 2af926d."""

    SECRET = bytes.fromhex("55" * 32)
    MESSAGE = bytes.fromhex("88" * 32)

    def test_signer_opening_vector_1(self):
        commitment = bytes.fromhex(
            "1bf6fb42f41eb876c4d7aa0d67242b00"
            "baab99dc2084493e4e63277fa1f77f22"
        )
        expected = bytes.fromhex(
            "02df63755d1f3292bffed82986b10649"
            "7c93b1f8bdc0454b6b0b0a4779c0ef7188"
        )
        self.assertEqual(signer_opening(self.SECRET, self.MESSAGE, commitment), expected)

    def test_signer_opening_vector_2(self):
        commitment = bytes.fromhex(
            "35199a8fbf84ad6ef69a184c1b19285b"
            "efbe06e60b6264e6d373893f6855e24a"
        )
        expected = bytes.fromhex(
            "02c04ac7f771e8ebdbf315ff5e58b7fe"
            "9516102103500066172c4fac5b20f9e0ea"
        )
        self.assertEqual(signer_opening(self.SECRET, self.MESSAGE, commitment), expected)


class AntiExfilRoundTripTest(unittest.TestCase):
    SECRET = bytes.fromhex("55" * 32)
    MESSAGE = bytes.fromhex("88" * 32)
    RHO = bytes.fromhex("a5" * 32)

    def test_complete_transcript(self):
        commitment = host_commit(self.RHO)
        opening = signer_opening(self.SECRET, self.MESSAGE, commitment)
        signature, signing_opening = anti_exfil_sign(self.SECRET, self.MESSAGE, self.RHO)
        self.assertEqual(opening, signing_opening)
        self.assertTrue(
            verify_anti_exfil(
                public_key(self.SECRET), self.MESSAGE, self.RHO, opening, signature
            )
        )

    def test_changed_host_reveal_fails(self):
        signature, opening = anti_exfil_sign(self.SECRET, self.MESSAGE, self.RHO)
        changed_rho = self.RHO[:-1] + bytes([self.RHO[-1] ^ 1])
        self.assertFalse(
            verify_anti_exfil(
                public_key(self.SECRET), self.MESSAGE, changed_rho, opening, signature
            )
        )

    def test_changed_message_fails(self):
        signature, opening = anti_exfil_sign(self.SECRET, self.MESSAGE, self.RHO)
        changed_message = self.MESSAGE[:-1] + bytes([self.MESSAGE[-1] ^ 1])
        self.assertFalse(
            verify_anti_exfil(
                public_key(self.SECRET), changed_message, self.RHO, opening, signature
            )
        )

    def test_changed_signature_r_fails(self):
        signature, opening = anti_exfil_sign(self.SECRET, self.MESSAGE, self.RHO)
        changed_signature = bytes([signature[0] ^ 1]) + signature[1:]
        self.assertFalse(
            verify_anti_exfil(
                public_key(self.SECRET), self.MESSAGE, self.RHO, opening, changed_signature
            )
        )

    def test_invalid_opening_rejected(self):
        with self.assertRaises(CryptoModelError):
            parse_point(b"\x02" + b"\xff" * 32)


if __name__ == "__main__":
    unittest.main()

