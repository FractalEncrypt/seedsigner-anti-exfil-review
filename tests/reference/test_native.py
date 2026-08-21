from pathlib import Path
import tempfile
import unittest

from anti_exfil.crypto import anti_exfil_sign, host_commit, public_key, signer_opening
from anti_exfil.errors import AntiExfilError, ErrorCode
from anti_exfil.native import NativeAntiExfil


NATIVE_LIBRARY = (
    Path(__file__).resolve().parents[2]
    / "run"
    / "native-build"
    / "bin"
    / "libsecp256k1-6.dll"
)


@unittest.skipUnless(NATIVE_LIBRARY.exists(), "pinned native D2 library is unavailable")
class NativeAntiExfilTest(unittest.TestCase):
    SECRET = bytes.fromhex("55" * 32)
    MESSAGE = bytes.fromhex("88" * 32)
    RHO = bytes.fromhex("a5" * 32)

    def test_native_outputs_match_pinned_reference_bytes(self):
        with NativeAntiExfil(NATIVE_LIBRARY) as native:
            commitment = native.host_commit(self.RHO)
            opening = native.signer_commit(self.SECRET, self.MESSAGE, commitment)
            signature = native.sign(self.SECRET, self.MESSAGE, self.RHO)
            self.assertEqual(commitment, host_commit(self.RHO))
            self.assertEqual(opening, signer_opening(self.SECRET, self.MESSAGE, commitment))
            self.assertEqual(signature, anti_exfil_sign(self.SECRET, self.MESSAGE, self.RHO)[0])
            self.assertTrue(
                native.verify(
                    public_key(self.SECRET), self.MESSAGE, self.RHO, opening, signature
                )
            )

    def test_native_verifier_rejects_changed_transcript(self):
        with NativeAntiExfil(NATIVE_LIBRARY) as native:
            commitment = native.host_commit(self.RHO)
            opening = native.signer_commit(self.SECRET, self.MESSAGE, commitment)
            signature = native.sign(self.SECRET, self.MESSAGE, self.RHO)
            changed_rho = self.RHO[:-1] + bytes([self.RHO[-1] ^ 1])
            self.assertFalse(
                native.verify(
                    public_key(self.SECRET), self.MESSAGE, changed_rho, opening, signature
                )
            )
            changed_signature = signature[:-1] + bytes([signature[-1] ^ 1])
            self.assertFalse(
                native.verify(
                    public_key(self.SECRET), self.MESSAGE, self.RHO, opening, changed_signature
                )
            )

    def test_native_rejects_invalid_secret_scalar(self):
        with NativeAntiExfil(NATIVE_LIBRARY) as native:
            with self.assertRaises(AntiExfilError) as raised:
                native.sign(bytes(32), self.MESSAGE, self.RHO)
        self.assertEqual(raised.exception.code, ErrorCode.NATIVE_BACKEND)


class NativeLibraryLoadFailureTest(unittest.TestCase):
    def test_missing_library_has_stable_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(AntiExfilError) as raised:
                NativeAntiExfil(Path(temporary) / "missing.dll")
        self.assertEqual(raised.exception.code, ErrorCode.NATIVE_BACKEND)


if __name__ == "__main__":
    unittest.main()
