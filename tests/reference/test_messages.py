import unittest

from anti_exfil.crypto import host_commit, public_key
from anti_exfil.errors import AntiExfilError, ErrorCode
from anti_exfil.messages import RungBMessage, Stage, decode_message


class RungBMessageTest(unittest.TestCase):
    SESSION = bytes.fromhex("c3" * 32)
    MESSAGE = bytes.fromhex("88" * 32)
    SECRET = bytes.fromhex("55" * 32)
    PUBKEY = public_key(SECRET)
    RHO = bytes.fromhex("a5" * 32)
    COMMITMENT = host_commit(RHO)

    def test_stage_one_canonical_round_trip(self):
        message = RungBMessage(
            stage=Stage.HOST_COMMIT,
            session_id=self.SESSION,
            message_hash=self.MESSAGE,
            signer_pubkey=self.PUBKEY,
            commitment=self.COMMITMENT,
        )
        self.assertEqual(decode_message(message.encode()), message)

    def test_trailing_data_is_rejected(self):
        message = RungBMessage(
            stage=Stage.HOST_COMMIT,
            session_id=self.SESSION,
            message_hash=self.MESSAGE,
            signer_pubkey=self.PUBKEY,
            commitment=self.COMMITMENT,
        )
        with self.assertRaises(AntiExfilError) as raised:
            decode_message(message.encode() + b"\x00")
        self.assertEqual(raised.exception.code, ErrorCode.INVALID_MESSAGE)

    def test_unknown_stage_is_rejected(self):
        message = bytearray(
            RungBMessage(
                stage=Stage.HOST_COMMIT,
                session_id=self.SESSION,
                message_hash=self.MESSAGE,
                signer_pubkey=self.PUBKEY,
                commitment=self.COMMITMENT,
            ).encode()
        )
        message[5] = 99
        with self.assertRaises(AntiExfilError) as raised:
            decode_message(bytes(message))
        self.assertEqual(raised.exception.code, ErrorCode.WRONG_STAGE)


if __name__ == "__main__":
    unittest.main()

