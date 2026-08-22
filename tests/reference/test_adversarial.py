import unittest

from anti_exfil.adversarial import (
    SelectiveAbortJournal,
    WalletAbortJournal,
    dark_skippy_signature,
    grind_nonce,
    predetermined_nonce_signature,
)
from anti_exfil.crypto import anti_exfil_sign, ecdsa_verify, host_commit, public_key, signer_opening, verify_anti_exfil
from anti_exfil.errors import AntiExfilError, ErrorCode


class AdversarialHarnessTest(unittest.TestCase):
    SECRET = bytes.fromhex("42" * 32)
    MESSAGE = bytes.fromhex("24" * 32)
    RHO = bytes.fromhex("a5" * 32)

    def assert_detected(self, malicious):
        pub = public_key(self.SECRET)
        opening = signer_opening(self.SECRET, self.MESSAGE, host_commit(self.RHO))
        self.assertTrue(ecdsa_verify(pub, self.MESSAGE, malicious))
        self.assertFalse(verify_anti_exfil(pub, self.MESSAGE, self.RHO, opening, malicious))

    def test_predetermined_nonce_is_valid_ecdsa_but_rejected_by_s2c(self):
        self.assert_detected(predetermined_nonce_signature(self.SECRET, self.MESSAGE))

    def test_dark_skippy_nonce_channel_is_detected(self):
        signature, nonce = dark_skippy_signature(self.SECRET, self.MESSAGE, 3)
        self.assertEqual(nonce & 7, int.from_bytes(self.SECRET, "big") & 7)
        self.assert_detected(signature)

    def test_nonce_grinding_channel_is_detected(self):
        signature, _ = grind_nonce(self.SECRET, self.MESSAGE, lambda point: point[1] == 0, 1000)
        self.assert_detected(signature)

    def test_honest_signature_passes_same_harness(self):
        signature, opening = anti_exfil_sign(self.SECRET, self.MESSAGE, self.RHO)
        self.assertTrue(verify_anti_exfil(public_key(self.SECRET), self.MESSAGE, self.RHO, opening, signature))

    def test_selective_abort_requires_same_session_and_exact_retry(self):
        journal = SelectiveAbortJournal(b"session" * 4 + b"xxxx")
        transcript = b"frozen-stage-two"
        journal.accept_openings(transcript)
        journal.accept_host_reveal(transcript)
        journal.record_post_reveal_failure()
        journal.require_exact_retry(journal.session_id, transcript)
        for session, retry in ((b"other" * 6 + b"xx", transcript), (journal.session_id, transcript + b"changed")):
            with self.assertRaises(AntiExfilError) as caught:
                journal.require_exact_retry(session, retry)
            self.assertEqual(caught.exception.code, ErrorCode.RETRY_CONFLICT)

    def test_wallet_abort_snapshot_revokes_only_first_reveal(self):
        journal = WalletAbortJournal()
        disclosed = journal.create_session(b"disclosed")
        staged = journal.create_session(b"staged")
        disclosed.accept_host_reveal(b"opening-a")
        disclosed.record_post_reveal_failure("SIGNER_CANCELLED")

        with self.assertRaises(AntiExfilError) as caught:
            staged.accept_host_reveal(b"opening-b")
        self.assertEqual(caught.exception.code, ErrorCode.RETRY_CONFLICT)

        disclosed.accept_host_reveal(b"opening-a")
        with self.assertRaises(AntiExfilError) as changed:
            disclosed.accept_host_reveal(b"changed")
        self.assertEqual(changed.exception.code, ErrorCode.RETRY_CONFLICT)

    def test_acknowledged_snapshot_is_revoked_by_later_abort(self):
        journal = WalletAbortJournal()
        first = journal.create_session(b"first")
        first.accept_host_reveal(b"first-opening")
        first.record_post_reveal_failure("USER_ABANDONED")

        acknowledged = journal.create_session(b"acknowledged", acknowledge_abort_history=True)
        later = journal.create_session(b"later", acknowledge_abort_history=True)
        later.accept_host_reveal(b"later-opening")
        later.record_post_reveal_failure("TRANSPORT_FAILED")
        with self.assertRaises(AntiExfilError) as caught:
            acknowledged.accept_host_reveal(b"acknowledged-opening")
        self.assertEqual(caught.exception.code, ErrorCode.RETRY_CONFLICT)

    def test_first_abort_reason_is_retained_and_rejection_is_automatic(self):
        journal = WalletAbortJournal()
        rejected = journal.create_session(b"rejected")
        first = rejected.reject_signer_data()
        duplicate = journal.record(b"rejected", "USER_ABANDONED")
        self.assertEqual(first, duplicate)
        self.assertEqual(first.reason, "SIGNATURE_REJECTED")
        self.assertEqual(len(journal.events), 1)

        with self.assertRaises(AntiExfilError) as blocked:
            journal.create_session(b"unacknowledged")
        self.assertEqual(blocked.exception.code, ErrorCode.RETRY_CONFLICT)


if __name__ == "__main__":
    unittest.main()
