from dataclasses import replace
import hashlib
import json
from pathlib import Path
import unittest

from embit import bip32, bip39, ec, script
from embit.networks import NETWORKS
from embit.psbt import DerivationPath, PSBT
from embit.transaction import SIGHASH, Transaction, TransactionInput, TransactionOutput

from anti_exfil.crypto import anti_exfil_sign, public_key
from anti_exfil.errors import AntiExfilError
from anti_exfil.protocol_v1_codec import Network, ProtocolMessage, SigningSlot, Stage, decode_message
from anti_exfil.protocol_v1_transport import ProtocolV1Package
from anti_exfil.psbt_v1 import build_host_commit_message, enumerate_signing_slots, parse_psbt_v0, reconstruct_signed_psbt_v1
from anti_exfil.psbt_v1_fixtures import build_multiscript_fixture


class SemanticPsbtV1Test(unittest.TestCase):
    def setUp(self):
        self.fixture = build_multiscript_fixture()

    def mutate(self, change):
        psbt = PSBT.parse(self.fixture.psbt)
        change(psbt)
        return psbt.serialize()

    def test_real_fixture_enumerates_canonically_with_real_sighashes(self):
        slots = enumerate_signing_slots(self.fixture.psbt, self.fixture.root)
        self.assertEqual([slot.input_index for slot in slots], [0, 1, 2, 2, 3])
        self.assertEqual([slot.script_kind for slot in slots], [
            "p2wpkh", "p2sh-p2wpkh", "p2wsh-multisig", "p2wsh-multisig", "p2sh-p2wsh-multisig"
        ])
        self.assertEqual(tuple(sorted(slot.identifier for slot in slots)), tuple(slot.identifier for slot in slots))
        parsed = PSBT.parse(self.fixture.psbt)
        for slot in slots:
            self.assertEqual(slot.message_hash, parsed.sighash(slot.input_index, sighash=SIGHASH.ALL))
        self.assertEqual(slots[2].message_hash, slots[3].message_hash)

    def test_semantic_golden_vector(self):
        path = Path(__file__).resolve().parents[2] / "fixtures" / "protocol-v1-semantic-psbt-vector.json"
        golden = json.loads(path.read_text(encoding="utf-8"))
        slots = enumerate_signing_slots(self.fixture.psbt, self.fixture.root)
        self.assertEqual(hashlib.sha256(self.fixture.psbt).hexdigest(), golden["psbt_sha256"])
        self.assertEqual(len(slots), golden["slot_count"])
        self.assertEqual([
            {"input_index": item.input_index, "script_kind": item.script_kind,
             "signer_pubkey": item.signer_pubkey.hex(), "message_hash": item.message_hash.hex()}
            for item in slots
        ], golden["slots"])

    def test_mixed_provenance_vector_preserves_ordinary_signature_without_blessing_it(self):
        path = Path(__file__).resolve().parents[2] / "fixtures" / "protocol-v1-mixed-provenance-vector.json"
        vector = json.loads(path.read_text(encoding="utf-8"))
        original = bytes.fromhex(vector["original_psbt_hex"])
        self.assertEqual(original, (path.parent / "protocol-v1-mixed-provenance.psbt").read_bytes())
        signed = bytes.fromhex(vector["signed_psbt_hex"])
        commit = decode_message(bytes.fromhex(vector["message_1_hex"]))
        signatures = decode_message(bytes.fromhex(vector["message_4_hex"]))
        rho = bytes.fromhex(vector["host_randomness"])
        root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(vector["signer_a"]["mnemonic"]),
                                     version=NETWORKS["regtest"]["xprv"])

        rebuilt = reconstruct_signed_psbt_v1(original, root, commit, signatures,
                                             {commit.slots[0].identifier: rho})
        self.assertEqual(signed, rebuilt)
        parsed_original = parse_psbt_v0(original)
        parsed_signed = parse_psbt_v0(signed)
        self.assertEqual(1, len(parsed_original.inputs[0].partial_sigs))
        self.assertEqual(2, len(parsed_signed.inputs[0].partial_sigs))
        self.assertEqual(bytes.fromhex(vector["signer_a"]["pubkey"]), signatures.slots[0].signer_pubkey)
        self.assertNotEqual(bytes.fromhex(vector["signer_b"]["ordinary_signature_der"]),
                            signatures.slots[0].signature)

    def test_psbt_version_and_encoding_mutations_fail(self):
        for raw in (self.fixture.psbt[:-1], self.fixture.psbt + b"trailing", b"not-a-psbt"):
            with self.subTest(length=len(raw)), self.assertRaises(AntiExfilError):
                parse_psbt_v0(raw)
        v2 = PSBT.parse(self.fixture.psbt)
        v2.version = 2
        with self.assertRaises(AntiExfilError):
            parse_psbt_v0(v2.serialize())

    def test_utxo_script_and_sighash_mutations_fail_closed(self):
        mutations = (
            lambda p: setattr(p.inputs[0], "witness_utxo", None),
            lambda p: setattr(p.inputs[1], "redeem_script", None),
            lambda p: setattr(p.inputs[2], "witness_script", script.Script(b"\x51")),
            lambda p: setattr(p.inputs[3], "redeem_script", script.p2wpkh(next(iter(p.inputs[3].bip32_derivations)))),
            lambda p: setattr(p.inputs[0], "sighash_type", SIGHASH.NONE),
            lambda p: setattr(p.inputs[0], "sighash_type", SIGHASH.ALL | SIGHASH.ANYONECANPAY),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(AntiExfilError):
                enumerate_signing_slots(self.mutate(mutation), self.fixture.root)

        def disagreeing_utxos(p):
            previous = Transaction(2, [TransactionInput(bytes.fromhex("77" * 32), 0)],
                                   [TransactionOutput(999_999, p.inputs[0].witness_utxo.script_pubkey)], 0)
            p.tx.vin[0].txid = previous.txid()
            p.tx.vin[0].vout = 0
            p.inputs[0].non_witness_utxo = previous
        with self.assertRaises(AntiExfilError):
            enumerate_signing_slots(self.mutate(disagreeing_utxos), self.fixture.root)

    def test_derivation_and_preexisting_signature_mutations_fail(self):
        def wrong_path(p):
            pub = next(iter(p.inputs[0].bip32_derivations))
            p.inputs[0].bip32_derivations[pub] = DerivationPath(self.fixture.root.my_fingerprint, [0])
        def foreign_key(p):
            pub = next(iter(p.inputs[0].bip32_derivations))
            p.inputs[1].bip32_derivations[pub] = p.inputs[0].bip32_derivations[pub]
        def signed(p):
            pub = next(iter(p.inputs[0].bip32_derivations))
            p.inputs[0].partial_sigs[pub] = b"invalid-existing-signature"
        for mutation in (wrong_path, foreign_key, signed):
            with self.subTest(mutation=mutation), self.assertRaises(AntiExfilError):
                enumerate_signing_slots(self.mutate(mutation), self.fixture.root)

    def test_taproot_and_mixed_legacy_inputs_fail_whole_request(self):
        pub = ec.PublicKey.parse(public_key(bytes.fromhex("11" * 32)))
        for replacement in (script.p2tr(pub), script.p2pkh(pub)):
            with self.subTest(kind=replacement.script_type()), self.assertRaises(AntiExfilError):
                enumerate_signing_slots(self.mutate(lambda p, r=replacement: setattr(p.inputs[3], "witness_utxo", TransactionOutput(103000, r))), self.fixture.root)

    def test_exact_commit_set_network_and_duplicate_randomness(self):
        slots = enumerate_signing_slots(self.fixture.psbt, self.fixture.root)
        rhos = {slot.identifier: bytes([i + 1]) * 32 for i, slot in enumerate(slots)}
        message = build_host_commit_message(self.fixture.psbt, self.fixture.root, Network.TESTNET4, b"s" * 32, rhos)
        self.assertEqual(message.network, Network.TESTNET4)
        self.assertEqual([record.identifier for record in message.slots], [slot.identifier for slot in slots])
        incomplete = dict(rhos); incomplete.pop(slots[-1].identifier)
        with self.assertRaises(AntiExfilError):
            build_host_commit_message(self.fixture.psbt, self.fixture.root, Network.TESTNET4, b"s" * 32, incomplete)
        duplicate = dict(rhos); duplicate[slots[-1].identifier] = duplicate[slots[0].identifier]
        with self.assertRaises(AntiExfilError):
            build_host_commit_message(self.fixture.psbt, self.fixture.root, Network.TESTNET4, b"s" * 32, duplicate)

    def test_atomic_reconstruction_sanitizes_returned_metadata(self):
        original = PSBT.parse(self.fixture.psbt)
        original.inputs[0].unknown[b"\xfcmetadata"] = b"host-owned"
        raw = original.serialize()
        semantic = enumerate_signing_slots(raw, self.fixture.root)
        rhos = {slot.identifier: bytes([0x80 + i]) * 32 for i, slot in enumerate(semantic)}
        commit = build_host_commit_message(raw, self.fixture.root, Network.TESTNET4, b"z" * 32, rhos)
        records = []
        for slot, base in zip(semantic, commit.slots, strict=True):
            secret = self.fixture.root.derive(slot.derivation).key.secret
            signature, opening = anti_exfil_sign(secret, slot.message_hash, rhos[slot.identifier])
            records.append(replace(base, opening=opening, signature=signature))
        response = ProtocolMessage(Network.TESTNET4, Stage.SIGNER_SIGNATURES, commit.session_id, commit.psbt_digest, tuple(records))
        with self.assertRaises(AntiExfilError):
            ProtocolV1Package(response, raw).encode()
        signed = reconstruct_signed_psbt_v1(raw, self.fixture.root, commit, response, rhos)
        parsed = PSBT.parse(signed)
        self.assertEqual(parsed.inputs[0].unknown[b"\xfcmetadata"], b"host-owned")
        self.assertEqual(sum(len(scope.partial_sigs) for scope in parsed.inputs), 5)
        with self.assertRaises(AntiExfilError):
            reconstruct_signed_psbt_v1(raw, self.fixture.root, commit, replace(response, slots=response.slots[:-1]), rhos)


if __name__ == "__main__":
    unittest.main()
