"""Deterministic real-PSBT fixtures covering all protocol-v1 script forms."""

from __future__ import annotations
from dataclasses import dataclass
from embit import bip32, bip39, ec, script
from embit.networks import NETWORKS
from embit.psbt import DerivationPath, PSBT
from embit.transaction import SIGHASH, Transaction, TransactionInput, TransactionOutput
from .crypto import public_key
from .psbt_tools import SEEDSIGNER_TEST_MNEMONIC

@dataclass(frozen=True, slots=True)
class MultiScriptFixture:
    psbt: bytes
    root: bip32.HDKey
    paths: tuple[tuple[int, ...], ...]

def build_multiscript_fixture() -> MultiScriptFixture:
    root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(SEEDSIGNER_TEST_MNEMONIC), version=NETWORKS["regtest"]["xprv"])
    paths = tuple(tuple(bip32.parse_path(f"m/84h/1h/0h/0/{i}")) for i in range(5))
    controlled = [root.derive(path).key.get_public_key() for path in paths]
    external = [ec.PublicKey.parse(public_key(bytes([n]) * 32)) for n in (0x31, 0x32, 0x33)]
    native_multi = script.multisig(2, [controlled[2], external[0], controlled[3]])
    nested_multi = script.multisig(2, [external[1], controlled[4], external[2]])
    redeem_p2wpkh, redeem_p2wsh = script.p2wpkh(controlled[1]), script.p2wsh(nested_multi)
    prevouts = (script.p2wpkh(controlled[0]), script.p2sh(redeem_p2wpkh), script.p2wsh(native_multi), script.p2sh(redeem_p2wsh))
    tx = Transaction(2, [TransactionInput(bytes([0x41 + i]) * 32, i, 0xFFFFFFFD) for i in range(4)], [TransactionOutput(390_000, script.p2wpkh(external[0]))], 0)
    psbt = PSBT(tx)
    for i, prevout in enumerate(prevouts):
        psbt.inputs[i].witness_utxo = TransactionOutput(100_000 + i * 1_000, prevout)
        psbt.inputs[i].sighash_type = SIGHASH.ALL
    psbt.inputs[1].redeem_script = redeem_p2wpkh
    psbt.inputs[2].witness_script = native_multi
    psbt.inputs[3].redeem_script, psbt.inputs[3].witness_script = redeem_p2wsh, nested_multi
    for input_index, key_index in ((0, 0), (1, 1), (2, 2), (2, 3), (3, 4)):
        psbt.inputs[input_index].bip32_derivations[controlled[key_index]] = DerivationPath(root.my_fingerprint, list(paths[key_index]))
    return MultiScriptFixture(psbt.serialize(), root, paths)
