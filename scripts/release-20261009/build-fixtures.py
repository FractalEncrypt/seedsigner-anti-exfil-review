from pathlib import Path
import sys,json,hashlib,shutil,base64
from embit import bip32,bip39,ec,script
from embit.psbt import PSBT,DerivationPath
from embit.networks import NETWORKS
from embit.transaction import Transaction,TransactionInput,TransactionOutput
import qrcode
from PIL import Image
from pyzbar.pyzbar import decode
repo=Path.cwd();sys.path.insert(0,str(repo/'src'));from anti_exfil.psbt_v1 import enumerate_signing_slots,parse_psbt_v0
work=repo/'run/device-test-usability-2026-10-09';old=repo/'run/restart-retest-2026-10-09/preview/AexTest';kit=work/'preview/AexTest'
assert not kit.exists();shutil.copytree(old,kit);out=kit/'Test-cases/remaining';out.mkdir()
accounts=json.loads((kit/'Test-cases/fixture-manifest.json').read_text(encoding='utf-8'))['accounts'];roots={k:bip32.HDKey.from_seed(bip39.mnemonic_to_seed(accounts[k]['mnemonic']),version=NETWORKS['test']['xprv']) for k in ['A','B']};assert [roots[k].my_fingerprint.hex() for k in roots]==['0fb882ff','05d027a5']
records=[];ids=set()
for folder in [old/'Test-cases',old/'Sparrow/post-sync-fixtures']:
 for p in folder.glob('*.psbt'):ids.add(PSBT.parse(p.read_bytes()).tx.txid().hex())
oldids=set(ids)
def write(name,p,kind,**more):
 raw=p.serialize();parse_psbt_v0(raw);file=out/name;file.write_bytes(raw)
 for inp in p.inputs:
  for pub,sig in inp.partial_sigs.items():assert sig[-1]==1 and pub.verify(ec.Signature.parse(sig[:-1]),p.sighash(0,sighash=1))
 records.append({'file':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'transaction_id':p.tx.txid().hex(),'recipient_sats':p.outputs[0].value,'change_sats':p.outputs[1].value,'fee_sats':500,'kind':kind,**more})
 return p
serial=0
# Distinct transactions and public child keys; the same existing account descriptor applies.
def fresh(name,multi=False,feedback=None):
 global serial
 serial+=1;index=100+serial;owners=['A','B'] if multi else ['A'];path=bip32.parse_path('m/48h/1h/0h/2h' if multi else 'm/84h/1h/0h');fund=path+[0,index];change=path+[1,index]
 pubs={k:roots[k].derive(fund).key.get_public_key() for k in owners};cpubs={k:roots[k].derive(change).key.get_public_key() for k in owners}
 witness=script.multisig(2,sorted(pubs.values(),key=lambda p:p.sec())) if multi else None;cwitness=script.multisig(2,sorted(cpubs.values(),key=lambda p:p.sec())) if multi else None
 prev=script.p2wsh(witness) if multi else script.p2wpkh(pubs['A']);cs=script.p2wsh(cwitness) if multi else script.p2wpkh(cpubs['A'])
 parent=Transaction(2,[TransactionInput(hashlib.sha256(('aext-public-r5-fabricated-parent:'+name).encode()).digest(),0)], [TransactionOutput(100000,prev)],0)
 amount=30000+serial*100;recipient=ec.PrivateKey(bytes.fromhex('31'*32)).get_public_key();tx=Transaction(2,[TransactionInput(parent.txid(),0,0xfffffffd)],[TransactionOutput(amount,script.p2wpkh(recipient)),TransactionOutput(99500-amount,cs)],0);p=PSBT(tx)
 p.inputs[0].non_witness_utxo=parent;p.inputs[0].witness_utxo=parent.vout[0];p.inputs[0].witness_script=witness;p.inputs[0].sighash_type=1;p.outputs[1].witness_script=cwitness
 for k in owners:
  p.inputs[0].bip32_derivations[pubs[k]]=DerivationPath(roots[k].my_fingerprint,fund);p.outputs[1].bip32_derivations[cpubs[k]]=DerivationPath(roots[k].my_fingerprint,change);p.xpubs[roots[k].derive(path).to_public()]=DerivationPath(roots[k].my_fingerprint,path)
 assert p.tx.txid().hex() not in ids;ids.add(p.tx.txid().hex());assert not p.inputs[0].partial_sigs
 for k in owners:assert len(enumerate_signing_slots(p.serialize(),roots[k]))==1
 write(name+'.psbt',p,'unsigned',owners=owners,child_index=index,feedback=feedback)
 return p
rr=fresh('multisig-required-required',True,'requiredRequired');ro=fresh('multisig-required-optional',True,'requiredOptional');fresh('multisig-restart-proof',True,'restartProof')
# Reserve alternatives are supplied, but completed signer-order tests are credited.
fresh('multisig-order-A-B-reserve',True,'orderAB');fresh('multisig-order-B-A-reserve',True,'orderBA')
for device in ['SS','Kern']:
 fresh('singlesig-retry-'+device,False,'recovery'+device)
 fresh('singlesig-stale-origin-'+device,False,'stale'+device);fresh('singlesig-stale-target-'+device,False,'stale'+device)
 fresh('singlesig-protection-ordinary-'+device,False,'protection'+device);fresh('singlesig-protection-protected-'+device,False,'protection'+device)
 # Extra distinct recovery fixtures for optional pre-reveal/abandon checks.
 fresh('singlesig-cancel-'+device,False,None);fresh('singlesig-abandon-'+device,False,None)
for case,p in [('multisig-required-required',rr),('multisig-required-optional',ro)]:
 for k in ['A','B']:
  signed=PSBT.parse(p.serialize());assert signed.sign_with(roots[k])==1;name=case+'-ordinary-'+k+'.psbt';write(name,signed,'ordinary-valid-single-signature',same_transaction_as=case+'.psbt',owner=k)
  text=base64.b64encode(signed.serialize()).decode('ascii');qr=qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,box_size=8,border=4);qr.add_data(text);qr.make(fit=True);png=out/(name[:-5]+'.png');qr.make_image().save(png);result=decode(Image.open(png));assert len(result)==1 and result[0].data.decode()==text
  (out/(name[:-5]+'.base64')).write_text(text+'\n',encoding='ascii')
manifest={'scope':'Additive public unfunded fixtures for the remaining device series; no production change','broadcastable':False,'fabricated_parent_outpoints':True,'qualification':'Python canonical parser/slots, unique unsigned transaction IDs, fee/change, valid ordinary ECDSA, exact QR pixel decode PASS; packaged-runtime checks required before delivery','accounts':{k:{a:v for a,v in accounts[k].items() if a!='mnemonic'} for k in accounts},'transactions':records,'unsigned_transaction_count':serial,'old_transaction_ids_excluded':len(oldids)}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8');(work/'FIXTURE-CHECKS.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
for k,a in accounts.items():
 with (out/'accounts.tsv').open('a',encoding='utf-8') as f:f.write('\t'.join([k,a['fingerprint'],a['multisig_path'],a['multisig_tpub']])+'\n')
print('Prepared',serial,'distinct unsigned transactions and 4 valid ordinary signed returns; QR decode PASS.',flush=True)
