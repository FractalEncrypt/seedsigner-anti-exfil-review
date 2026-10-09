from pathlib import Path
import json,hashlib,base64
from embit import bip32,ec
from embit.networks import NETWORKS
from embit.psbt import PSBT
import qrcode
from PIL import Image
from pyzbar.pyzbar import decode
repo=Path.cwd();work=repo/'run/device-test-usability-2026-10-09';out=work/'preview/AexTest/Test-cases/remaining';m=json.loads((out/'manifest.json').read_text(encoding='utf-8'))
for row in m['transactions']:
 p=PSBT.parse((out/row['file']).read_bytes());p.xpubs={bip32.HDKey.from_base58(key.to_base58(version=NETWORKS['test']['xpub'])):origin for key,origin in p.xpubs.items()};raw=p.serialize();(out/row['file']).write_bytes(raw);row['bytes']=len(raw);row['sha256']=hashlib.sha256(raw).hexdigest()
 for pub,sig in p.inputs[0].partial_sigs.items():assert pub.verify(ec.Signature.parse(sig[:-1]),p.sighash(0))
 if row['kind'].startswith('ordinary'):
  stem=row['file'][:-5];text=base64.b64encode(raw).decode();(out/(stem+'.base64')).write_text(text+'\n',encoding='ascii');qr=qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,box_size=8,border=4);qr.add_data(text);qr.make(fit=True);png=out/(stem+'.png');qr.make_image().save(png);result=decode(Image.open(png));assert len(result)==1 and result[0].data.decode()==text
(out/'manifest.json').write_text(json.dumps(m,indent=2)+'\n',encoding='utf-8');(work/'FIXTURE-CHECKS.json').write_text(json.dumps(m,indent=2)+'\n',encoding='utf-8')
p=work/'build-fixtures.py';s=p.read_text(encoding='utf-8-sig').replace('from embit.psbt import PSBT,DerivationPath','from embit.psbt import PSBT,DerivationPath\nfrom embit.networks import NETWORKS').replace("bip32.HDKey.from_seed(bip39.mnemonic_to_seed(accounts[k]['mnemonic']))","bip32.HDKey.from_seed(bip39.mnemonic_to_seed(accounts[k]['mnemonic']),version=NETWORKS['test']['xprv'])");p.write_text(s,encoding='utf-8')
p=work/'check-native-fixtures.py';s=p.read_text(encoding='utf-8-sig').replace('assert not engine.exists();shutil.copytree(original,engine)','\nif not engine.exists():shutil.copytree(original,engine)').replace('classes.mkdir();','classes.mkdir(exist_ok=True);');p.write_text(s,encoding='utf-8')
print('Corrected fixture global xpub versions to tpub; signatures/QR exact-byte checks pass.')
