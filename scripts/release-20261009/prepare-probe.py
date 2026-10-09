from pathlib import Path
import json
repo=Path.cwd();work=repo/'run/device-test-usability-2026-10-09';kit=work/'preview/AexTest';out=kit/'Test-cases/remaining';a=json.loads((kit/'Test-cases/fixture-manifest.json').read_text(encoding='utf-8'))['accounts']
with (out/'accounts.tsv').open('w',encoding='utf-8') as f:
 for k in ['A','B']:
  for mode in ['multisig','singlesig']:f.write('\t'.join([k+'-'+mode,a[k]['fingerprint'],a[k][mode+'_path'],a[k][mode+'_tpub']])+'\n')
src=work/'probe-src/check';src.mkdir(parents=True,exist_ok=True)
(work/'probe-src/module-info.java').write_text('module fixture.check { requires com.sparrowwallet.drongo; requires com.sparrowwallet.sparrow; }\n',encoding='utf-8')
(src/'FixtureCheck.java').write_text('''package check;
import java.nio.file.*;
import java.util.*;
import com.sparrowwallet.drongo.*;
import com.sparrowwallet.drongo.psbt.*;
import com.sparrowwallet.drongo.antiexfil.*;
import com.sparrowwallet.drongo.wallet.*;
import com.sparrowwallet.drongo.policy.*;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.sparrow.transaction.AntiExfilPolicy;
public class FixtureCheck {
 static Path dir;
 static Map<String,Keystore> keys=new HashMap<>();
 static PSBT load(String name) throws Exception {return new PSBT(Files.readAllBytes(dir.resolve(name)),true);}
 static void expect(boolean ok,String message){if(!ok)throw new AssertionError(message);}
 public static void main(String[] args) throws Exception {
  Network.set(Network.TESTNET4);dir=Path.of(args[0]);
  expect(org.bitcoin.Secp256k1Context.isEnabled(),"Native secp256k1");
  for(String line:Files.readAllLines(dir.resolve("accounts.tsv"))){String[] f=line.split("\\t");Keystore key=new Keystore(f[0]);key.setKeyDerivation(new KeyDerivation(f[1],f[2]));key.setExtendedPublicKey(ExtendedKey.fromDescriptor(f[3]));key.setAntiExfilPolicy(AntiExfilKeystorePolicy.REQUIRED);keys.put(f[0],key);}
  int unsigned=0,signed=0;Set<String> txids=new HashSet<>();
  try(var paths=Files.list(dir)){
   for(Path path:paths.filter(p->p.toString().endsWith(".psbt")).sorted().toList()){
    byte[] raw=Files.readAllBytes(path);PSBT p=new PSBT(raw,true);AntiExfilPsbt.parseCanonicalV0(raw);expect(p.getFee()==500L,"Fee "+path);
    if(!p.hasSignatures()){
     boolean multi=path.getFileName().toString().startsWith("multisig");int slots=0;
     if(multi){slots=AntiExfilPsbt.enumerateSigningSlots(raw,keys.get("A-multisig")).size()+AntiExfilPsbt.enumerateSigningSlots(raw,keys.get("B-multisig")).size();expect(slots==2,"Two slots "+path);}
     else {slots=AntiExfilPsbt.enumerateSigningSlots(raw,keys.get("A-singlesig")).size();expect(slots==1,"One slot "+path);}
     expect(txids.add(p.getTransaction().getTxId().toString()),"Fresh identity "+path);unsigned++;
    }else{expect(p.getPsbtInputs().getFirst().getPartialSignatures().size()==1,"One valid ordinary signature");String stem=path.getFileName().toString().replace(".psbt","");byte[] qr=Base64.getDecoder().decode(Files.readString(dir.resolve(stem+".base64")).trim());expect(Arrays.equals(qr,raw),"QR exact bytes "+path);signed++;}
   }
  }
  expect(unsigned==19 && signed==4,"Fixture inventory");
  Wallet wallet=new Wallet("public-fixture-check");wallet.getKeystores().addAll(List.of(keys.get("A-multisig"),keys.get("B-multisig")));wallet.setPolicyType(PolicyType.MULTI_HD);wallet.setScriptType(ScriptType.P2WSH);wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD,ScriptType.P2WSH,wallet.getKeystores(),2));
  for(String who:List.of("A","B")){
   PSBT returned=load("multisig-required-required-ordinary-"+who+".psbt");PSBT base=load("multisig-required-required.psbt");base.verifyCombinedSignatures(returned);
   expect(AntiExfilPolicy.evaluateSignatureProvenance(wallet,returned,Set.of())==AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,"RR refuses "+who);
  }
  keys.get("B-multisig").setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL);
  for(String who:List.of("A","B")){
   PSBT returned=load("multisig-required-optional-ordinary-"+who+".psbt");load("multisig-required-optional.psbt").verifyCombinedSignatures(returned);
   var expected=who.equals("A")?AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING:AntiExfilPolicy.ProvenanceStatus.PERMITTED;
   expect(AntiExfilPolicy.evaluateSignatureProvenance(wallet,returned,Set.of())==expected,"RO "+who+" policy");
  }
  PSBT control=load("multisig-required-required.psbt");control.combine(load("multisig-required-required-ordinary-A.psbt"));control.combine(load("multisig-required-required-ordinary-B.psbt"));wallet.finalise(control);expect(control.isFinalized(),"Cryptographic two-signature control finalizes");
  System.out.println("PASS: 19 unique canonical unsigned PSBTs, expected signer slots/fee, 4 valid ordinary signatures and QR payload byte matches; RR refuses A/B; RO refuses Required A and permits Optional B; ordinary crypto-only control finalizes. No GUI, profile, camera or physical device operation.");
 }
}
''',encoding='utf-8')
print('Prepared native packaged-runtime fixture and policy probe.')
