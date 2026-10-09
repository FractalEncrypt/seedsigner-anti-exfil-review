from pathlib import Path
import subprocess,shutil,json,hashlib,os
repo=Path.cwd();work=repo/'run/device-test-usability-2026-10-09';kit=work/'preview/AexTest';original=kit/'Sparrow/native-rebuild-windows-x64/engine';runtime=original/'runtime';jdk=repo/'run/native-rebuild-2026-10-08/post-install/jdk-25.0.2+10-crt1451/bin';engine=work/'probe-engine';
if not engine.exists():shutil.copytree(original,engine)
exports=['--add-exports=com.sparrowwallet.sparrow/com.sparrowwallet.sparrow.transaction=fixture.check','--add-exports=com.sparrowwallet.drongo/org.bitcoin=fixture.check']
classes=work/'probe-classes';classes.mkdir(exist_ok=True);subprocess.run([str(jdk/'javac.exe'),'--system',str(runtime),*exports,'-d',str(classes),str(work/'probe-src/module-info.java'),str(work/'probe-src/check/FixtureCheck.java')],check=True)
subprocess.run([str(jdk/'jar.exe'),'--create','--file',str(engine/'app/check.jar'),'-C',str(classes),'.'],check=True)
cfg=(original/'app/Sparrow.cfg').read_text(encoding='utf-8').replace('app.mainmodule=com.sparrowwallet.sparrow/com.sparrowwallet.sparrow.SparrowWallet','app.mainmodule=fixture.check/check.FixtureCheck\napp.modulepath=$APPDIR')
for option in exports:cfg+='\njava-options='+option
(engine/'app/Sparrow.cfg').write_text(cfg+'\n',encoding='utf-8')
r=subprocess.run([str(engine/'Sparrow.exe'),str(kit/'Test-cases/remaining')],capture_output=True,text=True,encoding='utf-8',timeout=50);(work/'native-fixture-check.log').write_text(r.stdout+r.stderr,encoding='utf-8');print(r.stdout+r.stderr,flush=True);assert r.returncode==0,r.returncode
(work/'PACKAGED-FIXTURE-CHECKS.json').write_text(json.dumps({'verdict':'PASS','method':'Native Sparrow launcher with isolated diagnostic entry point and unmodified r4 runtime/modules/native DLLs','runtime_modules_sha256':hashlib.sha256((runtime/'lib/modules').read_bytes()).hexdigest(),'scope':r.stdout.strip(),'physical_gui_signing':'Not performed','profile_operations':'None'},indent=2)+'\n',encoding='utf-8')
