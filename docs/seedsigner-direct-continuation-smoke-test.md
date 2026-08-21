# Clean SeedSigner direct-continuation smoke test

Purpose: confirm the clean SeedSigner/OS image retains the already selected seed
when message 3 is scanned through **Scan host reveal**, while ordinary
main-menu scanning remains stateless.

Use sections 4–7 of `protocol-v1-next-image-retest.md` with these updated paths:

```powershell
cd C:\Users\FractalEncrypt\Documents\SeedSigner_AntiExfil
$env:PYTHONPATH = "$PWD\src"
$py = "$PWD\.venv\Scripts\python.exe"
$sssrc = "C:\Users\FractalEncrypt\Documents\Windsurf\SeedSigner_AntiExfil_Review_Fresh\src"
$bridge = "$PWD\scripts\camera-bridge.cmd"
$run = "$PWD\run\protocol-v1-direct-continuation-clean-01"
$camera = "DroidCam Video"
```

Generate the fixture, load its public SeedQR, scan message 1, review the
transaction, create the nonce commitment, and capture message 2 exactly as the
existing guide specifies. Generate message 3, dismiss message 2, choose
**Scan host reveal**, and scan message 3.

Pass criteria:

- SeedSigner proceeds to protected signing without asking which seed to use;
- the retained fingerprint is the seed selected during message 1;
- message 4 completes and verifies all five slots with `broadcast: false`; and
- no nonce scalar or coordinator session is persisted on SeedSigner.

For the stateless control, start a fresh ceremony, choose **Exit to main menu**
after message 2, and scan message 3 through ordinary **Scan**. SeedSigner must
require the matching seed/context through the normal recovery path and still
complete successfully. This control may be recorded as a short observation
because the full stateless physical gate already passed previously.

## Result — 2026-08-12

Passed physically. Direct **Scan host reveal** continuation retained the seed
selected for message 1 and did not ask for another seed. A fresh ceremony that
returned to the main menu remained stateless and recovered through ordinary
**Scan**. The resulting single-signature Testnet4 transaction was accepted and
broadcast successfully.

During the same image session, the stock QR **Brighter/Darker** controls were
found to display their tips without changing the QR background. This is not an
anti-exfil state-machine failure; it is tracked separately as a current
SeedSigner/python-qrcode fallback regression and must be retested on the
corrected application image before the private review archive is frozen.
