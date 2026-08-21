# Current-upstream QR brightness correction gate

Purpose: verify the small SeedSigner compatibility fix found during the final
physical smoke tests. Current SeedSignerOS deliberately uses `python-qrcode`
instead of the removed native `qrencode` tool. The fallback must preserve and
normalize SeedSigner's requested QR background color.

This is a UX/release gate, not a cryptographic or anti-exfil protocol change.

## 1. Commit and publish the application correction

In SourceTree, open:

```text
C:\Users\FractalEncrypt\Documents\Windsurf\SeedSigner_AntiExfil_Review_Fresh
```

Exactly two files should be changed:

```text
src/seedsigner/helpers/qr.py
tests/test_seedqr.py
```

Committed as:

```text
aa8395e3576379467d795bb05268533e3a2ac082 Preserve QR brightness in Python renderer fallback
```

The local branch is one commit ahead of the personal fork. Push
`anti-exfil-review-v1` to the personal fork. Do not move the existing
`anti-exfil-review-v1-tested-2026-08-11` tag; it remains immutable evidence of
the earlier tested anti-exfil head. Record the new commit hash as `$appCommit`.

The focused local gate already reports `41 passed, 1 skipped` for the new QR
test plus the QR/anti-exfil set. Public CI should also pass before final bundle
freeze.

The Sparrow preview observation was investigated in:

```text
C:\Users\FractalEncrypt\Documents\Windsurf\Sparrow_AntiExfil_Review_Fresh
```

The same ending-frame preview occurred in installed stock Sparrow 2.4.0 and the
current-upstream review fork. It is a Windows/DroidCam capture-backend
presentation quirk, not an anti-exfil regression. Stale QR results remain
rejected during the existing 500 ms decoder window. The preview-only commit
was reverted to retain ordinary Sparrow presentation behavior:

```text
c88c5733afca81869aba8614366458e5fa5adb74 Revert "Hide buffered camera frames during scanner drain"
```

Physical testing then proved that explicit **Import > SeedSigner > Scan** also
defaulted to `UNSUPPORTED`. Static decoded-wallet QRs bypassed the parser method
that assigned `OPTIONAL`. This is corrected and committed locally as:

```text
74a3774 Default SeedSigner QR imports to optional protection
```

The original focused anti-exfil/scanner run passes 20/20. After restoring the
ordinary preview behavior, the directly affected QR decoder and SeedSigner
policy tests pass 5/5. The complete pre-revert Windows run passes 146/150; the
four failures are the unchanged CRLF-vs-LF golden export comparisons in
Caravan, Coldcard, and Specter DIY. Do not move the existing tested tag.

## 2. Build one corrected instrumented image

Use only the LF-safe corrected OS clone:

```powershell
$os = "C:\Users\FractalEncrypt\Documents\Windsurf\SeedSignerOS_AntiExfil_Review_Fresh_LF2"
$appRepo = "https://github.com/FractalEncrypt/FractalEncrypt_seedsigner.git"
$appCommit = "aa8395e3576379467d795bb05268533e3a2ac082"

Set-Location $os
git status --short --branch
git rev-parse HEAD
git -C opt/buildroot rev-parse HEAD

$env:DOCKER_DEFAULT_PLATFORM = "linux/amd64"
$env:SS_ARGS = "--pi0 --anti-exfil-test --app-repo=$appRepo --app-commit-id=$appCommit"
docker compose up --force-recreate --build
```

Do not add `--no-clean`. You do not need to monitor the build with Codex.

Record the result:

```powershell
$image = Join-Path $os "images\seedsigner_os.$appCommit.pi0.anti-exfil-test.img"
Get-Item $image | Select-Object FullName, Length, LastWriteTime
Get-FileHash $image -Algorithm SHA256
git status --short
```

The image must be 52,428,800 bytes and source status must remain clean.

## 3. Minimal device gate

Flash the image and let SeedSigner reach the main menu.

1. Display one static xpub QR.
2. Press Down repeatedly and verify the QR background visibly becomes darker.
3. Press Up repeatedly and verify it visibly becomes brighter.
4. Display one animated QR (an ordinary PSBT or an anti-exfil message is fine).
5. Repeat the Down/Up check and verify animation resumes after the tip closes.
6. Confirm the QR remains scannable at the normal/default setting.

Result on 2026-08-14: passed. Static and animated QR backgrounds respond in
both directions. The animated sequence resumes normally after the brightness
tip closes and does not freeze. The corrected image identity is recorded in
`final-smoke-checkpoint.json`.

In a disposable wallet, use **Import > SeedSigner > Scan** once and confirm the
result is **Airgapped Wallet (SeedSigner)** with **Protected signing: Optional**.
Repeat through the generic tpub/watch-only scanner and confirm it remains
**Unsupported**. No three-cosigner repeat is needed for this focused correction.

No funded transaction or complete signing ceremony is required. The direct
message-3, stateless recovery, and native self-test gates already passed and the
correction touches only QR background-color forwarding.

Optionally confirm the native receipt remains successful after shutdown:

```powershell
$boot = "G:\"
Get-Content (Join-Path $boot "anti-exfil-selftest.exit-code")
Get-Content (Join-Path $boot "anti-exfil-selftest.json") -Raw
```

## 4. Freeze inputs only after pass

After the physical brightness check and CI pass:

- create a new annotated SeedSigner review tag at the corrected commit;
- create a new annotated Sparrow review tag at its corrected commit;
- update the reviewer brief/checkpoint with that commit and tag;
- record the replacement image SHA-256 in `final-smoke-checkpoint.json`; and
- run `scripts/build_private_review_bundle.py` without `--allow-dirty`.
