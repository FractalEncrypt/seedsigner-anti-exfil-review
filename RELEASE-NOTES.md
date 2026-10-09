# Airgap Anti-Exfil tester kit — Windows x64 — 2026-10-09

This release contains everything you need to test the new anti-exfil signing
functionality on **Windows 10 or 11, x64**, with at least one supported device:

- **SeedSigner:** Pi Zero revision 1.3.
- **Kern:** Wave7B, ESP32-P4 revision v1.3.

The kit includes a custom Sparrow application with its own testing profile.
It leaves your existing Sparrow installation, wallets, and ordinary data
locations untouched. Java, both device images, and Kern's flashing tool are
included; no Git, Docker, WSL, or separate Java installation is needed.

Download **AexTest-20261009.zip** and **AexTest-20261009.zip.sha256**.
Follow the checksum check in [Download and test](https://github.com/FractalEncrypt/seedsigner-anti-exfil-review/blob/main/docs/download-and-test.md),
extract the ZIP once, and open **START-HERE.html**. Complete setup, then choose:

- **Live Testnet4 testing:** fund your own disposable test wallet, sign, and
  broadcast, with step-by-step singlesig and multisig instructions.
- **Prepared offline testing:** public seed QRs, transactions, and an HTML
  viewer for successful signing and rejection of malformed or malicious
  signing requests. Includes the interactive **Dark Skippy-style Sparrow
  rejection test** in **Open-Test-Cases.html**. No coins or server connection
  are needed. Additional tests are optional.

Open **FEEDBACK-OFFLINE.html** or **FEEDBACK-LIVE.html** for your testing path,
or **FEEDBACK.html** for the full form. Record what you tried and click
**Save feedback HTML**. Reopen the downloaded HTML to keep editing. Every result
has a Steps link. The optional issue-draft button prepares text you can review
and submit yourself with any screenshots or photos. Successful live tests can
include a TXID and network in a project issue.

Most new anti-exfil code and documentation were AI-written under human
direction. Extensive device testing and adversarial AI reviews are not an
independent human security audit. Read the colored notice in START-HERE before
running. Use disposable test seeds and testnet coins; offline fixtures cannot
be broadcast.

The application and firmware bytes are the versions tested on physical devices.
Coverage includes both signer orders, policy enforcement, proof persistence,
retry, stale replies, device rejection cases and Testnet3 signing. Single-device
multisig walkthroughs remain documented without end-to-end physical qualification.
macOS/Linux download packages and Jade firmware are not included.

Technical reviewers can download **AexSource-20261009.zip** and its **.sha256**
file for corresponding sources, build inputs, notices, exact identities and
review records. The tester kit already includes its required notices. The
historical frozen review archive remains a separate reference with its Sparrow
erratum; this release's qualification does not apply to that older runtime.
