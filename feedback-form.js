/* Local feedback: no network request or automatic submission. */
(function(global) {
'use strict';
const results = [["launch", "Sparrow opens directly on Testnet4"], ["camera", "Static ordinary-return camera scan"], ["animatedLow", "Animated scan: low density"], ["animatedMedium", "Animated scan: medium density"], ["animatedHigh", "Animated scan: high density"], ["cancel", "Camera cancel / reopen"], ["network", "Public Testnet4 connection and UTXOs"], ["reconnect", "Network toggle reconnect"], ["receiveSend", "Receive / Send views"], ["single", "Fresh protected singlesig: SeedSigner"], ["singleKern", "Fresh protected singlesig: Kern"], ["multi", "Protected 2-of-2: A then B; both signatures and finalization"], ["orderBA", "Fresh multisig: signer B then A"], ["ordinary", "Ordinary return refused: REQUIRED_PROOF_MISSING"], ["restart", "Required remains after restart; ordinary return refused"], ["requiredRequired", "Required / Required fails closed for ordinary returns"], ["requiredOptional", "Required / Optional: Required signer fails closed"], ["restartProof", "Restart after first protected proof; retain it, add second, finalize"], ["recoverySS", "Interruption / recovery: SeedSigner"], ["recoveryKern", "Interruption / recovery: Kern"], ["staleSS", "Stale reply refused: SeedSigner session"], ["staleKern", "Stale reply refused: Kern session"], ["protectionSS", "Protection on/off cases: SeedSigner; restored on"], ["protectionKern", "Protection on/off cases: Kern; restored on"], ["rejectSS01", "01: wrong mainnet — SeedSigner"], ["rejectKern01", "01: wrong mainnet — Kern"], ["rejectSS02", "02: wrong stage message 2 — SeedSigner"], ["rejectKern02", "02: wrong stage message 2 — Kern"], ["rejectSS03", "03: outer inner network mismatch — SeedSigner"], ["rejectKern03", "03: outer inner network mismatch — Kern"], ["rejectSS04", "04: truncated psbt — SeedSigner"], ["rejectKern04", "04: truncated psbt — Kern"], ["rejectSS05", "05: missing utxo — SeedSigner"], ["rejectKern05", "05: missing utxo — Kern"], ["rejectSS06", "06: broken witness script — SeedSigner"], ["rejectKern06", "06: broken witness script — Kern"], ["rejectSS07", "07: wrong derivation path — SeedSigner"], ["rejectKern07", "07: wrong derivation path — Kern"], ["rejectSS08", "08: unsupported sighash none — SeedSigner"], ["rejectKern08", "08: unsupported sighash none — Kern"], ["rejectSS09", "09: mixed taproot input — SeedSigner"], ["rejectKern09", "09: mixed taproot input — Kern"], ["rejectSS10", "10: duplicate slot record — SeedSigner"], ["rejectKern10", "10: duplicate slot record — Kern"], ["rejectSS11", "11: reordered slot records — SeedSigner"], ["rejectKern11", "11: reordered slot records — Kern"], ["rejectSS12", "12: altered host reveal — SeedSigner"], ["rejectKern12", "12: altered host reveal — Kern"], ["rejectSS13", "13: altered signer opening — SeedSigner"], ["rejectKern13", "13: altered signer opening — Kern"], ["testnet3SS", "Testnet3 protected singlesig: SeedSigner"], ["testnet3Kern", "Testnet3 protected singlesig: Kern"], ["testnet3Multi", "Testnet3 multisig (additional coverage)"], ["liveBroadcast", "Live transaction broadcast accepted"], ["liveConfirmation", "Live transaction confirmed (optional)"], ["attackA", "Dark Skippy A: malicious signature rejected"], ["attackA2", "Dark Skippy A2 (optional repeat)"], ["attackA3", "Dark Skippy A3 (optional repeat)"]];
function buildDraft(v) {
 const lines=['## Anti-exfil test feedback','','Kit: '+(v.kit||'Windows x64, 2026-10-09'),'Device: '+(v.device||'Not specified'),'Outcome: '+v.outcome];
 for(const [key,label] of [['deviceOther','Other hardware / source build details'],['testedKit','Package actually tested'],['checksum','Tested ZIP SHA-256'],['os','Computer / OS'],['webcam','Camera / browser'],['path','Testing path']]) if(v[key]?.trim())lines.push(label+': '+v[key].trim());
 const tried=results.filter(([key])=>v[key] && !['Not run','Not tried'].includes(v[key]));
 if(tried.length)lines.push('','### Tests tried',...tried.map(([key,label])=>'- '+label+': '+v[key]));
 if(v.skippy && v.skippy!=='Not tried')lines.push('- Dark Skippy-style Sparrow rejection: '+v.skippy);
 for(const [key,label] of [['notes','What happened / feedback'],['other','Additional test details']])if(v[key]?.trim())lines.push('','### '+label,v[key].trim());
 if(v.txid?.trim())lines.push('','Live TXID / network: '+v.txid.trim());
 if(v.round)lines.push('','Extra QR round: '+v.round);
 return {title:'Test feedback: '+(v.device||'Not specified')+' — '+v.outcome,body:lines.join('\n')};
}
function issueLink(title,body) {
 const base='https://github.com/FractalEncrypt/seedsigner-anti-exfil-review/issues/new';
 const url=base+'?'+new URLSearchParams({title,body}).toString();
 return url.length<=7500?{url,needsPaste:false}:{url:base+'?'+new URLSearchParams({title}).toString(),needsPaste:true};
}
function snapshot(doc) {
 const clone=doc.documentElement.cloneNode(true);
 for(const field of doc.querySelectorAll('input,select,textarea')) {
  const copy=clone.querySelector('#'+field.id);
  if(!copy)continue;
  if(field.tagName==='TEXTAREA')copy.textContent=field.value;
  else if(field.tagName==='SELECT')for(const option of copy.options)option.toggleAttribute('selected',option.value===field.value);
  else {copy.setAttribute('value',field.value);if(field.type==='checkbox'||field.type==='radio')copy.toggleAttribute('checked',field.checked);}
 }
 clone.querySelector('#status').textContent='Saved feedback. You can edit these fields and save another HTML copy.';
 // Keep saved feedback portable: the local kit link is no longer relative.
 for(const local of clone.querySelectorAll('#security-link,[data-kit-link]')){local.removeAttribute('href');local.textContent='the original kit’s '+(local.dataset.kitLink||'SECURITY.html');}
 return '<!doctype html>\n'+clone.outerHTML;
}
global.FeedbackDraft={buildDraft,issueLink,snapshot};
if(typeof document==='undefined')return;
const el=id=>document.getElementById(id),say=text=>{el('status').textContent=text;};
el('feedback-form').addEventListener('submit',event=>{
 event.preventDefault();
 const values=Object.fromEntries([...document.querySelectorAll('#feedback-form input,#feedback-form select,#feedback-form textarea')].map(field=>[field.id,field.value]));
 const draft=buildDraft(values);el('title').value=draft.title;el('draft').value=draft.body;el('result').hidden=false;say('Optional issue draft ready. Review it before sharing.');
});
el('save').addEventListener('click',()=>{
 const data=snapshot(document),url=URL.createObjectURL(new Blob([data],{type:'text/html;charset=utf-8'}));
 const link=document.createElement('a');link.href=url;link.download='anti-exfil-feedback-'+[new Date().getFullYear(),String(new Date().getMonth()+1).padStart(2,'0'),String(new Date().getDate()).padStart(2,'0')].join('-')+'.html';document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),10000);
 say('HTML download requested. Keep the downloaded file: reopen it to view or edit your results. Attach screenshots separately.');
});
el('copy').addEventListener('click',async()=>{
 try{if(!navigator.clipboard?.writeText)throw Error();await navigator.clipboard.writeText(el('draft').value);say('Issue text copied.');}
 catch{el('draft').focus();el('draft').select();say('The draft is selected. Press Ctrl+C to copy.');}
});
el('github').addEventListener('click',()=>{
 const link=issueLink(el('title').value,el('draft').value);
 say(link.needsPaste?'Copy the draft and paste it into the new issue. Review and submit it yourself.':'GitHub opens a draft. Review and submit it yourself.');window.open(link.url,'_blank','noopener,noreferrer');
});
})(globalThis);
