const $=(s,r=document)=>r.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const api=async(p,o)=>{const r=await fetch('/api'+p,o);if(!r.ok){let m=r.statusText;try{m=(await r.json()).detail||m}catch{}throw new Error(m)}return r.json()};
const COL={Critical:'#ff5d73',High:'#ffb347',Medium:'#5cc8ff',Low:'#3ee6b0'};
const ABI=['function anchor(bytes32 reportHash,string contractRef)','function verify(bytes32 reportHash) view returns (bool exists,address auditor,uint64 timestamp,string contractRef)'];
const date=t=>new Date(t*1000).toLocaleString();
const sevOf=r=>r>=20?'Critical':r>=12?'High':r>=6?'Medium':'Low';
let CFG={},S=null;

async function scanById(id){if(!S||S.id!==id)S=await api('/scans/'+id);return S}

function side(id,tab){
 const L=(h,t,on)=>`<a href="#/${h}" class="${on?'on':''}">${t}</a>`;
 let h=`<div class="logo"><i></i>AuditLens</div>${L('','New scan',!id&&tab!=='history')}${L('history','Scan history',tab==='history')}`;
 if(id)h+=`<h4>${esc(S?.name||'scan')}</h4>${L(`s/${id}`,'Findings',tab==='')}${L(`s/${id}/grc`,'GRC dashboard',tab==='grc')}${L(`s/${id}/governance`,'Governance check',tab==='governance')}${L(`s/${id}/chat`,'Ask the audit',tab==='chat')}${L(`s/${id}/report`,'Report and anchor',tab==='report')}`;
 h+=`<h4>Engine</h4><div class="stat"><span class="dot ${CFG.slither?'ok':''}"></span>Slither ${CFG.slither?'installed':'missing'}</div><div class="stat"><span class="dot ${CFG.llm?'ok':''}"></span>LLM ${CFG.llm?esc(CFG.model):'off'}</div><div class="stat"><span class="dot ${CFG.contract?'ok':''}"></span>Attestation ${CFG.contract?'ready':'not set'}</div>`;
 $('#side').innerHTML=h;
}

async function route(){
 const p=location.hash.slice(2).split('/').filter(Boolean),v=$('#view');
 try{
  if(p[0]==='s'&&p[1]){await scanById(p[1]);side(p[1],p[2]||'');({'':findings,grc,governance:gov,report:rep,chat:chatView}[p[2]||'']||findings)(v)}
  else if(p[0]==='history'){side(null,'history');await history(v)}
  else{side(null,'');scanView(v)}
 }catch(e){v.innerHTML=`<h1>Something went wrong</h1><p class="sub">${esc(e.message)}</p><a class="btn g" href="#/">Back to scan</a>`}
 window.scrollTo(0,0);
}

/* ---------- scan ---------- */
function scanView(v){
 v.innerHTML=`<h1>Scan a contract</h1><p class="sub">Slither finds the bugs, an LLM explains them, and every finding is mapped to OWASP, ISO 27001 and SOC 2 controls.</p>
 <div class="card"><div class="tabs"><button class="on" data-t="c">Paste Solidity</button><button data-t="a">Contract address</button></div>
 <div id="pc"><textarea id="src" spellcheck="false" aria-label="Solidity source" placeholder="// Paste Solidity source"></textarea></div>
 <div id="pa" hidden><div class="grid g2"><input type="text" id="addr" placeholder="0x… verified contract address"><input type="password" id="key" placeholder="Etherscan API key (or set ETHERSCAN_API_KEY on the server)"></div>
 <div class="row"><select id="chain" style="max-width:260px"><option value="1">Ethereum mainnet</option><option value="11155111">Sepolia</option><option value="8453">Base</option><option value="42161">Arbitrum One</option></select></div></div>
 <div class="row"><button class="btn" id="go">Run audit</button><button class="btn g" id="demo">Load vulnerable sample</button></div><div id="prog"></div></div>`;
 v.querySelectorAll('.tabs button').forEach(b=>b.onclick=()=>{v.querySelectorAll('.tabs button').forEach(x=>x.classList.toggle('on',x===b));$('#pc').hidden=b.dataset.t!=='c';$('#pa').hidden=b.dataset.t!=='a'});
 $('#demo').onclick=async()=>{$('#src').value=(await api('/sample')).source};
 $('#go').onclick=async()=>{
  const addr=!$('#pa').hidden,btn=$('#go');btn.disabled=true;
  const steps=['Parsing source','Running Slither','AI logic audit','Exploit scenarios and control mapping','On-chain and AI governance review','Building the PDF report'];let i=0;
  const draw=()=>{$('#prog').innerHTML='<ul class="steps" style="margin-top:14px">'+steps.map((s,n)=>`<li class="${n<i?'done':n===i?'now':''}">${n<i?'✓':n===i?'›':'·'} ${s}</li>`).join('')+'</ul>'};draw();
  const t=setInterval(()=>{if(i<steps.length-1){i++;draw()}},6000);
  try{
   const body=addr?{address:$('#addr').value,chain_id:+$('#chain').value,etherscan_key:$('#key').value||null}:{source:$('#src').value};
   S=await api('/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
   location.hash='#/s/'+S.id;
  }catch(e){$('#prog').innerHTML=`<div class="note bad">${esc(e.message)}</div>`}
  clearInterval(t);btn.disabled=false;
 };
}

/* ---------- history ---------- */
async function history(v){
 const rows=await api('/scans');
 v.innerHTML=`<h1>Scan history</h1><p class="sub">Every scan is stored with its frozen PDF, so the anchored hash stays verifiable.</p><div class="card">${rows.length?`<table><tr><th>Contract</th><th>Date</th><th>Posture</th><th>Findings</th><th>Anchored</th></tr>${rows.map(r=>`<tr class="link" data-id="${r.id}"><td><b>${esc(r.name)}</b></td><td>${date(r.created)}</td><td>${r.score}/100</td><td>${Object.entries(r.counts).filter(([,n])=>n).map(([k,n])=>`<span class="pill ${k}">${n}</span>`).join(' ')||'none'}</td><td>${r.anchor?'yes':'no'}</td></tr>`).join('')}</table>`:'<p class="sub">No scans yet.</p>'}</div>`;
 v.querySelectorAll('tr.link').forEach(t=>t.onclick=()=>{S=null;location.hash='#/s/'+t.dataset.id});
}

/* ---------- findings ---------- */
function head(s,title){
 const c=s.score>66?'#3ee6b0':s.score>33?'#ffb347':'#ff5d73';
 return `<h1>${title}</h1><p class="sub">${esc(s.name)} · ${s.loc} lines · scanned ${date(s.created)} · engine: ${s.engine.slither?'Slither':'Slither unavailable'}${s.engine.ai_audit?' + AI logic audit':''} · explanations: ${s.engine.llm?'AI ('+esc(s.engine.llm_info)+')':'built-in knowledge base'}</p>
 ${s.engine.note?`<div class="note info" style="margin:-8px 0 18px">${esc(s.engine.note)}</div>`:''}`
}
function findings(v){
 const s=S;let flt='All';
 const draw=()=>{
  const list=s.findings.filter(f=>flt==='All'||f.severity===flt);
  $('#fl').innerHTML=list.map(f=>`<article class="card f" id="${f.id}"><button aria-expanded="false"><span class="pill ${f.severity}">${f.severity}</span><h3>${esc(f.title)}</h3><span class="lab">${esc(f.file)}:${f.line}</span><span class="lab">▸</span></button>
  <div class="body"><pre>${esc(f.code)}</pre><div class="grid g2" style="margin-top:14px"><div><div class="lab">${f.ai?'AI analyst':'Explanation (built-in)'}</div><p class="ai">${esc(f.explanation)}</p><div class="lab" style="margin-top:12px">Business and compliance risk</div><p class="ai">${esc(f.risk_statement)}</p></div>
  <div><div class="lab">Suggested fix</div><p>${esc(f.fix)}</p>${f.fix_code?`<pre>${esc(f.fix_code)}</pre>`:''}</div></div>
  ${f.exploit&&f.exploit.length?`<div class="lab" style="margin-top:14px">Exploit scenario (AI-written, not executed)</div><ol class="ai">${f.exploit.map(x=>`<li>${esc(x)}</li>`).join('')}</ol>`:''}${f.poc?`<details><summary class="lab">Proof-of-concept test (Foundry, unexecuted)</summary><pre>${esc(f.poc)}</pre></details>`:''}
  <div class="row"><button class="btn g vf" data-id="${f.id}">Verify fix by re-scanning</button></div><div class="vfr" id="vf-${f.id}"></div>
  <div style="margin-top:14px"><span class="tag">OWASP <b>${esc(f.owasp)}</b></span>${f.iso.map(x=>`<span class="tag">ISO <b>${esc(x)}</b></span>`).join('')}${f.soc2.map(x=>`<span class="tag">SOC 2 <b>${esc(x)}</b></span>`).join('')}<span class="tag">owner <b>${esc(f.owner)}</b></span><span class="tag">likelihood×impact <b>${f.likelihood}×${f.impact}=${f.risk}</b></span><span class="tag">source <b>${f.engine}</b></span><span class="tag">mapping <b>${esc(f.mapping||'')}</b></span></div>${f.analyzer_note&&f.engine==='slither'?`<details style="margin-top:8px"><summary class="lab">Slither output</summary><pre>${esc(f.analyzer_note)}</pre></details>`:''}</div></article>`).join('')||'<div class="card">No findings at this severity.</div>';
  $('#fl').querySelectorAll('.vf').forEach(b=>b.onclick=async()=>{
   const o=$('#vf-'+b.dataset.id);b.disabled=true;o.innerHTML='<div class="note info">Asking the model for a patch, then re-scanning it…</div>';
   try{const r=await api(`/scans/${s.id}/findings/${b.dataset.id}/verify-fix`,{method:'POST'});
    o.innerHTML=`<div class="note ${r.resolved?'ok':'bad'}"><b>${r.resolved?'Resolved':'Not resolved'}</b> — ${esc(r.reason)}<br>Checked by: ${esc(r.rescan_engine)} · findings ${r.before} → ${r.remaining}${r.new_issue_types.length?`<br>New issue types introduced: ${esc(r.new_issue_types.join(', '))}`:''}${r.note?`<br>${esc(r.note)}`:''}</div><details><summary class="lab">Patch diff</summary><pre>${esc(r.diff)}</pre></details>`}
   catch(e){o.innerHTML=`<div class="note bad">${esc(e.message)}</div>`}b.disabled=false});
  $('#fl').querySelectorAll('.f>button:first-child').forEach(b=>b.onclick=()=>{const a=b.parentElement,o=a.classList.toggle('open');b.setAttribute('aria-expanded',o)});
 };
 v.innerHTML=head(s,'Findings')+`<div class="grid g31"><div class="card" style="text-align:center"><svg viewBox="0 0 120 120" width="150"><circle cx="60" cy="60" r="50" fill="none" stroke="#0b0916" stroke-width="12"/><circle id="arc" cx="60" cy="60" r="50" fill="none" stroke="${s.score>66?'#3ee6b0':s.score>33?'#ffb347':'#ff5d73'}" stroke-width="12" stroke-linecap="round" stroke-dasharray="314" stroke-dashoffset="314" transform="rotate(-90 60 60)" style="transition:stroke-dashoffset 1.1s cubic-bezier(.2,.8,.2,1)"/><text x="60" y="68" text-anchor="middle" fill="#ece9ff" font-size="30" font-weight="800" font-family="Bricolage Grotesque">${s.score}</text></svg><div class="lab">security posture</div></div>
 <div class="grid g4">${Object.entries(s.counts).map(([k,n])=>`<div class="card"><div class="num" style="color:${COL[k]}">${n}</div><div class="lab">${k}</div></div>`).join('')}</div></div>
 <h2>All findings</h2><div class="chips">${['All','Critical','High','Medium','Low'].map(k=>`<button class="${k===flt?'on':''}" data-k="${k}">${k}</button>`).join('')}</div><div id="fl"></div>`;
 requestAnimationFrame(()=>requestAnimationFrame(()=>$('#arc').style.strokeDashoffset=314*(1-s.score/100)));
 v.querySelectorAll('.chips button').forEach(b=>b.onclick=()=>{flt=b.dataset.k;v.querySelectorAll('.chips button').forEach(x=>x.classList.toggle('on',x===b));draw()});
 draw();
}

/* ---------- GRC ---------- */
function grc(v){
 const s=S;let h='';
 for(let im=5;im>=1;im--){h+=`<div class="ax">${im}</div>`;for(let l=1;l<=5;l++){const c=s.heatmap.find(x=>x.l===l&&x.i===im),col=COL[sevOf(l*im)];h+=`<div class="c" style="background:${col}${c?'':'30'};${c?`box-shadow:0 0 16px ${col}88`:''}" title="${c?c.ids.join(', '):''}">${c?c.ids.length:''}</div>`}}
 h+='<div></div>'+[1,2,3,4,5].map(x=>`<div class="ax">${x}</div>`).join('');
 v.innerHTML=head(s,'GRC dashboard')+`<div class="grid g2"><div class="card"><div class="lab" style="margin-bottom:12px">Risk heatmap · impact (up) × likelihood (right)</div><div class="hm">${h}</div></div>
 <div class="card"><div class="lab" style="margin-bottom:14px">Control coverage = controls with no open finding</div>${Object.values(s.coverage).map(c=>{const col=c.pct>=80?'#3ee6b0':c.pct>=50?'#ffb347':'#ff5d73';return `<div class="bar"><div><span>${esc(c.name)}</span><b>${c.pct}%</b></div><div class="t"><i data-w="${c.pct}" style="background:${col}"></i></div><small>${c.failing.length?'failing: '+esc(c.failing.join(', ')):'no failing controls'}</small></div>`}).join('')}</div></div>
 <h2>Risk register</h2><div class="card" style="overflow-x:auto"><table><tr><th>ID</th><th>Finding</th><th>Risk</th><th>OWASP</th><th>ISO 27001</th><th>SOC 2</th><th>Remediation owner</th></tr>${s.findings.map(f=>`<tr><td>${f.id}</td><td>${esc(f.title)}<div class="lab">${esc(f.file)}:${f.line}</div></td><td><span class="pill ${f.severity}">${f.risk}</span></td><td>${esc(f.owasp)}</td><td>${esc(f.iso.join(', '))}</td><td>${esc(f.soc2.join(', '))}</td><td>${esc(f.owner)}</td></tr>`).join('')}</table></div>
 <div class="row"><button class="btn g" id="csv">Export register (CSV)</button></div>`;
 requestAnimationFrame(()=>requestAnimationFrame(()=>v.querySelectorAll('.t i').forEach(i=>i.style.width=i.dataset.w+'%')));
 $('#csv').onclick=()=>{const q=x=>`"${String(x).replace(/"/g,'""')}"`;const rows=[['id','finding','severity','likelihood','impact','risk','file','line','owasp','iso27001','soc2','owner'],...s.findings.map(f=>[f.id,f.title,f.severity,f.likelihood,f.impact,f.risk,f.file,f.line,f.owasp,f.iso.join('; '),f.soc2.join('; '),f.owner])];
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([rows.map(r=>r.map(q).join(',')).join('\n')],{type:'text/csv'}));a.download=`risk-register-${s.id}.csv`;a.click()};
}

/* ---------- governance ---------- */
function gov(v){
 const g=S.governance;
 v.innerHTML=head(S,'Governance check')+`<div class="grid g31"><div class="card" style="text-align:center"><div class="num" style="color:${g.score==null?'#8a86b3':g.score>66?'#3ee6b0':g.score>33?'#ffb347':'#ff5d73'}">${g.score??'n/a'}</div><div class="lab">governance score</div></div><div class="card"><p>Who can change the contract after deployment. For an address scan this reads the live chain (owner(), EIP-1967 admin, Safe threshold, timelock delay); the AI review adds code-level findings, each tied to a verified source line.</p></div></div>
 <h2>Issues</h2>${g.items.length?g.items.map(i=>`<div class="card" style="margin-bottom:10px"><span class="pill ${i.severity}">${i.severity}</span> <b style="margin-left:8px">${esc(i.title)}</b> <span class="tag">${esc(i.source||'')}</span><p style="margin-top:8px">${esc(i.why)}</p>${i.detail.length?`<pre style="margin-top:8px">${esc(i.detail.join('\n'))}</pre>`:''}${i.fix?`<p class="lab" style="margin-top:8px">Fix: ${esc(i.fix)}</p>`:''}</div>`).join(''):'<div class="card">No governance issues found by the checks that ran.</div>'}${(g.notes||[]).map(n=>`<div class="note info" style="margin-top:10px">${esc(n)}</div>`).join('')}`;
}

/* ---------- report + chain ---------- */
function rep(v){
 const s=S,h=s.report_sha256;
 v.innerHTML=head(s,'Report and on-chain proof')+`<div class="card"><div class="lab">SHA-256 of the PDF report (this is what gets anchored)</div><div class="hash" style="margin:6px 0 16px">0x${h}</div>
 <div class="row" style="margin:0"><a class="btn g" href="/api/scans/${s.id}/report.pdf">Download PDF report</a><button class="btn m" id="anc" ${s.anchor?'disabled':''}>${s.anchor?'Already anchored':'Anchor report on Sepolia'}</button></div><div id="an">${s.anchor?`<div class="note ok">Anchored and verified on-chain (block ${s.anchor.block}) in tx ${esc(s.anchor.tx)} · <a style="color:inherit" target="_blank" rel="noopener" href="https://sepolia.etherscan.io/tx/${esc(s.anchor.tx)}">Etherscan</a></div>`:''}</div>
 ${CFG.contract?'':'<div class="note info">No attestation contract configured. Deploy contracts/AuditAttestation.sol (python contracts/deploy.py) and set CONTRACT_ADDRESS, then restart the server.</div>'}</div>
 <h2>Verify a report</h2><div class="card"><p class="sub" style="margin-top:0">Drop any PDF. The browser hashes it locally and asks the contract whether that exact hash was anchored, by whom and when. A single changed byte fails.</p><input type="file" id="vf" accept="application/pdf"><div class="row"><button class="btn g" id="vcur">Verify this scan's report</button></div><div id="vr"></div></div>`;
 const note=(id,c,t)=>$(id).innerHTML=`<div class="note ${c}">${t}</div>`;
 $('#anc').onclick=async()=>{
  try{
   if(!CFG.contract)throw Error('CONTRACT_ADDRESS is not configured on the server.');
   if(!window.ethereum)throw Error('No wallet found. Install MetaMask and reload.');
   const prov=new ethers.BrowserProvider(window.ethereum);await prov.send('eth_requestAccounts',[]);
   try{await prov.send('wallet_switchEthereumChain',[{chainId:'0x'+CFG.chain_id.toString(16)}])}catch{throw Error('Switch your wallet to Sepolia.')}
   const c=new ethers.Contract(CFG.contract,ABI,await prov.getSigner());
   note('#an','info','Confirm the transaction in your wallet…');
   const tx=await c.anchor('0x'+h,`${s.name}#${s.id}`);note('#an','info','Waiting for confirmation…');await tx.wait();note('#an','info','Confirmed. Having the server verify the receipt on Sepolia…');
   s.anchor=await api(`/scans/${s.id}/anchor`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tx:tx.hash})});
   rep(v);
  }catch(e){note('#an','bad',esc(e.shortMessage||e.message))}
 };
 const verify=async hex=>{
  try{
   if(!CFG.contract)throw Error('CONTRACT_ADDRESS is not configured on the server.');
   note('#vr','info','Hash: 0x'+hex+'<br>Reading Sepolia…');
   const c=new ethers.Contract(CFG.contract,ABI,new ethers.JsonRpcProvider(CFG.rpc));
   const [ok,aud,ts,ref]=await c.verify('0x'+hex);
   ok?note('#vr','ok',`Verified. This exact report was anchored by ${aud} on ${new Date(Number(ts)*1000).toLocaleString()}<br>Reference: ${esc(ref)}`):note('#vr','bad','Not found. This file was never anchored, or it has been modified.');
  }catch(e){note('#vr','bad',esc(e.shortMessage||e.message))}
 };
 $('#vcur').onclick=()=>verify(h);
 $('#vf').onchange=async e=>{const f=e.target.files[0];if(!f)return;const d=await crypto.subtle.digest('SHA-256',await f.arrayBuffer());verify([...new Uint8Array(d)].map(b=>b.toString(16).padStart(2,'0')).join(''))};
}

/* ---------- chat ---------- */
function chatView(v){
 const H=[];v.innerHTML=head(S,'Ask the audit')+`<div class="card"><div id="msgs" style="min-height:220px;max-height:50vh;overflow:auto"><p class="sub">Ask about any finding, how an exploit works, or what to fix first. Answers use this scan's findings and source.</p></div><div class="row"><input type="text" id="q" placeholder="e.g. Which finding should I fix first and why?"><button class="btn" id="send">Send</button></div></div>`;
 const add=(r,t)=>{const d=document.createElement('div');d.className='note '+(r==='user'?'info':'ok');d.style.margin='8px 0';d.style.whiteSpace='pre-wrap';d.textContent=t;$('#msgs').appendChild(d);d.scrollIntoView()};
 const send=async()=>{const q=$('#q').value.trim();if(!q)return;$('#q').value='';H.push({role:'user',content:q});add('user',q);$('#send').disabled=true;
  try{const r=await api(`/scans/${S.id}/chat`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({messages:H})});H.push({role:'assistant',content:r.reply});add('assistant',r.reply)}
  catch(e){H.pop();$('#msgs').insertAdjacentHTML('beforeend',`<div class="note bad">${esc(e.message)}</div>`)}$('#send').disabled=false};
 $('#send').onclick=send;$('#q').onkeydown=e=>{if(e.key==='Enter')send()};
}

addEventListener('hashchange',route);
(async()=>{CFG=await api('/config').catch(()=>({}));route()})();
