import { handleVibeCodeScan, handleVibeCodePatterns } from './handlers/vibeCodeScanner.js';

const VULN = `const key='sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
app.get('/u',(req,res)=>{const u=db.query("SELECT * FROM users WHERE id="+req.query.id);res.send(u);});
const out=await openai.chat.completions.create({messages});
eval(out.choices[0].message.content);
const h=crypto.createHash('md5').update(pw).digest('hex');`;

const mkReq = (bodyObj) => new Request('https://x/api/vibe-code/scan', {
  method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(bodyObj)
});

let pass=0, fail=0;
const ok=(c,m)=>{ if(c){pass++;console.log('PASS ',m);} else {fail++;console.log('FAIL ',m);} };

// 1. Anonymous (authCtx undefined) => free, gated
let r = await handleVibeCodeScan(mkReq({code:VULN}), {}, undefined);
let b = await r.json();
ok(r.status===200, 'anonymous scan returns 200');
ok(b.tier==='free' && b.gated===true, 'anonymous => free + gated');
ok(b.findings.length===3, 'free reveals exactly 3 findings');
ok(b.locked_count>=1 && b.upgrade.unlock_price.includes('999'), 'free locks rest behind ₹999');
ok(b.grade && b.severity_counts, 'free still shows grade + severity counts');

// 2. authCtx FREE (uppercase, as resolveAuthV5 emits) => gated
r = await handleVibeCodeScan(mkReq({code:VULN}), {}, {authenticated:false, tier:'FREE'});
b = await r.json();
ok(b.gated===true, 'authCtx tier=FREE => gated');

// 3. authCtx STARTER (₹999 plan) => full report
r = await handleVibeCodeScan(mkReq({code:VULN}), {}, {authenticated:true, tier:'STARTER'});
b = await r.json();
ok(b.gated===false && b.tier==='starter', 'STARTER => full report, not gated');
ok(b.findings.length===b.total_findings, 'STARTER reveals ALL findings');
ok(b.findings.every(f=>f.remediation), 'STARTER findings include remediation');

// 4. authCtx PRO / ENTERPRISE / MSSP => full
for (const t of ['PRO','ENTERPRISE','MSSP']) {
  r = await handleVibeCodeScan(mkReq({code:VULN}), {}, {authenticated:true, tier:t});
  b = await r.json();
  ok(b.gated===false, `${t} => full report`);
}

// 5. SECURITY: free caller cannot self-upgrade via body.tier
r = await handleVibeCodeScan(mkReq({code:VULN, tier:'pro'}), {}, {authenticated:false, tier:'FREE'});
b = await r.json();
ok(b.gated===true, 'body.tier=pro is IGNORED for a FREE authCtx (no self-upgrade)');

// 6. Bad input handling
r = await handleVibeCodeScan(mkReq({code:''}), {}, {tier:'FREE'});
ok((await r.json()).error==='EMPTY_CODE' && r.status===400, 'empty code => 400 EMPTY_CODE');
r = await handleVibeCodeScan(new Request('https://x',{method:'GET'}), {}, {tier:'FREE'});
ok(r.status===405, 'GET on scan => 405');

// 7. patterns endpoint
r = await handleVibeCodePatterns(new Request('https://x/api/vibe-code/patterns'), {});
b = await r.json();
ok(r.status===200 && b.ok && b.count===27 && Array.isArray(b.patterns), 'patterns returns all 27 rules');
ok(r.headers.get('cache-control').includes('max-age'), 'patterns is cacheable');

// 8. D1 metric never crashes the scan even with a throwing DB
const throwingDB = { prepare(){ return { bind(){ return { run(){ throw new Error('no table'); } }; } }; } };
r = await handleVibeCodeScan(mkReq({code:VULN}), {DB:throwingDB}, {tier:'STARTER'});
ok(r.status===200, 'scan survives a throwing D1 metric (best-effort)');

console.log(`\n===== ${pass}/${pass+fail} checks passed =====`);
process.exit(fail?1:0);
