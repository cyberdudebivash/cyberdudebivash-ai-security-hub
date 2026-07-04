#!/usr/bin/env node
/**
 * CEAP — Continuous Enterprise Assurance sweep.
 *
 * Re-executes the representative paying-customer lifecycle against live
 * production exactly as a customer would (public workflows only, throwaway
 * account, full cleanup) and exits non-zero if any step regresses. This is
 * the synthetic-detection layer motivated by the Incident Review Register:
 * both production incidents to date (IR-1 org-dashboard 500, IR-2 missing
 * credential recovery) were found by customers/audits, not monitoring —
 * this sweep would have caught IR-1 automatically.
 *
 * Usage: node scripts/ceap-sweep.mjs [base-url]   (default: production)
 * No dependencies; Node 18+.
 */
const BASE = process.argv[2] || 'https://cyberdudebivash.in';
const ts = Date.now();
const email = `ceap.${ts}@example.com`;
const password = 'Ceap!Sweep2026x';
const J = { 'Content-Type': 'application/json' };
const results = [];
let H = J, su = null, scan = null, org = null, failed = 0;

async function step(name, expect, fn) {
  const s = Date.now();
  try {
    const { status, note = '' } = await fn();
    const ok = Array.isArray(expect) ? expect.includes(status) : status === expect;
    if (!ok) failed++;
    results.push({ name, ok, status, expect, ms: Date.now() - s, note });
  } catch (e) {
    failed++;
    results.push({ name, ok: false, status: 'EXC', expect, ms: Date.now() - s, note: e.message });
  }
}

await step('version + health', 200, async () => {
  const v = await fetch(`${BASE}/api/version`);
  const h = await fetch(`${BASE}/api/health`);
  const commit = (await v.json()).commit?.slice(0, 7);
  return { status: h.status, note: `commit=${commit}` };
});

await step('signup (auto key issued)', 201, async () => {
  const r = await fetch(`${BASE}/api/auth/signup`, { method: 'POST', headers: J, body: JSON.stringify({ email, password, full_name: 'CEAP Sweep' }) });
  su = await r.json();
  H = { ...J, Authorization: `Bearer ${su.token || su.access_token}` };
  return { status: r.status, note: su.api_key ? 'key issued' : 'NO KEY' };
});

await step('entitlements truthful', 200, async () => {
  const r = await fetch(`${BASE}/api/user/plan`, { headers: H });
  const d = await r.json();
  const ok = d.features?.reports === true && d.features?.ai_analyze === true && d.features?.api_access === false;
  return { status: ok ? r.status : 599, note: `reports=${d.features?.reports} ai=${d.features?.ai_analyze} apiV1=${d.features?.api_access}` };
});

await step('domain scan (id contract)', 200, async () => {
  const r = await fetch(`${BASE}/api/scan/domain`, { method: 'POST', headers: H, body: JSON.stringify({ domain: 'iana.org' }) });
  scan = await r.json();
  const hdr = r.headers.get('X-Scan-ID');
  const ok = scan.scan_id && (!hdr || hdr === scan.scan_id);
  return { status: ok ? r.status : 598, note: `scan_id=${(scan.scan_id || '').slice(0, 14)} header_match=${!hdr || hdr === scan.scan_id}` };
});

await step('report generate (IR-1 class)', 201, async () => {
  const r = await fetch(`${BASE}/api/report/generate`, { method: 'POST', headers: H, body: JSON.stringify({ scan_id: scan.scan_id, format: 'html' }) });
  return { status: r.status };
});

await step('AI analyze grounded', 200, async () => {
  const r = await fetch(`${BASE}/api/ai/analyze`, { method: 'POST', headers: H, body: JSON.stringify({ scan_result: scan, module: 'domain', target: 'iana.org' }) });
  const conf = JSON.stringify(await r.json().catch(() => ({}))).match(/"confidence_score":(\d+)/)?.[1];
  return { status: conf ? r.status : 597, note: `confidence=${conf}` };
});

await step('paid AI gate holds', 402, async () => {
  const r = await fetch(`${BASE}/api/ai/simulate`, { method: 'POST', headers: H, body: JSON.stringify({ scenario: 'x' }) });
  return { status: r.status };
});

await step('org create + dashboard (IR-1)', 200, async () => {
  let r = await fetch(`${BASE}/api/orgs`, { method: 'POST', headers: H, body: JSON.stringify({ name: `CEAP Sweep ${ts}` }) });
  org = await r.json();
  r = await fetch(`${BASE}/api/orgs/${org.org_id}/dashboard`, { headers: H });
  const d = await r.json().catch(() => ({}));
  return { status: r.status, note: `scans_30d=${d.summary?.total_scans_30d}` };
});

await step('org scans (IR-1)', 200, async () => {
  const r = await fetch(`${BASE}/api/orgs/${org.org_id}/scans`, { headers: H });
  return { status: r.status };
});

await step('key rotation lifecycle', 201, async () => {
  let r = await fetch(`${BASE}/api/keys`, { headers: H });
  const keyId = ((await r.json()).keys || [])[0]?.id;
  r = await fetch(`${BASE}/api/keys/${keyId}/rotate`, { method: 'POST', headers: H });
  const rot = await r.json().catch(() => ({}));
  const st = await fetch(`${BASE}/api/auth/status`, { headers: { 'x-api-key': su.api_key } });
  const oldDead = (await st.json()).authenticated === false;
  return { status: oldDead ? r.status : 596, note: `old_key_dead=${oldDead} new_shown=${!!(rot.api_key || rot.key)}` };
});

await step('credential recovery (IR-2)', 200, async () => {
  const r1 = await fetch(`${BASE}/api/auth/forgot-password`, { method: 'POST', headers: J, body: JSON.stringify({ email }) });
  const r2 = await fetch(`${BASE}/api/auth/forgot-password`, { method: 'POST', headers: J, body: JSON.stringify({ email: `ghost.${ts}@example.com` }) });
  const identical = (await r1.text()) === (await r2.text());
  return { status: identical ? r1.status : 595, note: `enumeration_safe=${identical}` };
});

await step('pricing consistency', 200, async () => {
  const r = await fetch(`${BASE}/api/subscription/plans`);
  const ok = JSON.stringify(await r.json()).includes('5 domain scans/day');
  return { status: ok ? r.status : 594, note: 'FREE 5/day advertised' };
});

await step('offboarding + lockout', 200, async () => {
  const r = await fetch(`${BASE}/api/auth/delete-account`, { method: 'DELETE', headers: H });
  const login = await fetch(`${BASE}/api/auth/login`, { method: 'POST', headers: J, body: JSON.stringify({ email, password }) });
  return { status: login.status === 401 ? r.status : 593, note: `post_delete_login=${login.status}` };
});

console.log(`\nCEAP sweep — ${BASE} — ${new Date().toISOString()}\n`);
for (const r of results) {
  console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.name.padEnd(34)} ${String(r.status).padEnd(4)} (want ${r.expect}) ${String(r.ms).padStart(5)}ms  ${r.note}`);
}
console.log(`\n${results.length - failed}/${results.length} green${failed ? ` — ${failed} REGRESSION(S): treat as a production incident per CEAP` : ''}`);
process.exit(failed ? 1 : 0);
