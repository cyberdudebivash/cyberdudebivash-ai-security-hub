#!/usr/bin/env node
// phase8-scale-sim.mjs — Phase VIII live-operations simulation.
//
// Drives the platform over HTTP ONLY, exactly as 100 enterprise customers
// would (no implementation knowledge, no DB access). Ten archetypes × ten
// organizations, each with multiple users/roles, archetype-specific usage
// patterns, six simulated lifecycle waves. Captures latency distributions,
// error taxonomy, time-to-first-value, tenant-isolation probes, and a
// structured Customer Objection Register.
//
//   node scripts/phase8-scale-sim.mjs [--base http://127.0.0.1:8787]
//                                     [--orgs 100] [--wave onboarding|all]
//                                     [--out result.json]
//
// Exit 0 always (findings are data, not test failures); inspect --out.

const BASE = argOf('--base', 'http://127.0.0.1:8787');
const ORG_COUNT = parseInt(argOf('--orgs', '100'), 10);
const WAVE = argOf('--wave', 'all');
const OUT = argOf('--out', null);

function argOf(name, dflt) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : dflt;
}

// ── Archetypes ──────────────────────────────────────────────────────────────
// Each: how many orgs, users per org, roles, org plan requested, and the
// six-month behavioral pattern (scans/day intensity, AI usage, report cadence).
const ARCHETYPES = [
  { key: 'f500',        name: 'Fortune 500 Enterprise', users: 6, plan: 'ENTERPRISE', scanIntensity: 'high',   ai: true,  reports: 'weekly',  domains: ['example.com', 'iana.org', 'cloudflare.com'] },
  { key: 'bank',        name: 'Global Bank',            users: 5, plan: 'ENTERPRISE', scanIntensity: 'high',   ai: true,  reports: 'weekly',  domains: ['example.org', 'mit.edu', 'stanford.edu'] },
  { key: 'mssp',        name: 'MSSP',                   users: 8, plan: 'MSSP',       scanIntensity: 'burst',  ai: true,  reports: 'daily',   domains: ['example.net', 'nist.gov', 'owasp.org', 'kernel.org'] },
  { key: 'healthcare',  name: 'Healthcare Provider',    users: 4, plan: 'PRO',        scanIntensity: 'medium', ai: true,  reports: 'monthly', domains: ['who.int', 'cdc.gov'] },
  { key: 'gov',         name: 'Government Agency',       users: 5, plan: 'ENTERPRISE', scanIntensity: 'medium', ai: false, reports: 'monthly', domains: ['nasa.gov', 'noaa.gov'] },
  { key: 'manufacturing', name: 'Manufacturing Company', users: 3, plan: 'PRO',       scanIntensity: 'low',    ai: false, reports: 'monthly', domains: ['siemens.com', 'ge.com'] },
  { key: 'retail',      name: 'Retail Organization',    users: 4, plan: 'PRO',        scanIntensity: 'medium', ai: true,  reports: 'weekly',  domains: ['walmart.com', 'target.com'] },
  { key: 'saas',        name: 'SaaS Company',           users: 3, plan: 'STARTER',    scanIntensity: 'medium', ai: true,  reports: 'weekly',  domains: ['github.com', 'gitlab.com'] },
  { key: 'startup',     name: 'Startup',                users: 2, plan: 'FREE',        scanIntensity: 'low',    ai: false, reports: 'none',    domains: ['ycombinator.com'] },
  { key: 'university',  name: 'University',             users: 4, plan: 'STARTER',    scanIntensity: 'low',    ai: false, reports: 'monthly', domains: ['harvard.edu', 'berkeley.edu'] },
];

const ROLES = ['owner', 'admin', 'analyst', 'analyst', 'viewer', 'viewer', 'viewer', 'viewer'];

// ── HTTP with latency capture + 429 backoff ─────────────────────────────────
const latencies = {};   // op -> [ms]
const errors = {};       // op -> { code -> count }
const objections = [];
let httpCalls = 0;
let throttles = 0;

function recordLatency(op, ms) { (latencies[op] ||= []).push(ms); }
function recordError(op, code) { (errors[op] ||= {})[code] = ((errors[op] || {})[code] || 0) + 1; }

async function http(op, method, path, { token, apiKey, body } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  if (apiKey) headers['x-api-key'] = apiKey;
  let attempt = 0;
  for (;;) {
    attempt++;
    const t0 = performance.now();
    let res, text;
    try {
      res = await fetch(BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
      text = await res.text();
    } catch (e) {
      recordError(op, 'NETWORK');
      return { ok: false, status: 0, json: null, ms: performance.now() - t0, error: String(e.message) };
    }
    const ms = performance.now() - t0;
    httpCalls++;
    // A 429 is a real customer signal (rate/quota wall), not a failure to paper
    // over. One short retry to smooth transient bursts, then record it as a
    // throttle event and move on — mirrors a customer backing off, and keeps the
    // six-month simulation from serializing into a multi-hour crawl.
    if (res.status === 429 && attempt <= 1) {
      recordError(op, '429_retried');
      await sleep(250 + Math.random() * 150);
      continue;
    }
    if (res.status === 429) { throttles++; recordLatency(op, ms); recordError(op, 'HTTP_429'); return { ok: false, status: 429, json: null, ms, throttled: true }; }
    recordLatency(op, ms);
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { /* non-json */ }
    if (!res.ok) recordError(op, json?.code || `HTTP_${res.status}`);
    return { ok: res.ok, status: res.status, json, ms, text };
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function objection(persona, quote, category, impact, action) {
  objections.push({ persona, quote, category, impact, action, ts: new Date().toISOString() });
}

// ── Org lifecycle ───────────────────────────────────────────────────────────
let orgSeq = 0;
async function onboardOrg(arch, idx) {
  orgSeq++;
  const stamp = `${Date.now().toString(36)}${orgSeq}`;
  const org = { archetype: arch.key, name: `${arch.name} ${idx + 1}`, users: [], events: [], ttfv: null, planRequested: arch.plan };
  const t0 = performance.now();

  // Owner signs up
  const ownerEmail = `owner+${arch.key}${idx}-${stamp}@sim.example`;
  const pw = 'Str0ng!Passw0rd#' + stamp;
  const signup = await http('signup', 'POST', '/api/auth/signup', { body: { email: ownerEmail, password: pw, full_name: `${arch.name} Owner`, company: org.name } });
  if (!signup.ok) { org.events.push({ step: 'owner_signup', ok: false, status: signup.status, code: signup.json?.code }); org.fatal = 'owner_signup'; return org; }
  const ownerToken = signup.json.access_token;
  const apiKey = signup.json.api_key || null;  // Default Key auto-issued at signup (plaintext returned once)
  org.ownerEmail = ownerEmail;
  org.ownerId = signup.json.user?.id;
  org.gotSignupKey = !!apiKey;

  // Create the organization (tenant)
  const orgRes = await http('org_create', 'POST', '/api/orgs', { token: ownerToken, body: { name: org.name, industry: arch.key } });
  if (orgRes.ok) { org.orgId = orgRes.json.org_id; org.orgPlan = orgRes.json.plan; org.orgLimits = orgRes.json.limits; }
  else org.events.push({ step: 'org_create', ok: false, status: orgRes.status, code: orgRes.json?.code });

  // Additional users sign up (multi-user org)
  const nUsers = Math.min(arch.users, ROLES.length);
  for (let u = 1; u < nUsers; u++) {
    const email = `${ROLES[u]}+${arch.key}${idx}-${u}-${stamp}@sim.example`;
    const r = await http('member_signup', 'POST', '/api/auth/signup', { body: { email, password: pw, full_name: `${arch.name} ${ROLES[u]}`, company: org.name } });
    org.users.push({ role: ROLES[u], email, ok: r.ok, token: r.ok ? r.json.access_token : null });
  }
  org.users.unshift({ role: 'owner', email: ownerEmail, ok: true, token: ownerToken, apiKey });

  // First value: first domain scan
  const dom = arch.domains[0];
  const scan = await http('scan_domain', 'POST', '/api/scan/domain', { token: ownerToken, body: { domain: dom } });
  if (scan.ok) {
    org.firstScan = { domain: dom, grade: scan.json.grade, risk: scan.json.risk_score, level: scan.json.risk_level, status: scan.json.scan_status, id: scan.json.scan_id };
    org.ttfv = performance.now() - t0;
    // Sanity: does the verdict make sense? (unmeasurable must not grade A/LOW)
    if (scan.json.scan_status !== 'measured' && (scan.json.grade === 'A' || scan.json.risk_level === 'LOW')) {
      objection(`${arch.name} SOC analyst`, 'Why does an unresolvable domain show grade A / LOW risk?', 'product', 'False security assurance', 'unmeasurable must not grade');
    }
  } else {
    org.events.push({ step: 'first_scan', ok: false, status: scan.status, code: scan.json?.code });
  }

  // First report (paid-feature perception check)
  if (org.firstScan?.id && arch.reports !== 'none') {
    const rep = await http('report_generate', 'POST', '/api/report/generate', { token: ownerToken, body: { scan_id: org.firstScan.id } });
    org.firstReport = { ok: rep.ok, status: rep.status, expires: rep.json?.expires_at, token: rep.json?.download_token };
    if (rep.ok) {
      // Verify the shareable link actually downloads
      const tok = rep.json.download_token;
      const dl = await http('report_download', 'GET', `/api/report/${tok}`);
      org.firstReport.downloadable = dl.ok && (dl.text?.length || 0) > 500;
    }
  }

  // First AI recommendation (entitlement-gated)
  if (arch.ai) {
    // Correct contract: threat correlation needs a scan_result + module
    const ai = await http('ai_analyze', 'POST', '/api/ai/analyze', { token: ownerToken, body: { module: 'domain_scanner', scan_result: org.firstScan || { target: dom } } });
    org.firstAI = { ok: ai.ok, status: ai.status, code: ai.json?.code, gated: ai.status === 403 };
    if (ai.status === 403) org.firstAI.upgradeHint = ai.json?.upgrade_url || ai.json?.error;
  }

  // Plan/entitlement truthfulness probe
  const plan = await http('user_plan', 'GET', '/api/user/plan', { token: ownerToken });
  if (plan.ok) {
    org.plan = { tier: plan.json.plan, reports: plan.json.features?.reports, scans_limit: plan.json.usage?.scans_limit };
    if (plan.json.features?.reports === false && org.firstReport?.ok) {
      objection(`${arch.name} admin`, 'My plan says reports are not included, but I can generate them — which is true?', 'product', 'Entitlement display contradicts actual capability; erodes trust and upsell clarity', 'reconcile /api/user/plan features with real gating');
    }
  }

  org.onboardMs = performance.now() - t0;
  return org;
}

// ── Usage waves (six months) ────────────────────────────────────────────────
const INTENSITY = { low: 1, medium: 3, high: 6, burst: 10 };

async function runWave(orgs, waveName, multiplier) {
  const waveStats = { wave: waveName, scans: 0, scanErrors: 0, aiCalls: 0, reports: 0, quotaHits: 0 };
  for (const org of orgs) {
    if (org.fatal) continue;
    const arch = ARCHETYPES.find((a) => a.key === org.archetype);
    const owner = org.users[0];
    const base = INTENSITY[arch.scanIntensity] || 1;
    const nScans = Math.max(1, Math.round(base * multiplier));
    for (let i = 0; i < nScans; i++) {
      const dom = arch.domains[i % arch.domains.length];
      const useKey = owner.apiKey && i % 2 === 0;
      const r = await http('wave_scan', 'POST', '/api/scan/domain', useKey ? { apiKey: owner.apiKey, body: { domain: dom } } : { token: owner.token, body: { domain: dom } });
      waveStats.scans++;
      if (!r.ok) {
        waveStats.scanErrors++;
        if (r.status === 402 || r.json?.code === 'ERR_QUOTA_EXCEEDED' || /limit|quota/i.test(r.json?.error || '')) {
          waveStats.quotaHits++;
          if (!org.quotaHitAt) org.quotaHitAt = { wave: waveName, scanNo: org.lifetimeScans || 0 };
        }
      }
      org.lifetimeScans = (org.lifetimeScans || 0) + 1;
    }
    if (arch.ai) {
      const ai = await http('wave_ai', 'POST', '/api/ai/analyze', { token: owner.token, body: { module: 'domain_scanner', scan_result: org.firstScan || { target: arch.domains[0] } } });
      waveStats.aiCalls++;
      if (ai.ok) org.aiEverWorked = true;
    }
  }
  return waveStats;
}

// ── Cross-tenant isolation probe ────────────────────────────────────────────
async function isolationProbe(orgs) {
  const findings = [];
  const withOrg = orgs.filter((o) => o.orgId && !o.fatal);
  if (withOrg.length < 2) return findings;
  const a = withOrg[0], b = withOrg[withOrg.length - 1];
  // b's owner tries to read a's org dashboard
  const cross = await http('iso_cross_org', 'GET', `/api/orgs/${a.orgId}/dashboard`, { token: b.users[0].token });
  if (cross.ok) {
    findings.push({ kind: 'cross_org_dashboard_read', a: a.orgId, b: b.ownerEmail, status: cross.status });
    objection(`${b.archetype} CISO`, 'I can see another tenant\'s security dashboard with my own token', 'product', 'CRITICAL tenant isolation breach', 'enforce org membership on /api/orgs/:id/dashboard');
  }
  // b tries to read a's org record
  const crossRec = await http('iso_cross_org_rec', 'GET', `/api/orgs/${a.orgId}`, { token: b.users[0].token });
  findings.push({ kind: 'cross_org_record_read', status: crossRec.status, blocked: !crossRec.ok });
  return findings;
}

// ── Percentiles ─────────────────────────────────────────────────────────────
function pct(arr, p) {
  if (!arr || !arr.length) return null;
  const s = [...arr].sort((x, y) => x - y);
  return Math.round(s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]);
}
function summarizeLatency() {
  const out = {};
  for (const [op, arr] of Object.entries(latencies)) {
    out[op] = { n: arr.length, p50: pct(arr, 50), p95: pct(arr, 95), p99: pct(arr, 99), max: Math.round(Math.max(...arr)) };
  }
  return out;
}

// ── Main ────────────────────────────────────────────────────────────────────
(async () => {
  const started = new Date().toISOString();
  console.log(`Phase VIII scale simulation → ${BASE}  (${ORG_COUNT} orgs, wave=${WAVE})`);

  // Build org roster (round-robin archetypes up to ORG_COUNT)
  const roster = [];
  for (let i = 0; i < ORG_COUNT; i++) roster.push({ arch: ARCHETYPES[i % ARCHETYPES.length], idx: Math.floor(i / ARCHETYPES.length) });

  // Wave 1 — onboarding (Day 1)
  console.log('\n── Wave 1: Day-1 onboarding ──');
  const orgs = [];
  let done = 0;
  for (const { arch, idx } of roster) {
    const org = await onboardOrg(arch, idx);
    orgs.push(org);
    done++;
    if (done % 10 === 0) process.stdout.write(`  onboarded ${done}/${ORG_COUNT}\n`);
  }
  const onboarded = orgs.filter((o) => !o.fatal).length;
  const withScan = orgs.filter((o) => o.firstScan).length;
  const withReport = orgs.filter((o) => o.firstReport?.ok).length;
  const ttfvs = orgs.filter((o) => o.ttfv).map((o) => o.ttfv);
  console.log(`  onboarded ${onboarded}/${ORG_COUNT}, first-scan ${withScan}, first-report ${withReport}`);
  console.log(`  time-to-first-value p50=${pct(ttfvs, 50)}ms p95=${pct(ttfvs, 95)}ms`);

  const waves = [];
  let isolation = [];
  if (WAVE === 'all') {
    // Waves 2–6 — Week1, Week2, Month1, Month3, Month6
    const plan = [['Week 1', 1], ['Week 2', 1.5], ['Month 1', 2], ['Month 3', 3], ['Month 6', 4]];
    for (const [name, mult] of plan) {
      console.log(`\n── ${name} usage wave (×${mult}) ──`);
      const ws = await runWave(orgs, name, mult);
      console.log(`  scans=${ws.scans} errors=${ws.scanErrors} quotaHits=${ws.quotaHits} aiCalls=${ws.aiCalls}`);
      waves.push(ws);
    }
    console.log('\n── Cross-tenant isolation probe ──');
    isolation = await isolationProbe(orgs);
    console.log(`  ${isolation.map((f) => `${f.kind}:${f.blocked === false || f.status === 200 ? 'READABLE' : 'blocked'}`).join(', ')}`);
  }

  const result = {
    started, finished: new Date().toISOString(), base: BASE, orgCount: ORG_COUNT, httpCalls, throttles,
    onboarding: {
      onboarded, withScan, withReport,
      ttfv_p50_ms: pct(ttfvs, 50), ttfv_p95_ms: pct(ttfvs, 95),
      byArchetype: Object.fromEntries(ARCHETYPES.map((a) => {
        const g = orgs.filter((o) => o.archetype === a.key);
        return [a.key, { orgs: g.length, onboarded: g.filter((o) => !o.fatal).length, firstScan: g.filter((o) => o.firstScan).length, aiGated: g.filter((o) => o.firstAI?.gated).length, aiWorked: g.filter((o) => o.firstAI?.ok).length }];
      })),
    },
    waves, isolation,
    latency: summarizeLatency(),
    errors,
    objections,
    orgs: orgs.map((o) => ({ archetype: o.archetype, name: o.name, fatal: o.fatal || null, orgId: o.orgId, orgPlan: o.orgPlan, users: o.users.length, ttfv_ms: o.ttfv ? Math.round(o.ttfv) : null, firstScan: o.firstScan, firstReport: o.firstReport ? { ok: o.firstReport.ok, downloadable: o.firstReport.downloadable } : null, firstAI: o.firstAI, plan: o.plan, lifetimeScans: o.lifetimeScans || 0, quotaHitAt: o.quotaHitAt || null, aiEverWorked: o.aiEverWorked || false })),
  };

  if (OUT) {
    const { writeFileSync } = await import('node:fs');
    writeFileSync(OUT, JSON.stringify(result, null, 2));
    console.log(`\nResult written: ${OUT}`);
  }
  console.log(`\nTotals: ${httpCalls} HTTP calls, ${objections.length} objections captured.`);
  console.log('Error taxonomy:', JSON.stringify(errors));
})();
