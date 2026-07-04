#!/usr/bin/env node
// phase9-rc-journeys.mjs — Phase IX Release Candidate governance.
//
// Executes the full paying-customer lifecycle against a target (LIVE PRODUCTION
// by default) using PUBLIC customer workflows only — no admin, no DB, no
// internal overrides. Throwaway accounts are created and deleted. Every step
// records status, key evidence, and latency; anomalies are flagged as
// objections/blockers for the release decision.
//
//   node scripts/phase9-rc-journeys.mjs [--base https://cyberdudebivash.in]
//                                       [--out rc.json]
//
// Safety: never completes a real payment (only inspects order-creation shape);
// deletes every account it creates.

const BASE = argOf('--base', 'https://cyberdudebivash.in');
const OUT = argOf('--out', null);
function argOf(n, d) { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; }

const results = [];
const objections = [];
const blockers = [];
let created = { token: null, email: null, apiKey: null, orgId: null };

function rec(area, step, r, evidence) {
  results.push({ area, step, status: r.status, ok: r.ok, ms: r.ms, evidence: evidence ?? null });
  const tag = r.ok ? 'ok ' : 'ERR';
  console.log(`  [${tag}] ${area}/${step} → HTTP ${r.status} (${r.ms}ms)${evidence ? '  ' + evidence : ''}`);
}
function objection(persona, statement, observed, expected, impact, kind) {
  objections.push({ persona, statement, observed, expected, impact, kind });
}
function blocker(id, impact, severity, evidence, rootCause) {
  blockers.push({ id, impact, severity, evidence, rootCause });
}

async function http(method, path, { token, apiKey, body, accept } = {}) {
  const headers = {};
  if (body) headers['content-type'] = 'application/json';
  if (token) headers.authorization = `Bearer ${token}`;
  if (apiKey) headers['x-api-key'] = apiKey;
  if (accept) headers.accept = accept;
  const t0 = performance.now();
  try {
    const res = await fetch(BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(45000) });
    const text = await res.text();
    const ms = Math.round(performance.now() - t0);
    let json = null; try { json = text ? JSON.parse(text) : null; } catch { /* html/other */ }
    return { ok: res.ok, status: res.status, json, text, ms, headers: res.headers };
  } catch (e) {
    return { ok: false, status: 0, json: null, text: '', ms: Math.round(performance.now() - t0), error: String(e.message) };
  }
}
const now = () => performance.now();

(async () => {
  console.log(`Phase IX RC journeys → ${BASE}\n`);
  const started = new Date().toISOString();
  const timings = {};

  // ── 1. CUSTOMER ACQUISITION (public, read-only) ──────────────────────────
  console.log('── 1. Customer Acquisition (public) ──');
  const home = await http('GET', '/', { accept: 'text/html' });
  rec('acquisition', 'homepage', home, home.text ? `${home.text.length}B html` : '');
  const apidocs = await http('GET', '/api', { accept: 'application/json' });
  rec('acquisition', 'api_docs', apidocs, apidocs.json ? `version ${apidocs.json.version}` : 'non-json (pages intercept)');
  const plans = await http('GET', '/api/subscription/plans');
  const freePlan = plans.json?.data?.plans?.find(p => p.tier === 'FREE');
  rec('acquisition', 'pricing_plans', plans, freePlan ? `FREE ${freePlan.scans}` : '');
  const pricingJson = await http('GET', '/api/v1/intel/pricing.json');
  rec('acquisition', 'machine_pricing', pricingJson, pricingJson.json?.tiers ? `${pricingJson.json.tiers.length} tiers` : '');

  // ── 2. CUSTOMER IMPLEMENTATION (throwaway account) ───────────────────────
  console.log('\n── 2. Customer Implementation ──');
  const email = `rc-${Date.now().toString(36)}@phase9-rc.example`;
  const pw = 'Str0ng!Passw0rd#RC1';
  const tSignup = now();
  const signup = await http('POST', '/api/auth/signup', { body: { email, password: pw, full_name: 'RC Buyer', company: 'RC Enterprise' } });
  rec('implementation', 'signup', signup, signup.json?.user?.id ? `tier ${signup.json.user.tier}` : signup.json?.code);
  if (!signup.ok) { blocker('B-SIGNUP', 'Cannot create an account at all', 'Critical', `POST /api/auth/signup → ${signup.status}`, 'signup endpoint failure'); }
  const token = signup.json?.access_token; created.token = token; created.email = email;
  created.apiKey = signup.json?.api_key || null;
  timings.time_to_signup_ms = Math.round(now() - tSignup);

  const me = await http('GET', '/api/auth/me', { token });
  rec('implementation', 'auth_me', me, me.json?.email || me.json?.user?.email || '');
  // Email verification posture (self-serve activates on POST — known limitation)
  const verified = me.json?.email_verified ?? me.json?.user?.email_verified;
  rec('implementation', 'email_verification_state', { ok: true, status: 200, ms: 0 }, `email_verified=${verified}`);

  const login = await http('POST', '/api/auth/login', { body: { email, password: pw } });
  rec('implementation', 'login', login, login.json?.access_token ? 'token issued' : login.json?.code);

  const orgCreate = await http('POST', '/api/orgs', { token, body: { name: 'RC Enterprise', industry: 'finance' } });
  created.orgId = orgCreate.json?.org_id;
  rec('implementation', 'org_create', orgCreate, orgCreate.json?.plan ? `plan ${orgCreate.json.plan}` : '');
  const orgDash = created.orgId ? await http('GET', `/api/orgs/${created.orgId}/dashboard`, { token }) : { ok: false, status: 0, ms: 0 };
  rec('implementation', 'org_dashboard', orgDash, '');

  const keysList = await http('GET', '/api/keys', { token });
  rec('implementation', 'api_keys_list', keysList, `count ${keysList.json?.count ?? '?'} max ${keysList.json?.max_keys ?? '?'}`);
  // MFA (self-serve setup)
  const mfaSetup = await http('POST', '/api/auth/mfa/setup', { token });
  rec('implementation', 'mfa_setup', mfaSetup, mfaSetup.json?.secret ? 'secret issued' : (mfaSetup.json?.qr ? 'qr issued' : mfaSetup.json?.error || mfaSetup.json?.code));
  const mfaStatus = await http('GET', '/api/auth/mfa/status', { token });
  rec('implementation', 'mfa_status', mfaStatus, mfaStatus.json ? JSON.stringify(mfaStatus.json).slice(0, 60) : '');
  // SSO discovery (no live IdP — endpoint existence only)
  const sso = await http('GET', '/api/auth/sso/config', { token });
  rec('implementation', 'sso_discovery', sso, sso.status === 404 ? 'no sso config endpoint' : (sso.json ? 'sso config present' : ''));

  // ── 3. CUSTOMER OPERATIONS ───────────────────────────────────────────────
  console.log('\n── 3. Customer Operations ──');
  const tScan = now();
  const scan = await http('POST', '/api/scan/domain', { token, body: { domain: 'example.com' } });
  const scanId = scan.json?.scan_id;
  rec('operations', 'scan_domain', scan, scan.json ? `${scan.json.grade}/${scan.json.risk_level} status=${scan.json.scan_status} cache=${scan.headers?.get?.('x-cache')}` : '');
  timings.time_to_first_scan_ms = Math.round(now() - tScan);
  if (!scan.ok) blocker('B-SCAN', 'Cannot run the core domain scan', 'Critical', `POST /api/scan/domain → ${scan.status}`, 'scan endpoint failure');

  // Unmeasurable-domain honesty (must not grade A/LOW)
  const badScan = await http('POST', '/api/scan/domain', { token, body: { domain: 'this-domain-does-not-resolve-zzz9999.invalid' } });
  const bs = badScan.json;
  rec('operations', 'scan_unmeasurable_honesty', badScan, bs ? `status=${bs.scan_status} grade=${bs.grade} risk=${bs.risk_level}` : '');
  if (bs && bs.scan_status !== 'unmeasurable' && (bs.grade === 'A' || bs.risk_level === 'LOW')) {
    blocker('B-FALSEVERDICT', 'Unresolvable domain shown as grade A / LOW (false assurance)', 'Critical', `scan_status=${bs.scan_status} grade=${bs.grade}`, 'NaN-poisoned score regression');
    objection('SOC analyst', 'Why does an unreachable domain score grade A?', `grade ${bs.grade}`, 'unmeasurable', 'False security assurance', 'product');
  }

  const tReport = now();
  const report = scanId ? await http('POST', '/api/report/generate', { token, body: { scan_id: scanId } }) : { ok: false, status: 0, ms: 0 };
  rec('operations', 'report_generate', report, report.json?.download_token ? 'downloadable' : report.json?.error);
  timings.time_to_first_report_ms = Math.round(now() - tReport);
  if (scanId && !report.ok) blocker('B-REPORT', 'Cannot generate a report from a fresh scan', 'High', `report/generate → ${report.status}`, report.json?.error || 'unknown');
  const dl = report.json?.download_token ? await http('GET', `/api/report/${report.json.download_token}`) : { ok: false, status: 0, ms: 0 };
  rec('operations', 'report_download', dl, dl.text ? `${dl.text.length}B` : '');

  const tAI = now();
  const ai = await http('POST', '/api/ai/analyze', { token, body: { module: 'domain_scanner', scan_result: scan.json || { target: 'example.com' } } });
  rec('operations', 'ai_analyze', ai, ai.json?.data ? `severity ${ai.json.data.severity} conf ${ai.json.data.confidence_score}` : ai.json?.code);
  timings.time_to_first_ai_ms = Math.round(now() - tAI);

  const history = await http('GET', '/api/history', { token });
  rec('operations', 'history', history, Array.isArray(history.json?.history || history.json?.scans || history.json) ? 'list returned' : JSON.stringify(history.json || {}).slice(0, 50));
  const threatIntel = await http('GET', '/api/threat-intel', { token });
  rec('operations', 'threat_intel', threatIntel, threatIntel.json ? 'feed returned' : '');
  const kev = await http('GET', '/api/v1/intel/kev.json');
  rec('operations', 'public_kev_feed', kev, kev.json ? `live=${kev.json.live} src=${kev.json.data_source}` : '');
  // AI honesty on an unknown CVE (the differentiator)
  const aiHonesty = await http('POST', '/api/ai/analyze', { token, body: { module: 'threat_intel', scan_result: { cve: 'CVE-2099-00000', target: 'unknown' } } });
  rec('operations', 'ai_honesty_unknown_cve', aiHonesty, aiHonesty.json?.data ? 'answered (check grounding)' : (aiHonesty.json?.code || 'refused/none'));

  // ── 4. SUPPORT SCENARIOS (error quality) ─────────────────────────────────
  console.log('\n── 4. Support Scenarios (error quality) ──');
  const badLogin = await http('POST', '/api/auth/login', { body: { email, password: 'wrong-password' } });
  rec('support', 'bad_login', badLogin, `${badLogin.status} ${badLogin.json?.error || badLogin.json?.code || ''}`.slice(0, 60));
  if (badLogin.status !== 401 && badLogin.status !== 400) objection('Admin', 'Wrong password did not return a clear 401', `${badLogin.status}`, '401', 'Auth confusion', 'product');
  const badKey = await http('GET', '/api/v1/scan', { apiKey: 'cdb_invalid_key_zzz' });
  rec('support', 'bad_api_key', badKey, `${badKey.status} ${badKey.json?.error || badKey.json?.code || ''}`.slice(0, 60));
  const gatedFeature = await http('POST', '/api/ai/simulate', { token, body: { scenario: 'ransomware', scan_result: { target: 'example.com' } } });
  rec('support', 'paid_feature_gate', gatedFeature, `${gatedFeature.status} ${gatedFeature.json?.code || ''} plan=${gatedFeature.json?.required_plan || ''}`);
  if (gatedFeature.status === 402 && !gatedFeature.json?.upgrade_url && !gatedFeature.json?.required_plan) {
    objection('Buyer', 'Paid-feature block did not tell me how to upgrade', 'no upgrade path', 'upgrade_url + plan', 'Upsell friction', 'product');
  }
  const badScanInput = await http('POST', '/api/scan/domain', { token, body: { domain: '!!!not a domain!!!' } });
  rec('support', 'invalid_input', badScanInput, `${badScanInput.status} ${badScanInput.json?.error || ''}`.slice(0, 60));

  // ── 5. COMMERCIAL OPERATIONS ─────────────────────────────────────────────
  console.log('\n── 5. Commercial Operations ──');
  const plan = await http('GET', '/api/user/plan', { token });
  rec('commercial', 'user_plan', plan, plan.json ? `tier ${plan.json.plan} reports=${plan.json.features?.reports} ai=${plan.json.features?.ai_analyze}` : '');
  // Subscription order-creation shape ONLY (no payment completion)
  const order = await http('POST', '/api/subscription/create', { token, body: { plan: 'STARTER', tier: 'STARTER' } });
  rec('commercial', 'subscription_order_shape', order, order.json?.order_id ? 'order created' : (order.json?.error || order.json?.code || `${order.status}`));
  // Entitlement vs enforcement consistency: FREE features must match reality
  if (plan.json?.features) {
    const f = plan.json.features;
    // analyze worked above (ai) and reports worked above (report) — features must not contradict
    if (f.ai_analyze === false && ai.ok) objection('Admin', 'Plan says no AI but AI worked', 'ai_analyze=false', 'true', 'Trust/positioning', 'product');
    if (f.reports === false && report.ok) objection('Admin', 'Plan says no reports but report generated', 'reports=false', 'true', 'Trust/positioning', 'product');
  }

  // ── 6. CLEANUP (offboarding journey doubles as data-erasure evidence) ────
  console.log('\n── 6. Offboarding & cleanup ──');
  const del = await http('DELETE', '/api/auth/delete-account', { token });
  rec('offboarding', 'delete_account', del, del.json?.message ? 'erasure receipt' : `${del.status}`);
  const afterDel = await http('POST', '/api/auth/login', { body: { email, password: pw } });
  rec('offboarding', 'login_after_delete', afterDel, afterDel.status === 401 ? 'credentials dead (good)' : `${afterDel.status} (expected 401)`);
  if (afterDel.status !== 401) blocker('B-ERASURE', 'Account still usable after deletion', 'High', `login after delete → ${afterDel.status}`, 'deletion not effective');

  const summary = {
    started, finished: new Date().toISOString(), base: BASE, timings,
    counts: { steps: results.length, ok: results.filter(r => r.ok).length, err: results.filter(r => !r.ok).length, objections: objections.length, blockers: blockers.length },
    results, objections, blockers,
  };
  if (OUT) { const { writeFileSync } = await import('node:fs'); writeFileSync(OUT, JSON.stringify(summary, null, 2)); console.log(`\nWritten: ${OUT}`); }
  console.log(`\n── RC summary ──`);
  console.log(`  steps ${summary.counts.steps} · ok ${summary.counts.ok} · err ${summary.counts.err} · objections ${summary.counts.objections} · blockers ${summary.counts.blockers}`);
  console.log(`  timings: signup ${timings.time_to_signup_ms}ms · first scan ${timings.time_to_first_scan_ms}ms · first report ${timings.time_to_first_report_ms}ms · first AI ${timings.time_to_first_ai_ms}ms`);
  if (blockers.length) { console.log('  BLOCKERS:'); blockers.forEach(b => console.log(`   - ${b.id} [${b.severity}] ${b.impact}`)); }
})();
