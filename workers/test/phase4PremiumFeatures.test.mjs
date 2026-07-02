/* Phase 4 — Premium Feature Completion regression suite.
 *
 * Locks in the customer-facing workflows completed in Phase 4:
 *  A. Detection rule generation: STIX 2.1 export, per-format export filenames,
 *     authenticated save → history → versioning → revisit (generated_rules D1).
 *  B. Reporting engine: CTI and AI_SECURITY report types render REAL data from
 *     threat_intel / apt_profiles / ai_* tables, with truthful empty states
 *     (never fabricated numbers) when no data exists.
 *  C. API key rotation: POST /api/keys/:id/rotate revokes the old key and
 *     issues a replacement on the user's current tier (documented in the
 *     developer portal long before the endpoint existed).
 *  D. Billing downgrade close-the-loop: the cancel_url advertised by
 *     POST /api/billing/downgrade actually works (status + cancel).
 */
import { describe, it, expect } from 'vitest';
import { handleGenerateRules, handleRulesHistory, handleGetSavedRule } from '../src/handlers/aiAnalysis.js';
import { handleCreateReport, handleDownloadReport } from '../src/handlers/reportingEngine.js';
import { handleRotateKey } from '../src/handlers/apikeys.js';
import { handleDowngrade, handleDowngradeStatus, handleDowngradeCancel } from '../src/handlers/monetizationV2.js';

// ─── Minimal in-memory D1 for the generated_rules table ─────────────────────
function rulesDB() {
  const rows = [];
  return {
    _rows: rows,
    prepare(sql) {
      let bound = [];
      const stmt = {
        bind(...args) { bound = args; return stmt; },
        async run() {
          if (/INSERT INTO generated_rules/.test(sql)) {
            const [id, user_id, cve_id, platform, version, rules_json] = bound;
            rows.push({ id, user_id, cve_id, platform, version, rules_json, created_at: new Date().toISOString() });
          }
          return { success: true, meta: { changes: 1 } };
        },
        async first() {
          if (/SELECT COUNT\(\*\) as ct FROM generated_rules/.test(sql)) {
            const [user_id, cve_id, platform] = bound;
            return { ct: rows.filter(r => r.user_id === user_id && r.cve_id === cve_id && r.platform === platform).length };
          }
          if (/FROM generated_rules WHERE id = \? AND user_id = \?/.test(sql)) {
            const [id, user_id] = bound;
            return rows.find(r => r.id === id && r.user_id === user_id) || null;
          }
          return null;
        },
        async all() {
          if (/FROM generated_rules/.test(sql)) {
            const [user_id] = bound;
            return { results: rows.filter(r => r.user_id === user_id).map(({ rules_json, ...rest }) => rest) };
          }
          return { results: [] };
        },
      };
      return stmt;
    },
  };
}

function jsonReq(url, method = 'POST', body = null) {
  return new Request(url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
}

// ═══ A. Detection rule generation ════════════════════════════════════════════

describe('generate-rules — STIX 2.1 export', () => {
  it('returns a valid STIX 2.1 bundle with sigma and yara indicators for platform=stix', async () => {
    const res = await handleGenerateRules(
      jsonReq('https://x/api/ai/generate-rules', 'POST', { cve_id: 'CVE-2024-3400', platform: 'stix' }), {});
    const data = await res.json();
    expect(data.success).toBe(true);

    const bundle = JSON.parse(data.rules.stix);
    expect(bundle.type).toBe('bundle');
    expect(bundle.id).toMatch(/^bundle--/);

    const indicators = bundle.objects.filter(o => o.type === 'indicator');
    expect(indicators.length).toBe(2);
    expect(indicators.map(i => i.pattern_type).sort()).toEqual(['sigma', 'yara']);
    for (const ind of indicators) {
      expect(ind.spec_version).toBe('2.1');
      expect(ind.id).toMatch(/^indicator--/);
      expect(ind.pattern.length).toBeGreaterThan(50);
      expect(ind.valid_from).toBeTruthy();
      // CVE external reference present for real CVE IDs
      expect(ind.external_references[0].external_id).toBe('CVE-2024-3400');
    }
    const identity = bundle.objects.find(o => o.type === 'identity');
    expect(identity).toBeTruthy();
  });

  it('includes all 6 formats and platform-correct export filenames for platform=all', async () => {
    const res = await handleGenerateRules(
      jsonReq('https://x/api/ai/generate-rules', 'POST', { cve_id: 'CVE-2024-21762', platform: 'all' }), {});
    const data = await res.json();

    for (const fmt of ['sigma', 'splunk', 'kql', 'yara', 'elastic', 'stix']) {
      expect(data.rules[fmt], `missing format: ${fmt}`).toBeTruthy();
    }
    expect(data.export_filenames.sigma).toMatch(/_sigma_\d{4}-\d{2}-\d{2}\.yml$/);
    expect(data.export_filenames.splunk).toMatch(/\.spl$/);
    expect(data.export_filenames.kql).toMatch(/\.kql$/);
    expect(data.export_filenames.yara).toMatch(/\.yar$/);
    expect(data.export_filenames.elastic).toMatch(/\.json$/);
    expect(data.export_filenames.stix).toMatch(/\.json$/);
  });
});

describe('generate-rules — save, history, versioning, revisit', () => {
  it('does NOT persist anonymous generations and says so honestly', async () => {
    const db = rulesDB();
    const res = await handleGenerateRules(
      jsonReq('https://x/api/ai/generate-rules', 'POST', { cve_id: 'CVE-2024-1709', platform: 'sigma' }),
      { DB: db }, {});
    const data = await res.json();
    expect(data.saved).toBe(false);
    expect(data.record_id).toBeNull();
    expect(db._rows.length).toBe(0);
  });

  it('persists authenticated generations with incrementing versions per cve+platform', async () => {
    const db = rulesDB();
    const authCtx = { user_id: 'user-1', tier: 'PRO' };

    const r1 = await (await handleGenerateRules(
      jsonReq('https://x/api/ai/generate-rules', 'POST', { cve_id: 'CVE-2024-1709', platform: 'sigma' }),
      { DB: db }, authCtx)).json();
    expect(r1.saved).toBe(true);
    expect(r1.version).toBe(1);
    expect(r1.record_id).toBeTruthy();

    const r2 = await (await handleGenerateRules(
      jsonReq('https://x/api/ai/generate-rules', 'POST', { cve_id: 'CVE-2024-1709', platform: 'sigma' }),
      { DB: db }, authCtx)).json();
    expect(r2.version).toBe(2);

    // Different platform starts its own version sequence
    const r3 = await (await handleGenerateRules(
      jsonReq('https://x/api/ai/generate-rules', 'POST', { cve_id: 'CVE-2024-1709', platform: 'yara' }),
      { DB: db }, authCtx)).json();
    expect(r3.version).toBe(1);
    expect(db._rows.length).toBe(3);
  });

  it('history requires auth, lists own generations, and honestly reports the empty state', async () => {
    const db = rulesDB();

    const unauth = await handleRulesHistory(jsonReq('https://x/api/ai/rules/history', 'GET'), { DB: db }, {});
    expect(unauth.status).toBe(401);

    const empty = await (await handleRulesHistory(
      jsonReq('https://x/api/ai/rules/history', 'GET'), { DB: db }, { user_id: 'user-1' })).json();
    expect(empty.count).toBe(0);
    expect(empty.note).toContain('No detection rules generated yet');

    await handleGenerateRules(
      jsonReq('https://x/api/ai/generate-rules', 'POST', { cve_id: 'CVE-2023-4966', platform: 'kql' }),
      { DB: db }, { user_id: 'user-1' });
    const hist = await (await handleRulesHistory(
      jsonReq('https://x/api/ai/rules/history', 'GET'), { DB: db }, { user_id: 'user-1' })).json();
    expect(hist.count).toBe(1);
    expect(hist.history[0].cve_id).toBe('CVE-2023-4966');
    expect(hist.history[0].platform).toBe('kql');
    // List view must NOT bulk-ship full rule bodies
    expect(hist.history[0].rules_json).toBeUndefined();
  });

  it('saved rule revisit returns full content only to its owner', async () => {
    const db = rulesDB();
    const gen = await (await handleGenerateRules(
      jsonReq('https://x/api/ai/generate-rules', 'POST', { cve_id: 'CVE-2021-44228', platform: 'sigma' }),
      { DB: db }, { user_id: 'user-1' })).json();

    const own = await (await handleGetSavedRule(
      jsonReq(`https://x/api/ai/rules/${gen.record_id}`, 'GET'), { DB: db }, { user_id: 'user-1' }, gen.record_id)).json();
    expect(own.success).toBe(true);
    expect(own.rules.sigma).toContain('CVE-2021-44228');

    const theft = await handleGetSavedRule(
      jsonReq(`https://x/api/ai/rules/${gen.record_id}`, 'GET'), { DB: db }, { user_id: 'attacker' }, gen.record_id);
    expect(theft.status).toBe(404);
  });
});

// ═══ B. Reporting engine — CTI and AI_SECURITY types ═════════════════════════

function reportDB({ threatIntel = [], sevStats = [], aptProfiles = [], aiAssets = [], findingStats = [], findings = [], redteam = null, governance = [] } = {}) {
  return {
    prepare(sql) {
      let bound = [];
      const stmt = {
        bind(...args) { bound = args; return stmt; },
        async run() { return { success: true }; },
        async first() {
          if (/FROM ai_redteam_attempts/.test(sql)) return redteam;
          if (/FROM scan_results/.test(sql)) return { total: 0, critical_ct: 0, high_ct: 0, avg_risk: 50 };
          return null;
        },
        async all() {
          if (/FROM threat_intel/.test(sql) && /GROUP BY severity/.test(sql)) return { results: sevStats };
          if (/FROM threat_intel/.test(sql)) return { results: threatIntel };
          if (/FROM apt_profiles/.test(sql)) return { results: aptProfiles };
          if (/FROM ai_assets/.test(sql)) return { results: aiAssets };
          if (/FROM ai_findings/.test(sql) && /GROUP BY f.severity/.test(sql)) return { results: findingStats };
          if (/FROM ai_findings/.test(sql)) return { results: findings };
          if (/FROM ai_governance_assessments/.test(sql)) return { results: governance };
          return { results: [] };
        },
      };
      return stmt;
    },
  };
}

function reportKV() {
  const store = new Map();
  return {
    async put(k, v) { store.set(k, v); },
    async get(k, opts) {
      if (!store.has(k)) return null;
      const v = store.get(k);
      return (opts === 'json' || opts?.type === 'json') ? JSON.parse(v) : v;
    },
  };
}

async function renderReport(env, user, body) {
  const req = jsonReq('https://x/api/reports', 'POST', body);
  req.user = user;
  const created = await (await handleCreateReport(req, env)).json();
  expect(created.success).toBe(true);
  const dl = await handleDownloadReport(
    jsonReq(`https://x/api/reports/${created.job_id}/download?token=${created.download_token}`, 'GET'),
    env, created.job_id);
  expect(dl.status).toBe(200);
  return dl.text();
}

describe('reportingEngine — CTI (Threat Intelligence) report', () => {
  const proUser = { role: 'user', tier: 'pro', id: 'u1', userId: 'u1', org_id: 'org-1' };

  it('renders real CVE, APT, and IOC data from D1', async () => {
    const env = {
      DB: reportDB({
        threatIntel: [{
          id: 'CVE-2024-3400', title: 'PAN-OS GlobalProtect Command Injection', severity: 'CRITICAL',
          cvss: 10.0, epss_score: 0.94, exploit_status: 'confirmed', known_ransomware: 1,
          actively_exploited: 1, published_at: '2024-04-12', iocs: '["203.0.113.7","evil.example.com"]',
        }],
        sevStats: [{ severity: 'CRITICAL', ct: 3, exploited: 2, confirmed: 1 }, { severity: 'HIGH', ct: 5, exploited: 0, confirmed: 0 }],
        aptProfiles: [{
          group_name: 'UTA0218', origin_country: 'Unknown', target_sectors: '["government","telecom"]',
          typical_cves: '["CVE-2024-3400"]', mitre_ttps: '["T1190","T1059"]', activity_level: 'ACTIVE', last_seen: '2024-05-01',
        }],
      }),
      KV: reportKV(),
    };
    const html = await renderReport(env, proUser, { type: 'CTI' });
    expect(html).toContain('CVE-2024-3400');
    expect(html).toContain('PAN-OS GlobalProtect');
    expect(html).toContain('UTA0218');
    expect(html).toContain('203.0.113.7');
    expect(html).toContain('T1190');
    expect(html).toContain('94.0%'); // EPSS rendered as percentage
    // The generic stub body must be gone
    expect(html).not.toContain('CTI Report</h2>');
  });

  it('renders truthful empty states when no threat intel exists — no fabricated data', async () => {
    const env = { DB: reportDB(), KV: reportKV() };
    const html = await renderReport(env, proUser, { type: 'CTI' });
    expect(html).toContain('No CVEs have been ingested in the last 30 days');
    expect(html).toContain('No active APT group profiles are currently tracked');
    expect(html).toContain('No MITRE TTP mappings available');
    expect(html).not.toMatch(/CVE-\d{4}-\d+/);
  });
});

describe('reportingEngine — AI_SECURITY report', () => {
  const entUser = { role: 'user', tier: 'enterprise', id: 'u2', userId: 'u2', org_id: 'org-2' };

  it('renders real AI SPM inventory, findings, red team, and governance data', async () => {
    const env = {
      DB: reportDB({
        aiAssets: [{ name: 'prod-rag-pipeline', asset_type: 'rag', provider: 'anthropic', exposure: 'public', risk_score: 72, security_score: 41, status: 'active' }],
        findingStats: [{ severity: 'CRITICAL', ct: 1 }, { severity: 'HIGH', ct: 2 }],
        findings: [{ category: 'LLM01', title: 'Indirect prompt injection via retrieved documents', severity: 'CRITICAL', owasp_ref: 'LLM01', asset_name: 'prod-rag-pipeline' }],
        redteam: { total: 27, successful: 3 },
        governance: [{ framework: 'NIST_AI_RMF', overall_score: 64, risk_tier: 'HIGH', status: 'completed' }],
      }),
      KV: reportKV(),
    };
    const html = await renderReport(env, entUser, { type: 'AI_SECURITY' });
    expect(html).toContain('prod-rag-pipeline');
    expect(html).toContain('Indirect prompt injection');
    expect(html).toContain('NIST_AI_RMF');
    expect(html).toContain('<strong>27</strong>');
    expect(html).toContain('publicly exposed AI asset');
    expect(html).not.toContain('AI SECURITY Report</h2>'); // generic stub gone
  });

  it('renders truthful empty states when the org has no AI security data', async () => {
    const env = { DB: reportDB(), KV: reportKV() };
    const html = await renderReport(env, entUser, { type: 'AI_SECURITY' });
    expect(html).toContain('No AI assets registered for this organization yet');
    expect(html).toContain('No open AI security findings');
    expect(html).toContain('No AI red team engagements recorded yet');
    expect(html).toContain('No governance assessments completed yet');
  });
});

// ═══ C. API key rotation ═════════════════════════════════════════════════════

function keysDB(initial = []) {
  const keys = [...initial];
  return {
    _keys: keys,
    prepare(sql) {
      let bound = [];
      const stmt = {
        bind(...args) { bound = args; return stmt; },
        async run() {
          if (/UPDATE api_keys SET active = 0/.test(sql)) {
            const [keyId, userId] = bound;
            const k = keys.find(x => x.id === keyId && x.user_id === userId && x.active);
            if (k) { k.active = 0; return { meta: { changes: 1 } }; }
            return { meta: { changes: 0 } };
          }
          if (/INSERT INTO api_keys/.test(sql)) {
            const [id, user_id, key_hash, key_prefix, label, tier, daily_limit, monthly_limit, created_at] = bound;
            keys.push({ id, user_id, key_hash, key_prefix, label, tier, daily_limit, monthly_limit, active: 1, created_at });
            return { meta: { changes: 1 } };
          }
          return { meta: { changes: 0 } };
        },
        async first() { return null; },
        async all() {
          if (/FROM api_keys WHERE user_id = \?/.test(sql)) {
            const [userId] = bound;
            return { results: keys.filter(k => k.user_id === userId) };
          }
          return { results: [] };
        },
      };
      return stmt;
    },
  };
}

describe('API key rotation — POST /api/keys/:id/rotate', () => {
  it('requires authentication', async () => {
    const res = await handleRotateKey(jsonReq('https://x/api/keys/k1/rotate'), { DB: keysDB() }, {}, 'k1');
    expect(res.status).toBe(401);
  });

  it('404s for a key the caller does not own', async () => {
    const db = keysDB([{ id: 'k1', user_id: 'other-user', active: 1, label: 'their key', key_prefix: 'cdb_aaa...' }]);
    const res = await handleRotateKey(jsonReq('https://x/api/keys/k1/rotate'), { DB: db }, { user_id: 'me', tier: 'PRO' }, 'k1');
    expect(res.status).toBe(404);
  });

  it('409s when the key is already revoked', async () => {
    const db = keysDB([{ id: 'k1', user_id: 'me', active: 0, label: 'old', key_prefix: 'cdb_aaa...' }]);
    const res = await handleRotateKey(jsonReq('https://x/api/keys/k1/rotate'), { DB: db }, { user_id: 'me', tier: 'PRO' }, 'k1');
    expect(res.status).toBe(409);
  });

  it('revokes the old key, issues a replacement with the same label on the current tier, and shows the raw key once', async () => {
    const db = keysDB([{ id: 'k1', user_id: 'me', active: 1, label: 'production-siem', key_prefix: 'cdb_aaa...', tier: 'STARTER' }]);
    // User upgraded to PRO since the key was created — rotation must pick up PRO
    const res = await handleRotateKey(jsonReq('https://x/api/keys/k1/rotate'), { DB: db }, { user_id: 'me', tier: 'PRO' }, 'k1');
    expect(res.status).toBe(201);
    const data = await res.json();

    expect(data.success).toBe(true);
    expect(data.old_key_id).toBe('k1');
    expect(data.key).toMatch(/^cdb_[0-9a-f]{64}$/);
    expect(data.label).toBe('production-siem');
    expect(data.tier).toBe('PRO');

    const oldKey = db._keys.find(k => k.id === 'k1');
    expect(oldKey.active).toBe(0);
    const newKey = db._keys.find(k => k.id === data.key_id);
    expect(newKey.active).toBe(1);
    expect(newKey.tier).toBe('PRO');
  });
});

// ═══ D. Billing downgrade close-the-loop ═════════════════════════════════════

function billingKV() {
  const store = new Map();
  return {
    _store: store,
    async put(k, v) { store.set(k, v); },
    async get(k, opts) {
      if (!store.has(k)) return null;
      const v = store.get(k);
      return (opts === 'json' || opts?.type === 'json') ? JSON.parse(v) : v;
    },
    async delete(k) { store.delete(k); },
  };
}

describe('billing — downgrade schedule → status → cancel loop', () => {
  const authCtx = { authenticated: true, userId: 'u1', user_id: 'u1', tier: 'PRO', plan: 'PRO' };

  it('cancel requires auth and 404s when nothing is scheduled', async () => {
    const env = { SECURITY_HUB_KV: billingKV() };
    const unauth = await handleDowngradeCancel(jsonReq('https://x/api/billing/downgrade/cancel'), env, {});
    expect(unauth.status).toBe(401);

    const nothing = await handleDowngradeCancel(jsonReq('https://x/api/billing/downgrade/cancel'), env, authCtx);
    expect(nothing.status).toBe(404);
    expect((await nothing.json()).code).toBe('NO_PENDING_DOWNGRADE');
  });

  it('schedule → status shows pending → cancel → status shows clean', async () => {
    const env = { SECURITY_HUB_KV: billingKV() };

    const sched = await (await handleDowngrade(jsonReq('https://x/api/billing/downgrade'), env, authCtx)).json();
    expect(sched.data.downgrade_scheduled).toBe(true);
    expect(sched.data.cancel_url).toBe('/api/billing/downgrade/cancel');

    const st1 = await (await handleDowngradeStatus(jsonReq('https://x/api/billing/downgrade', 'GET'), env, authCtx)).json();
    expect(st1.data.downgrade_pending).toBe(true);
    expect(st1.data.request.current_tier).toBe('PRO');

    const cancel = await (await handleDowngradeCancel(jsonReq('https://x/api/billing/downgrade/cancel'), env, authCtx)).json();
    expect(cancel.data.downgrade_cancelled).toBe(true);

    const st2 = await (await handleDowngradeStatus(jsonReq('https://x/api/billing/downgrade', 'GET'), env, authCtx)).json();
    expect(st2.data.downgrade_pending).toBe(false);
    expect(env.SECURITY_HUB_KV._store.size).toBe(0);
  });
});
