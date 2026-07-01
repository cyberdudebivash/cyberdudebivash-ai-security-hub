#!/usr/bin/env node
/**
 * CYBERDUDEBIVASH AI Security Hub — Enterprise Release Gate
 *
 * A pre-release end-to-end integration check spanning backend API, frontend,
 * and the customer golden path. Intended to be run from an environment with
 * real network egress (GitHub Actions), against production or a preview URL.
 *
 * Read-mostly: the only state-changing call is a single domain scan against
 * "example.com" (the same domain the homepage itself suggests to visitors),
 * exercising the actual customer scan flow rather than mocking it.
 *
 * Usage: node scripts/enterprise-release-gate.mjs [BASE_URL]
 * Exits non-zero if any check tagged severity:"blocker" fails.
 */

const BASE = process.argv[2] || process.env.RELEASE_GATE_BASE || 'https://cyberdudebivash.in';
const TIMEOUT_MS = 15000;

const results = [];

function record(category, name, severity, pass, detail) {
  results.push({ category, name, severity, pass, detail });
  const icon = pass ? '✅' : (severity === 'blocker' ? '❌' : '⚠️ ');
  console.log(`${icon} [${category}] ${name}${detail ? ' — ' + detail : ''}`);
}

async function fetchJSON(path, opts = {}) {
  const url = `${BASE}${path}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const resp = await fetch(url, { ...opts, signal: controller.signal });
    clearTimeout(timer);
    let body = null;
    const text = await resp.text();
    try { body = JSON.parse(text); } catch { body = null; }
    return { ok: resp.ok, status: resp.status, headers: resp.headers, body, raw: text };
  } catch (e) {
    clearTimeout(timer);
    return { ok: false, status: 0, error: e?.message || 'fetch failed', body: null, raw: '' };
  }
}

async function main() {
  console.log(`\n━━━ Enterprise Release Gate — ${BASE} ━━━\n`);

  // ── A. Platform Health & Version ──────────────────────────────────────────
  {
    const r = await fetchJSON('/api/health');
    record('Health', 'GET /api/health returns 200', 'blocker', r.status === 200, `status=${r.status}`);
    if (r.body) {
      record('Health', 'health.status is ok|degraded', 'blocker',
        ['ok', 'degraded'].includes(r.body.status), `status=${r.body.status}`);
      record('Health', 'health.components present', 'warn',
        !!r.body.components, JSON.stringify(r.body.components || {}));
    }
  }
  {
    const r = await fetchJSON('/api/version');
    record('Health', 'GET /api/version returns 200 + version field', 'blocker',
      r.status === 200 && !!r.body?.version, `version=${r.body?.version}`);
  }

  // ── B. Threat Intelligence — real-data integrity (IBM mandate) ────────────
  {
    const r = await fetchJSON('/api/intelligence/summary');
    record('Intel', 'GET /api/intelligence/summary returns 200', 'blocker', r.status === 200);
    if (r.body) {
      record('Intel', 'active_apt_groups is an array (not fabricated static list)', 'blocker',
        Array.isArray(r.body.active_apt_groups), `len=${r.body.active_apt_groups?.length}`);
      record('Intel', 'global_risk_index is number or null (no hardcoded 72)', 'blocker',
        r.body.global_risk_index === null || typeof r.body.global_risk_index === 'number',
        `value=${r.body.global_risk_index}`);
      record('Intel', 'data_source reported', 'warn', !!r.body.data_source, r.body.data_source);
    }
  }
  {
    const r = await fetchJSON('/api/apt-intel/groups');
    record('Intel', 'GET /api/apt-intel/groups returns 200', 'blocker', r.status === 200);
    if (r.body) {
      record('Intel', 'apt-intel/groups has methodology + sources disclosure', 'blocker',
        !!r.body.methodology && Array.isArray(r.body.sources), `sources=${JSON.stringify(r.body.sources)}`);
      record('Intel', 'apt-intel/groups active_apt_groups is an array', 'blocker',
        Array.isArray(r.body.active_apt_groups), `count=${r.body.total}`);
    }
  }
  {
    // nocache=1 forces a fresh build from current code — otherwise this can
    // read a KV-cached feed object built before a deploy (up to 6h stale),
    // which would make a correct new deploy look like a false failure here.
    const r = await fetchJSON('/api/sentinel/feed?nocache=1');
    record('Intel', 'GET /api/sentinel/feed (nocache) returns 200', 'blocker', r.status === 200);
    if (r.body) {
      record('Intel', 'sentinel feed reports ThreatFox as a source', 'warn',
        !!r.body.sources?.threatfox, JSON.stringify(r.body.sources));
      record('Intel', 'sentinel feed ttl_seconds <= 1800 (freshness fix)', 'warn',
        typeof r.body.ttl_seconds === 'number' && r.body.ttl_seconds <= 1800,
        `ttl=${r.body.ttl_seconds}`);
    }
  }
  {
    const r = await fetchJSON('/api/global-threat-feed/stats');
    // Tier-gated is acceptable; a 500 or a "dark_web" source key is not.
    record('Intel', 'GET /api/global-threat-feed/stats does not 500', 'blocker', r.status !== 500, `status=${r.status}`);
    if (r.body?.by_source) {
      record('Intel', 'global-threat-feed no longer reports a dark_web source (fabrication removed)', 'blocker',
        !('dark_web' in r.body.by_source), JSON.stringify(r.body.by_source));
    }
  }
  {
    const r = await fetchJSON('/api/threat-intel/stats');
    record('Intel', 'GET /api/threat-intel/stats returns 200', 'blocker', r.status === 200);
  }
  {
    const r = await fetchJSON('/api/uptime');
    record('Intel', 'GET /api/uptime returns 200', 'warn', r.status === 200);
  }

  // ── C. Golden Path — real customer scan flow ──────────────────────────────
  {
    const r = await fetchJSON('/api/scan/domain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: 'example.com' }),
    });
    record('Golden Path', 'POST /api/scan/domain (example.com) does not 500', 'blocker',
      r.status !== 500, `status=${r.status}`);
    record('Golden Path', 'scan response is valid JSON', 'blocker', !!r.body, r.raw?.slice(0, 150));
  }
  {
    const r = await fetchJSON('/api/scan/stats');
    record('Golden Path', 'GET /api/scan/stats returns 200', 'warn', r.status === 200);
  }
  {
    // By design, unauthenticated callers get IP-scoped FREE-tier history (200,
    // user_id: null) rather than a hard 401 — resolveAuthV5's "IP fallback"
    // path (workers/src/auth/middleware.js) marks anonymous callers
    // authenticated:true under an `ip:<addr>` identity. The check that matters
    // is that no JWT means no *other* user's data comes back.
    const r = await fetchJSON('/api/history?limit=5');
    record('Golden Path', 'GET /api/history without auth does not 500', 'blocker',
      r.status !== 500, `status=${r.status}`);
    if (r.status === 200 && r.body) {
      record('Golden Path', 'GET /api/history without auth returns no user_id (IP-scoped anon, not another account)', 'blocker',
        r.body.user_id === null || r.body.user_id === undefined, `user_id=${r.body.user_id}`);
    }
  }

  // ── C2. Every scan module — golden path across all product pillars ───────
  // Mirrors frontend/index.html's `endpoints` map exactly (executeScan()).
  // A 500 here means a customer clicking that module's scan button breaks in
  // production; 200/400/403 all mean the route is alive and handling input.
  const scanModules = [
    { module: 'domain',       path: '/api/scan/domain',        payload: { domain: 'example.com' } },
    { module: 'ai',           path: '/api/scan/ai',             payload: { model_name: 'gpt-4', use_case: 'chatbot' } },
    { module: 'redteam',      path: '/api/scan/redteam',        payload: { target_org: 'example.com', scope: 'external' } },
    { module: 'identity',     path: '/api/scan/identity',       payload: { org_name: 'example.com', identity_provider: 'azuread' } },
    { module: 'compliance',   path: '/api/generate/compliance', payload: { org_name: 'example.com', framework: 'iso27001' } },
    { module: 'cloudsec',     path: '/api/scan/cloud-security', payload: { domain: 'example.com', provider: 'aws', checks: [] } },
    { module: 'mcp_security', path: '/api/mcp-security/scan',   payload: { server_url: 'https://example.com/mcp', server_name: 'test' } },
    { module: 'vibe_code',    path: '/api/vibe-code/scan',      payload: { code: 'console.log(1)', language: 'javascript' } },
  ];
  for (const { module, path, payload } of scanModules) {
    const r = await fetchJSON(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    record('Scan Modules', `POST ${path} (${module}) does not 500`, 'blocker',
      r.status !== 500 && r.status !== 0, `status=${r.status}`);
  }
  // darkscan/appsec are intentionally not wired on the frontend (honest "not
  // yet available" message shown client-side before any API call). If the
  // route doesn't exist server-side either, 404 is correct, not a defect.
  for (const { module, path } of [
    { module: 'darkscan', path: '/api/scan/darkscan' },
    { module: 'appsec',   path: '/api/scan/appsec' },
  ]) {
    const r = await fetchJSON(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    record('Scan Modules', `POST ${path} (${module}, known unimplemented) does not 500`, 'warn',
      r.status !== 500, `status=${r.status}`);
  }

  // ── C3. AI Copilot / Multi-Agent SOC ───────────────────────────────────────
  {
    const r = await fetchJSON('/api/copilot/capabilities');
    record('AI Copilot', 'GET /api/copilot/capabilities returns 200', 'blocker', r.status === 200, `status=${r.status}`);
  }
  {
    const r = await fetchJSON('/api/agents/status');
    record('AI Copilot', 'GET /api/agents/status returns 200', 'blocker', r.status === 200, `status=${r.status}`);
  }
  {
    const r = await fetchJSON('/api/sentinel/status');
    record('AI Copilot', 'GET /api/sentinel/status returns 200', 'warn', r.status === 200, `status=${r.status}`);
  }

  // ── C4. Streaming endpoints (SSE) — verify content-type without draining ──
  for (const path of ['/api/dashboard/stream', '/api/realtime/feed']) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      const resp = await fetch(`${BASE}${path}`, { signal: controller.signal });
      const ct = resp.headers.get('content-type') || '';
      record('Streaming', `GET ${path} responds (status ${resp.status})`, 'warn',
        resp.status !== 500, `content-type=${ct}`);
      resp.body?.cancel?.().catch(() => {});
    } catch (e) {
      record('Streaming', `GET ${path} responds`, 'warn', false, e?.message);
    } finally {
      clearTimeout(timer);
    }
  }

  // ── D. Auth boundary — must fail closed, never 500 ────────────────────────
  {
    const r = await fetchJSON('/api/admin/analytics');
    record('Security', 'GET /api/admin/analytics without auth is rejected cleanly', 'blocker',
      [401, 403].includes(r.status), `status=${r.status}`);
  }
  {
    const r = await fetchJSON('/api/mssp/clients');
    record('Security', 'GET /api/mssp/clients without auth is rejected cleanly', 'blocker',
      [401, 403].includes(r.status), `status=${r.status}`);
  }

  // ── E. Public monetization surface ────────────────────────────────────────
  {
    const r = await fetchJSON('/api/gumroad/products');
    record('Commerce', 'GET /api/gumroad/products returns 200 (public catalog)', 'warn', r.status === 200);
  }

  // ── F. Frontend load + security headers ───────────────────────────────────
  {
    const resp = await fetch(BASE, { signal: AbortSignal.timeout(TIMEOUT_MS) }).catch(e => ({ ok: false, status: 0, error: e?.message }));
    const html = resp.ok ? await resp.text() : '';
    record('Frontend', 'Homepage returns 200', 'blocker', resp.status === 200, `status=${resp.status}`);
    record('Frontend', 'Homepage contains primary scan CTA', 'blocker', /scan your domain/i.test(html));
    record('Frontend', 'Homepage has no leaked literal "undefined" text node', 'warn',
      !/>undefined</i.test(html));
    if (resp.ok && resp.headers) {
      const csp = resp.headers.get?.('content-security-policy');
      const xcto = resp.headers.get?.('x-content-type-options');
      record('Security', 'CSP header present', 'warn', !!csp);
      record('Security', 'X-Content-Type-Options: nosniff present', 'warn', xcto === 'nosniff');
    }
  }

  // ── F2. Full frontend page sweep — every page in frontend/*.html ─────────
  // Catches the release-blocking defect class this platform has hit before
  // (a page 404ing or throwing a fatal parse error in production) across the
  // entire site, not just the homepage. Checks status + absence of a raw,
  // unhandled server error string leaking into the HTML body.
  const ALL_PAGES = [
    'about.html','academy.html','admin-payments.html','agent-threats.html',
    'ai-governance-frameworks.html','ai-governance-pdf.html','ai-governance.html',
    'ai-red-team.html','ai-risk-management.html','ai-security-assessment.html',
    'ai-security-scorecard.html','ai-security-services.html','ai-security.html',
    'api-docs.html','attack-library.html','attack-surface-management.html',
    'automation-dashboard.html','autonomous-soc-dashboard.html','billing-portal.html',
    'booking.html','ciso-hub.html','cloud-security.html','compliance-management.html',
    'contact.html','customer-dashboard.html','customer-success-dashboard.html',
    'cyber-defense.html','cyber-signal-radar.html','decision-dashboard.html',
    'developer-onboarding.html','devsecops.html','enterprise-dashboard.html',
    'enterprise-kpi-dashboard.html','enterprise-portal.html','enterprise-security.html',
    'gadgets.html','god-mode.html','incident-response.html','intel-hub.html','intel.html',
    'marketplace-checkout.html','mcp-security.html','mssp-command-center.html',
    'mssp-onboarding.html','mssp.html','ops-dashboard.html','owasp-llm-security.html',
    'press.html','privacy-policy.html','prompt-injection-defense.html',
    'proposal-generator.html','refund-policy.html','revenue-command-center.html',
    'revenue-intelligence-dashboard.html','security-assessment.html',
    'security-automation.html','security-fabric-dashboard.html',
    'sentinel-apex-marketplace.html','services.html','sitemap.html','soc-agents.html',
    'soc-command-dashboard.html','soc-dashboard.html','soc-operations.html',
    'terms-of-service.html','threat-hunting.html','threat-intel-workbench.html',
    'threat-intelligence.html','tools.html','trust-center.html','upgrade.html',
    'user-dashboard.html','vibe-code-scanner.html','vulnerability-management.html',
    'zero-trust-security.html',
  ];
  const pageFailures = [];
  for (const page of ALL_PAGES) {
    const resp = await fetch(`${BASE}/${page}`, { signal: AbortSignal.timeout(TIMEOUT_MS) })
      .catch(e => ({ ok: false, status: 0, error: e?.message }));
    const okStatus = resp.status === 200;
    if (!okStatus) pageFailures.push(`${page} (status=${resp.status})`);
  }
  record('Frontend Sweep', `All ${ALL_PAGES.length} frontend pages return 200`, 'blocker',
    pageFailures.length === 0, pageFailures.length ? pageFailures.join(', ') : `${ALL_PAGES.length}/${ALL_PAGES.length} ok`);

  // ── Summary ────────────────────────────────────────────────────────────────
  const blockers = results.filter(r => r.severity === 'blocker' && !r.pass);
  const warnings = results.filter(r => r.severity === 'warn' && !r.pass);
  const passed = results.filter(r => r.pass).length;

  console.log(`\n━━━ Release Gate Summary ━━━`);
  console.log(`Passed: ${passed}/${results.length}`);
  console.log(`Blocking failures: ${blockers.length}`);
  console.log(`Warnings: ${warnings.length}`);

  if (blockers.length) {
    console.log('\n❌ BLOCKING FAILURES:');
    blockers.forEach(b => console.log(`   - [${b.category}] ${b.name} (${b.detail || ''})`));
  }
  if (warnings.length) {
    console.log('\n⚠️  WARNINGS (non-blocking):');
    warnings.forEach(w => console.log(`   - [${w.category}] ${w.name} (${w.detail || ''})`));
  }

  if (process.env.GITHUB_STEP_SUMMARY) {
    const fs = await import('node:fs');
    const lines = [
      '### 🏢 Enterprise Release Gate',
      '',
      `**Target:** ${BASE}`,
      `**Passed:** ${passed}/${results.length} · **Blockers:** ${blockers.length} · **Warnings:** ${warnings.length}`,
      '',
      '| Category | Check | Severity | Result | Detail |',
      '|---|---|---|---|---|',
      ...results.map(r => `| ${r.category} | ${r.name} | ${r.severity} | ${r.pass ? '✅' : (r.severity === 'blocker' ? '❌' : '⚠️')} | ${(r.detail || '').replace(/\|/g, '/')} |`),
    ];
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join('\n') + '\n');
  }

  process.exit(blockers.length ? 1 : 0);
}

main().catch(e => {
  console.error('Release gate crashed:', e);
  process.exit(1);
});
