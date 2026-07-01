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
    const r = await fetchJSON('/api/sentinel/feed');
    record('Intel', 'GET /api/sentinel/feed returns 200', 'blocker', r.status === 200);
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
    const r = await fetchJSON('/api/history?limit=5');
    record('Golden Path', 'GET /api/history without auth is rejected cleanly (401/403, not 500)', 'blocker',
      [401, 403].includes(r.status), `status=${r.status}`);
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
  {
    const resp = await fetch(`${BASE}/intel.html`, { signal: AbortSignal.timeout(TIMEOUT_MS) }).catch(() => ({ ok: false, status: 0 }));
    record('Frontend', 'GET /intel.html returns 200', 'warn', resp.status === 200, `status=${resp.status}`);
  }

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
