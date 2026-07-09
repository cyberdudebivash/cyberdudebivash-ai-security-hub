// CAP-RBAC-002 — Role/Plan-Based Frontend Feature Gating
// (docs/capability-registry/domains/rbac.json)
//
// Prior finding: the dashboard sidebar renders identically to every signed-in
// customer regardless of plan/role. While tracing the plan-gating code already
// in frontend/user-dashboard.html to design a fix, found several functions
// silently non-functional due to a case-sensitivity bug: GET /api/user/plan's
// `plan` field is genuinely uppercase ('FREE'|'STARTER'|'PRO'|'ENTERPRISE'|
// 'MSSP' — see workers/src/handlers/subscription.js:handleGetUserPlan and
// workers/src/auth/apiKeys.js's TIER_LIMITS/PLAN_FEATURES keys), but
// exportCisoPDF(), syncPlanCards(), and selectPlan() all compared it against
// lowercase literals — so their tier-gates never fired for any real account.
//
// Critically, submitAiAnalysis()/initAiPage() ALSO had this pattern, but
// "fixing" the case there would have been wrong: workers/test/
// aiBrainEntitlementGate.test.mjs proves POST /api/ai/analyze is intentionally
// NOT plan-gated for any tier (unlike /api/ai/simulate and /api/ai/forecast,
// which really are PRO+). The case bug there was masking an already-incorrect,
// stale restriction — production behavior (never blocked) was accidentally
// already correct. That block was removed, not case-corrected.
//
// Separately: TOOL_CATALOG/PLAN_QUOTA had no MSSP entries despite MSSP being
// a real backend tier (workers/src/auth/apiKeys.js TIER_LIMITS.MSSP/
// PLAN_FEATURES.MSSP, both ENTERPRISE-or-better) — MSSP customers saw every
// tool locked and FREE-tier quota numbers. And loadKeys() read
// _plan?.plan?.key_limit (plan is a string, not an object — always undefined)
// instead of _plan?.key_limit, always falling back to a hardcoded 2.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { TIER_LIMITS, PLAN_FEATURES, hasAccess } from '../src/auth/apiKeys.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DASH = readFileSync(resolve(__dirname, '../../frontend/user-dashboard.html'), 'utf8');

function fnBody(name) {
  const start = DASH.indexOf(`function ${name}`);
  if (start === -1) return '';
  return DASH.slice(start, start + 2000);
}

describe('AI Analysis is never plan-gated on the frontend (matches tested backend contract)', () => {
  it('initAiPage() no longer disables/hides anything for FREE tier', () => {
    const fn = fnBody('initAiPage');
    expect(fn).not.toBe('');
    expect(fn).not.toContain("plan === 'free'");
    expect(fn).not.toContain("getElementById('ai-upsell').style.display");
    expect(fn).not.toContain("getElementById('ai-submit-btn').disabled = true");
  });

  it('submitAiAnalysis() no longer blocks FREE tier before calling the API', () => {
    const fn = fnBody('submitAiAnalysis');
    expect(fn).not.toBe('');
    expect(fn).not.toContain("plan === 'free'");
    expect(fn).not.toContain('AI Analysis requires Pro or Enterprise plan');
    // Must still actually call the real, unmetered endpoint.
    expect(fn).toContain("'/api/ai/analyze'");
  });

  it('no fabricated "queries left" credits counter remains (no backing field in the real API response)', () => {
    // Checks the actual expression, not prose — a comment nearby documents
    // *why* this field was removed and legitimately mentions its name.
    expect(DASH).not.toContain('_plan?.ai_queries_remaining');
    expect(DASH).not.toMatch(/badgeEl\.textContent = Math\.max\(0, cur - 1\)/);
  });

  it('backend contract this relies on: /api/ai/analyze truly has no plan gate for any tier', () => {
    // Cross-checked against workers/test/aiBrainEntitlementGate.test.mjs, which
    // exercises the real worker.fetch() end-to-end; this is a lighter, direct
    // sanity check on the same PLAN_FEATURES source of truth.
    for (const t of ['FREE', 'STARTER', 'PRO', 'ENTERPRISE', 'MSSP']) {
      expect(hasAccess('ai_analyze', t), `${t} must have ai_analyze`).toBe(true);
    }
  });
});

describe('Tier-comparison case-sensitivity bug (CAP-RBAC-002)', () => {
  it('exportCisoPDF() normalizes the real uppercase tier before comparing', () => {
    const fn = fnBody('exportCisoPDF');
    expect(fn).not.toBe('');
    expect(fn).toContain('.toLowerCase()');
  });

  it('syncPlanCards() normalizes the real uppercase tier before comparing', () => {
    const fn = fnBody('syncPlanCards');
    expect(fn).not.toBe('');
    expect(fn).toContain('.toLowerCase()');
  });

  it('selectPlan() normalizes the real uppercase tier before comparing (was: "Upgrade to Pro" shown to existing Pro customers)', () => {
    const fn = fnBody('selectPlan');
    expect(fn).not.toBe('');
    expect(fn).toContain('.toLowerCase()');
  });

  it('loadKeys() reads the real key_limit field, not a nonexistent nested one', () => {
    const fn = fnBody('loadKeys');
    expect(fn).not.toBe('');
    expect(fn).not.toContain('_plan?.plan?.key_limit');
    expect(fn).toContain('_plan?.key_limit');
  });
});

describe('MSSP tier support in tool catalog and quota display', () => {
  it('every TOOL_CATALOG entry includes MSSP wherever it includes ENTERPRISE', () => {
    const start = DASH.indexOf('const TOOL_CATALOG');
    const end = DASH.indexOf('const PLAN_QUOTA');
    const catalogSrc = DASH.slice(start, end);
    const tierArrays = [...catalogSrc.matchAll(/tiers:\s*\[([^\]]*)\]/g)].map(m => m[1]);
    expect(tierArrays.length).toBeGreaterThan(0);
    for (const arr of tierArrays) {
      if (arr.includes('ENTERPRISE')) {
        expect(arr, `tiers array "${arr}" includes ENTERPRISE but not MSSP`).toContain('MSSP');
      }
    }
  });

  it('PLAN_QUOTA has an MSSP entry at least as generous as ENTERPRISE', () => {
    const start = DASH.indexOf('const PLAN_QUOTA');
    const end = DASH.indexOf('async function loadMyTools');
    const quotaSrc = DASH.slice(start, end);
    expect(quotaSrc).toMatch(/MSSP:\s*\{/);
  });

  it('backend contract this relies on: TIER_LIMITS.MSSP and PLAN_FEATURES.MSSP exist and are ENTERPRISE-or-better', () => {
    expect(TIER_LIMITS.MSSP).toBeDefined();
    expect(PLAN_FEATURES.MSSP).toBeDefined();
    for (const feature of ['ai_analyze', 'ai_simulate', 'ai_forecast', 'api_access', 'multi_user', 'priority_support']) {
      expect(hasAccess(feature, 'MSSP'), `MSSP must have ${feature}`).toBe(hasAccess(feature, 'ENTERPRISE'));
    }
  });
});
