/**
 * CYBERDUDEBIVASH® MYTHOS AI — Revenue Engine Handler v31.0.0
 * File: workers/src/handlers/mythosRevenueEngine.js
 *
 * Exports (imported by src/index.js):
 *   handleMythosScan       → POST /api/mythos/scan
 *   handleMythosCompliance → POST /api/mythos/compliance
 *
 * v31.0.0 — CAP-MYTHOS-003 remediation: this handler previously fabricated
 * every result. handleMythosScan returned a hardcoded, target-independent
 * "findings" set (same fallback counts, same 4 IOC addresses for any input)
 * plus static Sigma/YARA/KQL/Suricata/playbook string templates with only the
 * target name interpolated in. handleMythosCompliance returned a static
 * per-framework lookup table with verification_status always 'ALIGNED',
 * identical for any organization. Both are now thin wrappers around this
 * platform's real engines — the same ones already serving paying customers
 * on /api/scan/domain and /api/generate/compliance — so results are
 * genuinely target-specific:
 *   - Scan: live DNS-over-HTTPS + TLS header probe + 7-feed DNSBL check
 *     (workers/src/lib/dns.js, workers/src/lib/dnsbl.js), assembled by
 *     workers/src/handlers/domain.js's buildRealResult(), falling back to
 *     the honest heuristic domainScanEngine() (workers/src/engine.js) only
 *     if live DNS itself is unreachable — never to a fabricated verdict.
 *   - Compliance: workers/src/engine.js's complianceEngine(), the same
 *     industry-benchmark engine used by 6 other live pages via
 *     workers/src/handlers/compliance.js — self-labeled STATIC/benchmark
 *     rather than falsely claiming a verified "ALIGNED" audit result.
 * Both are enriched via the real, finding-driven mythosEnrichmentEngine.js
 * (MITRE ATT&CK mapping, CyberBrain risk scoring, attack-path prediction,
 * AI executive narrative, autonomous remediation plan) for premium tiers —
 * genuinely computed value in place of the deleted static rule templates.
 *
 * The multi-rail checkout (handleMythosCheckout/handleMythosWebhook,
 * previously also exported here) has been removed outright, not redirected:
 * it had zero frontend callers, never minted a real Razorpay order, and its
 * webhook wrote real tier upgrades to the same `users.tier` column the
 * platform's actual billing path (workers/src/handlers/payments.js +
 * workers/src/services/subscriptionPaywallEngine.js, wired to
 * billing-portal.html/upgrade.html) uses — a live, untested, duplicate
 * tier-grant mechanism with no product behind it. See PROGRAM_BOARD.md's
 * session log for the full investigation.
 */

import { domainScanEngine, complianceEngine }        from '../engine.js';
import { validateDomain, validateString, parseBody } from '../middleware/validation.js';
import { sanitizeString }                            from '../middleware/security.js';
import { resolveDomain, inferTLSGrade }              from '../lib/dns.js';
import { fullBlacklistCheck }                        from '../lib/dnsbl.js';
import { buildRealResult }                           from './domain.js';
import { enrichAssessmentWithMYTHOS }                from '../services/mythosEnrichmentEngine.js';

const SUPPORTED_FRAMEWORKS = ['iso27001', 'soc2', 'gdpr', 'pcidss', 'dpdp', 'hipaa'];

const PAYWALL_NOTICE = {
  status: 'LOCKED',
  _tier_notice: 'Upgrade to PRO or ENTERPRISE to unlock full findings, the autonomous remediation plan, and the AI executive brief.',
  _upgrade_url: 'https://intel.cyberdudebivash.com/upgrade.html?plan=pro',
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store',
    },
  });

function genScanId() {
  return 'mysc_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

/** Check if caller has PRO/ENTERPRISE tier from existing auth context */
function isPremium(authCtx) {
  if (!authCtx) return false;
  const tier = (authCtx.tier || authCtx.plan || 'FREE').toUpperCase();
  return tier === 'PRO' || tier === 'ENTERPRISE' || tier === 'PROFESSIONAL' || tier === 'TEAM' || tier === 'BUSINESS';
}

// ─── EXPORTS ──────────────────────────────────────────────────────────────────

/**
 * POST /api/mythos/scan
 * Body: { target } — live domain/DNS/TLS/threat-intel scan (paywall-aware).
 * Real, target-specific data only — see file header for the engine chain.
 */
export async function handleMythosScan(request, env, authCtx) {
  const body = await parseBody(request);
  const raw  = body?.target || body?.domain || '';

  const validation = validateDomain(sanitizeString(raw));
  if (!validation.valid) {
    return json({ error: 'Validation failed', message: validation.message, field: 'target' }, 400);
  }

  const target  = validation.value;
  const premium = isPremium(authCtx);
  const scanId  = genScanId();

  let dns = null, tls = null, bl = null, dataSource = 'deterministic_fallback';
  try {
    [dns, tls] = await Promise.all([resolveDomain(target), inferTLSGrade(target)]);
    bl         = await fullBlacklistCheck(target, dns?.ipv4 ?? []);
    dataSource = 'live_dns';
  } catch { /* live DNS unreachable — fall back to the honest deterministic engine below */ }

  let scanResult = (dataSource === 'live_dns' && dns)
    ? buildRealResult(target, dns, tls, bl, scanId)
    : {
        ...domainScanEngine(target),
        scan_id: scanId,
        data_source: dataSource,
        fallback_reason: 'Live DNS unavailable — deterministic heuristic engine used, not a live verdict',
      };

  try {
    scanResult = await enrichAssessmentWithMYTHOS(env, {
      report:        scanResult,
      findings:      scanResult.findings || [],
      service_name:  'MYTHOS Autonomous Domain Scan',
      service_ref:   'CDB-MYTHOS-SCAN-001',
      target,
      sector:        authCtx?.sector || 'Technology',
      tier:          authCtx?.tier   || 'FREE',
      probe_results: { status: scanResult.risk_level, api_accessible: dataSource === 'live_dns' },
    });
  } catch { /* enrichment must never break the scan response */ }

  const allFindings = scanResult.findings || [];
  const result = {
    ...scanResult,
    // Free tier: show first 2 real findings; PRO+: all of them.
    findings: premium ? allFindings : allFindings.slice(0, 2),
  };

  if (!premium) {
    const remaining = Math.max(0, allFindings.length - 2);
    if (remaining > 0) {
      result.locked_findings_count = remaining;
      result._paywall_findings = PAYWALL_NOTICE;
    }
    // Deep MYTHOS enrichment (attack-path prediction, autonomous remediation
    // plan, AI executive brief) is the real premium value-add — locked whole
    // rather than partially scrubbed, since every field in it is genuinely
    // computed (not filler) and none of it is safe to give away for free.
    if (result.mythos_intelligence) {
      const mi = result.mythos_intelligence;
      result.mythos_intelligence = {
        engine: mi.engine,
        version: mi.version,
        mythos_confidence: mi.mythos_confidence,
        cyber_brain: { risk_score: mi.cyber_brain?.risk_score, risk_level: mi.cyber_brain?.risk_level },
        _paywall: PAYWALL_NOTICE,
      };
    }
  }

  return json({
    ok: true,
    premium,
    engine: 'CYBERDUDEBIVASH MYTHOS AI — live DNS/TLS/threat-intel scan engine (v31.0.0)',
    result,
  });
}

/**
 * POST /api/mythos/compliance
 * Body: { framework, target|org_name } — framework-benchmark compliance
 * gap assessment (paywall-aware). Real engine, honestly labeled STATIC —
 * see file header.
 */
export async function handleMythosCompliance(request, env, authCtx) {
  const body = await parseBody(request);

  const orgRaw = body?.org_name || body?.org || body?.organization || body?.target || body?.domain || '';
  const orgVal = validateString(sanitizeString(orgRaw), 'org_name', 2, 120);
  if (!orgVal.valid) {
    return json({ error: 'Validation failed', message: orgVal.message }, 400);
  }

  const framework = (body?.framework || 'iso27001').toString().toLowerCase();
  if (!SUPPORTED_FRAMEWORKS.includes(framework)) {
    return json({
      error: `Unsupported framework. Choose: ${SUPPORTED_FRAMEWORKS.join(', ')}`,
      supported: SUPPORTED_FRAMEWORKS,
    }, 400);
  }

  const premium = isPremium(authCtx);
  let result = complianceEngine(orgVal.value, framework);

  try {
    result = await enrichAssessmentWithMYTHOS(env, {
      report:       result,
      findings:     result.domain_assessments || [],
      service_name: 'MYTHOS Compliance Gap Assessment',
      service_ref:  'CDB-MYTHOS-CMP-001',
      target:       orgVal.value,
      sector:       authCtx?.sector || 'Technology',
      tier:         authCtx?.tier   || 'FREE',
    });
  } catch { /* enrichment must never break the scan response */ }

  return json({
    ok: true,
    premium,
    engine: 'CYBERDUDEBIVASH MYTHOS AI — framework-benchmark compliance engine (v31.0.0)',
    result,
  });
}
