/**
 * CYBERDUDEBIVASH AI Security Hub v10.0
 * Scan → Upsell Conversion Engine (Phase 3)
 * Converts every scan result into a monetization opportunity
 */

// ─── Upsell rules: scan result → product/plan recommendation ─────────────────
const UPSELL_RULES = [
  {
    id: 'critical_cve',
    match: (scan) => scan.findings?.some(f => f.severity === 'CRITICAL' || f.cvss >= 9.0),
    products: ['firewall_script', 'sigma_rule', 'ir_playbook'],
    plan_upsell: 'PRO',
    headline: '🚨 Critical Vulnerability Detected — Fix Available Now',
    message: 'A CRITICAL-severity vulnerability was found in this scan. Our AI has generated a ready-to-deploy defense solution.',
    urgency: 'CRITICAL',
    discount: 0,
  },
  {
    id: 'active_apt',
    match: (scan) => scan.threat_intel?.apt_groups?.length > 0,
    products: ['sigma_rule', 'yara_rule', 'threat_hunt_pack'],
    plan_upsell: 'PRO',
    headline: `⚔️ APT Activity Detected — Hunt Them Now`,
    message: 'Threat actors are actively targeting this CVE. Deploy our detection rules before they reach you.',
    urgency: 'HIGH',
    discount: 0,
  },
  {
    id: 'compliance_gap',
    match: (scan) => scan.compliance?.gaps?.length > 2 || scan.module === 'compliance',
    products: ['exec_briefing', 'hardening_script'],
    plan_upsell: 'STARTER',
    headline: '📋 Compliance Gaps Found — Generate Your Report',
    message: 'Multiple compliance gaps detected. Get an executive briefing PDF + automated hardening scripts to close them.',
    urgency: 'MEDIUM',
    discount: 0,
  },
  {
    id: 'free_tier_limit',
    match: (scan) => scan.tier === 'free' && scan.finding_count >= 3,
    products: [],
    plan_upsell: 'STARTER',
    headline: '🔒 Unlock Full Findings — 3 More Issues Hidden',
    message: 'You\'ve hit the free tier preview limit. Upgrade to Starter to see all findings with full details.',
    urgency: 'SOFT',
    discount: 20,
    discount_code: 'UNLOCK20',
  },
  {
    id: 'domain_dns_risk',
    match: (scan) => scan.module === 'domain' && scan.findings?.some(f => f.type === 'DNSSEC' || f.type === 'MX'),
    products: ['firewall_script', 'hardening_script'],
    plan_upsell: null,
    headline: '🌐 DNS Security Issues — Auto-Fix Script Available',
    message: 'Your DNS configuration has exploitable gaps. Our hardening script fixes them automatically.',
    urgency: 'HIGH',
    discount: 0,
  },
  {
    id: 'ai_llm_risk',
    match: (scan) => scan.module === 'ai_security' || scan.findings?.some(f => f.type?.startsWith('LLM')),
    products: ['api_module', 'python_scanner'],
    plan_upsell: 'PRO',
    headline: '🤖 AI/LLM Vulnerabilities Found — Patch Your API',
    message: 'OWASP LLM risks detected in your AI stack. Deploy our security middleware module instantly.',
    urgency: 'HIGH',
    discount: 0,
  },
  {
    id: 'red_team_findings',
    match: (scan) => scan.module === 'red_team' && scan.risk_score >= 60,
    products: ['ir_playbook', 'hardening_script'],
    plan_upsell: 'ENTERPRISE',
    headline: '🎯 Red Team Simulation: Critical Gaps Found',
    message: 'Your security posture has exploitable weaknesses. Get enterprise-grade IR playbooks and hardening scripts.',
    urgency: 'HIGH',
    discount: 0,
  },
  {
    id: 'high_risk_score',
    match: (scan) => (scan.risk_score || scan.score || 0) >= 70,
    products: ['exec_briefing', 'ir_playbook'],
    plan_upsell: 'STARTER',
    headline: '⚠️ High Risk Score Detected',
    message: 'This target has a risk score above 70. Generate an executive briefing to communicate the risk to your board.',
    urgency: 'MEDIUM',
    discount: 0,
  },
];

// ─── Plan upgrade messaging ───────────────────────────────────────────────────
const PLAN_MESSAGING = {
  STARTER: {
    price: '₹499/mo',
    headline: 'Unlock Full Report + AI Analysis',
    features: ['Full findings (all CVEs)', 'AI Threat Analysis', 'PDF Report', '10 scans/month', '2 API Keys'],
    cta: 'Get Starter — ₹499/mo',
    color: '#00d4ff',
  },
  PRO: {
    price: '₹1,499/mo',
    headline: 'Pro: Unlimited Scans + Full AI Brain',
    features: ['Unlimited scans', 'Full AI Brain V2', 'Attack Simulation', 'API Access (500 req/day)', 'Advanced PDF Reports'],
    cta: 'Get Pro — ₹1,499/mo',
    color: '#7c3aed',
  },
  ENTERPRISE: {
    price: '₹4,999/mo',
    headline: 'Enterprise: Multi-User + White-Label',
    features: ['Unlimited scans', '10 seats', 'Custom integrations', 'SLA guarantee', 'White-label option'],
    cta: 'Get Enterprise — ₹4,999/mo',
    color: '#f59e0b',
  },
};

// ─── Core: evaluate scan result and build upsell payload ─────────────────────
export async function evaluateScanUpsell(env, scanResult, authCtx = {}) {
  try {
    const matched     = UPSELL_RULES.filter(rule => {
      try { return rule.match(scanResult); } catch { return false; }
    });

    if (!matched.length) return null;

    // Sort by urgency priority
    const urgencyOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, SOFT: 3 };
    matched.sort((a, b) => (urgencyOrder[a.urgency] ?? 99) - (urgencyOrder[b.urgency] ?? 99));

    const primary   = matched[0];
    const secondary = matched.slice(1, 3);

    // Fetch relevant defense solutions for product upsells
    let products = [];
    if (primary.products?.length && env.SECURITY_HUB_DB) {
      try {
        const cats   = primary.products.slice(0, 3);
        const query  = `SELECT id, cve_id, title, category, price_inr, severity, preview, demand_score
                        FROM defense_solutions WHERE is_active=1 AND category IN (${cats.map(() => '?').join(',')})
                        ORDER BY demand_score DESC, severity DESC LIMIT 3`;
        const rows   = await env.SECURITY_HUB_DB.prepare(query).bind(...cats).all();
        products     = rows.results || [];
      } catch { /* fallback to empty */ }
    }

    // Build FOMO signals
    const fomoSignals = await buildFOMOSignals(env, scanResult, primary.urgency);

    // Track upsell impression in KV
    const userId = authCtx?.userId || authCtx?.email;
    if (userId && env.SECURITY_HUB_KV) {
      const key = `upsell:impression:${userId}:${primary.id}`;
      const prev = await env.SECURITY_HUB_KV.get(key);
      if (!prev) {
        await env.SECURITY_HUB_KV.put(key, JSON.stringify({ rule: primary.id, ts: Date.now() }), { expirationTtl: 86400 });
      }
    }

    return {
      triggered:       true,
      rule_id:         primary.id,
      urgency:         primary.urgency,
      headline:        primary.headline,
      message:         primary.message,
      plan_upsell:     primary.plan_upsell,
      plan_messaging:  primary.plan_upsell ? PLAN_MESSAGING[primary.plan_upsell] : null,
      discount:        primary.discount,
      discount_code:   primary.discount_code || null,
      products,
      secondary_rules: secondary.map(r => ({ id: r.id, headline: r.headline, urgency: r.urgency })),
      fomo:            fomoSignals,
      scan_summary: {
        module:     scanResult.module,
        risk_score: scanResult.risk_score || scanResult.score,
        severity:   scanResult.severity,
        finding_count: scanResult.findings?.length || scanResult.finding_count || 0,
      },
    };
  } catch (err) {
    console.error('[scanUpsell] evaluateScanUpsell error:', err);
    return null;
  }
}

// ─── FOMO signal builder ──────────────────────────────────────────────────────
async function buildFOMOSignals(env, scanResult, urgency) {
  const signals = [];

  // Recent purchases in same category
  try {
    if (env.SECURITY_HUB_DB) {
      const row = await env.SECURITY_HUB_DB.prepare(
        `SELECT COUNT(*) as cnt FROM defense_purchases WHERE status='paid'
         AND created_at >= datetime('now','-24 hours')`
      ).first();
      if (row?.cnt > 0) {
        signals.push({ type: 'purchases_24h', message: `${row.cnt} solutions purchased in the last 24 hours`, icon: '🛡️' });
      }
    }
  } catch {}

  // Active threat context
  if (urgency === 'CRITICAL') {
    signals.push({ type: 'threat_active', message: 'Active exploitation confirmed by CISA KEV', icon: '🚨' });
    signals.push({ type: 'time_pressure', message: 'Average breach window: 72 hours after public disclosure', icon: '⏱️' });
  } else if (urgency === 'HIGH') {
    signals.push({ type: 'threat_active', message: 'Threat actors scanning for this vulnerability now', icon: '⚠️' });
  }

  // Generic social proof
  signals.push({ type: 'social_proof', message: 'Used by Fortune 500 SOC teams and MSSPs', icon: '🏢' });

  return signals.slice(0, 4);
}

// ─── Handler: POST /api/scan/upsell ──────────────────────────────────────────
export async function handleScanUpsell(request, env, authCtx) {
  try {
    const body = await request.json().catch(() => ({}));
    const upsell = await evaluateScanUpsell(env, body.scan_result || body, authCtx);
    if (!upsell) return json({ triggered: false });
    return json({ success: true, ...upsell });
  } catch (err) {
    return json({ triggered: false, error: err.message });
  }
}

// ─── Handler: GET /api/scan/upsell/stats ─────────────────────────────────────
export async function handleUpsellStats(request, env, authCtx) {
  try {
    if (authCtx?.role !== 'admin') return json({ error: 'Admin only' }, 403);
    const cacheKey = 'cache:upsell:stats';
    const cached   = await env.SECURITY_HUB_KV?.get(cacheKey, 'json');
    if (cached) return json({ success: true, cached: true, ...cached });

    const [impressions, conversions] = await Promise.all([
      env.SECURITY_HUB_KV?.list({ prefix: 'upsell:impression:' }).then(l => l?.keys?.length || 0).catch(() => 0),
      env.SECURITY_HUB_DB?.prepare(`SELECT COUNT(*) as cnt FROM revenue_events WHERE event_type='subscription_payment' AND created_at >= datetime('now','-30 days')`).first().catch(() => null),
    ]);

    const stats = {
      impressions_30d:  impressions,
      conversions_30d:  conversions?.cnt || 0,
      conversion_rate:  impressions > 0 ? ((conversions?.cnt || 0) / impressions * 100).toFixed(1) : '0.0',
    };
    await env.SECURITY_HUB_KV?.put(cacheKey, JSON.stringify(stats), { expirationTtl: 300 });
    return json({ success: true, ...stats });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
