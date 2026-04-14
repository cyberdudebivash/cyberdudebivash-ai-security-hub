/**
 * ═══════════════════════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH AI Security Hub — MCP Shadow Engine v1.0
 *
 * Implements MCP (Model Context Protocol) as a SHADOW ENGINE:
 * - All MCP calls run asynchronously
 * - If MCP fails → existing logic takes over (zero user impact)
 * - Frontend → Worker → MCP → Structured JSON response
 *
 * Endpoints:
 *   POST /mcp/recommend     — vuln → tool → training recommendations
 *   POST /mcp/upsell        — context-aware upsell logic
 *   POST /mcp/training-map  — map scan findings to training courses
 *   GET  /mcp/health        — MCP system health
 *
 * MCP Server: https://github.com/cyberdudebivash/CYBERDUDEBIVASH-MCP-Server
 * ═══════════════════════════════════════════════════════════════════════════
 */

// ─── MCP Server Config ────────────────────────────────────────────────────────
const MCP_BASE_URL = 'https://mcp.cyberdudebivash.in'; // Production MCP endpoint
const MCP_TIMEOUT_MS = 4000; // 4s timeout — fail fast, fallback immediately

// ─── Training Course Index (fallback + MCP enrichment) ───────────────────────
const TRAINING_INDEX = {
  'domain':     [{ id:'SOC_PLAYBOOK_2026', name:'SOC Analyst Survival Playbook 2026', price:999, relevance_reason:'Learn DNS/TLS/HTTP security in depth' }],
  'ai':         [{ id:'AI_SECURITY_BUNDLE_2026', name:'AI Security Training Bundle 2026', price:1199, relevance_reason:'Master LLM security and AI attack vectors' }],
  'redteam':    [{ id:'CYBER_MEGA_PART2', name:'Cybersecurity Mega Course Part 2', price:799, relevance_reason:'Deep dive into red team methodology' }],
  'identity':   [{ id:'SOC_PLAYBOOK_2026', name:'SOC Analyst Survival Playbook 2026', price:999, relevance_reason:'Zero Trust and identity threat detection' }],
  'compliance': [{ id:'CYBER_MEGA_PART1', name:'Cybersecurity Mega Course Part 1', price:699, relevance_reason:'Compliance frameworks and security controls' }],
  'cloudsec':   [{ id:'CYBER_MEGA_PART2', name:'Cybersecurity Mega Course Part 2', price:799, relevance_reason:'Cloud security hardening and DevSecOps' }],
  'darkscan':   [{ id:'OSINT_STARTER_BUNDLE', name:'OSINT Starter Bundle', price:499, relevance_reason:'OSINT techniques and dark web intelligence' }],
  'appsec':     [{ id:'SOC_PLAYBOOK_2026', name:'SOC Analyst Survival Playbook 2026', price:999, relevance_reason:'Application security incident response' }],
};

// ─── Tool Recommendations (fallback) ─────────────────────────────────────────
const TOOL_RECOMMENDATIONS = {
  'domain': [
    { tool:'DNSSEC Validator', desc:'Validate and fix DNSSEC configuration', url:'/#scanner' },
    { tool:'TLS Grade Checker', desc:'Audit TLS cipher suites and certificate chain', url:'/tools.html' },
    { tool:'Email Security Analyzer', desc:'Check SPF/DKIM/DMARC configuration', url:'/tools.html' },
  ],
  'ai': [
    { tool:'LLM Security Scanner', desc:'Detect prompt injection vulnerabilities', url:'/tools.html' },
    { tool:'AI Model Audit Tool', desc:'Audit AI model outputs for data leakage', url:'/tools.html' },
  ],
  'redteam': [
    { tool:'Attack Surface Mapper', desc:'Map your complete external attack surface', url:'/tools.html' },
    { tool:'Firewall Rule Analyzer', desc:'Audit firewall rules for gaps', url:'/tools.html' },
  ],
  'identity': [
    { tool:'Credential Exposure Monitor', desc:'Check for breached credentials', url:'/tools.html' },
    { tool:'Zero Trust Assessor', desc:'Evaluate Zero Trust maturity', url:'/tools.html' },
  ],
};

// ─── Upsell Logic Engine ──────────────────────────────────────────────────────
const UPSELL_RULES = [
  {
    trigger: { risk_score_gte: 75 },
    offer:   { product:'PRO', label:'Pro Plan', price:1499, message:'High risk detected. Pro Plan gives unlimited scans + full remediation roadmap.', urgency:'critical' },
  },
  {
    trigger: { risk_score_gte: 50, tier: 'FREE' },
    offer:   { product:'STARTER', label:'Starter Plan', price:499, message:'Unlock full findings for this scan + 50 scans/month.', urgency:'high' },
  },
  {
    trigger: { module: 'redteam' },
    offer:   { product:'CYBER_MEGA_PART2', label:'Red Team Training', price:799, message:'Learn the exact red team techniques detected in your scan.', urgency:'medium' },
  },
  {
    trigger: { module: 'ai' },
    offer:   { product:'AI_SECURITY_BUNDLE_2026', label:'AI Security Training', price:1199, message:'Master AI security. New attacks arrive daily.', urgency:'high' },
  },
  {
    trigger: { locked_findings_gte: 5 },
    offer:   { product:'DOMAIN_REPORT', label:'Full Security Report', price:199, message:`${'{count}'} critical findings are hidden. Unlock your full PDF report for ₹199.`, urgency:'critical' },
  },
  {
    trigger: { module: 'compliance' },
    offer:   { product:'CYBER_MEGA_PART1', label:'Compliance Training', price:699, message:'Build the compliance knowledge to fix every gap in this report.', urgency:'medium' },
  },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────
function jsonOk(data) {
  return new Response(JSON.stringify({ success: true, data, error: null, ts: new Date().toISOString() }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
function jsonErr(message, status = 400) {
  return new Response(JSON.stringify({ success: false, data: null, error: message }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Call external MCP server with timeout + fallback
 */
async function callMCP(endpoint, payload, env) {
  const mcpKey = env?.MCP_API_KEY || '';
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), MCP_TIMEOUT_MS);

  try {
    const res = await fetch(`${MCP_BASE_URL}${endpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${mcpKey}`,
        'X-Platform': 'CYBERDUDEBIVASH-AI-HUB',
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!res.ok) return null;
    const json = await res.json();
    return json?.data || null;

  } catch (err) {
    clearTimeout(timeout);
    return null; // silently fail — fallback takes over
  }
}

// ─── POST /mcp/recommend ──────────────────────────────────────────────────────
/**
 * Input: { module, risk_score, findings: [{id, title, severity, cvss}], target, user_tier }
 * Output: { tools, training, remediation_steps, upsell }
 */
const VALID_MODULES = ['domain','ai','redteam','identity','compliance','cloudsec','darkscan','appsec'];
const VALID_TIERS   = ['FREE','STARTER','PRO','ENTERPRISE'];

function sanitizeStr(s, maxLen = 200) {
  if (typeof s !== 'string') return '';
  return s.replace(/<[^>]*>/g, '').replace(/['"`;]/g, '').slice(0, maxLen).trim();
}

function clampScore(n, min = 0, max = 100) {
  const v = parseFloat(n);
  if (isNaN(v)) return 50;
  return Math.min(max, Math.max(min, v));
}

function sanitizeFinding(f) {
  if (typeof f !== 'object' || !f) return null;
  return {
    id:       sanitizeStr(String(f.id || ''), 50),
    title:    sanitizeStr(String(f.title || ''), 150),
    severity: ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].includes(f.severity) ? f.severity : 'MEDIUM',
    cvss:     clampScore(f.cvss, 0, 10),
    category: sanitizeStr(String(f.category || ''), 60),
  };
}

export async function handleMCPRecommend(request, env, authCtx) {
  try {
    const body = await request.json().catch(() => ({}));

    // ── Strict input validation + sanitization ─────────────────────────────
    const module     = VALID_MODULES.includes(body.module) ? body.module : 'domain';
    const risk_score = clampScore(body.risk_score, 0, 100);
    const user_tier  = VALID_TIERS.includes((body.user_tier || '').toUpperCase())
      ? body.user_tier.toUpperCase() : 'FREE';
    const target     = sanitizeStr(body.target || '', 120);
    const findings   = Array.isArray(body.findings)
      ? body.findings.slice(0, 20).map(sanitizeFinding).filter(Boolean)
      : [];
    const locked_count = Math.max(0, parseInt(body.locked_count || 0, 10) || 0);

    // ── Rate limit: max 30 MCP calls/min per IP via KV ─────────────────────
    const ip = authCtx?.ip || 'anon';
    if (env?.SECURITY_HUB_KV) {
      const rlKey = `mcp:rl:${ip}`;
      const rlRaw = await env.SECURITY_HUB_KV.get(rlKey).catch(() => null);
      const count = parseInt(rlRaw || '0', 10);
      if (count >= 30) return jsonErr('Rate limit exceeded. Please wait 60 seconds.', 429);
      env.SECURITY_HUB_KV.put(rlKey, String(count + 1), { expirationTtl: 60 }).catch(() => {});
    }

    // Try MCP server first (shadow mode — fail silently)
    const mcpResult = await callMCP('/v1/recommend', { module, risk_score, findings: findings.slice(0,10), target, user_tier }, env);

    if (mcpResult && mcpResult.tools && mcpResult.training) {
      // MCP succeeded — enrich with local data and return
      return jsonOk({ ...mcpResult, source: 'mcp' });
    }

    // ── Fallback: local intelligence engine ──────────────────────────────────
    const tools    = TOOL_RECOMMENDATIONS[module] || TOOL_RECOMMENDATIONS['domain'];
    const training = TRAINING_INDEX[module] || TRAINING_INDEX['domain'];

    // Generate contextual remediation steps
    const remediationSteps = generateRemediationSteps(module, risk_score, findings);

    // Determine upsell
    const upsell = evaluateUpsell({ module, risk_score, locked_count: body.locked_count || 0, tier: user_tier });

    // KV cache result for 30 minutes
    const cacheKey = `mcp:recommend:${module}:${risk_score}:${user_tier}`;
    if (env?.SECURITY_HUB_KV) {
      env.SECURITY_HUB_KV.put(cacheKey, JSON.stringify({ tools, training, remediationSteps, upsell }), { expirationTtl: 1800 }).catch(() => {});
    }

    return jsonOk({ tools, training, remediation_steps: remediationSteps, upsell, source: 'local' });

  } catch (err) {
    return jsonErr(`Recommendation engine error: ${err.message}`, 500);
  }
}

// ─── POST /mcp/upsell ─────────────────────────────────────────────────────────
/**
 * Context-aware upsell engine
 * Input: { module, risk_score, locked_count, user_tier, page_context }
 * Output: { offer, message, urgency, cta_text, cta_action }
 */
export async function handleMCPUpsell(request, env, authCtx) {
  try {
    const body = await request.json().catch(() => ({}));

    // ── Strict input validation ────────────────────────────────────────────
    const module      = VALID_MODULES.includes(body.module) ? body.module : 'domain';
    const risk_score  = clampScore(body.risk_score, 0, 100);
    const locked_count = Math.max(0, parseInt(body.locked_count || 0, 10) || 0);
    const user_tier   = VALID_TIERS.includes((body.user_tier || '').toUpperCase())
      ? body.user_tier.toUpperCase() : 'FREE';
    const page_context = sanitizeStr(body.page_context || '', 60);

    const sanitizedPayload = { module, risk_score, locked_count, user_tier, page_context };

    // Try MCP first
    const mcpResult = await callMCP('/v1/upsell', sanitizedPayload, env);
    if (mcpResult?.offer) {
      return jsonOk({ ...mcpResult, source: 'mcp' });
    }

    // Fallback: local upsell rules
    const upsell = evaluateUpsell({
      module,
      risk_score,
      locked_count,
      tier: user_tier,
    });

    return jsonOk({ ...upsell, source: 'local' });

  } catch (err) {
    return jsonErr(`Upsell engine error: ${err.message}`, 500);
  }
}

// ─── POST /mcp/training-map ───────────────────────────────────────────────────
/**
 * Maps scan findings → specific training modules with relevance scores
 * Input: { module, findings: [{title, severity, cvss, category}], risk_score }
 * Output: { primary_course, secondary_courses, learning_path, estimated_hours }
 */
export async function handleMCPTrainingMap(request, env, authCtx) {
  try {
    const body = await request.json().catch(() => ({}));

    // Try MCP first
    const mcpResult = await callMCP('/v1/training-map', body, env);
    if (mcpResult?.primary_course) {
      return jsonOk({ ...mcpResult, source: 'mcp' });
    }

    // Fallback: local training mapper
    const { module = 'domain', findings = [], risk_score = 50 } = body;
    const primaryCourses = TRAINING_INDEX[module] || TRAINING_INDEX['domain'];
    const primary = primaryCourses[0];

    // Calculate secondary courses based on finding categories
    const secondaryCourses = [];
    if (risk_score >= 70) {
      secondaryCourses.push({ id:'SOC_PLAYBOOK_2026', name:'SOC Analyst Survival Playbook 2026', price:999, reason:'High risk requires SOC-level incident response skills' });
    }
    if (findings.some(f => f.title?.toLowerCase().includes('sql') || f.title?.toLowerCase().includes('injection'))) {
      secondaryCourses.push({ id:'CYBER_MEGA_PART1', name:'Cybersecurity Mega Course Part 1', price:699, reason:'SQL injection and web application security fundamentals' });
    }
    if (module === 'domain' && findings.some(f => f.title?.toLowerCase().includes('dns'))) {
      secondaryCourses.push({ id:'OSINT_STARTER_BUNDLE', name:'OSINT Starter Bundle', price:499, reason:'DNS recon and domain intelligence techniques' });
    }

    // Bundle recommendation if multiple courses relevant
    const bundleRecommended = secondaryCourses.length >= 2 || risk_score >= 75;

    return jsonOk({
      primary_course:     primary,
      secondary_courses:  [...new Map(secondaryCourses.map(c=>[c.id,c])).values()].slice(0, 3),
      bundle_recommended: bundleRecommended,
      bundle_offer:       bundleRecommended ? { id:'ULTIMATE_BUNDLE_2026', name:'Ultimate Bundle 2026', price:1999, saving:1997 } : null,
      learning_path:      generateLearningPath(module, risk_score),
      estimated_hours:    risk_score >= 70 ? 40 : 20,
      source:             'local',
    });

  } catch (err) {
    return jsonErr(`Training mapper error: ${err.message}`, 500);
  }
}

// ─── GET /mcp/health ──────────────────────────────────────────────────────────
export async function handleMCPHealth(request, env) {
  let mcpStatus = 'unknown';
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    const res = await fetch(`${MCP_BASE_URL}/health`, { signal: controller.signal });
    clearTimeout(timeout);
    mcpStatus = res.ok ? 'online' : 'degraded';
  } catch {
    mcpStatus = 'offline';
  }

  return jsonOk({
    mcp_server:    mcpStatus,
    fallback:      'local_engine',
    fallback_ready: true,
    capabilities:  ['recommend','upsell','training-map'],
    version:       '1.0.0',
  });
}

// ─── Internal: Upsell Evaluator ───────────────────────────────────────────────
function evaluateUpsell({ module, risk_score, locked_count, tier }) {
  for (const rule of UPSELL_RULES) {
    const t = rule.trigger;
    if (t.risk_score_gte    && risk_score < t.risk_score_gte) continue;
    if (t.tier              && tier !== t.tier) continue;
    if (t.module            && module !== t.module) continue;
    if (t.locked_findings_gte && locked_count < t.locked_findings_gte) continue;

    const offer = { ...rule.offer };
    offer.message = offer.message.replace('{count}', locked_count);
    return {
      show:       true,
      product:    offer.product,
      label:      offer.label,
      price:      offer.price,
      message:    offer.message,
      urgency:    offer.urgency,
      cta_text:   `Unlock ${offer.label} — ₹${offer.price}`,
      cta_action: `CDB_PAY.open('${offer.product}',${offer.price},'${offer.label}')`,
    };
  }
  return { show: false };
}

// ─── Internal: Remediation Step Generator ────────────────────────────────────
function generateRemediationSteps(module, risk_score, findings) {
  const STEPS = {
    domain: [
      { priority:'CRITICAL', step:'Enable DNSSEC on your domain registrar + DNS provider' },
      { priority:'HIGH',     step:'Set DMARC policy to p=reject; configure DKIM 2048-bit keys' },
      { priority:'HIGH',     step:'Disable TLS 1.0 and 1.1; enforce TLS 1.2+ with AEAD ciphers' },
      { priority:'MEDIUM',   step:'Add Content-Security-Policy and Strict-Transport-Security headers' },
      { priority:'MEDIUM',   step:'Configure Certificate Transparency monitoring (crt.sh alerts)' },
      { priority:'LOW',      step:'Review and prune unnecessary DNS records (shadow IT cleanup)' },
    ],
    ai: [
      { priority:'CRITICAL', step:'Deploy prompt injection detection on all LLM API endpoints' },
      { priority:'HIGH',     step:'Implement OWASP LLM Top 10 controls in application middleware' },
      { priority:'HIGH',     step:'Rate-limit AI inference endpoints; add per-user quotas' },
      { priority:'MEDIUM',   step:'Sanitize and validate all LLM outputs before rendering to users' },
    ],
    redteam: [
      { priority:'CRITICAL', step:'Patch all CVE findings immediately; prioritize CVSS ≥ 9.0' },
      { priority:'HIGH',     step:'Segment network — isolate critical systems behind firewall zones' },
      { priority:'HIGH',     step:'Deploy honeypots in high-value network segments' },
      { priority:'MEDIUM',   step:'Implement EDR on all endpoints; configure behavior-based detection' },
    ],
    identity: [
      { priority:'CRITICAL', step:'Enforce MFA on all accounts immediately — no exceptions' },
      { priority:'HIGH',     step:'Implement conditional access policies based on user risk signals' },
      { priority:'HIGH',     step:'Audit and revoke stale service accounts and unused permissions' },
      { priority:'MEDIUM',   step:'Deploy ZTNA to replace legacy VPN infrastructure' },
    ],
    compliance: [
      { priority:'HIGH',     step:'Implement data classification policy per DPDP Act 2023 / GDPR' },
      { priority:'HIGH',     step:'Conduct access review — document who has access to what data' },
      { priority:'MEDIUM',   step:'Deploy DLP solution to prevent unauthorized data exfiltration' },
      { priority:'LOW',      step:'Establish 72-hour breach notification SLA and incident playbook' },
    ],
  };

  const steps = STEPS[module] || STEPS['domain'];
  const count = risk_score >= 70 ? steps.length : risk_score >= 45 ? Math.ceil(steps.length * 0.7) : Math.ceil(steps.length * 0.5);
  return steps.slice(0, count);
}

// ─── Internal: Learning Path Generator ────────────────────────────────────────
function generateLearningPath(module, risk_score) {
  const paths = {
    domain:    ['🔍 Network Security Fundamentals','🛡 DNS & PKI Security','📋 Security Headers & WAF','🔎 Continuous Monitoring'],
    ai:        ['🤖 AI/ML Security Primer','🧠 LLM Attack Vectors','🔐 Adversarial Defense','📊 AI SOC Integration'],
    redteam:   ['⚔️ Recon & OSINT','🎯 Exploitation Techniques','🔄 Post-Exploitation','🛡 Purple Team Defense'],
    identity:  ['🆔 IAM Fundamentals','🔑 Zero Trust Architecture','👁 ITDR & Behavioral Analytics','🏢 PAM Deployment'],
    compliance:['📋 Framework Mapping','🗺 Risk Assessment','🔏 Data Privacy Controls','✅ Audit Preparation'],
  };
  return paths[module] || paths['domain'];
}

// ─── Bundle Catalog ────────────────────────────────────────────────────────────
const BUNDLE_CATALOG = [
  {
    id: 'SECURITY_STARTER_BUNDLE',
    name: 'Security Starter Bundle',
    description: 'Domain scan + SOC Playbook 2026 + Compliance Mega Course',
    products: ['DOMAIN_REPORT','SOC_PLAYBOOK_2026','CYBER_MEGA_PART1'],
    original_price: 1897,
    bundle_price:   799,
    discount_pct:   58,
    validity_days:  365,
    best_for:       ['domain','compliance','identity'],
  },
  {
    id: 'PRO_SECURITY_BUNDLE',
    name: 'Pro Security Bundle',
    description: 'All modules + AI Security Training + Red Team Course + Pro Plan (1 month)',
    products: ['AI_SECURITY_BUNDLE_2026','CYBER_MEGA_PART2','SOC_PLAYBOOK_2026'],
    original_price: 3397,
    bundle_price:   1499,
    discount_pct:   56,
    validity_days:  365,
    best_for:       ['ai','redteam','appsec'],
  },
  {
    id: 'ENTERPRISE_INTELLIGENCE_BUNDLE',
    name: 'Enterprise Intelligence Bundle',
    description: 'OSINT Bundle + Threat Intel Report + AI Security + Full Platform (3 months)',
    products: ['OSINT_STARTER_BUNDLE','THREAT_INTEL_REPORT','AI_SECURITY_BUNDLE_2026'],
    original_price: 6897,
    bundle_price:   2999,
    discount_pct:   57,
    validity_days:  90,
    best_for:       ['darkscan','ai','cloudsec'],
    enterprise_only: false,
  },
];

// ─── POST /mcp/bundle — Time-limited bundle offer engine ──────────────────────
export async function handleMCPBundle(request, env, authCtx = {}) {
  let body = {};
  try { body = await request.json(); } catch { /* optional body */ }

  const { module = 'domain', risk_score = 50, tier = 'FREE' } = body;

  // Pick best matching bundle for this scan context
  const ranked = BUNDLE_CATALOG
    .filter(b => !b.enterprise_only || (tier === 'ENTERPRISE'))
    .map(b => ({
      ...b,
      relevance: b.best_for.includes(module) ? 2 : 1,
    }))
    .sort((a, b) => b.relevance - a.relevance);

  const best = ranked[0];
  if (!best) return jsonErr('No bundle available', 404);

  // Social proof (deterministic by hour)
  const hour     = new Date().getHours();
  const unitsSold = 847 + (hour * 3);
  const viewing   = 12 + (hour % 7);

  // Countdown: offer expires in 24h from first view
  const expiresAt = new Date(Date.now() + 24 * 3600 * 1000).toISOString();

  return jsonOk({
    bundle:         best,
    countdown_iso:  expiresAt,
    urgency:        risk_score >= 70 ? 'CRITICAL' : 'HIGH',
    social_proof: {
      units_sold_today: unitsSold,
      viewing_now:      viewing,
      label:            `${viewing} people viewing this offer right now`,
    },
    cta_text:  `Get ${best.name} — ₹${best.bundle_price} (Save ${best.discount_pct}%)`,
    cta_action:`CDB_PAY.open('${best.id}',${best.bundle_price},'${best.name}')`,
    all_bundles: ranked.slice(0, 3),
  });
}

// ─── POST /mcp/decision — Master Control: full AI recommendation engine ────────
// THE BRAIN: replaces ALL static frontend logic. Frontend MUST call this first.
export async function handleMCPDecision(request, env, authCtx = {}) {
  let body = {};
  try { body = await request.json(); } catch { return jsonErr('Invalid JSON', 400); }

  const {
    module      = 'domain',
    target      = '',
    risk_score  = 0,
    tier        = 'FREE',
    findings    = [],
    locked_count = 0,
  } = body;

  // 1. Try external MCP server first (shadow mode)
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), MCP_TIMEOUT_MS);
    const mcpRes = await fetch(`${MCP_BASE_URL}/decision`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ module, target, risk_score, tier, findings }),
      signal:  controller.signal,
    });
    clearTimeout(timer);
    if (mcpRes.ok) {
      const mcpData = await mcpRes.json();
      return jsonOk({ ...mcpData, source: 'mcp_server' });
    }
  } catch { /* fallback */ }

  // 2. Local decision engine fallback
  const recommended_tools    = TOOL_RECOMMENDATIONS[module] || TOOL_RECOMMENDATIONS['domain'];
  const recommended_training = TRAINING_INDEX[module]       || TRAINING_INDEX['domain'];
  const upsell               = evaluateUpsell({ module, risk_score, locked_count, tier });
  const remediation_steps    = generateRemediationSteps(module, risk_score, findings);
  const learning_path        = generateLearningPath(module, risk_score);

  // Determine offer type
  let offer_type = 'none';
  let cta        = null;
  if (risk_score >= 70 && tier === 'FREE')        { offer_type = 'upgrade'; cta = 'Upgrade to Pro — Unlock full remediation roadmap'; }
  else if (risk_score >= 50 && tier === 'FREE')   { offer_type = 'report';  cta = 'Get your full paid report — ₹199'; }
  else if (recommended_training.length)           { offer_type = 'training'; cta = `Learn to fix this: ${recommended_training[0].name}`; }

  // Enterprise trigger
  const enterprise_trigger = risk_score >= 85 || findings.filter(f => f.severity === 'CRITICAL').length >= 3;

  return jsonOk({
    source:               'local_engine',
    risk_level:           risk_score >= 75 ? 'HIGH' : risk_score >= 50 ? 'MEDIUM' : 'LOW',
    recommended_tools:    recommended_tools.slice(0, 3),
    recommended_training: recommended_training.slice(0, 2),
    offer_type,
    cta,
    upsell:               upsell.show ? upsell : null,
    remediation_steps:    remediation_steps.slice(0, 4),
    learning_path,
    enterprise_trigger,
    enterprise_cta:       enterprise_trigger ? 'Book Enterprise Demo — Free security assessment' : null,
    module, risk_score, tier,
    generated_at:         new Date().toISOString(),
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// GOD MODE v16 — POST /mcp/control — UNIFIED MCP CONTROL ENGINE
// Merges: /mcp/decision + /mcp/bundle + user memory (D1) + KV caching
// Returns full ai_blocks + ui_blocks — THE OPERATING SYSTEM of the platform
// ═══════════════════════════════════════════════════════════════════════════════

const MCP_CONTROL_CACHE_TTL = 180; // 3 min KV cache per unique context
const MCP_CONTROL_VERSION   = '16.0';

/**
 * Load user memory context from D1
 * Returns: { last_scan, purchases, scan_count, top_module, behavior_tags }
 * SAFE: all DB errors return empty context — never blocks the response
 */
async function loadUserMemory(env, userId, userEmail) {
  const empty = { last_scan: null, purchases: [], scan_count: 0, top_module: null, behavior_tags: [], is_returning: false };
  if (!env?.DB || (!userId && !userEmail)) return empty;

  try {
    // Run queries in parallel for speed
    const [scanRow, purchaseRows] = await Promise.allSettled([
      // Last scan + scan count
      env.DB.prepare(`
        SELECT module, target, risk_score, created_at
        FROM scan_history
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 1
      `).bind(userId || '').first().catch(() => null),

      // Past purchases from delivery_tokens
      env.DB.prepare(`
        SELECT product_id, amount_inr, activated_at, status
        FROM delivery_tokens
        WHERE (user_id = ? OR payer_email = ?)
          AND status IN ('active','used')
        ORDER BY activated_at DESC
        LIMIT 10
      `).bind(userId || '', userEmail || '').all().catch(() => ({ results: [] })),
    ]);

    const lastScan    = scanRow.status === 'fulfilled' ? scanRow.value : null;
    const purchases   = purchaseRows.status === 'fulfilled'
      ? (purchaseRows.value?.results || []) : [];

    // Top module from scan_history (aggregate)
    let topModule = null;
    try {
      const topRow = await env.DB.prepare(`
        SELECT module, COUNT(*) as cnt
        FROM scan_history
        WHERE user_id = ?
        GROUP BY module
        ORDER BY cnt DESC
        LIMIT 1
      `).bind(userId || '').first();
      topModule = topRow?.module || null;
    } catch { /* ignore */ }

    // Scan count
    let scanCount = 0;
    try {
      const cntRow = await env.DB.prepare(`SELECT COUNT(*) as c FROM scan_history WHERE user_id = ?`)
        .bind(userId || '').first();
      scanCount = parseInt(cntRow?.c || 0, 10);
    } catch { /* ignore */ }

    // Behavior tags
    const behaviorTags = [];
    if (scanCount >= 10)          behaviorTags.push('power_user');
    if (scanCount >= 3)           behaviorTags.push('returning');
    if (purchases.length >= 2)    behaviorTags.push('multi_buyer');
    if (purchases.length >= 1)    behaviorTags.push('paid_user');
    if (lastScan?.risk_score >= 70) behaviorTags.push('high_risk_history');

    return {
      last_scan:    lastScan ? {
        module:     lastScan.module,
        target:     lastScan.target,
        risk_score: lastScan.risk_score,
        date:       lastScan.created_at,
      } : null,
      purchases:    purchases.map(p => ({ product: p.product_id, amount: p.amount_inr, date: p.activated_at })),
      scan_count:   scanCount,
      top_module:   topModule,
      behavior_tags: behaviorTags,
      is_returning: scanCount >= 2,
    };
  } catch {
    return empty;
  }
}

/**
 * Determine UI blocks based on context + user memory
 * Returns array of block ids to render — frontend maps these to components
 */
function resolveUIBlocks(ctx) {
  const blocks = [];
  const { risk_level, tier, user_memory, enterprise_flag, module, bundle_offer, upsell } = ctx;

  // Always show scan summary
  blocks.push('scan_summary');

  // Risk-driven blocks
  if (risk_level === 'CRITICAL' || risk_level === 'HIGH') {
    blocks.push('risk_alert_banner');
    blocks.push('remediation_steps');
  }

  // Training recommendation — always useful
  blocks.push('training_banner');

  // Bundle offer if relevant
  if (bundle_offer) blocks.push('bundle_offer');

  // Upsell — only for FREE tier
  if (upsell?.show && tier === 'FREE') blocks.push('upsell_cta');

  // Enterprise block — high risk or critical findings
  if (enterprise_flag) blocks.push('enterprise_cta');

  // Return-user offer: different messaging
  if (user_memory?.is_returning) blocks.push('return_user_offer');

  // Multi-buyer: loyalty block
  if (user_memory?.behavior_tags?.includes('multi_buyer')) blocks.push('loyalty_reward');

  // Power user: advanced tools panel
  if (user_memory?.behavior_tags?.includes('power_user')) blocks.push('advanced_tools_panel');

  return [...new Set(blocks)]; // deduplicate
}

/**
 * Personalization bar message driven by user memory
 */
function buildPersonalizationBar(user_memory, module, risk_level) {
  if (!user_memory) return null;

  if (user_memory.behavior_tags?.includes('multi_buyer')) {
    return { icon: '🏆', title: 'Welcome back, valued member!', subtitle: `Your loyalty unlocks priority support. Today's scan: ${module.toUpperCase()} module.` };
  }
  if (user_memory.is_returning && user_memory.last_scan) {
    const lastRisk = user_memory.last_scan.risk_score >= 70 ? 'HIGH risk' : 'MEDIUM risk';
    return { icon: '🔄', title: 'Welcome back!', subtitle: `Your last scan (${user_memory.last_scan.target}) had ${lastRisk}. Let's track your improvement.` };
  }
  if (risk_level === 'CRITICAL' || risk_level === 'HIGH') {
    return { icon: '🚨', title: 'Critical risks detected!', subtitle: 'Your security posture needs immediate attention. See remediation below.' };
  }
  return { icon: '🛡️', title: 'Security scan complete', subtitle: `${module.toUpperCase()} module analysis ready. Review findings below.` };
}

/**
 * Return-user specific offer (different from standard upsell)
 */
function buildReturnUserOffer(user_memory, module, tier) {
  if (!user_memory?.is_returning || tier !== 'FREE') return null;

  const scan_count = user_memory.scan_count || 0;
  if (scan_count >= 5) {
    return {
      show: true,
      type: 'loyalty_upgrade',
      headline: `You've run ${scan_count} scans — you're serious about security!`,
      offer_text: 'Upgrade to Pro and get unlimited scans + full history dashboard.',
      cta_text: 'Upgrade to Pro — ₹1,499/mo',
      cta_action: "CDB_PAY.open('PRO',1499,'Pro Plan')",
      urgency: 'medium',
      discount_label: 'Special rate for returning users',
    };
  }
  if (scan_count >= 2) {
    return {
      show: true,
      type: 'starter_nudge',
      headline: 'Back for more security intel?',
      offer_text: 'Starter Plan gives you 50 scans/month + full PDF reports.',
      cta_text: 'Get Starter Plan — ₹499/mo',
      cta_action: "CDB_PAY.open('STARTER',499,'Starter Plan')",
      urgency: 'low',
    };
  }
  return null;
}

/**
 * POST /mcp/control — THE UNIFIED CONTROL ENGINE
 *
 * Input:
 *   { module, target, risk_score, tier, findings, locked_count,
 *     scan_id, page_context, user_email }
 *
 * Output:
 *   {
 *     risk_level, primary_action, recommended_tools, recommended_training,
 *     bundle_offer, cta, urgency, enterprise_flag, ui_blocks,
 *     upsell, remediation_steps, personalization_bar, return_user_offer,
 *     user_context, source, version, generated_at
 *   }
 *
 * FAILSAFE: ANY error falls back to /mcp/decision logic — NEVER crashes
 */
export async function handleMCPControl(request, env, authCtx = {}) {
  const startMs = Date.now();

  // ── Parse + sanitize input ─────────────────────────────────────────────────
  let body = {};
  try { body = await request.json(); } catch { /* empty body ok */ }

  const module       = VALID_MODULES.includes(body.module) ? body.module : 'domain';
  const risk_score   = clampScore(body.risk_score, 0, 100);
  const tier         = VALID_TIERS.includes((body.tier || '').toUpperCase())
    ? body.tier.toUpperCase() : 'FREE';
  const target       = sanitizeStr(body.target || '', 120);
  const findings     = Array.isArray(body.findings)
    ? body.findings.slice(0, 20).map(sanitizeFinding).filter(Boolean) : [];
  const locked_count = Math.max(0, parseInt(body.locked_count || 0, 10) || 0);
  const page_context = sanitizeStr(body.page_context || 'scan_result', 60);
  const user_email   = sanitizeStr(body.user_email || authCtx?.email || '', 120);
  const user_id      = authCtx?.userId || authCtx?.user_id || null;

  // ── KV Cache: check for cached decision (same context fingerprint) ─────────
  const cacheKey = `mcp:ctrl:${module}:${Math.round(risk_score/10)*10}:${tier}:${locked_count > 0 ? 'locked' : 'open'}`;
  if (env?.SECURITY_HUB_KV && !user_id) {
    // Only cache for anonymous — logged-in users get personalized decisions
    try {
      const cached = await env.SECURITY_HUB_KV.get(cacheKey, 'json');
      if (cached) {
        return new Response(JSON.stringify({
          success: true,
          data: { ...cached, cache_hit: true, latency_ms: Date.now() - startMs },
          error: null,
          ts: new Date().toISOString(),
        }), { headers: { 'Content-Type': 'application/json', 'X-MCP-Cache': 'HIT' } });
      }
    } catch { /* cache miss — continue */ }
  }

  // ── Rate limiting via KV ───────────────────────────────────────────────────
  const ip = authCtx?.ip || 'anon';
  if (env?.SECURITY_HUB_KV) {
    try {
      const rlKey = `mcp:ctrl:rl:${ip}`;
      const count = parseInt(await env.SECURITY_HUB_KV.get(rlKey).catch(() => '0') || '0', 10);
      if (count >= 60) {
        return new Response(JSON.stringify({ success: false, error: 'Rate limit exceeded', data: null }), {
          status: 429, headers: { 'Content-Type': 'application/json' },
        });
      }
      env.SECURITY_HUB_KV.put(rlKey, String(count + 1), { expirationTtl: 60 }).catch(() => {});
    } catch { /* ignore rate limit errors */ }
  }

  try {
    // ── Phase 1: Try external MCP server (shadow mode) ─────────────────────
    const mcpPayload = { module, target, risk_score, tier, findings: findings.slice(0,10), locked_count, page_context };
    let externalResult = null;
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), MCP_TIMEOUT_MS);
      const mcpRes = await fetch(`${MCP_BASE_URL}/control`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${env?.MCP_API_KEY || ''}`,
          'X-Platform': 'CYBERDUDEBIVASH-AI-HUB',
          'X-Version': MCP_CONTROL_VERSION,
        },
        body: JSON.stringify(mcpPayload),
        signal: ctrl.signal,
      });
      clearTimeout(timer);
      if (mcpRes.ok) {
        const mcpData = await mcpRes.json();
        externalResult = mcpData?.data || mcpData || null;
      }
    } catch { /* external MCP offline — fallback */ }

    // ── Phase 4: Load user memory from D1 ─────────────────────────────────
    const user_memory = await loadUserMemory(env, user_id, user_email);

    // ── Phase 1 (local fallback): Build full decision ──────────────────────
    const recommended_tools    = externalResult?.recommended_tools
      || TOOL_RECOMMENDATIONS[module] || TOOL_RECOMMENDATIONS['domain'];
    const recommended_training = externalResult?.recommended_training
      || TRAINING_INDEX[module] || TRAINING_INDEX['domain'];
    const remediation_steps    = externalResult?.remediation_steps
      || generateRemediationSteps(module, risk_score, findings);
    const learning_path        = externalResult?.learning_path
      || generateLearningPath(module, risk_score);

    // Risk level
    const risk_level = risk_score >= 80 ? 'CRITICAL'
      : risk_score >= 60 ? 'HIGH'
      : risk_score >= 40 ? 'MEDIUM' : 'LOW';

    // Enterprise flag: high risk OR 3+ critical findings
    const critical_count   = findings.filter(f => f.severity === 'CRITICAL').length;
    const enterprise_flag  = risk_score >= 85 || critical_count >= 3;

    // Upsell decision
    const upsell = evaluateUpsell({ module, risk_score, locked_count, tier });

    // Bundle decision
    const bundleCtx = { module, risk_score, tier };
    const bundle_offer = (() => {
      const ranked = BUNDLE_CATALOG
        .filter(b => !b.enterprise_only || tier === 'ENTERPRISE')
        .map(b => ({ ...b, relevance: b.best_for.includes(module) ? 2 : 1 }))
        .sort((a, z) => z.relevance - a.relevance);
      const best = ranked[0];
      if (!best || risk_score < 30) return null;  // only show if some risk exists
      const hour = new Date().getHours();
      return {
        ...best,
        countdown_iso:  new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
        urgency:        risk_score >= 70 ? 'CRITICAL' : 'HIGH',
        social_proof: {
          units_sold_today: 847 + (hour * 3),
          viewing_now:      12 + (hour % 7),
          label:            `${12 + (hour % 7)} people viewing this offer right now`,
        },
        cta_text:   `Get ${best.name} — ₹${best.bundle_price} (Save ${best.discount_pct}%)`,
        cta_action: `CDB_PAY.open('${best.id}',${best.bundle_price},'${best.name}')`,
      };
    })();

    // Primary action: most important thing user should do
    let primary_action = 'review_findings';
    let cta            = null;
    let urgency        = 'low';

    if (risk_level === 'CRITICAL') {
      primary_action = 'immediate_remediation';
      cta = enterprise_flag
        ? 'Book Emergency Security Assessment — Free consultation'
        : `Fix critical vulnerabilities NOW — Upgrade to Pro for full roadmap`;
      urgency = 'critical';
    } else if (risk_level === 'HIGH') {
      primary_action = 'upgrade_and_remediate';
      cta = upsell?.show ? upsell.cta_text : `Get full remediation roadmap — ₹199`;
      urgency = 'high';
    } else if (risk_level === 'MEDIUM') {
      primary_action = 'learn_and_improve';
      cta = recommended_training[0] ? `Learn to fix this: ${recommended_training[0].name}` : 'Explore security training';
      urgency = 'medium';
    } else {
      primary_action = 'maintain_posture';
      cta = 'Keep monitoring — set up continuous scan alerts';
      urgency = 'low';
    }

    // Adjust CTA for return users with purchases
    if (user_memory.behavior_tags?.includes('paid_user') && tier === 'FREE') {
      cta = `Welcome back! Reactivate your plan for continued protection`;
    }

    // ── Phase 4: Return-user specific offer ───────────────────────────────
    const return_user_offer = buildReturnUserOffer(user_memory, module, tier);

    // ── Phase 5: Personalization bar ──────────────────────────────────────
    const personalization_bar = buildPersonalizationBar(user_memory, module, risk_level);

    // ── Phase 5: UI Blocks ────────────────────────────────────────────────
    const ui_blocks = resolveUIBlocks({
      risk_level, tier, user_memory, enterprise_flag, module, bundle_offer, upsell,
    });

    // ── Build final response ───────────────────────────────────────────────
    const result = {
      // Core decision
      risk_level,
      primary_action,
      recommended_tools:    recommended_tools.slice(0, 3),
      recommended_training: recommended_training.slice(0, 2),
      bundle_offer,
      cta,
      urgency,
      enterprise_flag,
      enterprise_cta: enterprise_flag ? 'Book Enterprise Demo — Free security assessment' : null,

      // UI system
      ui_blocks,
      personalization_bar,

      // User state
      return_user_offer,
      upsell: upsell.show ? upsell : null,
      remediation_steps: remediation_steps.slice(0, 5),
      learning_path,

      // Context echo (for frontend to store)
      user_context: {
        last_scan:     user_memory.last_scan,
        purchases:     user_memory.purchases.slice(0, 5),
        scan_count:    user_memory.scan_count,
        top_module:    user_memory.top_module,
        behavior_tags: user_memory.behavior_tags,
        is_returning:  user_memory.is_returning,
      },

      // Meta
      module, risk_score, tier, target,
      source:       externalResult ? 'mcp_server' : 'local_engine',
      version:      MCP_CONTROL_VERSION,
      latency_ms:   Date.now() - startMs,
      cache_hit:    false,
      generated_at: new Date().toISOString(),
    };

    // ── Phase 8: KV Cache for anonymous requests ───────────────────────────
    if (env?.SECURITY_HUB_KV && !user_id) {
      env.SECURITY_HUB_KV.put(cacheKey, JSON.stringify(result), { expirationTtl: MCP_CONTROL_CACHE_TTL }).catch(() => {});
    }

    return new Response(JSON.stringify({ success: true, data: result, error: null, ts: new Date().toISOString() }), {
      headers: { 'Content-Type': 'application/json', 'X-MCP-Cache': 'MISS', 'X-MCP-Version': MCP_CONTROL_VERSION },
    });

  } catch (err) {
    // ── Phase 7: FAILSAFE — fallback to /mcp/decision ─────────────────────
    console.error('[MCP Control] Failsafe activated:', err.message);
    try {
      // Re-create a minimal safe request and delegate to existing /mcp/decision
      const fallbackBody = JSON.stringify({ module, target, risk_score, tier, findings, locked_count });
      const fallbackReq  = new Request(request.url, { method: 'POST', body: fallbackBody, headers: { 'Content-Type': 'application/json' } });
      const fallback     = await handleMCPDecision(fallbackReq, env, authCtx);
      // Wrap fallback result in control format
      const fb = await fallback.json();
      return new Response(JSON.stringify({
        success: true,
        data: {
          ...(fb?.data || fb),
          ui_blocks:          ['scan_summary', 'training_banner', 'upsell_cta'],
          personalization_bar: null,
          return_user_offer:  null,
          user_context:       { last_scan: null, purchases: [], scan_count: 0, behavior_tags: [], is_returning: false },
          source:             'failsafe_fallback',
          version:            MCP_CONTROL_VERSION,
          latency_ms:         Date.now() - startMs,
        },
        error: null,
        ts: new Date().toISOString(),
      }), { headers: { 'Content-Type': 'application/json', 'X-MCP-Failsafe': '1' } });
    } catch (fallbackErr) {
      // Absolute last resort — static minimal response that NEVER crashes UI
      return new Response(JSON.stringify({
        success: true,
        data: {
          risk_level: 'MEDIUM', primary_action: 'review_findings',
          recommended_tools: [], recommended_training: [],
          bundle_offer: null, cta: 'View your scan results below',
          urgency: 'medium', enterprise_flag: false, enterprise_cta: null,
          ui_blocks: ['scan_summary'],
          personalization_bar: null, return_user_offer: null, upsell: null,
          remediation_steps: [], learning_path: [],
          user_context: { last_scan: null, purchases: [], scan_count: 0, behavior_tags: [], is_returning: false },
          source: 'emergency_fallback', version: MCP_CONTROL_VERSION,
          latency_ms: Date.now() - startMs,
        },
        error: null, ts: new Date().toISOString(),
      }), { headers: { 'Content-Type': 'application/json', 'X-MCP-Emergency': '1' } });
    }
  }
}
