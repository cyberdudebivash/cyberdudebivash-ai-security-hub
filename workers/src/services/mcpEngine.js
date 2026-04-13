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
