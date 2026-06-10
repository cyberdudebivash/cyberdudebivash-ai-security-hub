/**
 * CYBERDUDEBIVASH MYTHOS AI PROVIDER — Multi-Provider Sovereign Engine v2.0
 * ════════════════════════════════════════════════════════════════════════════
 * Thin compatibility shim — delegates to AIProviderRouter.
 * All existing callClaude() callers work unchanged.
 *
 * Provider chain (no vendor lock-in):
 *   Groq → DeepSeek → Cloudflare Workers AI → OpenRouter → Anthropic (optional)
 *
 * Env secrets (add any combination — platform works with whatever is set):
 *   GROQ_API_KEY        — Groq Cloud (recommended free tier)
 *   DEEPSEEK_API_KEY    — DeepSeek (ultra-cheap technical reasoning)
 *   OPENROUTER_API_KEY  — OpenRouter meta-provider (50+ models)
 *   ANTHROPIC_API_KEY   — Anthropic Claude (optional premium tier)
 *   env.AI              — CF Workers AI binding (always available, no key needed)
 * ════════════════════════════════════════════════════════════════════════════
 */

import {
  callViaRouter,
  routeAICall,
  getProviderHealthStatus,
  PROVIDERS,
} from './aiProviderRouter.js';

// ── Model registry (kept for backward compat — callers that pass model= opt) ──
export const CLAUDE_MODELS = {
  OPUS:   'claude-opus-4-8',
  SONNET: 'claude-sonnet-4-6',
  HAIKU:  'claude-haiku-4-5-20251001',
};

// ════════════════════════════════════════════════════════════════════════════
// PRIMARY EXPORT: callClaude — unchanged interface, now router-backed
// ════════════════════════════════════════════════════════════════════════════
/**
 * @param {object} env          — Worker env bindings
 * @param {object} opts
 * @param {string} opts.prompt  — User message / task
 * @param {string} [opts.system]— Additional system context
 * @param {string} [opts.tier]  — 'ENTERPRISE'|'PRO'|'FREE'
 * @param {string} [opts.model] — Ignored by router (kept for caller compat)
 * @param {number} [opts.max_tokens=800]
 * @param {number} [opts.temperature=0.3]
 * @param {boolean}[opts.json_mode=false]
 * @param {string} [opts.task_type] — Optional routing hint
 * @returns {Promise<{content,model,source,provider,tokens}|null>}
 */
export async function callClaude(env, opts) {
  return callViaRouter(env, opts);
}

// ── Convenience: generate executive narrative ─────────────────────────────────
export async function generateExecutiveNarrative(env, {
  target,
  service_name,
  riskScore,
  riskLevel,
  findings = [],
  sector   = 'Technology',
  tier     = 'PRO',
  extra_context = '',
}) {
  const topFindings = findings
    .filter(f => ['CRITICAL','HIGH'].includes(f.severity))
    .slice(0, 6)
    .map(f => `• [${f.severity}] ${f.title || f.id}: ${(f.description || '').slice(0, 120)}`)
    .join('\n');

  const prompt = `Generate a 3-paragraph enterprise security intelligence brief for:

Target: ${target || 'the assessed system'}
Service: ${service_name}
Risk Score: ${riskScore}/100 (${riskLevel})
Industry: ${sector}
${extra_context ? `Context: ${extra_context}` : ''}

Key findings:
${topFindings || '• Assessment complete — findings prioritized below'}

Requirements:
Paragraph 1: Executive threat posture summary — specific risk level, business exposure, and immediate urgency (2-3 sentences)
Paragraph 2: Top 3 critical actions with explicit business impact — what breaks if ignored (2-3 sentences each)
Paragraph 3: Strategic 90-day security roadmap with measurable milestones (3-4 sentences)

Standards: Enterprise-grade precision. MITRE ATT&CK references where applicable. No generic advice.`;

  const result = await routeAICall(env, {
    prompt,
    task_type:   'executive',
    tier,
    max_tokens:  500,
    temperature: 0.2,
  });
  return result?.content || null;
}

// ── Convenience: AI threat actor attribution ──────────────────────────────────
export async function generateThreatAttribution(env, {
  findings = [],
  sector   = 'Technology',
  tier     = 'PRO',
}) {
  if (findings.length === 0) return null;

  const prompt = `Based on these security findings in the ${sector} sector:
${findings.slice(0, 5).map(f => `• ${f.title}: ${(f.description||'').slice(0,80)}`).join('\n')}

Identify the top 2-3 most likely threat actors or attack campaigns relevant to these findings. For each provide:
- Threat actor name/group
- Origin/attribution (if known)
- Relevant TTPs matching these findings (MITRE ATT&CK IDs)
- Likelihood score (1-10)

Be specific and evidence-based. Reference CISA advisories or known campaigns where applicable.`;

  const result = await routeAICall(env, {
    prompt,
    task_type:   'threat_intel',
    tier,
    max_tokens:  400,
    temperature: 0.1,
  });
  return result?.content || null;
}

// ── Convenience: autonomous remediation narrative ─────────────────────────────
export async function generateRemediationNarrative(env, {
  findings = [],
  riskScore,
  org = 'the organization',
  tier = 'PRO',
}) {
  if (findings.length === 0) return null;

  const critHigh = findings.filter(f => ['CRITICAL','HIGH'].includes(f.severity)).slice(0, 5);
  const prompt = `For ${org} with risk score ${riskScore}/100, provide a structured remediation narrative for these ${critHigh.length} critical/high findings:

${critHigh.map((f, i) => `${i+1}. [${f.severity}] ${f.title}\n   Remediation hint: ${(f.remediation||'').slice(0,100)}`).join('\n')}

Provide:
1. Immediate actions (this week) — specific, executable steps
2. Short-term program (30 days) — process and tooling changes
3. Success metrics — how to measure improvement

Be concise and actionable. Format for a CISO presentation.`;

  const result = await routeAICall(env, {
    prompt,
    task_type:   'executive',
    tier,
    max_tokens:  500,
    temperature: 0.2,
  });
  return result?.content || null;
}

// ── Health check (used by GET /api/ai/health) ─────────────────────────────────
export async function checkAIProviderHealth(env) {
  // Import the router's compat health check
  const { checkAIProviderHealth: routerHealthCheck } = await import('./aiProviderRouter.js');
  return routerHealthCheck(env);
}
