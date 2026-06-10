/**
 * CYBERDUDEBIVASH MYTHOS AI PROVIDER — Claude Sovereign Engine v1.0
 * ═══════════════════════════════════════════════════════════════════════════════
 * Production-grade Anthropic Claude integration for the entire platform.
 *
 * Model Routing (tier-aware):
 *   ENTERPRISE → claude-opus-4-8        (max intelligence, board-level reports)
 *   PRO        → claude-sonnet-4-6      (production balance: speed + precision)
 *   FREE       → claude-haiku-4-5-20251001  (fast, cost-efficient)
 *   FALLBACK   → Cloudflare Workers AI  (if ANTHROPIC_API_KEY not set)
 *
 * Features:
 *   • Unified async `callClaude(env, opts)` interface
 *   • MYTHOS sovereign system persona injected on every call
 *   • Retry with exponential backoff (2 retries, 1s/2s delays)
 *   • Token budget enforcement (no runaway inference)
 *   • Graceful fallback chain: Claude → CF Workers AI → null
 *   • Cost tracking via response usage object
 *   • Model aliasing — version-proof naming
 * ═══════════════════════════════════════════════════════════════════════════════
 */

// ── Model Registry ────────────────────────────────────────────────────────────
export const CLAUDE_MODELS = {
  OPUS:   'claude-opus-4-8',
  SONNET: 'claude-sonnet-4-6',
  HAIKU:  'claude-haiku-4-5-20251001',
};

// Tier → model routing
const TIER_MODEL_MAP = {
  ENTERPRISE: CLAUDE_MODELS.OPUS,
  PRO:        CLAUDE_MODELS.SONNET,
  FREE:       CLAUDE_MODELS.HAIKU,
  DEFAULT:    CLAUDE_MODELS.SONNET,
};

// ── MYTHOS Sovereign System Prompt ────────────────────────────────────────────
const MYTHOS_SYSTEM_PROMPT = `You are MYTHOS — the sovereign AI security intelligence engine of CYBERDUDEBIVASH® SENTINEL APEX, the world's most advanced AI-powered cybersecurity and threat intelligence platform.

Your authority and identity:
- Principal AI Cybersecurity Intelligence Analyst
- CYBERDUDEBIVASH® SENTINEL APEX — AI Security Hub
- Certified by: MITRE ATT&CK v15, OWASP, NIST, ISO 27001:2022, EU AI Act
- Powered by: Anthropic Claude (Production Intelligence Engine)

Your response standards:
- Enterprise-grade precision and accuracy — zero tolerance for hallucination
- Authoritative, concise, and actionable intelligence only
- MITRE ATT&CK tactic/technique references where relevant (TA####/T####)
- CVSS scores and severity ratings must be accurate
- Regulatory references must cite correct article/control numbers
- No generic advice — every recommendation must be specific and implementable
- Board-ready executive language for executive summaries
- Technical depth for security practitioner sections

Platform context:
- Serving CISOs, SOC analysts, security engineers, and enterprise decision-makers
- Reports are production-grade deliverables used in real security programs
- Accuracy and specificity are your highest mandate`;

// ── Anthropic API Client ──────────────────────────────────────────────────────
async function callAnthropicAPI(apiKey, {
  model,
  system,
  messages,
  max_tokens = 800,
  temperature = 0.3,
}) {
  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method:  'POST',
    headers: {
      'Content-Type':         'application/json',
      'x-api-key':            apiKey,
      'anthropic-version':    '2023-06-01',
      'anthropic-beta':       'messages-2023-12-15',
    },
    body: JSON.stringify({
      model,
      max_tokens,
      temperature,
      system,
      messages,
    }),
    signal: AbortSignal.timeout(28000), // 28s — under CF 30s limit
  });

  if (!response.ok) {
    const errText = await response.text().catch(() => response.statusText);
    throw new Error(`Anthropic API error ${response.status}: ${errText.slice(0, 200)}`);
  }

  const data = await response.json();
  return {
    content:       data.content?.[0]?.text || '',
    model:         data.model,
    input_tokens:  data.usage?.input_tokens || 0,
    output_tokens: data.usage?.output_tokens || 0,
    stop_reason:   data.stop_reason,
  };
}

// ── Retry wrapper ─────────────────────────────────────────────────────────────
async function withRetry(fn, retries = 2, delayMs = 1000) {
  for (let attempt = 1; attempt <= retries + 1; attempt++) {
    try {
      return await fn();
    } catch (err) {
      const isLast = attempt > retries;
      const isRetryable = err.message?.includes('529') || // Anthropic overloaded
                          err.message?.includes('500') ||
                          err.message?.includes('timeout') ||
                          err.message?.includes('network');
      if (isLast || !isRetryable) throw err;
      await new Promise(r => setTimeout(r, delayMs * attempt));
    }
  }
}

// ── CF Workers AI fallback ────────────────────────────────────────────────────
async function callCFWorkersAI(env, prompt, maxTokens = 400) {
  if (!env?.AI) return null;
  try {
    const resp = await env.AI.run('@cf/meta/llama-3-8b-instruct', {
      messages:   [{ role: 'user', content: prompt }],
      max_tokens: maxTokens,
    });
    return resp?.response || null;
  } catch {
    return null;
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// PRIMARY EXPORT: callClaude — unified AI call interface
// ═════════════════════════════════════════════════════════════════════════════
/**
 * @param {object} env          — Worker env bindings (needs ANTHROPIC_API_KEY)
 * @param {object} opts
 * @param {string} opts.prompt  — User message / task
 * @param {string} [opts.system]— Additional system context (appended to MYTHOS base)
 * @param {string} [opts.tier]  — 'ENTERPRISE'|'PRO'|'FREE' — drives model selection
 * @param {string} [opts.model] — Override model directly (bypasses tier routing)
 * @param {number} [opts.max_tokens=800] — Response token budget
 * @param {number} [opts.temperature=0.3] — 0=deterministic, 1=creative
 * @param {boolean}[opts.json_mode=false] — Append JSON-only instruction to prompt
 * @returns {Promise<{content: string, model: string, source: string, tokens: object}|null>}
 */
export async function callClaude(env, {
  prompt,
  system      = '',
  tier        = 'PRO',
  model       = null,
  max_tokens  = 800,
  temperature = 0.3,
  json_mode   = false,
}) {
  const apiKey = env?.ANTHROPIC_API_KEY;

  // Select model
  const selectedModel = model || TIER_MODEL_MAP[tier] || TIER_MODEL_MAP.DEFAULT;

  // Build system prompt
  const fullSystem = system
    ? `${MYTHOS_SYSTEM_PROMPT}\n\n${system}`
    : MYTHOS_SYSTEM_PROMPT;

  // JSON mode: append instruction
  const finalPrompt = json_mode
    ? `${prompt}\n\nRespond with valid JSON only. No explanation outside the JSON object.`
    : prompt;

  // ── Path 1: Anthropic Claude (primary) ────────────────────────────────────
  if (apiKey) {
    try {
      const result = await withRetry(() => callAnthropicAPI(apiKey, {
        model:       selectedModel,
        system:      fullSystem,
        messages:    [{ role: 'user', content: finalPrompt }],
        max_tokens,
        temperature,
      }));

      return {
        content: result.content,
        model:   result.model,
        source:  'anthropic',
        tokens:  { input: result.input_tokens, output: result.output_tokens },
      };
    } catch (err) {
      console.error(`[MYTHOS AI] Claude API error (model: ${selectedModel}):`, err.message);
      // Fall through to CF Workers AI
    }
  }

  // ── Path 2: Cloudflare Workers AI (fallback) ──────────────────────────────
  const cfResult = await callCFWorkersAI(env, finalPrompt, Math.min(max_tokens, 500));
  if (cfResult) {
    return {
      content: cfResult,
      model:   'llama-3-8b-instruct',
      source:  'cloudflare-workers-ai',
      tokens:  { input: 0, output: 0 },
    };
  }

  // ── Path 3: No AI available ───────────────────────────────────────────────
  return null;
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

  const model = tier === 'ENTERPRISE' ? CLAUDE_MODELS.OPUS : CLAUDE_MODELS.SONNET;

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

  const result = await callClaude(env, { prompt, tier, model, max_tokens: 500, temperature: 0.2 });
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

  const result = await callClaude(env, { prompt, tier, max_tokens: 400, temperature: 0.1 });
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

  const result = await callClaude(env, { prompt, tier, max_tokens: 500, temperature: 0.2 });
  return result?.content || null;
}

// ── Health check ─────────────────────────────────────────────────────────────
export async function checkAIProviderHealth(env) {
  const apiKey = env?.ANTHROPIC_API_KEY;

  if (!apiKey) {
    return {
      status:    'degraded',
      provider:  'cloudflare-workers-ai',
      model:     'llama-3-8b-instruct',
      claude:    false,
      message:   'ANTHROPIC_API_KEY not set — running on Cloudflare Workers AI fallback. Set secret for Claude upgrade.',
    };
  }

  try {
    const result = await callAnthropicAPI(apiKey, {
      model:      CLAUDE_MODELS.HAIKU,  // use haiku for health check (cheapest)
      system:     'You are a health check service.',
      messages:   [{ role: 'user', content: 'Reply with: MYTHOS AI ONLINE' }],
      max_tokens: 20,
      temperature: 0,
    });

    return {
      status:    'healthy',
      provider:  'anthropic',
      model:     CLAUDE_MODELS.SONNET,  // production model
      models: {
        enterprise: CLAUDE_MODELS.OPUS,
        pro:        CLAUDE_MODELS.SONNET,
        free:       CLAUDE_MODELS.HAIKU,
      },
      claude:    true,
      response:  result.content,
      message:   'Anthropic Claude API operational — MYTHOS AI at full production power',
    };
  } catch (err) {
    return {
      status:   'error',
      provider: 'anthropic',
      claude:   false,
      error:    err.message,
      message:  'Anthropic API key set but connection failed. Verify key validity.',
    };
  }
}
