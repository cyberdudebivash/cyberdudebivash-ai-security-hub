/**
 * CYBERDUDEBIVASH® AI Security Hub
 * AI Provider Router — Multi-Provider Failover Engine
 *
 * Provider priority:
 *   1. Groq      (free tier, 60 RPM, fast inference)
 *   2. DeepSeek  (cost-optimised)
 *   3. Cloudflare Workers AI (env.AI binding — always available at edge)
 *   4. OpenRouter (aggregator, many models)
 *   5. Anthropic  (optional premium — not required)
 *
 * Zero single-provider dependency. Platform stays operational
 * even if every paid provider is removed.
 */

const GROQ_ENDPOINT       = 'https://api.groq.com/openai/v1/chat/completions';
const DEEPSEEK_ENDPOINT   = 'https://api.deepseek.com/v1/chat/completions';
const OPENROUTER_ENDPOINT = 'https://openrouter.ai/api/v1/chat/completions';
const ANTHROPIC_ENDPOINT  = 'https://api.anthropic.com/v1/messages';

// Models optimised for cybersecurity narrative generation
const GROQ_MODEL       = 'llama3-8b-8192';
const DEEPSEEK_MODEL   = 'deepseek-chat';
const OPENROUTER_MODEL = 'meta-llama/llama-3-8b-instruct:free';
const ANTHROPIC_MODEL  = 'claude-haiku-4-5-20251001';
const CF_AI_MODEL      = '@cf/meta/llama-3.1-8b-instruct';

// ─── Unified request builder ──────────────────────────────────────────────────

function buildOpenAIPayload(systemPrompt, userPrompt, maxTokens = 1024) {
  return {
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user',   content: userPrompt   },
    ],
    max_tokens:  maxTokens,
    temperature: 0.3,
    stream:      false,
  };
}

// ─── Provider call functions ──────────────────────────────────────────────────

async function callGroq(env, systemPrompt, userPrompt, maxTokens) {
  if (!env.GROQ_API_KEY) throw new Error('GROQ_API_KEY not configured');
  const resp = await fetch(GROQ_ENDPOINT, {
    method:  'POST',
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${env.GROQ_API_KEY}`,
    },
    body: JSON.stringify({ ...buildOpenAIPayload(systemPrompt, userPrompt, maxTokens), model: GROQ_MODEL }),
  });
  if (!resp.ok) throw new Error(`Groq HTTP ${resp.status}`);
  const data = await resp.json();
  return data.choices?.[0]?.message?.content?.trim() || null;
}

async function callDeepSeek(env, systemPrompt, userPrompt, maxTokens) {
  if (!env.DEEPSEEK_API_KEY) throw new Error('DEEPSEEK_API_KEY not configured');
  const resp = await fetch(DEEPSEEK_ENDPOINT, {
    method:  'POST',
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${env.DEEPSEEK_API_KEY}`,
    },
    body: JSON.stringify({ ...buildOpenAIPayload(systemPrompt, userPrompt, maxTokens), model: DEEPSEEK_MODEL }),
  });
  if (!resp.ok) throw new Error(`DeepSeek HTTP ${resp.status}`);
  const data = await resp.json();
  return data.choices?.[0]?.message?.content?.trim() || null;
}

async function callCFWorkersAI(env, systemPrompt, userPrompt, maxTokens) {
  if (!env.AI) throw new Error('Cloudflare Workers AI binding (env.AI) not available');
  const response = await env.AI.run(CF_AI_MODEL, {
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user',   content: userPrompt   },
    ],
    max_tokens: maxTokens,
  });
  const text = response?.response || response?.result?.response || null;
  if (!text) throw new Error('CF Workers AI returned empty response');
  return text.trim();
}

async function callOpenRouter(env, systemPrompt, userPrompt, maxTokens) {
  if (!env.OPENROUTER_API_KEY) throw new Error('OPENROUTER_API_KEY not configured');
  const resp = await fetch(OPENROUTER_ENDPOINT, {
    method:  'POST',
    headers: {
      'Content-Type':   'application/json',
      'Authorization':  `Bearer ${env.OPENROUTER_API_KEY}`,
      'HTTP-Referer':   'https://cyberdudebivash.in',
      'X-Title':        'CyberDudeBivash AI Security Hub',
    },
    body: JSON.stringify({ ...buildOpenAIPayload(systemPrompt, userPrompt, maxTokens), model: OPENROUTER_MODEL }),
  });
  if (!resp.ok) throw new Error(`OpenRouter HTTP ${resp.status}`);
  const data = await resp.json();
  return data.choices?.[0]?.message?.content?.trim() || null;
}

async function callAnthropic(env, systemPrompt, userPrompt, maxTokens) {
  if (!env.ANTHROPIC_API_KEY) throw new Error('ANTHROPIC_API_KEY not configured');
  const resp = await fetch(ANTHROPIC_ENDPOINT, {
    method:  'POST',
    headers: {
      'Content-Type':      'application/json',
      'x-api-key':         env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model:      ANTHROPIC_MODEL,
      max_tokens: maxTokens,
      system:     systemPrompt,
      messages:   [{ role: 'user', content: userPrompt }],
    }),
  });
  if (!resp.ok) throw new Error(`Anthropic HTTP ${resp.status}`);
  const data = await resp.json();
  return data.content?.[0]?.text?.trim() || null;
}

// ─── Provider priority list (ordered: cheapest/fastest first) ─────────────────

function getProviderChain(env) {
  // Build ordered list of available providers at call time
  const chain = [];
  if (env.GROQ_API_KEY)        chain.push({ name: 'groq',        fn: callGroq        });
  if (env.DEEPSEEK_API_KEY)    chain.push({ name: 'deepseek',    fn: callDeepSeek    });
  if (env.AI)                  chain.push({ name: 'cloudflare',  fn: callCFWorkersAI });
  if (env.OPENROUTER_API_KEY)  chain.push({ name: 'openrouter',  fn: callOpenRouter  });
  if (env.ANTHROPIC_API_KEY)   chain.push({ name: 'anthropic',   fn: callAnthropic   });
  return chain;
}

// ─── Core router — tries providers in order, returns first success ─────────────

export async function generateWithAI(env, systemPrompt, userPrompt, options = {}) {
  const { maxTokens = 1024, taskType = 'general' } = options;
  const chain = getProviderChain(env);

  if (chain.length === 0) {
    // Graceful degradation: return a structured placeholder that does NOT
    // contain fake intelligence data — just signals AI unavailability
    return {
      success:   false,
      provider:  'none',
      narrative: null,
      error:     'No AI provider configured. Set GROQ_API_KEY (free) to enable AI narratives.',
    };
  }

  const errors = [];
  for (const provider of chain) {
    try {
      const startMs = Date.now();
      const text = await provider.fn(env, systemPrompt, userPrompt, maxTokens);
      if (text && text.length > 10) {
        return {
          success:      true,
          provider:     provider.name,
          narrative:    text,
          latency_ms:   Date.now() - startMs,
        };
      }
      errors.push(`${provider.name}: empty response`);
    } catch (err) {
      errors.push(`${provider.name}: ${err.message}`);
    }
  }

  return {
    success:   false,
    provider:  'failed',
    narrative: null,
    error:     `All providers failed: ${errors.join(' | ')}`,
  };
}

// ─── Specialised task generators ──────────────────────────────────────────────

export async function generateThreatNarrative(env, threatData) {
  const system = `You are a senior threat intelligence analyst at a cybersecurity firm.
Provide concise, technical, actionable threat narratives. No padding. No disclaimers.
Output plain text suitable for a security dashboard.`;

  const user = `Generate a 2-3 sentence threat intelligence narrative for:
Title: ${threatData.title}
Severity: ${threatData.severity}
CVE: ${threatData.cve_id || 'N/A'}
CVSS: ${threatData.cvss || 'N/A'}
Description: ${threatData.description || threatData.summary || ''}

Include: attack vector, affected systems, recommended immediate action.`;

  return generateWithAI(env, system, user, { maxTokens: 300, taskType: 'threat_intel' });
}

export async function generateExecutiveReport(env, reportData) {
  const system = `You are a CISO writing a board-level executive security summary.
Use precise language. Avoid technical jargon. Focus on business risk and recommended actions.
Format: 3 paragraphs — Current State, Key Risks, Recommended Actions.`;

  const user = `Generate an executive security summary for:
Period: ${reportData.period || 'Last 30 days'}
Overall Risk Score: ${reportData.risk_score || 'N/A'}/10
Critical Findings: ${reportData.critical_count || 0}
High Findings: ${reportData.high_count || 0}
Threats Detected: ${reportData.threats_detected || 0}
Compliance Status: ${reportData.compliance_pct || 'N/A'}%
Top Risk: ${reportData.top_risk || 'Not specified'}`;

  return generateWithAI(env, system, user, { maxTokens: 600, taskType: 'executive_report' });
}

export async function generateAIAssessment(env, assetData) {
  const system = `You are an AI security expert specialising in OWASP LLM Top 10 and NIST AI RMF.
Provide specific, actionable security assessments. Reference exact OWASP LLM codes (LLM01-LLM10).`;

  const user = `Assess the security posture of this AI asset:
Asset Name: ${assetData.name}
Type: ${assetData.asset_type}
Exposure Level: ${assetData.exposure_level}
Has Public Endpoint: ${assetData.has_endpoint ? 'Yes' : 'No'}
Risk Score: ${assetData.risk_score}/10

Identify top 2 OWASP LLM risks and one specific remediation action for each.`;

  return generateWithAI(env, system, user, { maxTokens: 400, taskType: 'ai_assessment' });
}

export async function generateGovernanceReport(env, frameworkData) {
  const system = `You are an AI governance expert specialising in NIST AI RMF, ISO 42001, and EU AI Act.
Write precise compliance gap analysis narratives for enterprise security teams.`;

  const user = `Generate a compliance narrative for:
Framework: ${frameworkData.framework}
Compliance Score: ${frameworkData.score}%
Grade: ${frameworkData.grade}
Gap Count: ${frameworkData.gaps || 0}
Key Failing Controls: ${(frameworkData.failing_controls || []).slice(0, 3).join(', ')}

2 sentences: current compliance state and top remediation priority.`;

  return generateWithAI(env, system, user, { maxTokens: 250, taskType: 'governance' });
}

export async function generateSOARRule(env, threatData) {
  const system = `You are a detection engineering expert. Generate detection rules in Sigma YAML format.
Rules must be syntactically valid. Include title, description, detection, and condition fields.`;

  const user = `Generate a Sigma detection rule for:
Threat: ${threatData.title}
CVE: ${threatData.cve_id || 'N/A'}
MITRE Technique: ${(threatData.mitre_ttps || ['T1190'])[0]}
Severity: ${threatData.severity}

Output ONLY the Sigma YAML rule, no additional commentary.`;

  return generateWithAI(env, system, user, { maxTokens: 500, taskType: 'soar_rule' });
}

// ─── Health check ─────────────────────────────────────────────────────────────

export async function getAIProviderHealth(env) {
  const providers = [
    { name: 'groq',       configured: !!env.GROQ_API_KEY,       tier: 'free',     priority: 1 },
    { name: 'deepseek',   configured: !!env.DEEPSEEK_API_KEY,   tier: 'low_cost', priority: 2 },
    { name: 'cloudflare', configured: !!env.AI,                  tier: 'free',     priority: 3 },
    { name: 'openrouter', configured: !!env.OPENROUTER_API_KEY, tier: 'low_cost', priority: 4 },
    { name: 'anthropic',  configured: !!env.ANTHROPIC_API_KEY,  tier: 'premium',  priority: 5 },
  ];

  const available = providers.filter(p => p.configured);
  const primary   = available[0] || null;

  return {
    status:           available.length > 0 ? 'healthy' : 'degraded',
    primary_provider: primary?.name || null,
    provider_count:   available.length,
    mythos_capable:   available.length > 0,
    providers,
    recommendation:   available.length === 0
      ? 'Set GROQ_API_KEY (free at console.groq.com) to enable AI narratives'
      : null,
  };
}
