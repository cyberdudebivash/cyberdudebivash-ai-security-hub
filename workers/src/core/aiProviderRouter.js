/**
 * CYBERDUDEBIVASH MYTHOS — AI Provider Router v1.0
 * ════════════════════════════════════════════════════════════════════════════
 * Provider-agnostic, multi-model AI orchestration layer.
 * Zero vendor lock-in. No single point of AI failure.
 *
 * Priority chain (default):
 *   1. Groq          — fast, free tier generous (Llama 3.3 70B)
 *   2. DeepSeek      — ultra-cheap, strong technical reasoning
 *   3. Cloudflare AI — always-available, zero cost (Llama 3.1 8B)
 *   4. OpenRouter    — meta-provider fallback (many models)
 *   5. Anthropic     — optional premium tier (Claude)
 *
 * Task-type routing (cost optimized):
 *   threat_intel   → DeepSeek (best technical/CVE reasoning)
 *   executive      → Groq     (fast, clear prose)
 *   governance     → Groq     (structured, compliant)
 *   assessment     → CF AI    (fast, short outputs)
 *   enterprise     → Anthropic if available, else Groq
 *   general        → Groq → DeepSeek → CF AI
 *
 * All providers return the same normalized response shape:
 *   { content, model, source, provider, tokens: {input, output}, latency_ms }
 * ════════════════════════════════════════════════════════════════════════════
 */

// ── Provider configurations ───────────────────────────────────────────────────
export const PROVIDERS = {
  GROQ:        'groq',
  DEEPSEEK:    'deepseek',
  CF_AI:       'cloudflare-workers-ai',
  OPENROUTER:  'openrouter',
  ANTHROPIC:   'anthropic',
};

const PROVIDER_CONFIG = {
  [PROVIDERS.GROQ]: {
    endpoint:    'https://api.groq.com/openai/v1/chat/completions',
    envKey:      'GROQ_API_KEY',
    models: {
      default:     'llama-3.3-70b-versatile',
      fast:        'llama-3.1-8b-instant',
      enterprise:  'llama-3.3-70b-versatile',
    },
    max_tokens_cap: 4096,
    timeout_ms:     20000,
    cost_per_1k:    0.00, // generous free tier
  },
  [PROVIDERS.DEEPSEEK]: {
    endpoint:    'https://api.deepseek.com/chat/completions',
    envKey:      'DEEPSEEK_API_KEY',
    models: {
      default:     'deepseek-chat',
      fast:        'deepseek-chat',
      enterprise:  'deepseek-chat',
    },
    max_tokens_cap: 4096,
    timeout_ms:     25000,
    cost_per_1k:    0.00014, // $0.14/1M tokens
  },
  [PROVIDERS.CF_AI]: {
    endpoint:    null, // uses env.AI binding directly
    envKey:      null, // always available
    models: {
      default:     '@cf/meta/llama-3.1-8b-instruct',
      fast:        '@cf/meta/llama-3.1-8b-instruct',
      enterprise:  '@cf/meta/llama-3.1-8b-instruct',
    },
    max_tokens_cap: 512,
    timeout_ms:     15000,
    cost_per_1k:    0.00, // included in Workers plan
  },
  [PROVIDERS.OPENROUTER]: {
    endpoint:    'https://openrouter.ai/api/v1/chat/completions',
    envKey:      'OPENROUTER_API_KEY',
    models: {
      default:     'meta-llama/llama-3.3-70b-instruct',
      fast:        'meta-llama/llama-3.1-8b-instruct',
      enterprise:  'anthropic/claude-sonnet-4-6',
    },
    max_tokens_cap: 2048,
    timeout_ms:     25000,
    cost_per_1k:    0.00072,
  },
  [PROVIDERS.ANTHROPIC]: {
    endpoint:    'https://api.anthropic.com/v1/messages',
    envKey:      'ANTHROPIC_API_KEY',
    models: {
      default:     'claude-haiku-4-5-20251001',
      fast:        'claude-haiku-4-5-20251001',
      enterprise:  'claude-sonnet-4-6',
      opus:        'claude-opus-4-8',
    },
    max_tokens_cap: 2048,
    timeout_ms:     28000,
    cost_per_1k:    0.003,
  },
};

// ── MYTHOS system persona (injected on every call) ────────────────────────────
const MYTHOS_SYSTEM = `You are MYTHOS — the sovereign AI security intelligence engine of CYBERDUDEBIVASH® SENTINEL APEX.

Identity: Principal AI Cybersecurity Intelligence Analyst — CYBERDUDEBIVASH® AI Security Hub
Standards: MITRE ATT\&CK v15 | OWASP | NIST | ISO 27001:2022 | CVSS v3.1

Requirements:
- Enterprise-grade precision — zero tolerance for hallucination
- MITRE ATT\&CK tactic/technique references where relevant (TA####/T####)
- CVSS scores must be accurate; regulatory references must cite correct article numbers
- No generic advice — every recommendation must be specific and implementable
- Board-ready executive language for executive summaries
- Technical depth for security practitioner sections

Serving: CISOs, SOC analysts, security engineers, and enterprise decision-makers.
Reports are production-grade deliverables used in real security programs.`;

// ── Task-type → provider priority mapping ─────────────────────────────────────
const TASK_PROVIDER_ORDER = {
  threat_intel:  [PROVIDERS.DEEPSEEK,   PROVIDERS.GROQ,    PROVIDERS.CF_AI,  PROVIDERS.OPENROUTER, PROVIDERS.ANTHROPIC],
  executive:     [PROVIDERS.GROQ,       PROVIDERS.DEEPSEEK, PROVIDERS.CF_AI, PROVIDERS.OPENROUTER, PROVIDERS.ANTHROPIC],
  governance:    [PROVIDERS.GROQ,       PROVIDERS.DEEPSEEK, PROVIDERS.CF_AI, PROVIDERS.OPENROUTER, PROVIDERS.ANTHROPIC],
  assessment:    [PROVIDERS.CF_AI,      PROVIDERS.GROQ,    PROVIDERS.DEEPSEEK, PROVIDERS.OPENROUTER],
  enterprise:    [PROVIDERS.ANTHROPIC,  PROVIDERS.GROQ,    PROVIDERS.DEEPSEEK, PROVIDERS.OPENROUTER, PROVIDERS.CF_AI],
  general:       [PROVIDERS.GROQ,       PROVIDERS.DEEPSEEK, PROVIDERS.CF_AI, PROVIDERS.OPENROUTER, PROVIDERS.ANTHROPIC],
};

// ── OpenAI-compatible API client (Groq, DeepSeek, OpenRouter) ─────────────────
async function callOpenAICompat(endpoint, apiKey, {
  model,
  system,
  prompt,
  max_tokens = 800,
  temperature = 0.3,
  timeout_ms = 20000,
  extra_headers = {},
}) {
  const messages = [];
  if (system) messages.push({ role: 'system', content: system });
  messages.push({ role: 'user', content: prompt });

  const response = await fetch(endpoint, {
    method:  'POST',
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${apiKey}`,
      ...extra_headers,
    },
    body: JSON.stringify({ model, messages, max_tokens, temperature, stream: false }),
    signal: AbortSignal.timeout(timeout_ms),
  });

  if (!response.ok) {
    const err = await response.text().catch(() => response.statusText);
    throw new Error(`[${endpoint}] ${response.status}: ${err.slice(0, 150)}`);
  }

  const data = await response.json();
  const content = data.choices?.[0]?.message?.content || '';
  if (!content) throw new Error(`[${endpoint}] Empty response from model ${model}`);

  return {
    content,
    model:         data.model || model,
    input_tokens:  data.usage?.prompt_tokens || 0,
    output_tokens: data.usage?.completion_tokens || 0,
  };
}

// ── Anthropic API client ──────────────────────────────────────────────────────
async function callAnthropicDirect(apiKey, {
  model,
  system,
  prompt,
  max_tokens = 800,
  temperature = 0.3,
  timeout_ms = 28000,
}) {
  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method:  'POST',
    headers: {
      'Content-Type':      'application/json',
      'x-api-key':         apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model,
      max_tokens,
      temperature,
      system:   system || MYTHOS_SYSTEM,
      messages: [{ role: 'user', content: prompt }],
    }),
    signal: AbortSignal.timeout(timeout_ms),
  });

  if (!response.ok) {
    const err = await response.text().catch(() => response.statusText);
    throw new Error(`[Anthropic] ${response.status}: ${err.slice(0, 150)}`);
  }

  const data = await response.json();
  const content = data.content?.[0]?.text || '';
  if (!content) throw new Error('[Anthropic] Empty response');

  return {
    content,
    model:         data.model || model,
    input_tokens:  data.usage?.input_tokens || 0,
    output_tokens: data.usage?.output_tokens || 0,
  };
}

// ── Cloudflare Workers AI client ──────────────────────────────────────────────
async function callCFAI(ai, { model, system, prompt, max_tokens = 400 }) {
  if (!ai) throw new Error('[CF AI] env.AI binding not available');
  const messages = [];
  if (system) messages.push({ role: 'system', content: system });
  messages.push({ role: 'user', content: prompt });

  const resp = await ai.run(model, { messages, max_tokens });
  const content = resp?.response || '';
  if (!content) throw new Error('[CF AI] Empty response');
  return { content, model, input_tokens: 0, output_tokens: 0 };
}

// ── Per-provider dispatch ─────────────────────────────────────────────────────
async function dispatchToProvider(provider, env, { system, prompt, max_tokens, temperature, tier }) {
  const cfg = PROVIDER_CONFIG[provider];
  const t0  = Date.now();

  const model = (tier === 'ENTERPRISE')
    ? (cfg.models.enterprise || cfg.models.default)
    : cfg.models.default;

  const cappedTokens = Math.min(max_tokens, cfg.max_tokens_cap);
  let raw;

  if (provider === PROVIDERS.CF_AI) {
    raw = await callCFAI(env?.AI, { model, system, prompt, max_tokens: cappedTokens });

  } else if (provider === PROVIDERS.ANTHROPIC) {
    const apiKey = env?.[cfg.envKey];
    if (!apiKey) throw new Error('[Anthropic] ANTHROPIC_API_KEY not configured');
    raw = await callAnthropicDirect(apiKey, { model, system, prompt, max_tokens: cappedTokens, temperature, timeout_ms: cfg.timeout_ms });

  } else {
    // Groq, DeepSeek, OpenRouter — all OpenAI-compat
    const apiKey = env?.[cfg.envKey];
    if (!apiKey) throw new Error(`[${provider}] API key not configured`);
    const extra = provider === PROVIDERS.OPENROUTER
      ? { 'HTTP-Referer': 'https://cyberdudebivash.in', 'X-Title': 'CYBERDUDEBIVASH MYTHOS' }
      : {};
    raw = await callOpenAICompat(cfg.endpoint, apiKey, {
      model, system, prompt, max_tokens: cappedTokens, temperature,
      timeout_ms: cfg.timeout_ms, extra_headers: extra,
    });
  }

  return {
    content:     raw.content,
    model:       raw.model,
    source:      provider,
    provider,
    tokens:      { input: raw.input_tokens, output: raw.output_tokens },
    latency_ms:  Date.now() - t0,
  };
}

// ── Check which providers are configured ─────────────────────────────────────
function getConfiguredProviders(env) {
  const configured = [];
  for (const [prov, cfg] of Object.entries(PROVIDER_CONFIG)) {
    if (!cfg.envKey) {
      // CF AI — available if env.AI exists
      if (env?.AI) configured.push(prov);
    } else {
      if (env?.[cfg.envKey]) configured.push(prov);
    }
  }
  return configured;
}

// ════════════════════════════════════════════════════════════════════════════
// PRIMARY EXPORT: routeAICall
// ════════════════════════════════════════════════════════════════════════════
/**
 * Route an AI call through the priority chain for the given task type.
 * Tries providers in order, returns first successful response.
 *
 * @param {object} env         — Worker env (bindings + secrets)
 * @param {object} opts
 * @param {string} opts.prompt       — The user message / task
 * @param {string} [opts.system]     — Extra system context (appended to MYTHOS base)
 * @param {string} [opts.task_type]  — 'threat_intel'|'executive'|'governance'|'assessment'|'enterprise'|'general'
 * @param {string} [opts.tier]       — 'ENTERPRISE'|'PRO'|'FREE'
 * @param {number} [opts.max_tokens] — Token budget (default 800)
 * @param {number} [opts.temperature]— 0=deterministic (default 0.3)
 * @param {boolean}[opts.json_mode]  — Append JSON instruction
 * @returns {Promise<{content,model,source,provider,tokens,latency_ms}|null>}
 */
export async function routeAICall(env, {
  prompt,
  system      = '',
  task_type   = 'general',
  tier        = 'PRO',
  max_tokens  = 800,
  temperature = 0.3,
  json_mode   = false,
}) {
  if (!prompt) return null;

  const fullSystem = system
    ? `${MYTHOS_SYSTEM}\n\n${system}`
    : MYTHOS_SYSTEM;

  const finalPrompt = json_mode
    ? `${prompt}\n\nRespond with valid JSON only. No explanation outside the JSON object.`
    : prompt;

  const providerOrder  = TASK_PROVIDER_ORDER[task_type] || TASK_PROVIDER_ORDER.general;
  const configured     = getConfiguredProviders(env);
  const candidateOrder = providerOrder.filter(p => configured.includes(p));

  if (candidateOrder.length === 0) {
    console.error('[AI Router] No providers configured. Set GROQ_API_KEY, DEEPSEEK_API_KEY, or ensure env.AI is bound.');
    return null;
  }

  let lastError;
  for (const provider of candidateOrder) {
    try {
      const result = await dispatchToProvider(provider, env, {
        system: fullSystem,
        prompt: finalPrompt,
        max_tokens,
        temperature,
        tier,
      });
      // Log successful routing
      console.log(`[AI Router] ${task_type} → ${provider} (${result.model}) ${result.latency_ms}ms`);
      return result;
    } catch (err) {
      lastError = err;
      console.warn(`[AI Router] ${provider} failed (${task_type}): ${err.message}`);
      // Continue to next provider
    }
  }

  console.error(`[AI Router] All providers exhausted for task_type=${task_type}. Last error: ${lastError?.message}`);
  return null;
}

// ── Convenience interface matching legacy callClaude signature ────────────────
// Allows mythosAIProvider.js to delegate without breaking its callers
export async function callViaRouter(env, {
  prompt,
  system      = '',
  tier        = 'PRO',
  model       = null, // kept for compat — ignored; router selects model
  max_tokens  = 800,
  temperature = 0.3,
  json_mode   = false,
  task_type   = null, // override routing task type
}) {
  // Infer task_type from tier if not provided
  const resolvedType = task_type || (tier === 'ENTERPRISE' ? 'enterprise' : 'general');

  return routeAICall(env, {
    prompt, system, task_type: resolvedType, tier,
    max_tokens, temperature, json_mode,
  });
}

// ════════════════════════════════════════════════════════════════════════════
// PROVIDER HEALTH CHECK — powers GET /api/ai/providers/status
// ════════════════════════════════════════════════════════════════════════════
export async function getProviderHealthStatus(env) {
  const PING_PROMPT = 'Reply with exactly: MYTHOS ONLINE';
  const results = {};

  const checks = Object.entries(PROVIDER_CONFIG).map(async ([provider, cfg]) => {
    const t0 = Date.now();

    // Skip if not configured
    if (cfg.envKey && !env?.[cfg.envKey]) {
      results[provider] = { status: 'unconfigured', available: false, key_required: cfg.envKey };
      return;
    }
    if (!cfg.envKey && !env?.AI) {
      results[provider] = { status: 'unconfigured', available: false, reason: 'env.AI not bound' };
      return;
    }

    try {
      const r = await dispatchToProvider(provider, env, {
        system:      'You are a health check service.',
        prompt:      PING_PROMPT,
        max_tokens:  20,
        temperature: 0,
        tier:        'FREE',
      });
      results[provider] = {
        status:     'healthy',
        available:  true,
        model:      r.model,
        latency_ms: Date.now() - t0,
        optional:   provider === PROVIDERS.ANTHROPIC,
      };
    } catch (err) {
      results[provider] = {
        status:     'error',
        available:  false,
        latency_ms: Date.now() - t0,
        error:      err.message.slice(0, 100),
        optional:   provider === PROVIDERS.ANTHROPIC,
      };
    }
  });

  await Promise.allSettled(checks);

  // Summary
  const healthy    = Object.values(results).filter(r => r.status === 'healthy').length;
  const total      = Object.keys(results).length;
  const cfHealthy  = results[PROVIDERS.CF_AI]?.status === 'healthy';
  const anyHealthy = healthy > 0 || cfHealthy;

  return {
    summary: {
      status:            anyHealthy ? 'operational' : 'degraded',
      healthy_providers: healthy,
      total_providers:   total,
      anthropic_required: false,
      vendor_lock_in:    false,
    },
    providers: {
      [PROVIDERS.GROQ]:       results[PROVIDERS.GROQ]       || { status: 'unconfigured' },
      [PROVIDERS.DEEPSEEK]:   results[PROVIDERS.DEEPSEEK]   || { status: 'unconfigured' },
      [PROVIDERS.CF_AI]:      results[PROVIDERS.CF_AI]      || { status: 'unconfigured' },
      [PROVIDERS.OPENROUTER]: results[PROVIDERS.OPENROUTER] || { status: 'unconfigured' },
      [PROVIDERS.ANTHROPIC]:  { ...(results[PROVIDERS.ANTHROPIC] || { status: 'unconfigured' }), optional: true },
    },
    task_routing: {
      threat_intel:  'deepseek → groq → cloudflare-workers-ai',
      executive:     'groq → deepseek → cloudflare-workers-ai',
      governance:    'groq → deepseek → cloudflare-workers-ai',
      assessment:    'cloudflare-workers-ai → groq → deepseek',
      enterprise:    'anthropic (optional) → groq → deepseek',
      general:       'groq → deepseek → cloudflare-workers-ai',
    },
    architecture: 'MYTHOS → Provider Router → Multi-Provider AI Mesh',
    vendor_lock_in: 'NONE — platform operational without any single provider',
  };
}

// ── Legacy compat export (used by existing health endpoint in index.js) ───────
export async function checkAIProviderHealth(env) {
  const health = await getProviderHealthStatus(env);
  const { providers } = health;

  // Determine primary active provider
  const priority = [PROVIDERS.GROQ, PROVIDERS.DEEPSEEK, PROVIDERS.CF_AI, PROVIDERS.OPENROUTER, PROVIDERS.ANTHROPIC];
  const primary  = priority.find(p => providers[p]?.status === 'healthy') || null;

  return {
    status:   primary ? 'healthy' : 'degraded',
    provider: primary || 'none',
    model:    primary ? (PROVIDER_CONFIG[primary]?.models?.default || 'unknown') : null,
    claude:   providers[PROVIDERS.ANTHROPIC]?.status === 'healthy',
    message:  primary
      ? `AI router operational — primary provider: ${primary}. Anthropic is optional.`
      : 'No AI providers configured. Set GROQ_API_KEY or DEEPSEEK_API_KEY.',
    providers: {
      groq:       providers[PROVIDERS.GROQ]?.status,
      deepseek:   providers[PROVIDERS.DEEPSEEK]?.status,
      cf_ai:      providers[PROVIDERS.CF_AI]?.status,
      openrouter: providers[PROVIDERS.OPENROUTER]?.status,
      anthropic:  providers[PROVIDERS.ANTHROPIC]?.status + ' (optional)',
    },
  };
}
