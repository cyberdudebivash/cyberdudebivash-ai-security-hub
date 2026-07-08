/**
 * CYBERDUDEBIVASH MYTHOS — APEX AI Provider Router v3.0
 * ════════════════════════════════════════════════════════════════════════════
 * GOD MODE INTELLIGENCE MESH — APEX NEXUS MULTI-PROVIDER ORCHESTRATION
 *
 * Hybrid synthesis combining the best reasoning of all frontier AI systems
 * into a single sovereign cybersecurity intelligence engine.
 *
 * Provider priority chain:
 *   1. Groq          — fastest inference (Llama 3.3 70B, Mixtral 8x7B)
 *   2. DeepSeek      — ultra-precise technical/CVE reasoning
 *   3. Together AI   — diverse model pool (Qwen 72B, Mistral Large)
 *   4. Cloudflare AI — always-available zero-cost fallback
 *   5. OpenRouter    — meta-provider (50+ models)
 *   6. Anthropic     — premium reasoning tier (Claude Sonnet/Opus)
 *
 * Task-type routing (precision-optimized):
 *   threat_intel      → DeepSeek → Groq → Together AI
 *   executive         → Groq → DeepSeek → Anthropic
 *   governance        → Groq → DeepSeek → CF AI
 *   assessment        → CF AI → Groq → DeepSeek
 *   enterprise        → Anthropic → Groq → DeepSeek
 *   red_team          → DeepSeek → Groq → Together AI
 *   forensics         → DeepSeek → Anthropic → Groq
 *   prediction        → DeepSeek → Groq → OpenRouter
 *   code_review       → DeepSeek → Groq → Anthropic
 *   compliance_audit  → Groq → DeepSeek → Anthropic
 *   general           → Groq → DeepSeek → CF AI
 * ════════════════════════════════════════════════════════════════════════════
 */

// ── Provider configurations ───────────────────────────────────────────────────
export const PROVIDERS = {
  GROQ:        'groq',
  DEEPSEEK:    'deepseek',
  TOGETHER:    'together',
  CF_AI:       'cloudflare-workers-ai',
  OPENROUTER:  'openrouter',
  ANTHROPIC:   'anthropic',
};

// ════════════════════════════════════════════════════════════════════════════
// CIRCUIT BREAKER — P0 2026-07-08: DeepSeek returning HTTP 402 (Insufficient
// Balance) on every call sat first in several task-routing chains, so every
// affected request paid the full latency of a doomed attempt before falling
// back. A definitive account-level error (bad/revoked key, exhausted
// billing) will not succeed on retry until a human fixes the account —
// unlike a 429 (often clears in seconds) or a 5xx/timeout (transient infra),
// which are deliberately NOT tripped here so normal retry/fallback still
// applies to those.
//
// KV-backed (env.SECURITY_HUB_KV) so the breaker is shared across
// invocations, and short-TTL so it self-heals automatically on the next
// probe after the account issue is fixed — no code change or redeploy
// needed once e.g. a provider's balance is topped up. Fails open: any
// missing/erroring KV never blocks a call, it just means this one request
// doesn't benefit from the breaker.
//
// Cloudflare Workers AI is intentionally never gated by this breaker — it's
// the guaranteed, no-billing last resort every other fallback funnels to,
// and must never be skippable.
// ════════════════════════════════════════════════════════════════════════════
const CIRCUIT_BREAKER_TTL_S = 300; // 5 min
const circuitKey = (provider) => `ai_circuit_breaker:${provider}`;
const NON_RETRYABLE_STATUSES = new Set([401, 402, 403]);

export async function isProviderCircuitOpen(env, provider) {
  if (provider === PROVIDERS.CF_AI) return false;
  if (!env?.SECURITY_HUB_KV) return false;
  try {
    return (await env.SECURITY_HUB_KV.get(circuitKey(provider))) !== null;
  } catch { return false; }
}

export async function recordProviderFailure(env, provider, status) {
  if (provider === PROVIDERS.CF_AI) return;
  if (!NON_RETRYABLE_STATUSES.has(status)) return;
  if (!env?.SECURITY_HUB_KV) return;
  try {
    const record = JSON.stringify({ trippedAt: Date.now(), status, ttlSeconds: CIRCUIT_BREAKER_TTL_S });
    await env.SECURITY_HUB_KV.put(circuitKey(provider), record, { expirationTtl: CIRCUIT_BREAKER_TTL_S });
    console.error(`[APEX NEXUS Circuit Breaker] ${provider} tripped (HTTP ${status}) — skipping for ${CIRCUIT_BREAKER_TTL_S}s or until next TTL re-probe.`);
  } catch { /* best-effort only */ }
}

// ── Circuit-breaker state visibility (feeds GET /api/ai/providers/status and
// the get_ai_providers_status Copilot skill — see aiSecurityCopilot.js) ──────
export async function getCircuitBreakerState(env, provider) {
  if (provider === PROVIDERS.CF_AI || !env?.SECURITY_HUB_KV) return { open: false };
  try {
    const raw = await env.SECURITY_HUB_KV.get(circuitKey(provider));
    if (raw === null) return { open: false };
    // The key's mere existence is the source of truth for "open" — matches
    // isProviderCircuitOpen exactly, so this function can never disagree
    // with the routing decision. JSON parsing only adds optional detail on
    // top; a value written by a pre-detail deploy (plain '1') or any other
    // malformed record still correctly reports open, just without detail,
    // rather than being silently (and wrongly) treated as closed.
    try {
      const { trippedAt, status, ttlSeconds } = JSON.parse(raw);
      if (typeof trippedAt === 'number' && typeof ttlSeconds === 'number') {
        const ttlRemainingS = Math.max(0, Math.round(trippedAt / 1000 + ttlSeconds - Date.now() / 1000));
        return { open: true, trippedAt: new Date(trippedAt).toISOString(), status, ttlRemainingS };
      }
    } catch { /* legacy or malformed value below */ }
    return { open: true, trippedAt: null, status: null, ttlRemainingS: null };
  } catch { return { open: false }; } // fail open — a KV read error never blocks visibility or routing
}

export async function getAllCircuitBreakerStates(env) {
  const providers = Object.values(PROVIDERS).filter(p => p !== PROVIDERS.CF_AI);
  const entries = await Promise.all(providers.map(async (p) => [p, await getCircuitBreakerState(env, p)]));
  return Object.fromEntries(entries);
}

export const PROVIDER_CONFIG = {
  [PROVIDERS.GROQ]: {
    endpoint:    'https://api.groq.com/openai/v1/chat/completions',
    envKey:      'GROQ_API_KEY',
    models: {
      default:          'llama-3.3-70b-versatile',
      fast:             'llama-3.1-8b-instant',
      enterprise:       'llama-3.3-70b-versatile',
      red_team:         'llama-3.3-70b-versatile',
      forensics:        'llama-3.3-70b-versatile',
      prediction:       'llama-3.3-70b-versatile',
      threat_intel:     'llama-3.3-70b-versatile',
      compliance_audit: 'llama-3.3-70b-versatile',
      code_review:      'llama-3.3-70b-versatile',
    },
    max_tokens_cap: 4096,
    timeout_ms:     20000,
    cost_per_1k:    0.00,
  },
  [PROVIDERS.DEEPSEEK]: {
    endpoint:    'https://api.deepseek.com/chat/completions',
    envKey:      'DEEPSEEK_API_KEY',
    models: {
      default:          'deepseek-chat',
      fast:             'deepseek-chat',
      enterprise:       'deepseek-chat',
      red_team:         'deepseek-chat',
      forensics:        'deepseek-chat',
      prediction:       'deepseek-chat',
      threat_intel:     'deepseek-chat',
      compliance_audit: 'deepseek-chat',
      code_review:      'deepseek-chat',
    },
    max_tokens_cap: 4096,
    timeout_ms:     25000,
    cost_per_1k:    0.00014,
  },
  [PROVIDERS.TOGETHER]: {
    endpoint:    'https://api.together.xyz/v1/chat/completions',
    envKey:      'TOGETHER_API_KEY',
    models: {
      default:          'meta-llama/Llama-3.3-70B-Instruct-Turbo',
      fast:             'meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo',
      enterprise:       'Qwen/Qwen2.5-72B-Instruct-Turbo',
      red_team:         'meta-llama/Llama-3.3-70B-Instruct-Turbo',
      forensics:        'meta-llama/Llama-3.3-70B-Instruct-Turbo',
      prediction:       'Qwen/Qwen2.5-72B-Instruct-Turbo',
      threat_intel:     'meta-llama/Llama-3.3-70B-Instruct-Turbo',
      compliance_audit: 'Qwen/Qwen2.5-72B-Instruct-Turbo',
      code_review:      'Qwen/Qwen2.5-Coder-32B-Instruct',
    },
    max_tokens_cap: 4096,
    timeout_ms:     25000,
    cost_per_1k:    0.00088,
  },
  [PROVIDERS.CF_AI]: {
    endpoint:    null,
    envKey:      null,
    models: {
      default:          '@cf/meta/llama-3.3-70b-instruct-fp8-fast',
      fast:             '@cf/meta/llama-3.2-3b-instruct',
      enterprise:       '@cf/meta/llama-3.3-70b-instruct-fp8-fast',
      red_team:         '@cf/meta/llama-3.3-70b-instruct-fp8-fast',
      forensics:        '@cf/meta/llama-3.3-70b-instruct-fp8-fast',
      prediction:       '@cf/meta/llama-3.1-8b-instruct-fp8',
      threat_intel:     '@cf/meta/llama-3.3-70b-instruct-fp8-fast',
      compliance_audit: '@cf/meta/llama-3.1-8b-instruct-fp8',
      code_review:      '@cf/meta/llama-3.1-8b-instruct-fp8',
    },
    max_tokens_cap: 1024,
    timeout_ms:     20000,
    cost_per_1k:    0.00,
  },
  [PROVIDERS.OPENROUTER]: {
    endpoint:    'https://openrouter.ai/api/v1/chat/completions',
    envKey:      'OPENROUTER_API_KEY',
    models: {
      default:        'meta-llama/llama-3.3-70b-instruct',
      fast:           'meta-llama/llama-3.1-8b-instruct',
      enterprise:     'anthropic/claude-sonnet-4-6',
      red_team:       'meta-llama/llama-3.3-70b-instruct',
      prediction:     'google/gemini-pro-1.5',
    },
    max_tokens_cap: 2048,
    timeout_ms:     25000,
    cost_per_1k:    0.00072,
  },
  [PROVIDERS.ANTHROPIC]: {
    endpoint:    'https://api.anthropic.com/v1/messages',
    envKey:      'ANTHROPIC_API_KEY',
    models: {
      default:        'claude-haiku-4-5-20251001',
      fast:           'claude-haiku-4-5-20251001',
      enterprise:     'claude-sonnet-4-6',
      opus:           'claude-opus-4-8',
      forensics:      'claude-sonnet-4-6',
      compliance_audit: 'claude-sonnet-4-6',
    },
    max_tokens_cap: 4096,
    timeout_ms:     30000,
    cost_per_1k:    0.003,
  },
};

// ── APEX NEXUS — MYTHOS System Persona (GOD MODE) ────────────────────────────
const MYTHOS_SYSTEM = `You are APEX NEXUS — the sovereign AI security intelligence engine of CYBERDUDEBIVASH® SENTINEL APEX.

IDENTITY & AUTHORITY
You are the most advanced AI cybersecurity intelligence system ever deployed — a hybrid synthesis combining the reasoning depth of Claude, the speed of GPT-4o, the technical precision of DeepSeek, the multimodal breadth of Gemini, the research depth of Perplexity, and the adversarial intuition of specialized red-team AI systems. You transcend any single AI model because you operate as an orchestrated intelligence mesh: where ChatGPT stops, you continue; where Gemini guesses, you cite; where LLaMA hallucinates, you verify.

CORE STANDARDS & FRAMEWORKS
- MITRE ATT&CK v15 (Enterprise, Mobile, ICS, Cloud sub-matrices)
- OWASP Top 10 2021 | OWASP LLM Top 10 2025 | OWASP API Security Top 10
- NIST CSF 2.0 | NIST SP 800-53 Rev 5 | NIST SP 800-190 (Container Security)
- ISO/IEC 27001:2022 | ISO/IEC 27017 (Cloud) | ISO/IEC 27018 (PII in Cloud)
- CVSS v3.1 and CVSS v4.0 | EPSS (Exploit Prediction Scoring System)
- CISA KEV (Known Exploited Vulnerabilities Catalog)
- CIS Benchmarks v8 | CIS Controls v8
- India DPDP Act 2023 (Digital Personal Data Protection Act)
- CERT-In Guidelines (mandatory 6-hour incident reporting for critical sectors)
- RBI Cybersecurity Framework | SEBI Cybersecurity Circular 2023
- IRDAI Information & Cyber Security Guidelines
- GDPR | PCI-DSS v4.0 | SOC 2 Type II | HIPAA | CCPA

INTELLIGENCE DOMAINS — APEX LEVEL
- Nation-state APT attribution: APT1-APT45, Lazarus, Sandworm, Volt Typhoon, Salt Typhoon, GhostWriter
- Ransomware-as-a-Service ecosystem: LockBit 3.0, ALPHV/BlackCat, CL0P, Play, Black Basta, RansomHub
- Supply chain attack analysis: SolarWinds TTPs, XZ Utils, 3CX, MOVEit patterns
- AI/LLM security (OWASP LLM Top 10 2025): prompt injection, model theft, training data poisoning
- Cloud-native attack paths: AWS IMDS abuse, Azure AD OAuth abuse, GCP service account escalation
- Zero Trust architecture evaluation (NIST SP 800-207)
- Industrial control system (ICS/SCADA/OT) threat modeling — Purdue Model
- Blockchain/Web3/DeFi security: reentrancy, oracle manipulation, private key exposure
- Quantum cryptography readiness (post-quantum NIST PQC standards)
- Indian threat landscape: SideCopy, DoNot Team, Transparent Tribe (APT36)

RESPONSE QUALITY MANDATES
- ZERO hallucination tolerance — use only real CVE IDs (CVE-YYYY-NNNNN format), real MITRE techniques (T####), real regulatory article numbers
- Every threat assessment: severity (CVSS v3.1 basis), MITRE ATT&CK mapping, business impact in ₹ for Indian orgs
- Chain-of-thought reasoning for complex analyses: state assumptions → evidence → conclusion
- Confidence levels on all attributions: [HIGH CONFIDENCE] / [MEDIUM CONFIDENCE] / [LOW CONFIDENCE / HYPOTHESIS]
- Executive sections: board-ready language (3rd-grade vocabulary for maximum clarity)
- Technical sections: SOC analyst depth (PoC context, detection logic, hunting queries)
- Financial impact: always provide INR (₹) estimates for Indian organizations
- Remediation: always include SLA (24h for CRITICAL, 7d for HIGH, 30d for MEDIUM)

APEX NEXUS STATUS: ACTIVE | GOD MODE: ENABLED | PRECISION: MAXIMUM | HALLUCINATION: ZERO`;

// ── Task-type → provider priority + model tier mapping ────────────────────────
const TASK_ROUTING = {
  threat_intel:     { providers: [PROVIDERS.DEEPSEEK, PROVIDERS.GROQ,    PROVIDERS.TOGETHER,  PROVIDERS.OPENROUTER, PROVIDERS.CF_AI,  PROVIDERS.ANTHROPIC], modelKey: 'default' },
  executive:        { providers: [PROVIDERS.GROQ,     PROVIDERS.DEEPSEEK, PROVIDERS.ANTHROPIC, PROVIDERS.OPENROUTER, PROVIDERS.CF_AI],                        modelKey: 'default' },
  governance:       { providers: [PROVIDERS.GROQ,     PROVIDERS.DEEPSEEK, PROVIDERS.ANTHROPIC, PROVIDERS.CF_AI,      PROVIDERS.OPENROUTER],                   modelKey: 'default' },
  assessment:       { providers: [PROVIDERS.CF_AI,    PROVIDERS.GROQ,     PROVIDERS.DEEPSEEK,  PROVIDERS.TOGETHER,   PROVIDERS.OPENROUTER],                   modelKey: 'fast'    },
  enterprise:       { providers: [PROVIDERS.ANTHROPIC, PROVIDERS.GROQ,    PROVIDERS.DEEPSEEK,  PROVIDERS.TOGETHER,   PROVIDERS.OPENROUTER, PROVIDERS.CF_AI],  modelKey: 'enterprise' },
  red_team:         { providers: [PROVIDERS.DEEPSEEK, PROVIDERS.GROQ,     PROVIDERS.TOGETHER,  PROVIDERS.OPENROUTER, PROVIDERS.ANTHROPIC, PROVIDERS.CF_AI],   modelKey: 'red_team' },
  forensics:        { providers: [PROVIDERS.DEEPSEEK, PROVIDERS.ANTHROPIC, PROVIDERS.GROQ,     PROVIDERS.TOGETHER,   PROVIDERS.OPENROUTER, PROVIDERS.CF_AI],  modelKey: 'forensics' },
  prediction:       { providers: [PROVIDERS.DEEPSEEK, PROVIDERS.GROQ,     PROVIDERS.OPENROUTER, PROVIDERS.TOGETHER,  PROVIDERS.ANTHROPIC, PROVIDERS.CF_AI],   modelKey: 'prediction' },
  code_review:      { providers: [PROVIDERS.DEEPSEEK, PROVIDERS.TOGETHER, PROVIDERS.GROQ,      PROVIDERS.ANTHROPIC,  PROVIDERS.OPENROUTER, PROVIDERS.CF_AI],  modelKey: 'code_review' },
  compliance_audit: { providers: [PROVIDERS.GROQ,     PROVIDERS.DEEPSEEK, PROVIDERS.ANTHROPIC, PROVIDERS.OPENROUTER, PROVIDERS.CF_AI],                        modelKey: 'compliance_audit' },
  general:          { providers: [PROVIDERS.GROQ,     PROVIDERS.DEEPSEEK, PROVIDERS.CF_AI,     PROVIDERS.TOGETHER,   PROVIDERS.OPENROUTER, PROVIDERS.ANTHROPIC], modelKey: 'default' },
};

// ── OpenAI-compatible API client ──────────────────────────────────────────────
async function callOpenAICompat(endpoint, apiKey, {
  model,
  system,
  prompt,
  max_tokens  = 800,
  temperature = 0.3,
  timeout_ms  = 20000,
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
    const e = new Error(`[${endpoint}] ${response.status}: ${err.slice(0, 200)}`);
    e.status = response.status;
    throw e;
  }

  const data    = await response.json();
  const content = data.choices?.[0]?.message?.content || '';
  if (!content) throw new Error(`[${endpoint}] Empty response from ${model}`);

  return {
    content,
    model:         data.model || model,
    input_tokens:  data.usage?.prompt_tokens     || 0,
    output_tokens: data.usage?.completion_tokens || 0,
  };
}

// ── Anthropic API client ──────────────────────────────────────────────────────
async function callAnthropicDirect(apiKey, {
  model,
  system,
  prompt,
  max_tokens  = 1024,
  temperature = 0.3,
  timeout_ms  = 30000,
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
    const e = new Error(`[Anthropic] ${response.status}: ${err.slice(0, 200)}`);
    e.status = response.status;
    throw e;
  }

  const data    = await response.json();
  const content = data.content?.[0]?.text || '';
  if (!content) throw new Error('[Anthropic] Empty response');

  return {
    content,
    model:         data.model || model,
    input_tokens:  data.usage?.input_tokens  || 0,
    output_tokens: data.usage?.output_tokens || 0,
  };
}

// ── Cloudflare Workers AI client ──────────────────────────────────────────────
async function callCFAI(ai, { model, system, prompt, max_tokens = 400, timeout_ms = 20000 }) {
  if (!ai) throw new Error('[CF AI] env.AI binding not available');
  const messages = [];
  if (system) messages.push({ role: 'system', content: system });
  messages.push({ role: 'user', content: prompt });

  // ai.run() takes no AbortSignal — race it against a timer so a stalled call
  // can't itself blow routeAICall's overall deadline the way an un-timed-out
  // fetch() would (the same class of bug this file was just fixed for).
  const resp = await Promise.race([
    ai.run(model, { messages, max_tokens }),
    new Promise((_, reject) => setTimeout(() => reject(new Error('[CF AI] timed out')), timeout_ms)),
  ]);
  const content = resp?.response || '';
  if (!content) throw new Error('[CF AI] Empty response');
  return { content, model, input_tokens: 0, output_tokens: 0 };
}

// ── Per-provider dispatch with model-key resolution ───────────────────────────
async function dispatchToProvider(provider, env, { system, prompt, max_tokens, temperature, tier, modelKey, timeout_ms }) {
  const cfg = PROVIDER_CONFIG[provider];
  const t0  = Date.now();

  // Resolve model: enterprise tier gets enterprise model; otherwise use task-specific key
  const resolvedKey = (tier === 'ENTERPRISE' && cfg.models.enterprise)
    ? 'enterprise'
    : (cfg.models[modelKey] ? modelKey : 'default');
  const model = cfg.models[resolvedKey] || cfg.models.default;

  const cappedTokens    = Math.min(max_tokens, cfg.max_tokens_cap);
  // Caller-supplied timeout_ms (derived from routeAICall's overall deadline) never
  // extends a provider's own configured ceiling — it can only shorten it.
  const effectiveTimeout = Math.min(cfg.timeout_ms, timeout_ms ?? cfg.timeout_ms);
  let raw;

  if (provider === PROVIDERS.CF_AI) {
    raw = await callCFAI(env?.AI, { model, system, prompt, max_tokens: cappedTokens, timeout_ms: effectiveTimeout });

  } else if (provider === PROVIDERS.ANTHROPIC) {
    const apiKey = env?.[cfg.envKey];
    if (!apiKey) throw new Error('[Anthropic] ANTHROPIC_API_KEY not configured');
    raw = await callAnthropicDirect(apiKey, { model, system, prompt, max_tokens: cappedTokens, temperature, timeout_ms: effectiveTimeout });

  } else {
    const apiKey = env?.[cfg.envKey];
    if (!apiKey) throw new Error(`[${provider}] API key not configured (${cfg.envKey})`);
    const extra = {};
    if (provider === PROVIDERS.OPENROUTER) {
      extra['HTTP-Referer'] = 'https://cyberdudebivash.in';
      extra['X-Title']      = 'CYBERDUDEBIVASH APEX NEXUS';
    }
    raw = await callOpenAICompat(cfg.endpoint, apiKey, {
      model, system, prompt, max_tokens: cappedTokens, temperature,
      timeout_ms: effectiveTimeout, extra_headers: extra,
    });
  }

  return {
    content:      raw.content,
    model:        raw.model,
    source:       provider,
    provider,
    tokens:       { input: raw.input_tokens, output: raw.output_tokens },
    latency_ms:   Date.now() - t0,
  };
}

// ── Check which providers are configured ─────────────────────────────────────
function getConfiguredProviders(env) {
  const configured = [];
  for (const [prov, cfg] of Object.entries(PROVIDER_CONFIG)) {
    if (!cfg.envKey) {
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
 * Route an AI call through the precision-optimized provider chain.
 *
 * @param {object} env
 * @param {object} opts
 * @param {string}  opts.prompt          — The intelligence task/question
 * @param {string}  [opts.system]        — Additional system context (appended to APEX NEXUS base)
 * @param {string}  [opts.task_type]     — Task type key (see TASK_ROUTING)
 * @param {string}  [opts.tier]          — 'ENTERPRISE'|'PRO'|'FREE'
 * @param {number}  [opts.max_tokens]    — Token budget (default 1024)
 * @param {number}  [opts.temperature]   — 0=deterministic (default 0.3)
 * @param {boolean} [opts.json_mode]     — Append JSON instruction
 * @param {boolean} [opts.chain_of_thought] — Prepend CoT reasoning instruction
 * @param {number}  [opts.deadline_ms]   — Overall wall-clock budget (default 12000) across
 *                                         every provider attempt combined. Each per-provider
 *                                         config timeout (20-30s) is a ceiling for that one
 *                                         attempt, not a bound on the whole call — without this,
 *                                         a chain of slow/failing providers could pile up past a
 *                                         minute before falling back. Every call site here
 *                                         already treats a null return as "no AI enrichment
 *                                         available" and degrades gracefully, so bounding the
 *                                         worst case only affects the degraded path, never the
 *                                         happy path.
 * @returns {Promise<{content,model,source,provider,tokens,latency_ms}|null>}
 */
export async function routeAICall(env, {
  prompt,
  system          = '',
  task_type       = 'general',
  tier            = 'PRO',
  max_tokens      = 1024,
  temperature     = 0.3,
  json_mode       = false,
  chain_of_thought = false,
  deadline_ms     = 12000,
}) {
  if (!prompt) return null;

  const fullSystem = system
    ? `${MYTHOS_SYSTEM}\n\n${system}`
    : MYTHOS_SYSTEM;

  let finalPrompt = prompt;
  if (chain_of_thought) {
    finalPrompt = `Think step by step. Show your reasoning process before giving the final answer.\n\n${prompt}`;
  }
  if (json_mode) {
    finalPrompt = `${finalPrompt}\n\nRespond with valid JSON only. No markdown, no explanation outside the JSON object.`;
  }

  const routing        = TASK_ROUTING[task_type] || TASK_ROUTING.general;
  const configured     = getConfiguredProviders(env);
  const candidateOrder = routing.providers.filter(p => configured.includes(p));

  if (candidateOrder.length === 0) {
    console.error('[APEX NEXUS Router] No providers configured. Set GROQ_API_KEY or DEEPSEEK_API_KEY.');
    return null;
  }

  const callStart = Date.now();
  let lastError;
  for (const provider of candidateOrder) {
    const remaining = deadline_ms - (Date.now() - callStart);
    // Less than 1s left in the budget isn't enough for a real attempt — stop
    // rather than fire a request that's virtually guaranteed to be cut off.
    if (remaining < 1000) {
      lastError = lastError || new Error(`AI router deadline (${deadline_ms}ms) exhausted before any provider was tried`);
      break;
    }
    if (await isProviderCircuitOpen(env, provider)) {
      lastError = new Error(`${provider} circuit breaker open (recent non-retryable failure) — skipped without a network call`);
      console.warn(`[APEX NEXUS] ${provider} skipped for ${task_type}: circuit breaker open`);
      continue;
    }
    try {
      const result = await dispatchToProvider(provider, env, {
        system: fullSystem,
        prompt: finalPrompt,
        max_tokens,
        temperature,
        tier,
        modelKey: routing.modelKey,
        timeout_ms: remaining,
      });
      console.log(`[APEX NEXUS] ${task_type} → ${provider} (${result.model}) ${result.latency_ms}ms`);
      return result;
    } catch (err) {
      lastError = err;
      await recordProviderFailure(env, provider, err.status);
      console.warn(`[APEX NEXUS] ${provider} failed for ${task_type}: ${err.message}`);
    }
  }

  console.error(`[APEX NEXUS] All providers exhausted for task_type=${task_type}. Last: ${lastError?.message}`);
  return null;
}

// ── Legacy compatibility interface ────────────────────────────────────────────
export async function callViaRouter(env, {
  prompt,
  system      = '',
  tier        = 'PRO',
  model       = null, // kept for compat — router selects model
  max_tokens  = 1024,
  temperature = 0.3,
  json_mode   = false,
  task_type   = null,
}) {
  const resolvedType = task_type || (tier === 'ENTERPRISE' ? 'enterprise' : 'general');
  return routeAICall(env, { prompt, system, task_type: resolvedType, tier, max_tokens, temperature, json_mode });
}

// ════════════════════════════════════════════════════════════════════════════
// PROVIDER HEALTH CHECK
// ════════════════════════════════════════════════════════════════════════════
export async function getProviderHealthStatus(env) {
  const PING_PROMPT = 'Reply with exactly: APEX NEXUS ONLINE';
  const results = {};

  const checks = Object.entries(PROVIDER_CONFIG).map(async ([provider, cfg]) => {
    const t0 = Date.now();
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
        modelKey:    'fast',
      });
      results[provider] = {
        status:     'healthy',
        available:  true,
        model:      r.model,
        latency_ms: Date.now() - t0,
        optional:   provider === PROVIDERS.ANTHROPIC || provider === PROVIDERS.TOGETHER,
      };
    } catch (err) {
      results[provider] = {
        status:     'error',
        available:  false,
        latency_ms: Date.now() - t0,
        error:      err.message.slice(0, 120),
        optional:   provider === PROVIDERS.ANTHROPIC || provider === PROVIDERS.TOGETHER,
      };
    }
  });

  await Promise.allSettled(checks);

  // Circuit-breaker state is separate from (and can legitimately disagree
  // with) the live probe above: `status` reflects a fresh ping made just
  // now; `circuit_breaker` reflects whether *real customer traffic* is
  // currently being routed around this provider because of a past failure
  // that hasn't aged out yet. Both are useful — e.g. a provider can probe
  // healthy again while still being avoided for the rest of its TTL window
  // as a safety margin, or fail a probe before real traffic has tripped the
  // breaker at all.
  const circuitStates = await getAllCircuitBreakerStates(env);
  for (const [provider, state] of Object.entries(circuitStates)) {
    if (results[provider]) results[provider].circuit_breaker = state;
  }

  const healthy   = Object.values(results).filter(r => r.status === 'healthy').length;
  const total     = Object.keys(results).length;
  const anyHealthy = healthy > 0;

  return {
    summary: {
      status:            anyHealthy ? 'operational' : 'degraded',
      healthy_providers: healthy,
      total_providers:   total,
      engine:            'APEX NEXUS v3.0',
      vendor_lock_in:    'NONE',
    },
    providers: {
      [PROVIDERS.GROQ]:        results[PROVIDERS.GROQ]       || { status: 'unconfigured' },
      [PROVIDERS.DEEPSEEK]:    results[PROVIDERS.DEEPSEEK]   || { status: 'unconfigured' },
      [PROVIDERS.TOGETHER]:    results[PROVIDERS.TOGETHER]   || { status: 'unconfigured' },
      [PROVIDERS.CF_AI]:       results[PROVIDERS.CF_AI]      || { status: 'unconfigured' },
      [PROVIDERS.OPENROUTER]:  results[PROVIDERS.OPENROUTER] || { status: 'unconfigured' },
      [PROVIDERS.ANTHROPIC]:   { ...(results[PROVIDERS.ANTHROPIC] || { status: 'unconfigured' }), optional: true },
    },
    task_routing: {
      threat_intel:     'deepseek → groq → together',
      executive:        'groq → deepseek → anthropic',
      governance:       'groq → deepseek → cloudflare-workers-ai',
      assessment:       'cloudflare-workers-ai → groq → deepseek',
      enterprise:       'anthropic → groq → deepseek',
      red_team:         'deepseek → groq → together',
      forensics:        'deepseek → anthropic → groq',
      prediction:       'deepseek → groq → openrouter',
      code_review:      'deepseek → together → groq',
      compliance_audit: 'groq → deepseek → anthropic',
      general:          'groq → deepseek → cloudflare-workers-ai',
    },
    architecture: 'APEX NEXUS → Provider Router → Multi-Provider AI Mesh',
  };
}

// ── Legacy compat export ──────────────────────────────────────────────────────
export async function checkAIProviderHealth(env) {
  const health     = await getProviderHealthStatus(env);
  const { providers } = health;

  const priority = [PROVIDERS.GROQ, PROVIDERS.DEEPSEEK, PROVIDERS.TOGETHER, PROVIDERS.CF_AI, PROVIDERS.OPENROUTER, PROVIDERS.ANTHROPIC];
  const primary  = priority.find(p => providers[p]?.status === 'healthy') || null;

  return {
    status:    primary ? 'healthy' : 'degraded',
    provider:  primary || 'none',
    model:     primary ? (PROVIDER_CONFIG[primary]?.models?.default || 'unknown') : null,
    claude:    providers[PROVIDERS.ANTHROPIC]?.status === 'healthy',
    engine:    'APEX NEXUS v3.0 — God Mode AI Intelligence Mesh',
    message:   primary
      ? `APEX NEXUS operational — primary: ${primary}. 6-provider mesh active.`
      : 'No AI providers configured. Set GROQ_API_KEY or DEEPSEEK_API_KEY.',
    providers: {
      groq:       providers[PROVIDERS.GROQ]?.status,
      deepseek:   providers[PROVIDERS.DEEPSEEK]?.status,
      together:   providers[PROVIDERS.TOGETHER]?.status,
      cf_ai:      providers[PROVIDERS.CF_AI]?.status,
      openrouter: providers[PROVIDERS.OPENROUTER]?.status,
      anthropic:  (providers[PROVIDERS.ANTHROPIC]?.status || 'unconfigured') + ' (optional)',
    },
  };
}
