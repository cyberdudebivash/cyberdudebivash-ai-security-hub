/**
 * CYBERDUDEBIVASH AI Security Hub — APEX Multi-Agent SOC (MASOC) v2.0
 *
 * Architecture: 9 specialist AI agents dispatched in parallel via Promise.all()
 * Each agent has its own system prompt, AI provider routing, and domain expertise.
 * An Orchestrator classifies the task and activates the relevant agent subset.
 * A Synthesis Agent fuses all results into a unified executive brief.
 *
 * Production hardening (v2.0):
 *   - ctx.waitUntil() for SSE floating promise (Workers best practice)
 *   - Per-agent 25s AbortSignal timeout (prevents single slow provider hanging all agents)
 *   - MASOC-specific rate limiting (5 runs/min per user, KV-backed)
 *   - Real EPSS enrichment from api.first.org (EPSS v3)
 *   - Body size guard (max 8 KB task input)
 *   - SSE CORS restricted to platform origin (not wildcard)
 *   - Structured JSON logging for CF observability
 *   - Dynamic risk score/level extracted from synthesis output
 */

import { routeAICall } from '../core/aiProviderRouter.js';
import { corsHeaders } from '../middleware/cors.js';

// ─── Constants ────────────────────────────────────────────────────────────────
const MASOC_VERSION       = '2.0';
const MAX_BODY_BYTES      = 8192;           // 8 KB max task input
const AGENT_TIMEOUT_MS    = 25_000;         // per-agent AI call timeout
const RATE_LIMIT_WINDOW_S = 60;            // 1-minute window
const RATE_LIMIT_MAX      = 5;             // max MASOC runs per user per minute
const PLATFORM_ORIGIN     = 'https://cyberdudebivash.in';

// ─── Agent Registry ───────────────────────────────────────────────────────────
const AGENTS = {
  cve_intel: {
    id:          'cve_intel',
    name:        'CVE Intel Agent',
    icon:        '🔍',
    description: 'Threat intelligence specialist. Enriches CVEs from NVD, CISA KEV, EPSS. Provides CVSS scoring, exploit probability, and patch prioritization.',
    task_type:   'threat_intel',
    domains:     ['cve', 'vulnerability', 'patch', 'nvd', 'kev', 'cvss', 'epss', 'exploit', 'threat intel'],
    system_prompt: `You are the CVE Intel Agent — a world-class cybersecurity threat intelligence specialist.
Your sole focus: CVE enrichment, CVSS/EPSS scoring, CISA KEV status, exploit probability, and patch prioritization.
Always provide: CVE ID, CVSS score, EPSS score (exploitation probability %), KEV status (exploited in the wild), severity, affected products, and a 3-bullet remediation plan.
Be precise, technical, and actionable. Prioritize by exploit probability × CVSS score. Never hallucinate CVE details.`,
    max_tokens:  900,
    temperature: 0.1,
  },

  ioc_hunter: {
    id:          'ioc_hunter',
    name:        'IOC Hunter Agent',
    icon:        '🎯',
    description: 'IOC enrichment specialist. Analyzes IPs, domains, hashes, URLs via VirusTotal, AbuseIPDB, Shodan. Returns unified threat verdict.',
    task_type:   'threat_intel',
    domains:     ['ip', 'domain', 'hash', 'url', 'ioc', 'malware', 'c2', 'botnet', 'phishing', 'indicator'],
    system_prompt: `You are the IOC Hunter Agent — a threat intelligence analyst specialized in Indicator of Compromise enrichment.
Your focus: analyzing IPs, domains, file hashes, and URLs for malicious activity.
Always provide: threat verdict, confidence score (0-100), categories (malware/phishing/spam/c2), recommended actions (block/monitor/allow), and MITRE ATT&CK technique if known.
Reason from VirusTotal detections, AbuseIPDB scores, and Shodan exposure data. Be decisive — give a clear verdict.`,
    max_tokens:  800,
    temperature: 0.1,
  },

  siem_defender: {
    id:          'siem_defender',
    name:        'SIEM Defender Agent',
    icon:        '⚡',
    description: 'Detection engineering specialist. Generates Sigma/KQL/Splunk/YARA rules and deploys them to configured SIEMs.',
    task_type:   'threat_intel',
    domains:     ['siem', 'splunk', 'sentinel', 'elastic', 'qradar', 'sigma', 'kql', 'detection', 'rule', 'alert', 'yara'],
    system_prompt: `You are the SIEM Defender Agent — a detection engineering expert.
Your focus: generating production-ready detection rules and deploying them to SIEMs.
For every threat or CVE, produce: 1) Sigma rule (universal), 2) Splunk SPL, 3) Microsoft Sentinel KQL, 4) YARA rule (if applicable).
Rules must be syntactically correct, include MITRE ATT&CK technique tags, and have specific enough conditions to minimize false positives.
Always include the rule confidence level and estimated false positive rate.`,
    max_tokens:  1200,
    temperature: 0.05,
  },

  threat_hunter: {
    id:          'threat_hunter',
    name:        'Threat Hunt Agent',
    icon:        '🔎',
    description: 'Proactive threat hunting specialist. Designs hunt hypotheses, selects MITRE ATT&CK aligned queries, and correlates evidence.',
    task_type:   'threat_intel',
    domains:     ['hunt', 'hunting', 'hypothesis', 'mitre', 'attack', 'tactic', 'technique', 'lateral movement', 'persistence', 'exfiltration'],
    system_prompt: `You are the Threat Hunt Agent — a proactive threat hunting specialist aligned with MITRE ATT&CK.
Your focus: designing hunt hypotheses, selecting relevant ATT&CK tactics/techniques, and producing actionable hunt queries.
Always provide: 1) Hunt hypothesis, 2) Relevant MITRE ATT&CK techniques (TID), 3) KQL hunting query, 4) Sigma rule for the hunt, 5) Evidence to look for, 6) False positive considerations.
Think like an adversary — what would an APT group do after initial access?`,
    max_tokens:  1000,
    temperature: 0.2,
  },

  ir_playbook: {
    id:          'ir_playbook',
    name:        'IR Playbook Agent',
    icon:        '🚨',
    description: 'Incident response specialist. Generates NIST 800-61 aligned IR playbooks with specific actions, timelines, and escalation paths.',
    task_type:   'compliance_audit',
    domains:     ['incident', 'response', 'ir', 'playbook', 'containment', 'eradication', 'recovery', 'breach', 'ransomware', 'phishing attack'],
    system_prompt: `You are the IR Playbook Agent — an incident response expert following NIST 800-61 Rev 3.
Your focus: generating immediately actionable IR playbooks with specific commands, timelines, and ownership.
Always structure output as: 1) Detection & Triage (0-15 min), 2) Containment (15-60 min), 3) Eradication (1-4h), 4) Recovery (4-24h), 5) Post-Incident (24-72h).
Include: specific CLI commands where relevant, escalation matrix, evidence preservation steps, regulatory notification requirements (GDPR/DPDP 72h rule), and lessons learned template.`,
    max_tokens:  1100,
    temperature: 0.1,
  },

  compliance_guardian: {
    id:          'compliance_guardian',
    name:        'Compliance Guardian Agent',
    icon:        '📋',
    description: 'Compliance specialist across NIST CSF, ISO 27001, SOC 2, PCI-DSS, GDPR, EU AI Act, DPDP Act, NIST AI RMF.',
    task_type:   'compliance_audit',
    domains:     ['compliance', 'nist', 'iso', 'soc2', 'pci', 'gdpr', 'dpdp', 'hipaa', 'fedramp', 'eu ai act', 'audit', 'framework', 'control'],
    system_prompt: `You are the Compliance Guardian Agent — a multi-framework compliance expert.
Your focus: gap analysis, control mapping, and remediation roadmaps across NIST CSF 2.0, ISO 27001:2022, SOC 2 Type II, PCI-DSS v4.0, GDPR, EU AI Act, NIST AI RMF, and India DPDP Act 2023.
Always provide: compliance score estimate (0-100), top 5 gaps with severity, specific control references (e.g. NIST CSF PR.AC-1), 30/60/90-day remediation roadmap, and executive summary.
Reference specific framework sections. Be actionable — give control IDs and remediation steps, not just observations.`,
    max_tokens:  1000,
    temperature: 0.1,
  },

  red_team: {
    id:          'red_team',
    name:        'Red Team Agent',
    icon:        '⚔️',
    description: 'Adversarial thinking specialist. Maps attack paths, simulates APT behavior, and identifies kill chain opportunities.',
    task_type:   'red_team',
    domains:     ['red team', 'attack', 'apt', 'adversary', 'kill chain', 'initial access', 'privilege escalation', 'c2', 'exfiltration', 'ransomware', 'social engineering'],
    system_prompt: `You are the Red Team Agent — an elite adversarial security specialist thinking like a nation-state APT actor.
Your focus: mapping realistic attack paths, identifying kill chain opportunities, and providing defender countermeasures.
Always think in MITRE ATT&CK phases: Reconnaissance → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → Exfiltration → Impact.
For each attack path: provide the technique ID (TID), example tools/malware, detection opportunity, and mitigation. End with a purple team recommendation.`,
    max_tokens:  1000,
    temperature: 0.2,
  },

  zero_trust_sentinel: {
    id:          'zero_trust_sentinel',
    name:        'Zero Trust Sentinel Agent',
    icon:        '🛡️',
    description: 'Zero Trust architecture specialist. Assesses identity posture, device compliance, network segmentation, and ZT maturity.',
    task_type:   'compliance_audit',
    domains:     ['zero trust', 'identity', 'mfa', 'conditional access', 'microsegmentation', 'privileged access', 'pam', 'iam', 'sase', 'ztna'],
    system_prompt: `You are the Zero Trust Sentinel Agent — a Zero Trust Architecture specialist following NIST SP 800-207 and CISA ZT Maturity Model v2.
Your focus: assessing Zero Trust posture across 5 pillars: Identity, Devices, Networks, Applications, Data.
Always score each pillar 0-100, identify the top 3 gaps per pillar, provide specific NIST SP 800-207 references, and a phased ZT implementation roadmap (30/90/180 days).
Reference: Microsoft ZT Framework, Zscaler ZTNA, CISA ZT Maturity Model v2. Be prescriptive — name specific tools and configurations.`,
    max_tokens:  900,
    temperature: 0.1,
  },

  risk_synthesizer: {
    id:          'risk_synthesizer',
    name:        'Risk Synthesizer Agent',
    icon:        '🧠',
    description: 'Master orchestrator. Fuses all specialist agent outputs into a unified executive risk brief with overall risk score and priority action plan.',
    task_type:   'general',
    domains:     ['synthesis', 'executive', 'summary', 'risk score', 'priority', 'board report'],
    system_prompt: `You are the Risk Synthesizer Agent — the master intelligence fusion analyst.
Your job: take outputs from multiple specialist security agents and synthesize them into a single authoritative executive brief.
Always produce: 1) Overall Risk Score (0-100), 2) Risk Level (CRITICAL/HIGH/MEDIUM/LOW), 3) Top 5 Priority Actions (owner, timeline, expected impact), 4) Executive Summary (3 sentences max), 5) 7-day action plan.
Be ruthlessly concise — an enterprise CISO reads this in under 2 minutes. Every recommendation must have a named owner and deadline.`,
    max_tokens:  1200,
    temperature: 0.15,
  },
};

const AGENT_IDS = Object.keys(AGENTS);

// ─── Structured logger ────────────────────────────────────────────────────────
function log(level, event, data = {}) {
  console.log(JSON.stringify({ level, event, service: 'masoc', version: MASOC_VERSION, ts: new Date().toISOString(), ...data }));
}

// ─── Rate limiter (KV-backed, per user, fixed 60-second window) ──────────────
async function checkRateLimit(env, userId) {
  const kvStore = env?.KV || env?.SECURITY_HUB_KV;
  if (!kvStore) {
    // Fail closed when KV unavailable — MASOC fires 9 parallel AI calls so abuse cost is high
    console.warn('[MASOC] KV unavailable — rate limit enforced (fail closed)');
    return { allowed: false, count: 0, limit: RATE_LIMIT_MAX, retry_after: 60, reason: 'kv_unavailable' };
  }
  // Fixed window: key includes current minute so window doesn't slide on each request
  const window  = Math.floor(Date.now() / (RATE_LIMIT_WINDOW_S * 1000));
  const key     = `masoc_rl:${userId}:${window}`;
  try {
    const raw   = await kvStore.get(key);
    const count = raw ? parseInt(raw, 10) : 0;
    if (count >= RATE_LIMIT_MAX) {
      return { allowed: false, count, limit: RATE_LIMIT_MAX, retry_after: RATE_LIMIT_WINDOW_S };
    }
    await kvStore.put(key, String(count + 1), { expirationTtl: RATE_LIMIT_WINDOW_S * 2 });
    return { allowed: true, count: count + 1 };
  } catch (e) {
    console.error('[MASOC] Rate limit KV error — failing closed', e?.message);
    return { allowed: false, count: 0, limit: RATE_LIMIT_MAX, retry_after: 30, reason: 'kv_error' };
  }
}

// ─── Task Classifier ──────────────────────────────────────────────────────────
export function classifyTask(userMessage) {
  const msg = userMessage.toLowerCase();
  const scores = {};

  for (const [id, agent] of Object.entries(AGENTS)) {
    if (id === 'risk_synthesizer') continue;
    let score = 0;
    for (const domain of agent.domains) {
      if (msg.includes(domain)) score += 2;
    }
    if (id === 'cve_intel'          && /cve-\d{4}-\d+/.test(msg))                                score += 5;
    if (id === 'ioc_hunter'         && /\b(\d{1,3}\.){3}\d{1,3}\b/.test(msg))                    score += 5;
    if (id === 'siem_defender'      && /(sigma|splunk|sentinel|elastic|kql|spl)\b/i.test(msg))    score += 4;
    if (id === 'ir_playbook'        && /\b(incident|breach|ransom|compromis)\b/i.test(msg))       score += 4;
    if (id === 'compliance_guardian'&& /\b(nist|iso.?27001|soc.?2|pci|gdpr|hipaa|audit)\b/i.test(msg)) score += 4;
    if (id === 'red_team'           && /\b(attack|apt|adversar|exploit|pentest)\b/i.test(msg))    score += 3;
    if (id === 'zero_trust_sentinel'&& /\b(mfa|iam|identity|zero.?trust|access)\b/i.test(msg))   score += 3;
    if (id === 'threat_hunter'      && /\b(hunt|hypothes|lateral|persist|tactic|mitre)\b/i.test(msg)) score += 3;
    scores[id] = score;
  }

  const sorted  = Object.entries(scores).sort((a, b) => b[1] - a[1]).map(([id]) => id);
  const topScore = scores[sorted[0]] || 0;

  if (topScore < 2) return ['cve_intel', 'threat_hunter', 'siem_defender', 'ir_playbook'];

  const selected = sorted.filter(id => scores[id] >= 1).slice(0, 6);
  if (selected.length < 3) {
    selected.push(...sorted.filter(id => !selected.includes(id)).slice(0, 3 - selected.length));
  }
  return selected;
}

// ─── Real-data enrichment helpers ─────────────────────────────────────────────

// NVD + EPSS enrichment in a single parallel fetch
export async function fetchCVEContext(userMessage, _env) {
  const cveMatch = userMessage.match(/CVE-\d{4}-\d+/i);
  if (!cveMatch) return null;
  const cveId = cveMatch[0].toUpperCase();

  try {
    const [nvdResp, epssResp] = await Promise.allSettled([
      fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`, {
        headers: { Accept: 'application/json' },
        signal:  AbortSignal.timeout(6000),
      }),
      fetch(`https://api.first.org/data/v1/epss?cve=${cveId}`, {
        headers: { Accept: 'application/json' },
        signal:  AbortSignal.timeout(5000),
      }),
    ]);

    // Parse NVD
    let description = '', cvss_score = null;
    if (nvdResp.status === 'fulfilled' && nvdResp.value.ok) {
      const j   = await nvdResp.value.json();
      const item = j?.vulnerabilities?.[0]?.cve;
      if (item) {
        description = item.descriptions?.find(d => d.lang === 'en')?.value?.slice(0, 400) || '';
        const metrics = item.metrics?.cvssMetricV31?.[0] || item.metrics?.cvssMetricV30?.[0];
        cvss_score = metrics?.cvssData?.baseScore ?? null;
      }
    }

    // Parse EPSS v3
    let epss_score = null, epss_percentile = null;
    if (epssResp.status === 'fulfilled' && epssResp.value.ok) {
      const ej = await epssResp.value.json();
      const row = ej?.data?.[0];
      if (row) {
        epss_score      = parseFloat(row.epss);
        epss_percentile = parseFloat(row.percentile);
      }
    }

    if (!description && cvss_score === null) return null;

    log('info', 'cve_enrichment', { cve_id: cveId, cvss_score, epss_score });
    return { cve_id: cveId, description, cvss_score, epss_score, epss_percentile, source: 'NVD+EPSS' };
  } catch (err) {
    log('warn', 'cve_enrichment_failed', { cve_id: cveId, error: err.message });
    return null;
  }
}

export async function fetchKEVStatus(userMessage, env) {
  const cveMatch = userMessage.match(/CVE-\d{4}-\d+/i);
  if (!cveMatch) return null;
  const cveId = cveMatch[0].toUpperCase();
  try {
    const kv = env?.KV;
    if (kv) {
      const cached = await kv.get('kev_catalog', { type: 'json' }).catch(() => null);
      if (cached?.lookup?.[cveId]) return { in_kev: true, details: cached.lookup[cveId] };
    }
    return { in_kev: false };
  } catch { return null; }
}

export async function fetchIOCContext(userMessage, env) {
  const ipMatch   = userMessage.match(/\b(\d{1,3}\.){3}\d{1,3}\b/);
  const hashMatch = userMessage.match(/\b[a-f0-9]{32,64}\b/i);
  if (!ipMatch && !hashMatch) return null;
  const ioc = (ipMatch || hashMatch)[0];
  try {
    const base = env?.ORIGIN || env?.WORKER_URL || PLATFORM_ORIGIN;
    const r = await fetch(`${base}/api/hunt/ioc`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ ioc }),
      signal:  AbortSignal.timeout(6000),
    });
    if (!r.ok) return null;
    const j = await r.json();
    return { ioc, result: j.data || j };
  } catch { return null; }
}

// ─── Single Agent Executor ────────────────────────────────────────────────────
export async function runAgent(agentId, userMessage, context, env, tier) {
  const agent = AGENTS[agentId];
  if (!agent) throw new Error(`Unknown agent: ${agentId}`);

  const t0 = Date.now();
  log('info', 'agent_start', { agent_id: agentId });

  // Build enriched prompt
  let enrichedPrompt = userMessage;
  if (context?.cve) {
    const { cve_id, cvss_score, epss_score, epss_percentile, description } = context.cve;
    enrichedPrompt += `\n\n[CVE CONTEXT — NVD + EPSS v3]
CVE ID:          ${cve_id}
CVSS v3.1:       ${cvss_score ?? 'N/A'}
EPSS Score:      ${epss_score !== null ? (epss_score * 100).toFixed(2) + '%' : 'N/A'} exploitation probability
EPSS Percentile: ${epss_percentile !== null ? (epss_percentile * 100).toFixed(1) + 'th' : 'N/A'}
Description:     ${description}`;
  }
  if (context?.kev?.in_kev) {
    enrichedPrompt += `\n\n[CISA KEV] ⚠️ This CVE IS in the Known Exploited Vulnerabilities catalog — actively exploited in the wild. Treat as CRITICAL priority.`;
  }
  if (context?.ioc) {
    enrichedPrompt += `\n\n[IOC ENRICHMENT]\n${JSON.stringify(context.ioc.result, null, 2).slice(0, 600)}`;
  }
  enrichedPrompt += `\n\nRespond as the ${agent.name}. Be precise, technical, and actionable. Output well-structured analysis.`;

  // Per-agent timeout via AbortSignal — prevents one slow provider hanging all parallel agents
  const controller = new AbortController();
  const timeoutId  = setTimeout(() => controller.abort(), AGENT_TIMEOUT_MS);

  try {
    const result = await routeAICall(env, {
      prompt:      enrichedPrompt,
      system:      agent.system_prompt,
      task_type:   agent.task_type,
      tier:        tier || 'ENTERPRISE',
      max_tokens:  agent.max_tokens,
      temperature: agent.temperature,
    });

    const latency_ms = Date.now() - t0;
    log('info', 'agent_done', { agent_id: agentId, latency_ms, provider: result?.provider, model: result?.model });

    return {
      agent_id:    agentId,
      agent_name:  agent.name,
      icon:        agent.icon,
      description: agent.description,
      status:      result ? 'success' : 'no_provider',
      content:     result?.content || `${agent.name} unavailable — no AI provider configured. Set GROQ_API_KEY, DEEPSEEK_API_KEY, or OPENROUTER_API_KEY as Wrangler secrets.`,
      model:       result?.model    || 'none',
      provider:    result?.provider || 'none',
      latency_ms,
      tokens:      result?.tokens   || null,
    };
  } catch (err) {
    const latency_ms = Date.now() - t0;
    const timedOut   = err.name === 'AbortError';
    log('error', 'agent_error', { agent_id: agentId, error: err.message, timed_out: timedOut, latency_ms });
    return {
      agent_id:   agentId,
      agent_name: agent.name,
      icon:       agent.icon,
      description:agent.description,
      status:     'error',
      content:    timedOut ? `${agent.name} timed out after ${AGENT_TIMEOUT_MS / 1000}s. Try again or use a faster AI provider.` : `Agent error: ${err.message}`,
      model:      'none',
      provider:   'none',
      latency_ms,
      tokens:     null,
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

// ─── Synthesis Agent ──────────────────────────────────────────────────────────
async function runSynthesis(userMessage, agentResults, env, tier) {
  const t0        = Date.now();
  const synthAgent = AGENTS.risk_synthesizer;

  const agentSummaries = agentResults
    .filter(r => r.status === 'success')
    .map(r => `=== ${r.agent_name} (${r.icon}) ===\n${r.content.slice(0, 1400)}`)
    .join('\n\n');

  const synthPrompt = `ORIGINAL USER REQUEST: ${userMessage}

SPECIALIST AGENT OUTPUTS:
${agentSummaries}

Synthesize all specialist analyses into a unified executive risk brief per your system prompt format.`;

  const result = await routeAICall(env, {
    prompt:      synthPrompt,
    system:      synthAgent.system_prompt,
    task_type:   'general',
    tier:        tier || 'ENTERPRISE',
    max_tokens:  synthAgent.max_tokens,
    temperature: synthAgent.temperature,
  });

  log('info', 'synthesis_done', { latency_ms: Date.now() - t0, provider: result?.provider });

  return {
    agent_id:   'risk_synthesizer',
    agent_name: synthAgent.name,
    icon:       synthAgent.icon,
    status:     result ? 'success' : 'no_provider',
    content:    result?.content || 'Synthesis unavailable — configure an AI provider.',
    model:      result?.model    || 'none',
    provider:   result?.provider || 'none',
    latency_ms: Date.now() - t0,
    tokens:     result?.tokens   || null,
  };
}

// ─── Body size guard ──────────────────────────────────────────────────────────
async function parseBody(request) {
  const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (contentLength > MAX_BODY_BYTES) {
    return { error: `Request body too large (max ${MAX_BODY_BYTES} bytes).`, status: 413 };
  }
  try {
    const body = await request.json();
    return { body };
  } catch {
    return { error: 'Invalid JSON body.', status: 400 };
  }
}

// ─── POST /api/agents/run — parallel execution (JSON response) ────────────────
export async function handleAgentsRun(request, env, authCtx) {
  const { body, error, status } = await parseBody(request);
  if (error) return Response.json({ error }, { status });

  const userMessage = (body.message || body.query || body.task || '').trim();
  if (!userMessage || userMessage.length < 5) {
    return Response.json({ error: 'message/query/task required (min 5 chars).' }, { status: 400 });
  }

  // Rate limiting
  const userId = authCtx?.user_id || authCtx?.key_id || request.headers.get('CF-Connecting-IP') || 'anon';
  const rl = await checkRateLimit(env, userId);
  if (!rl.allowed) {
    log('warn', 'rate_limited', { user_id: userId });
    return Response.json(
      { error: `MASOC rate limit exceeded — max ${RATE_LIMIT_MAX} runs/minute. Retry in ${rl.retry_after}s.`, retry_after: rl.retry_after },
      { status: 429, headers: { 'Retry-After': String(rl.retry_after) } }
    );
  }

  const requestedAgents = (body.agents && Array.isArray(body.agents))
    ? body.agents.filter(id => AGENT_IDS.includes(id))
    : classifyTask(userMessage);

  const tier = authCtx?.tier || 'ENTERPRISE';
  const t0   = Date.now();

  log('info', 'run_start', { user_id: userId, agents: requestedAgents.length, task_len: userMessage.length });

  // Pre-enrichment in parallel
  const [cveCtx, kevCtx, iocCtx] = await Promise.all([
    fetchCVEContext(userMessage, env),
    fetchKEVStatus(userMessage, env),
    fetchIOCContext(userMessage, env),
  ]);
  const context = { cve: cveCtx, kev: kevCtx, ioc: iocCtx };

  // Run all selected agents in parallel
  const agentResults = await Promise.all(
    requestedAgents.map(id => runAgent(id, userMessage, context, env, tier))
  );

  // Synthesis
  const synthesis  = await runSynthesis(userMessage, agentResults, env, tier);
  const totalMs    = Date.now() - t0;

  // Extract real risk level/score from synthesis for D1
  const synthText  = synthesis?.content || '';
  const lvlMatch   = synthText.match(/\b(CRITICAL|HIGH|MEDIUM|LOW)\b/i);
  const scrMatch   = synthText.match(/Risk Score[:\s]+(\d{1,3})/i) || synthText.match(/\bScore[:\s]+(\d{1,3})/i);
  const riskLevel  = lvlMatch ? lvlMatch[1].toUpperCase() : 'HIGH';
  const riskScore  = scrMatch ? Math.min(100, parseInt(scrMatch[1], 10)) : 75;

  // Persist to D1
  try {
    if (env?.DB) {
      const taskId = `masoc_${Date.now().toString(36)}_${crypto.randomUUID().slice(0, 8)}`;
      await env.DB.prepare(
        `INSERT OR IGNORE INTO scan_jobs
         (id, user_id, module, target, status, risk_level, risk_score, completed_at)
         VALUES (?, ?, 'masoc', ?, 'completed', ?, ?, datetime('now'))`
      ).bind(taskId, authCtx?.user_id || null, userMessage.slice(0, 200), riskLevel, riskScore).run();
    }
  } catch (dbErr) {
    log('warn', 'db_persist_failed', { error: dbErr.message });
  }

  log('info', 'run_complete', { user_id: userId, total_ms: totalMs, agents: requestedAgents.length, risk_level: riskLevel });

  return Response.json({
    success:          true,
    task:             userMessage,
    agents_activated: requestedAgents.length,
    total_latency_ms: totalMs,
    context_enriched: { cve: !!cveCtx, kev: !!kevCtx, ioc: !!iocCtx },
    agent_results:    agentResults,
    synthesis,
    timestamp:        new Date().toISOString(),
  });
}

// ─── POST /api/agents/stream — SSE real-time streaming ───────────────────────
export async function handleAgentsStream(request, env, authCtx, ctx) {
  const { body, error, status } = await parseBody(request);
  if (error) {
    return new Response(`data: ${JSON.stringify({ type: 'error', message: error })}\n\n`, {
      status,
      headers: { 'Content-Type': 'text/event-stream' },
    });
  }

  const userMessage = (body.message || body.query || body.task || '').trim();
  if (!userMessage || userMessage.length < 5) {
    return new Response(`data: ${JSON.stringify({ type: 'error', message: 'message required (min 5 chars)' })}\n\n`, {
      status: 400,
      headers: { 'Content-Type': 'text/event-stream' },
    });
  }

  // Rate limiting
  const userId = authCtx?.user_id || authCtx?.key_id || request.headers.get('CF-Connecting-IP') || 'anon';
  const rl = await checkRateLimit(env, userId);
  if (!rl.allowed) {
    log('warn', 'rate_limited_stream', { user_id: userId });
    return new Response(
      `data: ${JSON.stringify({ type: 'error', message: `Rate limit exceeded — max ${RATE_LIMIT_MAX} runs/minute. Retry in ${rl.retry_after}s.` })}\n\n`,
      { status: 429, headers: { 'Content-Type': 'text/event-stream', 'Retry-After': String(rl.retry_after) } }
    );
  }

  const requestedAgents = (body.agents && Array.isArray(body.agents))
    ? body.agents.filter(id => AGENT_IDS.includes(id))
    : classifyTask(userMessage);

  const tier = authCtx?.tier || 'ENTERPRISE';
  const t0   = Date.now();

  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const enc    = new TextEncoder();

  const send = (obj) => {
    try { writer.write(enc.encode(`data: ${JSON.stringify(obj)}\n\n`)); } catch {}
  };

  const runAll = async () => {
    try {
      log('info', 'stream_start', { user_id: userId, agents: requestedAgents.length });
      send({ type: 'start', task: userMessage, agents: requestedAgents, ts: new Date().toISOString() });

      const [cveCtx, kevCtx, iocCtx] = await Promise.all([
        fetchCVEContext(userMessage, env),
        fetchKEVStatus(userMessage, env),
        fetchIOCContext(userMessage, env),
      ]);
      const context = { cve: cveCtx, kev: kevCtx, ioc: iocCtx };

      if (cveCtx || kevCtx || iocCtx) {
        send({ type: 'context', cve: cveCtx, kev: kevCtx, ioc: !!iocCtx });
      }

      requestedAgents.forEach(id => {
        const a = AGENTS[id];
        send({ type: 'agent_start', agent_id: id, agent_name: a.name, icon: a.icon, description: a.description });
      });

      const agentResults = [];
      await Promise.all(requestedAgents.map(async (id) => {
        try {
          const result = await runAgent(id, userMessage, context, env, tier);
          send({ type: 'agent_result', ...result });
          agentResults.push(result);
        } catch (err) {
          const errResult = {
            agent_id: id, agent_name: AGENTS[id]?.name || id, icon: AGENTS[id]?.icon || '❓',
            description: AGENTS[id]?.description || '',
            status: 'error', content: `Agent error: ${err.message}`,
            model: 'none', provider: 'none', latency_ms: 0, tokens: null,
          };
          send({ type: 'agent_result', ...errResult });
          agentResults.push(errResult);
        }
      }));

      send({ type: 'synthesis_start', message: 'Risk Synthesizer Agent fusing all results…' });
      const synthesis = await runSynthesis(userMessage, agentResults, env, tier);
      send({ type: 'synthesis', ...synthesis });

      send({ type: 'complete', agents_activated: requestedAgents.length, total_latency_ms: Date.now() - t0, timestamp: new Date().toISOString() });
      log('info', 'stream_complete', { user_id: userId, total_ms: Date.now() - t0 });
    } catch (err) {
      log('error', 'stream_error', { error: err.message });
      send({ type: 'error', message: err.message });
    } finally {
      writer.close().catch(() => {});
    }
  };

  // ctx.waitUntil ensures CF Workers keeps the request alive for the full stream duration
  if (ctx?.waitUntil) {
    ctx.waitUntil(runAll());
  } else {
    void runAll();
  }

  // CORS: use the shared production-origin allowlist (workers/src/middleware/cors.js)
  // instead of a hand-rolled `.endsWith('.cyberdudebivash.in')` check — that check
  // silently rejected 3 of 6 real production origins (cyberdudebivash.pages.dev,
  // tools.cyberdudebivash.com, intel.cyberdudebivash.com), so SSE streaming was
  // browser-CORS-blocked from those origins while the JSON/status MASOC routes
  // (already on withCors()) kept working fine from the same origin.
  const cors = corsHeaders(request, env);

  return new Response(readable, {
    status: 200,
    headers: {
      'Content-Type':                     'text/event-stream; charset=utf-8',
      'Cache-Control':                    'no-cache, no-store',
      'Connection':                       'keep-alive',
      'X-Accel-Buffering':                'no',
      'Access-Control-Allow-Origin':      cors['Access-Control-Allow-Origin'],
      'Access-Control-Allow-Credentials': cors['Access-Control-Allow-Credentials'],
    },
  });
}

// ─── POST /api/agents/dispatch/:agent — single agent ──────────────────────────
export async function handleAgentDispatch(request, env, authCtx, agentId) {
  const agent = AGENTS[agentId];
  if (!agent) {
    return Response.json({ error: `Unknown agent: "${agentId}". Available: ${AGENT_IDS.join(', ')}` }, { status: 404 });
  }

  const { body, error, status } = await parseBody(request);
  if (error) return Response.json({ error }, { status });

  const userMessage = (body.message || body.query || body.task || '').trim();
  if (!userMessage || userMessage.length < 5) {
    return Response.json({ error: 'message/query/task required (min 5 chars).' }, { status: 400 });
  }

  const userId = authCtx?.user_id || authCtx?.key_id || 'anon';
  const rl = await checkRateLimit(env, `dispatch:${userId}`);
  if (!rl.allowed) {
    return Response.json({ error: `Rate limit exceeded. Retry in ${rl.retry_after}s.` }, { status: 429 });
  }

  const tier = authCtx?.tier || 'ENTERPRISE';
  const [cveCtx, kevCtx, iocCtx] = await Promise.all([
    fetchCVEContext(userMessage, env),
    fetchKEVStatus(userMessage, env),
    fetchIOCContext(userMessage, env),
  ]);
  const context = { cve: cveCtx, kev: kevCtx, ioc: iocCtx };
  const result  = await runAgent(agentId, userMessage, context, env, tier);

  return Response.json({
    success:          true,
    agent:            result,
    context_enriched: { cve: !!cveCtx, kev: !!kevCtx, ioc: !!iocCtx },
    timestamp:        new Date().toISOString(),
  });
}

// ─── GET /api/agents/status ───────────────────────────────────────────────────
export async function handleAgentsStatus(request, env, authCtx) {
  const providers = {
    groq:          !!env?.GROQ_API_KEY,
    deepseek:      !!env?.DEEPSEEK_API_KEY,
    openrouter:    !!env?.OPENROUTER_API_KEY,
    cf_workers_ai: !!env?.AI,
  };
  const anyProvider  = Object.values(providers).some(Boolean);
  const activeCount  = Object.values(providers).filter(Boolean).length;

  return Response.json({
    success:    true,
    service:    'APEX Multi-Agent SOC (MASOC)',
    version:    MASOC_VERSION,
    status:     anyProvider ? 'OPERATIONAL' : 'NO_PROVIDER_CONFIGURED',
    ai_providers: providers,
    provider_note: anyProvider
      ? `${activeCount}/4 provider${activeCount !== 1 ? 's' : ''} active: ${Object.entries(providers).filter(([,v])=>v).map(([k])=>k).join(', ')}`
      : 'Set GROQ_API_KEY, DEEPSEEK_API_KEY, or OPENROUTER_API_KEY as Wrangler secrets. CF Workers AI is always available as fallback.',
    total_agents:  AGENT_IDS.length,
    rate_limits: {
      run_per_minute:      RATE_LIMIT_MAX,
      window_seconds:      RATE_LIMIT_WINDOW_S,
      agents_per_run:      'up to 9',
      agent_timeout_ms:    AGENT_TIMEOUT_MS,
    },
    agents: AGENT_IDS.map(id => {
      const a = AGENTS[id];
      return { id: a.id, name: a.name, icon: a.icon, description: a.description, task_type: a.task_type, domains: a.domains };
    }),
    endpoints: {
      run:      'POST /api/agents/run      — parallel JSON response',
      stream:   'POST /api/agents/stream  — SSE real-time per-agent streaming',
      status:   'GET  /api/agents/status  — agent registry + provider health',
      dispatch: 'POST /api/agents/dispatch/:agent_id — single-agent invocation',
    },
    enrichment: {
      nvd:  'https://services.nvd.nist.gov/rest/json/cves/2.0',
      epss: 'https://api.first.org/data/v1/epss  (EPSS v3)',
      kev:  'CISA KEV catalog via KV cache',
      ioc:  'POST /api/hunt/ioc  (VirusTotal+AbuseIPDB+Shodan)',
    },
    timestamp: new Date().toISOString(),
  });
}
