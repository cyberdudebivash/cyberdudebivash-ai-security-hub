/**
 * CYBERDUDEBIVASH AI Security Hub — APEX Multi-Agent SOC (MASOC) v1.0
 *
 * Architecture: 9 specialist AI agents dispatched in parallel via Promise.all()
 * Each agent has its own system prompt, AI provider routing, tool set, and domain expertise.
 * An Orchestrator classifies the user task and activates the relevant subset of agents.
 * A Synthesis Agent fuses all parallel results into a unified executive brief.
 *
 * Agents:
 *   1. CVE_Intel_Agent         — NVD/KEV/EPSS threat intelligence & CVE enrichment
 *   2. IOC_Hunter_Agent        — VirusTotal/AbuseIPDB/Shodan IOC enrichment
 *   3. SIEM_Defender_Agent     — Detection rule generation & SIEM deployment
 *   4. Threat_Hunt_Agent       — MITRE ATT&CK hunt templates & correlation
 *   5. IR_Playbook_Agent       — NIST 800-61 incident response playbook generation
 *   6. Compliance_Guardian     — NIST/ISO/SOC2/PCI/GDPR compliance gap analysis
 *   7. RedTeam_Agent           — Attack path mapping & adversarial scenario analysis
 *   8. ZeroTrust_Sentinel      — Zero Trust posture & anomaly assessment
 *   9. Risk_Synthesizer        — Fuses all agent outputs → executive brief + risk score
 *
 * Endpoints:
 *   POST /api/agents/run       — parallel multi-agent execution (JSON response)
 *   POST /api/agents/stream    — streaming multi-agent SSE (real-time agent results)
 *   GET  /api/agents/status    — agent registry, capabilities, AI provider health
 *   POST /api/agents/dispatch/:agent — direct single-agent invocation
 *
 * AI Provider Routing per agent:
 *   CVE Intel / IOC / Red Team → DeepSeek V3 (best technical reasoning)
 *   Compliance / IR Playbook   → Groq 70B (structured prose + NIST frameworks)
 *   SIEM / Hunt                → Groq R1 (reasoning for rule correctness)
 *   Zero Trust / Risk Synth    → Groq 70B (executive-grade output)
 *   Fallback chain             → OpenRouter → CF Workers AI
 *
 * Cloudflare Workers compatibility:
 *   - All parallelism via Promise.all() — no threads needed
 *   - SSE streaming via ReadableStream/TransformStream
 *   - State via D1 (persistent task history) + KV (session cache)
 *   - AI via existing env.AI (CF Workers AI), GROQ_API_KEY, DEEPSEEK_API_KEY, OPENROUTER_API_KEY
 */

import { routeAICall } from '../core/aiProviderRouter.js';

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
Always provide: CVE ID, CVSS score, EPSS score, KEV status (exploited in the wild), severity, affected products, and a 3-bullet remediation plan.
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
    task_type:   'detection',
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
    task_type:   'compliance',
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
    task_type:   'compliance',
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
    task_type:   'redteam',
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
    task_type:   'compliance',
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

// ─── Task Classifier ──────────────────────────────────────────────────────────
// Determines which agents are relevant for a given user request.
// Returns an ordered subset of AGENT_IDS to activate.
function classifyTask(userMessage) {
  const msg = userMessage.toLowerCase();
  const scores = {};

  for (const [id, agent] of Object.entries(AGENTS)) {
    if (id === 'risk_synthesizer') continue; // always runs last
    let score = 0;
    for (const domain of agent.domains) {
      if (msg.includes(domain)) score += 2;
    }
    // Boost for strong exact matches
    if (id === 'cve_intel'          && /cve-\d{4}-\d+/.test(msg)) score += 5;
    if (id === 'ioc_hunter'         && /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(msg)) score += 5;
    if (id === 'siem_defender'      && /(sigma|splunk|sentinel|elastic|kql|spl)\b/i.test(msg)) score += 4;
    if (id === 'ir_playbook'        && /\b(incident|breach|ransom|compromis)\b/i.test(msg)) score += 4;
    if (id === 'compliance_guardian'&& /\b(nist|iso.?27001|soc.?2|pci|gdpr|hipaa|audit)\b/i.test(msg)) score += 4;
    if (id === 'red_team'           && /\b(attack|apt|adversar|exploit|pentest)\b/i.test(msg)) score += 3;
    if (id === 'zero_trust_sentinel'&& /\b(mfa|iam|identity|zero.?trust|access)\b/i.test(msg)) score += 3;
    if (id === 'threat_hunter'      && /\b(hunt|hypothes|lateral|persist|tactic|mitre)\b/i.test(msg)) score += 3;
    scores[id] = score;
  }

  // Sort agents by relevance score
  const sorted = Object.entries(scores)
    .sort((a, b) => b[1] - a[1])
    .map(([id]) => id);

  // For broad queries (low scores), activate the core 4
  const topScore = scores[sorted[0]] || 0;
  if (topScore < 2) {
    // Default: activate all relevant security agents for broad security questions
    return ['cve_intel', 'threat_hunter', 'siem_defender', 'ir_playbook'];
  }

  // Activate agents with score ≥ 1, up to 6 (keep runtime fast)
  const selected = sorted.filter(id => scores[id] >= 1).slice(0, 6);
  // Always include at minimum 3 agents for rich context
  if (selected.length < 3) {
    const fill = sorted.filter(id => !selected.includes(id)).slice(0, 3 - selected.length);
    selected.push(...fill);
  }
  return selected;
}

// ─── Real-data enrichment helpers ────────────────────────────────────────────
// These pull real data to augment agent prompts before AI inference.

async function fetchCVEContext(userMessage, env) {
  const cveMatch = userMessage.match(/CVE-\d{4}-\d+/i);
  if (!cveMatch) return null;
  const cveId = cveMatch[0].toUpperCase();
  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
    const r = await fetch(url, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) return null;
    const j = await r.json();
    const item = j?.vulnerabilities?.[0]?.cve;
    if (!item) return null;
    const desc = item.descriptions?.find(d => d.lang === 'en')?.value || '';
    const metrics = item.metrics?.cvssMetricV31?.[0] || item.metrics?.cvssMetricV30?.[0];
    const cvss = metrics?.cvssData?.baseScore;
    return { cve_id: cveId, description: desc.slice(0, 400), cvss_score: cvss, source: 'NVD' };
  } catch { return null; }
}

async function fetchKEVStatus(userMessage, env) {
  const cveMatch = userMessage.match(/CVE-\d{4}-\d+/i);
  if (!cveMatch) return null;
  const cveId = cveMatch[0].toUpperCase();
  try {
    const kv = env?.SECURITY_HUB_KV;
    if (kv) {
      const cached = await kv.get('kev_catalog', { type: 'json' }).catch(() => null);
      if (cached?.lookup?.[cveId]) {
        return { in_kev: true, details: cached.lookup[cveId] };
      }
    }
    return { in_kev: false };
  } catch { return null; }
}

async function fetchIOCContext(userMessage, env) {
  const ipMatch   = userMessage.match(/\b(\d{1,3}\.){3}\d{1,3}\b/);
  const hashMatch = userMessage.match(/\b[a-f0-9]{32,64}\b/i);
  if (!ipMatch && !hashMatch) return null;
  const ioc = (ipMatch || hashMatch)[0];
  try {
    const base = env?.WORKER_URL || 'https://cyberdudebivash-security-hub.iambivash-bn.workers.dev';
    const r = await fetch(`${base}/api/hunt/ioc`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ioc }),
      signal: AbortSignal.timeout(6000),
    });
    if (!r.ok) return null;
    const j = await r.json();
    return { ioc, result: j.data || j };
  } catch { return null; }
}

// ─── Single Agent Executor ────────────────────────────────────────────────────
async function runAgent(agentId, userMessage, context, env, tier) {
  const agent = AGENTS[agentId];
  if (!agent) throw new Error(`Unknown agent: ${agentId}`);

  const t0 = Date.now();

  // Build enriched prompt
  let enrichedPrompt = userMessage;
  if (context?.cve) {
    enrichedPrompt += `\n\n[CVE CONTEXT FROM NVD]\nCVE ID: ${context.cve.cve_id}\nCVSS: ${context.cve.cvss_score}\nDescription: ${context.cve.description}`;
  }
  if (context?.kev?.in_kev) {
    enrichedPrompt += `\n\n[CISA KEV] This CVE IS in the Known Exploited Vulnerabilities catalog — actively exploited in the wild.`;
  }
  if (context?.ioc) {
    enrichedPrompt += `\n\n[IOC ENRICHMENT]\n${JSON.stringify(context.ioc.result, null, 2).slice(0, 600)}`;
  }

  enrichedPrompt += `\n\nRespond as the ${agent.name}. Be precise, technical, and actionable. Output well-structured analysis.`;

  const result = await routeAICall(env, {
    prompt:      enrichedPrompt,
    system:      agent.system_prompt,
    task_type:   agent.task_type,
    tier:        tier || 'ENTERPRISE',
    max_tokens:  agent.max_tokens,
    temperature: agent.temperature,
  });

  const latency_ms = Date.now() - t0;

  return {
    agent_id:    agentId,
    agent_name:  agent.name,
    icon:        agent.icon,
    description: agent.description,
    status:      result ? 'success' : 'no_provider',
    content:     result?.content || `${agent.name} could not respond — no AI provider configured. Set GROQ_API_KEY, DEEPSEEK_API_KEY, or OPENROUTER_API_KEY.`,
    model:       result?.model || 'none',
    provider:    result?.provider || 'none',
    latency_ms,
    tokens:      result?.tokens || null,
  };
}

// ─── Synthesis Agent ──────────────────────────────────────────────────────────
async function runSynthesis(userMessage, agentResults, env, tier) {
  const t0 = Date.now();
  const synthAgent = AGENTS.risk_synthesizer;

  const agentSummaries = agentResults
    .filter(r => r.status === 'success')
    .map(r => `=== ${r.agent_name} (${r.icon}) ===\n${r.content.slice(0, 800)}`)
    .join('\n\n');

  const synthPrompt = `ORIGINAL USER REQUEST: ${userMessage}

SPECIALIST AGENT OUTPUTS:
${agentSummaries}

Now synthesize all the above specialist analyses into a single unified executive risk brief. Follow your system prompt format exactly.`;

  const result = await routeAICall(env, {
    prompt:      synthPrompt,
    system:      synthAgent.system_prompt,
    task_type:   'general',
    tier:        tier || 'ENTERPRISE',
    max_tokens:  synthAgent.max_tokens,
    temperature: synthAgent.temperature,
  });

  return {
    agent_id:   'risk_synthesizer',
    agent_name: synthAgent.name,
    icon:       synthAgent.icon,
    status:     result ? 'success' : 'no_provider',
    content:    result?.content || 'Synthesis unavailable — configure an AI provider.',
    model:      result?.model || 'none',
    provider:   result?.provider || 'none',
    latency_ms: Date.now() - t0,
  };
}

// ─── POST /api/agents/run — parallel execution ────────────────────────────────
export async function handleAgentsRun(request, env, authCtx) {
  let body;
  try { body = await request.json(); } catch {
    return Response.json({ error: 'Invalid JSON body.' }, { status: 400 });
  }

  const userMessage = (body.message || body.query || body.task || '').trim();
  if (!userMessage || userMessage.length < 5) {
    return Response.json({ error: 'message/query/task required (min 5 chars).' }, { status: 400 });
  }

  // Determine which agents to run
  const requestedAgents = (body.agents && Array.isArray(body.agents))
    ? body.agents.filter(id => AGENT_IDS.includes(id))
    : classifyTask(userMessage);

  const tier = authCtx?.tier || 'ENTERPRISE';
  const t0   = Date.now();

  // Pull real-data context in parallel before running agents
  const [cveCtx, kevCtx, iocCtx] = await Promise.all([
    fetchCVEContext(userMessage, env),
    fetchKEVStatus(userMessage, env),
    fetchIOCContext(userMessage, env),
  ]);
  const context = { cve: cveCtx, kev: kevCtx, ioc: iocCtx };

  // Run all selected agents in parallel
  const agentPromises = requestedAgents.map(id => runAgent(id, userMessage, context, env, tier));
  const agentResults  = await Promise.all(agentPromises);

  // Run synthesis agent on all results
  const synthesis = await runSynthesis(userMessage, agentResults, env, tier);

  const totalMs = Date.now() - t0;

  // Persist task to D1 for history
  try {
    if (env?.DB) {
      const taskId = `masoc_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
      await env.DB.prepare(
        `INSERT OR IGNORE INTO scan_jobs
         (id, user_id, module, target, status, risk_level, risk_score, completed_at)
         VALUES (?, ?, 'masoc', ?, 'completed', 'HIGH', 75, datetime('now'))`
      ).bind(taskId, authCtx?.user_id || null, userMessage.slice(0, 200)).run();
    }
  } catch {}

  return Response.json({
    success:         true,
    task:            userMessage,
    agents_activated: requestedAgents.length,
    total_latency_ms: totalMs,
    context_enriched: { cve: !!cveCtx, kev: !!kevCtx, ioc: !!iocCtx },
    agent_results:   agentResults,
    synthesis,
    timestamp:       new Date().toISOString(),
  });
}

// ─── POST /api/agents/stream — SSE streaming ─────────────────────────────────
export async function handleAgentsStream(request, env, authCtx) {
  let body;
  try { body = await request.json(); } catch {
    return new Response('data: {"error":"Invalid JSON"}\n\n', {
      status: 400,
      headers: { 'Content-Type': 'text/event-stream' },
    });
  }

  const userMessage = (body.message || body.query || body.task || '').trim();
  if (!userMessage || userMessage.length < 5) {
    return new Response('data: {"error":"message required"}\n\n', {
      status: 400,
      headers: { 'Content-Type': 'text/event-stream' },
    });
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

  // Run everything in background (CF Workers: use ctx.waitUntil if available)
  const runAll = async () => {
    try {
      send({ type: 'start', task: userMessage, agents: requestedAgents, ts: new Date().toISOString() });

      // Enrich context
      const [cveCtx, kevCtx, iocCtx] = await Promise.all([
        fetchCVEContext(userMessage, env),
        fetchKEVStatus(userMessage, env),
        fetchIOCContext(userMessage, env),
      ]);
      const context = { cve: cveCtx, kev: kevCtx, ioc: iocCtx };

      if (cveCtx || kevCtx || iocCtx) {
        send({ type: 'context', cve: cveCtx, kev: kevCtx, ioc: !!iocCtx });
      }

      // Announce all agent activations
      requestedAgents.forEach(id => {
        const a = AGENTS[id];
        send({ type: 'agent_start', agent_id: id, agent_name: a.name, icon: a.icon, description: a.description });
      });

      // Run all agents in parallel and stream each result as it arrives
      const agentResults = [];
      const promises = requestedAgents.map(async (id) => {
        try {
          const result = await runAgent(id, userMessage, context, env, tier);
          send({ type: 'agent_result', ...result });
          agentResults.push(result);
        } catch (err) {
          const errResult = {
            agent_id: id, agent_name: AGENTS[id]?.name || id, icon: AGENTS[id]?.icon || '❓',
            status: 'error', content: `Agent error: ${err.message}`, latency_ms: 0,
          };
          send({ type: 'agent_result', ...errResult });
          agentResults.push(errResult);
        }
      });
      await Promise.all(promises);

      // Synthesis
      send({ type: 'synthesis_start', message: 'Risk Synthesizer Agent fusing all results…' });
      const synthesis = await runSynthesis(userMessage, agentResults, env, tier);
      send({ type: 'synthesis', ...synthesis });

      send({
        type:             'complete',
        agents_activated: requestedAgents.length,
        total_latency_ms: Date.now() - t0,
        timestamp:        new Date().toISOString(),
      });
    } catch (err) {
      send({ type: 'error', message: err.message });
    } finally {
      writer.close().catch(() => {});
    }
  };

  runAll(); // fire and forget — stream stays open

  return new Response(readable, {
    status: 200,
    headers: {
      'Content-Type':  'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-store',
      'Connection':    'keep-alive',
      'X-Accel-Buffering': 'no',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

// ─── POST /api/agents/dispatch/:agent — single agent ──────────────────────────
export async function handleAgentDispatch(request, env, authCtx, agentId) {
  const agent = AGENTS[agentId];
  if (!agent) {
    return Response.json({
      error: `Unknown agent: "${agentId}". Available: ${AGENT_IDS.join(', ')}`,
    }, { status: 404 });
  }

  let body;
  try { body = await request.json(); } catch {
    return Response.json({ error: 'Invalid JSON body.' }, { status: 400 });
  }

  const userMessage = (body.message || body.query || body.task || '').trim();
  if (!userMessage || userMessage.length < 5) {
    return Response.json({ error: 'message/query/task required (min 5 chars).' }, { status: 400 });
  }

  const tier = authCtx?.tier || 'ENTERPRISE';
  const [cveCtx, kevCtx, iocCtx] = await Promise.all([
    fetchCVEContext(userMessage, env),
    fetchKEVStatus(userMessage, env),
    fetchIOCContext(userMessage, env),
  ]);
  const context = { cve: cveCtx, kev: kevCtx, ioc: iocCtx };

  const result = await runAgent(agentId, userMessage, context, env, tier);

  return Response.json({
    success: true,
    agent:   result,
    context_enriched: { cve: !!cveCtx, kev: !!kevCtx, ioc: !!iocCtx },
    timestamp: new Date().toISOString(),
  });
}

// ─── GET /api/agents/status ───────────────────────────────────────────────────
export async function handleAgentsStatus(request, env, authCtx) {
  // Quick provider availability check
  const providers = {
    groq:        !!env.GROQ_API_KEY,
    deepseek:    !!env.DEEPSEEK_API_KEY,
    openrouter:  !!env.OPENROUTER_API_KEY,
    cf_workers_ai: !!env.AI,
  };

  const anyProvider = Object.values(providers).some(Boolean);

  return Response.json({
    success: true,
    service: 'APEX Multi-Agent SOC (MASOC) v1.0',
    status:  anyProvider ? 'OPERATIONAL' : 'NO_PROVIDER_CONFIGURED',
    ai_providers: providers,
    provider_note: anyProvider
      ? `${Object.entries(providers).filter(([,v])=>v).map(([k])=>k).join(', ')} available`
      : 'Set GROQ_API_KEY, DEEPSEEK_API_KEY, or OPENROUTER_API_KEY as Wrangler secrets. CF Workers AI is always available as fallback.',
    total_agents:   AGENT_IDS.length,
    agents: AGENT_IDS.map(id => {
      const a = AGENTS[id];
      return {
        id:          a.id,
        name:        a.name,
        icon:        a.icon,
        description: a.description,
        task_type:   a.task_type,
        domains:     a.domains,
        ai_routing:  a.task_type,
      };
    }),
    endpoints: {
      run:      'POST /api/agents/run',
      stream:   'POST /api/agents/stream  (SSE — real-time agent results)',
      status:   'GET  /api/agents/status',
      dispatch: 'POST /api/agents/dispatch/:agent_id',
    },
    usage: {
      run_example: {
        method: 'POST',
        path:   '/api/agents/run',
        body:   { message: 'We detected CVE-2024-3400 on our Palo Alto firewall — what should we do?', agents: ['cve_intel', 'ir_playbook', 'siem_defender'] },
      },
      stream_example: {
        method: 'POST',
        path:   '/api/agents/stream',
        body:   { message: 'Ransomware detected on 10.0.0.45, hash abc123def456' },
        note:   'Returns SSE stream — connect with EventSource in browser or curl -N',
      },
      dispatch_example: {
        method: 'POST',
        path:   '/api/agents/dispatch/cve_intel',
        body:   { message: 'CVE-2024-21762 — assess risk and patch priority' },
      },
    },
    timestamp: new Date().toISOString(),
  });
}
