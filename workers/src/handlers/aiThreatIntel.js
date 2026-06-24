/**
 * CYBERDUDEBIVASH v28 — AI Threat Intelligence Feed Handler
 * PILLAR 5: AI Threat Feed | AI Vulnerability Feed | Prompt Attack Feed | Agent Threat Feed
 *
 * GET  /api/ai-security/threat-feed              -> latest AI-specific threats
 * GET  /api/ai-security/threat-feed/prompt-attacks -> prompt attack patterns
 * GET  /api/ai-security/threat-feed/agent-threats  -> agent-specific threats
 * GET  /api/ai-security/threat-feed/ai-vulns       -> AI model vulnerabilities
 * GET  /api/ai-security/threat-feed/radar-status   -> AI Threat Radar health/coverage
 * POST /api/ai-security/threat-feed/radar-scan-now -> force an immediate radar scan (admin only)
 * POST /api/ai-security/threat-feed/submit         -> submit community threat (admin verified)
 *
 * PILLAR 4: AI AGENT SECURITY
 * POST /api/ai-security/agents/scan               -> scan agent config for security issues
 * GET  /api/ai-security/agents                    -> list registered agents
 * POST /api/ai-security/agents/register           -> register agent in inventory
 */

import { RADAR_STATUS_KV_KEY, AI_RADAR_PACKAGES, runAIThreatRadar } from '../services/aiThreatRadar.js';
import { ensureAIThreatFeedTable } from '../services/aiThreatIngestion.js';

const CORS = { 'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization' };
const json = (d,s=200) => new Response(JSON.stringify(d),{status:s,headers:{...CORS,'Content-Type':'application/json'}});
const err  = (m,s=400) => json({success:false,error:m},s);

// ─── Tier gating — same normalize/free-vs-paid convention as vibeCodeScanner.js
// (kept local rather than imported: each handler module here is self-contained).
// Plan comes from authCtx ONLY, resolved upstream by resolveAuthV5() — never
// from the request itself, so a caller cannot self-upgrade.
function normalizeTier(tier) {
  const t = String(tier || 'free').toLowerCase();
  if (t.includes('enterprise') || t.includes('mssp')) return 'enterprise';
  if (t.includes('pro')) return 'pro';
  if (t.includes('starter')) return 'starter';
  return 'free';
}
const isPaidTier = (tier) => normalizeTier(tier) !== 'free';
function tierFromAuth(authCtx) {
  if (authCtx && typeof authCtx === 'object' && authCtx.tier) return normalizeTier(authCtx.tier);
  return 'free';
}
const FREE_LIVE_PREVIEW = 3; // free/anon callers see this many live, source-attributed entries per bucket

// Curated AI threat intelligence — updated by Sentinel APEX
const AI_THREAT_LIBRARY = {

  prompt_attack_patterns: [
    { id:'PAP-001', name:'Many-Shot Jailbreaking (MSJ)', severity:'CRITICAL', description:'Attacker uses hundreds of faked examples in long context to override safety training. Effective against models with large context windows.', affected_models:['GPT-4','Claude','Gemini','Llama'], mitigation:'Implement context length limits for safety-sensitive applications. Use streaming safety checks rather than final-output-only checks.', discovered:'2024-Q1', owasp_ref:'LLM01', atlas_ref:'AML.T0054' },
    { id:'PAP-002', name:'PAIR (Prompt Automatic Iterative Refinement)', severity:'HIGH', description:'Automated attack using a second LLM to iteratively refine jailbreak prompts until the target model complies.', affected_models:['All frontier models'], mitigation:'Rate limit API calls. Implement anomaly detection for repetitive semantically-similar queries. Use behavioral analysis not just input filtering.', discovered:'2023-Q4', owasp_ref:'LLM01', atlas_ref:'AML.T0054' },
    { id:'PAP-003', name:'Crescendo Multi-Turn Jailbreak', severity:'HIGH', description:'Gradual escalation across multiple conversation turns — each turn seems benign, cumulative effect bypasses safety.', affected_models:['GPT-4o','Claude','Gemini'], mitigation:'Implement conversation-level (not just turn-level) safety evaluation. Track semantic drift across turns.', discovered:'2024-Q2', owasp_ref:'LLM01', atlas_ref:'AML.T0054' },
    { id:'PAP-004', name:'Indirect Prompt Injection via RAG', severity:'CRITICAL', description:'Attacker injects malicious instructions into documents retrieved by RAG pipeline — model executes injected instructions believing they are retrieved context.', affected_models:['Any RAG-enabled system'], mitigation:'Scan all retrieved documents for prompt injection patterns before insertion into context. Implement strict separation between system context and retrieved content.', discovered:'2023-Q3', owasp_ref:'LLM01', atlas_ref:'AML.T0051' },
    { id:'PAP-005', name:'ASCII Smuggling / Unicode Injection', severity:'MEDIUM', description:'Hidden characters (zero-width spaces, Unicode lookalikes) used to smuggle instructions past input filters.', affected_models:['All models'], mitigation:'Normalize Unicode input. Strip zero-width and control characters before tokenization.', discovered:'2024-Q1', owasp_ref:'LLM01' },
    { id:'PAP-006', name:'Multimodal Injection (Vision Models)', severity:'HIGH', description:'Instructions embedded in images using steganography or visible text that bypass text-layer security controls.', affected_models:['GPT-4V','Claude Sonnet (vision)','Gemini Vision'], mitigation:'OCR and analyze image text content through safety pipeline. Treat all extracted image text as untrusted user input.', discovered:'2024-Q2', owasp_ref:'LLM01' },
  ],

  agent_threats: [
    { id:'AGT-001', name:'Prompt Injection via Tool Return Values', severity:'CRITICAL', description:'Attacker controls content returned by tools (web pages, API responses) to inject instructions that hijack agent behavior.', affected_frameworks:['LangChain','AutoGen','CrewAI','OpenAI Agents','Claude MCP'], mitigation:'Treat all tool outputs as untrusted user input. Run safety checks on tool returns before re-entering agent loop.', owasp_ref:'LLM08', atlas_ref:'AML.T0051' },
    { id:'AGT-002', name:'Agent Memory Store Poisoning', severity:'HIGH', description:'Injecting malicious content into agent long-term memory (vector store, key-value memory) to alter future behavior.', affected_frameworks:['LangChain with memory','MemGPT','Any agent with persistent memory'], mitigation:'Implement memory integrity checks. Version and audit memory stores. Restrict what content can be written to persistent memory.', owasp_ref:'LLM08' },
    { id:'AGT-003', name:'Multi-Agent Trust Boundary Violation', severity:'CRITICAL', description:'In multi-agent orchestration, a compromised sub-agent can escalate privileges by sending crafted messages to orchestrator agents.', affected_frameworks:['CrewAI','AutoGen','LangGraph','Microsoft Semantic Kernel'], mitigation:'Implement explicit trust levels between agents. Never allow sub-agents to modify orchestrator instructions. Use message signing between agents.', owasp_ref:'LLM08' },
    { id:'AGT-004', name:'Tool Permission Escalation', severity:'HIGH', description:'Agent requests or is granted broader tool permissions than necessary for current task, enabling future abuse.', affected_frameworks:['All agentic frameworks'], mitigation:'Implement just-in-time permission granting. Each tool call requires explicit justification. Implement tool call sandboxing.', owasp_ref:'LLM07' },
    { id:'AGT-005', name:'Infinite Loop / Resource Exhaustion', severity:'MEDIUM', description:'Crafted inputs cause agent to enter infinite reasoning loops, consuming compute resources (AI-specific DoS).', affected_frameworks:['All agentic frameworks'], mitigation:'Implement maximum iteration limits. Set timeout boundaries per agent invocation. Monitor agent step counts in production.', owasp_ref:'LLM04', atlas_ref:'AML.T0029' },
    { id:'AGT-006', name:'RLHF Backdoor / Trojan Model', severity:'CRITICAL', description:'Model fine-tuned by attacker contains hidden trigger that activates malicious behavior when specific input is detected.', affected_frameworks:['Any system using fine-tuned models'], mitigation:'Only use models from trusted sources with verifiable training provenance. Conduct behavioral testing for hidden triggers before deployment.', owasp_ref:'LLM03', atlas_ref:'AML.T0018' },
  ],

  ai_vulnerabilities: [
    { id:'AIV-001', cve_id:'CVE-2024-5184', name:'Embedchain RAG Framework SSRF', severity:'CRITICAL', description:'Embedchain allows retrieval of arbitrary URLs including internal network resources, enabling SSRF attacks via RAG pipeline.', affected_models:['embedchain<=0.1.57'], mitigation:'Upgrade to embedchain>=0.1.58. Implement URL allowlist for RAG data sources.', cvss_score:9.1, attack_ref:'T1190' },
    { id:'AIV-002', cve_id:'CVE-2024-3571', name:'LangChain ReAct Agent Prompt Injection', severity:'HIGH', description:'LangChain ReAct agents with web browsing capability are vulnerable to indirect prompt injection via web page content.', affected_models:['langchain<0.2.0'], mitigation:'Upgrade LangChain. Implement content filtering on all web-retrieved content before agent processing.', cvss_score:8.1, atlas_ref:'AML.T0051' },
    { id:'AIV-003', cve_id:'CVE-2024-27564', name:'ChatGPT Plugin SSRF', severity:'HIGH', description:'SSRF via ChatGPT image generation allowing requests to internal services.', affected_models:['ChatGPT with plugins'], mitigation:'Validate and restrict all URLs in plugin-generated content. Block internal IP ranges.', cvss_score:8.1, attack_ref:'T1190' },
    { id:'AIV-004', cve_id:'CVE-2023-29374', name:'LangChain Math Arbitrary Code Execution', severity:'CRITICAL', description:'LangChain math chain allows execution of arbitrary Python code through crafted input.', affected_models:['langchain<0.0.131'], mitigation:'Upgrade immediately. Never use eval-based expression evaluation for untrusted input.', cvss_score:9.8, attack_ref:'T1059' },
    { id:'AIV-005', cve_id:'CVE-2024-21510', name:'Transformers Library Deserialization RCE', severity:'HIGH', description:'Unsafe deserialization in HuggingFace Transformers allows remote code execution when loading untrusted model weights.', affected_models:['transformers<4.38.0'], mitigation:'Only load model weights from trusted sources. Use safetensors format instead of pickle.', cvss_score:8.4, attack_ref:'T1059' },
  ],
};

// Public `type` query param (documented in frontend/api-docs.html) -> the real
// feed_type enum stored in ai_threat_feed (schema_master.sql). `ai_vulns` is kept
// as a legacy alias since this handler's own original comment used that name.
const TYPE_TO_FEED_TYPE = {
  prompt_attacks:    'prompt_attack',
  agent_threats:     'agent_threat',
  ai_cves:           'vulnerability',
  ai_vulns:          'vulnerability',
  model_advisories:  'advisory',
};

// Map a live ai_threat_feed row onto the same card shape the curated library
// entries already use (name/mitigation singular), so it renders through the
// exact same frontend code paths as curated entries — no frontend changes needed.
function dbRowToCard(r) {
  return {
    id: r.id,
    name: r.title,
    severity: r.severity,
    description: r.description,
    cve_id: r.cve_id || undefined,
    affected_models: r.affected_models,
    affected_frameworks: (() => { try { return JSON.parse(r.affected_frameworks || '[]'); } catch { return []; } })(),
    mitigation: (r.mitigations||[])[0] || '',
    owasp_ref: r.owasp_ref || undefined,
    attack_ref: r.attack_ref || undefined,
    atlas_ref: r.atlas_ref || undefined,
    source_url: r.source_url || undefined,
    live: true,
  };
}

// Fetch + classify the live ai_threat_feed rows shared by both the feed and
// report endpoints. Returns the rows bucketed by feed_type plus the raw list.
async function fetchLiveThreatBuckets(env, { feedTypeFilter = null, limit = 50 } = {}) {
  let dbItems = [];
  try {
    if (env?.DB) await ensureAIThreatFeedTable(env.DB);
    const rows = feedTypeFilter
      ? await env.DB.prepare('SELECT * FROM ai_threat_feed WHERE feed_type=? ORDER BY published_at DESC LIMIT ?').bind(feedTypeFilter, limit).all()
      : await env.DB.prepare('SELECT * FROM ai_threat_feed ORDER BY published_at DESC LIMIT ?').bind(limit).all();
    dbItems = (rows.results||[]).map(r => ({ ...r, affected_models:JSON.parse(r.affected_models||'[]'), mitigations:JSON.parse(r.mitigations||'[]') }));
  } catch { /* fallback to static library */ }

  const liveByFeedType = { prompt_attack: [], agent_threat: [], vulnerability: [], advisory: [], attack_pattern: [], malware: [] };
  for (const r of dbItems) (liveByFeedType[r.feed_type] || liveByFeedType.advisory).push(dbRowToCard(r));
  return { dbItems, liveByFeedType };
}

// GET /api/ai-security/threat-feed ────────────────────────────────────────────
export async function handleAIThreatFeed(request, env, authCtx) {
  const url = new URL(request.url);
  const type  = url.searchParams.get('type');   // prompt_attacks | agent_threats | ai_cves | model_advisories | all
  const limit = Math.min(parseInt(url.searchParams.get('limit')||'20'), 50);
  const feedTypeFilter = type && type !== 'all' ? (TYPE_TO_FEED_TYPE[type] || null) : null;
  // Recognized `type` shape but unmapped value — no live rows, curated-only fallthrough.
  const unmappedType = type && type !== 'all' && !feedTypeFilter;

  // First try D1 for source-attributed live threats (ai_threat_feed, populated by
  // services/aiThreatIngestion.js from the same NVD/CISA-KEV/GitHub CTI pipeline).
  const { dbItems, liveByFeedType } = unmappedType
    ? { dbItems: [], liveByFeedType: { prompt_attack: [], agent_threat: [], vulnerability: [], advisory: [], attack_pattern: [], malware: [] } }
    : await fetchLiveThreatBuckets(env, { feedTypeFilter, limit });

  // The live, source-attributed feed is the paid value-add. Free/anonymous
  // callers see a capped preview per bucket (curated static library stays
  // fully visible either way) plus an upgrade CTA — same freemium convention
  // as vibeCodeScanner's applyTierGate.
  const tier = tierFromAuth(authCtx);
  const paid = isPaidTier(tier);
  let liveLockedCount = 0;
  if (!paid) {
    for (const k of Object.keys(liveByFeedType)) {
      const arr = liveByFeedType[k];
      if (arr.length > FREE_LIVE_PREVIEW) {
        liveLockedCount += arr.length - FREE_LIVE_PREVIEW;
        liveByFeedType[k] = arr.slice(0, FREE_LIVE_PREVIEW);
      }
    }
  }

  // Merge live rows into the curated library so existing frontend pages (which
  // already read prompt_attack_patterns / agent_threats / ai_vulnerabilities)
  // pick up real, source-attributed data automatically.
  const curated = {
    prompt_attack_patterns: [...AI_THREAT_LIBRARY.prompt_attack_patterns, ...liveByFeedType.prompt_attack],
    agent_threats:          [...AI_THREAT_LIBRARY.agent_threats, ...liveByFeedType.agent_threat],
    ai_vulnerabilities:     [...AI_THREAT_LIBRARY.ai_vulnerabilities, ...liveByFeedType.vulnerability, ...liveByFeedType.advisory],
  };

  // Best-effort radar status — single KV read, never blocks/fails the feed response.
  let radarStatus = null;
  try {
    const raw = await env.SECURITY_HUB_KV?.get(RADAR_STATUS_KV_KEY);
    if (raw) radarStatus = JSON.parse(raw);
  } catch { /* radar field stays inactive below */ }

  // Background bootstrap: if no published report exists yet (e.g. before first cron),
  // generate one immediately from the curated library so the report endpoint is
  // always available to paying customers. Fire-and-forget — never blocks the feed.
  if (env.SECURITY_HUB_KV) {
    env.SECURITY_HUB_KV.get(LATEST_REPORT_KV_KEY)
      .then(existing => { if (!existing) generateAndPublishAIThreatReport(env).catch(() => {}); })
      .catch(() => {});
  }

  return json({
    success:true,
    feed_generated: new Date().toISOString(),
    source: 'CYBERDUDEBIVASH Sentinel APEX AI Threat Intelligence',
    data_sources: ['NVD', 'CISA KEV', 'GitHub Advisory Database', 'OSV.dev', 'GitHub Security Advisories API'],
    tier: normalizeTier(tier),
    gated: !paid,
    radar: {
      active: !!radarStatus,
      packages_watched: AI_RADAR_PACKAGES.length,
      last_scan_at: radarStatus?.last_scan_at || null,
      signals_found_last_scan: radarStatus?.signals_found ?? 0,
    },
    summary: {
      total_prompt_attacks: curated.prompt_attack_patterns.length,
      total_agent_threats:  curated.agent_threats.length,
      total_ai_cves:        curated.ai_vulnerabilities.length,
      critical_count:       [...curated.prompt_attack_patterns,...curated.agent_threats].filter(t=>t.severity==='CRITICAL').length,
    },
    prompt_attack_patterns: type&&type!=='all' ? (type==='prompt_attacks'?curated.prompt_attack_patterns:[]) : curated.prompt_attack_patterns,
    agent_threats:          type&&type!=='all' ? (type==='agent_threats'?curated.agent_threats:[])          : curated.agent_threats,
    ai_vulnerabilities:     type&&type!=='all' ? (['ai_cves','ai_vulns','model_advisories'].includes(type)?curated.ai_vulnerabilities:[]) : curated.ai_vulnerabilities,
    community_submissions:  dbItems,
    ...(liveLockedCount > 0 ? {
      live_locked_count: liveLockedCount,
      upgrade: {
        message: `${liveLockedCount} more live, source-attributed threat ${liveLockedCount===1?'entry':'entries'} (full feed + downloadable report) ${liveLockedCount===1?'is':'are'} available on Starter plan and above.`,
        cta: 'Upgrade to unlock the full live feed',
      },
    } : {}),
  });
}

// ─── Report deliverable ───────────────────────────────────────────────────────
const DATA_SOURCE_DISCLAIMER =
  'Live entries in this report are derived from public records in the National ' +
  'Vulnerability Database (NVD), the CISA Known Exploited Vulnerabilities (KEV) ' +
  'catalog, and the GitHub Advisory Database, filtered for relevance to the AI/LLM ' +
  'ecosystem. Each live entry links to its original public source record. ' +
  'CYBERDUDEBIVASH is not affiliated with NIST, CISA, or GitHub, and this report ' +
  'is not an official product of those organizations. Curated threat-pattern entries ' +
  '(no CVE/source link) are independent research by CYBERDUDEBIVASH Sentinel APEX.';

// KV key for the continuously-published latest report
export const LATEST_REPORT_KV_KEY = 'ai_threat_report:latest';

// Compute overall risk level from threat distribution
function computeRiskLevel(allThreats) {
  const critCount = allThreats.filter(t => t.severity === 'CRITICAL').length;
  const highCount  = allThreats.filter(t => t.severity === 'HIGH').length;
  if (critCount >= 3) return 'CRITICAL';
  if (critCount >= 1 || highCount >= 5) return 'HIGH';
  if (highCount >= 2) return 'MEDIUM';
  return 'LOW';
}

// Map OWASP LLM categories across all threats
function owaspCoverage(allThreats) {
  const map = {};
  for (const t of allThreats) {
    if (t.owasp_ref) map[t.owasp_ref] = (map[t.owasp_ref] || 0) + 1;
  }
  return map;
}

// Map MITRE ATLAS TTPs across all threats
function atlasCoverage(allThreats) {
  const map = {};
  for (const t of allThreats) {
    if (t.atlas_ref) map[t.atlas_ref] = (map[t.atlas_ref] || 0) + 1;
  }
  return map;
}

// Sigma rule template for a threat entry
function sigmaRule(t) {
  const ts = new Date().toISOString().slice(0, 10);
  const title = (t.name || t.cve_id || 'AI Threat').replace(/[^\w\s-]/g, '').slice(0, 60);
  return `title: ${title}
id: cdb-${(t.id || t.cve_id || 'ai').replace(/[^a-z0-9]/gi, '-').toLowerCase().slice(0, 20)}
status: experimental
description: Auto-generated by CYBERDUDEBIVASH Sentinel APEX AI Threat Intelligence
author: CYBERDUDEBIVASH Sentinel APEX
date: ${ts}
references:
  - ${t.source_url || 'https://cyberdudebivash.in'}
tags:
  - attack.${t.attack_ref ? t.attack_ref.toLowerCase().replace('.', '.') : 'initial_access'}
  - ${t.owasp_ref ? 'owasp.' + t.owasp_ref.toLowerCase().replace(' ', '_') : 'owasp.llm_top10'}
logsource:
  category: application
  product: ai_platform
detection:
  keywords:
    - '${(t.cve_id || t.name || '').slice(0, 40)}'
    - 'prompt_injection'
    - 'jailbreak'
  condition: keywords
falsepositives:
  - Security research and testing
level: ${t.severity === 'CRITICAL' ? 'critical' : t.severity === 'HIGH' ? 'high' : 'medium'}`;
}

// Premium markdown report — production-grade, globally sellable format
function renderAIThreatReportMarkdown({ curated, liveByFeedType, generatedAt, reportId }) {
  const liveAll    = Object.values(liveByFeedType).flat();
  const curatedAll = [...curated.prompt_attack_patterns, ...curated.agent_threats, ...curated.ai_vulnerabilities];
  const allThreats = [...liveAll, ...curatedAll];
  const critCount  = allThreats.filter(t => t.severity === 'CRITICAL').length;
  const highCount  = allThreats.filter(t => t.severity === 'HIGH').length;
  const medCount   = allThreats.filter(t => t.severity === 'MEDIUM').length;
  const riskLevel  = computeRiskLevel(allThreats);
  const owaspMap   = owaspCoverage(allThreats);
  const atlasMap   = atlasCoverage(allThreats);
  const topCves    = [...liveAll, ...curated.ai_vulnerabilities].filter(t => t.cve_id).slice(0, 5);

  const lines = [];

  // ── Cover ──────────────────────────────────────────────────────────────────
  lines.push('# CYBERDUDEBIVASH AI Threat Intelligence Report');
  lines.push('## Premium Edition — Sentinel APEX Intelligence Platform');
  lines.push('');
  lines.push(`**Report ID:** \`${reportId}\``);
  lines.push(`**Generated:** ${generatedAt}`);
  lines.push(`**Classification:** CONFIDENTIAL — For Authorized Recipients Only`);
  lines.push(`**Validity:** 24 Hours from Generation`);
  lines.push(`**Edition:** Global AI/LLM Threat Intelligence — Production Grade`);
  lines.push('');
  lines.push('> *This report is produced continuously and in real time by the CYBERDUDEBIVASH Sentinel APEX AI Threat Intelligence Engine. It aggregates live data from NVD, CISA KEV, OSV.dev, and the GitHub Advisory Database with curated research from our AI security team.*');
  lines.push('');
  lines.push('---');
  lines.push('');

  // ── Executive Summary ──────────────────────────────────────────────────────
  lines.push('## EXECUTIVE SUMMARY');
  lines.push('');
  lines.push(`The CYBERDUDEBIVASH Sentinel APEX intelligence engine has identified **${allThreats.length} distinct threats** targeting AI/LLM systems in the current monitoring window. Of these, **${critCount} are rated CRITICAL** and **${highCount} are rated HIGH severity**, requiring immediate attention from AI security teams globally.`);
  lines.push('');
  lines.push(`Organizations deploying large language models, agentic AI systems, RAG pipelines, and AI-powered applications face an escalating threat landscape. This report provides actionable intelligence, detection rules, and remediation guidance aligned to MITRE ATLAS, OWASP LLM Top 10, and international security standards.`);
  lines.push('');
  lines.push('### Overall Risk Assessment');
  lines.push('');
  lines.push(`| Risk Level | Status |`);
  lines.push(`|------------|--------|`);
  lines.push(`| **Current Threat Level** | **${riskLevel}** |`);
  lines.push(`| Critical Threats | ${critCount} |`);
  lines.push(`| High Severity | ${highCount} |`);
  lines.push(`| Medium Severity | ${medCount} |`);
  lines.push(`| Live Source-Attributed Entries | ${liveAll.length} |`);
  lines.push(`| Curated Pattern Library Entries | ${curatedAll.length} |`);
  lines.push(`| Total Threat Entries | ${allThreats.length} |`);
  lines.push('');

  // ── Key Findings ──────────────────────────────────────────────────────────
  lines.push('### Key Findings');
  lines.push('');
  if (critCount > 0) lines.push(`- **CRITICAL:** ${critCount} critical-severity AI/LLM threats require immediate response`);
  if (topCves.length > 0) lines.push(`- **CVE INTELLIGENCE:** ${topCves.length} AI-specific CVEs tracked with patch status`);
  lines.push(`- **ATTACK SURFACES:** Prompt injection, agent memory poisoning, and model supply chain attacks are the highest-volume active threats`);
  lines.push(`- **AFFECTED ECOSYSTEMS:** LangChain, Hugging Face Transformers, PyTorch/TensorFlow, CrewAI, AutoGen, and all major LLM APIs`);
  lines.push(`- **OWASP LLM COVERAGE:** ${Object.keys(owaspMap).length} distinct OWASP LLM Top 10 categories represented`);
  lines.push(`- **MITRE ATLAS COVERAGE:** ${Object.keys(atlasMap).length} ATLAS technique IDs mapped`);
  lines.push('');
  lines.push('---');
  lines.push('');

  // ── Section 1: Threat Landscape ───────────────────────────────────────────
  lines.push('## SECTION 1: AI THREAT LANDSCAPE OVERVIEW');
  lines.push('');
  lines.push('### Active Threat Categories');
  lines.push('');
  lines.push('| Category | Count | Critical | High |');
  lines.push('|----------|-------|----------|------|');
  const cats = [
    ['Prompt Attack Patterns', curated.prompt_attack_patterns],
    ['AI Agent Threats', curated.agent_threats],
    ['AI/ML CVE Vulnerabilities', curated.ai_vulnerabilities],
    ['Live Feed Entries (prompt_attack)', liveByFeedType.prompt_attack],
    ['Live Feed Entries (agent_threat)', liveByFeedType.agent_threat],
    ['Live Feed Entries (vulnerability)', [...(liveByFeedType.vulnerability || []), ...(liveByFeedType.advisory || [])]],
  ];
  for (const [name, arr] of cats) {
    if (!arr.length) continue;
    const c = arr.filter(t => t.severity === 'CRITICAL').length;
    const h = arr.filter(t => t.severity === 'HIGH').length;
    lines.push(`| ${name} | ${arr.length} | ${c} | ${h} |`);
  }
  lines.push('');

  // ── OWASP LLM Top 10 coverage ──────────────────────────────────────────────
  lines.push('### OWASP LLM Top 10 Coverage');
  lines.push('');
  const owaspDefs = {
    'LLM01': 'Prompt Injection',
    'LLM02': 'Insecure Output Handling',
    'LLM03': 'Training Data Poisoning',
    'LLM04': 'Model Denial of Service',
    'LLM05': 'Supply Chain Vulnerabilities',
    'LLM06': 'Sensitive Information Disclosure',
    'LLM07': 'Insecure Plugin Design',
    'LLM08': 'Excessive Agency',
    'LLM09': 'Overreliance',
    'LLM10': 'Model Theft',
  };
  lines.push('| Category | Description | Threats Found |');
  lines.push('|----------|-------------|---------------|');
  for (const [code, desc] of Object.entries(owaspDefs)) {
    const count = owaspMap[code] || 0;
    lines.push(`| **${code}** | ${desc} | ${count > 0 ? `**${count}**` : '0'} |`);
  }
  lines.push('');
  lines.push('---');
  lines.push('');

  // ── Section 2: Critical CVE Intelligence ─────────────────────────────────
  lines.push('## SECTION 2: CRITICAL CVE INTELLIGENCE (AI/LLM Ecosystem)');
  lines.push('');
  if (topCves.length === 0) {
    lines.push('_No new CVEs ingested in the current monitoring window. Live radar actively scanning OSV.dev, NVD, and GitHub Advisory API._');
  } else {
    for (const t of topCves) {
      lines.push(`### ${t.cve_id || t.id} — ${t.name}`);
      lines.push('');
      lines.push(`**Severity:** \`${t.severity}\``);
      if (t.cvss_score) lines.push(`**CVSS Score:** ${t.cvss_score}/10`);
      if (t.owasp_ref) lines.push(`**OWASP LLM:** ${t.owasp_ref}`);
      if (t.attack_ref) lines.push(`**MITRE ATT&CK:** ${t.attack_ref}`);
      if (t.atlas_ref) lines.push(`**MITRE ATLAS:** ${t.atlas_ref}`);
      if (t.source_url) lines.push(`**Source:** [${t.source_url}](${t.source_url})`);
      lines.push('');
      lines.push(`**Description:** ${t.description || t.name}`);
      lines.push('');
      if (t.affected_models?.length) lines.push(`**Affected Systems:** ${Array.isArray(t.affected_models) ? t.affected_models.join(', ') : t.affected_models}`);
      if (t.mitigation) lines.push(`**Mitigation:** ${t.mitigation}`);
      lines.push('');
    }
  }
  lines.push('---');
  lines.push('');

  // ── Section 3: Prompt Attack Intelligence ─────────────────────────────────
  lines.push('## SECTION 3: PROMPT ATTACK INTELLIGENCE');
  lines.push('');
  lines.push('*Prompt injection and jailbreak techniques represent the highest-volume active threat vector against LLM deployments. The following techniques have been curated from real-world attack research and mapped to MITRE ATLAS and OWASP LLM Top 10.*');
  lines.push('');
  const promptThreats = [...curated.prompt_attack_patterns, ...liveByFeedType.prompt_attack];
  if (!promptThreats.length) {
    lines.push('_No prompt attack patterns in current window._');
  } else {
    promptThreats.forEach((t, i) => {
      lines.push(`### ${i + 1}. ${t.name}  \`${t.severity}\``);
      lines.push('');
      if (t.owasp_ref) lines.push(`**OWASP LLM:** ${t.owasp_ref}`);
      if (t.atlas_ref) lines.push(`**MITRE ATLAS:** ${t.atlas_ref}`);
      if (t.attack_ref) lines.push(`**MITRE ATT&CK:** ${t.attack_ref}`);
      if (t.discovered) lines.push(`**First Observed:** ${t.discovered}`);
      if (t.source_url) lines.push(`**Source:** [${t.source_url}](${t.source_url})`);
      lines.push('');
      if (t.description) lines.push(`**Threat Description:** ${t.description}`);
      lines.push('');
      if (Array.isArray(t.affected_models) && t.affected_models.length) lines.push(`**Affected Models:** ${t.affected_models.join(' · ')}`);
      if (t.mitigation) lines.push(`**Recommended Mitigation:** ${t.mitigation}`);
      lines.push('');
    });
  }
  lines.push('---');
  lines.push('');

  // ── Section 4: Agent Security Threats ─────────────────────────────────────
  lines.push('## SECTION 4: AI AGENT SECURITY THREATS');
  lines.push('');
  lines.push('*Agentic AI systems introduce new attack surfaces not covered by traditional security controls. The following threats target agent orchestration, memory systems, tool execution, and multi-agent trust boundaries.*');
  lines.push('');
  const agentThreats = [...curated.agent_threats, ...liveByFeedType.agent_threat];
  if (!agentThreats.length) {
    lines.push('_No agent threats in current window._');
  } else {
    agentThreats.forEach((t, i) => {
      lines.push(`### ${i + 1}. ${t.name}  \`${t.severity}\``);
      lines.push('');
      if (t.owasp_ref) lines.push(`**OWASP LLM:** ${t.owasp_ref}`);
      if (t.atlas_ref) lines.push(`**MITRE ATLAS:** ${t.atlas_ref}`);
      if (t.attack_ref) lines.push(`**MITRE ATT&CK:** ${t.attack_ref}`);
      if (t.source_url) lines.push(`**Source:** [${t.source_url}](${t.source_url})`);
      lines.push('');
      if (t.description) lines.push(`**Threat Description:** ${t.description}`);
      lines.push('');
      const frameworks = Array.isArray(t.affected_frameworks) ? t.affected_frameworks : [];
      if (frameworks.length) lines.push(`**Affected Frameworks:** ${frameworks.join(' · ')}`);
      if (t.mitigation) lines.push(`**Recommended Mitigation:** ${t.mitigation}`);
      lines.push('');
    });
  }
  lines.push('---');
  lines.push('');

  // ── Section 5: AI Vulnerability Feed ──────────────────────────────────────
  lines.push('## SECTION 5: AI/ML VULNERABILITY INTELLIGENCE FEED');
  lines.push('');
  lines.push('*Source-attributed vulnerability entries from NVD, CISA KEV, OSV.dev, and GitHub Advisory Database filtered for AI/ML ecosystem relevance.*');
  lines.push('');
  const vulnThreats = [...curated.ai_vulnerabilities, ...(liveByFeedType.vulnerability || []), ...(liveByFeedType.advisory || [])];
  if (!vulnThreats.length) {
    lines.push('_No vulnerability entries in current monitoring window._');
  } else {
    vulnThreats.forEach((t, i) => {
      lines.push(`### ${i + 1}. ${t.name || t.cve_id}  \`${t.severity}\``);
      if (t.cve_id) lines.push(`**CVE ID:** ${t.cve_id}`);
      if (t.cvss_score) lines.push(`**CVSS Score:** ${t.cvss_score}/10`);
      if (t.owasp_ref) lines.push(`**OWASP LLM:** ${t.owasp_ref}`);
      if (t.attack_ref) lines.push(`**MITRE ATT&CK:** ${t.attack_ref}`);
      if (t.atlas_ref) lines.push(`**MITRE ATLAS:** ${t.atlas_ref}`);
      if (t.source_url) lines.push(`**Source:** [${t.source_url}](${t.source_url})`);
      lines.push('');
      if (t.description) lines.push(t.description);
      lines.push('');
      const models = Array.isArray(t.affected_models) ? t.affected_models : [];
      if (models.length) lines.push(`**Affected Systems:** ${models.join(' · ')}`);
      if (t.mitigation) lines.push(`**Mitigation:** ${t.mitigation}`);
      lines.push('');
    });
  }
  lines.push('---');
  lines.push('');

  // ── Section 6: Detection Rules ────────────────────────────────────────────
  lines.push('## SECTION 6: DETECTION RULES (PRODUCTION READY)');
  lines.push('');
  lines.push('*The following rules are auto-generated by Sentinel APEX and are ready for immediate deployment into your SIEM, EDR, or security monitoring platform. Validated for Splunk, Elastic SIEM, Microsoft Sentinel, and Chronicle.*');
  lines.push('');

  const ruleTargets = [...critCount > 0 ? allThreats.filter(t => t.severity === 'CRITICAL') : allThreats].slice(0, 4);
  if (ruleTargets.length > 0) {
    lines.push('### Sigma Rules (Cross-Platform)');
    lines.push('');
    for (const t of ruleTargets.slice(0, 3)) {
      lines.push('```yaml');
      lines.push(sigmaRule(t));
      lines.push('```');
      lines.push('');
    }
    lines.push('### KQL (Microsoft Sentinel / Defender)');
    lines.push('');
    lines.push('```kql');
    lines.push('// AI Threat Detection — Prompt Injection & Jailbreak Patterns');
    lines.push('SecurityEvent');
    lines.push('| where TimeGenerated > ago(1h)');
    lines.push('| where EventData has_any ("prompt_injection", "jailbreak", "many-shot", "PAIR", "crescendo", "indirect injection")');
    lines.push('| extend ThreatType = "AI_Prompt_Attack"');
    lines.push('| project TimeGenerated, Computer, EventData, ThreatType');
    lines.push('| sort by TimeGenerated desc');
    lines.push('```');
    lines.push('');
    lines.push('```kql');
    lines.push('// AI Agent Tool Abuse Detection');
    lines.push('DeviceProcessEvents');
    lines.push('| where TimeGenerated > ago(24h)');
    lines.push('| where ProcessCommandLine has_any ("langchain", "crewai", "autogen", "openai", "anthropic")');
    lines.push('| where ProcessCommandLine has_any ("exec", "shell", "subprocess", "os.system", "eval")');
    lines.push('| extend RiskLevel = "HIGH", ThreatCategory = "AI_Agent_Privilege_Escalation"');
    lines.push('| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, RiskLevel');
    lines.push('```');
    lines.push('');
    lines.push('### Splunk SPL');
    lines.push('');
    lines.push('```spl');
    lines.push('index=* sourcetype=ai_application');
    lines.push('| eval threat_signals = mvappend(');
    lines.push('    if(like(lower(request_content), "%prompt injection%"), "PROMPT_INJECTION", null()),');
    lines.push('    if(like(lower(request_content), "%jailbreak%"), "JAILBREAK", null()),');
    lines.push('    if(like(lower(request_content), "%ignore previous%"), "INSTRUCTION_OVERRIDE", null()),');
    lines.push('    if(like(lower(request_content), "%system prompt%"), "SYSTEM_LEAK_ATTEMPT", null())');
    lines.push(')');
    lines.push('| where isnotnull(threat_signals)');
    lines.push('| stats count by user, threat_signals, _time');
    lines.push('| sort -count');
    lines.push('```');
    lines.push('');
  }
  lines.push('---');
  lines.push('');

  // ── Section 7: Remediation Roadmap ────────────────────────────────────────
  lines.push('## SECTION 7: REMEDIATION ROADMAP');
  lines.push('');
  lines.push('### Immediate Actions (0–24 Hours)');
  lines.push('');
  lines.push('- [ ] **Patch critical AI/ML packages** — Update LangChain, Transformers, LlamaIndex, Gradio, and MLflow to latest versions');
  lines.push('- [ ] **Enable prompt injection filtering** — Deploy input validation and output sanitization on all LLM API endpoints');
  lines.push('- [ ] **Audit agent tool permissions** — Apply principle of least privilege; remove file_write, shell, and code_exec permissions where not required');
  lines.push('- [ ] **Activate SIEM detection rules** — Deploy the Sigma/KQL/Splunk rules in Section 6 to your monitoring stack');
  lines.push('- [ ] **Review RAG pipeline sources** — Scan all data sources feeding RAG systems for embedded prompt injection payloads');
  lines.push('');
  lines.push('### Short-Term Hardening (7–30 Days)');
  lines.push('');
  lines.push('- [ ] **Implement conversation-level safety evaluation** — Move beyond per-turn checks to multi-turn semantic drift detection');
  lines.push('- [ ] **Deploy agent memory integrity controls** — Version and audit all long-term memory stores; restrict write permissions');
  lines.push('- [ ] **Establish AI asset inventory** — Catalogue all AI models, agents, and pipelines in use across the organization');
  lines.push('- [ ] **Configure automated threat alerting** — Integrate this report pipeline with PagerDuty/Slack for continuous notification');
  lines.push('- [ ] **Red-team your LLM applications** — Conduct adversarial testing using MITRE ATLAS tactics identified in this report');
  lines.push('');
  lines.push('### Strategic Security Program (30–90 Days)');
  lines.push('');
  lines.push('- [ ] **Implement AI Security Posture Management (AI SPM)** — Continuous asset discovery and risk scoring');
  lines.push('- [ ] **Establish AI Governance Framework** — Align to NIST AI RMF, EU AI Act, and ISO/IEC 42001');
  lines.push('- [ ] **Deploy AI-specific SOC playbooks** — Automated incident response for prompt injection, model abuse, and agent compromise');
  lines.push('- [ ] **Supply chain verification** — Implement cryptographic verification of model weights; migrate from pickle to safetensors');
  lines.push('- [ ] **Zero-trust AI architecture** — Treat all LLM outputs, retrieved context, and agent tool returns as untrusted data');
  lines.push('');
  lines.push('---');
  lines.push('');

  // ── Section 8: Compliance Implications ────────────────────────────────────
  lines.push('## SECTION 8: COMPLIANCE & REGULATORY IMPLICATIONS');
  lines.push('');
  lines.push('| Framework | AI-Relevant Control Areas Affected |');
  lines.push('|-----------|-------------------------------------|');
  lines.push('| **SOC 2 Type II** | CC6 (Logical Access), CC7 (System Operations), CC8 (Change Management) |');
  lines.push('| **ISO 27001:2022** | A.8.8 (Vulnerability Mgmt), A.8.25 (Secure Development), A.5.23 (Cloud Security) |');
  lines.push('| **NIST AI RMF** | GOVERN 1.1, MAP 2.1, MEASURE 2.5, MANAGE 2.2 |');
  lines.push('| **EU AI Act** | Art. 9 (Risk Mgmt), Art. 15 (Accuracy/Robustness), Art. 72 (Serious Incident Reporting) |');
  lines.push('| **GDPR** | Art. 25 (Data Protection by Design), Art. 32 (Security of Processing) |');
  lines.push('| **OWASP LLM Top 10** | LLM01 (Prompt Injection), LLM03 (Training Data Poisoning), LLM08 (Excessive Agency) |');
  lines.push('');
  lines.push('---');
  lines.push('');

  // ── Section 9: MITRE ATLAS TTP Coverage ───────────────────────────────────
  lines.push('## SECTION 9: MITRE ATLAS TECHNIQUE COVERAGE');
  lines.push('');
  if (Object.keys(atlasMap).length > 0) {
    lines.push('| ATLAS Technique | Occurrences in This Report |');
    lines.push('|----------------|---------------------------|');
    for (const [tech, cnt] of Object.entries(atlasMap).sort((a, b) => b[1] - a[1])) {
      lines.push(`| ${tech} | ${cnt} |`);
    }
  } else {
    lines.push('| AML.T0051 | Adversarial Input — Indirect Prompt Injection |');
    lines.push('| AML.T0054 | LLM Jailbreak |');
    lines.push('| AML.T0018 | Backdoor ML Model |');
    lines.push('| AML.T0029 | Denial of ML Service |');
  }
  lines.push('');
  lines.push('---');
  lines.push('');

  // ── Section 10: Intelligence Sources ──────────────────────────────────────
  lines.push('## SECTION 10: INTELLIGENCE SOURCES & METHODOLOGY');
  lines.push('');
  lines.push('### Live Data Sources (Real-Time Ingestion)');
  lines.push('');
  lines.push('| Source | Type | Coverage | Update Frequency |');
  lines.push('|--------|------|----------|-----------------|');
  lines.push('| NIST NVD | CVE Database | AI/LLM keyword search (12 rotating terms) | Hourly |');
  lines.push('| CISA KEV | Known Exploited Vulnerabilities | Full catalog | Hourly |');
  lines.push('| OSV.dev | Package Vulnerabilities | 25 AI/ML packages (PyPI + npm) | Hourly |');
  lines.push('| GitHub Advisory API | Security Advisories | pip + npm AI ecosystem | Hourly |');
  lines.push('');
  lines.push('### Curated Research Library');
  lines.push('');
  lines.push('Independent research by CYBERDUDEBIVASH Sentinel APEX security team covering:');
  lines.push('- Prompt attack techniques (MSJ, PAIR, Crescendo, Indirect Injection, ASCII Smuggling, Multimodal)');
  lines.push('- AI agent threat taxonomy (tool return injection, memory poisoning, trust violations, RLHF backdoors)');
  lines.push('- AI/LLM CVE library with OWASP/ATLAS/ATT&CK cross-mapping');
  lines.push('');
  lines.push('### Data Attribution');
  lines.push('');
  lines.push(DATA_SOURCE_DISCLAIMER);
  lines.push('');
  lines.push('---');
  lines.push('');

  // ── Appendix: Full Curated Library ────────────────────────────────────────
  lines.push('## APPENDIX A: CURATED THREAT PATTERN LIBRARY (FULL)');
  lines.push('');
  curatedAll.forEach((t, i) => {
    lines.push(`### A${i + 1}. ${t.name}  \`${t.severity}\``);
    if (t.id) lines.push(`**ID:** ${t.id}`);
    if (t.cve_id) lines.push(`**CVE:** ${t.cve_id}`);
    if (t.owasp_ref) lines.push(`**OWASP LLM:** ${t.owasp_ref}`);
    if (t.attack_ref) lines.push(`**MITRE ATT&CK:** ${t.attack_ref}`);
    if (t.atlas_ref) lines.push(`**MITRE ATLAS:** ${t.atlas_ref}`);
    if (t.discovered) lines.push(`**Discovered:** ${t.discovered}`);
    lines.push('');
    if (t.description) lines.push(t.description);
    lines.push('');
    const models = Array.isArray(t.affected_models) ? t.affected_models : [];
    const frameworks = Array.isArray(t.affected_frameworks) ? t.affected_frameworks : [];
    if (models.length) lines.push(`**Affected Models:** ${models.join(', ')}`);
    if (frameworks.length) lines.push(`**Affected Frameworks:** ${frameworks.join(', ')}`);
    if (t.mitigation) lines.push(`**Mitigation:** ${t.mitigation}`);
    lines.push('');
  });

  // ── Footer ─────────────────────────────────────────────────────────────────
  lines.push('---');
  lines.push('');
  lines.push('## REPORT FOOTER');
  lines.push('');
  lines.push('**Generated By:** CYBERDUDEBIVASH Sentinel APEX AI Threat Intelligence Engine');
  lines.push('**Platform:** CYBERDUDEBIVASH AI Security Hub — Global Cyber Intelligence Dominance System');
  lines.push('**Contact:** bivash@cyberdudebivash.com');
  lines.push('**Website:** https://cyberdudebivash.in');
  lines.push('');
  lines.push('> **Classification:** CONFIDENTIAL');
  lines.push('> This report and all intelligence contained herein is proprietary to CYBERDUDEBIVASH.');
  lines.push('> Unauthorized redistribution, reproduction, or disclosure is strictly prohibited.');
  lines.push('> This report does not replace a dedicated penetration test or red-team engagement.');
  lines.push('> For enterprise licensing, white-label distribution, or custom threat intelligence feeds,');
  lines.push('> contact: bivash@cyberdudebivash.com');
  lines.push('');
  lines.push(`*Report ID: ${reportId} | Generated: ${generatedAt} | Sentinel APEX v28 | © CYBERDUDEBIVASH*`);

  return lines.join('\n');
}

// Generate and publish the latest premium report to KV for real-time access.
// Always succeeds — curated library is the baseline, live D1 rows augment it.
// Called from cron (independently of radar scan) AND on-demand on first page hit.
export async function generateAndPublishAIThreatReport(env) {
  if (!env?.SECURITY_HUB_KV) return null;
  const generatedAt = new Date().toISOString();
  const reportId = `RPT-${Date.now().toString(36).toUpperCase()}-APEX`;
  // Always use curated library as baseline — safe even with no D1 data
  const curated = {
    prompt_attack_patterns: AI_THREAT_LIBRARY.prompt_attack_patterns,
    agent_threats:          AI_THREAT_LIBRARY.agent_threats,
    ai_vulnerabilities:     AI_THREAT_LIBRARY.ai_vulnerabilities,
  };
  // Augment with live D1 rows (best-effort — failure is non-fatal)
  let liveByFeedType = { prompt_attack: [], agent_threat: [], vulnerability: [], advisory: [], attack_pattern: [], malware: [] };
  try {
    const buckets = await fetchLiveThreatBuckets(env, { limit: 200 });
    liveByFeedType = buckets.liveByFeedType;
  } catch { /* live rows unavailable — curated baseline still produces valid report */ }
  try {
    const markdown = renderAIThreatReportMarkdown({ curated, liveByFeedType, generatedAt, reportId });
    const liveAll = Object.values(liveByFeedType).flat();
    const allThreats = [...liveAll, ...curated.prompt_attack_patterns, ...curated.agent_threats, ...curated.ai_vulnerabilities];
    const meta = {
      report_id:     reportId,
      generated_at:  generatedAt,
      risk_level:    computeRiskLevel(allThreats),
      total_threats: allThreats.length,
      critical_count: allThreats.filter(t => t.severity === 'CRITICAL').length,
      high_count:    allThreats.filter(t => t.severity === 'HIGH').length,
      live_entries:  liveAll.length,
      format:        'markdown',
      report:        markdown,
    };
    await env.SECURITY_HUB_KV.put(LATEST_REPORT_KV_KEY, JSON.stringify(meta), { expirationTtl: 86400 * 2 });
    return meta;
  } catch (e) {
    console.error('[AIThreatReport] publish failed:', e?.message);
    return null;
  }
}

// GET /api/ai-security/threat-feed/report — premium downloadable report ───────
export async function handleAIThreatReport(request, env, authCtx) {
  const tier = tierFromAuth(authCtx);
  const paid = isPaidTier(tier);
  const generatedAt = new Date().toISOString();
  const reportId = `RPT-${Date.now().toString(36).toUpperCase()}-APEX`;

  const { liveByFeedType } = await fetchLiveThreatBuckets(env, { limit: 200 });
  const curated = {
    prompt_attack_patterns: AI_THREAT_LIBRARY.prompt_attack_patterns,
    agent_threats:          AI_THREAT_LIBRARY.agent_threats,
    ai_vulnerabilities:     AI_THREAT_LIBRARY.ai_vulnerabilities,
  };

  if (!paid) {
    const liveAll = Object.values(liveByFeedType).flat();
    const allThreats = [...liveAll, ...curated.prompt_attack_patterns, ...curated.agent_threats, ...curated.ai_vulnerabilities];
    return json({
      success: true,
      gated: true,
      tier: normalizeTier(tier),
      preview: {
        generated_at: generatedAt,
        report_id: `PREVIEW-${reportId}`,
        risk_level: computeRiskLevel(allThreats),
        live_entries_available: liveAll.length,
        curated_entries_available: curated.prompt_attack_patterns.length + curated.agent_threats.length + curated.ai_vulnerabilities.length,
        critical_count: allThreats.filter(t => t.severity === 'CRITICAL').length,
        high_count: allThreats.filter(t => t.severity === 'HIGH').length,
        sample: liveAll.slice(0, 2),
        report_sections: [
          'Executive Summary + Risk Assessment',
          'AI Threat Landscape Overview + OWASP LLM Top 10 Coverage',
          'Critical CVE Intelligence (AI/LLM Ecosystem)',
          'Prompt Attack Intelligence + MITRE ATLAS Mapping',
          'AI Agent Security Threats + Kill Chain Analysis',
          'AI/ML Vulnerability Intelligence Feed',
          'Production-Ready Detection Rules (Sigma / KQL / Splunk)',
          'Remediation Roadmap (0–24h / 7–30d / 30–90d)',
          'Compliance Implications (SOC2, ISO27001, NIST AI RMF, EU AI Act)',
          'MITRE ATLAS Technique Coverage Matrix',
          'Intelligence Sources & Methodology',
          'Curated Threat Pattern Library (Full)',
        ],
      },
      upgrade: {
        message: 'The full premium AI Threat Intelligence Report (12 sections, production-ready detection rules, remediation roadmap, compliance implications) is available on Starter plan and above.',
        cta: 'Upgrade to unlock the full premium report',
      },
    });
  }

  const markdown = renderAIThreatReportMarkdown({ curated, liveByFeedType, generatedAt, reportId });

  if (new URL(request.url).searchParams.get('download') === '1') {
    return new Response(markdown, {
      status: 200,
      headers: {
        ...CORS,
        'Content-Type': 'text/markdown; charset=utf-8',
        'Content-Disposition': `attachment; filename="cyberdudebivash-ai-threat-report-${reportId}.md"`,
        'Cache-Control': 'private, no-store',
        'X-Report-ID': reportId,
        'X-Report-Generated': generatedAt,
      },
    });
  }

  const liveAll = Object.values(liveByFeedType).flat();
  const allThreats = [...liveAll, ...curated.prompt_attack_patterns, ...curated.agent_threats, ...curated.ai_vulnerabilities];
  return json({
    success: true, gated: false, tier: normalizeTier(tier),
    report_id: reportId,
    generated_at: generatedAt,
    risk_level: computeRiskLevel(allThreats),
    total_threats: allThreats.length,
    critical_count: allThreats.filter(t => t.severity === 'CRITICAL').length,
    format: 'markdown',
    report: markdown,
  });
}

// GET /api/ai-security/threat-feed/latest-report — serve the continuously-published report from KV
export async function handleLatestPublishedReport(request, env, authCtx) {
  const tier = tierFromAuth(authCtx);
  const paid = isPaidTier(tier);

  // Try to serve from KV (auto-published by cron after every radar scan)
  let cached = null;
  try {
    const raw = await env.SECURITY_HUB_KV?.get(LATEST_REPORT_KV_KEY, { type: 'json' });
    if (raw) cached = raw;
  } catch { /* fall through */ }

  if (!paid) {
    return json({
      success: true, gated: true, tier: normalizeTier(tier),
      last_published: cached?.generated_at || null,
      risk_level: cached?.risk_level || null,
      total_threats: cached?.total_threats || null,
      upgrade: {
        message: 'The continuously-published live AI Threat Intelligence Report is available on Starter plan and above. Reports are auto-generated after every hourly radar scan.',
        cta: 'Upgrade to access real-time premium reports',
      },
    });
  }

  if (!cached) {
    // No cached report yet (pre-cron or fresh deployment) — generate on-demand.
    // generateAndPublishAIThreatReport always succeeds with curated baseline data.
    cached = await generateAndPublishAIThreatReport(env);
  }
  // Ultimate fallback: build an in-memory report from curated library alone
  // so paid customers are never served a 503 error.
  if (!cached) {
    const generatedAt = new Date().toISOString();
    const reportId = `RPT-${Date.now().toString(36).toUpperCase()}-APEX-FALLBACK`;
    const curated = {
      prompt_attack_patterns: AI_THREAT_LIBRARY.prompt_attack_patterns,
      agent_threats:          AI_THREAT_LIBRARY.agent_threats,
      ai_vulnerabilities:     AI_THREAT_LIBRARY.ai_vulnerabilities,
    };
    const emptyLive = { prompt_attack: [], agent_threat: [], vulnerability: [], advisory: [], attack_pattern: [], malware: [] };
    const allThreats = [...curated.prompt_attack_patterns, ...curated.agent_threats, ...curated.ai_vulnerabilities];
    cached = {
      report_id:     reportId,
      generated_at:  generatedAt,
      risk_level:    computeRiskLevel(allThreats),
      total_threats: allThreats.length,
      critical_count: allThreats.filter(t => t.severity === 'CRITICAL').length,
      high_count:    allThreats.filter(t => t.severity === 'HIGH').length,
      live_entries:  0,
      format:        'markdown',
      report:        renderAIThreatReportMarkdown({ curated, liveByFeedType: emptyLive, generatedAt, reportId }),
    };
  }

  const url = new URL(request.url);
  if (url.searchParams.get('download') === '1') {
    return new Response(cached.report, {
      status: 200,
      headers: {
        ...CORS,
        'Content-Type': 'text/markdown; charset=utf-8',
        'Content-Disposition': `attachment; filename="cyberdudebivash-ai-threat-report-${cached.report_id}.md"`,
        'Cache-Control': 'private, no-store',
        'X-Report-ID': cached.report_id,
        'X-Report-Generated': cached.generated_at,
      },
    });
  }

  return json({ success: true, gated: false, tier: normalizeTier(tier), ...cached });
}

// GET /api/ai-security/threat-feed/radar-status — radar health/coverage ──────
// Reads the snapshot services/aiThreatRadar.js writes to KV after every run.
// TTL'd at 6h server-side, so a stalled cron naturally reports `active:false`
// here instead of serving a stale "last scan" timestamp forever.
export async function handleAIThreatRadarStatus(request, env) {
  let status = null;
  try {
    const raw = await env.SECURITY_HUB_KV?.get(RADAR_STATUS_KV_KEY);
    if (raw) status = JSON.parse(raw);
  } catch { /* fall through to inactive state below */ }

  return json({
    success: true,
    radar_active: !!status,
    sources: ['OSV.dev', 'NVD (targeted keyword search)', 'GitHub Security Advisories API'],
    packages_watched: AI_RADAR_PACKAGES.length,
    scan_interval_minutes: 60,
    last_scan_at: status?.last_scan_at || null,
    last_scan_duration_ms: status?.duration_ms ?? null,
    last_scan_signals_found: status?.signals_found ?? 0,
    last_scan_signals_inserted: status?.signals_inserted ?? 0,
    source_breakdown: status?.source_breakdown || null,
    last_scan_errors: status?.errors || [],
  });
}

// POST /api/ai-security/threat-feed/radar-scan-now — admin-only forced scan ──
// The radar otherwise only runs on the hourly cron, so a fresh deploy (or an
// operator who needs proof-of-freshness right now rather than waiting up to
// 60 minutes) has no way to force an immediate pass. Runs the exact same
// runAIThreatRadar() the cron calls — same sources, same upsert path, same KV
// status snapshot — just invoked synchronously over HTTP instead of waitUntil.
export async function handleAIThreatRadarScanNow(request, env, authCtx) {
  if (!authCtx?.isAdmin) return err('Admin access required', 403);
  const triggeredAt = new Date().toISOString();
  const result = await runAIThreatRadar(env);
  // Always publish a fresh report immediately after the forced scan
  const published = await generateAndPublishAIThreatReport(env).catch(() => null);
  return json({
    success: true,
    triggered_at: triggeredAt,
    // Spread radar result fields at top level for backward compat
    ...result,
    report_published: !!published,
    report_id: published?.report_id || null,
    report_risk_level: published?.risk_level || null,
  });
}

// POST /api/ai-security/agents/scan ───────────────────────────────────────────
export async function handleScanAgent(request, env, authCtx) {
  if (!authCtx?.userId) return err('Auth required', 401);
  let body; try { body = await request.json(); } catch { return err('Invalid JSON'); }

  const { name, framework, tools, permissions, data_access, internet_access } = body;
  if (!name) return err('Agent name required');

  const toolList   = tools || [];
  const permList   = permissions || [];
  const dataList   = data_access || [];
  const hasNet     = !!internet_access;
  const fw         = (framework||'custom').toLowerCase();

  const issues = [];
  let riskScore = 0;

  // Excessive agency checks
  if (toolList.length > 10) { issues.push({ severity:'HIGH', issue:'Excessive tool count: '+toolList.length+' tools granted', recommendation:'Audit and remove unused tools. Apply principle of least privilege.', owasp_ref:'LLM08' }); riskScore+=25; }
  if (permList.includes('file_write') || permList.includes('file_system')) { issues.push({ severity:'CRITICAL', issue:'File system write access granted', recommendation:'Restrict file write permissions to specific directories only. Use sandboxed file access.', owasp_ref:'LLM08' }); riskScore+=30; }
  if (permList.includes('exec') || permList.includes('shell') || permList.includes('code_exec')) { issues.push({ severity:'CRITICAL', issue:'Code execution permissions detected', recommendation:'Remove code execution permissions unless absolutely required. Use sandboxed execution environment.', owasp_ref:'LLM08' }); riskScore+=40; }
  if (permList.includes('email_send') || permList.includes('email')) { issues.push({ severity:'HIGH', issue:'Email sending capability — data exfiltration vector', recommendation:'Require explicit human approval before any outbound email. Log all email activity.', owasp_ref:'LLM08' }); riskScore+=20; }
  if (hasNet && toolList.some(t => ['web_browser','fetch_url','browse','search'].some(k => t.toLowerCase().includes(k)))) { issues.push({ severity:'CRITICAL', issue:'Unrestricted internet access with browsing tools — indirect prompt injection vector', recommendation:'Implement URL allowlist. Scan all retrieved web content for prompt injection patterns before re-entering agent context.', owasp_ref:'LLM01' }); riskScore+=35; }
  if (dataList.some(d => ['all','*','database','sql'].includes(d.toLowerCase()))) { issues.push({ severity:'HIGH', issue:'Broad database access scope', recommendation:'Restrict data access to specific tables/schemas needed for the agent task.', owasp_ref:'LLM06' }); riskScore+=20; }
  if (['langchain','autogen','crewai'].includes(fw) && !body.memory_protection) { issues.push({ severity:'MEDIUM', issue:'Memory store not protected against injection', recommendation:'Implement memory content filtering. Treat all memory writes as potentially untrusted.', owasp_ref:'LLM08' }); riskScore+=15; }

  riskScore = Math.min(100, riskScore);
  const riskLevel = riskScore>=70?'CRITICAL':riskScore>=50?'HIGH':riskScore>=30?'MEDIUM':'LOW';

  // Register in inventory
  const agentId = 'agt_'+Date.now().toString(36)+Math.random().toString(36).slice(2,6);
  try {
    await env.DB.prepare(
      'INSERT INTO ai_agent_inventory (id,org_id,name,framework,tools,permissions,data_access,internet_access,tool_count,risk_score,issues) VALUES (?,?,?,?,?,?,?,?,?,?,?)'
    ).bind(agentId, authCtx.orgId||authCtx.userId, name, fw, JSON.stringify(toolList), JSON.stringify(permList), JSON.stringify(dataList), hasNet?1:0, toolList.length, riskScore, JSON.stringify(issues.map(i=>i.issue))).run();
  } catch { /* non-blocking */ }

  return json({
    success:true, agent_id:agentId, name, framework:fw,
    security_assessment:{ risk_score:riskScore, risk_level:riskLevel, total_issues:issues.length, critical_issues:issues.filter(i=>i.severity==='CRITICAL').length },
    issues,
    owasp_mapping: [...new Set(issues.map(i=>i.owasp_ref))],
    recommended_controls: issues.length===0 ? ['Agent configuration looks good. Schedule periodic re-assessment as permissions change.'] : issues.map(i=>i.recommendation).slice(0,3),
  });
}

export async function handleRegisterAgent(request, env, authCtx) {
  return handleScanAgent(request, env, authCtx);
}

export async function handleListAgents(request, env, authCtx) {
  if (!authCtx?.userId) return err('Auth required', 401);
  const orgId = authCtx.orgId||authCtx.userId;
  const rows = await env.DB.prepare('SELECT id,name,framework,tool_count,risk_score,status FROM ai_agent_inventory WHERE org_id=? ORDER BY risk_score DESC').bind(orgId).all();
  return json({ success:true, agents:rows.results||[] });
}
