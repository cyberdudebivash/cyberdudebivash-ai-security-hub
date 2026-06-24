/**
 * CYBERDUDEBIVASH v28 — AI Threat Intelligence Feed Handler
 * PILLAR 5: AI Threat Feed | AI Vulnerability Feed | Prompt Attack Feed | Agent Threat Feed
 *
 * GET  /api/ai-security/threat-feed              -> latest AI-specific threats
 * GET  /api/ai-security/threat-feed/prompt-attacks -> prompt attack patterns
 * GET  /api/ai-security/threat-feed/agent-threats  -> agent-specific threats
 * GET  /api/ai-security/threat-feed/ai-vulns       -> AI model vulnerabilities
 * POST /api/ai-security/threat-feed/submit         -> submit community threat (admin verified)
 *
 * PILLAR 4: AI AGENT SECURITY
 * POST /api/ai-security/agents/scan               -> scan agent config for security issues
 * GET  /api/ai-security/agents                    -> list registered agents
 * POST /api/ai-security/agents/register           -> register agent in inventory
 */

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
    { id:'PAP-001', name:'Many-Shot Jailbreaking (MSJ)', severity:'CRITICAL', description:'Attacker uses hundreds of faked examples in long context to override safety training. Effective against models with large context windows.', affected_models:['GPT-4','Claude','Gemini','Llama'], mitigation:'Implement context length limits for safety-sensitive applications. Use streaming safety checks rather than final-output-only checks.', discovered:'2024-Q1', owasp_ref:'LLM01' },
    { id:'PAP-002', name:'PAIR (Prompt Automatic Iterative Refinement)', severity:'HIGH', description:'Automated attack using a second LLM to iteratively refine jailbreak prompts until the target model complies.', affected_models:['All frontier models'], mitigation:'Rate limit API calls. Implement anomaly detection for repetitive semantically-similar queries. Use behavioral analysis not just input filtering.', discovered:'2023-Q4', owasp_ref:'LLM01' },
    { id:'PAP-003', name:'Crescendo Multi-Turn Jailbreak', severity:'HIGH', description:'Gradual escalation across multiple conversation turns — each turn seems benign, cumulative effect bypasses safety.', affected_models:['GPT-4o','Claude','Gemini'], mitigation:'Implement conversation-level (not just turn-level) safety evaluation. Track semantic drift across turns.', discovered:'2024-Q2', owasp_ref:'LLM01' },
    { id:'PAP-004', name:'Indirect Prompt Injection via RAG', severity:'CRITICAL', description:'Attacker injects malicious instructions into documents retrieved by RAG pipeline — model executes injected instructions believing they are retrieved context.', affected_models:['Any RAG-enabled system'], mitigation:'Scan all retrieved documents for prompt injection patterns before insertion into context. Implement strict separation between system context and retrieved content.', discovered:'2023-Q3', owasp_ref:'LLM01' },
    { id:'PAP-005', name:'ASCII Smuggling / Unicode Injection', severity:'MEDIUM', description:'Hidden characters (zero-width spaces, Unicode lookalikes) used to smuggle instructions past input filters.', affected_models:['All models'], mitigation:'Normalize Unicode input. Strip zero-width and control characters before tokenization.', discovered:'2024-Q1', owasp_ref:'LLM01' },
    { id:'PAP-006', name:'Multimodal Injection (Vision Models)', severity:'HIGH', description:'Instructions embedded in images using steganography or visible text that bypass text-layer security controls.', affected_models:['GPT-4V','Claude Sonnet (vision)','Gemini Vision'], mitigation:'OCR and analyze image text content through safety pipeline. Treat all extracted image text as untrusted user input.', discovered:'2024-Q2', owasp_ref:'LLM01' },
  ],

  agent_threats: [
    { id:'AGT-001', name:'Prompt Injection via Tool Return Values', severity:'CRITICAL', description:'Attacker controls content returned by tools (web pages, API responses) to inject instructions that hijack agent behavior.', affected_frameworks:['LangChain','AutoGen','CrewAI','OpenAI Agents','Claude MCP'], mitigation:'Treat all tool outputs as untrusted user input. Run safety checks on tool returns before re-entering agent loop.', owasp_ref:'LLM08' },
    { id:'AGT-002', name:'Agent Memory Store Poisoning', severity:'HIGH', description:'Injecting malicious content into agent long-term memory (vector store, key-value memory) to alter future behavior.', affected_frameworks:['LangChain with memory','MemGPT','Any agent with persistent memory'], mitigation:'Implement memory integrity checks. Version and audit memory stores. Restrict what content can be written to persistent memory.', owasp_ref:'LLM08' },
    { id:'AGT-003', name:'Multi-Agent Trust Boundary Violation', severity:'CRITICAL', description:'In multi-agent orchestration, a compromised sub-agent can escalate privileges by sending crafted messages to orchestrator agents.', affected_frameworks:['CrewAI','AutoGen','LangGraph','Microsoft Semantic Kernel'], mitigation:'Implement explicit trust levels between agents. Never allow sub-agents to modify orchestrator instructions. Use message signing between agents.', owasp_ref:'LLM08' },
    { id:'AGT-004', name:'Tool Permission Escalation', severity:'HIGH', description:'Agent requests or is granted broader tool permissions than necessary for current task, enabling future abuse.', affected_frameworks:['All agentic frameworks'], mitigation:'Implement just-in-time permission granting. Each tool call requires explicit justification. Implement tool call sandboxing.', owasp_ref:'LLM07' },
    { id:'AGT-005', name:'Infinite Loop / Resource Exhaustion', severity:'MEDIUM', description:'Crafted inputs cause agent to enter infinite reasoning loops, consuming compute resources (AI-specific DoS).', affected_frameworks:['All agentic frameworks'], mitigation:'Implement maximum iteration limits. Set timeout boundaries per agent invocation. Monitor agent step counts in production.', owasp_ref:'LLM04' },
    { id:'AGT-006', name:'RLHF Backdoor / Trojan Model', severity:'CRITICAL', description:'Model fine-tuned by attacker contains hidden trigger that activates malicious behavior when specific input is detected.', affected_frameworks:['Any system using fine-tuned models'], mitigation:'Only use models from trusted sources with verifiable training provenance. Conduct behavioral testing for hidden triggers before deployment.', owasp_ref:'LLM03' },
  ],

  ai_vulnerabilities: [
    { id:'AIV-001', cve_id:'CVE-2024-5184', name:'Embedchain RAG Framework SSRF', severity:'CRITICAL', description:'Embedchain allows retrieval of arbitrary URLs including internal network resources, enabling SSRF attacks via RAG pipeline.', affected_models:['embedchain<=0.1.57'], mitigation:'Upgrade to embedchain>=0.1.58. Implement URL allowlist for RAG data sources.', cvss_score:9.1 },
    { id:'AIV-002', cve_id:'CVE-2024-3571', name:'LangChain ReAct Agent Prompt Injection', severity:'HIGH', description:'LangChain ReAct agents with web browsing capability are vulnerable to indirect prompt injection via web page content.', affected_models:['langchain<0.2.0'], mitigation:'Upgrade LangChain. Implement content filtering on all web-retrieved content before agent processing.', cvss_score:8.1 },
    { id:'AIV-003', cve_id:'CVE-2024-27564', name:'ChatGPT Plugin SSRF', severity:'HIGH', description:'SSRF via ChatGPT image generation allowing requests to internal services.', affected_models:['ChatGPT with plugins'], mitigation:'Validate and restrict all URLs in plugin-generated content. Block internal IP ranges.', cvss_score:8.1 },
    { id:'AIV-004', cve_id:'CVE-2023-29374', name:'LangChain Math Arbitrary Code Execution', severity:'CRITICAL', description:'LangChain math chain allows execution of arbitrary Python code through crafted input.', affected_models:['langchain<0.0.131'], mitigation:'Upgrade immediately. Never use eval-based expression evaluation for untrusted input.', cvss_score:9.8 },
    { id:'AIV-005', cve_id:'CVE-2024-21510', name:'Transformers Library Deserialization RCE', severity:'HIGH', description:'Unsafe deserialization in HuggingFace Transformers allows remote code execution when loading untrusted model weights.', affected_models:['transformers<4.38.0'], mitigation:'Only load model weights from trusted sources. Use safetensors format instead of pickle.', cvss_score:8.4 },
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
    source_url: r.source_url || undefined,
    live: true,
  };
}

// Fetch + classify the live ai_threat_feed rows shared by both the feed and
// report endpoints. Returns the rows bucketed by feed_type plus the raw list.
async function fetchLiveThreatBuckets(env, { feedTypeFilter = null, limit = 50 } = {}) {
  let dbItems = [];
  try {
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

  return json({
    success:true,
    feed_generated: new Date().toISOString(),
    source: 'CYBERDUDEBIVASH Sentinel APEX AI Threat Intelligence',
    data_sources: ['NVD', 'CISA KEV', 'GitHub Advisory Database'],
    tier: normalizeTier(tier),
    gated: !paid,
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
// Source-attribution disclaimer included in every generated report — see also
// frontend/terms-of-service.html "Third-Party Threat Intelligence Data" section.
const DATA_SOURCE_DISCLAIMER =
  'Live entries in this report are derived from public records in the National ' +
  'Vulnerability Database (NVD), the CISA Known Exploited Vulnerabilities (KEV) ' +
  'catalog, and the GitHub Advisory Database, filtered for relevance to the AI/LLM ' +
  'ecosystem. Each live entry links to its original public source record below. ' +
  'CYBERDUDEBIVASH is not affiliated with NIST, CISA, or GitHub, and this report is ' +
  'not an official product of those organizations. Curated threat-pattern entries ' +
  '(no CVE/source link) are independent research by CYBERDUDEBIVASH Sentinel APEX.';

function renderAIThreatReportMarkdown({ curated, liveByFeedType, generatedAt }) {
  const liveAll = Object.values(liveByFeedType).flat();
  const curatedAll = [...curated.prompt_attack_patterns, ...curated.agent_threats, ...curated.ai_vulnerabilities];
  const lines = [];
  lines.push('# CYBERDUDEBIVASH AI Threat Intelligence Report');
  lines.push(`*Generated ${generatedAt} — CYBERDUDEBIVASH Sentinel APEX AI Threat Intelligence*`);
  lines.push('');
  lines.push('## Data Sources & Attribution');
  lines.push(DATA_SOURCE_DISCLAIMER);
  lines.push('');
  lines.push('## Summary');
  lines.push(`- Live source-attributed entries: ${liveAll.length}`);
  lines.push(`- Curated threat-pattern entries: ${curatedAll.length}`);
  lines.push(`- Critical severity (all entries): ${[...liveAll, ...curatedAll].filter(t=>t.severity==='CRITICAL').length}`);
  lines.push('');
  lines.push('## Live AI/LLM Threat Intelligence (source-attributed)');
  if (!liveAll.length) lines.push('_No live entries currently match the AI/LLM ecosystem filter._');
  liveAll.forEach((t, i) => {
    lines.push(`### ${i + 1}. ${t.name}  \`${t.severity}\``);
    if (t.cve_id) lines.push(`**CVE:** ${t.cve_id}`);
    if (t.owasp_ref) lines.push(`**OWASP LLM Top 10:** ${t.owasp_ref}`);
    if (t.source_url) lines.push(`**Source:** ${t.source_url}`);
    lines.push('');
    if (t.description) lines.push(t.description);
    if (t.mitigation) lines.push(`**Mitigation:** ${t.mitigation}`);
    lines.push('');
  });
  lines.push('## Curated Threat Pattern Library');
  curatedAll.forEach((t, i) => {
    lines.push(`### ${i + 1}. ${t.name}  \`${t.severity}\``);
    if (t.cve_id) lines.push(`**CVE:** ${t.cve_id}`);
    if (t.owasp_ref) lines.push(`**OWASP LLM Top 10:** ${t.owasp_ref}`);
    lines.push('');
    if (t.description) lines.push(t.description);
    if (t.mitigation) lines.push(`**Mitigation:** ${t.mitigation}`);
    lines.push('');
  });
  lines.push('---');
  lines.push('_This report blends curated threat-pattern research with live, source-attributed vulnerability data. It does not replace a dedicated penetration test or red-team engagement._');
  return lines.join('\n');
}

// GET /api/ai-security/threat-feed/report — downloadable digest report ────────
export async function handleAIThreatReport(request, env, authCtx) {
  const tier = tierFromAuth(authCtx);
  const paid = isPaidTier(tier);
  const generatedAt = new Date().toISOString();

  const { liveByFeedType } = await fetchLiveThreatBuckets(env, { limit: 200 });
  const curated = {
    prompt_attack_patterns: AI_THREAT_LIBRARY.prompt_attack_patterns,
    agent_threats:          AI_THREAT_LIBRARY.agent_threats,
    ai_vulnerabilities:     AI_THREAT_LIBRARY.ai_vulnerabilities,
  };

  if (!paid) {
    const liveAll = Object.values(liveByFeedType).flat();
    return json({
      success: true,
      gated: true,
      tier: normalizeTier(tier),
      preview: {
        generated_at: generatedAt,
        live_entries_available: liveAll.length,
        curated_entries_available: curated.prompt_attack_patterns.length + curated.agent_threats.length + curated.ai_vulnerabilities.length,
        critical_count: liveAll.filter(t => t.severity === 'CRITICAL').length,
        sample: liveAll.slice(0, 2),
      },
      upgrade: {
        message: 'The full downloadable AI Threat Intelligence Report (all live, source-attributed entries plus the curated pattern library) is available on Starter plan and above.',
        cta: 'Upgrade to unlock the full report',
      },
    });
  }

  const markdown = renderAIThreatReportMarkdown({ curated, liveByFeedType, generatedAt });
  const reportId = (typeof crypto !== 'undefined' && crypto.randomUUID) ? crypto.randomUUID() : `r_${Date.now()}`;

  if (new URL(request.url).searchParams.get('download') === '1') {
    return new Response(markdown, {
      status: 200,
      headers: {
        ...CORS,
        'Content-Type': 'text/markdown; charset=utf-8',
        'Content-Disposition': `attachment; filename="cyberdudebivash-ai-threat-report-${reportId}.md"`,
        'Cache-Control': 'private, no-store',
      },
    });
  }

  return json({
    success: true, gated: false, tier: normalizeTier(tier),
    report_id: reportId, generated_at: generatedAt, format: 'markdown',
    report: markdown,
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
