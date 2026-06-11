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

// CORS applied by centralized withCors() in index.js — no per-handler wildcard
const json = (d,s=200) => new Response(JSON.stringify(d),{status:s,headers:{'Content-Type':'application/json'}});
const err  = (m,s=400) => json({success:false,error:m},s);

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

// GET /api/ai-security/threat-feed ────────────────────────────────────────────
export async function handleAIThreatFeed(request, env) {
  const url = new URL(request.url);
  const type  = url.searchParams.get('type');   // prompt_attacks | agent_threats | ai_vulns | all
  const limit = Math.min(parseInt(url.searchParams.get('limit')||'20'), 50);

  // First try D1 for community-submitted + verified threats
  let dbItems = [];
  try {
    const rows = type && type !== 'all'
      ? await env.DB.prepare('SELECT * FROM ai_threat_feed WHERE feed_type=? ORDER BY published_at DESC LIMIT ?').bind(type, limit).all()
      : await env.DB.prepare('SELECT * FROM ai_threat_feed ORDER BY published_at DESC LIMIT ?').bind(limit).all();
    dbItems = (rows.results||[]).map(r => ({ ...r, affected_models:JSON.parse(r.affected_models||'[]'), mitigations:JSON.parse(r.mitigations||'[]') }));
  } catch { /* fallback to static library */ }

  // Merge with curated library
  const curated = {
    prompt_attack_patterns: AI_THREAT_LIBRARY.prompt_attack_patterns,
    agent_threats:          AI_THREAT_LIBRARY.agent_threats,
    ai_vulnerabilities:     AI_THREAT_LIBRARY.ai_vulnerabilities,
  };

  return json({
    success:true,
    feed_generated: new Date().toISOString(),
    source: 'CYBERDUDEBIVASH Sentinel APEX AI Threat Intelligence',
    summary: {
      total_prompt_attacks: AI_THREAT_LIBRARY.prompt_attack_patterns.length,
      total_agent_threats:  AI_THREAT_LIBRARY.agent_threats.length,
      total_ai_cves:        AI_THREAT_LIBRARY.ai_vulnerabilities.length,
      critical_count:       [...AI_THREAT_LIBRARY.prompt_attack_patterns,...AI_THREAT_LIBRARY.agent_threats].filter(t=>t.severity==='CRITICAL').length,
    },
    prompt_attack_patterns: type&&type!=='all' ? (type==='prompt_attacks'?curated.prompt_attack_patterns:[]) : curated.prompt_attack_patterns,
    agent_threats:          type&&type!=='all' ? (type==='agent_threats'?curated.agent_threats:[])          : curated.agent_threats,
    ai_vulnerabilities:     type&&type!=='all' ? (type==='ai_vulns'?curated.ai_vulnerabilities:[])          : curated.ai_vulnerabilities,
    community_submissions:  dbItems,
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
