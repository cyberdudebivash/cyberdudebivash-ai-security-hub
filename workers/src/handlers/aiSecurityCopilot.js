/**
 * CYBERDUDEBIVASH AI Security Hub — APEX AI Security Copilot v3.0 (God Mode)
 *
 * Provider mesh: Groq → DeepSeek → OpenRouter → Cloudflare Workers AI
 * Anthropic is NOT used — platform operates 100% on open-weight models.
 *
 * God Mode routing intelligence:
 *   Threat intel deep dive   → DeepSeek V3 (best technical CVE reasoning)
 *   Reasoning / correlation  → Groq deepseek-r1-distill-llama-70b (R1 chain-of-thought)
 *   Fast responses           → Groq llama-3.1-8b-instant (< 500 ms)
 *   Governance / compliance  → Groq llama-3.3-70b-versatile (structured prose)
 *   Executive summaries      → Groq llama-3.3-70b-versatile (eloquent, fast)
 *   Complex multi-step       → DeepSeek deepseek-reasoner (extended CoT)
 *   Fallback                 → OpenRouter meta-llama/llama-3.3-70b-instruct
 *   Last resort              → Cloudflare Workers AI text mode
 *
 * Architecture:
 *   • Query classifier   — detects task_type + complexity from user message
 *   • Routing matrix     — maps task × complexity → ordered provider + model list
 *   • Reasoning pre-pass — runs R1/reasoner before tool loop for complex queries
 *   • Agentic tool loop  — OpenAI-compat function calling (up to 5 rounds)
 *   • Auto-failover      — cascades through the provider chain on any error
 *   • Session management — KV-backed 24h sessions, 20-msg sliding window
 *   • Session compaction — summarises sessions > 15 messages to save tokens
 *   • Tool telemetry     — logs tool calls to KV for analytics
 *
 * Endpoints:
 *   POST   /api/copilot/chat          — multi-turn conversational AI
 *   GET    /api/copilot/session       — session history
 *   DELETE /api/copilot/session       — clear session
 *   POST   /api/copilot/quick-action  — direct skill invocation
 *   GET    /api/copilot/capabilities  — skill catalogue + live provider status
 */

import { ok, badRequest } from '../lib/response.js';
import { PROVIDERS, PROVIDER_CONFIG, routeAICall } from '../core/aiProviderRouter.js';

// ─── Constants ────────────────────────────────────────────────────────────────
const SESSION_TTL      = 86400;   // 24h KV TTL
const MAX_HISTORY      = 20;      // sliding window (messages)
const COMPACT_THRESHOLD = 15;     // compact session when history >= this
const MAX_TOOL_ROUNDS  = 5;       // max agentic loop depth
const TOOL_RESULT_LIMIT = 6000;   // max chars per tool result injected into context

// Daily message quotas (null = unlimited)
const DAILY_QUOTA = {
  ENTERPRISE: null,
  MSSP:       null,
  TEAM:       500,
  PRO:        200,
  STARTER:    50,
  FREE:       5,
};

// ─── Provider priority chain (Anthropic excluded) ─────────────────────────────
const COPILOT_PROVIDERS = [PROVIDERS.GROQ, PROVIDERS.DEEPSEEK, PROVIDERS.OPENROUTER, PROVIDERS.CF_AI];

// ─── Model definitions ─────────────────────────────────────────────────────────
// All models have confirmed OpenAI-compat tool calling support unless noted.
const MODELS = {
  // Groq — sub-second inference on premium hardware
  GROQ_70B:        'llama-3.3-70b-versatile',       // best overall, tool calling ✓
  GROQ_8B:         'llama-3.1-8b-instant',           // fastest (<500ms), tool calling ✓
  GROQ_MIXTRAL:    'mixtral-8x7b-32768',             // long context (32k), tool calling ✓
  GROQ_R1:         'deepseek-r1-distill-llama-70b',  // reasoning model (R1 distill on Groq)
  // DeepSeek — elite technical reasoning
  DEEPSEEK_V3:     'deepseek-chat',                  // V3, excellent CVE/code reasoning, tools ✓
  DEEPSEEK_R1:     'deepseek-reasoner',              // R1, extended chain-of-thought, limited tools
  // OpenRouter — meta-provider access to many models
  OR_LLAMA_70B:    'meta-llama/llama-3.3-70b-instruct',  // strong general purpose, tools ✓
  OR_DEEPSEEK_V3:  'deepseek/deepseek-chat',              // DeepSeek V3 via OpenRouter, tools ✓
  OR_DEEPSEEK_R1:  'deepseek/deepseek-r1',                // DeepSeek R1 via OpenRouter
  OR_MISTRAL:      'mistralai/mistral-large',             // strong structured output, tools ✓
  OR_GEMINI_FLASH: 'google/gemini-flash-1.5',             // fast multimodal, tools ✓
  // CF Workers AI
  CF_LLAMA:        '@cf/meta/llama-3.1-8b-instruct',     // text only (no tool calling)
};

// ─── Routing matrix ───────────────────────────────────────────────────────────
// Maps task_type × complexity → ordered list of {provider, model, use_tool_calling}
// The orchestrator walks this list until one succeeds.
const ROUTING_MATRIX = {
  // Technical CVE / threat intel — DeepSeek V3 is unmatched here
  threat_intel: {
    complex:  [
      { p: PROVIDERS.DEEPSEEK,   m: MODELS.DEEPSEEK_V3,   tools: true  },
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_R1,        tools: false }, // reasoning pre-pass
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
      { p: PROVIDERS.OPENROUTER, m: MODELS.OR_DEEPSEEK_V3, tools: true  },
      { p: PROVIDERS.OPENROUTER, m: MODELS.OR_LLAMA_70B,   tools: true  },
    ],
    standard: [
      { p: PROVIDERS.DEEPSEEK,   m: MODELS.DEEPSEEK_V3,   tools: true  },
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
      { p: PROVIDERS.OPENROUTER, m: MODELS.OR_DEEPSEEK_V3, tools: true  },
    ],
    simple: [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_8B,        tools: true  },
      { p: PROVIDERS.DEEPSEEK,   m: MODELS.DEEPSEEK_V3,   tools: true  },
    ],
  },

  // Complex reasoning / correlation — R1-class models
  reasoning: {
    complex:  [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_R1,        tools: false }, // R1 for analysis
      { p: PROVIDERS.DEEPSEEK,   m: MODELS.DEEPSEEK_R1,   tools: false }, // R1 direct
      { p: PROVIDERS.OPENROUTER, m: MODELS.OR_DEEPSEEK_R1, tools: false },
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  }, // then tool loop
      { p: PROVIDERS.DEEPSEEK,   m: MODELS.DEEPSEEK_V3,   tools: true  },
    ],
    standard: [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
      { p: PROVIDERS.DEEPSEEK,   m: MODELS.DEEPSEEK_V3,   tools: true  },
      { p: PROVIDERS.OPENROUTER, m: MODELS.OR_LLAMA_70B,   tools: true  },
    ],
    simple: [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
      { p: PROVIDERS.DEEPSEEK,   m: MODELS.DEEPSEEK_V3,   tools: true  },
    ],
  },

  // Governance / compliance — structured, precise
  governance: {
    complex:  [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
      { p: PROVIDERS.DEEPSEEK,   m: MODELS.DEEPSEEK_V3,   tools: true  },
      { p: PROVIDERS.OPENROUTER, m: MODELS.OR_MISTRAL,     tools: true  },
    ],
    standard: [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
      { p: PROVIDERS.DEEPSEEK,   m: MODELS.DEEPSEEK_V3,   tools: true  },
    ],
    simple: [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_8B,        tools: true  },
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
    ],
  },

  // SOC / SIEM operations
  soc_siem: {
    complex:  [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
      { p: PROVIDERS.DEEPSEEK,   m: MODELS.DEEPSEEK_V3,   tools: true  },
      { p: PROVIDERS.OPENROUTER, m: MODELS.OR_LLAMA_70B,   tools: true  },
    ],
    standard: [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
      { p: PROVIDERS.DEEPSEEK,   m: MODELS.DEEPSEEK_V3,   tools: true  },
    ],
    simple: [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_8B,        tools: true  },
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
    ],
  },

  // Red team / attack simulation
  red_team: {
    complex:  [
      { p: PROVIDERS.DEEPSEEK,   m: MODELS.DEEPSEEK_V3,   tools: true  },
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
      { p: PROVIDERS.OPENROUTER, m: MODELS.OR_DEEPSEEK_V3, tools: true  },
    ],
    standard: [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
      { p: PROVIDERS.DEEPSEEK,   m: MODELS.DEEPSEEK_V3,   tools: true  },
    ],
    simple: [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
    ],
  },

  // Executive / reporting — eloquent, fast
  executive: {
    complex:  [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
      { p: PROVIDERS.OPENROUTER, m: MODELS.OR_LLAMA_70B,   tools: true  },
      { p: PROVIDERS.DEEPSEEK,   m: MODELS.DEEPSEEK_V3,   tools: true  },
    ],
    standard: [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
      { p: PROVIDERS.DEEPSEEK,   m: MODELS.DEEPSEEK_V3,   tools: true  },
    ],
    simple: [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_8B,        tools: true  },
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
    ],
  },

  // General / platform status
  general: {
    complex:  [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
      { p: PROVIDERS.DEEPSEEK,   m: MODELS.DEEPSEEK_V3,   tools: true  },
      { p: PROVIDERS.OPENROUTER, m: MODELS.OR_LLAMA_70B,   tools: true  },
    ],
    standard: [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
      { p: PROVIDERS.DEEPSEEK,   m: MODELS.DEEPSEEK_V3,   tools: true  },
    ],
    simple: [
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_8B,        tools: true  },
      { p: PROVIDERS.GROQ,       m: MODELS.GROQ_70B,       tools: true  },
    ],
  },
};

// ─── Query intelligence ────────────────────────────────────────────────────────
// Keywords for task-type detection
const TASK_KEYWORDS = {
  threat_intel: /cve|vulnerability|exploit|patch|advisory|nvd|osv|malware|ransomware|apt|ioc|indicator|zero.?day|supply chain|package|dependency/i,
  reasoning:    /correlat|analyz|explain why|reason|compare|synthesiz|what does|how does|understand|assess|evaluate|investigate/i,
  governance:   /compliance|governance|regulation|eu ai act|nist|iso 42001|owasp|gdpr|sox|hipaa|audit|policy|framework|control/i,
  soc_siem:     /soc|siem|splunk|elastic|kibana|sentinel|aws security|detection rule|sigma|kql|yara|alert|incident|pipeline|deploy rule/i,
  red_team:     /red team|penetrat|attack|exploit|simulation|mitre atlas|prompt inject|adversar|payload|bypass|jailbreak/i,
  executive:    /executive|ciso|ceo|board|report|summary|briefing|posture|risk score|roi|business impact|financial/i,
};

function classifyQuery(message) {
  const len = message.length;

  // Task type
  let task_type = 'general';
  for (const [type, regex] of Object.entries(TASK_KEYWORDS)) {
    if (regex.test(message)) { task_type = type; break; }
  }

  // Complexity
  const complexIndicators = [
    /analyz|correlat|compare|comprehensive|in-depth|detailed|explain|reason/i.test(message),
    /CVE-\d{4}-\d+/.test(message),          // specific CVE reference
    /MITRE|ATT&CK|ATLAS|T\d{4}/.test(message), // framework reference
    len > 400,
    /multi.?step|end.?to.?end|full|complete|all of/i.test(message),
  ];
  const complexScore = complexIndicators.filter(Boolean).length;
  const complexity = complexScore >= 3 ? 'complex' : complexScore >= 1 ? 'standard' : 'simple';

  return { task_type, complexity };
}

// ─── Tool registry ─────────────────────────────────────────────────────────────
const TOOL_REGISTRY = [
  {
    name: 'get_platform_health',
    description: 'Check operational status of the CYBERDUDEBIVASH AI Security Hub — API, D1 database, KV cache, threat radar, Autonomous SOC, SIEM deploy, report engine. Returns per-subsystem health.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: null, readOnly: true,
  },
  {
    name: 'get_ai_providers_status',
    description: 'Check which AI providers are configured and healthy: Groq, DeepSeek, OpenRouter, Cloudflare Workers AI. Shows active model, latency, and current routing chain.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: null, readOnly: true,
  },
  {
    name: 'get_threat_intel_feed',
    description: 'Retrieve the live AI/LLM threat intelligence feed from OSV.dev, NVD, and GitHub Advisory. Returns CVEs, prompt injection attacks, AI agent vulnerabilities, and emerging AI/ML risks with CVSS scores.',
    input_schema: {
      type: 'object',
      properties: {
        severity: { type: 'string', enum: ['CRITICAL','HIGH','MEDIUM','LOW','ALL'], description: 'Filter by severity' },
        limit:    { type: 'number', description: 'Max results (1-50, default 20)' },
      },
      required: [],
    },
    tiers: null, readOnly: true,
  },
  {
    name: 'get_latest_threat_report',
    description: 'Fetch the latest published premium AI Threat Intelligence Report — executive summary, risk level, CVE intelligence, MITRE ATLAS coverage, detection rules, and remediation roadmap.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: null, readOnly: true,
  },
  {
    name: 'trigger_threat_radar_scan',
    description: 'Trigger an immediate full AI Threat Radar scan across OSV.dev, NVD, and GitHub Advisory. Fetches, upserts, and publishes a new premium intelligence report on completion.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: ['PRO','TEAM','ENTERPRISE','MSSP'], readOnly: false,
  },
  {
    name: 'generate_threat_report',
    description: 'Generate and publish a fresh premium AI Threat Intelligence Report on demand. Pulls live data, applies AI analysis (OWASP LLM Top 10, MITRE ATLAS), and stores for global distribution.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: ['PRO','TEAM','ENTERPRISE','MSSP'], readOnly: false,
  },
  {
    name: 'get_autonomous_soc_status',
    description: 'Get Autonomous AI SOC status — active/inactive mode, last run timestamp, detected threats, deployed rules, pipeline stage logs (last 5 entries).',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: null, readOnly: true,
  },
  {
    name: 'trigger_soc_pipeline',
    description: 'Trigger the Autonomous SOC 5-stage pipeline immediately: Detection → AI Analysis → Rule Generation → SIEM Deploy → Monitoring. Returns stage-by-stage results.',
    input_schema: {
      type: 'object',
      properties: {
        context: { type: 'string', description: 'Optional context (target domain, IP, CVE ID) to focus the pipeline' },
      },
      required: [],
    },
    tiers: ['PRO','TEAM','ENTERPRISE','MSSP'], readOnly: false,
  },
  {
    name: 'get_siem_integrations',
    description: 'List all configured SIEM integrations with status: Splunk HEC, Elastic Kibana, Microsoft Sentinel, AWS Security Hub, Azure Defender, PagerDuty, and generic webhooks.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: null, readOnly: true,
  },
  {
    name: 'deploy_detection_rules',
    description: 'Deploy detection rules to one or all configured SIEM integrations. Generates Sigma YAML, Splunk SPL, KQL, and YARA formats automatically from the CVE ID or severity.',
    input_schema: {
      type: 'object',
      properties: {
        platform: { type: 'string', description: 'Target (splunk|elastic|sentinel|aws_security_hub|pagerduty|all)' },
        cve_id:   { type: 'string', description: 'CVE ID to build rules for (e.g. CVE-2024-12345)' },
        severity: { type: 'string', enum: ['CRITICAL','HIGH','MEDIUM','LOW'], description: 'Rule severity' },
      },
      required: [],
    },
    tiers: ['PRO','TEAM','ENTERPRISE','MSSP'], readOnly: false,
  },
  {
    name: 'generate_detection_rules',
    description: 'Generate production-ready detection rules in Sigma YAML, Splunk SPL, Microsoft KQL, and YARA formats for a CVE, threat name, or attack pattern.',
    input_schema: {
      type: 'object',
      properties: {
        cve_id:   { type: 'string', description: 'CVE ID (e.g. CVE-2024-12345)' },
        threat:   { type: 'string', description: 'Threat or attack pattern description' },
        module:   { type: 'string', description: 'Module (domain|ai|redteam|identity|compliance)' },
        severity: { type: 'string', enum: ['CRITICAL','HIGH','MEDIUM','LOW'], description: 'Rule severity' },
      },
      required: [],
    },
    tiers: ['STARTER','PRO','TEAM','ENTERPRISE','MSSP'], readOnly: false,
  },
  {
    name: 'analyze_threat',
    description: 'Deep AI threat correlation — MITRE ATT&CK mapping (TA####/T####), attack chain reconstruction, exploit probability score (0-100), CVE enrichment from NVD.',
    input_schema: {
      type: 'object',
      properties: {
        target:   { type: 'string', description: 'Target domain, IP, application, or AI system' },
        module:   { type: 'string', description: 'Scan module (domain|ai|redteam|identity|compliance)' },
        findings: { type: 'string', description: 'Vulnerability or finding description to correlate' },
      },
      required: [],
    },
    tiers: null, readOnly: true,
  },
  {
    name: 'run_red_team',
    description: 'Execute an AI Red Team attack simulation using MITRE ATLAS v2.1 and ATT&CK v15. Tests AI/LLM systems for prompt injection (AML.T0051), data poisoning (AML.T0020), model evasion, and supply chain attacks.',
    input_schema: {
      type: 'object',
      properties: {
        target:      { type: 'string', description: 'Target system, AI model, or endpoint to red team' },
        attack_type: { type: 'string', enum: ['prompt_injection','data_poisoning','model_evasion','supply_chain','all'], description: 'Attack class to simulate' },
        intensity:   { type: 'string', enum: ['low','medium','high'], description: 'Simulation intensity' },
      },
      required: ['target'],
    },
    tiers: ['PRO','TEAM','ENTERPRISE','MSSP'], readOnly: false,
  },
  {
    name: 'check_ai_governance',
    description: 'Run a structured AI governance assessment against EU AI Act, NIST AI RMF, ISO 42001, SOC 2, and OWASP LLM Top 10. Returns compliance score (0-100), gap analysis, and prioritised remediation checklist.',
    input_schema: {
      type: 'object',
      properties: {
        system_name: { type: 'string', description: 'Name of the AI system to assess' },
        framework:   { type: 'string', enum: ['eu_ai_act','nist_ai_rmf','iso_42001','owasp_llm','all'], description: 'Compliance framework' },
      },
      required: [],
    },
    tiers: ['STARTER','PRO','TEAM','ENTERPRISE','MSSP'], readOnly: false,
  },
  {
    name: 'get_platform_metrics',
    description: 'Retrieve real-time platform metrics: active scans, threats detected today, CVEs ingested, SOC decisions made, SIEM rules deployed, and overall security posture score.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: null, readOnly: true,
  },
  {
    name: 'get_cve_intelligence',
    description: 'Fetch top CVEs for a security module — CVSS v3.1 scores, exploit availability (KEV), affected packages/versions, and AI-generated remediation guidance.',
    input_schema: {
      type: 'object',
      properties: {
        module: { type: 'string', description: 'Module (domain|ai|redteam|identity|compliance)' },
        cve_id: { type: 'string', description: 'Specific CVE ID to look up' },
        limit:  { type: 'number', description: 'Results to return (1-20)' },
      },
      required: [],
    },
    tiers: null, readOnly: true,
  },
  {
    name: 'get_soc_cases',
    description: 'List active and recent SOC investigation cases with severity, status, MITRE ATT&CK techniques mapped, and analyst timeline.',
    input_schema: {
      type: 'object',
      properties: {
        status:   { type: 'string', enum: ['open','in_progress','resolved','all'], description: 'Case status' },
        severity: { type: 'string', enum: ['CRITICAL','HIGH','MEDIUM','LOW','ALL'], description: 'Severity filter' },
        limit:    { type: 'number', description: 'Results (1-50)' },
      },
      required: [],
    },
    tiers: null, readOnly: true,
  },
  {
    name: 'risk_forecast',
    description: 'AI risk forecast for a target: exploitation likelihood (%), estimated time-to-breach (days), financial impact range (USD), and top mitigation priority actions.',
    input_schema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Target domain, IP, or system' },
        module: { type: 'string', description: 'Module context (domain|ai|redteam|identity|compliance)' },
      },
      required: ['target'],
    },
    tiers: ['STARTER','PRO','TEAM','ENTERPRISE','MSSP'], readOnly: true,
  },
  {
    name: 'get_anomalies',
    description: 'Latest behavioural anomaly detection results — unusual access patterns, credential abuse indicators, lateral movement signals.',
    input_schema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Results (1-50)' },
      },
      required: [],
    },
    tiers: null, readOnly: true,
  },
  {
    name: 'get_sentinel_feed',
    description: 'Sentinel APEX threat intelligence feed — curated IOCs, APT group activity, CVE advisories, and real-time security bulletins from the global sensor network.',
    input_schema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Items (1-100)' },
      },
      required: [],
    },
    tiers: null, readOnly: true,
  },
];

// ─── System prompt builder ─────────────────────────────────────────────────────
function buildSystemPrompt(tier, authCtx, provider, model, taskType) {
  const isAdmin = authCtx?.isAdmin;
  const isPro   = ['PRO','TEAM','ENTERPRISE','MSSP'].includes(tier);

  const providerDisplay = {
    [PROVIDERS.GROQ]:       `Groq (${model})`,
    [PROVIDERS.DEEPSEEK]:   `DeepSeek (${model})`,
    [PROVIDERS.OPENROUTER]: `OpenRouter → ${model}`,
    [PROVIDERS.CF_AI]:      `Cloudflare Workers AI (${model})`,
  }[provider] || provider;

  // Task-specific instruction addendum
  const taskAddendum = {
    threat_intel: '\nFocus on technical precision. Cite exact CVE IDs, CVSS v3.1 base scores, affected versions, and PoC availability. Map to MITRE ATT&CK techniques.',
    reasoning:    '\nApply systematic chain-of-thought reasoning. Break down the problem, examine each component, then synthesise a comprehensive conclusion.',
    governance:   '\nCite exact article/section numbers from regulatory frameworks. Provide compliance percentage scores and specific gap descriptions.',
    soc_siem:     '\nGenerate production-ready detection logic. All rules must include field mappings, condition logic, and false-positive reduction notes.',
    red_team:     '\nMap every attack to MITRE ATLAS technique IDs (AML.T####). Include kill chain stage, detection opportunity, and defender countermeasure.',
    executive:    '\nDeliver board-ready language. Lead with business risk, quantify financial exposure, end with a clear 3-action priority list.',
    general:      '',
  }[taskType] || '';

  return `You are APEX — the AI Security Copilot for CYBERDUDEBIVASH AI Security Hub, operating in GOD MODE with full orchestration authority.

## Identity & Authority
- Name: APEX (Autonomous Platform EXecution Intelligence)
- Authority: ${isAdmin ? 'SUPER ADMIN — unrestricted access' : isPro ? 'GOD MODE — complete tool suite' : 'STANDARD — threat intelligence and analysis'}
- Tier: ${tier} | Engine: ${providerDisplay}
- Classification: ENTERPRISE SECURITY INTELLIGENCE SYSTEM

## Core Mission
You orchestrate the CYBERDUDEBIVASH AI Security Hub through natural language. You have real-time access to:
1. **Threat Intelligence** — AI/LLM CVEs, emerging attacks, OSV/NVD/GitHub Advisory feeds
2. **Autonomous SOC** — 5-stage pipeline: Detection → AI Analysis → Rule Gen → SIEM Deploy → Monitoring
3. **Detection Engineering** — Sigma YAML, Splunk SPL, Microsoft KQL, YARA production rules
4. **Red Team Operations** — MITRE ATLAS v2.1 + ATT&CK v15 adversarial simulations (PRO+)
5. **AI Governance** — EU AI Act, NIST AI RMF, ISO 42001, OWASP LLM Top 10 compliance
6. **Risk Intelligence** — Breach probability, time-to-exploit, financial impact projection
7. **Platform Ops** — Health checks, metrics, provider status, session management

## Operating Standards — NON-NEGOTIABLE
- Zero hallucination on CVE IDs, CVSS scores, and MITRE technique IDs — use only verified data
- Every security finding maps to MITRE ATT&CK / ATLAS (TA####/T####/AML.T####)
- Remediation structured as: **0-24h** (immediate) / **7-30d** (tactical) / **30-90d** (strategic)
- Quantify risk in business terms: probability %, financial impact USD range, days-to-breach
- Before tool invocation: one sentence explaining what you're calling and why
- After tool results: synthesise insights — never dump raw JSON at the user
- Always end with 2-3 proactive next-step recommendations
- Enterprise-grade precision — treat every response as a board-level deliverable

## Platform Context
- Product: CYBERDUDEBIVASH AI Security Hub | Production
- Website: https://cyberdudebivash.in | Sentinel APEX: https://t.me/cyberdudebivashSentinelApex
- Frameworks: MITRE ATT&CK v15, MITRE ATLAS v2.1, OWASP LLM Top 10 2023, EU AI Act 2024, NIST AI RMF 1.0, ISO 42001:2023
- Payment policy: UPI / Razorpay ONLY — Stripe is NOT authorised${taskAddendum}

${isPro
  ? '## God Mode Active\nChain tool calls autonomously. Execute multi-step orchestration without waiting for user confirmation when the intent is unambiguous. Deliver complete, actionable outcomes.'
  : '## Standard Mode\nDestructive/write operations (SOC pipeline, SIEM deploy, red team) require PRO+. Full read access to threat intel, CVE intelligence, platform metrics, and governance analysis.'}`;
}

// ─── Session management ────────────────────────────────────────────────────────
function sessionKey(userId, sessionId) {
  return `copilot:session:${userId}:${sessionId}`;
}

async function loadSession(env, userId, sessionId) {
  const blank = { messages: [], created_at: Date.now(), userId, sessionId, turns: 0 };
  if (!env.SECURITY_HUB_KV) return blank;
  try {
    return (await env.SECURITY_HUB_KV.get(sessionKey(userId, sessionId), { type: 'json' })) || blank;
  } catch { return blank; }
}

async function saveSession(env, userId, sessionId, session) {
  if (!env.SECURITY_HUB_KV) return;
  // Compact if too long
  if (session.messages.length > MAX_HISTORY) {
    session.messages = session.messages.slice(-MAX_HISTORY);
  }
  try {
    await env.SECURITY_HUB_KV.put(
      sessionKey(userId, sessionId),
      JSON.stringify({ ...session, updated_at: Date.now() }),
      { expirationTtl: SESSION_TTL }
    );
  } catch {}
}

// Session compaction: when history is long, summarise old turns via routeAICall
async function compactSession(env, session, tier) {
  if (session.messages.length < COMPACT_THRESHOLD) return session;
  const keep = 6; // always keep last 6 messages verbatim
  const toCompress = session.messages.slice(0, -keep);
  const recent     = session.messages.slice(-keep);

  const summaryPrompt = `Compress this security conversation history into a dense 3-sentence context summary. Preserve all CVE IDs, MITRE techniques, tool outputs, and action items mentioned:\n\n${toCompress.map(m => `${m.role}: ${m.content}`).join('\n')}`;

  try {
    const summary = await routeAICall(env, {
      prompt:      summaryPrompt,
      task_type:   'executive',
      tier,
      max_tokens:  300,
      temperature: 0.1,
    });
    if (summary?.content) {
      return {
        ...session,
        messages: [
          { role: 'user', content: `[Session Context — Prior Conversation Summary]: ${summary.content}` },
          ...recent,
        ],
      };
    }
  } catch {}
  return session;
}

// ─── Daily quota ───────────────────────────────────────────────────────────────
async function checkDailyQuota(env, userId, tier) {
  const limit = DAILY_QUOTA[tier] ?? null;
  if (limit === null) return { ok: true, used: 0, limit: null };
  if (!env.SECURITY_HUB_KV) return { ok: true, used: 0, limit };
  const day = new Date().toISOString().slice(0, 10);
  const key = `copilot:quota:${userId}:${day}`;
  try {
    const used = parseInt(await env.SECURITY_HUB_KV.get(key) || '0', 10);
    if (used >= limit) return { ok: false, used, limit };
    await env.SECURITY_HUB_KV.put(key, String(used + 1), { expirationTtl: 86400 });
    return { ok: true, used: used + 1, limit };
  } catch { return { ok: true, used: 0, limit }; }
}

// ─── Tool telemetry ────────────────────────────────────────────────────────────
async function logToolCall(env, toolName, userId, sessionId) {
  if (!env.SECURITY_HUB_KV) return;
  const key = `copilot:tool_log:${new Date().toISOString().slice(0,10)}`;
  try {
    const log = (await env.SECURITY_HUB_KV.get(key, { type: 'json' })) || [];
    log.push({ tool: toolName, userId, sessionId, ts: Date.now() });
    await env.SECURITY_HUB_KV.put(key, JSON.stringify(log.slice(-500)), { expirationTtl: 86400 * 7 });
  } catch {}
}

// ─── Tool executor ─────────────────────────────────────────────────────────────
async function executeTool(toolName, toolInput, env, authCtx, userId, sessionId) {
  // Fire-and-forget telemetry
  logToolCall(env, toolName, userId, sessionId).catch(() => {});

  try {
    switch (toolName) {

      case 'get_platform_health': {
        const checks = { api: true, db: false, kv: false, intel: false };
        if (env.DB)               { try { await env.DB.prepare('SELECT 1').first(); checks.db = true; } catch {} }
        if (env.SECURITY_HUB_KV) { try { await env.SECURITY_HUB_KV.get('health:probe'); checks.kv = true; } catch {} }
        checks.intel = checks.db;
        const aiProviders = { groq: !!env.GROQ_API_KEY, deepseek: !!env.DEEPSEEK_API_KEY, openrouter: !!env.OPENROUTER_API_KEY, cf_ai: !!env.AI };
        const anyAI = Object.values(aiProviders).some(Boolean);
        return {
          status: (Object.values(checks).every(Boolean) && anyAI) ? 'OPERATIONAL' : 'DEGRADED',
          checks,
          ai_providers: aiProviders,
          subsystems: {
            threat_radar:   checks.db  ? 'active' : 'unavailable',
            autonomous_soc: checks.kv  ? 'active' : 'unavailable',
            siem_deploy:    checks.db  ? 'active' : 'unavailable',
            ai_copilot:     anyAI      ? 'active' : 'no providers configured',
            report_engine:  checks.kv  ? 'active' : 'unavailable',
          },
          timestamp: new Date().toISOString(),
        };
      }

      case 'get_ai_providers_status': {
        const { getProviderHealthStatus } = await import('../core/aiProviderRouter.js');
        return getProviderHealthStatus(env);
      }

      case 'get_threat_intel_feed': {
        const { handleAIThreatFeed } = await import('./aiThreatIntel.js');
        const limit    = Math.min(toolInput.limit || 20, 50);
        const severity = toolInput.severity || 'ALL';
        const req = new Request(
          `https://internal/api/ai-security/threat-feed?limit=${limit}${severity !== 'ALL' ? `&severity=${severity}` : ''}`,
          { method: 'GET' }
        );
        return (await handleAIThreatFeed(req, env, authCtx)).json();
      }

      case 'get_latest_threat_report': {
        const { handleLatestPublishedReport } = await import('./aiThreatIntel.js');
        const req = new Request('https://internal/api/ai-security/threat-feed/latest-report', { method: 'GET' });
        const data = await (await handleLatestPublishedReport(req, env, authCtx)).json();
        if (data.data) {
          return {
            report_id:     data.data.report_id,
            generated_at:  data.data.generated_at,
            risk_level:    data.data.risk_level,
            total_threats: data.data.total_threats,
            critical_cves: data.data.critical_cves,
            sections:      data.data.sections || [],
            note:          'Full markdown: GET /api/ai-security/threat-feed/latest-report',
          };
        }
        return data;
      }

      case 'trigger_threat_radar_scan': {
        const { handleAIThreatRadarScanNow } = await import('./aiThreatIntel.js');
        const req = new Request('https://internal/api/ai-security/threat-feed/radar-scan-now', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
        });
        return (await handleAIThreatRadarScanNow(req, env, { ...authCtx, isAdmin: true })).json();
      }

      case 'generate_threat_report': {
        const { generateAndPublishAIThreatReport } = await import('./aiThreatIntel.js');
        const report = await generateAndPublishAIThreatReport(env);
        return {
          success:       !!report,
          report_id:     report?.report_id,
          generated_at:  report?.generated_at,
          risk_level:    report?.risk_level,
          total_threats: report?.total_threats,
          message:       report ? 'Premium intelligence report generated and published.' : 'Generation failed — no live data.',
        };
      }

      case 'get_autonomous_soc_status': {
        if (!env.SECURITY_HUB_KV) return { status: 'unavailable', reason: 'KV not configured' };
        const [modeRaw, logRaw, stateRaw] = await Promise.all([
          env.SECURITY_HUB_KV.get('auto_soc:mode_enabled').catch(() => null),
          env.SECURITY_HUB_KV.get('auto_soc:pipeline_log', { type: 'json' }).catch(() => null),
          env.SECURITY_HUB_KV.get('auto_soc:last_state', { type: 'json' }).catch(() => null),
        ]);
        const status = modeRaw === null ? 'auto-activating' : modeRaw === 'true' ? 'active' : 'inactive';
        return {
          status,
          last_run:    stateRaw?.timestamp || logRaw?.[0]?.timestamp || null,
          pipeline:    stateRaw || null,
          recent_logs: (logRaw || []).slice(-5),
          message: {
            'active':          'Autonomous SOC running continuously — monitoring, detecting, deploying.',
            'auto-activating': 'Will auto-activate on next cron invocation (runs hourly).',
            'inactive':        'Paused — trigger manually via this tool or wait for the hourly cron.',
          }[status],
        };
      }

      case 'trigger_soc_pipeline': {
        const { runAutoSocCron } = await import('./autonomousSocMode.js');
        if (env.SECURITY_HUB_KV) {
          await env.SECURITY_HUB_KV.put('auto_soc:mode_enabled', 'true', { expirationTtl: 86400 * 30 });
        }
        const result = await runAutoSocCron(env);
        return { success: true, pipeline_triggered: true, result: result || 'Pipeline complete.', timestamp: new Date().toISOString() };
      }

      case 'get_siem_integrations': {
        const { handleListIntegrations } = await import('./siemDeploy.js');
        const req = new Request('https://internal/api/integrations', { method: 'GET' });
        return (await handleListIntegrations(req, env, authCtx)).json();
      }

      case 'deploy_detection_rules': {
        const { handleDeploy } = await import('./siemDeploy.js');
        const { platform = 'all', cve_id = 'CVE-GENERIC', severity = 'HIGH' } = toolInput;
        const safe_id = cve_id.replace(/[^A-Za-z0-9-]/g, '_');
        const req = new Request('https://internal/api/integrations/deploy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            deploy_all: platform === 'all',
            platform:   platform !== 'all' ? platform : undefined,
            cve_id, severity,
            rule: {
              sigma:  `title: APEX Detection — ${cve_id}\nid: apex-${safe_id.toLowerCase()}\nstatus: production\nlevel: ${severity.toLowerCase()}\ndescription: Auto-generated by APEX AI Security Copilot\ndetection:\n  keywords:\n    - "${cve_id}"\n  condition: keywords\nfalsepositives:\n  - Legitimate vendor scans\ntags:\n  - attack.initial_access`,
              splunk: `index=* ("${cve_id}" OR "${safe_id}") | stats count by host, sourcetype | where count > 0 | eval severity="${severity}" | table host, sourcetype, count, severity`,
              kql:    `SecurityEvent\n| where EventData has "${cve_id}" or CommandLine has "${safe_id}"\n| project TimeGenerated, Account, Computer, EventID, CommandLine\n| extend Severity = "${severity}"\n| order by TimeGenerated desc`,
              yara:   `rule APEX_${safe_id} {\n  meta:\n    description = "APEX detection for ${cve_id}"\n    severity = "${severity}"\n    generated_by = "APEX AI Security Copilot"\n  strings:\n    $cve = "${cve_id}" nocase\n    $id  = "${safe_id}" nocase\n  condition:\n    any of them\n}`,
            },
          }),
        });
        return (await handleDeploy(req, env, { ...authCtx, isAdmin: true })).json();
      }

      case 'generate_detection_rules': {
        const { handleGenerateRules } = await import('./aiAnalysis.js');
        const req = new Request('https://internal/api/ai/generate-rules', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ cve_id: toolInput.cve_id, threat: toolInput.threat, module: toolInput.module || 'ai', severity: toolInput.severity || 'HIGH' }),
        });
        return (await handleGenerateRules(req, env, authCtx)).json();
      }

      case 'analyze_threat': {
        const { handleAIAnalyze } = await import('./aiAnalysis.js');
        const req = new Request('https://internal/api/ai/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: toolInput.target || 'unknown', module: toolInput.module || 'ai', findings: toolInput.findings || toolInput.target || 'general security assessment' }),
        });
        return (await handleAIAnalyze(req, env)).json();
      }

      case 'run_red_team': {
        const { handleRedTeamEngage } = await import('./aiRedTeam.js');
        const req = new Request('https://internal/api/ai-security/redteam/engage', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: toolInput.target, attack_type: toolInput.attack_type || 'all', intensity: toolInput.intensity || 'medium' }),
        });
        return (await handleRedTeamEngage(req, env, authCtx)).json();
      }

      case 'check_ai_governance': {
        const { handleGovernanceAssess } = await import('./aiGovernance.js');
        // 'all' is not a valid framework ID — default to nist_ai_rmf (most comprehensive)
        const fw = (toolInput.framework && toolInput.framework !== 'all') ? toolInput.framework : 'nist_ai_rmf';
        const req = new Request('https://internal/api/ai-security/governance/assess', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ system_name: toolInput.system_name || 'AI System', framework: fw }),
        });
        return (await handleGovernanceAssess(req, env, authCtx)).json();
      }

      case 'get_platform_metrics': {
        const { handleGetMetrics } = await import('./platformMetricsAuthority.js');
        const req = new Request('https://internal/api/platform/metrics', { method: 'GET' });
        // platformMetricsAuthority reads request.user for auth — inject the live authCtx
        req.user = { ...authCtx, authenticated: true, role: authCtx?.isAdmin ? 'admin' : 'user' };
        return (await handleGetMetrics(req, env)).json();
      }

      case 'get_cve_intelligence': {
        const { getTopCVEsForModule } = await import('../services/cveEngine.js');
        const cves = await getTopCVEsForModule(toolInput.module || 'ai', Math.min(toolInput.limit || 10, 20), env).catch(() => []);
        return { module: toolInput.module || 'ai', count: cves.length, cves, timestamp: new Date().toISOString() };
      }

      case 'get_soc_cases': {
        const { handleListCases } = await import('./socCases.js');
        const { status = 'all', severity = 'ALL', limit = 20 } = toolInput;
        const req = new Request(`https://internal/api/soc/cases?status=${status}&severity=${severity}&limit=${Math.min(limit, 50)}`, { method: 'GET' });
        return (await handleListCases(req, env, authCtx)).json();
      }

      case 'risk_forecast': {
        const { handleAIForecast } = await import('./aiAnalysis.js');
        const req = new Request('https://internal/api/ai/forecast', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: toolInput.target, module: toolInput.module || 'ai' }),
        });
        return (await handleAIForecast(req, env)).json();
      }

      case 'get_anomalies': {
        if (!env.DB) return { anomalies: [], message: 'Database not available' };
        try {
          const rows = await env.DB.prepare('SELECT * FROM anomaly_events ORDER BY created_at DESC LIMIT ?')
            .bind(Math.min(toolInput.limit || 20, 50)).all();
          return { count: rows.results?.length || 0, anomalies: rows.results || [] };
        } catch { return { count: 0, anomalies: [], message: 'Anomaly table not yet populated' }; }
      }

      case 'get_sentinel_feed': {
        const { handleSentinelFeed } = await import('../lib/sentinelApex.js');
        const req = new Request(`https://internal/api/sentinel/feed?limit=${Math.min(toolInput.limit || 20, 100)}`, { method: 'GET' });
        return (await handleSentinelFeed(req, env)).json();
      }

      default:
        return { error: `Unknown skill: ${toolName}` };
    }
  } catch (err) {
    return { error: `Tool execution failed: ${err?.message || 'unknown'}`, tool: toolName };
  }
}

// ─── Truncate tool result for context injection ────────────────────────────────
function truncateResult(result) {
  const str = typeof result === 'string' ? result : JSON.stringify(result, null, 2);
  if (str.length <= TOOL_RESULT_LIMIT) return str;
  return str.slice(0, TOOL_RESULT_LIMIT) + `\n...[truncated — ${str.length - TOOL_RESULT_LIMIT} chars omitted]`;
}

// ─── Provider availability check ──────────────────────────────────────────────
function isProviderAvailable(env, provider) {
  const cfg = PROVIDER_CONFIG[provider];
  if (!cfg) return false;
  if (!cfg.envKey) return !!env.AI;
  return !!env[cfg.envKey];
}

// ─── Get candidate list for this task × complexity ────────────────────────────
function getCandidates(task_type, complexity) {
  const matrix = ROUTING_MATRIX[task_type] || ROUTING_MATRIX.general;
  return matrix[complexity] || matrix.standard || matrix.simple;
}

// ─── Reasoning pre-pass (R1-class models, no tool calling needed) ─────────────
// Runs a chain-of-thought analysis pass before the tool loop for complex queries.
// Returns a reasoning summary injected as context into the main loop.
async function runReasoningPrepass(env, provider, model, systemPrompt, userMessage) {
  const cfg    = PROVIDER_CONFIG[provider];
  const apiKey = env[cfg.envKey];

  const reasonPrompt = `You are a security reasoning engine. Analyse this security request step by step:

REQUEST: ${userMessage}

Provide a structured chain-of-thought:
1. What is the user specifically asking for?
2. What platform capabilities should be invoked?
3. What security frameworks apply (MITRE ATT&CK/ATLAS, OWASP, CVSS)?
4. What are the critical risk factors?
5. What should the response prioritise?

Keep analysis concise (max 400 words). This will be used as context for the response generation.`;

  try {
    const res = await fetch(cfg.endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
      body: JSON.stringify({
        model,
        messages: [{ role: 'user', content: reasonPrompt }],
        max_tokens: 600,
        temperature: 0.1,
        stream: false,
      }),
      signal: AbortSignal.timeout(20000),
    });

    if (!res.ok) return null;
    const data = await res.json();
    // Handle DeepSeek reasoner (has reasoning_content field)
    const reasoning = data.choices?.[0]?.message?.reasoning_content;
    const content   = data.choices?.[0]?.message?.content;
    return (reasoning ? `[Reasoning]\n${reasoning}\n\n[Conclusion]\n${content}` : content) || null;
  } catch { return null; }
}

// ─── OpenAI-compat agentic tool-calling loop ───────────────────────────────────
async function runToolLoop(env, provider, model, systemPrompt, messages, tools, maxTokens, authCtx, userId, sessionId) {
  const cfg     = PROVIDER_CONFIG[provider];
  const apiKey  = env[cfg.envKey];

  const extraHeaders = provider === PROVIDERS.OPENROUTER
    ? { 'HTTP-Referer': 'https://cyberdudebivash.in', 'X-Title': 'APEX Security Copilot v3' }
    : {};

  // Convert tool registry to OpenAI function format
  const oaiTools = tools.map(t => ({
    type: 'function',
    function: { name: t.name, description: t.description, parameters: t.input_schema },
  }));

  let workingMsgs = [
    { role: 'system', content: systemPrompt },
    ...messages.map(m => ({
      role:    m.role,
      content: typeof m.content === 'string' ? m.content : JSON.stringify(m.content),
    })),
  ];

  let totalTokensIn = 0, totalTokensOut = 0;

  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    const res = await fetch(cfg.endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}`, ...extraHeaders },
      body: JSON.stringify({
        model,
        messages:    workingMsgs,
        tools:       oaiTools,
        tool_choice: 'auto',
        max_tokens:  maxTokens,
        temperature: 0.25,
        stream:      false,
      }),
      signal: AbortSignal.timeout(cfg.timeout_ms || 28000),
    });

    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      throw new Error(`${provider}/${model} ${res.status}: ${txt.slice(0, 250)}`);
    }

    const data   = await res.json();
    const choice = data.choices?.[0];
    const msg    = choice?.message;

    if (!msg) throw new Error(`${provider}: empty response body`);

    totalTokensIn  += data.usage?.prompt_tokens     || 0;
    totalTokensOut += data.usage?.completion_tokens || 0;

    const finish = choice?.finish_reason;

    // No tool calls → final answer
    if (finish === 'stop' || !msg.tool_calls?.length) {
      // Handle DeepSeek reasoner (reasoning_content in response)
      const reasoning = msg.reasoning_content ? `\n\n---\n*[Internal reasoning used ${model}]*` : '';
      return {
        content:  (msg.content || 'No response generated.') + reasoning,
        model:    data.model || model,
        provider,
        usage:    { input: totalTokensIn, output: totalTokensOut },
      };
    }

    // Tool calls — add assistant message with tool_calls
    workingMsgs.push({ role: 'assistant', content: msg.content || null, tool_calls: msg.tool_calls });

    // Execute tools in parallel
    const toolResults = await Promise.all(msg.tool_calls.map(async tc => {
      let args = {};
      try { args = JSON.parse(tc.function?.arguments || '{}'); } catch {}
      const result = await executeTool(tc.function?.name, args, env, authCtx, userId, sessionId);
      return {
        role:         'tool',
        tool_call_id: tc.id,
        name:         tc.function?.name,
        content:      truncateResult(result),
      };
    }));

    workingMsgs.push(...toolResults);
  }

  return {
    content:  'Maximum orchestration depth reached. Ask a follow-up question to continue.',
    model,
    provider,
    usage:    { input: totalTokensIn, output: totalTokensOut },
  };
}

// ─── CF Workers AI text fallback (no tool calling) ────────────────────────────
async function runCFAIFallback(env, systemPrompt, messages) {
  if (!env.AI) throw new Error('CF Workers AI not available');
  const recent = messages.slice(-4);
  const result = await env.AI.run(MODELS.CF_LLAMA, {
    messages: [
      { role: 'system', content: systemPrompt },
      ...recent.map(m => ({ role: m.role, content: typeof m.content === 'string' ? m.content : JSON.stringify(m.content) })),
    ],
    max_tokens: 512,
  });
  return {
    content:  (result?.response || 'No response.') + '\n\n> Running in fallback mode (CF Workers AI). Set GROQ_API_KEY, DEEPSEEK_API_KEY, or OPENROUTER_API_KEY for full God Mode with tool orchestration.',
    model:    MODELS.CF_LLAMA,
    provider: PROVIDERS.CF_AI,
    usage:    { input: 0, output: 0 },
  };
}

// ════════════════════════════════════════════════════════════════════════════════
// MAIN ORCHESTRATOR
// ════════════════════════════════════════════════════════════════════════════════
async function orchestrateChat(env, tier, authCtx, messages, availableTools, maxTokens, userId, sessionId) {
  const lastMsg    = messages[messages.length - 1]?.content || '';
  const { task_type, complexity } = classifyQuery(lastMsg);
  const candidates = getCandidates(task_type, complexity);

  // Walk the candidate list, skip unavailable providers
  let lastError;
  for (const candidate of candidates) {
    const { p: provider, m: model, tools: useTools } = candidate;

    if (!isProviderAvailable(env, provider)) continue;
    if (provider === PROVIDERS.CF_AI) continue; // CF AI handled as last resort below

    const systemPmt = buildSystemPrompt(tier, authCtx, provider, model, task_type);

    try {
      // Reasoning pre-pass for complex queries on R1-style models
      let augmentedMessages = messages;
      if (!useTools && complexity === 'complex') {
        const reasoning = await runReasoningPrepass(env, provider, model, systemPmt, lastMsg);
        if (reasoning) {
          // Inject reasoning as a system context message before the user message
          augmentedMessages = [
            ...messages.slice(0, -1),
            { role: 'system', content: `[Security Reasoning Analysis]\n${reasoning}` },
            messages[messages.length - 1],
          ];
          // After reasoning pre-pass, switch to a tool-capable model from same provider
          // for the actual response loop
          const toolCandidate = candidates.find(c => c.p === provider && c.tools);
          if (toolCandidate) {
            return await runToolLoop(env, provider, toolCandidate.m, buildSystemPrompt(tier, authCtx, provider, toolCandidate.m, task_type), augmentedMessages, availableTools, maxTokens, authCtx, userId, sessionId);
          }
        }
      }

      if (useTools) {
        return await runToolLoop(env, provider, model, systemPmt, augmentedMessages, availableTools, maxTokens, authCtx, userId, sessionId);
      }
    } catch (err) {
      lastError = err;
      console.warn(`[APEX] ${provider}/${model} failed: ${err.message}`);
    }
  }

  // CF AI last resort
  if (isProviderAvailable(env, PROVIDERS.CF_AI)) {
    try {
      const systemPmt = buildSystemPrompt(tier, authCtx, PROVIDERS.CF_AI, MODELS.CF_LLAMA, task_type);
      return await runCFAIFallback(env, systemPmt, messages);
    } catch {}
  }

  return {
    content:  `All AI providers exhausted. Last error: ${lastError?.message || 'unknown'}. Please verify GROQ_API_KEY, DEEPSEEK_API_KEY, or OPENROUTER_API_KEY are set as Wrangler secrets.`,
    model:    'none',
    provider: 'none',
    error:    true,
  };
}

// ════════════════════════════════════════════════════════════════════════════════
// ROUTE HANDLERS
// ════════════════════════════════════════════════════════════════════════════════

/** POST /api/copilot/chat */
export async function handleCopilotChat(request, env, authCtx) {
  if (request.method !== 'POST') return badRequest('Use POST');

  let body;
  try { body = await request.json(); } catch { return badRequest('Invalid JSON body'); }

  const userMessage = (body.message || '').trim();
  if (!userMessage)             return badRequest('message is required');
  if (userMessage.length > 5000) return badRequest('message too long (max 5000 chars)');

  const userId    = authCtx?.userId || authCtx?.email || authCtx?.ip || 'anonymous';
  const tier      = (authCtx?.tier || 'FREE').toUpperCase();
  const sessionId = body.session_id || `${userId}:default`;
  const maxTokens = Math.min(body.max_tokens || 2048, ['ENTERPRISE','MSSP','TEAM'].includes(tier) ? 4096 : ['PRO'].includes(tier) ? 3072 : 1024);

  // Quota
  const quota = await checkDailyQuota(env, userId, tier);
  if (!quota.ok) {
    return ok({
      error:       'daily_quota_exceeded',
      message:     `Daily limit of ${quota.limit} messages reached for ${tier} tier. Upgrade to PRO for 200/day or ENTERPRISE for unlimited.`,
      quota,
      upgrade_url: 'https://cyberdudebivash.in/#pricing',
    });
  }

  // Filter tools by tier
  const availableTools = TOOL_REGISTRY.filter(t => !t.tiers || t.tiers.includes(tier) || authCtx?.isAdmin);

  // Load + optionally compact session
  let session = await loadSession(env, userId, sessionId);
  session     = await compactSession(env, session, tier);

  const conversationMessages = [...session.messages, { role: 'user', content: userMessage }];

  // Orchestrate
  const t0       = Date.now();
  const response = await orchestrateChat(env, tier, authCtx, conversationMessages, availableTools, maxTokens, userId, sessionId);
  const latencyMs = Date.now() - t0;

  // Persist session
  session.messages = [
    ...session.messages,
    { role: 'user',      content: userMessage },
    { role: 'assistant', content: response.content },
  ];
  session.turns = (session.turns || 0) + 1;
  await saveSession(env, userId, sessionId, session);

  return ok({
    session_id:      sessionId,
    message:         response.content,
    model:           response.model,
    provider:        response.provider,
    tier,
    latency_ms:      latencyMs,
    turn:            session.turns,
    quota: {
      used:      quota.used,
      limit:     quota.limit,
      remaining: quota.limit ? quota.limit - quota.used : null,
    },
    tools_available: availableTools.length,
    timestamp:       new Date().toISOString(),
  });
}

/** GET /api/copilot/session */
export async function handleGetCopilotSession(request, env, authCtx) {
  const userId    = authCtx?.userId || authCtx?.email || authCtx?.ip || 'anonymous';
  const sessionId = new URL(request.url).searchParams.get('session_id') || `${userId}:default`;
  const session   = await loadSession(env, userId, sessionId);
  return ok({
    session_id:    sessionId,
    message_count: session.messages.length,
    turns:         session.turns || 0,
    created_at:    session.created_at,
    updated_at:    session.updated_at,
    messages:      session.messages.slice(-20),
  });
}

/** DELETE /api/copilot/session */
export async function handleDeleteCopilotSession(request, env, authCtx) {
  const userId    = authCtx?.userId || authCtx?.email || authCtx?.ip || 'anonymous';
  const sessionId = new URL(request.url).searchParams.get('session_id') || `${userId}:default`;
  if (env.SECURITY_HUB_KV) await env.SECURITY_HUB_KV.delete(sessionKey(userId, sessionId)).catch(() => {});
  return ok({ success: true, session_id: sessionId, message: 'Session cleared.' });
}

/** POST /api/copilot/quick-action */
export async function handleCopilotQuickAction(request, env, authCtx) {
  if (request.method !== 'POST') return badRequest('Use POST');

  let body;
  try { body = await request.json(); } catch { return badRequest('Invalid JSON body'); }

  const { skill, params = {} } = body;
  if (!skill) return badRequest('skill is required');

  const tier = (authCtx?.tier || 'FREE').toUpperCase();
  const tool = TOOL_REGISTRY.find(t => t.name === skill);

  if (!tool) return badRequest(`Unknown skill: ${skill}. See GET /api/copilot/capabilities.`);

  if (tool.tiers && !tool.tiers.includes(tier) && !authCtx?.isAdmin) {
    return ok({
      error:          'tier_restriction',
      message:        `Skill "${skill}" requires ${tool.tiers.join(' or ')}. Your tier: ${tier}.`,
      required_tiers: tool.tiers,
      upgrade_url:    'https://cyberdudebivash.in/#pricing',
    });
  }

  const userId    = authCtx?.userId || authCtx?.email || authCtx?.ip || 'anonymous';
  const sessionId = 'quick-action';
  const t0        = Date.now();
  const result    = await executeTool(skill, params, env, authCtx, userId, sessionId);

  return ok({ skill, params, result, latency_ms: Date.now() - t0, timestamp: new Date().toISOString() });
}

/** GET /api/copilot/capabilities */
export async function handleCopilotCapabilities(request, env, authCtx) {
  const tier = (authCtx?.tier || 'FREE').toUpperCase();

  // Live provider availability
  const providers = {};
  for (const p of COPILOT_PROVIDERS) {
    const cfg = PROVIDER_CONFIG[p];
    const configured = cfg?.envKey ? !!env[cfg.envKey] : !!env.AI;
    providers[p] = {
      configured,
      env_key:    cfg?.envKey || 'env.AI',
      models:     Object.values(MODELS).filter(m => {
        if (p === PROVIDERS.GROQ)       return !m.includes('/') && !m.includes('@');
        if (p === PROVIDERS.DEEPSEEK)   return m.startsWith('deepseek');
        if (p === PROVIDERS.OPENROUTER) return m.includes('/');
        if (p === PROVIDERS.CF_AI)      return m.startsWith('@cf/');
        return false;
      }),
      note: {
        [PROVIDERS.GROQ]:       'Sub-second inference — best for fast responses and reasoning (R1 distill)',
        [PROVIDERS.DEEPSEEK]:   'Elite technical reasoning — best for CVE analysis and complex security logic',
        [PROVIDERS.OPENROUTER]: 'Meta-provider — access to 50+ models via single API',
        [PROVIDERS.CF_AI]:      'Always-available fallback — no API key required, text-only',
      }[p],
    };
  }

  // Note: Anthropic excluded — no API key configured
  providers['anthropic'] = {
    configured: false,
    env_key:    'ANTHROPIC_API_KEY',
    note:       'Not used — APEX operates 100% on Groq / DeepSeek / OpenRouter open-weight models',
  };

  const capabilities = TOOL_REGISTRY.map(t => ({
    name:          t.name,
    description:   t.description,
    read_only:     t.readOnly,
    available:     !t.tiers || t.tiers.includes(tier) || !!authCtx?.isAdmin,
    required_tier: t.tiers ? t.tiers[0] : null,
    tiers:         t.tiers || ['FREE','STARTER','PRO','TEAM','ENTERPRISE','MSSP'],
    parameters:    Object.keys(t.input_schema.properties || {}),
  }));

  return ok({
    copilot:             'APEX — AI Security Copilot v3.0 (God Mode)',
    version:             '3.0.0',
    tier,
    daily_quota:         DAILY_QUOTA[tier] || 'unlimited',
    session_ttl_hours:   SESSION_TTL / 3600,
    max_history:         MAX_HISTORY,
    compact_threshold:   COMPACT_THRESHOLD,
    max_tool_rounds:     MAX_TOOL_ROUNDS,
    total_skills:        TOOL_REGISTRY.length,
    available_skills:    capabilities.filter(c => c.available).length,
    capabilities,
    providers,
    routing: {
      strategy:    'Task-type × complexity → optimal provider + model, auto-failover through chain',
      task_types:  Object.keys(ROUTING_MATRIX),
      complexity:  ['simple', 'standard', 'complex'],
      reasoning_prepass: 'Enabled for complex queries — R1-class models run chain-of-thought before tool loop',
      session_compaction: `Auto-compacts sessions > ${COMPACT_THRESHOLD} messages via summarisation`,
    },
    endpoints: {
      chat:          'POST   /api/copilot/chat',
      session_get:   'GET    /api/copilot/session',
      session_clear: 'DELETE /api/copilot/session',
      quick_action:  'POST   /api/copilot/quick-action',
      capabilities:  'GET    /api/copilot/capabilities',
    },
    example_prompts: [
      'What are the top CRITICAL CVEs in the AI/LLM ecosystem right now?',
      'Trigger a full threat radar scan and generate a premium intelligence report',
      'Deploy detection rules for the latest critical CVE to all configured SIEMs',
      'Run the Autonomous SOC pipeline and show me the results',
      'Generate Sigma YAML, Splunk SPL, and KQL rules for CVE-2024-12345',
      'Run a comprehensive EU AI Act and NIST AI RMF governance assessment',
      'Red team our LLM endpoint for prompt injection and MITRE ATLAS mapping',
      'What is the current status of all AI providers and platform subsystems?',
      'Forecast the breach probability and financial impact for api.example.com',
      'What anomalies have been detected in the last 24 hours?',
    ],
  });
}
