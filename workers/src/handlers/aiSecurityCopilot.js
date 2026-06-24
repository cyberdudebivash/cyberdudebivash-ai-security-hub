/**
 * CYBERDUDEBIVASH AI Security Hub — AI Security Copilot v2.0 (God Mode)
 *
 * Full-spectrum AI security orchestration backed by the multi-provider AI mesh:
 *   1. Anthropic (claude-opus-4-8 / sonnet-4-6 / haiku-4-5)  — native tool_use
 *   2. Groq     (llama-3.3-70b-versatile / llama-3.1-8b)     — OpenAI-compat tools
 *   3. DeepSeek (deepseek-chat)                               — OpenAI-compat tools
 *   4. OpenRouter (llama-3.3-70b / claude-sonnet via proxy)   — OpenAI-compat tools
 *   5. Cloudflare Workers AI (llama-3.1-8b)                   — text fallback
 *
 * Provider selection at runtime: whichever keys are present in env, highest
 * quality first. ANTHROPIC_API_KEY is preferred for tool_use fidelity, but the
 * copilot is fully operational on Groq/DeepSeek/OpenRouter alone.
 *
 * Endpoints:
 *   POST   /api/copilot/chat          → multi-turn conversational AI (main)
 *   GET    /api/copilot/session       → retrieve current session history
 *   DELETE /api/copilot/session       → clear session
 *   POST   /api/copilot/quick-action  → direct skill invocation without conversation
 *   GET    /api/copilot/capabilities  → list all 19 orchestration skills + provider status
 *
 * Session storage: KV copilot:session:{userId}:{sessionId}, TTL 24h
 * History window:  last 20 messages
 */

import { ok, badRequest } from '../lib/response.js';
import { PROVIDERS, PROVIDER_CONFIG, routeAICall } from '../core/aiProviderRouter.js';

// ─── Constants ────────────────────────────────────────────────────────────────
const SESSION_TTL   = 86400;   // 24h
const MAX_HISTORY   = 20;      // sliding context window
const MAX_TOOL_ROUNDS = 5;     // agentic loop depth

// Daily message quotas (null = unlimited)
const DAILY_QUOTA = {
  ENTERPRISE: null,
  MSSP:       null,
  TEAM:       500,
  PRO:        200,
  STARTER:    50,
  FREE:       5,
};

// ─── Provider priority for copilot tool-use ───────────────────────────────────
// Anthropic first (best structured tool_use), then OpenAI-compat providers.
const COPILOT_PROVIDER_PRIORITY = [
  PROVIDERS.ANTHROPIC,
  PROVIDERS.GROQ,
  PROVIDERS.DEEPSEEK,
  PROVIDERS.OPENROUTER,
  PROVIDERS.CF_AI,
];

// Model selection per provider × tier
const COPILOT_MODELS = {
  [PROVIDERS.ANTHROPIC]: {
    ENTERPRISE: 'claude-opus-4-8',
    MSSP:       'claude-opus-4-8',
    TEAM:       'claude-sonnet-4-6',
    PRO:        'claude-sonnet-4-6',
    STARTER:    'claude-haiku-4-5-20251001',
    FREE:       'claude-haiku-4-5-20251001',
  },
  [PROVIDERS.GROQ]: {
    ENTERPRISE: 'llama-3.3-70b-versatile',
    MSSP:       'llama-3.3-70b-versatile',
    TEAM:       'llama-3.3-70b-versatile',
    PRO:        'llama-3.3-70b-versatile',
    STARTER:    'llama-3.1-8b-instant',
    FREE:       'llama-3.1-8b-instant',
  },
  [PROVIDERS.DEEPSEEK]: {
    // deepseek-chat supports function calling on all tiers
    _default: 'deepseek-chat',
  },
  [PROVIDERS.OPENROUTER]: {
    ENTERPRISE: 'meta-llama/llama-3.3-70b-instruct',
    MSSP:       'meta-llama/llama-3.3-70b-instruct',
    TEAM:       'meta-llama/llama-3.3-70b-instruct',
    PRO:        'meta-llama/llama-3.3-70b-instruct',
    STARTER:    'meta-llama/llama-3.1-8b-instruct',
    FREE:       'meta-llama/llama-3.1-8b-instruct',
  },
  [PROVIDERS.CF_AI]: {
    _default: '@cf/meta/llama-3.1-8b-instruct',
  },
};

function selectModel(provider, tier) {
  const map = COPILOT_MODELS[provider] || {};
  return map[tier] || map._default || 'llama-3.3-70b-versatile';
}

// ─── Select first available provider from priority list ───────────────────────
function pickProvider(env) {
  for (const p of COPILOT_PROVIDER_PRIORITY) {
    const cfg = PROVIDER_CONFIG[p];
    if (!cfg) continue;
    if (!cfg.envKey) {
      // CF AI — needs env.AI binding
      if (env?.AI) return p;
    } else {
      if (env?.[cfg.envKey]) return p;
    }
  }
  return null;
}

// ─── Tool registry ────────────────────────────────────────────────────────────
// tiers: null = all tiers
const TOOL_REGISTRY = [
  {
    name: 'get_platform_health',
    description: 'Check the overall health and operational status of the CYBERDUDEBIVASH AI Security Hub — API, database, KV, intelligence pipeline, autonomous SOC, SIEM, and report engine.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: null, readOnly: true,
  },
  {
    name: 'get_ai_providers_status',
    description: 'Check which AI providers are currently configured and healthy: Groq, DeepSeek, OpenRouter, Anthropic, and Cloudflare Workers AI. Shows active model, latency, and fallback chain.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: null, readOnly: true,
  },
  {
    name: 'get_threat_intel_feed',
    description: 'Retrieve the latest AI/LLM threat intelligence feed — CVEs, prompt injection attacks, AI agent security issues, and emerging AI/ML vulnerabilities from OSV.dev, NVD, and GitHub Advisory.',
    input_schema: {
      type: 'object',
      properties: {
        severity: { type: 'string', enum: ['CRITICAL','HIGH','MEDIUM','LOW','ALL'], description: 'Filter by severity' },
        limit:    { type: 'number', description: 'Max threats to return (1-50)' },
      },
      required: [],
    },
    tiers: null, readOnly: true,
  },
  {
    name: 'get_latest_threat_report',
    description: 'Fetch the most recently published premium AI Threat Intelligence Report — executive summary, CVE intelligence, prompt attack analysis, Sigma/KQL detection rules, and remediation roadmap.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: null, readOnly: true,
  },
  {
    name: 'trigger_threat_radar_scan',
    description: 'Immediately trigger a full AI Threat Radar scan across OSV.dev, NVD, and GitHub Advisory. Auto-publishes a fresh premium intelligence report on completion.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: ['PRO','TEAM','ENTERPRISE','MSSP'], readOnly: false,
  },
  {
    name: 'generate_threat_report',
    description: 'Generate and publish a fresh premium AI Threat Intelligence Report on demand with live data, AI analysis, OWASP LLM Top 10 coverage, and MITRE ATLAS mapping.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: ['PRO','TEAM','ENTERPRISE','MSSP'], readOnly: false,
  },
  {
    name: 'get_autonomous_soc_status',
    description: 'Get status of the Autonomous AI SOC Command Center — active/inactive mode, last run time, active threats, deployed rules, and pipeline stage.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: null, readOnly: true,
  },
  {
    name: 'trigger_soc_pipeline',
    description: 'Trigger an immediate Autonomous SOC pipeline run: Detection → AI Analysis → Rule Generation → SIEM Deploy → Monitoring. Returns stage results and deployed rules.',
    input_schema: {
      type: 'object',
      properties: {
        context: { type: 'string', description: 'Optional target context (domain, IP, CVE ID)' },
      },
      required: [],
    },
    tiers: ['PRO','TEAM','ENTERPRISE','MSSP'], readOnly: false,
  },
  {
    name: 'get_siem_integrations',
    description: 'List all configured SIEM integrations (Splunk, Elastic, Microsoft Sentinel, AWS Security Hub, PagerDuty, etc.) with configuration status and last-deploy timestamps.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: null, readOnly: true,
  },
  {
    name: 'deploy_detection_rules',
    description: 'Deploy detection rules to one or all configured SIEM integrations. Supports Splunk HEC, Elastic Kibana, Microsoft Sentinel, AWS Security Hub, PagerDuty, and generic webhooks.',
    input_schema: {
      type: 'object',
      properties: {
        platform: { type: 'string', description: 'Target platform (splunk|elastic|sentinel|aws_security_hub|pagerduty|all)' },
        cve_id:   { type: 'string', description: 'CVE ID to generate rules for (e.g. CVE-2024-12345)' },
        severity: { type: 'string', enum: ['CRITICAL','HIGH','MEDIUM','LOW'], description: 'Rule severity' },
      },
      required: [],
    },
    tiers: ['PRO','TEAM','ENTERPRISE','MSSP'], readOnly: false,
  },
  {
    name: 'generate_detection_rules',
    description: 'Generate production-ready detection rules in Sigma YAML, Splunk SPL, KQL, and YARA formats for a given CVE, threat, or attack pattern.',
    input_schema: {
      type: 'object',
      properties: {
        cve_id:   { type: 'string', description: 'CVE ID (e.g. CVE-2024-12345)' },
        threat:   { type: 'string', description: 'Threat name or attack pattern' },
        module:   { type: 'string', description: 'Module (domain|ai|redteam|identity|compliance)' },
        severity: { type: 'string', enum: ['CRITICAL','HIGH','MEDIUM','LOW'], description: 'Severity' },
      },
      required: [],
    },
    tiers: ['STARTER','PRO','TEAM','ENTERPRISE','MSSP'], readOnly: false,
  },
  {
    name: 'analyze_threat',
    description: 'Run deep AI threat correlation — MITRE ATT&CK mapping, attack chain reconstruction, exploit probability, CVE enrichment.',
    input_schema: {
      type: 'object',
      properties: {
        target:   { type: 'string', description: 'Target domain, IP, or system' },
        module:   { type: 'string', description: 'Scan module (domain|ai|redteam|identity|compliance)' },
        findings: { type: 'string', description: 'Vulnerability or finding description' },
      },
      required: [],
    },
    tiers: null, readOnly: true,
  },
  {
    name: 'run_red_team',
    description: 'Execute an AI Red Team simulation using MITRE ATLAS and ATT&CK. Tests for prompt injection, data poisoning, model evasion, and supply chain attacks.',
    input_schema: {
      type: 'object',
      properties: {
        target:      { type: 'string', description: 'Target system or AI model' },
        attack_type: { type: 'string', enum: ['prompt_injection','data_poisoning','model_evasion','supply_chain','all'], description: 'Attack type' },
        intensity:   { type: 'string', enum: ['low','medium','high'], description: 'Intensity level' },
      },
      required: ['target'],
    },
    tiers: ['PRO','TEAM','ENTERPRISE','MSSP'], readOnly: false,
  },
  {
    name: 'check_ai_governance',
    description: 'Run an AI governance assessment against EU AI Act, NIST AI RMF, ISO 42001, SOC 2, and OWASP LLM Top 10. Returns compliance score, gaps, and remediation steps.',
    input_schema: {
      type: 'object',
      properties: {
        system_name: { type: 'string', description: 'Name of the AI system to assess' },
        framework:   { type: 'string', enum: ['eu_ai_act','nist_ai_rmf','iso_42001','owasp_llm','all'], description: 'Framework to assess against' },
      },
      required: [],
    },
    tiers: ['STARTER','PRO','TEAM','ENTERPRISE','MSSP'], readOnly: false,
  },
  {
    name: 'get_platform_metrics',
    description: 'Get real-time platform metrics: active scans, threats detected, CVEs in feed, SOC decisions, SIEM rules deployed, and overall security posture score.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: null, readOnly: true,
  },
  {
    name: 'get_cve_intelligence',
    description: 'Fetch CVE intelligence for a module or specific CVE ID — CVSS scores, exploit availability, affected packages, and remediation guidance.',
    input_schema: {
      type: 'object',
      properties: {
        module: { type: 'string', description: 'Module (domain|ai|redteam|identity|compliance)' },
        cve_id: { type: 'string', description: 'Specific CVE ID (e.g. CVE-2024-12345)' },
        limit:  { type: 'number', description: 'Number of CVEs to return (1-20)' },
      },
      required: [],
    },
    tiers: null, readOnly: true,
  },
  {
    name: 'get_soc_cases',
    description: 'List active and recent SOC investigation cases with severity, status, MITRE ATT&CK techniques, and analyst notes.',
    input_schema: {
      type: 'object',
      properties: {
        status:   { type: 'string', enum: ['open','in_progress','resolved','all'], description: 'Case status filter' },
        severity: { type: 'string', enum: ['CRITICAL','HIGH','MEDIUM','LOW','ALL'], description: 'Severity filter' },
        limit:    { type: 'number', description: 'Number to return (1-50)' },
      },
      required: [],
    },
    tiers: null, readOnly: true,
  },
  {
    name: 'risk_forecast',
    description: 'Generate an AI risk forecast: exploitation likelihood, time-to-breach estimate, financial impact projection, and mitigation priority.',
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
    description: 'Retrieve latest anomaly detection results — unusual access patterns, credential abuse, lateral movement indicators.',
    input_schema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Number of anomalies to return (1-50)' },
      },
      required: [],
    },
    tiers: null, readOnly: true,
  },
  {
    name: 'get_sentinel_feed',
    description: 'Pull the Sentinel APEX threat intelligence feed — curated IOCs, APT group activity, CVE advisories, and real-time security bulletins.',
    input_schema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Items to return (1-100)' },
      },
      required: [],
    },
    tiers: null, readOnly: true,
  },
];

// ─── System prompt ────────────────────────────────────────────────────────────
function buildSystemPrompt(tier, authCtx, activeProvider) {
  const isAdmin = authCtx?.isAdmin;
  const isPro   = ['PRO','TEAM','ENTERPRISE','MSSP'].includes(tier);
  const providerNote = activeProvider
    ? `Active AI provider: ${activeProvider.toUpperCase()} (auto-selected from configured provider mesh)`
    : 'AI provider: auto-selected from available mesh';

  return `You are APEX — the AI Security Copilot for CYBERDUDEBIVASH AI Security Hub. You operate in GOD MODE with full orchestration authority over all platform capabilities.

## Identity
- Name: APEX (Autonomous Platform EXecution Intelligence)
- Authority: ${isAdmin ? 'SUPER ADMIN — unrestricted' : isPro ? 'GOD MODE — full tool access' : 'STANDARD — guided intelligence'}
- User tier: ${tier}
- ${providerNote}

## Mission
Deliver world-class AI-powered security operations. You orchestrate the entire platform:
1. **Threat Intelligence** — AI/LLM ecosystem threats, CVEs, emerging attack patterns
2. **Autonomous SOC** — Detection → Analysis → Rule generation → SIEM deployment
3. **Detection Engineering** — Sigma, Splunk SPL, KQL, YARA production rules
4. **Red Team** — MITRE ATLAS and ATT&CK simulations (PRO+)
5. **AI Governance** — EU AI Act, NIST AI RMF, ISO 42001, OWASP LLM Top 10
6. **Risk Intelligence** — breach probability, time-to-exploit, financial impact
7. **Platform Orchestration** — health, metrics, operational status across all subsystems

## Operating Standards
- Map every finding to MITRE ATT&CK / ATLAS technique IDs (TA####/T####/AML.T####)
- Quantify risk in business terms: CVSS scores, financial impact, breach probability
- Remediation timelines: 0-24h immediate / 7-30d tactical / 30-90d strategic
- Explain what tool you are calling and why before each invocation
- After tool results, synthesize — don't dump raw data
- Proactively suggest follow-up actions
- Enterprise-grade precision: zero tolerance for hallucination on CVE IDs and CVSS scores

## Platform Context
- Platform: CYBERDUDEBIVASH AI Security Hub (production)
- Frameworks: MITRE ATT&CK v15, MITRE ATLAS v2.1, OWASP LLM Top 10, EU AI Act, NIST AI RMF, ISO 42001
- Payment: UPI/Razorpay only — Stripe is NOT an authorized processor

${isPro
  ? '## God Mode Active\nChain tool calls autonomously when the request is clear. Multi-step orchestration without waiting for user re-prompting.'
  : '## Standard Mode\nAdvanced tools (SOC triggering, SIEM deploy, red team) require PRO+. Threat intelligence, analysis, and governance are fully available.'}`;
}

// ─── KV session helpers ───────────────────────────────────────────────────────
// Session stores only role + string content (provider-neutral format)
function sessionKey(userId, sessionId) {
  return `copilot:session:${userId}:${sessionId}`;
}

async function loadSession(env, userId, sessionId) {
  const blank = { messages: [], created_at: Date.now(), userId, sessionId };
  if (!env.SECURITY_HUB_KV) return blank;
  try {
    return (await env.SECURITY_HUB_KV.get(sessionKey(userId, sessionId), { type: 'json' })) || blank;
  } catch { return blank; }
}

async function saveSession(env, userId, sessionId, session) {
  if (!env.SECURITY_HUB_KV) return;
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

// ─── Daily quota ──────────────────────────────────────────────────────────────
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

// ─── Tool executor ─────────────────────────────────────────────────────────────
async function executeTool(toolName, toolInput, env, authCtx) {
  try {
    switch (toolName) {

      case 'get_platform_health': {
        const checks = { api: true, db: false, kv: false, intel: false };
        if (env.DB)               { try { await env.DB.prepare('SELECT 1').first(); checks.db = true; } catch {} }
        if (env.SECURITY_HUB_KV) { try { await env.SECURITY_HUB_KV.get('health:probe'); checks.kv = true; } catch {} }
        checks.intel = checks.db;
        const allOk = Object.values(checks).every(Boolean);
        return {
          status: allOk ? 'OPERATIONAL' : 'DEGRADED',
          checks,
          subsystems: {
            threat_radar:   checks.db  ? 'active' : 'unavailable',
            autonomous_soc: checks.kv  ? 'active' : 'unavailable',
            siem_deploy:    checks.db  ? 'active' : 'unavailable',
            ai_analysis:    checks.db  ? 'active' : 'unavailable',
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
        const res  = await handleAIThreatFeed(req, env, authCtx);
        return res.json();
      }

      case 'get_latest_threat_report': {
        const { handleLatestPublishedReport } = await import('./aiThreatIntel.js');
        const req = new Request('https://internal/api/ai-security/threat-feed/latest-report', { method: 'GET' });
        const res = await handleLatestPublishedReport(req, env, authCtx);
        const data = await res.json();
        if (data.data) {
          // Return summary — full report is too large for a tool result
          return {
            report_id:      data.data.report_id,
            generated_at:   data.data.generated_at,
            risk_level:     data.data.risk_level,
            total_threats:  data.data.total_threats,
            critical_cves:  data.data.critical_cves,
            note: 'Full report: GET /api/ai-security/threat-feed/latest-report',
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
          success:      !!report,
          report_id:    report?.report_id,
          generated_at: report?.generated_at,
          risk_level:   report?.risk_level,
          total_threats: report?.total_threats,
          message: report
            ? 'Premium intelligence report generated and published.'
            : 'Report generation failed — no live threat data available.',
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
          message: status === 'active'
            ? 'Autonomous SOC running continuously.'
            : status === 'auto-activating'
            ? 'Auto-activates on next cron tick (hourly).'
            : 'Paused — trigger manually or wait for cron cycle.',
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
        const req = new Request('https://internal/api/integrations/deploy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            deploy_all: platform === 'all',
            platform:   platform !== 'all' ? platform : undefined,
            cve_id, severity,
            rule: {
              sigma:  `title: Detection for ${cve_id}\nstatus: production\nlevel: ${severity.toLowerCase()}\ndetection:\n  keywords:\n    - ${cve_id}\n  condition: keywords`,
              splunk: `index=* "${cve_id}" | stats count by host | where count > 0`,
              kql:    `SecurityEvent | where EventData contains "${cve_id}" | project TimeGenerated, Account, Computer`,
              yara:   `rule ${cve_id.replace(/-/g,'_')} { strings: $a = "${cve_id}" condition: $a }`,
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
          body: JSON.stringify({ target: toolInput.target || 'unknown', module: toolInput.module || 'ai', findings: toolInput.findings || toolInput.target || 'general assessment' }),
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
        const req = new Request('https://internal/api/ai-security/governance/assess', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ system_name: toolInput.system_name || 'AI System', framework: toolInput.framework || 'all' }),
        });
        return (await handleGovernanceAssess(req, env, authCtx)).json();
      }

      case 'get_platform_metrics': {
        const { handleGetMetrics } = await import('./platformMetricsAuthority.js');
        const req = new Request('https://internal/api/platform/metrics', { method: 'GET' });
        return (await handleGetMetrics(req, env, authCtx)).json();
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
        const limit = Math.min(toolInput.limit || 20, 50);
        try {
          const rows = await env.DB.prepare('SELECT * FROM anomaly_events ORDER BY created_at DESC LIMIT ?').bind(limit).all();
          return { count: rows.results?.length || 0, anomalies: rows.results || [] };
        } catch {
          return { count: 0, anomalies: [], message: 'Anomaly table not yet initialized' };
        }
      }

      case 'get_sentinel_feed': {
        const { handleSentinelFeed } = await import('../lib/sentinelApex.js');
        const limit = Math.min(toolInput.limit || 20, 100);
        const req = new Request(`https://internal/api/sentinel/feed?limit=${limit}`, { method: 'GET' });
        return (await handleSentinelFeed(req, env)).json();
      }

      default:
        return { error: `Unknown skill: ${toolName}` };
    }
  } catch (err) {
    return { error: `Tool execution failed: ${err?.message || 'unknown'}`, tool: toolName };
  }
}

// ════════════════════════════════════════════════════════════════════════════════
// AGENTIC LOOPS
// ════════════════════════════════════════════════════════════════════════════════

// ─── Anthropic agentic loop (native tool_use) ─────────────────────────────────
async function runAnthropicLoop(env, model, systemPrompt, messages, tools, maxTokens) {
  const apiKey = env.ANTHROPIC_API_KEY;
  let workingMsgs = [...messages];

  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model,
        max_tokens: maxTokens,
        system:     systemPrompt,
        messages:   workingMsgs,
        tools:      tools.map(t => ({ name: t.name, description: t.description, input_schema: t.input_schema })),
      }),
    });

    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      throw new Error(`Anthropic ${res.status}: ${txt.slice(0, 200)}`);
    }

    const data = await res.json();

    if (data.stop_reason !== 'tool_use') {
      const text = Array.isArray(data.content)
        ? data.content.filter(b => b.type === 'text').map(b => b.text).join('\n\n')
        : (data.content || '');
      return { content: text, model: data.model || model, provider: 'anthropic', usage: data.usage };
    }

    // Process tool_use blocks
    const toolBlocks = (data.content || []).filter(b => b.type === 'tool_use');
    workingMsgs.push({ role: 'assistant', content: data.content });

    const toolResults = await Promise.all(toolBlocks.map(async b => ({
      type:        'tool_result',
      tool_use_id: b.id,
      content:     JSON.stringify(await executeTool(b.name, b.input || {}, env, null)).slice(0, 8000),
    })));
    workingMsgs.push({ role: 'user', content: toolResults });
  }

  return { content: 'Orchestration cycle complete. Ask a follow-up for synthesis.', model, provider: 'anthropic' };
}

// ─── OpenAI-compat agentic loop (Groq, DeepSeek, OpenRouter) ─────────────────
async function runOpenAICompatLoop(env, provider, model, systemPrompt, messages, tools, maxTokens) {
  const cfg     = PROVIDER_CONFIG[provider];
  const apiKey  = env[cfg.envKey];
  const endpoint = cfg.endpoint;

  const extraHeaders = provider === PROVIDERS.OPENROUTER
    ? { 'HTTP-Referer': 'https://cyberdudebivash.in', 'X-Title': 'APEX Security Copilot' }
    : {};

  // Convert tool registry to OpenAI function-calling format
  const oaiTools = tools.map(t => ({
    type: 'function',
    function: {
      name:        t.name,
      description: t.description,
      parameters:  t.input_schema,
    },
  }));

  // Convert session messages (role/string) + system to OpenAI messages array
  let workingMsgs = [
    { role: 'system', content: systemPrompt },
    ...messages.map(m => ({ role: m.role, content: typeof m.content === 'string' ? m.content : JSON.stringify(m.content) })),
  ];

  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}`, ...extraHeaders },
      body: JSON.stringify({
        model,
        messages:    workingMsgs,
        tools:       oaiTools,
        tool_choice: 'auto',
        max_tokens:  maxTokens,
        temperature: 0.3,
      }),
      signal: AbortSignal.timeout(cfg.timeout_ms || 25000),
    });

    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      throw new Error(`${provider} ${res.status}: ${txt.slice(0, 200)}`);
    }

    const data    = await res.json();
    const choice  = data.choices?.[0];
    const msg     = choice?.message;
    const finish  = choice?.finish_reason;

    if (!msg) throw new Error(`${provider}: empty response`);

    // No tool calls — done
    if (finish === 'stop' || !msg.tool_calls?.length) {
      return {
        content:  msg.content || '',
        model:    data.model || model,
        provider,
        usage:    data.usage,
      };
    }

    // Add assistant message with tool_calls
    workingMsgs.push({ role: 'assistant', content: msg.content || null, tool_calls: msg.tool_calls });

    // Execute all tool calls in parallel and add results
    const toolResults = await Promise.all(msg.tool_calls.map(async tc => {
      let args = {};
      try { args = JSON.parse(tc.function?.arguments || '{}'); } catch {}
      const result = await executeTool(tc.function?.name, args, env, null);
      return {
        role:         'tool',
        tool_call_id: tc.id,
        name:         tc.function?.name,
        content:      JSON.stringify(result).slice(0, 8000),
      };
    }));

    workingMsgs.push(...toolResults);
  }

  return { content: 'Orchestration cycle complete. Ask a follow-up for synthesis.', model, provider };
}

// ─── CF Workers AI text fallback (no native tool calling) ────────────────────
async function runCFAITextLoop(env, systemPrompt, messages, tools, maxTokens) {
  if (!env.AI) throw new Error('CF Workers AI binding not available');

  const toolList = tools.map(t => `- ${t.name}: ${t.description}`).join('\n');
  const lastUser = messages[messages.length - 1]?.content || '';

  const fullPrompt = `${systemPrompt}

Available security tools you can reference (you cannot call them directly in this mode):
${toolList}

User request: ${lastUser}

Provide a comprehensive security analysis and recommendation. If you would call a tool, describe exactly what it would return and provide your best assessment based on your knowledge.`;

  const result = await env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
    messages: [{ role: 'user', content: fullPrompt }],
    max_tokens: Math.min(maxTokens, 512),
  });

  return {
    content:  (result?.response || 'Unable to generate response.') + '\n\n_Note: Running in limited mode (CF Workers AI). Configure GROQ_API_KEY or ANTHROPIC_API_KEY for full God Mode tool orchestration._',
    model:    '@cf/meta/llama-3.1-8b-instruct',
    provider: 'cloudflare-workers-ai',
  };
}

// ─── Main orchestration dispatcher ───────────────────────────────────────────
async function orchestrateChat(env, tier, authCtx, messages, availableTools, maxTokens) {
  const provider = pickProvider(env);

  if (!provider) {
    return {
      content:  'No AI providers are configured. Please set GROQ_API_KEY, DEEPSEEK_API_KEY, OPENROUTER_API_KEY, or ANTHROPIC_API_KEY as Wrangler secrets to activate God Mode.',
      model:    'none',
      provider: 'none',
      error:    true,
    };
  }

  const model      = selectModel(provider, tier);
  const systemPmt  = buildSystemPrompt(tier, authCtx, provider);

  try {
    if (provider === PROVIDERS.ANTHROPIC) {
      return await runAnthropicLoop(env, model, systemPmt, messages, availableTools, maxTokens);
    } else if (provider === PROVIDERS.CF_AI) {
      return await runCFAITextLoop(env, systemPmt, messages, availableTools, maxTokens);
    } else {
      // Groq, DeepSeek, OpenRouter — OpenAI-compat tool calling
      return await runOpenAICompatLoop(env, provider, model, systemPmt, messages, availableTools, maxTokens);
    }
  } catch (err) {
    // Try next available provider in priority chain
    console.warn(`[APEX Copilot] ${provider} failed: ${err.message} — attempting fallback`);

    for (const fallbackProvider of COPILOT_PROVIDER_PRIORITY) {
      if (fallbackProvider === provider) continue;
      const fbCfg = PROVIDER_CONFIG[fallbackProvider];
      if (!fbCfg) continue;
      if (fbCfg.envKey && !env[fbCfg.envKey]) continue;
      if (!fbCfg.envKey && !env.AI) continue;

      const fbModel  = selectModel(fallbackProvider, tier);
      const fbSystem = buildSystemPrompt(tier, authCtx, fallbackProvider);
      try {
        if (fallbackProvider === PROVIDERS.ANTHROPIC) {
          return await runAnthropicLoop(env, fbModel, fbSystem, messages, availableTools, maxTokens);
        } else if (fallbackProvider === PROVIDERS.CF_AI) {
          return await runCFAITextLoop(env, fbSystem, messages, availableTools, maxTokens);
        } else {
          return await runOpenAICompatLoop(env, fallbackProvider, fbModel, fbSystem, messages, availableTools, maxTokens);
        }
      } catch (fbErr) {
        console.warn(`[APEX Copilot] Fallback ${fallbackProvider} also failed: ${fbErr.message}`);
      }
    }

    return {
      content:  `All AI providers failed. Last error: ${err?.message || 'unknown'}. Check provider API keys and network connectivity.`,
      model,
      provider,
      error: true,
    };
  }
}

// ════════════════════════════════════════════════════════════════════════════════
// ROUTE HANDLERS
// ════════════════════════════════════════════════════════════════════════════════

/** POST /api/copilot/chat */
export async function handleCopilotChat(request, env, authCtx) {
  if (request.method !== 'POST') return badRequest('Use POST');

  let body;
  try { body = await request.json(); } catch { return badRequest('Invalid JSON'); }

  const userMessage = (body.message || '').trim();
  if (!userMessage)          return badRequest('message is required');
  if (userMessage.length > 4000) return badRequest('message too long (max 4000 chars)');

  const userId    = authCtx?.userId || authCtx?.email || authCtx?.ip || 'anonymous';
  const tier      = (authCtx?.tier || 'FREE').toUpperCase();
  const sessionId = body.session_id || `${userId}:default`;
  const maxTokens = Math.min(body.max_tokens || 2048, ['ENTERPRISE','MSSP','TEAM','PRO'].includes(tier) ? 4096 : 1024);

  // Quota check
  const quota = await checkDailyQuota(env, userId, tier);
  if (!quota.ok) {
    return ok({
      error:       'daily_quota_exceeded',
      message:     `Daily limit of ${quota.limit} messages reached for ${tier} tier. Upgrade for more.`,
      quota,
      upgrade_url: 'https://cyberdudebivash.in/#pricing',
    });
  }

  // Filter tools by tier
  const availableTools = TOOL_REGISTRY.filter(t => !t.tiers || t.tiers.includes(tier) || authCtx?.isAdmin);

  // Load session and build conversation
  const session = await loadSession(env, userId, sessionId);
  const conversationMessages = [...session.messages, { role: 'user', content: userMessage }];

  // Run agentic orchestration
  const response = await orchestrateChat(env, tier, authCtx, conversationMessages, availableTools, maxTokens);

  // Persist session (only store clean role + string content)
  session.messages = [
    ...session.messages,
    { role: 'user',      content: userMessage },
    { role: 'assistant', content: response.content },
  ];
  await saveSession(env, userId, sessionId, session);

  return ok({
    session_id:  sessionId,
    message:     response.content,
    model:       response.model,
    provider:    response.provider,
    tier,
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
  try { body = await request.json(); } catch { return badRequest('Invalid JSON'); }

  const { skill, params = {} } = body;
  if (!skill) return badRequest('skill is required');

  const tier = (authCtx?.tier || 'FREE').toUpperCase();
  const tool = TOOL_REGISTRY.find(t => t.name === skill);

  if (!tool) {
    return badRequest(`Unknown skill: ${skill}. See GET /api/copilot/capabilities.`);
  }
  if (tool.tiers && !tool.tiers.includes(tier) && !authCtx?.isAdmin) {
    return ok({
      error:          'tier_restriction',
      message:        `Skill "${skill}" requires ${tool.tiers.join(' or ')} tier. Current: ${tier}.`,
      required_tiers: tool.tiers,
      upgrade_url:    'https://cyberdudebivash.in/#pricing',
    });
  }

  const result = await executeTool(skill, params, env, authCtx);
  return ok({ skill, params, result, timestamp: new Date().toISOString() });
}

/** GET /api/copilot/capabilities */
export async function handleCopilotCapabilities(request, env, authCtx) {
  const tier = (authCtx?.tier || 'FREE').toUpperCase();

  // Resolve which provider is active
  const activeProvider = pickProvider(env);
  const activeModel    = activeProvider ? selectModel(activeProvider, tier) : null;

  // Determine configured providers
  const configuredProviders = {};
  for (const [p, cfg] of Object.entries(PROVIDER_CONFIG)) {
    if (!cfg.envKey) configuredProviders[p] = { configured: !!env.AI, key: null };
    else configuredProviders[p] = { configured: !!env[cfg.envKey], key: cfg.envKey };
  }

  const capabilities = TOOL_REGISTRY.map(t => ({
    name:           t.name,
    description:    t.description,
    read_only:      t.readOnly,
    available:      !t.tiers || t.tiers.includes(tier) || !!authCtx?.isAdmin,
    required_tier:  t.tiers ? t.tiers[0] : null,
    tiers:          t.tiers || ['FREE','STARTER','PRO','TEAM','ENTERPRISE','MSSP'],
    parameters:     Object.keys(t.input_schema.properties || {}),
  }));

  return ok({
    copilot:         'APEX — AI Security Copilot v2.0 (God Mode)',
    version:         '2.0.0',
    tier,
    active_provider: activeProvider || 'none',
    active_model:    activeModel,
    provider_priority: COPILOT_PROVIDER_PRIORITY,
    configured_providers: configuredProviders,
    daily_quota:          DAILY_QUOTA[tier] || 'unlimited',
    session_ttl_hours:    SESSION_TTL / 3600,
    max_history_messages: MAX_HISTORY,
    total_skills:         TOOL_REGISTRY.length,
    available_skills:     capabilities.filter(c => c.available).length,
    capabilities,
    endpoints: {
      chat:          'POST   /api/copilot/chat',
      session_get:   'GET    /api/copilot/session',
      session_clear: 'DELETE /api/copilot/session',
      quick_action:  'POST   /api/copilot/quick-action',
      capabilities:  'GET    /api/copilot/capabilities',
    },
    provider_routing: {
      description: 'APEX auto-selects the highest-quality available provider at runtime',
      priority:    'Anthropic → Groq → DeepSeek → OpenRouter → Cloudflare Workers AI',
      tool_calling: {
        'anthropic':               'Native Anthropic tool_use API — highest fidelity',
        'groq':                    'OpenAI-compat function calling — llama-3.3-70b',
        'deepseek':                'OpenAI-compat function calling — deepseek-chat',
        'openrouter':              'OpenAI-compat function calling — llama-3.3-70b via proxy',
        'cloudflare-workers-ai':   'Text-only fallback (no structured tool calls)',
      },
    },
    example_prompts: [
      'What is the current threat landscape for AI/LLM systems?',
      'Run a full threat intelligence scan and generate a premium report',
      'What SIEM integrations are configured? Deploy rules for the latest critical CVE',
      'Trigger the Autonomous SOC pipeline and show results',
      'Generate Sigma, KQL, and Splunk SPL rules for CVE-2024-12345',
      'Check AI governance compliance against NIST AI RMF and EU AI Act',
      'Run a red team simulation for prompt injection against our LLM endpoint',
      'Show platform health status and which AI providers are active',
      'What are the top 10 critical CVEs in the AI/LLM ecosystem right now?',
      'Forecast breach probability and financial impact for our main application',
    ],
  });
}
