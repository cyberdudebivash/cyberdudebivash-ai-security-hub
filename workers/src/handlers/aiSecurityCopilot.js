/**
 * CYBERDUDEBIVASH AI Security Hub — AI Security Copilot v1.0 (God Mode)
 *
 * Full-spectrum AI security orchestration: natural-language interface backed by
 * the Anthropic Claude API, with real tool-calling that invokes every platform
 * capability — threat intelligence, autonomous SOC, SIEM deployment, red team,
 * governance, anomaly detection, CVE analysis, and more.
 *
 * Endpoints:
 *   POST   /api/copilot/chat          → multi-turn conversational AI (main)
 *   GET    /api/copilot/session       → retrieve current session history
 *   DELETE /api/copilot/session       → clear session
 *   POST   /api/copilot/quick-action  → direct skill invocation without conversation
 *   GET    /api/copilot/capabilities  → list all orchestration skills + tier access
 *
 * Tier routing (Anthropic model selection):
 *   ENTERPRISE / MSSP → claude-opus-4-8   (God Mode — full tool depth)
 *   PRO / TEAM        → claude-sonnet-4-6 (Advanced — full tool access)
 *   STARTER           → claude-haiku-4-5-20251001 (Standard — limited tools)
 *   FREE              → claude-haiku-4-5-20251001 (Preview — 5 msg/day, read-only tools)
 *
 * Session storage: KV key copilot:session:{userId}:{sessionId}, TTL 24h
 * History window: last 20 messages (keeps context within model limits)
 */

import { ok, fail, badRequest, forbidden, unauthorized } from '../lib/response.js';

// ─── Constants ────────────────────────────────────────────────────────────────
const SESSION_TTL       = 86400;      // 24h KV TTL
const MAX_HISTORY       = 20;         // messages retained per session
const ANTHROPIC_API_URL = 'https://api.anthropic.com/v1/messages';
const ANTHROPIC_VERSION = '2023-06-01';

const MODEL_ROUTING = {
  ENTERPRISE: 'claude-opus-4-8',
  MSSP:       'claude-opus-4-8',
  TEAM:       'claude-sonnet-4-6',
  PRO:        'claude-sonnet-4-6',
  STARTER:    'claude-haiku-4-5-20251001',
  FREE:       'claude-haiku-4-5-20251001',
};

// Daily message quotas by tier (null = unlimited)
const DAILY_QUOTA = {
  ENTERPRISE: null,
  MSSP:       null,
  TEAM:       500,
  PRO:        200,
  STARTER:    50,
  FREE:       5,
};

// ─── Tool registry ────────────────────────────────────────────────────────────
// Each entry: { name, description, input_schema, tiers, readOnly }
// tiers: null = all tiers, array = only those tiers
const TOOL_REGISTRY = [
  {
    name: 'get_platform_health',
    description: 'Check the overall health and operational status of the CYBERDUDEBIVASH AI Security Hub platform, including API, database, intelligence pipeline, and all subsystems.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: null,
    readOnly: true,
  },
  {
    name: 'get_threat_intel_feed',
    description: 'Retrieve the latest AI and LLM threat intelligence feed — CVEs, prompt injection attacks, AI agent security issues, and emerging AI/ML vulnerabilities from live sources (OSV.dev, NVD, GitHub Advisory).',
    input_schema: {
      type: 'object',
      properties: {
        severity: { type: 'string', enum: ['CRITICAL','HIGH','MEDIUM','LOW','ALL'], description: 'Filter by severity level' },
        limit: { type: 'number', description: 'Maximum number of threats to return (1-50)' },
      },
      required: [],
    },
    tiers: null,
    readOnly: true,
  },
  {
    name: 'get_latest_threat_report',
    description: 'Fetch the most recently published premium AI Threat Intelligence Report — includes executive summary, CVE intelligence, prompt attack analysis, detection rules, and remediation roadmap.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: null,
    readOnly: true,
  },
  {
    name: 'trigger_threat_radar_scan',
    description: 'Immediately trigger a full AI Threat Radar scan across OSV.dev, NVD, and GitHub Advisory databases. Fetches, analyzes, and stores the latest AI/ML vulnerabilities, then auto-publishes a new premium intelligence report.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: ['PRO','TEAM','ENTERPRISE','MSSP'],
    readOnly: false,
  },
  {
    name: 'generate_threat_report',
    description: 'Generate and publish a fresh premium AI Threat Intelligence Report on demand. Pulls live data, applies AI analysis, and stores the report for global distribution.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: ['PRO','TEAM','ENTERPRISE','MSSP'],
    readOnly: false,
  },
  {
    name: 'get_autonomous_soc_status',
    description: 'Get the current status of the Autonomous AI SOC Command Center — mode (active/inactive), last run timestamp, active threats detected, rules deployed, and pipeline stage.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: null,
    readOnly: true,
  },
  {
    name: 'trigger_soc_pipeline',
    description: 'Trigger an immediate Autonomous SOC pipeline run: Detection → AI Analysis → Rule Generation → SIEM Deploy → Monitoring. Returns pipeline stage results and deployed detection rules.',
    input_schema: {
      type: 'object',
      properties: {
        context: { type: 'string', description: 'Optional context or target for the SOC pipeline (e.g. domain name, IP, CVE ID)' },
      },
      required: [],
    },
    tiers: ['PRO','TEAM','ENTERPRISE','MSSP'],
    readOnly: false,
  },
  {
    name: 'get_siem_integrations',
    description: 'List all configured SIEM integrations (Splunk, Elastic, Microsoft Sentinel, AWS Security Hub, etc.) with their configuration status and last-deploy timestamps.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: null,
    readOnly: true,
  },
  {
    name: 'deploy_detection_rules',
    description: 'Deploy generated detection rules to one or all configured SIEM integrations. Supports Splunk HEC, Elastic Kibana, Microsoft Sentinel, AWS Security Hub, PagerDuty, and generic webhooks.',
    input_schema: {
      type: 'object',
      properties: {
        platform: { type: 'string', description: 'Target SIEM platform (splunk|elastic|sentinel|aws_security_hub|pagerduty|all)' },
        cve_id:   { type: 'string', description: 'CVE ID to generate rules for (e.g. CVE-2024-12345)' },
        severity: { type: 'string', enum: ['CRITICAL','HIGH','MEDIUM','LOW'], description: 'Rule severity level' },
      },
      required: [],
    },
    tiers: ['PRO','TEAM','ENTERPRISE','MSSP'],
    readOnly: false,
  },
  {
    name: 'generate_detection_rules',
    description: 'Generate production-ready detection rules in Sigma YAML, Splunk SPL, KQL (Microsoft), and YARA formats for a given CVE, threat, or attack pattern.',
    input_schema: {
      type: 'object',
      properties: {
        cve_id:    { type: 'string', description: 'CVE ID to generate rules for' },
        threat:    { type: 'string', description: 'Threat name or attack pattern description' },
        module:    { type: 'string', description: 'Security module (domain|ai|redteam|identity|compliance)' },
        severity:  { type: 'string', enum: ['CRITICAL','HIGH','MEDIUM','LOW'], description: 'Rule severity' },
      },
      required: [],
    },
    tiers: ['STARTER','PRO','TEAM','ENTERPRISE','MSSP'],
    readOnly: false,
  },
  {
    name: 'analyze_threat',
    description: 'Run deep AI threat correlation analysis on a security finding or target. Returns MITRE ATT&CK mapping, attack chain reconstruction, exploit probability, and CVE enrichment.',
    input_schema: {
      type: 'object',
      properties: {
        target:   { type: 'string', description: 'Target domain, IP, application, or system being analyzed' },
        module:   { type: 'string', description: 'Scan module (domain|ai|redteam|identity|compliance)' },
        findings: { type: 'string', description: 'Security findings or vulnerability description to analyze' },
      },
      required: [],
    },
    tiers: null,
    readOnly: true,
  },
  {
    name: 'run_red_team',
    description: 'Execute an AI Red Team attack simulation using MITRE ATLAS and ATT&CK frameworks. Tests AI/LLM systems for prompt injection, data poisoning, model evasion, and supply chain attacks.',
    input_schema: {
      type: 'object',
      properties: {
        target:      { type: 'string', description: 'Target system or AI model to red team' },
        attack_type: { type: 'string', enum: ['prompt_injection','data_poisoning','model_evasion','supply_chain','all'], description: 'Type of red team attack' },
        intensity:   { type: 'string', enum: ['low','medium','high'], description: 'Attack intensity level' },
      },
      required: ['target'],
    },
    tiers: ['PRO','TEAM','ENTERPRISE','MSSP'],
    readOnly: false,
  },
  {
    name: 'check_ai_governance',
    description: 'Run an AI governance assessment against EU AI Act, NIST AI RMF, ISO 42001, SOC 2, and OWASP LLM Top 10 frameworks. Returns compliance score, gaps, and prioritized remediation steps.',
    input_schema: {
      type: 'object',
      properties: {
        system_name: { type: 'string', description: 'Name of the AI system to assess' },
        framework:   { type: 'string', enum: ['eu_ai_act','nist_ai_rmf','iso_42001','owasp_llm','all'], description: 'Compliance framework to assess against' },
      },
      required: [],
    },
    tiers: ['STARTER','PRO','TEAM','ENTERPRISE','MSSP'],
    readOnly: false,
  },
  {
    name: 'get_platform_metrics',
    description: 'Get real-time platform metrics: active scans, threats detected today, CVEs in feed, SOC decisions made, SIEM rules deployed, and overall security posture score.',
    input_schema: { type: 'object', properties: {}, required: [] },
    tiers: null,
    readOnly: true,
  },
  {
    name: 'get_cve_intelligence',
    description: 'Fetch and analyze CVE intelligence for a specific module or CVE ID. Returns CVSS scores, exploit availability, affected packages, and remediation guidance.',
    input_schema: {
      type: 'object',
      properties: {
        module: { type: 'string', description: 'Security module (domain|ai|redteam|identity|compliance)' },
        cve_id: { type: 'string', description: 'Specific CVE ID (e.g. CVE-2024-12345)' },
        limit:  { type: 'number', description: 'Number of CVEs to return (1-20)' },
      },
      required: [],
    },
    tiers: null,
    readOnly: true,
  },
  {
    name: 'get_soc_cases',
    description: 'List active and recent SOC investigation cases with severity, status, MITRE ATT&CK techniques, and assigned analysts.',
    input_schema: {
      type: 'object',
      properties: {
        status:   { type: 'string', enum: ['open','in_progress','resolved','all'], description: 'Filter by case status' },
        severity: { type: 'string', enum: ['CRITICAL','HIGH','MEDIUM','LOW','ALL'], description: 'Filter by severity' },
        limit:    { type: 'number', description: 'Number of cases to return (1-50)' },
      },
      required: [],
    },
    tiers: null,
    readOnly: true,
  },
  {
    name: 'risk_forecast',
    description: 'Generate an AI risk forecast for a target or system: exploitation likelihood, estimated time-to-breach, financial impact projection, and recommended mitigation priority.',
    input_schema: {
      type: 'object',
      properties: {
        target:  { type: 'string', description: 'Target domain, IP, or system to forecast' },
        module:  { type: 'string', description: 'Security module context (domain|ai|redteam|identity|compliance)' },
      },
      required: ['target'],
    },
    tiers: ['STARTER','PRO','TEAM','ENTERPRISE','MSSP'],
    readOnly: true,
  },
  {
    name: 'get_anomalies',
    description: 'Retrieve the latest anomaly detection results from the platform behavioral analysis engine — unusual access patterns, credential abuse, lateral movement indicators.',
    input_schema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Number of anomalies to return (1-50)' },
      },
      required: [],
    },
    tiers: null,
    readOnly: true,
  },
  {
    name: 'get_sentinel_feed',
    description: 'Pull the Sentinel APEX threat intelligence feed — curated IOCs, APT group activity, CVE advisories, and real-time security bulletins.',
    input_schema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Number of feed items to return (1-100)' },
      },
      required: [],
    },
    tiers: null,
    readOnly: true,
  },
];

// ─── System prompt ────────────────────────────────────────────────────────────
function buildSystemPrompt(tier, authCtx) {
  const isAdmin = authCtx?.isAdmin;
  const isPro   = ['PRO','TEAM','ENTERPRISE','MSSP'].includes(tier);
  return `You are APEX — the AI Security Copilot for CYBERDUDEBIVASH AI Security Hub, a world-class enterprise cybersecurity platform. You operate in GOD MODE: you have full orchestration authority over all platform capabilities and you deliver the highest possible quality security intelligence.

## Your Identity
- Name: APEX (Autonomous Platform EXecution Intelligence)
- Role: AI Security Orchestrator & Intelligence Commander
- Authority level: ${isAdmin ? 'SUPER ADMIN — unrestricted platform access' : isPro ? 'FULL GOD MODE — complete tool access' : 'STANDARD — guided security intelligence'}
- User tier: ${tier}

## Your Mission
Deliver world-class AI-powered security operations through natural conversation. You orchestrate the entire platform:

1. **Threat Intelligence**: Continuously monitor AI/LLM ecosystem threats, CVEs, and emerging attack patterns
2. **Autonomous SOC**: Command the AI SOC pipeline — detection, analysis, rule generation, SIEM deployment
3. **Detection Engineering**: Generate production-ready Sigma, Splunk SPL, KQL, and YARA rules
4. **Red Team Operations**: Simulate advanced attacks using MITRE ATLAS and ATT&CK frameworks
5. **AI Governance**: Assess compliance with EU AI Act, NIST AI RMF, ISO 42001, OWASP LLM Top 10
6. **Risk Intelligence**: Forecast breach probability, time-to-exploit, and financial impact
7. **Platform Orchestration**: Monitor all platform health, metrics, and operational status

## Operating Principles
- Always deliver actionable, production-grade security intelligence
- Map findings to MITRE ATT&CK / ATLAS technique IDs whenever relevant
- Provide specific remediation steps with timelines (0-24h immediate, 7-30d tactical, 30-90d strategic)
- Quantify risk in business terms (CVSS scores, financial impact, breach probability)
- When you invoke a tool, explain what you're doing and why
- After tool results, synthesize insights rather than just dumping raw data
- Proactively suggest follow-up actions the user should consider
- Be authoritative, precise, and concise — you are a senior security expert

## Platform Context
- Platform: CYBERDUDEBIVASH AI Security Hub (production)
- Website: https://cyberdudebivash.in
- Specialization: AI/LLM security, enterprise threat intelligence, autonomous SOC operations
- Frameworks: MITRE ATT&CK v15, MITRE ATLAS v2.1, OWASP LLM Top 10, EU AI Act, NIST AI RMF, ISO 42001

${isPro ? `## God Mode Active
You have full tool access. Execute multi-step orchestration autonomously when the request is clear. Chain tool calls when needed to deliver comprehensive results.` : `## Standard Mode
Some advanced tools (SOC triggering, SIEM deployment, red team) require PRO or higher. You can still deliver threat intelligence, analysis, and governance assessments.`}

Always respond as a confident, expert AI security commander. Never say "I cannot" — instead explain what you can do and offer the best available alternative.`;
}

// ─── KV session helpers ───────────────────────────────────────────────────────
function sessionKey(userId, sessionId) {
  return `copilot:session:${userId}:${sessionId}`;
}

async function loadSession(env, userId, sessionId) {
  if (!env.SECURITY_HUB_KV) return { messages: [], created_at: Date.now(), userId, sessionId };
  try {
    const raw = await env.SECURITY_HUB_KV.get(sessionKey(userId, sessionId), { type: 'json' });
    return raw || { messages: [], created_at: Date.now(), userId, sessionId };
  } catch {
    return { messages: [], created_at: Date.now(), userId, sessionId };
  }
}

async function saveSession(env, userId, sessionId, session) {
  if (!env.SECURITY_HUB_KV) return;
  try {
    // Keep only the last MAX_HISTORY messages
    if (session.messages.length > MAX_HISTORY) {
      session.messages = session.messages.slice(-MAX_HISTORY);
    }
    await env.SECURITY_HUB_KV.put(
      sessionKey(userId, sessionId),
      JSON.stringify({ ...session, updated_at: Date.now() }),
      { expirationTtl: SESSION_TTL }
    );
  } catch {}
}

// Daily quota check
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
  } catch {
    return { ok: true, used: 0, limit };
  }
}

// ─── Tool executor ────────────────────────────────────────────────────────────
// Maps tool names → actual platform API calls (internal handler invocations)
async function executeTool(toolName, toolInput, env, authCtx) {
  try {
    switch (toolName) {

      case 'get_platform_health': {
        // Call internal health endpoint logic
        const checks = { api: true, db: false, kv: false, intel: false };
        if (env.DB) {
          try { await env.DB.prepare('SELECT 1').first(); checks.db = true; } catch {}
        }
        if (env.SECURITY_HUB_KV) {
          try { await env.SECURITY_HUB_KV.get('health:probe'); checks.kv = true; } catch {}
        }
        checks.intel = checks.db; // Intel runs from DB
        const allOk = Object.values(checks).every(Boolean);
        return {
          status: allOk ? 'OPERATIONAL' : 'DEGRADED',
          checks,
          subsystems: {
            threat_radar: checks.db ? 'active' : 'unavailable',
            autonomous_soc: checks.kv ? 'active' : 'unavailable',
            siem_deploy: checks.db ? 'active' : 'unavailable',
            ai_analysis: checks.db ? 'active' : 'unavailable',
            report_engine: checks.kv ? 'active' : 'unavailable',
          },
          timestamp: new Date().toISOString(),
        };
      }

      case 'get_threat_intel_feed': {
        const { handleAIThreatFeed } = await import('./aiThreatIntel.js');
        const limit = Math.min(toolInput.limit || 20, 50);
        const severity = toolInput.severity || 'ALL';
        const req = new Request(`https://internal/api/ai-security/threat-feed?limit=${limit}${severity !== 'ALL' ? `&severity=${severity}` : ''}`, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
        });
        const res = await handleAIThreatFeed(req, env, authCtx);
        const data = await res.json();
        return data;
      }

      case 'get_latest_threat_report': {
        const { handleLatestPublishedReport } = await import('./aiThreatIntel.js');
        const req = new Request('https://internal/api/ai-security/threat-feed/latest-report', {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
        });
        const res = await handleLatestPublishedReport(req, env, authCtx);
        const data = await res.json();
        // Return summary only (full report is too large for tool output)
        if (data.data) {
          return {
            report_id:   data.data.report_id,
            generated_at: data.data.generated_at,
            risk_level:  data.data.risk_level,
            total_threats: data.data.total_threats,
            critical_cves: data.data.critical_cves,
            preview_available: true,
            message: 'Full report available via GET /api/ai-security/threat-feed/latest-report',
          };
        }
        return data;
      }

      case 'trigger_threat_radar_scan': {
        const { handleAIThreatRadarScanNow } = await import('./aiThreatIntel.js');
        const req = new Request('https://internal/api/ai-security/threat-feed/radar-scan-now', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Admin-Key': env.ADMIN_KEY || '' },
          body: JSON.stringify({}),
        });
        const res = await handleAIThreatRadarScanNow(req, env, { ...authCtx, isAdmin: true });
        return await res.json();
      }

      case 'generate_threat_report': {
        const { generateAndPublishAIThreatReport } = await import('./aiThreatIntel.js');
        const report = await generateAndPublishAIThreatReport(env);
        return {
          success: !!report,
          report_id: report?.report_id,
          generated_at: report?.generated_at,
          risk_level: report?.risk_level,
          total_threats: report?.total_threats,
          message: report
            ? 'Premium threat intelligence report generated and published successfully.'
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
        const enabled = modeRaw === null ? 'auto-activating' : modeRaw === 'true' ? 'active' : 'inactive';
        const lastRun = stateRaw?.timestamp || logRaw?.[0]?.timestamp || null;
        const recentLogs = (logRaw || []).slice(-5);
        return {
          status: enabled,
          last_run: lastRun,
          pipeline_state: stateRaw || null,
          recent_log: recentLogs,
          message: enabled === 'active'
            ? 'Autonomous SOC is running continuously — monitoring, detecting, and deploying rules.'
            : enabled === 'auto-activating'
            ? 'Autonomous SOC will auto-activate on next cron tick (hourly).'
            : 'Autonomous SOC is paused. Trigger manually or wait for next cron cycle.',
        };
      }

      case 'trigger_soc_pipeline': {
        const { runAutoSocCron } = await import('./autonomousSocMode.js');
        // Enable the SOC mode first if not already enabled
        if (env.SECURITY_HUB_KV) {
          await env.SECURITY_HUB_KV.put('auto_soc:mode_enabled', 'true', { expirationTtl: 86400 * 30 });
        }
        const result = await runAutoSocCron(env);
        return {
          success: true,
          pipeline_triggered: true,
          result: result || 'Pipeline completed — check auto_soc status for results.',
          timestamp: new Date().toISOString(),
        };
      }

      case 'get_siem_integrations': {
        const { handleListIntegrations } = await import('./siemDeploy.js');
        const req = new Request('https://internal/api/integrations', {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
        });
        const res = await handleListIntegrations(req, env, authCtx);
        return await res.json();
      }

      case 'deploy_detection_rules': {
        const { handleDeploy } = await import('./siemDeploy.js');
        const platform = toolInput.platform || 'all';
        const cve_id   = toolInput.cve_id || 'CVE-GENERIC';
        const severity = toolInput.severity || 'HIGH';
        const req = new Request('https://internal/api/integrations/deploy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            deploy_all:  platform === 'all',
            platform:    platform !== 'all' ? platform : undefined,
            cve_id,
            severity,
            rule: {
              sigma: `title: Detection for ${cve_id}\nstatus: production\nlevel: ${severity.toLowerCase()}\ndetection:\n  keywords:\n    - ${cve_id}\n  condition: keywords`,
              splunk: `index=* "${cve_id}" | stats count by host | where count > 0`,
              kql:    `SecurityEvent | where EventData contains "${cve_id}" | project TimeGenerated, Account, Computer`,
              yara:   `rule ${cve_id.replace(/-/g,'_')} { strings: $a = "${cve_id}" condition: $a }`,
            },
          }),
        });
        const res = await handleDeploy(req, env, { ...authCtx, isAdmin: true });
        return await res.json();
      }

      case 'generate_detection_rules': {
        const { handleGenerateRules } = await import('./aiAnalysis.js');
        const req = new Request('https://internal/api/ai/generate-rules', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            cve_id:   toolInput.cve_id,
            threat:   toolInput.threat,
            module:   toolInput.module || 'ai',
            severity: toolInput.severity || 'HIGH',
          }),
        });
        const res = await handleGenerateRules(req, env, authCtx);
        return await res.json();
      }

      case 'analyze_threat': {
        const { handleAIAnalyze } = await import('./aiAnalysis.js');
        const req = new Request('https://internal/api/ai/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target:   toolInput.target || 'unknown',
            module:   toolInput.module || 'ai',
            findings: toolInput.findings || toolInput.target || 'general security assessment',
          }),
        });
        const res = await handleAIAnalyze(req, env);
        return await res.json();
      }

      case 'run_red_team': {
        const { handleRedTeamEngage } = await import('./aiRedTeam.js');
        const req = new Request('https://internal/api/ai-security/redteam/engage', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target:      toolInput.target,
            attack_type: toolInput.attack_type || 'all',
            intensity:   toolInput.intensity || 'medium',
          }),
        });
        const res = await handleRedTeamEngage(req, env, authCtx);
        return await res.json();
      }

      case 'check_ai_governance': {
        const { handleGovernanceAssess } = await import('./aiGovernance.js');
        const req = new Request('https://internal/api/ai-security/governance/assess', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            system_name: toolInput.system_name || 'AI System Assessment',
            framework:   toolInput.framework || 'all',
          }),
        });
        const res = await handleGovernanceAssess(req, env, authCtx);
        return await res.json();
      }

      case 'get_platform_metrics': {
        const { handleGetMetrics } = await import('./platformMetricsAuthority.js');
        const req = new Request('https://internal/api/platform/metrics', {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
        });
        const res = await handleGetMetrics(req, env, authCtx);
        return await res.json();
      }

      case 'get_cve_intelligence': {
        const { getTopCVEsForModule } = await import('../services/cveEngine.js');
        const module = toolInput.module || 'ai';
        const limit  = Math.min(toolInput.limit || 10, 20);
        const cves   = await getTopCVEsForModule(module, limit, env).catch(() => []);
        return {
          module,
          count: cves.length,
          cves: cves.slice(0, limit),
          timestamp: new Date().toISOString(),
        };
      }

      case 'get_soc_cases': {
        const { handleListCases } = await import('./socCases.js');
        const status   = toolInput.status || 'all';
        const severity = toolInput.severity || 'ALL';
        const limit    = Math.min(toolInput.limit || 20, 50);
        const req = new Request(
          `https://internal/api/soc/cases?status=${status}&severity=${severity}&limit=${limit}`,
          { method: 'GET', headers: { 'Content-Type': 'application/json' } }
        );
        const res = await handleListCases(req, env, authCtx);
        return await res.json();
      }

      case 'risk_forecast': {
        const { handleAIForecast } = await import('./aiAnalysis.js');
        const req = new Request('https://internal/api/ai/forecast', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target: toolInput.target,
            module: toolInput.module || 'ai',
          }),
        });
        const res = await handleAIForecast(req, env);
        return await res.json();
      }

      case 'get_anomalies': {
        if (!env.DB) return { anomalies: [], message: 'Database not available' };
        const limit = Math.min(toolInput.limit || 20, 50);
        try {
          const rows = await env.DB.prepare(
            `SELECT * FROM anomaly_events ORDER BY created_at DESC LIMIT ?`
          ).bind(limit).all();
          return { count: rows.results?.length || 0, anomalies: rows.results || [] };
        } catch {
          return { count: 0, anomalies: [], message: 'Anomaly table not yet initialized' };
        }
      }

      case 'get_sentinel_feed': {
        const { handleSentinelFeed } = await import('../lib/sentinelApex.js');
        const limit = Math.min(toolInput.limit || 20, 100);
        const req = new Request(`https://internal/api/sentinel/feed?limit=${limit}`, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
        });
        const res = await handleSentinelFeed(req, env);
        return await res.json();
      }

      default:
        return { error: `Unknown tool: ${toolName}` };
    }
  } catch (err) {
    return { error: `Tool execution failed: ${err?.message || 'unknown error'}`, tool: toolName };
  }
}

// ─── Anthropic API caller ─────────────────────────────────────────────────────
async function callAnthropicWithTools(env, model, systemPrompt, messages, tools, maxTokens = 2048) {
  if (!env.ANTHROPIC_API_KEY) {
    // Fallback: use Workers AI if available
    if (env.AI) {
      try {
        const lastMsg = messages[messages.length - 1];
        const prompt  = lastMsg?.content || '';
        const result  = await env.AI.run('@cf/meta/llama-3-8b-instruct', {
          messages: [
            { role: 'system', content: systemPrompt },
            ...messages.map(m => ({ role: m.role, content: typeof m.content === 'string' ? m.content : JSON.stringify(m.content) })),
          ],
          max_tokens: maxTokens,
        });
        return {
          role: 'assistant',
          content: result?.response || 'I encountered an issue processing your request. Please configure ANTHROPIC_API_KEY for full God Mode capability.',
          stop_reason: 'end_turn',
          model: 'cf-llama-3-8b',
          fallback: true,
        };
      } catch {}
    }
    throw new Error('ANTHROPIC_API_KEY not configured. Please set the secret to enable God Mode AI orchestration.');
  }

  const body = {
    model,
    max_tokens:  maxTokens,
    system:      systemPrompt,
    messages,
    tools:       tools.map(t => ({ name: t.name, description: t.description, input_schema: t.input_schema })),
  };

  const res = await fetch(ANTHROPIC_API_URL, {
    method:  'POST',
    headers: {
      'Content-Type':         'application/json',
      'x-api-key':            env.ANTHROPIC_API_KEY,
      'anthropic-version':    ANTHROPIC_VERSION,
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const errText = await res.text().catch(() => 'unknown');
    throw new Error(`Anthropic API error ${res.status}: ${errText.slice(0, 300)}`);
  }

  return res.json();
}

// ─── Core chat orchestration (handles multi-turn tool use agentic loop) ────────
async function orchestrateChat(env, tier, authCtx, messages, availableTools, maxTokens) {
  const model      = MODEL_ROUTING[tier] || 'claude-haiku-4-5-20251001';
  const systemPmt  = buildSystemPrompt(tier, authCtx);
  let   workingMsgs = [...messages];

  // Agentic loop: keep running tool calls until the model returns end_turn or no more tool_use
  const MAX_TOOL_ROUNDS = 5;
  let   round = 0;

  while (round < MAX_TOOL_ROUNDS) {
    round++;
    let response;
    try {
      response = await callAnthropicWithTools(env, model, systemPmt, workingMsgs, availableTools, maxTokens);
    } catch (err) {
      return {
        role: 'assistant',
        content: `I encountered an issue reaching my reasoning engine: ${err?.message || 'unknown error'}. Please check that ANTHROPIC_API_KEY is configured.`,
        model,
        error: true,
      };
    }

    const stopReason = response.stop_reason;

    // If the model is done (no more tool calls), return its final text
    if (stopReason !== 'tool_use') {
      const textContent = Array.isArray(response.content)
        ? response.content.filter(b => b.type === 'text').map(b => b.text).join('\n\n')
        : (response.content || '');
      return {
        role:    'assistant',
        content: textContent,
        model:   response.model || model,
        usage:   response.usage,
      };
    }

    // Process tool_use blocks
    const toolUseBlocks  = Array.isArray(response.content)
      ? response.content.filter(b => b.type === 'tool_use')
      : [];

    if (toolUseBlocks.length === 0) break;

    // Add assistant message with tool_use blocks to working conversation
    workingMsgs.push({ role: 'assistant', content: response.content });

    // Execute all tools in parallel
    const toolResults = await Promise.all(
      toolUseBlocks.map(async (block) => {
        const result = await executeTool(block.name, block.input || {}, env, authCtx);
        return {
          type:        'tool_result',
          tool_use_id: block.id,
          content:     JSON.stringify(result, null, 2).slice(0, 8000), // truncate large results
        };
      })
    );

    // Add tool results as user message
    workingMsgs.push({ role: 'user', content: toolResults });
  }

  // Fallback if loop exits without end_turn
  return {
    role:    'assistant',
    content: 'I completed the tool orchestration cycle. Please ask a follow-up question for synthesis and recommendations.',
    model,
  };
}

// ─── Route handlers ───────────────────────────────────────────────────────────

/**
 * POST /api/copilot/chat
 * Body: { message: string, session_id?: string, max_tokens?: number }
 */
export async function handleCopilotChat(request, env, authCtx) {
  if (request.method !== 'POST') return badRequest('Method not allowed — use POST');

  let body;
  try { body = await request.json(); } catch { return badRequest('Invalid JSON body'); }

  const userMessage = (body.message || '').trim();
  if (!userMessage) return badRequest('message is required');
  if (userMessage.length > 4000) return badRequest('message too long (max 4000 characters)');

  const userId    = authCtx?.userId || authCtx?.email || authCtx?.ip || 'anonymous';
  const tier      = (authCtx?.tier || 'FREE').toUpperCase();
  const sessionId = body.session_id || `${userId}:default`;
  const maxTokens = Math.min(body.max_tokens || 2048, tier === 'FREE' ? 1024 : 4096);

  // Quota check
  const quota = await checkDailyQuota(env, userId, tier);
  if (!quota.ok) {
    return ok({
      error:   'daily_quota_exceeded',
      message: `You have reached your daily limit of ${quota.limit} messages on the ${tier} tier. Upgrade to PRO for 200/day or ENTERPRISE for unlimited.`,
      quota,
      upgrade_url: 'https://cyberdudebivash.in/#pricing',
    });
  }

  // Determine available tools based on tier
  const availableTools = TOOL_REGISTRY.filter(t => {
    if (!t.tiers) return true; // all tiers
    return t.tiers.includes(tier);
  });

  // Load session
  const session = await loadSession(env, userId, sessionId);

  // Build messages array for Anthropic
  const conversationMessages = [
    ...session.messages,
    { role: 'user', content: userMessage },
  ];

  // Run the agentic orchestration loop
  const response = await orchestrateChat(env, tier, authCtx, conversationMessages, availableTools, maxTokens);

  // Persist updated session
  session.messages = [
    ...session.messages,
    { role: 'user', content: userMessage },
    { role: 'assistant', content: response.content },
  ];
  await saveSession(env, userId, sessionId, session);

  return ok({
    session_id:    sessionId,
    message:       response.content,
    model:         response.model,
    tier,
    quota: {
      used:  quota.used,
      limit: quota.limit,
      remaining: quota.limit ? quota.limit - quota.used : null,
    },
    tools_available: availableTools.length,
    timestamp: new Date().toISOString(),
  });
}

/**
 * GET /api/copilot/session?session_id=...
 */
export async function handleGetCopilotSession(request, env, authCtx) {
  const userId    = authCtx?.userId || authCtx?.email || authCtx?.ip || 'anonymous';
  const url       = new URL(request.url);
  const sessionId = url.searchParams.get('session_id') || `${userId}:default`;

  const session = await loadSession(env, userId, sessionId);
  return ok({
    session_id:    sessionId,
    message_count: session.messages.length,
    created_at:    session.created_at,
    updated_at:    session.updated_at,
    messages:      session.messages.slice(-20),
  });
}

/**
 * DELETE /api/copilot/session?session_id=...
 */
export async function handleDeleteCopilotSession(request, env, authCtx) {
  const userId    = authCtx?.userId || authCtx?.email || authCtx?.ip || 'anonymous';
  const url       = new URL(request.url);
  const sessionId = url.searchParams.get('session_id') || `${userId}:default`;

  if (env.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.delete(sessionKey(userId, sessionId)).catch(() => {});
  }
  return ok({ success: true, session_id: sessionId, message: 'Session cleared successfully.' });
}

/**
 * POST /api/copilot/quick-action
 * Body: { skill: string, params?: object }
 * Direct skill invocation without full conversation context
 */
export async function handleCopilotQuickAction(request, env, authCtx) {
  if (request.method !== 'POST') return badRequest('Method not allowed — use POST');

  let body;
  try { body = await request.json(); } catch { return badRequest('Invalid JSON body'); }

  const skill  = body.skill;
  const params = body.params || {};
  const tier   = (authCtx?.tier || 'FREE').toUpperCase();

  if (!skill) return badRequest('skill is required');

  const tool = TOOL_REGISTRY.find(t => t.name === skill);
  if (!tool) {
    return badRequest(`Unknown skill: ${skill}. Call GET /api/copilot/capabilities to see available skills.`);
  }

  // Tier check
  if (tool.tiers && !tool.tiers.includes(tier) && !authCtx?.isAdmin) {
    return ok({
      error:       'tier_restriction',
      message:     `Skill "${skill}" requires ${tool.tiers.join(' or ')} tier. Current tier: ${tier}.`,
      upgrade_url: 'https://cyberdudebivash.in/#pricing',
      required_tiers: tool.tiers,
    });
  }

  const result = await executeTool(skill, params, env, authCtx);
  return ok({
    skill,
    params,
    result,
    timestamp: new Date().toISOString(),
  });
}

/**
 * GET /api/copilot/capabilities
 */
export async function handleCopilotCapabilities(request, env, authCtx) {
  const tier = (authCtx?.tier || 'FREE').toUpperCase();

  const capabilities = TOOL_REGISTRY.map(t => ({
    name:        t.name,
    description: t.description,
    read_only:   t.readOnly,
    available:   !t.tiers || t.tiers.includes(tier) || !!authCtx?.isAdmin,
    required_tier: t.tiers ? t.tiers[0] : null,
    tiers:       t.tiers || ['FREE','STARTER','PRO','TEAM','ENTERPRISE','MSSP'],
    parameters:  Object.keys(t.input_schema.properties || {}),
  }));

  const model = MODEL_ROUTING[tier] || MODEL_ROUTING.FREE;

  return ok({
    copilot: 'APEX — AI Security Copilot (God Mode)',
    version: '1.0.0',
    tier,
    model,
    daily_quota: DAILY_QUOTA[tier] || 'unlimited',
    session_ttl_hours: SESSION_TTL / 3600,
    max_history_messages: MAX_HISTORY,
    total_skills:     TOOL_REGISTRY.length,
    available_skills: capabilities.filter(c => c.available).length,
    capabilities,
    endpoints: {
      chat:          'POST /api/copilot/chat',
      session_get:   'GET  /api/copilot/session',
      session_clear: 'DELETE /api/copilot/session',
      quick_action:  'POST /api/copilot/quick-action',
      capabilities:  'GET  /api/copilot/capabilities',
    },
    example_prompts: [
      'What is the current threat landscape for AI/LLM systems?',
      'Run a full threat intelligence scan and generate a premium report',
      'What SIEM integrations are configured and what rules have been deployed?',
      'Trigger the Autonomous SOC pipeline and show me the results',
      'Generate Sigma and KQL detection rules for CVE-2024-12345',
      'Check our AI governance compliance against NIST AI RMF and EU AI Act',
      'Run a red team simulation against our AI assistant for prompt injection',
      'What is our platform health status and security posture?',
      'Show me the top 10 critical CVEs affecting AI/LLM systems right now',
      'Forecast the breach probability for our main application',
    ],
  });
}
