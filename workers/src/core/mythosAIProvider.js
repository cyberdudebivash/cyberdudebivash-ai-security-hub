/**
 * CYBERDUDEBIVASH MYTHOS AI PROVIDER — APEX NEXUS Sovereign Engine v3.0
 * ════════════════════════════════════════════════════════════════════════════
 * God Mode AI convenience layer — delegates to APEX AI Provider Router.
 * All existing callClaude() callers work unchanged.
 *
 * v3.0 New capabilities:
 * - analyzeCodeSecurity()    — Source code vulnerability analysis
 * - investigateForensics()   — Incident forensics + attacker timeline
 * - researchCVE()            — Deep CVE analysis with exploitation context
 * - simulateRedTeam()        — Red team scenario simulation
 * - generateComplianceNarrative() — DPDP/GDPR/ISO compliance gap narrative
 *
 * Provider chain (no vendor lock-in):
 *   Groq → DeepSeek → Together AI → Cloudflare Workers AI → OpenRouter → Anthropic
 *
 * Env secrets (add any combination — platform works with whatever is set):
 *   GROQ_API_KEY        — Groq Cloud (recommended, fast, generous free tier)
 *   DEEPSEEK_API_KEY    — DeepSeek (ultra-cheap, best technical CVE reasoning)
 *   TOGETHER_API_KEY    — Together AI (diverse models: Qwen, Mistral, CodeLlama)
 *   OPENROUTER_API_KEY  — OpenRouter meta-provider (50+ models)
 *   ANTHROPIC_API_KEY   — Anthropic Claude (optional premium tier)
 *   env.AI              — CF Workers AI binding (always available, zero key needed)
 * ════════════════════════════════════════════════════════════════════════════
 */

import {
  callViaRouter,
  routeAICall,
  getProviderHealthStatus,
  checkAIProviderHealth as routerHealthCheck,
  PROVIDERS,
} from './aiProviderRouter.js';

// ── Model registry (kept for backward compat) ─────────────────────────────────
export const CLAUDE_MODELS = {
  OPUS:   'claude-opus-4-8',
  SONNET: 'claude-sonnet-4-6',
  HAIKU:  'claude-haiku-4-5-20251001',
};

// ════════════════════════════════════════════════════════════════════════════
// PRIMARY: callClaude — unchanged interface, now APEX NEXUS router-backed
// ════════════════════════════════════════════════════════════════════════════
export async function callClaude(env, opts) {
  return callViaRouter(env, opts);
}

// ── Executive security narrative ──────────────────────────────────────────────
export async function generateExecutiveNarrative(env, {
  target,
  service_name,
  riskScore,
  riskLevel,
  findings     = [],
  sector       = 'Technology',
  tier         = 'PRO',
  extra_context = '',
}) {
  const topFindings = findings
    .filter(f => ['CRITICAL','HIGH'].includes(f.severity))
    .slice(0, 6)
    .map(f => `• [${f.severity}] ${f.title || f.id}: ${(f.description || '').slice(0, 120)}`)
    .join('\n');

  const prompt = `Generate a 3-paragraph enterprise security intelligence brief for:

Target: ${target || 'the assessed system'}
Service: ${service_name}
Risk Score: ${riskScore}/100 (${riskLevel})
Industry/Sector: ${sector}
${extra_context ? `Context: ${extra_context}` : ''}

Key findings:
${topFindings || '• Assessment complete — findings prioritized below'}

Requirements:
Paragraph 1: Executive threat posture summary — current risk level, business exposure, immediate urgency (2-3 sentences). Include estimated financial impact in ₹ for Indian context.
Paragraph 2: Top 3 critical actions with explicit business impact — what breaks if ignored. Include CERT-In 6-hour reporting obligation if applicable (2-3 sentences each).
Paragraph 3: Strategic 90-day security roadmap with measurable milestones (3-4 sentences).

Standards: Enterprise-grade precision. MITRE ATT&CK references (T####) where applicable. DPDP Act / CERT-In regulatory context for India. No generic advice.`;

  const result = await routeAICall(env, {
    prompt,
    task_type:   'executive',
    tier,
    max_tokens:  600,
    temperature: 0.2,
  });
  return result?.content || null;
}

// ── AI threat actor attribution ────────────────────────────────────────────────
export async function generateThreatAttribution(env, {
  findings = [],
  sector   = 'Technology',
  tier     = 'PRO',
}) {
  if (findings.length === 0) return null;

  const prompt = `Based on these security findings in the ${sector} sector:
${findings.slice(0, 5).map(f => `• ${f.title}: ${(f.description||'').slice(0,80)}`).join('\n')}

Identify the top 2-3 most likely threat actors or attack campaigns relevant to these findings. For each provide:
- Threat actor name (include nation-state attribution if applicable)
- Relevant TTPs matching these findings (MITRE ATT&CK T#### IDs)
- Likelihood score (1-10) with confidence level [HIGH/MEDIUM/LOW]
- India-specific relevance (are they known to target Indian organizations?)
- One specific remediation priority

Be specific and evidence-based. Reference CISA advisories or recent campaigns.`;

  const result = await routeAICall(env, {
    prompt,
    task_type:   'threat_intel',
    tier,
    max_tokens:  500,
    temperature: 0.1,
  });
  return result?.content || null;
}

// ── Remediation narrative ──────────────────────────────────────────────────────
export async function generateRemediationNarrative(env, {
  findings  = [],
  riskScore,
  org       = 'the organization',
  sector    = 'technology',
  tier      = 'PRO',
}) {
  if (findings.length === 0) return null;

  const critHigh = findings.filter(f => ['CRITICAL','HIGH'].includes(f.severity)).slice(0, 5);
  const prompt = `For ${org} in the ${sector} sector with risk score ${riskScore}/100, provide a structured remediation narrative for these ${critHigh.length} critical/high findings:

${critHigh.map((f, i) => `${i+1}. [${f.severity}] ${f.title}\n   Remediation hint: ${(f.remediation||f.description||'').slice(0,100)}`).join('\n')}

Provide:
1. Immediate actions (24-48h) — specific, executable steps with owner assignment
2. Short-term program (7-30 days) — process and tooling changes
3. Success metrics — how to measure improvement
4. Regulatory considerations — CERT-In 6-hour reporting if applicable; DPDP Act §8 safeguards

Be concise and actionable. Format for CISO presentation. Include ₹ cost estimates where relevant.`;

  const result = await routeAICall(env, {
    prompt,
    task_type:   'executive',
    tier,
    max_tokens:  600,
    temperature: 0.2,
  });
  return result?.content || null;
}

// ════════════════════════════════════════════════════════════════════════════
// v3.0 NEW: analyzeCodeSecurity
// ════════════════════════════════════════════════════════════════════════════
export async function analyzeCodeSecurity(env, {
  code,
  language   = 'javascript',
  context    = '',
  tier       = 'PRO',
  max_tokens = 800,
}) {
  if (!code || code.length < 10) return null;

  const prompt = `Perform a thorough security code review for this ${language} code:

${context ? `Context: ${context}\n\n` : ''}
\`\`\`${language}
${code.slice(0, 2000)}
\`\`\`

Analyze for:
1. OWASP Top 10 vulnerabilities (injection, broken auth, XSS, CSRF, insecure deserialization, etc.)
2. Secrets/credentials hardcoded in code
3. SQL/NoSQL injection vectors
4. Unsafe input handling or deserialization
5. Insecure cryptographic practices
6. Supply chain risks (dependency vulnerabilities)

For each finding provide:
- Severity (CRITICAL/HIGH/MEDIUM/LOW)
- MITRE ATT&CK technique (T####)
- Specific vulnerable line/pattern
- Secure code fix (code snippet)

Format: structured list. Be specific about line numbers and exact vulnerable patterns.`;

  const result = await routeAICall(env, {
    prompt,
    task_type:    'code_review',
    tier,
    max_tokens,
    temperature:  0.1,
  });
  return result?.content || null;
}

// ════════════════════════════════════════════════════════════════════════════
// v3.0 NEW: investigateForensics
// ════════════════════════════════════════════════════════════════════════════
export async function investigateForensics(env, {
  incident_type,
  indicators    = [],
  timeline      = [],
  affected_systems = [],
  tier          = 'PRO',
}) {
  const iocs = indicators.slice(0, 20).map(i => `• ${i}`).join('\n');
  const events = timeline.slice(0, 10).map(e => `• ${e}`).join('\n');

  const prompt = `You are APEX NEXUS forensic investigator. Analyze this security incident:

Incident Type: ${incident_type}
Affected Systems: ${affected_systems.join(', ') || 'Unknown'}

Indicators of Compromise (IOCs):
${iocs || '• No IOCs provided'}

Timeline Events:
${events || '• No timeline provided'}

Provide:
1. Attack vector analysis — how did the attacker gain initial access?
2. MITRE ATT&CK kill chain reconstruction (T#### for each stage)
3. Threat actor attribution hypothesis with confidence [HIGH/MEDIUM/LOW]
4. Lateral movement and persistence indicators to hunt for
5. Containment actions — ranked by urgency
6. Evidence preservation checklist for CERT-In reporting
7. Estimated attacker dwell time

Be forensically precise. CERT-In 6-hour reporting obligation assessment required.`;

  const result = await routeAICall(env, {
    prompt,
    task_type:       'forensics',
    tier,
    max_tokens:      800,
    temperature:     0.1,
    chain_of_thought: true,
  });
  return result?.content || null;
}

// ════════════════════════════════════════════════════════════════════════════
// v3.0 NEW: researchCVE
// ════════════════════════════════════════════════════════════════════════════
export async function researchCVE(env, {
  cve_id,
  cvss_score = null,
  description = '',
  tier        = 'PRO',
}) {
  if (!cve_id) return null;

  const prompt = `Provide deep threat intelligence analysis for ${cve_id}:

CVSS Score: ${cvss_score || 'Unknown'}
Description: ${description.slice(0, 300) || 'Not provided'}

Research and provide:
1. Vulnerability technical details — root cause, attack vector, prerequisites
2. MITRE ATT&CK technique mapping (T####)
3. Exploitation status — is there a public PoC? Is it in CISA KEV? Active exploitation evidence?
4. Affected products/versions — comprehensive list
5. Threat actors known to exploit this CVE
6. EPSS score estimate — probability of exploitation in next 30 days
7. Patch availability and workarounds
8. Detection logic — SIEM query/Sigma rule concept for detecting exploitation attempts
9. India-specific impact — any known targeting of Indian organizations?

Cite real sources (NVD, CISA, vendor advisories). No fabrication.`;

  const result = await routeAICall(env, {
    prompt,
    task_type:       'threat_intel',
    tier,
    max_tokens:      800,
    temperature:     0.1,
  });
  return result?.content || null;
}

// ════════════════════════════════════════════════════════════════════════════
// v3.0 NEW: simulateRedTeam
// ════════════════════════════════════════════════════════════════════════════
export async function simulateRedTeam(env, {
  target_profile,    // { name, sector, size, tech_stack }
  scope             = 'full',
  findings          = [],
  tier              = 'PRO',
}) {
  const topVulns = findings
    .filter(f => ['CRITICAL','HIGH'].includes(f.severity))
    .slice(0, 5)
    .map(f => `• ${f.title} (${f.severity})`)
    .join('\n');

  const prompt = `You are an elite red team operator. Simulate an attack scenario against:

Target: ${target_profile?.name || 'unnamed organization'}
Sector: ${target_profile?.sector || 'technology'}
Tech Stack: ${target_profile?.tech_stack || 'unknown'}
Scope: ${scope}

Known vulnerabilities:
${topVulns || '• No specific vulnerabilities provided — simulate common attack surface'}

Design a realistic attack scenario:
1. Reconnaissance approach (OSINT sources, scanning methodology)
2. Initial access vector (most viable given the vulnerabilities)
3. Kill chain (step-by-step with MITRE ATT&CK T#### for each step)
4. Persistence mechanism
5. Lateral movement strategy
6. Data collection and exfiltration approach
7. Anti-forensics / defense evasion techniques
8. Estimated time to complete objectives
9. Detection likelihood at each stage
10. Recommended defenses that would block each stage

This is for authorized red team planning and defensive purposes.`;

  const result = await routeAICall(env, {
    prompt,
    task_type:       'red_team',
    tier,
    max_tokens:      900,
    temperature:     0.25,
    chain_of_thought: true,
  });
  return result?.content || null;
}

// ════════════════════════════════════════════════════════════════════════════
// v3.0 NEW: generateComplianceNarrative
// ════════════════════════════════════════════════════════════════════════════
export async function generateComplianceNarrative(env, {
  findings    = [],
  frameworks  = ['DPDP_2023','ISO27001','SOC2'],
  org_type    = 'technology company',
  risk_score  = 50,
  tier        = 'PRO',
}) {
  const critCount = findings.filter(f => f.severity === 'CRITICAL').length;

  const prompt = `As APEX NEXUS compliance analyst, generate a compliance gap assessment narrative for a ${org_type}:

Risk Score: ${risk_score}/100
Critical Findings: ${critCount}
Frameworks in scope: ${frameworks.join(', ')}

Key findings:
${findings.slice(0, 5).map(f => `• [${f.severity}] ${f.title}`).join('\n') || '• No findings provided'}

For each applicable framework, provide:
1. Current compliance posture (estimate %)
2. Specific gaps identified from the findings
3. Control references at risk (e.g., ISO 27001 A.9.4, SOC2 CC6.1)
4. Remediation roadmap (30/60/90 day)
5. Risk if unaddressed (financial penalty in ₹, regulatory consequence)

Special focus on:
- DPDP Act 2023: personal data processing obligations, consent, breach notification (72h to DPIB)
- CERT-In: 6-hour mandatory reporting if critical incident detected
- ISO 27001:2022: Annex A controls mapping

Be specific about article/clause numbers. No generic statements.`;

  const result = await routeAICall(env, {
    prompt,
    task_type:   'compliance_audit',
    tier,
    max_tokens:  700,
    temperature: 0.15,
  });
  return result?.content || null;
}

// ── Health check ──────────────────────────────────────────────────────────────
export async function checkAIProviderHealth(env) {
  return routerHealthCheck(env);
}
