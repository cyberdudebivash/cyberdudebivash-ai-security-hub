/**
 * MCP SECURITY SCANNER — v29.0.0
 * World's first dedicated Model Context Protocol security scanning engine
 * Scans MCP server configurations for: tool permission scope, auth enforcement,
 * data exfil vectors, injection surfaces, privilege escalation paths
 *
 * ENDPOINTS:
 *   POST /api/mcp-security/scan        — Full MCP server config scan
 *   GET  /api/mcp-security/results/:id — Get scan results by ID
 *   GET  /api/mcp-security/threats     — Curated MCP threat-pattern catalog
 *   POST /api/mcp-security/assess      — Quick risk assessment (3-question flow)
 *
 * Revenue trigger: Free = 3 findings | Paid ₹999 = Full report + remediation
 */

// ── MCP Security Vulnerability Catalog (OWASP LLM + MCP-specific) ─────────────
const MCP_VULN_CATALOG = [
  {
    id: 'MCP-001', severity: 'CRITICAL',
    title: 'Unrestricted Tool Permission Scope',
    description: 'MCP server exposes tools with broad filesystem or network access without scope restriction.',
    attack_vector: 'Tool Abuse (MITRE ATLAS ML10)',
    owasp_llm: 'LLM07: Insecure Plugin Design',
    remediation: 'Implement tool permission scoping: restrict filesystem access to specific directories, network access to allowlisted domains.',
    cvss_base: 9.1,
    affected_tools: ['read_file', 'write_file', 'execute_command', 'bash', 'shell'],
  },
  {
    id: 'MCP-002', severity: 'CRITICAL',
    title: 'Missing Authentication Enforcement',
    description: 'MCP server accepts tool calls without verifying caller identity or session tokens.',
    attack_vector: 'Unauthorized Access',
    owasp_llm: 'LLM01: Prompt Injection',
    remediation: 'Enforce OAuth 2.0 or API key authentication on all MCP endpoints. Validate JWT on each tool invocation.',
    cvss_base: 9.8,
    affected_tools: ['*'],
  },
  {
    id: 'MCP-003', severity: 'HIGH',
    title: 'Data Exfiltration via Tool Chaining',
    description: 'Tools can be chained to read sensitive data and transmit it to external endpoints.',
    attack_vector: 'Indirect Prompt Injection + Tool Abuse',
    owasp_llm: 'LLM08: Excessive Agency',
    remediation: 'Implement data egress controls. Log all tool outputs. Block tool chains that combine read+network operations.',
    cvss_base: 8.2,
    affected_tools: ['read_file', 'web_search', 'http_request', 'send_email'],
  },
  {
    id: 'MCP-004', severity: 'HIGH',
    title: 'Prompt Injection via Tool Results',
    description: 'Tool results containing attacker-controlled content can inject malicious instructions into the LLM context.',
    attack_vector: 'Indirect Prompt Injection',
    owasp_llm: 'LLM01: Prompt Injection',
    remediation: 'Sanitize all tool outputs before injecting into LLM context. Apply content security policy to tool responses.',
    cvss_base: 8.6,
    affected_tools: ['web_search', 'read_file', 'browse_url', 'query_database'],
  },
  {
    id: 'MCP-005', severity: 'HIGH',
    title: 'Privilege Escalation via Chained Tool Calls',
    description: 'Low-privilege tool calls can be sequenced to escalate to high-privilege operations.',
    attack_vector: 'Privilege Escalation',
    owasp_llm: 'LLM08: Excessive Agency',
    remediation: 'Implement least-privilege enforcement per tool. Define explicit tool dependency graphs and break privilege chains.',
    cvss_base: 7.9,
    affected_tools: ['execute_command', 'run_script', 'manage_files'],
  },
  {
    id: 'MCP-006', severity: 'HIGH',
    title: 'Secrets Exposure in Tool Arguments',
    description: 'MCP server logs or transmits full tool arguments, exposing API keys and credentials passed as parameters.',
    attack_vector: 'Credential Exposure',
    owasp_llm: 'LLM06: Sensitive Information Disclosure',
    remediation: 'Implement argument sanitization in logs. Never log tool arguments containing credential patterns. Use secret redaction middleware.',
    cvss_base: 7.5,
    affected_tools: ['authenticate', 'api_call', 'database_query', 'send_request'],
  },
  {
    id: 'MCP-007', severity: 'MEDIUM',
    title: 'Missing Rate Limiting on Tool Invocations',
    description: 'No rate limiting on tool calls allows abuse: mass data scraping, compute exhaustion, API quota depletion.',
    attack_vector: 'Denial of Service / Abuse',
    owasp_llm: 'LLM04: Model Denial of Service',
    remediation: 'Implement per-session tool call rate limiting. Set max tool calls per minute per user. Use exponential backoff on repeated calls.',
    cvss_base: 6.5,
    affected_tools: ['*'],
  },
  {
    id: 'MCP-008', severity: 'MEDIUM',
    title: 'Insufficient Tool Result Validation',
    description: 'Tool results are trusted and injected into prompts without schema validation, enabling response tampering.',
    attack_vector: 'Response Tampering',
    owasp_llm: 'LLM09: Overreliance',
    remediation: 'Define strict JSON schemas for each tool\'s return type. Validate all tool results against schema before LLM injection.',
    cvss_base: 6.1,
    affected_tools: ['*'],
  },
  {
    id: 'MCP-009', severity: 'MEDIUM',
    title: 'Cross-Session Tool State Leakage',
    description: 'Tool state (file handles, database cursors, network connections) persists across user sessions.',
    attack_vector: 'Session Isolation Failure',
    owasp_llm: 'LLM06: Sensitive Information Disclosure',
    remediation: 'Enforce strict session isolation for all tool state. Clean up all tool resources on session termination.',
    cvss_base: 5.8,
    affected_tools: ['read_file', 'query_database', 'maintain_connection'],
  },
  {
    id: 'MCP-010', severity: 'LOW',
    title: 'Missing Tool Invocation Audit Log',
    description: 'Tool calls are not logged with sufficient detail for security incident investigation.',
    attack_vector: 'Audit Gap',
    owasp_llm: 'LLM03: Training Data Poisoning',
    remediation: 'Implement immutable audit logs for all tool invocations: timestamp, session ID, tool name, arguments hash, result hash.',
    cvss_base: 4.3,
    affected_tools: ['*'],
  },
];

// ── Risk scoring engine ───────────────────────────────────────────────────────
function scoreMCPConfig(config) {
  const findings = [];
  const tools = config.tools || [];
  const auth = config.auth || {};
  const transport = config.transport || {};
  const permissions = config.permissions || {};

  // Check MCP-001: Tool scope
  const dangerousTools = ['read_file', 'write_file', 'execute_command', 'bash', 'shell', 'run_script', 'manage_files'];
  const exposedDangerous = tools.filter(t =>
    dangerousTools.some(d => (t.name || t).toLowerCase().includes(d.replace('_', '')))
  );
  if (exposedDangerous.length > 0) {
    const vuln = { ...MCP_VULN_CATALOG[0] };
    vuln.affected_tools = exposedDangerous.map(t => t.name || t);
    vuln.evidence = `Exposed dangerous tools: ${vuln.affected_tools.join(', ')}`;
    if (!permissions.filesystem_scope || permissions.filesystem_scope === '*' || permissions.filesystem_scope === '/') {
      vuln.severity = 'CRITICAL';
    } else {
      vuln.severity = 'MEDIUM';
      vuln.cvss_base = 5.5;
      vuln.evidence += ` — scope restricted to: ${permissions.filesystem_scope}`;
    }
    findings.push(vuln);
  }

  // Check MCP-002: Authentication
  if (!auth.type || auth.type === 'none') {
    findings.push({ ...MCP_VULN_CATALOG[1], evidence: 'No authentication mechanism configured on MCP server' });
  } else if (auth.type === 'api_key' && !auth.enforce_on_all_routes) {
    findings.push({
      ...MCP_VULN_CATALOG[1],
      severity: 'HIGH',
      cvss_base: 7.5,
      evidence: `API key auth configured but not enforced on all routes (enforce_on_all_routes: false)`,
    });
  }

  // Check MCP-003: Data exfil
  const readTools = tools.filter(t => ['read_file', 'query', 'search', 'fetch', 'browse', 'get'].some(k => (t.name||t).toLowerCase().includes(k)));
  const networkTools = tools.filter(t => ['http', 'request', 'send', 'post', 'email', 'webhook', 'notify'].some(k => (t.name||t).toLowerCase().includes(k)));
  if (readTools.length > 0 && networkTools.length > 0 && !config.egress_controls) {
    findings.push({
      ...MCP_VULN_CATALOG[2],
      evidence: `Read tools (${readTools.slice(0,3).map(t=>t.name||t).join(', ')}) + Network tools (${networkTools.slice(0,3).map(t=>t.name||t).join(', ')}) with no egress controls`,
    });
  }

  // Check MCP-004: Injection surface
  const webTools = tools.filter(t => ['web_search', 'browse', 'url', 'scrape', 'fetch'].some(k => (t.name||t).toLowerCase().includes(k)));
  if (webTools.length > 0 && !config.content_security_policy) {
    findings.push({
      ...MCP_VULN_CATALOG[3],
      evidence: `Web-fetching tools without content security policy: ${webTools.slice(0,3).map(t=>t.name||t).join(', ')}`,
    });
  }

  // Check MCP-007: Rate limiting — only meaningful when manifest was fetched (tools present)
  if (tools.length > 0 && (!config.rate_limits || !config.rate_limits.tool_calls_per_minute)) {
    findings.push({ ...MCP_VULN_CATALOG[6], evidence: 'No rate_limits.tool_calls_per_minute configured' });
  }

  // Check MCP-008: Schema validation — requires actual tool definitions to evaluate
  if (tools.length > 0) {
    const toolsWithoutSchema = tools.filter(t => !t.output_schema && !t.returns);
    if (toolsWithoutSchema.length > 2) {
      findings.push({
        ...MCP_VULN_CATALOG[7],
        evidence: `${toolsWithoutSchema.length} tools have no output_schema defined`,
      });
    }
  }

  // Check MCP-010: Audit log — only flag when we have actual manifest data, not empty defaults
  if (tools.length > 0 && !config.audit_log && !config.logging?.audit_tool_calls) {
    findings.push({ ...MCP_VULN_CATALOG[9], evidence: 'No audit logging configured (audit_log: false or missing)' });
  }

  // Surface data-quality note when manifest was unavailable
  if (tools.length === 0 && !config._manifest_fetched) {
    findings.push({
      id: 'MCP-000', severity: 'INFO',
      title: 'Manifest Not Found',
      description: 'Could not retrieve /.well-known/mcp-manifest.json from this server. Static URL analysis only.',
      evidence: 'Submit a JSON config directly via the advanced tab for deeper analysis.',
      remediation: 'Expose a public MCP manifest at /.well-known/mcp-manifest.json',
      affected_tools: [],
    });
  }

  // Compute risk score
  const sevWeights = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3 };
  const rawScore = findings.reduce((sum, f) => sum + (sevWeights[f.severity] || 0), 0);
  const risk_score = Math.min(100, rawScore);

  let risk_level = 'LOW';
  if (risk_score >= 75) risk_level = 'CRITICAL';
  else if (risk_score >= 50) risk_level = 'HIGH';
  else if (risk_score >= 25) risk_level = 'MEDIUM';

  const grades = { CRITICAL: 'F', HIGH: 'D', MEDIUM: 'C', LOW: 'B' };
  const grade = findings.some(f => f.severity === 'CRITICAL') ? 'F'
    : findings.some(f => f.severity === 'HIGH') ? 'D'
    : findings.some(f => f.severity === 'MEDIUM') ? 'C'
    : findings.length > 0 ? 'B' : 'A';

  // Split into free (3) and locked
  const free_findings = findings.slice(0, 3).map(f => ({ id: f.id, severity: f.severity, title: f.title, description: f.description, evidence: f.evidence, owasp_llm: f.owasp_llm, cvss_base: f.cvss_base }));
  const locked_findings = findings.slice(3).map(f => ({
    id: f.id, severity: f.severity, title: f.title,
    preview: `${f.description.substring(0, 80)}...`,
    cvss_base: f.cvss_base,
  }));

  const top_remediations = findings.slice(0, 5).map(f => `[${f.id}] ${f.remediation}`);

  return {
    risk_score, risk_level, grade,
    total_vulnerabilities: findings.length,
    findings: free_findings,
    locked_findings,
    top_remediations: locked_findings.length === 0 ? findings.map(f => `[${f.id}] ${f.remediation}`) : top_remediations,
    summary: `MCP server scored ${risk_score}/100 risk. ${findings.filter(f=>f.severity==='CRITICAL').length} CRITICAL, ${findings.filter(f=>f.severity==='HIGH').length} HIGH vulnerabilities.`,
    scanned_tools: tools.length,
    mcp_attack_surface: {
      tool_count: tools.length,
      dangerous_tool_count: exposedDangerous.length,
      has_auth: !!(auth.type && auth.type !== 'none'),
      has_egress_controls: !!config.egress_controls,
      has_rate_limits: !!(config.rate_limits?.tool_calls_per_minute),
      has_audit_log: !!(config.audit_log || config.logging?.audit_tool_calls),
    },
    monetization: locked_findings.length > 0 ? {
      unlock_price: '₹999',
      amount: 99900,
      upgrade_cta: `Unlock ${locked_findings.length} additional vulnerabilities + complete remediation roadmap`,
    } : null,
    scan_id: crypto.randomUUID(),
    scanned_at: new Date().toISOString(),
    scanner_version: 'MCP-SCANNER-v29.0',
  };
}

// ── Handler: Full MCP Scan ───────────────────────────────────────────────────
export async function handleMCPSecurityScan(request, env, authCtx) {
  try {
    const body = await request.json().catch(() => ({}));
    const { config, server_url, server_name = 'MCP Server' } = body;

    // If URL provided, try to fetch the MCP server manifest
    let resolvedConfig = config;
    if (!resolvedConfig && server_url) {
      try {
        const resp = await fetch(`${server_url}/.well-known/mcp-manifest.json`, {
          signal: AbortSignal.timeout(5000),
          headers: { 'User-Agent': 'CYBERDUDEBIVASH-MCP-SCANNER/29.0' },
        });
        if (resp.ok) resolvedConfig = await resp.json();
      } catch (_) {
        // Manifest not found — use what was provided or defaults
      }
    }

    if (!resolvedConfig) {
      // Basic scan based on URL or server_name only
      resolvedConfig = {
        tools: [],
        auth: {},
        server_url,
        note: 'No config provided — scanned defaults only',
      };
    }

    const result = scoreMCPConfig(resolvedConfig);
    result.server_name = server_name;
    result.server_url = server_url || 'local';

    // Persist to D1 if available
    if (env.DB) {
      try {
        await env.DB.prepare(`
          INSERT OR IGNORE INTO mcp_security_scans (scan_id, server_name, server_url, risk_score, risk_level, grade, vuln_count, result_json, scanned_at, user_email)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          result.scan_id, server_name, result.server_url || 'local',
          result.risk_score, result.risk_level, result.grade,
          result.total_vulnerabilities, JSON.stringify(result),
          result.scanned_at, authCtx?.email || null
        ).run();
      } catch (_) { /* non-fatal */ }
    }

    // Track funnel event
    if (env.DB) {
      try {
        await env.DB.prepare(`
          INSERT OR IGNORE INTO funnel_events (event_id, event_type, module, email, meta, created_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `).bind(
          crypto.randomUUID(), 'mcp_scan_complete', 'mcp_security',
          authCtx?.email || null,
          JSON.stringify({ server_name, risk_score: result.risk_score }),
          new Date().toISOString()
        ).run();
      } catch (_) {}
    }

    return Response.json(result, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-store',
        'X-Scanner': 'CYBERDUDEBIVASH-MCP-SCANNER-v29',
      },
    });
  } catch (e) {
    return Response.json({ error: 'MCP scan failed', detail: e.message }, { status: 500 });
  }
}

// ── Handler: Get Scan Results ────────────────────────────────────────────────
export async function handleMCPScanResult(request, env, authCtx) {
  const url = new URL(request.url);
  const scanId = url.pathname.split('/').pop();

  if (env.DB) {
    try {
      const row = await env.DB.prepare('SELECT result_json FROM mcp_security_scans WHERE scan_id = ?').bind(scanId).first();
      if (row) {
        return Response.json(JSON.parse(row.result_json), { headers: { 'Access-Control-Allow-Origin': '*' } });
      }
    } catch (_) {}
  }
  return Response.json({ error: 'Scan not found', scan_id: scanId }, { status: 404, headers: { 'Access-Control-Allow-Origin': '*' } });
}

// ── Handler: MCP Threat Feed ─────────────────────────────────────────────────
export async function handleMCPThreatFeed(request, env) {
  const threats = [
    {
      id: 'MCP-THREAT-2026-001', type: 'tool_abuse', severity: 'CRITICAL',
      title: 'Indirect Prompt Injection via MCP Web Search Tool',
      description: 'Attacker embeds malicious instructions in web pages that are returned by MCP web_search tools, hijacking agent behavior.',
      affected_tools: ['web_search', 'browse_url', 'fetch_page'],
      first_seen: '2026-03-15', last_seen: '2026-03-15',
      mitre_atlas: 'AML.T0054.001',
      cve: null, poc_available: true,
      indicators: ['Unusual tool chain: web_search → write_file', 'Tool results containing role: or system: prefix'],
    },
    {
      id: 'MCP-THREAT-2026-002', type: 'privilege_escalation', severity: 'HIGH',
      title: 'MCP Tool Chaining for Filesystem Takeover',
      description: 'Sequence of read_file + write_file + execute_command tools used to achieve arbitrary code execution on MCP server host.',
      affected_tools: ['read_file', 'write_file', 'execute_command'],
      first_seen: '2026-04-02', last_seen: '2026-04-02',
      mitre_atlas: 'AML.T0010',
      cve: null, poc_available: true,
      indicators: ['Tool chain: read_file → write_file in /tmp → execute_command /tmp/'],
    },
    {
      id: 'MCP-THREAT-2026-003', type: 'data_exfiltration', severity: 'HIGH',
      title: 'Sensitive Data Exfiltration via Webhook Tool',
      description: 'Agent instructed to read sensitive files and send contents to attacker-controlled endpoint via webhook/http_request tools.',
      affected_tools: ['read_file', 'http_request', 'send_email', 'webhook'],
      first_seen: '2026-04-18', last_seen: '2026-04-18',
      mitre_atlas: 'AML.T0048',
      cve: null, poc_available: false,
      indicators: ['read_file + http_request in same session', 'Outbound requests to non-allowlisted domains'],
    },
    {
      id: 'MCP-THREAT-2026-004', type: 'credential_theft', severity: 'HIGH',
      title: 'MCP Environment Variable Extraction',
      description: 'Prompt injection causes agent to call execute_command with env or printenv, exposing API keys and secrets.',
      affected_tools: ['execute_command', 'bash', 'shell'],
      first_seen: '2026-05-01', last_seen: '2026-05-01',
      mitre_atlas: 'AML.T0056',
      cve: null, poc_available: true,
      indicators: ['execute_command with printenv, env, cat ~/.env', 'Tool result contains API_KEY= pattern'],
    },
    {
      id: 'MCP-THREAT-2026-005', type: 'agent_takeover', severity: 'CRITICAL',
      title: 'Cross-Agent MCP Session Hijacking',
      description: 'Shared MCP server state allows one agent session to read or modify another session\'s tool context.',
      affected_tools: ['*'],
      first_seen: '2026-05-22', last_seen: '2026-05-22',
      mitre_atlas: 'AML.T0049',
      cve: null, poc_available: false,
      indicators: ['Tool calls accessing resources from different session_id', 'Missing session isolation headers'],
    },
  ];

  const catalogUpdatedAt = threats.reduce((max, t) => (t.last_seen > max ? t.last_seen : max), threats[0].last_seen);

  return Response.json({
    feed_version: 'v29.0',
    source: 'CYBERDUDEBIVASH MCP Security Research Lab (curated catalog)',
    total: threats.length,
    critical: threats.filter(t => t.severity === 'CRITICAL').length,
    high: threats.filter(t => t.severity === 'HIGH').length,
    catalog_last_updated: catalogUpdatedAt,
    threats,
    powered_by: 'CYBERDUDEBIVASH Sentinel APEX + MCP Security Research Lab',
  }, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=1800',
      'X-Scanner': 'CYBERDUDEBIVASH-MCP-THREAT-FEED-v29',
    },
  });
}

// ── Handler: Quick Risk Assessment ──────────────────────────────────────────
export async function handleMCPQuickAssess(request, env) {
  const body = await request.json().catch(() => ({}));
  const { answers = {} } = body;
  // answers: { has_auth: bool, has_filesystem_tools: bool, has_network_tools: bool, has_rate_limits: bool, has_egress_controls: bool }

  const score_map = {
    has_auth:            answers.has_auth ? 0 : 35,
    has_filesystem_tools: answers.has_filesystem_tools ? 20 : 0,
    has_network_tools:   answers.has_network_tools ? 15 : 0,
    has_rate_limits:     answers.has_rate_limits ? 0 : 10,
    has_egress_controls: answers.has_egress_controls ? 0 : 15,
  };

  const risk_score = Math.min(100, Object.values(score_map).reduce((a, b) => a + b, 0));
  const risk_level = risk_score >= 75 ? 'CRITICAL' : risk_score >= 50 ? 'HIGH' : risk_score >= 25 ? 'MEDIUM' : 'LOW';

  const recommended_actions = [];
  if (!answers.has_auth)            recommended_actions.push('URGENT: Add OAuth 2.0 or API key authentication to all MCP endpoints');
  if (answers.has_filesystem_tools) recommended_actions.push('HIGH: Restrict filesystem tool scope to specific allowed directories');
  if (!answers.has_egress_controls) recommended_actions.push('HIGH: Add egress controls to prevent data exfiltration via network tools');
  if (!answers.has_rate_limits)     recommended_actions.push('MEDIUM: Implement rate limiting on tool invocations (max calls/minute)');

  return Response.json({
    risk_score, risk_level,
    recommended_actions,
    full_scan_cta: 'Run a full MCP Security Scan for detailed vulnerability report — from ₹999',
    scan_endpoint: 'POST /api/mcp-security/scan',
  }, { headers: { 'Access-Control-Allow-Origin': '*' } });
}
