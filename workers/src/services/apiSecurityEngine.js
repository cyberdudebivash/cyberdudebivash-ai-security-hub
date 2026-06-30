/**
 * CYBERDUDEBIVASH AI Security Hub — API Security Assessment Engine v1.0
 * Service: CDB-APISEC-001 (₹19,999) — OWASP API Top 10 2023 Assessment
 */

// ── OWASP API Security Top 10 (2023) ─────────────────────────────────────────
const OWASP_API_TOP10 = [
  {
    id:          'API1:2023',
    title:       'Broken Object Level Authorization (BOLA)',
    description: 'APIs that don\'t validate user authorization for object access — most common API vulnerability.',
    test_vectors: ['Access objects using another user\'s ID', 'Enumerate sequential IDs', 'Test UUID predictability'],
    detection:   'Test resource endpoints with different user tokens; check if you can access others\' data',
    mitigation:  'Implement object-level authorization checks on every endpoint. Never trust client-supplied IDs.',
    cvss:        8.6,
    risk:        'CRITICAL',
  },
  {
    id:          'API2:2023',
    title:       'Broken Authentication',
    description: 'Weak authentication mechanisms, credential stuffing exposure, missing rate limiting on auth.',
    test_vectors: ['Credential stuffing attack', 'Brute force token/PIN', 'JWT algorithm confusion (none alg)'],
    detection:   'Test for weak token entropy, missing account lockout, JWT none algorithm acceptance',
    mitigation:  'Strong tokens (256-bit entropy), rate limiting on auth endpoints, MFA, JWT RS256/ES256',
    cvss:        7.5,
    risk:        'HIGH',
  },
  {
    id:          'API3:2023',
    title:       'Broken Object Property Level Authorization',
    description: 'APIs exposing sensitive object properties to users who shouldn\'t see them (mass assignment, excessive data exposure).',
    test_vectors: ['Check API responses for hidden admin fields', 'Test mass assignment via extra request fields'],
    detection:   'Inspect all API responses for sensitive fields. Test PUT/PATCH with additional undocumented fields.',
    mitigation:  'Allowlist output properties explicitly. Never return full objects — filter to what\'s needed.',
    cvss:        6.5,
    risk:        'HIGH',
  },
  {
    id:          'API4:2023',
    title:       'Unrestricted Resource Consumption',
    description: 'No limits on request size, frequency, or resource usage — enables DoS and cost attacks.',
    test_vectors: ['Send oversized request bodies', 'Flood endpoint without rate limit response', 'Multi-resource queries'],
    detection:   'Test without rate limiting headers. Measure response to large payloads.',
    mitigation:  'Rate limiting, request size limits, query complexity limits, resource quotas per user/key',
    cvss:        6.5,
    risk:        'HIGH',
  },
  {
    id:          'API5:2023',
    title:       'Broken Function Level Authorization',
    description: 'Admin functions accessible to regular users — privilege escalation via API endpoint access.',
    test_vectors: ['Access admin endpoints as regular user', 'Change HTTP method (GET→POST→DELETE)', 'Test /admin/* paths'],
    detection:   'Test all endpoints with lower-privilege tokens. Check for verb-tampering (GET vs DELETE).',
    mitigation:  'Enforce function-level authorization. Deny by default — allow only explicitly granted functions.',
    cvss:        7.2,
    risk:        'HIGH',
  },
  {
    id:          'API6:2023',
    title:       'Unrestricted Access to Sensitive Business Flows',
    description: 'APIs lack protection against automated misuse — scalping, mass account creation, loyalty fraud.',
    test_vectors: ['Automate purchase flow without CAPTCHA', 'Mass-create accounts', 'Exploit gift card/voucher APIs'],
    detection:   'Test business logic flows at scale — check for device fingerprinting, behavior analysis',
    mitigation:  'Business logic rate limiting, CAPTCHA on sensitive flows, anomaly detection, device fingerprinting',
    cvss:        5.3,
    risk:        'MEDIUM',
  },
  {
    id:          'API7:2023',
    title:       'Server Side Request Forgery (SSRF)',
    description: 'APIs that accept URLs and make server-side requests without validation — enables cloud metadata access.',
    test_vectors: ['Pass http://169.254.169.254/ as URL parameter', 'Test internal service discovery via URL params'],
    detection:   'Identify URL-accepting parameters. Test with internal IPs, localhost, and cloud metadata endpoints.',
    mitigation:  'Validate and allowlist URL destinations. Block internal IP ranges. Use deny-by-default network policies.',
    cvss:        7.5,
    risk:        'HIGH',
  },
  {
    id:          'API8:2023',
    title:       'Security Misconfiguration',
    description: 'Unnecessary HTTP methods, permissive CORS, missing security headers, error messages disclosing info.',
    test_vectors: ['Test OPTIONS/TRACE methods', 'Check CORS headers for wildcard origins', 'Trigger API errors for stack traces'],
    detection:   'OPTIONS request to all endpoints. Review CORS headers. Force errors to inspect responses.',
    mitigation:  'Disable unused HTTP methods. Restrict CORS. Implement security headers. Suppress detailed error messages.',
    cvss:        6.5,
    risk:        'HIGH',
  },
  {
    id:          'API9:2023',
    title:       'Improper Inventory Management',
    description: 'Outdated, undocumented, or shadow API versions exposed — missing version control and decommissioning.',
    test_vectors: ['Test /api/v1 vs /api/v2 — is old version still live?', 'Find undocumented endpoints'],
    detection:   'Enumerate API versions. Check for /swagger.json, /api-docs, /openapi.yaml.',
    mitigation:  'Maintain API inventory. Document and decommission old versions. Monitor for shadow APIs.',
    cvss:        5.0,
    risk:        'MEDIUM',
  },
  {
    id:          'API10:2023',
    title:       'Unsafe Consumption of APIs',
    description: 'Trusting third-party API responses without validation — enables injection via untrusted API data.',
    test_vectors: ['Inject malicious data via integrated third-party APIs', 'Test SSRF through third-party webhooks'],
    detection:   'Review third-party API integrations. Test whether external API responses are sanitized.',
    mitigation:  'Treat third-party API responses as untrusted input. Validate and sanitize all external data.',
    cvss:        6.0,
    risk:        'MEDIUM',
  },
];

// ── SSRF guard — reject private/loopback/internal hostnames ──────────────────
function isPrivateHost(rawUrl) {
  try {
    const hostname = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`).hostname.toLowerCase();
    return /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1|0\.0\.0\.0|fc00:|fd)/.test(hostname)
      || hostname === '[::1]'
      || hostname.endsWith('.local')
      || hostname.endsWith('.internal')
      || !hostname.includes('.');
  } catch { return true; }
}

// ── Probe API endpoints ───────────────────────────────────────────────────────
async function probeAPIEndpoint(baseUrl) {
  const results = {};
  if (isPrivateHost(baseUrl)) return { ssrf_blocked: true, error: 'Private/internal hosts not permitted' };
  const url = baseUrl.startsWith('http') ? baseUrl : `https://${baseUrl}`;

  // Test 1: OPTIONS (allowed methods)
  try {
    const r = await fetch(url, { method: 'OPTIONS', signal: AbortSignal.timeout(6000) });
    results.allowed_methods = r.headers.get('allow') || r.headers.get('Access-Control-Allow-Methods') || 'unknown';
    results.options_status  = r.status;
    results.cors_origin     = r.headers.get('access-control-allow-origin') || null;
    results.cors_wildcard   = results.cors_origin === '*';
  } catch { results.options_error = true; }

  // Test 2: Security headers
  try {
    const r = await fetch(url, { method: 'GET', signal: AbortSignal.timeout(6000) });
    results.status = r.status;
    results.has_auth_header    = !!(r.headers.get('www-authenticate'));
    results.rate_limit_headers = !!(r.headers.get('x-ratelimit-limit') || r.headers.get('ratelimit-limit'));
    results.has_security_headers = !!(r.headers.get('strict-transport-security') || r.headers.get('content-security-policy'));
    results.exposes_server     = r.headers.get('server') || null;
    results.exposes_x_powered  = r.headers.get('x-powered-by') || null;

    // Try to detect API documentation
    results.api_accessible = r.status < 500;
  } catch (e) {
    results.probe_error = e.message;
  }

  // Test 3: Common API docs endpoints
  const docEndpoints = ['/swagger.json', '/openapi.json', '/api-docs', '/v1', '/api/v1', '/graphql'];
  const docProbes = await Promise.allSettled(
    docEndpoints.map(ep =>
      fetch(`${url.replace(/\/$/, '')}${ep}`, {
        signal: AbortSignal.timeout(4000),
        headers: { 'User-Agent': 'CyberdudeBivash-APIScanner/1.0' },
      }).then(r => ({ endpoint: ep, status: r.status, exposed: r.status !== 404 }))
        .catch(() => ({ endpoint: ep, status: null, exposed: false }))
    )
  );

  results.discovered_endpoints = docProbes
    .filter(r => r.status === 'fulfilled' && r.value.exposed)
    .map(r => r.value);

  return results;
}

// ── Score API security from inputs + probe results ────────────────────────────
function scoreAPIFromInputs(inputs, probeResults) {
  const vulnMap = {
    'API1:2023': !inputs.has_object_auth,
    'API2:2023': !inputs.has_auth_rate_limit || !inputs.has_strong_tokens,
    'API3:2023': !inputs.has_output_filtering,
    'API4:2023': !inputs.has_rate_limiting || (probeResults && !probeResults.rate_limit_headers),
    'API5:2023': !inputs.has_function_auth,
    'API6:2023': !inputs.has_business_logic_protection,
    'API7:2023': !inputs.has_ssrf_protection,
    'API8:2023': (probeResults?.cors_wildcard) || !inputs.has_security_headers,
    'API9:2023': !inputs.has_api_inventory,
    'API10:2023': !inputs.has_third_party_validation,
  };

  return OWASP_API_TOP10.map(item => ({
    ...item,
    status:    vulnMap[item.id] ? 'VULNERABLE' : 'PASS',
    detected:  vulnMap[item.id],
  }));
}

export async function runAPISecurityAssessment(env, apiBaseUrl, orderId = null, directInputs = null) {
  const startedAt  = new Date().toISOString();
  const cleanUrl   = (apiBaseUrl || '').replace(/\/$/, '').trim();

  // Use directInputs if provided (direct scan), else load from DB order
  let inputs = directInputs || {};
  if (!directInputs && env?.DB && orderId) {
    const order = await env.DB.prepare('SELECT assessment_inputs FROM service_orders WHERE id=?').bind(orderId).first().catch(() => null);
    if (order?.assessment_inputs) {
      try { inputs = JSON.parse(order.assessment_inputs); } catch {}
    }
  }

  // Probe the API
  const probeResults = cleanUrl ? await probeAPIEndpoint(cleanUrl) : {};

  // Auto-detect issues from probing
  if (probeResults.cors_wildcard) inputs.has_security_headers = false;
  if (!probeResults.rate_limit_headers) inputs.has_rate_limiting = false;
  if (probeResults.exposes_server || probeResults.exposes_x_powered) inputs.server_info_disclosed = true;

  const owaspResults = scoreAPIFromInputs(inputs, probeResults);
  const vulnItems    = owaspResults.filter(r => r.detected);

  let riskScore = vulnItems.reduce((s, v) => s + Math.min(v.cvss * 3, 20), 0);
  riskScore += probeResults.cors_wildcard ? 15 : 0;
  riskScore += probeResults.server_info_disclosed ? 5 : 0;
  riskScore = Math.min(100, riskScore);
  const secScore = 100 - riskScore;
  const grade    = secScore >= 80 ? 'A' : secScore >= 65 ? 'B' : secScore >= 50 ? 'C' : secScore >= 35 ? 'D' : 'F';

  const findings = [
    ...vulnItems.map(item => ({
      id:          `APISEC-${item.id}`,
      severity:    item.risk,
      category:    'OWASP API Security',
      title:       `${item.id}: ${item.title}`,
      description: item.description,
      cvss:        item.cvss,
      test_vectors: item.test_vectors,
      remediation: item.mitigation,
    })),
    ...(probeResults.cors_wildcard ? [{
      id:          'APISEC-CORS-WILDCARD',
      severity:    'HIGH',
      category:    'Security Misconfiguration',
      title:       'CORS Wildcard Origin Detected',
      description: 'Access-Control-Allow-Origin: * allows any origin to make cross-origin requests',
      remediation: 'Replace wildcard CORS with explicit allowlist of trusted origins',
    }] : []),
    ...(probeResults.exposes_server ? [{
      id:          'APISEC-INFO-DISC',
      severity:    'LOW',
      category:    'Information Disclosure',
      title:       `Server Technology Disclosed: ${probeResults.exposes_server}`,
      description: 'Server header reveals technology stack — useful for targeted attacks',
      remediation: 'Remove or obscure Server header in web server configuration',
    }] : []),
  ];

  findings.sort((a, b) => {
    const so = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return (so[a.severity] ?? 4) - (so[b.severity] ?? 4);
  });

  const report = {
    meta: {
      service:      'CDB-APISEC-001',
      service_name: 'API Security Assessment',
      version:      '1.0',
      api_base_url: cleanUrl || 'N/A',
      generated_at: startedAt,
      framework:    'OWASP API Security Top 10 (2023)',
      powered_by:   'CYBERDUDEBIVASH AI Security Hub™',
    },
    executive_summary: {
      security_score:    secScore,
      risk_score:        riskScore,
      grade,
      owasp_pass:        owaspResults.filter(r => !r.detected).length,
      owasp_fail:        vulnItems.length,
      total_findings:    findings.length,
      critical_count:    findings.filter(f => f.severity === 'CRITICAL').length,
      high_count:        findings.filter(f => f.severity === 'HIGH').length,
      api_docs_exposed:  probeResults.discovered_endpoints?.length || 0,
      cors_wildcard:     probeResults.cors_wildcard || false,
    },
    probe_results:    probeResults,
    owasp_api_top10:  owaspResults,
    findings,
    recommendations: [
      ...(vulnItems.length > 0 ? [{ priority: 1, action: `Remediate ${vulnItems.length} OWASP API Security vulnerabilities`, effort: 'High', impact: 'Critical' }] : []),
      { priority: 2, action: 'Implement API gateway with rate limiting and auth enforcement', effort: 'Medium', impact: 'High' },
      { priority: 3, action: 'Deploy API security scanning in CI/CD pipeline', effort: 'Medium', impact: 'High' },
      { priority: 4, action: 'Maintain complete API inventory with version lifecycle management', effort: 'Low', impact: 'Medium' },
      { priority: 5, action: 'Conduct quarterly API penetration testing', effort: 'Medium', impact: 'High' },
    ],
  };

  if (env?.DB && orderId) {
    const assessId = crypto.randomUUID();
    try {
      await env.DB.prepare(
        `INSERT INTO service_assessments
         (id, order_id, service_ref, target, status, risk_score, risk_grade,
          findings_count, critical_count, high_count,
          findings_json, recommendations_json, report_json,
          engine_version, started_at, completed_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ).bind(
        assessId, orderId, 'CDB-APISEC-001', cleanUrl, 'complete',
        riskScore, grade,
        findings.length,
        findings.filter(f => f.severity === 'CRITICAL').length,
        findings.filter(f => f.severity === 'HIGH').length,
        JSON.stringify(findings),
        JSON.stringify(report.recommendations),
        JSON.stringify(report),
        '1.0', startedAt, new Date().toISOString()
      ).run();
      await env.DB.prepare(
        `UPDATE service_orders SET order_status='delivered', updated_at=datetime('now') WHERE id=?`
      ).bind(orderId).run();
    } catch (e) { console.error('[API-Security-Engine] DB error:', e.message); }
  }

  return report;
}
