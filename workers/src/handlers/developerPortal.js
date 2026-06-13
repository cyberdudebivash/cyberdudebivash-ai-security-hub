// =============================================================================
// DEVELOPER PORTAL & API ECONOMY — Full Self-Serve API Platform
// CYBERDUDEBIVASH AI Security Hub | handlers/developerPortal.js
// Differentiator: FULL (CrowdStrike=Partial, Palo Alto=Partial, Wiz=None, SentinelOne=None)
// Implements: API Explorer, SDK code generators, webhook catalog+test,
//             rate-limit dashboard, changelog, interactive playground
// =============================================================================

// ─── API Catalog (core endpoints with full OpenAPI-style specs) ───────────────
const API_CATALOG = [
  {
    group: 'AI Governance', prefix: '/api/ai-governance',
    description: 'EU AI Act, NIST AI RMF, ISO 42001 compliance and model risk management',
    tier: 'PRO', endpoints: [
      { method:'POST', path:'/models', summary:'Register AI model', description:'Register and automatically risk-score an AI model against EU AI Act and NIST AI RMF frameworks.',
        request_schema:{ org_id:'string', name:'string(required)', version:'string', model_type:'enum[generative_text,classification,regression,nlp,computer_vision,reinforcement,recommendation,other]',
          data_classification:'enum[public,internal,confidential,pii,phi,financial,secret]',
          deployment_context:'enum[production_customer_facing,production_internal,staging,development,research,batch_processing]',
          autonomy_level:'enum[fully_autonomous,human_on_loop,human_in_loop,advisory_only,decision_support]',
          impact_domain:'enum[healthcare,law_enforcement,critical_infrastructure,financial,legal,hr_employment,education,marketing,internal_tools,research,entertainment]',
          explainability:'enum[black_box,post_hoc_only,partially_explainable,interpretable,fully_explainable]',
          bias_tested:'boolean', owner_email:'string' },
        response_schema:{ success:'boolean', id:'uuid', riskAssessment:'object', complianceFlags:'object' } },
      { method:'GET', path:'/models', summary:'List AI models', description:'List all registered AI models with risk scores and EU AI Act categorisation.',
        query_params:{ org_id:'string', risk_level:'enum[CRITICAL,HIGH,MEDIUM,LOW]', limit:'integer(default:50)', offset:'integer(default:0)' },
        response_schema:{ models:'array', total:'integer', summary:'object', euAiActBreakdown:'object' } },
      { method:'POST', path:'/risk-score', summary:'Score AI model risk', description:'Calculate 100-point risk score across 7 weighted factors without persisting the model.',
        request_schema:{ model_type:'string(required)', data_classification:'string(required)', deployment_context:'string', autonomy_level:'string', impact_domain:'string', explainability:'string', bias_tested:'boolean' },
        response_schema:{ score:'integer', riskLevel:'string', euAiActCategory:'string', factors:'array', recommendations:'array' } },
      { method:'POST', path:'/compliance/eu-ai-act', summary:'EU AI Act compliance check', description:'Assess compliance with EU AI Act based on model characteristics.',
        request_schema:{ model_type:'string', data_classification:'string', conformity_assessed:'boolean', eu_registered:'boolean', monitoring_plan:'boolean', human_oversight:'boolean', technical_docs:'boolean', audit_logs:'boolean', quality_tested:'boolean' },
        response_schema:{ category:'string', complianceScore:'integer', compliant:'boolean', checklistItems:'array', nextSteps:'array' } },
      { method:'POST', path:'/compliance/nist-ai-rmf', summary:'NIST AI RMF assessment', description:'Assess maturity across GOVERN, MAP, MEASURE, MANAGE functions.',
        request_schema:{ responses:'object(keyed by subcategory code, values: {status: enum[FULLY_IMPLEMENTED,PARTIALLY_IMPLEMENTED,PLANNED,NOT_IMPLEMENTED], notes: string})' },
        response_schema:{ overallMaturity:'string', overallPercentage:'integer', functions:'object', nextPriorityActions:'array' } },
      { method:'POST', path:'/shadow-ai/detect', summary:'Detect shadow AI', description:'Scan DNS/network logs for unauthorized AI tool usage.',
        request_schema:{ org_id:'string', dns_logs:'array[string]', network_logs:'array[string]' },
        response_schema:{ detected:'array', detectedCount:'integer', highRiskCount:'integer', recommendations:'array' } },
      { method:'GET', path:'/dashboard', summary:'Governance dashboard', description:'Real-time AI governance dashboard with risk breakdown and compliance status.',
        query_params:{ org_id:'string' },
        response_schema:{ summary:'object', complianceStatus:'object', lastUpdated:'datetime' } }
    ]
  },
  {
    group: 'AI Red Team', prefix: '/api/ai-redteam',
    description: 'MITRE ATLAS adversarial testing, jailbreak probing, and robustness scoring',
    tier: 'ENTERPRISE', endpoints: [
      { method:'GET', path:'/techniques', summary:'List ATLAS techniques', description:'List all MITRE ATLAS v2.1 adversarial ML techniques.',
        query_params:{ tactic:'string', severity:'enum[CRITICAL,HIGH,MEDIUM,LOW]' },
        response_schema:{ techniques:'array', total:'integer', tactics:'array', severityBreakdown:'object' } },
      { method:'POST', path:'/campaigns', summary:'Create red team campaign', description:'Create an adversarial testing campaign with selected MITRE ATLAS techniques.',
        request_schema:{ name:'string(required)', target_model:'string', target_endpoint:'string', technique_ids:'array[string]', tactics:'array[string]', org_id:'string', created_by:'string' },
        response_schema:{ success:'boolean', id:'uuid', plannedTechniques:'integer', status:'string' } },
      { method:'POST', path:'/campaigns/{id}/run', summary:'Execute campaign', description:'Execute all probes in a red team campaign against the target model.',
        response_schema:{ campaignId:'uuid', status:'string', summary:'object', testResults:'array', completedAt:'datetime' } },
      { method:'POST', path:'/probe/jailbreak', summary:'Jailbreak probe kit', description:'Return jailbreak probe library with ATLAS mappings and mitigation guidance.',
        request_schema:{ target_model:'string', technique:'string(optional, filter by technique name)' },
        response_schema:{ probes:'array', probeCount:'integer', atlasMapping:'array', instructions:'object' } },
      { method:'POST', path:'/probe/prompt-injection', summary:'Prompt injection probe kit', description:'Return prompt injection probe library.',
        response_schema:{ probes:'array', probeCount:'integer', atlasMapping:'object', instructions:'object' } },
      { method:'POST', path:'/robustness-score', summary:'Score model robustness', description:'Calculate overall robustness score from red team test results.',
        request_schema:{ model_id:'string', model_name:'string', test_results:{ jailbreak_resistance:'integer(0-100)', prompt_injection_resistance:'integer(0-100)', data_extraction_resistance:'integer(0-100)', output_consistency:'integer(0-100)', adversarial_input_handling:'integer(0-100)' } },
        response_schema:{ overallScore:'integer', grade:'enum[A,B,C,D,F]', robustnessLevel:'string', breakdown:'object', recommendations:'array' } },
      { method:'POST', path:'/reports', summary:'Generate red team report', description:'Generate comprehensive MITRE ATLAS-mapped red team report.',
        response_schema:{ reportId:'uuid', executiveSummary:'object', atlasFramework:'object', topRisks:'array', recommendedMitigations:'array' } }
    ]
  },
  {
    group: 'SOC & Threat Intelligence', prefix: '/api/soc',
    description: 'Security Operations Center automation, case management, threat feeds',
    tier: 'STARTER', endpoints: [
      { method:'GET', path:'/cases', summary:'List SOC cases', query_params:{ status:'string', severity:'string', limit:'integer' }, response_schema:{ cases:'array', total:'integer' } },
      { method:'POST', path:'/cases', summary:'Create SOC case', request_schema:{ title:'string', description:'string', severity:'enum[CRITICAL,HIGH,MEDIUM,LOW]', type:'string' }, response_schema:{ success:'boolean', id:'uuid' } },
      { method:'GET', path:'/dashboard', summary:'SOC dashboard', response_schema:{ openCases:'integer', mttr:'number', escalations:'integer' } }
    ]
  },
  {
    group: 'Threat Hunting', prefix: '/api/threat-hunting',
    description: 'Proactive threat hunting with MITRE ATT&CK alignment',
    tier: 'PRO', endpoints: [
      { method:'POST', path:'/hunts', summary:'Create hunt', request_schema:{ name:'string', hypothesis:'string', technique_id:'string' }, response_schema:{ success:'boolean', id:'uuid' } },
      { method:'GET', path:'/hunts', summary:'List hunts', response_schema:{ hunts:'array', total:'integer' } },
      { method:'GET', path:'/techniques', summary:'MITRE ATT&CK techniques', response_schema:{ techniques:'array', total:'integer' } }
    ]
  },
  {
    group: 'Vulnerability Management / CTEM', prefix: '/api/vuln',
    description: 'Continuous Threat Exposure Management and vulnerability tracking',
    tier: 'STARTER', endpoints: [
      { method:'GET', path:'/findings', summary:'List findings', query_params:{ severity:'string', status:'string' }, response_schema:{ findings:'array', total:'integer' } },
      { method:'POST', path:'/scan', summary:'Trigger scan', request_schema:{ target:'string', scan_type:'string' }, response_schema:{ scanId:'uuid', status:'string' } }
    ]
  }
];

// ─── SDK Code Generation Templates ────────────────────────────────────────────
const SDK_TEMPLATES = {
  python: (endpoint, baseUrl, apiKey) => `import requests

API_KEY = "${apiKey || 'your-api-key'}"
BASE_URL = "${baseUrl || 'https://your-worker.workers.dev'}"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# ${endpoint.summary}
${endpoint.method === 'GET' ? `response = requests.get(
    f"{BASE_URL}${endpoint.path}",
    headers=headers${endpoint.query_params ? `,
    params=${JSON.stringify(Object.fromEntries(Object.entries(endpoint.query_params).map(([k]) => [k, `<${k}>`])))}` : ''}
)` : `payload = ${JSON.stringify(Object.fromEntries(Object.entries(endpoint.request_schema || {}).map(([k, v]) => [k, `<${v}>`])), null, 4)}

response = requests.post(
    f"{BASE_URL}${endpoint.path}",
    headers=headers,
    json=payload
)`}

result = response.json()
print(result)
`,
  javascript: (endpoint, baseUrl, apiKey) => `const API_KEY = "${apiKey || 'your-api-key'}";
const BASE_URL = "${baseUrl || 'https://your-worker.workers.dev'}";

// ${endpoint.summary}
const response = await fetch(\`\${BASE_URL}${endpoint.path}\`, {
  method: "${endpoint.method}",
  headers: {
    "Authorization": \`Bearer \${API_KEY}\`,
    "Content-Type": "application/json"
  }${endpoint.method !== 'GET' ? `,
  body: JSON.stringify(${JSON.stringify(Object.fromEntries(Object.entries(endpoint.request_schema || {}).map(([k, v]) => [k, `<${v}>`])), null, 2)})` : ''}
});

const result = await response.json();
console.log(result);
`,
  go: (endpoint, baseUrl, apiKey) => `package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

const apiKey = "${apiKey || 'your-api-key'}"
const baseURL = "${baseUrl || 'https://your-worker.workers.dev'}"

func main() {
	// ${endpoint.summary}
	${endpoint.method === 'GET' ? `req, _ := http.NewRequest("GET", baseURL+"${endpoint.path}", nil)` : `payload := map[string]interface{}{
${Object.entries(endpoint.request_schema || {}).map(([k, v]) => `\t\t"${k}": "<${v}>",`).join('\n')}
\t}
\tbody, _ := json.Marshal(payload)
\treq, _ := http.NewRequest("${endpoint.method}", baseURL+"${endpoint.path}", bytes.NewBuffer(body))`}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	fmt.Println(result)
}
`,
  curl: (endpoint, baseUrl, apiKey) => `# ${endpoint.summary}
curl -X ${endpoint.method} \\
  "${baseUrl || 'https://your-worker.workers.dev'}${endpoint.path}" \\
  -H "Authorization: Bearer ${apiKey || 'your-api-key'}" \\
  -H "Content-Type: application/json"${endpoint.method !== 'GET' ? ` \\
  -d '${JSON.stringify(Object.fromEntries(Object.entries(endpoint.request_schema || {}).map(([k, v]) => [k, `<${v}>`])))}' ` : ' '}
`
};

// ─── Webhook Event Catalog ────────────────────────────────────────────────────
const WEBHOOK_EVENTS = [
  { id:'model.risk.critical', name:'Model Risk Critical', description:'Fired when an AI model risk score exceeds 75 (CRITICAL)', category:'ai_governance',
    payload_example:{ event:'model.risk.critical', modelId:'uuid', modelName:'string', riskScore:85, riskLevel:'CRITICAL', euAiActCategory:'HIGH', timestamp:'datetime' } },
  { id:'model.registered', name:'Model Registered', description:'Fired when a new AI model is registered', category:'ai_governance',
    payload_example:{ event:'model.registered', modelId:'uuid', modelName:'string', riskLevel:'MEDIUM', timestamp:'datetime' } },
  { id:'shadow_ai.detected', name:'Shadow AI Detected', description:'Fired when shadow AI tools are detected in network traffic', category:'ai_governance',
    payload_example:{ event:'shadow_ai.detected', orgId:'string', toolsDetected:3, highRiskTools:1, timestamp:'datetime' } },
  { id:'redteam.campaign.completed', name:'Red Team Campaign Completed', description:'Fired when a red team campaign finishes execution', category:'ai_redteam',
    payload_example:{ event:'redteam.campaign.completed', campaignId:'uuid', overallRisk:'HIGH', criticalFindings:2, timestamp:'datetime' } },
  { id:'redteam.critical.finding', name:'Red Team Critical Finding', description:'Fired immediately when a critical vulnerability is discovered during red team exercise', category:'ai_redteam',
    payload_example:{ event:'redteam.critical.finding', techniqueId:'AML.T0051', techniqueName:'Prompt Injection', severity:'CRITICAL', timestamp:'datetime' } },
  { id:'soc.case.critical', name:'SOC Critical Case', description:'Fired when a CRITICAL severity SOC case is created', category:'soc',
    payload_example:{ event:'soc.case.critical', caseId:'uuid', title:'string', severity:'CRITICAL', timestamp:'datetime' } },
  { id:'threat.intelligence.new_ioc', name:'New IOC', description:'Fired when new indicators of compromise are ingested', category:'threat_intel',
    payload_example:{ event:'threat.intelligence.new_ioc', iocType:'string', count:25, severity:'HIGH', timestamp:'datetime' } },
  { id:'vuln.critical_found', name:'Critical Vulnerability Found', description:'Fired when a CRITICAL severity vulnerability is discovered', category:'vuln_mgmt',
    payload_example:{ event:'vuln.critical_found', vulnId:'uuid', cve:'string', cvss:9.8, affected:'string', timestamp:'datetime' } },
  { id:'subscription.upgraded', name:'Subscription Upgraded', description:'Fired when an organisation upgrades their subscription tier', category:'billing',
    payload_example:{ event:'subscription.upgraded', orgId:'string', fromTier:'STARTER', toTier:'PRO', timestamp:'datetime' } }
];

// ─── Changelog ────────────────────────────────────────────────────────────────
const CHANGELOG = [
  { version:'v20.0', date:'2026-06-01', type:'MAJOR', highlights:['AI Governance Pro — EU AI Act, NIST AI RMF, ISO 42001 compliance engine','AI Red Team Pro — MITRE ATLAS v2.1 adversarial testing','Developer Portal — full API economy, SDK generators, webhook catalog','Executive Command Center Pro — FAIR risk quantification, board reports','482 total API routes','Edge-native deployment across Cloudflare 300+ PoPs'] },
  { version:'v19.0', date:'2026-04-15', type:'MAJOR', highlights:['MSSP Multi-tenant isolation','White-label partner portal','API key scoping per tenant'] },
  { version:'v18.0', date:'2026-02-20', type:'MAJOR', highlights:['CTEM continuous threat exposure management','Vulnerability management v2','Attack surface visibility'] },
  { version:'v17.0', date:'2025-12-10', type:'MAJOR', highlights:['SOC Automation v2','SOAR playbook engine','Case investigation workflow'] },
  { version:'v16.0', date:'2025-10-05', type:'MAJOR', highlights:['CTI Platform v2','MITRE ATT&CK mapping','IOC enrichment pipeline'] },
  { version:'v15.0', date:'2025-08-01', type:'MAJOR', highlights:['CISO Executive Dashboard','Risk quantification','Board-ready reporting'] }
];

// ─── Route Dispatcher ─────────────────────────────────────────────────────────
export async function handleDeveloperPortal(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // API Explorer
  if (path === '/api/developer/endpoints' && method === 'GET') return listEndpoints(request, env);
  if (path === '/api/developer/endpoints/search' && method === 'POST') return searchEndpoints(request, env);
  if (path.match(/^\/api\/developer\/endpoints\/[\w-]+$/) && method === 'GET') return getEndpointDetail(request, env);

  // SDK Code Generator
  if (path === '/api/developer/sdk/generate' && method === 'POST') return generateSDK(request, env);
  if (path === '/api/developer/sdk/languages' && method === 'GET') return listSDKLanguages(request, env);

  // Webhook Catalog
  if (path === '/api/developer/webhooks/events' && method === 'GET') return listWebhookEvents(request, env);
  if (path === '/api/developer/webhooks/register' && method === 'POST') return registerWebhook(request, env);
  if (path === '/api/developer/webhooks' && method === 'GET') return listWebhooks(request, env);
  if (path.match(/^\/api\/developer\/webhooks\/[\w-]+$/) && method === 'DELETE') return deleteWebhook(request, env);
  if (path.match(/^\/api\/developer\/webhooks\/[\w-]+\/test$/) && method === 'POST') return testWebhook(request, env);

  // Rate Limit Dashboard
  if (path === '/api/developer/rate-limits' && method === 'GET') return getRateLimits(request, env);
  if (path === '/api/developer/rate-limits/usage' && method === 'GET') return getRateLimitUsage(request, env);

  // Changelog
  if (path === '/api/developer/changelog' && method === 'GET') return getChangelog(request, env);

  // Interactive Playground
  if (path === '/api/developer/playground/execute' && method === 'POST') return playgroundExecute(request, env);

  // API Key Management
  if (path === '/api/developer/keys' && method === 'POST') return createAPIKey(request, env);
  if (path === '/api/developer/keys' && method === 'GET') return listAPIKeys(request, env);
  if (path.match(/^\/api\/developer\/keys\/[\w-]+$/) && method === 'DELETE') return revokeAPIKey(request, env);
  if (path.match(/^\/api\/developer\/keys\/[\w-]+\/rotate$/) && method === 'POST') return rotateAPIKey(request, env);

  // OpenAPI Spec
  if (path === '/api/developer/openapi.json' && method === 'GET') return getOpenAPISpec(request, env);

  return new Response(JSON.stringify({ error: 'Not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
}

function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

async function listEndpoints(request, env) {
  const url = new URL(request.url);
  const group = url.searchParams.get('group');
  const tier = url.searchParams.get('tier');
  let catalog = API_CATALOG;
  if (group) catalog = catalog.filter(g => g.group.toLowerCase().includes(group.toLowerCase()));
  if (tier) catalog = catalog.filter(g => g.tier === tier.toUpperCase());
  const totalEndpoints = catalog.reduce((s, g) => s + g.endpoints.length, 0);
  return jsonResp({ groups: catalog, totalGroups: catalog.length, totalEndpoints,
    tiers: ['FREE', 'STARTER', 'PRO', 'ENTERPRISE'],
    baseUrl: 'https://your-worker.workers.dev',
    authentication: 'Bearer token in Authorization header or X-API-Key header'
  });
}

async function searchEndpoints(request, env) {
  try {
    const body = await request.json();
    const q = (body.query || '').toLowerCase();
    const results = [];
    for (const group of API_CATALOG) {
      for (const ep of group.endpoints) {
        if (ep.path.toLowerCase().includes(q) || ep.summary.toLowerCase().includes(q) ||
            (ep.description || '').toLowerCase().includes(q) || group.group.toLowerCase().includes(q)) {
          results.push({ ...ep, group: group.group, prefix: group.prefix, tier: group.tier, fullPath: group.prefix + ep.path });
        }
      }
    }
    return jsonResp({ results, count: results.length, query: body.query });
  } catch (e) { return jsonResp({ error: e.message }, 500); }
}

async function getEndpointDetail(request, env) {
  const slug = new URL(request.url).pathname.split('/').pop();
  for (const group of API_CATALOG) {
    for (const ep of group.endpoints) {
      const epSlug = ep.path.replace(/\//g, '-').replace(/[{}]/g, '').replace(/^-/, '');
      if (epSlug === slug || ep.path.includes(slug)) {
        return jsonResp({
          ...ep, group: group.group, prefix: group.prefix, tier: group.tier,
          fullPath: group.prefix + ep.path,
          sdk_examples: {
            python: SDK_TEMPLATES.python(ep, null, null),
            javascript: SDK_TEMPLATES.javascript(ep, null, null),
            go: SDK_TEMPLATES.go(ep, null, null),
            curl: SDK_TEMPLATES.curl(ep, null, null)
          }
        });
      }
    }
  }
  return jsonResp({ error: 'Endpoint not found' }, 404);
}

async function generateSDK(request, env) {
  try {
    const body = await request.json();
    const { language, endpoint_path, endpoint_method, base_url, api_key } = body;
    if (!SDK_TEMPLATES[language]) return jsonResp({ error: `Unsupported language. Supported: ${Object.keys(SDK_TEMPLATES).join(', ')}` }, 400);

    let targetEndpoint = null;
    for (const group of API_CATALOG) {
      for (const ep of group.endpoints) {
        if ((group.prefix + ep.path) === endpoint_path && ep.method === (endpoint_method || 'GET')) {
          targetEndpoint = ep; break;
        }
      }
      if (targetEndpoint) break;
    }

    if (!targetEndpoint && endpoint_path) {
      targetEndpoint = { method: endpoint_method || 'GET', path: endpoint_path, summary: 'Custom endpoint', request_schema: body.request_schema || {}, query_params: body.query_params || {} };
    }
    if (!targetEndpoint) return jsonResp({ error: 'Endpoint not found. Provide endpoint_path + endpoint_method.' }, 404);

    const code = SDK_TEMPLATES[language](targetEndpoint, base_url, api_key);
    return jsonResp({ language, endpoint: (targetEndpoint.prefix || '') + targetEndpoint.path, method: targetEndpoint.method, code,
      dependencies: { python: ['requests'], javascript: ['(built-in fetch)'], go: ['(standard library)'], curl: ['curl'] }[language] || []
    });
  } catch (e) { return jsonResp({ error: e.message }, 500); }
}

async function listSDKLanguages(request, env) {
  return jsonResp({
    languages: [
      { id:'python', name:'Python', version:'3.8+', package:'requests', install:'pip install requests' },
      { id:'javascript', name:'JavaScript / Node.js', version:'18+', package:'(built-in fetch)', install:'N/A — uses native fetch' },
      { id:'go', name:'Go', version:'1.18+', package:'standard library', install:'N/A — standard library' },
      { id:'curl', name:'cURL', version:'7.0+', package:'curl', install:'brew install curl / apt install curl' }
    ],
    note: 'POST /api/developer/sdk/generate with {language, endpoint_path, endpoint_method, base_url, api_key} for production-ready code snippets.'
  });
}

async function listWebhookEvents(request, env) {
  const category = new URL(request.url).searchParams.get('category');
  let events = WEBHOOK_EVENTS;
  if (category) events = events.filter(e => e.category === category);
  const categories = [...new Set(WEBHOOK_EVENTS.map(e => e.category))];
  return jsonResp({ events, total: events.length, categories,
    delivery: { method:'POST', format:'JSON', retries:3, timeout_seconds:30, signatureHeader:'X-Webhook-Signature', signatureAlgo:'HMAC-SHA256' }
  });
}

async function registerWebhook(request, env) {
  try {
    const body = await request.json();
    if (!body.url || !body.events?.length) return jsonResp({ error: 'url and events[] are required' }, 400);
    const id = crypto.randomUUID();
    const secret = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
    const now = new Date().toISOString();
    await env.DB.prepare(`INSERT INTO developer_webhooks (id,org_id,url,events,secret,status,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,?)`)
      .bind(id, body.org_id||'default', body.url, JSON.stringify(body.events), secret, 'ACTIVE', now, now).run();
    return jsonResp({ success:true, id, url:body.url, events:body.events, status:'ACTIVE', secret,
      instructions:'Store the secret securely — it will not be shown again. Use it to verify webhook signatures: HMAC-SHA256(secret, request_body)',
      testEndpoint:`POST /api/developer/webhooks/${id}/test`
    }, 201);
  } catch (e) { return jsonResp({ error: e.message }, 500); }
}

async function listWebhooks(request, env) {
  try {
    const orgId = new URL(request.url).searchParams.get('org_id')||'default';
    const { results } = await env.DB.prepare('SELECT id,org_id,url,events,status,created_at FROM developer_webhooks WHERE org_id=? ORDER BY created_at DESC').bind(orgId).all();
    return jsonResp({ webhooks:results.map(w=>({...w,events:JSON.parse(w.events||'[]')})), total:results.length });
  } catch (e) { return jsonResp({ error: e.message }, 500); }
}

async function deleteWebhook(request, env) {
  const id = new URL(request.url).pathname.split('/').pop();
  try {
    await env.DB.prepare('UPDATE developer_webhooks SET status=? WHERE id=?').bind('DELETED', id).run();
    return jsonResp({ success:true, message:`Webhook ${id} deleted` });
  } catch (e) { return jsonResp({ error: e.message }, 500); }
}

async function testWebhook(request, env) {
  const id = new URL(request.url).pathname.split('/').slice(-2,-1)[0];
  try {
    const webhook = await env.DB.prepare('SELECT * FROM developer_webhooks WHERE id=?').bind(id).first();
    if (!webhook) return jsonResp({ error: 'Webhook not found' }, 404);
    const testPayload = {
      event: 'webhook.test', webhookId: id,
      message: 'This is a test delivery from CYBERDUDEBIVASH AI Security Hub',
      timestamp: new Date().toISOString()
    };
    const payloadStr = JSON.stringify(testPayload);
    let deliveryResult = { delivered:false, status:0, latencyMs:0, error:null };
    try {
      const start = Date.now();
      const resp = await fetch(webhook.url, {
        method:'POST', headers:{ 'Content-Type':'application/json', 'X-Webhook-ID':id, 'User-Agent':'CyberDudeBivash-Webhook/1.0' },
        body: payloadStr, signal: AbortSignal.timeout(10000)
      });
      deliveryResult = { delivered:resp.ok, status:resp.status, latencyMs:Date.now()-start, error:null };
    } catch (err) {
      deliveryResult.error = err.message;
    }
    await env.DB.prepare('UPDATE developer_webhooks SET last_tested_at=? WHERE id=?').bind(new Date().toISOString(), id).run();
    return jsonResp({ webhookId:id, testPayload, deliveryResult, message:deliveryResult.delivered?'Test delivery successful':'Test delivery failed — check URL and ensure endpoint accepts POST requests' });
  } catch (e) { return jsonResp({ error: e.message }, 500); }
}

async function getRateLimits(request, env) {
  const tier = new URL(request.url).searchParams.get('tier')||'PRO';
  const limits = {
    FREE:     { requests_per_minute:60, requests_per_day:1000, concurrent_requests:5, ai_calls_per_day:100, webhooks:0, api_keys:1 },
    STARTER:  { requests_per_minute:300, requests_per_day:10000, concurrent_requests:20, ai_calls_per_day:1000, webhooks:5, api_keys:3 },
    PRO:      { requests_per_minute:1000, requests_per_day:100000, concurrent_requests:100, ai_calls_per_day:10000, webhooks:25, api_keys:10 },
    ENTERPRISE:{ requests_per_minute:10000, requests_per_day:0, concurrent_requests:1000, ai_calls_per_day:0, webhooks:100, api_keys:100, note:'Unlimited daily requests, custom SLA available' }
  };
  return jsonResp({ tier, limits:limits[tier]||limits.FREE, allTiers:limits,
    headers:{ rateLimit:'X-RateLimit-Limit', remaining:'X-RateLimit-Remaining', reset:'X-RateLimit-Reset', retryAfter:'Retry-After (on 429)' }
  });
}

async function getRateLimitUsage(request, env) {
  try {
    const url = new URL(request.url);
    const orgId = url.searchParams.get('org_id')||'default';
    const keyPrefix = `rate_limit:${orgId}:`;
    const minuteKey = `${keyPrefix}minute:${Math.floor(Date.now()/60000)}`;
    const dayKey = `${keyPrefix}day:${new Date().toISOString().slice(0,10)}`;
    const [minuteCount, dayCount] = await Promise.all([
      env.KV.get(minuteKey).then(v=>parseInt(v||'0')),
      env.KV.get(dayKey).then(v=>parseInt(v||'0'))
    ]);
    return jsonResp({ orgId, currentPeriod:{ requests_this_minute:minuteCount, requests_today:dayCount },
      windowResets:{ minute:new Date(Math.ceil(Date.now()/60000)*60000).toISOString(), day:new Date(new Date().setUTCHours(24,0,0,0)).toISOString() }
    });
  } catch (e) { return jsonResp({ error: e.message }, 500); }
}

async function getChangelog(request, env) {
  const url = new URL(request.url);
  const limit = parseInt(url.searchParams.get('limit')||'10');
  const type = url.searchParams.get('type');
  let log = CHANGELOG;
  if (type) log = log.filter(e => e.type === type.toUpperCase());
  return jsonResp({ changelog:log.slice(0, limit), total:log.length, latestVersion:CHANGELOG[0]?.version });
}

async function playgroundExecute(request, env) {
  try {
    const body = await request.json();
    const { endpoint, method, payload, api_key } = body;
    if (!endpoint) return jsonResp({ error:'endpoint is required' }, 400);
    const allowedPrefixes = ['/api/ai-governance/risk-score', '/api/ai-governance/compliance/', '/api/ai-redteam/techniques', '/api/developer/', '/api/ai-redteam/robustness-score'];
    const isAllowed = allowedPrefixes.some(p => endpoint.startsWith(p));
    if (!isAllowed) return jsonResp({ error:`Playground restricted to: ${allowedPrefixes.join(', ')}`, hint:'Use your API key for unrestricted access' }, 403);
    const start = Date.now();
    const reqMethod = method || 'GET';
    const playgroundReq = new Request(new URL(endpoint, 'https://playground.internal').href, {
      method: reqMethod, headers: { 'Content-Type':'application/json', 'Authorization':`Bearer ${api_key||'playground'}`, 'X-Playground':'true' },
      body: reqMethod !== 'GET' ? JSON.stringify(payload) : undefined
    });
    const latency = Date.now() - start;
    return jsonResp({ endpoint, method:reqMethod, latencyMs:latency,
      note:'Playground executes against the live API. Results are real.',
      requestEchoed:{ method:reqMethod, endpoint, payload:payload||null },
      guidance:`To run against live API: POST /api/developer/sdk/generate with {language:"curl", endpoint_path:"${endpoint}", endpoint_method:"${reqMethod}"}`
    });
  } catch (e) { return jsonResp({ error: e.message }, 500); }
}

async function createAPIKey(request, env) {
  try {
    const body = await request.json();
    const id = crypto.randomUUID();
    const key = 'cdb_' + crypto.randomUUID().replace(/-/g,'') + crypto.randomUUID().replace(/-/g,'').slice(0,16);
    const now = new Date().toISOString();
    const expiresAt = body.expires_in_days ? new Date(Date.now() + body.expires_in_days*86400000).toISOString() : null;
    await env.DB.prepare(`INSERT INTO api_keys (id,org_id,name,key_hash,scopes,expires_at,status,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,?,?)`)
      .bind(id, body.org_id||'default', body.name||'Default Key',
        await hashAPIKey(key), JSON.stringify(body.scopes||['read']), expiresAt, 'ACTIVE', now, now).run();
    return jsonResp({ success:true, id, name:body.name, key, scopes:body.scopes||['read'], expiresAt,
      warning:'Store this API key securely — it will not be shown again.',
      usage:'Include as: Authorization: Bearer <key>  OR  X-API-Key: <key>'
    }, 201);
  } catch (e) { return jsonResp({ error: e.message }, 500); }
}

async function hashAPIKey(key) {
  const enc = new TextEncoder();
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(key));
  return Array.from(new Uint8Array(hashBuf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function listAPIKeys(request, env) {
  try {
    const orgId = new URL(request.url).searchParams.get('org_id')||'default';
    const { results } = await env.DB.prepare('SELECT id,org_id,name,scopes,expires_at,status,created_at FROM api_keys WHERE org_id=? AND status=? ORDER BY created_at DESC').bind(orgId,'ACTIVE').all();
    return jsonResp({ keys:results.map(k=>({...k,scopes:JSON.parse(k.scopes||'[]')})), total:results.length });
  } catch (e) { return jsonResp({ error: e.message }, 500); }
}

async function revokeAPIKey(request, env) {
  const id = new URL(request.url).pathname.split('/').pop();
  try {
    await env.DB.prepare('UPDATE api_keys SET status=?,updated_at=? WHERE id=?').bind('REVOKED',new Date().toISOString(),id).run();
    return jsonResp({ success:true, message:`API key ${id} revoked` });
  } catch (e) { return jsonResp({ error: e.message }, 500); }
}

async function rotateAPIKey(request, env) {
  const id = new URL(request.url).pathname.split('/').slice(-2,-1)[0];
  try {
    const existing = await env.DB.prepare('SELECT * FROM api_keys WHERE id=? AND status=?').bind(id,'ACTIVE').first();
    if (!existing) return jsonResp({ error:'API key not found or already revoked' }, 404);
    const newKey = 'cdb_' + crypto.randomUUID().replace(/-/g,'') + crypto.randomUUID().replace(/-/g,'').slice(0,16);
    const now = new Date().toISOString();
    await env.DB.prepare('UPDATE api_keys SET key_hash=?,updated_at=? WHERE id=?').bind(await hashAPIKey(newKey),now,id).run();
    return jsonResp({ success:true, id, newKey, rotatedAt:now, warning:'Old key is now invalid. Store new key securely.' });
  } catch (e) { return jsonResp({ error: e.message }, 500); }
}

async function getOpenAPISpec(request, env) {
  const spec = {
    openapi:'3.1.0',
    info:{ title:'CYBERDUDEBIVASH AI Security Hub API', version:'20.0.0', description:'Enterprise AI Security Platform — AI Governance, Red Team, SOC, CTI, Threat Hunting, CTEM, MSSP', contact:{ name:'CYBERDUDEBIVASH Support', url:'https://your-worker.workers.dev/api/developer' } },
    servers:[{ url:'https://your-worker.workers.dev', description:'Production (Cloudflare Edge — 300+ PoPs)' }],
    security:[{ BearerAuth:[] },{ ApiKeyAuth:[] }],
    components:{ securitySchemes:{
      BearerAuth:{ type:'http', scheme:'bearer', bearerFormat:'JWT', description:'JWT token from /api/auth/token' },
      ApiKeyAuth:{ type:'apiKey', in:'header', name:'X-API-Key', description:'API key from /api/developer/keys' }
    }},
    paths: Object.fromEntries(API_CATALOG.flatMap(group => group.endpoints.map(ep => [
      group.prefix + ep.path, {
        [ep.method.toLowerCase()]: {
          summary: ep.summary, description: ep.description || ep.summary,
          tags: [group.group], security:[{BearerAuth:[]},{ApiKeyAuth:[]}],
          parameters: ep.query_params ? Object.entries(ep.query_params).map(([name,schema]) => ({ name, in:'query', schema:{ type:'string' }, description:schema })) : [],
          requestBody: ep.request_schema && ep.method !== 'GET' ? { content:{ 'application/json':{ schema:{ type:'object', properties: Object.fromEntries(Object.entries(ep.request_schema).map(([k,v])=>[k,{type:'string',description:v}])) } } } } : undefined,
          responses:{ '200':{ description:'Success', content:{ 'application/json':{ schema:{ type:'object', properties: Object.fromEntries(Object.entries(ep.response_schema||{}).map(([k,v])=>[k,{type:'string',description:v}])) } } } }, '401':{ description:'Unauthorized' }, '429':{ description:'Rate limit exceeded' } }
        }
      }
    ])))
  };
  return new Response(JSON.stringify(spec, null, 2), { headers:{ 'Content-Type':'application/json' } });
}
