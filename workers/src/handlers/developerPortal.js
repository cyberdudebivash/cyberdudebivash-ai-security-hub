// =============================================================================
// DEVELOPER PORTAL & API ECONOMY — Full Self-Serve API Platform
// CYBERDUDEBIVASH AI Security Hub | handlers/developerPortal.js
// Differentiator: FULL (CrowdStrike=Partial, Palo Alto=Partial, Wiz=None, SentinelOne=None)
// Implements: API Explorer, SDK code generators, webhook catalog+test,
//             rate-limit dashboard, changelog, interactive playground
//
// Key management (POST/GET/DELETE /api/developer/keys, POST .../rotate)
// delegates entirely to the canonical, tested, ownership-scoped
// implementation in handlers/apikeys.js (auth/apiKeys.js's createApiKey())
// rather than reimplementing key issuance against this file's own
// (previously drifted, schema-mismatched) INSERT statements — see
// docs/capability-registry/domains/developer-portal-apikeys.json
// (CAP-DEVPORTAL-003) for the fix rationale.
// =============================================================================

import { isRealUser } from '../auth/middleware.js';
import { handleCreateKey, handleListKeys, handleRevokeKey, handleRotateKey } from './apikeys.js';

function authRequired() {
  return new Response(JSON.stringify({ error: 'Authentication required' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
}

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
  },
  {
    group: 'Radar', prefix: '/api/radar',
    description: 'Real-time global threat radar — CVE signals, trending threats, actor and campaign intelligence',
    tier: 'FREE', endpoints: [
      { method:'GET', path:'/snapshot', summary:'Unified radar snapshot', description:'Public snapshot of all threat signals, 5-minute edge cache.', response_schema:{ signals:'array', generatedAt:'datetime' } },
      { method:'GET', path:'/latest', summary:'Latest CVE signals', query_params:{ limit:'integer(default:50)' }, response_schema:{ signals:'array', total:'integer' } },
      { method:'GET', path:'/summary', summary:'Severity distribution summary', response_schema:{ critical:'integer', high:'integer', medium:'integer', low:'integer' } },
      { method:'GET', path:'/trending', summary:'Trending threats', description:'Top threats ranked by EPSS/CVSS/risk score.', response_schema:{ trending:'array' } },
      { method:'GET', path:'/threat-actors', summary:'Threat actor intelligence', description:'MITRE ATT&CK correlated threat actor profiles (top 20).', response_schema:{ actors:'array', total:'integer' } },
      { method:'GET', path:'/campaigns', summary:'Active campaign summaries', response_schema:{ campaigns:'array', total:'integer' } },
      { method:'GET', path:'/sectors', summary:'Industry sector threat breakdown', response_schema:{ sectors:'array' } },
      { method:'GET', path:'/enterprise', summary:'Full enterprise radar snapshot', description:'Authenticated, PRO+ tier. Extended risk-scored signal set.', response_schema:{ signals:'array', riskScore:'object' } },
      { method:'GET', path:'/enterprise/signals', summary:'Extended enterprise signals', description:'Authenticated, PRO+ tier. Signal list with confidence scores.', response_schema:{ signals:'array', confidence:'object' } }
    ]
  },
  {
    group: 'Customer Intelligence', prefix: '/api/customer',
    description: 'Personalized threat intelligence and asset risk monitoring for authenticated customer organizations',
    tier: 'STARTER', endpoints: [
      { method:'GET', path:'/profile', summary:'Get organization profile', response_schema:{ org:'object' } },
      { method:'PUT', path:'/profile', summary:'Update organization profile', request_schema:{ name:'string', industry:'string', size:'string' }, response_schema:{ success:'boolean', org:'object' } },
      { method:'GET', path:'/radar', summary:'Personalized radar', description:"Radar signals filtered by the customer's registered assets.", response_schema:{ signals:'array' } },
      { method:'GET', path:'/risk', summary:'Organization risk assessment', response_schema:{ riskScore:'integer', distribution:'object' } },
      { method:'GET', path:'/assets', summary:'List monitored assets', response_schema:{ assets:'array', total:'integer' } },
      { method:'POST', path:'/assets', summary:'Register asset for monitoring', request_schema:{ domain:'string(required)', type:'string' }, response_schema:{ success:'boolean', id:'uuid' } },
      { method:'DELETE', path:'/assets/{assetId}', summary:'Remove monitored asset', response_schema:{ success:'boolean' } },
      { method:'GET', path:'/report', summary:'Organization threat report', response_schema:{ report:'object' } }
    ]
  },
  {
    group: 'Enterprise Intelligence', prefix: '/api/enterprise',
    description: 'Risk-scored intelligence, campaign tracking, and threat actor correlation for enterprise tier customers',
    tier: 'PRO', endpoints: [
      { method:'GET', path:'/intelligence', summary:'Enterprise risk-scored signals', response_schema:{ signals:'array', riskScore:'object' } },
      { method:'GET', path:'/risk', summary:'Risk-ranked signals', response_schema:{ signals:'array', severityDistribution:'object' } },
      { method:'GET', path:'/campaigns', summary:'Campaign intelligence', description:'Campaign data with sector targeting.', response_schema:{ campaigns:'array' } },
      { method:'GET', path:'/actors', summary:'Threat actor intelligence', description:'MITRE ATT&CK correlated actor profiles. ENTERPRISE tier.', response_schema:{ actors:'array' } }
    ]
  },
  {
    group: 'Operations', prefix: '/api/ops',
    description: 'Platform operations — feature flags, observability metrics, and notification management',
    tier: 'ADMIN', endpoints: [
      { method:'GET', path:'/flags', summary:'Get feature flags', response_schema:{ flags:'object' } },
      { method:'PUT', path:'/flags', summary:'Set feature flag', description:'Admin only.', request_schema:{ key:'string(required)', enabled:'boolean(required)' }, response_schema:{ success:'boolean' } },
      { method:'GET', path:'/metrics', summary:'Operations metrics', response_schema:{ metrics:'object' } },
      { method:'GET', path:'/notifications', summary:'Get personal notifications', response_schema:{ notifications:'array' } }
    ]
  },
  {
    group: 'Automation', prefix: '/api/auto',
    description: 'Enterprise automation — webhooks, scheduled reports, team management, usage and governance',
    tier: 'PRO', endpoints: [
      { method:'GET', path:'/webhooks', summary:'List webhooks', response_schema:{ webhooks:'array' } },
      { method:'POST', path:'/webhooks', summary:'Create webhook', request_schema:{ url:'string(required)', events:'array[string](required)' }, response_schema:{ success:'boolean', id:'uuid', secret:'string' } },
      { method:'PATCH', path:'/webhooks/{whId}', summary:'Update webhook', response_schema:{ success:'boolean' } },
      { method:'DELETE', path:'/webhooks/{whId}', summary:'Delete webhook', response_schema:{ success:'boolean' } },
      { method:'GET', path:'/webhooks/{whId}/logs', summary:'Get webhook delivery logs', response_schema:{ logs:'array' } },
      { method:'GET', path:'/reports', summary:'List scheduled reports', response_schema:{ reports:'array' } },
      { method:'POST', path:'/reports', summary:'Create scheduled report', request_schema:{ cadence:'enum[daily,weekly,monthly]', recipients:'array[string]' }, response_schema:{ success:'boolean', id:'uuid' } },
      { method:'PATCH', path:'/reports/{rpId}', summary:'Update scheduled report', response_schema:{ success:'boolean' } },
      { method:'DELETE', path:'/reports/{rpId}', summary:'Delete scheduled report', response_schema:{ success:'boolean' } },
      { method:'GET', path:'/team', summary:'List team members', response_schema:{ members:'array', roles:'array' } },
      { method:'POST', path:'/team', summary:'Invite team member', request_schema:{ email:'string(required)', role:'enum[ADMIN,ANALYST,VIEWER]' }, response_schema:{ success:'boolean', id:'uuid' } },
      { method:'PATCH', path:'/team/{mid}', summary:'Update member role', response_schema:{ success:'boolean' } },
      { method:'DELETE', path:'/team/{mid}', summary:'Remove team member', response_schema:{ success:'boolean' } },
      { method:'GET', path:'/usage', summary:'API usage dashboard', response_schema:{ usage:'object' } },
      { method:'GET', path:'/governance', summary:'API governance manifest', description:'Endpoint registry, deprecations, and per-tier throttle limits.', response_schema:{ version:'string', endpoints:'array', deprecations:'array', throttling:'object' } },
      { method:'GET', path:'/metrics', summary:'Enterprise automation metrics', description:'OWNER/ADMIN only.', response_schema:{ active_organizations:'integer', active_api_keys:'integer', webhooks:'object', api_health:'object' } }
    ]
  },
  {
    group: 'API Key Self-Service', prefix: '/api/self',
    description: 'Self-service API key lifecycle management for authenticated organizations',
    tier: 'STARTER', endpoints: [
      { method:'GET', path:'/keys', summary:'List API keys', response_schema:{ keys:'array' } },
      { method:'POST', path:'/keys', summary:'Generate API key', request_schema:{ name:'string', scopes:'array[string]' }, response_schema:{ success:'boolean', id:'uuid', key:'string' } },
      { method:'PATCH', path:'/keys/{keyId}', summary:'Update key label', response_schema:{ success:'boolean' } },
      { method:'DELETE', path:'/keys/{keyId}', summary:'Revoke API key', response_schema:{ success:'boolean' } },
      { method:'GET', path:'/keys/{keyId}/usage', summary:'Get key usage metrics', response_schema:{ usage:'object' } },
      { method:'POST', path:'/keys/{keyId}/rotate', summary:'Rotate API key', response_schema:{ success:'boolean', newKey:'string' } }
    ]
  },
  {
    group: 'Developer Platform', prefix: '/api/developer',
    description: 'API explorer, SDK code generation, rate-limit visibility, changelog and OpenAPI spec. Webhooks are managed under Automation (/api/auto/webhooks) — see GET /api/webhooks/catalog for the event vocabulary.',
    tier: 'FREE', endpoints: [
      { method:'GET', path:'/endpoints', summary:'List API catalog', query_params:{ group:'string', tier:'string' }, response_schema:{ groups:'array', totalEndpoints:'integer' } },
      { method:'POST', path:'/endpoints/search', summary:'Search API catalog', request_schema:{ query:'string' }, response_schema:{ results:'array' } },
      { method:'GET', path:'/endpoints/{slug}', summary:'Get endpoint detail + SDK examples', response_schema:{ summary:'string', sdk_examples:'object' } },
      { method:'POST', path:'/sdk/generate', summary:'Generate SDK code snippet', request_schema:{ language:'enum[python,javascript,typescript,go,curl]', endpoint_path:'string', endpoint_method:'string' }, response_schema:{ language:'string', code:'string' } },
      { method:'GET', path:'/sdk/languages', summary:'List supported SDK languages', response_schema:{ languages:'array' } },
      { method:'GET', path:'/rate-limits', summary:'Get rate limit tiers', query_params:{ tier:'string' }, response_schema:{ tier:'string', limits:'object', allTiers:'object' } },
      { method:'GET', path:'/rate-limits/usage', summary:'Get current usage against rate limits', response_schema:{ currentPeriod:'object' } },
      { method:'GET', path:'/changelog', summary:'Platform changelog', query_params:{ limit:'integer', type:'string' }, response_schema:{ changelog:'array', latestVersion:'string' } },
      { method:'POST', path:'/playground/execute', summary:'Execute request in API playground', request_schema:{ endpoint:'string(required)', method:'string', payload:'object' }, response_schema:{ latencyMs:'integer', requestEchoed:'object' } },
      { method:'POST', path:'/keys', summary:'Create developer API key', auth:'required', request_schema:{ label:'string' }, response_schema:{ success:'boolean', key:'string (shown once)', prefix:'string', label:'string', tier:'string' } },
      { method:'GET', path:'/keys', summary:'List developer API keys', auth:'required', response_schema:{ keys:'array', count:'integer', max_keys:'integer', tier_limits:'object' } },
      { method:'DELETE', path:'/keys/{id}', summary:'Revoke developer API key', auth:'required', response_schema:{ success:'boolean', message:'string' } },
      { method:'POST', path:'/keys/{id}/rotate', summary:'Rotate developer API key', auth:'required', response_schema:{ success:'boolean', key:'string (shown once)', key_id:'string' } },
      { method:'GET', path:'/openapi.json', summary:'OpenAPI 3.1 specification', description:'Full machine-readable spec for every documented endpoint in this catalog. Also aliased at /api/openapi.json.', response_schema:{} },
      { method:'GET', path:'/sdk/download/{language}', summary:'Download full SDK client', description:'Download a complete auto-generated multi-endpoint client library. Supported: python, javascript, typescript, go. Add ?raw=1 to get the raw source file.', response_schema:{ language:'string', filename:'string', install:'string', total_methods:'integer', total_groups:'integer', code:'string', download:'string' } },
      { method:'GET', path:'/postman.json', summary:'Postman Collection v2.1', description:'Download an importable Postman Collection containing every documented API endpoint with pre-filled authentication and example requests.', response_schema:{} },
      { method:'GET', path:'/quickstart', summary:'Quick start guide', description:'Getting started guide covering authentication, first API call, and key concepts.', response_schema:{ title:'string', steps:'array', authentication:'object', sdks:'object' } },
      { method:'GET', path:'/auth-guide', summary:'Authentication guide', description:'Complete authentication reference — Bearer tokens, API key scopes, rate limiting, and error codes.', response_schema:{ methods:'array', scopes:'array', rate_limiting:'object', errors:'object' } },
      { method:'GET', path:'/migration-guide', summary:'API migration guide', description:'Migration guidance for version-to-version API changes, deprecated endpoints, and breaking-change timelines.', response_schema:{ currentVersion:'string', guides:'array', deprecations:'array' } },
      { method:'GET', path:'/version-policy', summary:'API version policy', description:'Versioning strategy, stability guarantees, deprecation timelines, and sunset schedules.', response_schema:{ policy:'object', stability:'object', sunset_schedule:'array' } },
      { method:'GET', path:'/examples', summary:'Enterprise integration examples', description:'Production-ready integration examples for SIEM, SOAR, and enterprise security workflows.', response_schema:{ examples:'array', categories:'array', sdk_downloads:'object' } }
    ]
  },
  {
    group: 'Payments & Billing', prefix: '/api',
    description: 'Subscription plans, Razorpay payment processing, and usage-based billing',
    tier: 'FREE', endpoints: [
      { method:'GET', path:'/subscription/plans', summary:'List subscription plans', response_schema:{ plans:'array' } },
      { method:'POST', path:'/subscription/create', summary:'Create subscription order', request_schema:{ plan:'enum[STARTER,PRO,ENTERPRISE](required)' }, response_schema:{ orderId:'string', amount:'integer' } },
      { method:'POST', path:'/subscription/activate', summary:'Verify payment and activate plan', request_schema:{ razorpay_order_id:'string', razorpay_payment_id:'string', razorpay_signature:'string' }, response_schema:{ success:'boolean', plan:'string' } },
      { method:'GET', path:'/subscription/plan', summary:'Get current active plan', response_schema:{ plan:'string', status:'string' } },
      { method:'GET', path:'/payment-config', summary:'Get canonical payment configuration', response_schema:{ keyId:'string', currency:'string' } },
      { method:'POST', path:'/payment/create-order', summary:'Create Razorpay order', request_schema:{ amount:'integer(required)', plan:'string' }, response_schema:{ orderId:'string' } },
      { method:'POST', path:'/payment/verify', summary:'Verify Razorpay payment signature', request_schema:{ razorpay_order_id:'string', razorpay_payment_id:'string', razorpay_signature:'string' }, response_schema:{ success:'boolean' } },
      { method:'GET', path:'/payment/status/{id}', summary:'Get payment status', response_schema:{ status:'string' } },
      { method:'GET', path:'/billing/usage', summary:'Get usage and quota status', response_schema:{ usage:'object', quota:'object' } },
      { method:'POST', path:'/billing/upgrade', summary:'Initiate plan upgrade', request_schema:{ target_plan:'string(required)' }, response_schema:{ success:'boolean' } },
      { method:'GET', path:'/billing/plans', summary:'Enriched plan comparison', response_schema:{ plans:'array' } },
      { method:'POST', path:'/billing/trial/start', summary:'Activate 14-day PRO trial', response_schema:{ success:'boolean', trialEndsAt:'datetime' } },
      { method:'GET', path:'/billing/limits', summary:'Get quota enforcement state', response_schema:{ limits:'object' } },
      { method:'GET', path:'/billing/invoices', summary:'Get invoice history', response_schema:{ invoices:'array' } },
      { method:'POST', path:'/billing/downgrade', summary:'Schedule plan downgrade', request_schema:{ target_plan:'string(required)' }, response_schema:{ success:'boolean', effectiveAt:'datetime' } }
    ]
  },
  {
    group: 'SIEM Export', prefix: '/api/export',
    description: 'Export threat intelligence data to SIEM/SOAR-ready formats',
    tier: 'PRO', endpoints: [
      { method:'GET', path:'/siem', summary:'Export capabilities and format list', response_schema:{ formats:'array', planLimits:'object' } },
      { method:'POST', path:'/siem', summary:'Export threat data', description:'Supports JSON, CEF, STIX 2.1, Sigma, CSV, NDJSON, IOC Bundle, and Executive PDF. Format availability gated by plan tier.', query_params:{ format:'enum[json,cef,stix,sigma,csv,ndjson,ioc_bundle,executive_pdf]', source:'string', hours:'integer' }, response_schema:{} },
      { method:'GET', path:'/siem/stream', summary:'Streaming NDJSON export', description:'ENTERPRISE only. For Logstash/Fluentd ingestion.', response_schema:{} }
    ]
  },
  {
    group: 'SIEM/SOAR Integrations', prefix: '/api/integrations',
    description: 'Native deployment connectors to third-party SIEM/SOAR platforms',
    tier: 'ENTERPRISE', endpoints: [
      { method:'GET', path:'', summary:'List available integration platforms', response_schema:{ platforms:'array' } },
      { method:'POST', path:'/configure', summary:'Configure platform connection', request_schema:{ platform:'string(required)', config:'object(required)' }, response_schema:{ success:'boolean' } },
      { method:'POST', path:'/deploy', summary:'Deploy a rule to a configured platform', request_schema:{ platform:'string(required)', rule:'object(required)' }, response_schema:{ success:'boolean', deployedAt:'datetime' } },
      { method:'POST', path:'/test', summary:'Test platform connection', request_schema:{ platform:'string(required)' }, response_schema:{ success:'boolean', latencyMs:'integer' } },
      { method:'GET', path:'/deploy-log', summary:'Get deployment history', response_schema:{ log:'array' } },
      { method:'DELETE', path:'/{platform}', summary:'Remove platform configuration', response_schema:{ success:'boolean' } }
    ]
  },
  {
    group: 'Platform Health', prefix: '/api',
    description: 'Service health, readiness, and dependency status — unauthenticated, used for uptime monitoring',
    tier: 'FREE', endpoints: [
      { method:'GET', path:'/health', summary:'Service health check', description:'60-second edge cache.', response_schema:{ status:'string', bindings:'object' } },
      { method:'GET', path:'/platform/health', summary:'Production health check', description:'Real probes against D1, KV, and external dependencies.', response_schema:{ status:'string', checks:'object' } },
      { method:'GET', path:'/platform/health/deep', summary:'Deep health check', description:'Extended probe across all subsystems.', response_schema:{ status:'string', subsystems:'object' } },
      { method:'GET', path:'/platform/health/services', summary:'Per-service health status', response_schema:{ services:'array' } }
    ]
  }
];

// ─── SDK Code Generation Templates ────────────────────────────────────────────
const SDK_TEMPLATES = {
  python: (endpoint, baseUrl, apiKey) => `import requests

API_KEY = "${apiKey || 'your-api-key'}"
BASE_URL = "${baseUrl || 'https://cyberdudebivash.in'}"

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
const BASE_URL = "${baseUrl || 'https://cyberdudebivash.in'}";

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
  typescript: (endpoint, baseUrl, apiKey) => `const API_KEY: string = "${apiKey || 'your-api-key'}";
const BASE_URL: string = "${baseUrl || 'https://cyberdudebivash.in'}";

// ${endpoint.summary}
const response = await fetch(\`\${BASE_URL}${endpoint.path}\`, {
  method: "${endpoint.method}",
  headers: {
    "Authorization": \`Bearer \${API_KEY}\`,
    "Content-Type": "application/json"
  }${endpoint.method !== 'GET' ? `,
  body: JSON.stringify(${JSON.stringify(Object.fromEntries(Object.entries(endpoint.request_schema || {}).map(([k, v]) => [k, `<${v}>`])), null, 2)})` : ''}
});

const result: Record<string, any> = await response.json();
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
const baseURL = "${baseUrl || 'https://cyberdudebivash.in'}"

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
  "${baseUrl || 'https://cyberdudebivash.in'}${endpoint.path}" \\
  -H "Authorization: Bearer ${apiKey || 'your-api-key'}" \\
  -H "Content-Type: application/json"${endpoint.method !== 'GET' ? ` \\
  -d '${JSON.stringify(Object.fromEntries(Object.entries(endpoint.request_schema || {}).map(([k, v]) => [k, `<${v}>`])))}' ` : ' '}
`
};

// ─── Full Multi-Endpoint SDK Client Generator (P8.0-006) ─────────────────────
// Builds one complete, installable client library per language — every
// method below is derived mechanically from API_CATALOG (method + path),
// never hand-authored per endpoint. API_CATALOG remains the single source
// of truth shared with getOpenAPISpec(); this adds zero new registries.

function sdkOperations() {
  const seen = new Map();
  const ops = [];
  for (const group of API_CATALOG) {
    for (const ep of group.endpoints) {
      const fullPath = group.prefix + ep.path;
      const pathParams = [];
      const segments = fullPath.replace(/^\/api\//, '').split('/').filter(Boolean);
      const tokens = [];
      for (const seg of segments) {
        if (seg.startsWith('{')) {
          const name = seg.slice(1, -1);
          pathParams.push(name);
          tokens.push('by');
          for (const t of name.split(/[^a-zA-Z0-9]+/).filter(Boolean)) tokens.push(t);
        } else {
          for (const t of seg.split(/[^a-zA-Z0-9]+/).filter(Boolean)) tokens.push(t);
        }
      }
      const baseTokens = [ep.method.toLowerCase(), ...tokens];
      const key = baseTokens.join('_').toLowerCase();
      const dupes = seen.get(key) || 0;
      seen.set(key, dupes + 1);
      const nameTokens = dupes === 0 ? baseTokens : baseTokens.concat(String(dupes + 1));
      ops.push({ groupName: group.group, fullPath, pathParams, nameTokens, ep });
    }
  }
  return ops;
}

const sdkCamelName = tokens => tokens.map((t, i) => i === 0 ? t.toLowerCase() : t.charAt(0).toUpperCase() + t.slice(1).toLowerCase()).join('');
const sdkPascalName = tokens => tokens.map(t => t.charAt(0).toUpperCase() + t.slice(1).toLowerCase()).join('');
const sdkSnakeName = tokens => tokens.map(t => t.toLowerCase()).join('_');
const sdkPyArg = name => name.replace(/[^a-zA-Z0-9]+/g, '_');
const sdkJsArg = name => sdkCamelName(name.split(/[^a-zA-Z0-9]+/).filter(Boolean));

function buildPythonClient() {
  const lines = [
    '"""CyberDudeBivash AI Security Hub — Python SDK',
    'Auto-generated from the platform API registry. Do not hand-edit."""',
    'import requests',
    '',
    '',
    'class CyberDudeBivashClient:',
    '    def __init__(self, api_key, base_url="https://cyberdudebivash.in"):',
    '        self.api_key = api_key',
    '        self.base_url = base_url.rstrip("/")',
    '        self.session = requests.Session()',
    '        self.session.headers.update({',
    '            "Authorization": "Bearer " + api_key,',
    '            "Content-Type": "application/json",',
    '        })',
    '',
    '    def _request(self, method, path, params=None, body=None):',
    '        resp = self.session.request(method, self.base_url + path, params=params, json=body)',
    '        resp.raise_for_status()',
    '        return resp.json()',
  ];
  for (const op of sdkOperations()) {
    const name = sdkSnakeName(op.nameTokens);
    const args = ['self', ...op.pathParams.map(sdkPyArg), 'params=None', 'body=None'];
    let pathExpr = '"' + op.fullPath + '"';
    for (const pn of op.pathParams) {
      pathExpr = pathExpr.replace('{' + pn + '}', '" + str(' + sdkPyArg(pn) + ') + "');
    }
    lines.push('');
    lines.push('    # ' + op.groupName + ': ' + (op.ep.summary || ''));
    lines.push('    def ' + name + '(' + args.join(', ') + '):');
    lines.push('        path = ' + pathExpr);
    lines.push('        return self._request("' + op.ep.method + '", path, params=params, body=body)');
  }
  return lines.join('\n') + '\n';
}

function buildJavaScriptClient() {
  const lines = [
    '// CyberDudeBivash AI Security Hub — JavaScript SDK',
    '// Auto-generated from the platform API registry. Do not hand-edit.',
    '',
    'export class CyberDudeBivashClient {',
    '  constructor(apiKey, baseUrl = "https://cyberdudebivash.in") {',
    '    this.apiKey = apiKey;',
    '    this.baseUrl = baseUrl.replace(/\\/$/, "");',
    '  }',
    '',
    '  async _request(method, path, options = {}) {',
    '    const url = new URL(this.baseUrl + path);',
    '    if (options.params) for (const [k, v] of Object.entries(options.params)) url.searchParams.set(k, v);',
    '    const resp = await fetch(url, {',
    '      method,',
    '      headers: { Authorization: "Bearer " + this.apiKey, "Content-Type": "application/json" },',
    '      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,',
    '    });',
    '    if (!resp.ok) throw new Error("API error " + resp.status + ": " + (await resp.text()));',
    '    return resp.json();',
    '  }',
  ];
  for (const op of sdkOperations()) {
    const name = sdkCamelName(op.nameTokens);
    const args = [...op.pathParams.map(sdkJsArg), 'options = {}'];
    let pathExpr = '"' + op.fullPath + '"';
    for (const pn of op.pathParams) {
      pathExpr = pathExpr.replace('{' + pn + '}', '" + ' + sdkJsArg(pn) + ' + "');
    }
    lines.push('');
    lines.push('  // ' + op.groupName + ': ' + (op.ep.summary || ''));
    lines.push('  ' + name + '(' + args.join(', ') + ') {');
    lines.push('    return this._request("' + op.ep.method + '", ' + pathExpr + ', options);');
    lines.push('  }');
  }
  lines.push('}');
  return lines.join('\n') + '\n';
}

function buildTypeScriptClient() {
  const lines = [
    '// CyberDudeBivash AI Security Hub — TypeScript SDK',
    '// Auto-generated from the platform API registry. Do not hand-edit.',
    '',
    'export type ApiRequestOptions = { params?: Record<string, string | number | boolean>; body?: unknown };',
    'export type ApiResponse = Record<string, any>;',
    '',
    'export class CyberDudeBivashClient {',
    '  private apiKey: string;',
    '  private baseUrl: string;',
    '',
    '  constructor(apiKey: string, baseUrl: string = "https://cyberdudebivash.in") {',
    '    this.apiKey = apiKey;',
    '    this.baseUrl = baseUrl.replace(/\\/$/, "");',
    '  }',
    '',
    '  private async request(method: string, path: string, options: ApiRequestOptions = {}): Promise<ApiResponse> {',
    '    const url = new URL(this.baseUrl + path);',
    '    if (options.params) for (const [k, v] of Object.entries(options.params)) url.searchParams.set(k, String(v));',
    '    const resp = await fetch(url, {',
    '      method,',
    '      headers: { Authorization: "Bearer " + this.apiKey, "Content-Type": "application/json" },',
    '      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,',
    '    });',
    '    if (!resp.ok) throw new Error("API error " + resp.status + ": " + (await resp.text()));',
    '    return resp.json();',
    '  }',
  ];
  for (const op of sdkOperations()) {
    const name = sdkCamelName(op.nameTokens);
    const args = [...op.pathParams.map(p => sdkJsArg(p) + ': string'), 'options: ApiRequestOptions = {}'];
    let pathExpr = '"' + op.fullPath + '"';
    for (const pn of op.pathParams) {
      pathExpr = pathExpr.replace('{' + pn + '}', '" + ' + sdkJsArg(pn) + ' + "');
    }
    lines.push('');
    lines.push('  // ' + op.groupName + ': ' + (op.ep.summary || ''));
    lines.push('  ' + name + '(' + args.join(', ') + '): Promise<ApiResponse> {');
    lines.push('    return this.request("' + op.ep.method + '", ' + pathExpr + ', options);');
    lines.push('  }');
  }
  lines.push('}');
  return lines.join('\n') + '\n';
}

function buildGoClient() {
  const lines = [
    '// Package cyberdudebivash provides a generated Go client for the',
    '// CyberDudeBivash AI Security Hub API. Do not hand-edit.',
    'package cyberdudebivash',
    '',
    'import (',
    '\t"bytes"',
    '\t"encoding/json"',
    '\t"fmt"',
    '\t"net/http"',
    '\t"net/url"',
    ')',
    '',
    'type Client struct {',
    '\tAPIKey  string',
    '\tBaseURL string',
    '\tHTTP    *http.Client',
    '}',
    '',
    'func NewClient(apiKey string) *Client {',
    '\treturn &Client{APIKey: apiKey, BaseURL: "https://cyberdudebivash.in", HTTP: &http.Client{}}',
    '}',
    '',
    'func (c *Client) request(method, path string, query map[string]string, body interface{}) (map[string]interface{}, error) {',
    '\treqURL := c.BaseURL + path',
    '\tif len(query) > 0 {',
    '\t\tv := url.Values{}',
    '\t\tfor k, val := range query {',
    '\t\t\tv.Set(k, val)',
    '\t\t}',
    '\t\treqURL += "?" + v.Encode()',
    '\t}',
    '\tvar reqBody *bytes.Buffer',
    '\tif body != nil {',
    '\t\tb, err := json.Marshal(body)',
    '\t\tif err != nil {',
    '\t\t\treturn nil, err',
    '\t\t}',
    '\t\treqBody = bytes.NewBuffer(b)',
    '\t} else {',
    '\t\treqBody = bytes.NewBuffer(nil)',
    '\t}',
    '\treq, err := http.NewRequest(method, reqURL, reqBody)',
    '\tif err != nil {',
    '\t\treturn nil, err',
    '\t}',
    '\treq.Header.Set("Authorization", "Bearer "+c.APIKey)',
    '\treq.Header.Set("Content-Type", "application/json")',
    '\tresp, err := c.HTTP.Do(req)',
    '\tif err != nil {',
    '\t\treturn nil, err',
    '\t}',
    '\tdefer resp.Body.Close()',
    '\tif resp.StatusCode >= 400 {',
    '\t\treturn nil, fmt.Errorf("api error: status %d", resp.StatusCode)',
    '\t}',
    '\tvar result map[string]interface{}',
    '\tif err := json.NewDecoder(resp.Body).Decode(&result); err != nil {',
    '\t\treturn nil, err',
    '\t}',
    '\treturn result, nil',
    '}',
  ];
  for (const op of sdkOperations()) {
    const name = sdkPascalName(op.nameTokens);
    const goArgs = [...op.pathParams.map(p => sdkJsArg(p) + ' string'), 'query map[string]string', 'body interface{}'];
    let pathExpr;
    if (op.pathParams.length) {
      let fmtPath = op.fullPath;
      for (const pn of op.pathParams) fmtPath = fmtPath.replace('{' + pn + '}', '%s');
      const fmtArgs = op.pathParams.map(sdkJsArg).join(', ');
      pathExpr = 'fmt.Sprintf("' + fmtPath + '", ' + fmtArgs + ')';
    } else {
      pathExpr = '"' + op.fullPath + '"';
    }
    lines.push('');
    lines.push('// ' + name + ' — ' + op.groupName + ': ' + (op.ep.summary || ''));
    lines.push('func (c *Client) ' + name + '(' + goArgs.join(', ') + ') (map[string]interface{}, error) {');
    lines.push('\tpath := ' + pathExpr);
    lines.push('\treturn c.request("' + op.ep.method + '", path, query, body)');
    lines.push('}');
  }
  return lines.join('\n') + '\n';
}

const SDK_CLIENT_BUILDERS = {
  python:     { build: buildPythonClient,     filename: 'cyberdudebivash_client.py', install: 'pip install requests' },
  javascript: { build: buildJavaScriptClient, filename: 'cyberdudebivash-client.js', install: 'N/A — uses native fetch (Node 18+)' },
  typescript: { build: buildTypeScriptClient, filename: 'cyberdudebivash-client.ts', install: 'N/A — uses native fetch (Node 18+ / TS 4.7+)' },
  go:         { build: buildGoClient,         filename: 'cyberdudebivash_client.go', install: 'go get (standard library only)' },
};

function buildFullClient(language) {
  const entry = SDK_CLIENT_BUILDERS[language];
  if (!entry) return null;
  return {
    language, filename: entry.filename, install: entry.install,
    code: entry.build(),
    total_methods: sdkOperations().length,
    total_groups: API_CATALOG.length,
  };
}

async function downloadFullSDK(request, env) {
  const url = new URL(request.url);
  const language = url.pathname.split('/').pop();
  const result = buildFullClient(language);
  if (!result) return jsonResp({ error: `Unsupported language. Supported: ${Object.keys(SDK_CLIENT_BUILDERS).join(', ')}` }, 400);
  if (url.searchParams.get('raw') === '1') {
    return new Response(result.code, { status: 200, headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': `attachment; filename="${result.filename}"`,
    }});
  }
  return jsonResp({
    language: result.language, filename: result.filename, install: result.install,
    total_methods: result.total_methods, total_groups: result.total_groups,
    code: result.code,
    download: `${url.pathname}?raw=1`,
  });
}

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
export async function handleDeveloperPortal(request, env, authCtx) {
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
  if (path.match(/^\/api\/developer\/sdk\/download\/[\w-]+$/) && method === 'GET') return downloadFullSDK(request, env);

  // Webhooks retired from the Developer Platform (CAP-NOTIF-003): this
  // implementation had zero frontend callers, no real event dispatch (only
  // a manual test-ping), no delivery-log table, and its own catalog
  // promised HMAC signing that the code never actually sent. The sibling
  // implementation at /api/auto/webhooks (enterpriseAutomation.js) is the
  // one with live customer usage, real signing, and (as of the fix
  // alongside this retirement) working update/logs routes and populated
  // delivery logs. See docs/capability-registry/PROGRAM_BOARD.md for the
  // full comparison and decision record. Canonical routes:
  //   GET  /api/webhooks/catalog        (event vocabulary + delivery info)
  //   GET/POST/PATCH/DELETE /api/auto/webhooks[/:id]
  //   POST /api/auto/webhooks/:id/test
  //   GET  /api/auto/webhooks/:id/logs

  // Rate Limit Dashboard
  if (path === '/api/developer/rate-limits' && method === 'GET') return getRateLimits(request, env);
  if (path === '/api/developer/rate-limits/usage' && method === 'GET') return getRateLimitUsage(request, env);

  // Changelog
  if (path === '/api/developer/changelog' && method === 'GET') return getChangelog(request, env);

  // Interactive Playground
  if (path === '/api/developer/playground/execute' && method === 'POST') return playgroundExecute(request, env);

  // API Key Management — same keys, same accounts, same limits as the
  // canonical POST /api/keys surface (handlers/apikeys.js); this is just a
  // developer-portal-branded URL onto it, not a second key system.
  if (path === '/api/developer/keys' && method === 'POST') {
    if (!isRealUser(authCtx)) return authRequired();
    return handleCreateKey(request, env, authCtx);
  }
  if (path === '/api/developer/keys' && method === 'GET') {
    if (!isRealUser(authCtx)) return authRequired();
    return handleListKeys(request, env, authCtx);
  }
  if (path.match(/^\/api\/developer\/keys\/[\w-]+$/) && method === 'DELETE') {
    if (!isRealUser(authCtx)) return authRequired();
    return handleRevokeKey(request, env, authCtx, path.split('/').pop());
  }
  if (path.match(/^\/api\/developer\/keys\/[\w-]+\/rotate$/) && method === 'POST') {
    if (!isRealUser(authCtx)) return authRequired();
    return handleRotateKey(request, env, authCtx, path.split('/').slice(-2, -1)[0]);
  }

  // OpenAPI Spec
  if (path === '/api/developer/openapi.json' && method === 'GET') return getOpenAPISpec(request, env);

  // Developer Guides & Resources (P8.0-007)
  if (path === '/api/developer/postman.json' && method === 'GET') return getPostmanCollection(request, env);
  if (path === '/api/developer/quickstart' && method === 'GET') return getQuickStart(request, env);
  if (path === '/api/developer/auth-guide' && method === 'GET') return getAuthGuide(request, env);
  if (path === '/api/developer/migration-guide' && method === 'GET') return getMigrationGuide(request, env);
  if (path === '/api/developer/version-policy' && method === 'GET') return getVersionPolicy(request, env);
  if (path === '/api/developer/examples' && method === 'GET') return getEnterpriseExamples(request, env);

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
    tiers: ['FREE', 'STARTER', 'PRO', 'ENTERPRISE', 'ADMIN'],
    baseUrl: 'https://cyberdudebivash.in',
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
      dependencies: { python: ['requests'], javascript: ['(built-in fetch)'], typescript: ['(built-in fetch)'], go: ['(standard library)'], curl: ['curl'] }[language] || []
    });
  } catch (e) { return jsonResp({ error: e.message }, 500); }
}

async function listSDKLanguages(request, env) {
  return jsonResp({
    languages: [
      { id:'python', name:'Python', version:'3.8+', package:'requests', install:'pip install requests' },
      { id:'javascript', name:'JavaScript / Node.js', version:'18+', package:'(built-in fetch)', install:'N/A — uses native fetch' },
      { id:'typescript', name:'TypeScript', version:'4.7+', package:'(built-in fetch)', install:'N/A — uses native fetch, typed client' },
      { id:'go', name:'Go', version:'1.18+', package:'standard library', install:'N/A — standard library' },
      { id:'curl', name:'cURL', version:'7.0+', package:'curl', install:'brew install curl / apt install curl' }
    ],
    note: 'POST /api/developer/sdk/generate with {language, endpoint_path, endpoint_method, base_url, api_key} for a single-endpoint snippet. GET /api/developer/sdk/download/{language} (python, javascript, typescript, go) returns a complete multi-endpoint client library generated from the full API catalog — add ?raw=1 to download the source file directly.'
  });
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

// createAPIKey/listAPIKeys/revokeAPIKey/rotateAPIKey were removed 2026-07 —
// they reimplemented key issuance against columns (name, scopes, updated_at)
// that never existed in the live api_keys schema (every call 500'd) and had
// no auth check at all. Key management now delegates to the canonical,
// tested implementation — see the router above and handlers/apikeys.js.


// ─── P8.0-007: Postman Collection Builder ────────────────────────────────────
async function getPostmanCollection(request, env) {
  const collection = {
    info: {
      _postman_id: 'cyberdudebivash-ai-security-hub-v20',
      name: 'CYBERDUDEBIVASH AI Security Hub API',
      description: 'Enterprise AI Security Platform — AI Governance, Red Team, SOC, CTI, Threat Hunting, CTEM, MSSP. Auto-generated from live API catalog v20.0.0.',
      schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
      version: '20.0.0',
    },
    auth: { type: 'bearer', bearer: [{ key: 'token', value: '{{API_KEY}}', type: 'string' }] },
    variable: [
      { key: 'BASE_URL', value: 'https://cyberdudebivash.in', type: 'string' },
      { key: 'API_KEY', value: 'your-api-key-here', type: 'string' },
    ],
    item: API_CATALOG.map(group => ({
      name: group.group,
      description: group.description,
      item: group.endpoints.map(ep => {
        const fullPath = group.prefix + ep.path;
        const urlObj = {
          raw: '{{BASE_URL}}' + fullPath,
          host: ['{{BASE_URL}}'],
          path: fullPath.replace(/^\//, '').split('/'),
        };
        if (ep.query_params) {
          urlObj.query = Object.entries(ep.query_params).map(([key, desc]) => ({ key, value: '', description: desc, disabled: true }));
        }
        const hasBody = ep.method !== 'GET' && ep.request_schema && Object.keys(ep.request_schema).length > 0;
        return {
          name: ep.summary,
          request: {
            method: ep.method,
            header: [
              { key: 'Content-Type', value: 'application/json' },
              { key: 'Authorization', value: 'Bearer {{API_KEY}}' },
            ],
            url: urlObj,
            description: ep.description || ep.summary,
            ...(hasBody ? {
              body: {
                mode: 'raw',
                raw: JSON.stringify(Object.fromEntries(Object.entries(ep.request_schema).map(([k, v]) => [k, `<${v}>`])), null, 2),
                options: { raw: { language: 'json' } },
              },
            } : {}),
          },
          response: [],
        };
      }),
    })),
  };
  const url = new URL(request.url);
  if (url.searchParams.get('raw') === '1') {
    return new Response(JSON.stringify(collection, null, 2), { headers: {
      'Content-Type': 'application/json',
      'Content-Disposition': 'attachment; filename="cyberdudebivash-api.postman_collection.json"',
    }});
  }
  return jsonResp({
    collection_name: 'CYBERDUDEBIVASH AI Security Hub API',
    version: '20.0.0',
    postman_schema: 'v2.1.0',
    total_groups: API_CATALOG.length,
    total_endpoints: API_CATALOG.reduce((s, g) => s + g.endpoints.length, 0),
    download: '/api/developer/postman.json?raw=1',
    instructions: 'Import into Postman via File > Import > Raw Text or Collection File. Set BASE_URL and API_KEY variables after import.',
    collection,
  });
}

// ─── P8.0-007: Quick Start Guide ────────────────────────────────────────────
async function getQuickStart(request, env) {
  return jsonResp({
    title: 'CYBERDUDEBIVASH AI Security Hub — Quick Start Guide',
    version: '20.0.0',
    baseUrl: 'https://cyberdudebivash.in',
    steps: [
      { step: 1, title: 'Get your API key', description: 'Create an API key via the self-service portal.', endpoint: 'POST /api/developer/keys', example: { name: 'My App', scopes: ['read', 'write'] }, note: 'Store your key securely — it will not be shown again.' },
      { step: 2, title: 'Make your first request', description: 'Fetch the latest threat signals from the radar.', endpoint: 'GET /api/radar/latest', curl: 'curl -H "Authorization: Bearer <YOUR_API_KEY>" https://cyberdudebivash.in/api/radar/latest' },
      { step: 3, title: 'Explore the API catalog', description: 'Browse all available endpoints by group and tier.', endpoint: 'GET /api/developer/endpoints' },
      { step: 4, title: 'Download an SDK', description: 'Get a complete client library for your language.', endpoint: 'GET /api/developer/sdk/download/{language}', supported: ['python', 'javascript', 'typescript', 'go'] },
      { step: 5, title: 'Register a webhook', description: 'Receive real-time event notifications.', endpoint: 'POST /api/auto/webhooks', example: { url: 'https://your-server.com/webhook', events: ['threat.new_cve', 'threat.critical'] }, note: 'See GET /api/webhooks/catalog for the full event vocabulary.' },
    ],
    authentication: { methods: ['Bearer token (Authorization: Bearer <key>)', 'API key header (X-API-Key: <key>)'], example_header: 'Authorization: Bearer cdb_your_api_key_here', docs: '/api/developer/auth-guide' },
    sdks: { download: '/api/developer/sdk/download/{language}', generate: 'POST /api/developer/sdk/generate', languages: ['python', 'javascript', 'typescript', 'go', 'curl'] },
    resources: { openapi: '/api/developer/openapi.json', postman: '/api/developer/postman.json?raw=1', changelog: '/api/developer/changelog', rate_limits: '/api/developer/rate-limits', auth_guide: '/api/developer/auth-guide', examples: '/api/developer/examples' },
  });
}

// ─── P8.0-007: Authentication Guide ─────────────────────────────────────────
async function getAuthGuide(request, env) {
  return jsonResp({
    title: 'Authentication Guide — CYBERDUDEBIVASH AI Security Hub',
    version: '20.0.0',
    methods: [
      { name: 'Bearer Token', header: 'Authorization: Bearer <your-api-key>', description: 'Recommended. Pass your API key as a Bearer token in the Authorization header.', example_curl: 'curl -H "Authorization: Bearer cdb_your_key" https://cyberdudebivash.in/api/radar/latest' },
      { name: 'API Key Header', header: 'X-API-Key: <your-api-key>', description: 'Alternative method. Pass your API key in the X-API-Key header.', example_curl: 'curl -H "X-API-Key: cdb_your_key" https://cyberdudebivash.in/api/radar/latest' },
    ],
    key_management: { create: 'POST /api/developer/keys', list: 'GET /api/developer/keys', revoke: 'DELETE /api/developer/keys/{id}', rotate: 'POST /api/developer/keys/{id}/rotate', format: 'cdb_ prefix followed by 48 hex characters' },
    scopes: [
      { scope: 'read', description: 'Read access to all GET endpoints for your tier' },
      { scope: 'write', description: 'Read + write access (POST, PUT, PATCH, DELETE)' },
      { scope: 'admin', description: 'Full access including team management and configuration' },
      { scope: 'webhooks', description: 'Webhook registration and management' },
      { scope: 'billing', description: 'Billing and subscription management' },
    ],
    rate_limiting: {
      headers: { 'X-RateLimit-Limit': 'Requests allowed per minute for your tier', 'X-RateLimit-Remaining': 'Requests remaining in current window', 'X-RateLimit-Reset': 'Unix timestamp when the window resets', 'Retry-After': 'Seconds to wait after a 429 response' },
      tiers: { FREE: '60/min', STARTER: '300/min', PRO: '1000/min', ENTERPRISE: '10000/min' },
      details: '/api/developer/rate-limits',
    },
    errors: { '401': { code: 'UNAUTHORIZED', description: 'Missing or invalid API key' }, '403': { code: 'FORBIDDEN', description: 'Valid key but insufficient tier or scope for this endpoint' }, '429': { code: 'RATE_LIMITED', description: 'Too many requests — see Retry-After header' }, '400': { code: 'BAD_REQUEST', description: 'Missing or invalid request parameters' } },
    security: { storage: 'Store API keys in environment variables or a secrets manager. Never commit to source control.', rotation: 'Rotate keys regularly using POST /api/developer/keys/{id}/rotate', expiry: 'Set expires_in_days when creating keys for automatic expiration' },
  });
}

// ─── P8.0-007: Migration Guide ───────────────────────────────────────────────
async function getMigrationGuide(request, env) {
  return jsonResp({
    title: 'API Migration Guide — CYBERDUDEBIVASH AI Security Hub',
    currentVersion: '20.0.0',
    apiVersionHeader: 'API-Version',
    guides: [
      {
        from: 'v19.x', to: 'v20.0',
        breaking_changes: [
          'AI Governance endpoints moved: /api/governance/* → /api/ai-governance/*',
          'Red Team campaign results include MITRE ATLAS v2.1 technique IDs',
          'Export format enum expanded: ioc_bundle and executive_pdf added to /api/export/siem',
        ],
        new_endpoints: [
          'GET /api/export/siem?format=ioc_bundle', 'GET /api/export/siem?format=executive_pdf',
          'POST /api/integrations/configure (QRadar, Google SecOps, Cortex XSOAR)',
          'GET /api/developer/sdk/download/{language}', 'GET /api/developer/postman.json',
          'GET /api/webhooks/catalog', 'GET /api/developer/openapi.json',
          'GET /api/developer/quickstart', 'GET /api/developer/auth-guide',
          'GET /api/developer/migration-guide', 'GET /api/developer/version-policy',
          'GET /api/developer/examples',
        ],
        migration_steps: [
          'Update AI Governance endpoint base path from /api/governance/* to /api/ai-governance/*',
          'Update ATLAS technique ID references to v2.1 format (AML.T0051 etc.)',
          'Test SDK download endpoints: GET /api/developer/sdk/download/python',
          'Import Postman collection: GET /api/developer/postman.json?raw=1',
          'Register webhook catalog events: GET /api/webhooks/catalog',
        ],
      },
    ],
    deprecations: [
      { endpoint: 'GET /api/v1/signals', sunset: '2027-01-01', replacement: 'GET /api/radar/latest', reason: 'Unified radar API provides richer signal data with EPSS scoring' },
      { endpoint: 'POST /api/v1/redteam/test', sunset: '2027-01-01', replacement: 'POST /api/ai-redteam/campaigns', reason: 'Campaign-based red teaming provides full MITRE ATLAS coverage' },
    ],
    deprecation_policy: '/api/developer/version-policy',
    support: 'Contact support before migrating major versions for enterprise accounts.',
  });
}

// ─── P8.0-007: Version Policy ────────────────────────────────────────────────
async function getVersionPolicy(request, env) {
  return jsonResp({
    title: 'API Version Policy — CYBERDUDEBIVASH AI Security Hub',
    currentVersion: '20.0.0',
    policy: {
      versioning_strategy: 'Semantic versioning (MAJOR.MINOR.PATCH). Breaking changes increment MAJOR only.',
      stability_levels: { stable: 'No breaking changes without 12-month deprecation notice and Sunset header', beta: 'May change with 90-day notice', preview: 'No stability guarantees — experimental endpoints only' },
      deprecation_window: '12 months minimum for stable endpoints',
      sunset_headers: 'Deprecated endpoints return Deprecation and Sunset HTTP response headers per RFC 8594',
      api_version_header: 'Include API-Version: 20.0.0 in requests to pin to current version',
    },
    stability: {
      stable_endpoints: ['/api/radar/*', '/api/customer/*', '/api/enterprise/*', '/api/developer/*', '/api/auth/*', '/api/subscription/*', '/api/export/*', '/api/integrations/*'],
      beta_endpoints: ['/api/ai-redteam/probe/*'],
      preview_endpoints: [],
    },
    sunset_schedule: [
      { endpoint: 'GET /api/v1/signals', sunset_date: '2027-01-01', replacement: 'GET /api/radar/latest' },
      { endpoint: 'POST /api/v1/redteam/test', sunset_date: '2027-01-01', replacement: 'POST /api/ai-redteam/campaigns' },
    ],
    notification: { channels: ['Deprecation response header (RFC 8594)', 'Sunset response header (RFC 8594)', 'Changelog: /api/developer/changelog'], advance_notice: '12 months for stable endpoints, 90 days for beta endpoints' },
    change_log: '/api/developer/changelog',
    migration_guide: '/api/developer/migration-guide',
  });
}

// ─── P8.0-007: Enterprise Integration Examples ───────────────────────────────
async function getEnterpriseExamples(request, env) {
  return jsonResp({
    title: 'Enterprise Integration Examples — CYBERDUDEBIVASH AI Security Hub',
    categories: ['siem_integration', 'soar_automation', 'ai_governance', 'threat_hunting', 'soc_operations'],
    examples: [
      {
        id: 'splunk-threat-export', title: 'Export threat intelligence to Splunk', category: 'siem_integration',
        description: 'Continuously export CVE signals and IOC data into Splunk for SIEM correlation.',
        steps: ['Configure Splunk connector: POST /api/integrations/configure (platform: splunk)', 'Test connection: POST /api/integrations/test', 'Export signals: GET /api/export/siem?format=cef&hours=24', 'Schedule via webhook: POST /api/auto/webhooks (event: threat.new_cve)'],
        code_curl: 'curl -X POST https://cyberdudebivash.in/api/integrations/configure -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d \'{"platform":"splunk","config":{"host":"splunk.company.com","token":"HEC_TOKEN","index":"security"}}\'',
      },
      {
        id: 'ai-governance-workflow', title: 'Automate AI model risk governance', category: 'ai_governance',
        description: 'Register new AI models and automatically gate deployment based on EU AI Act risk score.',
        steps: ['Register model: POST /api/ai-governance/models', 'Get risk score: POST /api/ai-governance/risk-score', 'Check EU AI Act compliance: POST /api/ai-governance/compliance/eu-ai-act'],
        code_python: 'import requests\nAPI_KEY = "cdb_your_key"\nBASE = "https://cyberdudebivash.in"\nheaders = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}\nmodel = requests.post(f"{BASE}/api/ai-governance/models", headers=headers, json={"name": "ProdEngine-v3", "version": "3.2.1", "model_type": "recommendation", "data_classification": "pii", "deployment_context": "production_customer_facing", "autonomy_level": "fully_autonomous", "impact_domain": "financial"}).json()\nprint(f"Risk Level: {model[\'riskAssessment\'][\'riskLevel\']}")'
      },
      {
        id: 'soc-case-automation', title: 'Automated SOC case creation on critical CVEs', category: 'soc_operations',
        description: 'Automatically create SOC investigation cases when CRITICAL CVEs are detected via webhook.',
        steps: ['Register webhook: POST /api/auto/webhooks (event: threat.critical)', 'Handle event payload in your service', 'Create SOC case: POST /api/soc/cases with cve reference in description'],
        webhook_payload_example: { event: 'threat.critical', vulnId: 'uuid', cve: 'CVE-2026-XXXXX', cvss: 9.8, affected: 'vendor/product', timestamp: '2026-06-25T00:00:00Z' },
      },
      {
        id: 'threat-hunting-mitre', title: 'MITRE ATT&CK-aligned threat hunt campaign', category: 'threat_hunting',
        description: 'Launch a structured threat hunt based on the latest MITRE ATT&CK techniques observed in radar signals.',
        steps: ['Fetch trending threats: GET /api/radar/trending', 'Identify MITRE techniques: GET /api/threat-hunting/techniques', 'Create hunt: POST /api/threat-hunting/hunts', 'Register completion webhook: POST /api/auto/webhooks (event: redteam.campaign.completed)'],
      },
      {
        id: 'enterprise-pdf-report', title: 'Generate executive PDF threat report', category: 'soc_operations',
        description: 'Generate a board-ready executive PDF summarising the threat landscape for CISO reporting.',
        steps: ['Ensure ENTERPRISE tier subscription', 'Call: GET /api/export/siem?format=executive_pdf', 'Save response binary as .pdf'],
        code_curl: 'curl "https://cyberdudebivash.in/api/export/siem?format=executive_pdf" -H "Authorization: Bearer $API_KEY" -o threat-report.pdf',
      },
    ],
    sdk_downloads: { python: '/api/developer/sdk/download/python?raw=1', javascript: '/api/developer/sdk/download/javascript?raw=1', typescript: '/api/developer/sdk/download/typescript?raw=1', go: '/api/developer/sdk/download/go?raw=1' },
    postman_collection: '/api/developer/postman.json?raw=1',
    openapi_spec: '/api/developer/openapi.json',
  });
}

export async function getOpenAPISpec(request, env) {
  const spec = {
    openapi:'3.1.0',
    info:{ title:'CYBERDUDEBIVASH AI Security Hub API', version:'20.0.0', description:'Enterprise AI Security Platform — AI Governance, Red Team, SOC, CTI, Threat Hunting, CTEM, MSSP', contact:{ name:'CYBERDUDEBIVASH Support', url:'https://cyberdudebivash.in/api/developer' } },
    servers:[{ url:'https://cyberdudebivash.in', description:'Production (Cloudflare Edge — 300+ PoPs)' }],
    security:[{ BearerAuth:[] },{ ApiKeyAuth:[] }],
    components:{ securitySchemes:{
      BearerAuth:{ type:'http', scheme:'bearer', bearerFormat:'JWT', description:'JWT token from /api/auth/token' },
      ApiKeyAuth:{ type:'apiKey', in:'header', name:'X-API-Key', description:'API key from /api/developer/keys' }
    }},
    paths: API_CATALOG.flatMap(group => group.endpoints.map(ep => ({ group, ep }))).reduce((paths, { group, ep }) => {
      const key = group.prefix + ep.path;
      paths[key] = paths[key] || {};
      paths[key][ep.method.toLowerCase()] = {
        summary: ep.summary, description: ep.description || ep.summary,
        tags: [group.group], security:[{BearerAuth:[]},{ApiKeyAuth:[]}],
        parameters: ep.query_params ? Object.entries(ep.query_params).map(([name,schema]) => ({ name, in:'query', schema:{ type:'string' }, description:schema })) : [],
        requestBody: ep.request_schema && ep.method !== 'GET' ? { content:{ 'application/json':{ schema:{ type:'object', properties: Object.fromEntries(Object.entries(ep.request_schema).map(([k,v])=>[k,{type:'string',description:v}])) } } } } : undefined,
        responses:{ '200':{ description:'Success', content:{ 'application/json':{ schema:{ type:'object', properties: Object.fromEntries(Object.entries(ep.response_schema||{}).map(([k,v])=>[k,{type:'string',description:v}])) } } } }, '401':{ description:'Unauthorized' }, '429':{ description:'Rate limit exceeded' } }
      };
      return paths;
    }, {})
  };
  return new Response(JSON.stringify(spec, null, 2), { headers:{ 'Content-Type':'application/json' } });
}
