/**
 * CYBERDUDEBIVASH AI Security Hub — SIEM Integration Deploy Handler v1.0
 *
 * Enables one-click rule deployment to external SIEM/security platforms.
 *
 * Endpoints:
 *   GET  /api/integrations              → list all configured integrations + status
 *   POST /api/integrations/configure    → save webhook URL for a platform
 *   POST /api/integrations/deploy       → push a rule to one or all platforms
 *   GET  /api/integrations/deploy-log   → fetch deployment history
 *   POST /api/integrations/test         → test webhook connectivity
 *   DELETE /api/integrations/:platform  → remove integration config
 */

import { ok, fail } from '../lib/response.js';

// ── Supported integration platforms ──────────────────────────────────────────
export const INTEGRATION_PLATFORMS = {
  splunk: {
    label:       'Splunk',
    icon:        '🟢',
    description: 'Splunk HEC (HTTP Event Collector) endpoint',
    rule_format: 'splunk',
    docs_url:    'https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector',
    field_label: 'HEC URL (e.g. https://splunk.acme.com:8088/services/collector)',
  },
  elastic: {
    label:       'Elastic Security',
    icon:        '🔵',
    description: 'Elastic SIEM / EQL rule push via Kibana API',
    rule_format: 'elastic',
    docs_url:    'https://www.elastic.co/guide/en/security/current/rules-ui-create.html',
    field_label: 'Kibana API base URL (e.g. https://kibana.acme.com:5601)',
  },
  sentinel: {
    label:       'Microsoft Sentinel',
    icon:        '🔷',
    description: 'Azure Sentinel Logic App Webhook / ARM REST',
    rule_format: 'kql',
    docs_url:    'https://learn.microsoft.com/azure/sentinel/detect-threats-custom',
    field_label: 'Logic App HTTP Trigger URL',
  },
  aws_security_hub: {
    label:       'AWS Security Hub',
    icon:        '🟠',
    description: 'AWS Security Hub custom findings ingestion',
    rule_format: 'json',
    docs_url:    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-custom-findings.html',
    field_label: 'AWS Security Hub Findings API URL / Lambda URL',
  },
  aws_waf: {
    label:       'AWS WAF',
    icon:        '🟡',
    description: 'AWS WAF IP set / rule group update via API Gateway webhook',
    rule_format: 'json',
    docs_url:    'https://docs.aws.amazon.com/waf/latest/developerguide/',
    field_label: 'API Gateway URL for WAF rule ingestion',
  },
  azure_defender: {
    label:       'Azure Defender',
    icon:        '🔶',
    description: 'Azure Defender for Cloud alert suppression / custom rule',
    rule_format: 'json',
    docs_url:    'https://learn.microsoft.com/azure/defender-for-cloud/',
    field_label: 'Logic App / Event Hub ingestion URL',
  },
  generic_webhook: {
    label:       'Generic Webhook',
    icon:        '🔗',
    description: 'Any firewall or SOAR that accepts JSON webhooks',
    rule_format: 'json',
    docs_url:    null,
    field_label: 'Webhook URL (POST, expects JSON body)',
  },
  pagerduty: {
    label:       'PagerDuty',
    icon:        '🔴',
    description: 'Trigger PagerDuty incidents for critical detections',
    rule_format: 'json',
    docs_url:    'https://developer.pagerduty.com/docs/events-api-v2/',
    field_label: 'PagerDuty Events API v2 Integration Key',
  },
};

const KV_CONFIG_PREFIX  = 'siem_integration:config:';
const KV_LOG_KEY        = 'siem_integration:deploy_log';
const DEPLOY_LOG_MAX    = 200;

// ── Load integration config from KV ──────────────────────────────────────────
async function loadConfig(env, platform) {
  if (!env?.SECURITY_HUB_KV) return null;
  try {
    return await env.SECURITY_HUB_KV.get(`${KV_CONFIG_PREFIX}${platform}`, { type: 'json' });
  } catch { return null; }
}

async function saveConfig(env, platform, config) {
  if (!env?.SECURITY_HUB_KV) return;
  await env.SECURITY_HUB_KV.put(`${KV_CONFIG_PREFIX}${platform}`, JSON.stringify(config), { expirationTtl: 86400 * 365 });
}

async function deleteConfig(env, platform) {
  if (!env?.SECURITY_HUB_KV) return;
  await env.SECURITY_HUB_KV.delete(`${KV_CONFIG_PREFIX}${platform}`);
}

// ── Deploy log helpers ────────────────────────────────────────────────────────
async function appendDeployLog(env, entry) {
  if (!env?.SECURITY_HUB_KV) return;
  try {
    const log = (await env.SECURITY_HUB_KV.get(KV_LOG_KEY, { type: 'json' })) || [];
    log.unshift({ ...entry, ts: new Date().toISOString() });
    await env.SECURITY_HUB_KV.put(KV_LOG_KEY, JSON.stringify(log.slice(0, DEPLOY_LOG_MAX)), { expirationTtl: 86400 * 14 });
  } catch {}
}

// ── Build platform-specific payload ──────────────────────────────────────────
function buildPayload(platform, rule, meta = {}) {
  const ts     = new Date().toISOString();
  const ruleId = `CDB_${meta.cve_id || 'RULE'}_${Date.now().toString(36).toUpperCase()}`;

  switch (platform) {
    case 'splunk':
      return {
        event:      { sourcetype: 'cdb:soc_rule', rule_id: ruleId, rule: rule.splunk || rule.raw, cve_id: meta.cve_id, severity: meta.severity || 'HIGH', platform: 'CYBERDUDEBIVASH_MYTHOS', ts },
        time:       Math.floor(Date.now() / 1000),
        host:       'cyberdudebivash-ai-security-hub',
        index:      'security',
      };

    case 'elastic':
      return {
        type:        'eql',
        name:        `CDB MYTHOS: ${meta.cve_id || 'Custom Rule'}`,
        description: `Auto-generated by CYBERDUDEBIVASH MYTHOS Engine at ${ts}`,
        query:       rule.elastic || rule.kql || rule.raw,
        severity:    (meta.severity || 'high').toLowerCase(),
        tags:        ['cdb', 'mythos', meta.cve_id].filter(Boolean),
        enabled:     true,
        created_at:  ts,
        risk_score:  meta.cvss ? Math.round(parseFloat(meta.cvss) * 10) : 70,
      };

    case 'sentinel':
      return {
        displayName: `CDB MYTHOS: ${meta.cve_id || 'Detection Rule'}`,
        description: `Auto-generated detection rule from CYBERDUDEBIVASH MYTHOS Engine`,
        query:       rule.kql || rule.splunk || rule.raw,
        queryFrequency: 'PT1H',
        queryPeriod:    'PT1H',
        triggerOperator: 'GreaterThan',
        triggerThreshold: 0,
        severity:    meta.severity || 'High',
        tactics:     ['InitialAccess', 'Execution'],
        enabled:     true,
        cve_id:      meta.cve_id,
        source:      'CYBERDUDEBIVASH_AI_SECURITY_HUB',
        ts,
      };

    case 'aws_security_hub':
      return {
        Findings: [{
          SchemaVersion: '2018-10-08',
          Id:            ruleId,
          ProductArn:    'arn:aws:securityhub:ap-south-1::product/cyberdudebivash/mythos',
          GeneratorId:   'CDB_MYTHOS_AUTOENGINE',
          AwsAccountId:  meta.aws_account || '000000000000',
          Types:         ['Software and Configuration Checks/Vulnerabilities/CVE'],
          CreatedAt:     ts,
          UpdatedAt:     ts,
          Severity:      { Label: meta.severity || 'HIGH' },
          Title:         `MYTHOS Alert: ${meta.cve_id || 'Critical Detection'}`,
          Description:   rule.raw || rule.sigma || 'Generated by CYBERDUDEBIVASH MYTHOS Engine',
          Remediation:   { Recommendation: { Text: 'Apply vendor patch immediately and enable detection rule' } },
        }],
      };

    case 'pagerduty':
      return {
        routing_key:  meta.integration_key || '',
        event_action: 'trigger',
        dedup_key:    ruleId,
        payload: {
          summary:    `🚨 MYTHOS Alert: ${meta.cve_id || 'Critical Threat'} Detected`,
          severity:   (meta.severity || 'critical').toLowerCase(),
          source:     'CYBERDUDEBIVASH AI Security Hub',
          timestamp:  ts,
          custom_details: {
            rule_id:    ruleId,
            cve_id:     meta.cve_id,
            cvss:       meta.cvss,
            sigma_rule: rule.sigma,
          },
        },
        links: [{ href: 'https://cyberdudebivash.com', text: 'CYBERDUDEBIVASH Dashboard' }],
      };

    default: // generic_webhook + aws_waf + azure_defender
      return {
        source:      'CYBERDUDEBIVASH_MYTHOS',
        rule_id:     ruleId,
        cve_id:      meta.cve_id,
        severity:    meta.severity || 'HIGH',
        cvss:        meta.cvss,
        ts,
        rule: {
          sigma:   rule.sigma,
          splunk:  rule.splunk,
          kql:     rule.kql,
          yara:    rule.yara,
          elastic: rule.elastic,
          raw:     rule.raw,
        },
      };
  }
}

// ── Perform the actual HTTP deploy ────────────────────────────────────────────
async function deployToEndpoint(platformId, config, payload) {
  const headers = { 'Content-Type': 'application/json', 'User-Agent': 'CYBERDUDEBIVASH-MYTHOS/1.0' };

  // Platform-specific auth headers
  if (platformId === 'splunk' && config.hec_token) {
    headers['Authorization'] = `Splunk ${config.hec_token}`;
  } else if (platformId === 'elastic' && config.api_key) {
    headers['Authorization'] = `ApiKey ${config.api_key}`;
    headers['kbn-xsrf']      = 'true';
  } else if (config.auth_token) {
    headers['Authorization'] = `Bearer ${config.auth_token}`;
  }

  // Special handling for PagerDuty (routing_key in body)
  if (platformId === 'pagerduty') {
    payload.routing_key = config.integration_key || config.webhook_url;
  }

  const endpoint = platformId === 'elastic'
    ? `${config.webhook_url}/api/detection_engine/rules`
    : config.webhook_url;

  const res = await fetch(endpoint, {
    method:  'POST',
    headers,
    body:    JSON.stringify(payload),
    signal:  AbortSignal.timeout(15000),
  });

  return {
    http_status: res.status,
    ok:          res.ok,
    body_preview: (await res.text()).slice(0, 300),
  };
}

// ── GET /api/integrations ─────────────────────────────────────────────────────
export async function handleListIntegrations(request, env, authCtx = {}) {
  const integrations = [];
  for (const [platformId, meta] of Object.entries(INTEGRATION_PLATFORMS)) {
    const config = await loadConfig(env, platformId);
    integrations.push({
      id:          platformId,
      label:       meta.label,
      icon:        meta.icon,
      description: meta.description,
      rule_format: meta.rule_format,
      docs_url:    meta.docs_url,
      field_label: meta.field_label,
      configured:  !!config?.webhook_url,
      enabled:     config?.enabled !== false && !!config?.webhook_url,
      last_deploy: config?.last_deploy || null,
      deploy_count: config?.deploy_count || 0,
    });
  }
  return ok(request, { integrations, total: integrations.length });
}

// ── POST /api/integrations/configure ─────────────────────────────────────────
export async function handleConfigure(request, env, authCtx = {}) {
  let body = {};
  try { body = await request.json(); } catch {}

  const { platform, webhook_url, auth_token, hec_token, api_key, integration_key, enabled = true } = body;

  if (!platform || !INTEGRATION_PLATFORMS[platform]) {
    return fail(request, 'Invalid or unsupported platform', 400, 'INVALID_PLATFORM');
  }
  if (!webhook_url && !integration_key) {
    return fail(request, 'webhook_url or integration_key is required', 400, 'MISSING_URL');
  }

  // Basic URL validation
  if (webhook_url) {
    try { new URL(webhook_url); } catch {
      return fail(request, 'Invalid webhook_url format', 400, 'INVALID_URL');
    }
  }

  const config = {
    platform,
    webhook_url:     webhook_url || '',
    auth_token:      auth_token  || null,
    hec_token:       hec_token   || null,
    api_key:         api_key     || null,
    integration_key: integration_key || null,
    enabled:         enabled,
    configured_at:   new Date().toISOString(),
    configured_by:   authCtx?.email || 'admin',
    deploy_count:    0,
    last_deploy:     null,
  };

  await saveConfig(env, platform, config);

  return ok(request, {
    message:    `${INTEGRATION_PLATFORMS[platform].label} configured successfully`,
    platform,
    configured: true,
  });
}

// ── POST /api/integrations/deploy ─────────────────────────────────────────────
export async function handleDeploy(request, env, authCtx = {}) {
  let body = {};
  try { body = await request.json(); } catch {}

  const { platform, rule, cve_id, severity, cvss, deploy_all } = body;

  if (!rule || (!rule.sigma && !rule.splunk && !rule.kql && !rule.yara && !rule.elastic && !rule.raw)) {
    return fail(request, 'rule object with at least one format (sigma/splunk/kql/yara/elastic/raw) is required', 400, 'MISSING_RULE');
  }

  const meta = { cve_id, severity: severity || 'HIGH', cvss: cvss || 8.0 };

  // Deploy to specific platform or all configured platforms
  const platformsToDeploy = deploy_all
    ? Object.keys(INTEGRATION_PLATFORMS)
    : [platform];

  if (!deploy_all && !platform) {
    return fail(request, 'platform is required when deploy_all is not set', 400, 'MISSING_PLATFORM');
  }

  const results = [];

  for (const pid of platformsToDeploy) {
    const config = await loadConfig(env, pid);
    if (!config?.webhook_url && !config?.integration_key) {
      if (!deploy_all) {
        return fail(request, `${pid} is not configured. Use POST /api/integrations/configure first.`, 400, 'NOT_CONFIGURED');
      }
      continue; // skip unconfigured in deploy_all mode
    }
    if (!config.enabled) continue;

    let deployResult;
    try {
      const payload = buildPayload(pid, rule, { ...meta, integration_key: config.integration_key, aws_account: config.aws_account });
      deployResult  = await deployToEndpoint(pid, config, payload);
    } catch (err) {
      deployResult = { http_status: 0, ok: false, body_preview: err.message };
    }

    // Update config stats
    const updatedConfig = { ...config, deploy_count: (config.deploy_count || 0) + 1, last_deploy: new Date().toISOString() };
    await saveConfig(env, pid, updatedConfig);

    // Log the deployment
    await appendDeployLog(env, {
      platform: pid,
      cve_id,
      severity,
      http_status: deployResult.http_status,
      success:     deployResult.ok,
      triggered_by: authCtx?.email || 'system',
    });

    results.push({
      platform:    pid,
      label:       INTEGRATION_PLATFORMS[pid]?.label,
      success:     deployResult.ok,
      http_status: deployResult.http_status,
      preview:     deployResult.body_preview,
    });
  }

  const successCount = results.filter(r => r.success).length;
  return ok(request, {
    deployed:    results.length,
    successful:  successCount,
    failed:      results.length - successCount,
    results,
    deployed_at: new Date().toISOString(),
  });
}

// ── POST /api/integrations/test ───────────────────────────────────────────────
export async function handleTestIntegration(request, env, authCtx = {}) {
  let body = {};
  try { body = await request.json(); } catch {}

  const { platform } = body;
  if (!platform || !INTEGRATION_PLATFORMS[platform]) {
    return fail(request, 'Invalid platform', 400, 'INVALID_PLATFORM');
  }

  const config = await loadConfig(env, platform);
  if (!config?.webhook_url && !config?.integration_key) {
    return fail(request, `${platform} is not configured`, 400, 'NOT_CONFIGURED');
  }

  const testRule = { raw: 'CYBERDUDEBIVASH MYTHOS connectivity test', sigma: 'title: Test\nstatus: test', kql: '// Test KQL', splunk: '| makeresults' };
  const testMeta = { cve_id: 'TEST-001', severity: 'LOW', cvss: 1.0 };

  let result;
  try {
    const payload = buildPayload(platform, testRule, { ...testMeta, integration_key: config.integration_key });
    result        = await deployToEndpoint(platform, config, payload);
  } catch (err) {
    result = { http_status: 0, ok: false, body_preview: err.message };
  }

  return ok(request, {
    platform,
    label:       INTEGRATION_PLATFORMS[platform]?.label,
    reachable:   result.ok || result.http_status < 500,
    http_status: result.http_status,
    message:     result.ok ? 'Connection successful' : `Connection failed (HTTP ${result.http_status})`,
    preview:     result.body_preview,
  });
}

// ── GET /api/integrations/deploy-log ─────────────────────────────────────────
export async function handleDeployLog(request, env, authCtx = {}) {
  const url   = new URL(request.url);
  const limit = Math.min(50, parseInt(url.searchParams.get('limit') || '20', 10));
  let log     = [];
  if (env?.SECURITY_HUB_KV) {
    try { log = (await env.SECURITY_HUB_KV.get(KV_LOG_KEY, { type: 'json' })) || []; } catch {}
  }
  return ok(request, { log: log.slice(0, limit), total: log.length });
}

// ── DELETE /api/integrations/:platform ───────────────────────────────────────
export async function handleDeleteIntegration(request, env, authCtx = {}) {
  const url      = new URL(request.url);
  const platform = url.pathname.split('/').pop();

  if (!INTEGRATION_PLATFORMS[platform]) {
    return fail(request, 'Invalid platform', 400, 'INVALID_PLATFORM');
  }
  await deleteConfig(env, platform);
  return ok(request, { message: `${platform} integration removed`, platform });
}
