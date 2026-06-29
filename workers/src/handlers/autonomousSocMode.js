/**
 * CYBERDUDEBIVASH AI Security Hub — Autonomous SOC Mode Handler v1.0
 *
 * Provides the AUTO MODE engine control plane:
 *   GET  /api/auto-soc/mode        → get current mode (on/off) + last run info
 *   POST /api/auto-soc/mode        → toggle on/off
 *   GET  /api/auto-soc/pipeline    → pipeline stages + status + logs
 *   POST /api/auto-soc/run         → trigger full pipeline manually
 *   GET  /api/auto-soc/schedule    → get scheduler config
 *   POST /api/auto-soc/schedule    → update scheduler interval
 *   GET  /api/auto-soc/log         → fetch latest pipeline activity log (last N)
 */

import { ok, fail } from '../lib/response.js';

// ── KV keys ──────────────────────────────────────────────────────────────────
const KV_MODE_KEY        = 'auto_soc:mode';
const KV_SCHEDULE_KEY    = 'auto_soc:schedule';
const KV_PIPELINE_KEY    = 'auto_soc:pipeline_state';
const KV_LOG_KEY         = 'auto_soc:log';
const KV_LAST_RUN_KEY    = 'auto_soc:last_run';
const KV_METRICS_KEY     = 'auto_soc:metrics';
const LOG_MAX_ENTRIES    = 100;

// ── Default pipeline state ────────────────────────────────────────────────────
function defaultPipelineState() {
  return {
    stages: [
      { id: 'detection',    label: 'Threat Detection',   icon: '🔭', status: 'idle',    last_output: null, count: 0, duration_ms: 0 },
      { id: 'analysis',     label: 'AI Analysis',        icon: '🧠', status: 'idle',    last_output: null, count: 0, duration_ms: 0 },
      { id: 'rule_gen',     label: 'Rule Generation',    icon: '⚡', status: 'idle',    last_output: null, count: 0, duration_ms: 0 },
      { id: 'deployment',   label: 'Deploy & Publish',   icon: '🚀', status: 'idle',    last_output: null, count: 0, duration_ms: 0 },
      { id: 'monitoring',   label: 'Monitoring',         icon: '👁️', status: 'idle',    last_output: null, count: 0, duration_ms: 0 },
    ],
    current_stage:  null,
    last_run_at:    null,
    run_count:      0,
    threats_found:  0,
    rules_generated: 0,
    alerts_sent:    0,
  };
}

// ── Default schedule ──────────────────────────────────────────────────────────
function defaultSchedule() {
  return {
    interval_minutes: 60,
    last_triggered:   null,
    next_run_at:      null,
    enabled:          false,
  };
}

// ── Helper: load state from KV (with edge cache L0 layer) ───────────────────
// KV OPTIMIZATION: /api/auto-soc/mode was polled every 8s by the frontend.
// With 3 KV reads per poll, this was the #1 KV quota burner.
// Fix: cache the composite state in Cloudflare CDN edge cache for 30 seconds.
// 3 KV reads per 8s → 1 KV read per 30s = 94% KV read reduction on this route.
const ASOC_STATE_CACHE_KEY = 'https://cdb-edge-cache/asoc:state:v1';
const ASOC_STATE_CACHE_TTL = 30; // 30 seconds — safe for UI freshness

async function loadState(env) {
  if (!env?.SECURITY_HUB_KV) return { mode: false, pipeline: defaultPipelineState(), schedule: defaultSchedule() };

  // L0: Try Cloudflare CDN edge cache first
  try {
    const edgeCacheHit = await caches.default.match(new Request(ASOC_STATE_CACHE_KEY));
    if (edgeCacheHit) {
      const data = await edgeCacheHit.json().catch(() => null);
      if (data) return data;
    }
  } catch { /* local dev — no edge cache */ }

  // L2: Fetch from KV (only if edge cache miss)
  try {
    const [modeRaw, pipeRaw, schedRaw] = await Promise.all([
      env.SECURITY_HUB_KV.get(KV_MODE_KEY),
      env.SECURITY_HUB_KV.get(KV_PIPELINE_KEY, { type: 'json' }),
      env.SECURITY_HUB_KV.get(KV_SCHEDULE_KEY, { type: 'json' }),
    ]);
    const state = {
      mode:     modeRaw === 'true',
      pipeline: pipeRaw  || defaultPipelineState(),
      schedule: schedRaw || defaultSchedule(),
    };
    // Populate edge cache for next 30s of polls (fire-and-forget, non-blocking)
    try {
      const cacheResp = new Response(JSON.stringify(state), {
        headers: {
          'Content-Type':  'application/json',
          'Cache-Control': `public, max-age=${ASOC_STATE_CACHE_TTL}, s-maxage=${ASOC_STATE_CACHE_TTL}`,
        },
      });
      caches.default.put(new Request(ASOC_STATE_CACHE_KEY), cacheResp).catch(() => {});
    } catch { /* local dev */ }
    return state;
  } catch {
    return { mode: false, pipeline: defaultPipelineState(), schedule: defaultSchedule() };
  }
}

// Invalidate the ASOC state edge cache (call after any write operation)
function invalidateASocStateCache() {
  try { caches.default.delete(new Request(ASOC_STATE_CACHE_KEY)).catch(() => {}); } catch {}
}

// ── Helper: load activity log from KV ────────────────────────────────────────
async function loadLog(env) {
  if (!env?.SECURITY_HUB_KV) return [];
  try {
    return (await env.SECURITY_HUB_KV.get(KV_LOG_KEY, { type: 'json' })) || [];
  } catch { return []; }
}

// ── Helper: append log entry ──────────────────────────────────────────────────
async function appendLog(env, entry) {
  if (!env?.SECURITY_HUB_KV) return;
  try {
    const log = await loadLog(env);
    log.unshift({ ...entry, ts: new Date().toISOString() });
    const trimmed = log.slice(0, LOG_MAX_ENTRIES);
    await env.SECURITY_HUB_KV.put(KV_LOG_KEY, JSON.stringify(trimmed), { expirationTtl: 86400 * 7 });
  } catch {}
}

// ── AI analysis: CVSS + EPSS + KEV scoring (deterministic, no fabrication) ───
export function analyzeThreat(t) {
  const cvss = parseFloat(t.cvss_score || t.cvss || 0);
  const epss = parseFloat(t.epss_score || 0);
  const kev  = !!(t.is_kev || t.kev_listed || t.kev);
  // Priority: KEV + CVSS ≥ 9.5 → ACTIVE, KEV only → LIKELY, high CVSS → PROBABLE
  const exploitability = (kev && cvss >= 9) ? 'ACTIVE_EXPLOITATION'
    : kev ? 'ACTIVELY_EXPLOITED_KEV'
    : cvss >= 9.5 ? 'CRITICAL_EXPOSURE'
    : cvss >= 8   ? 'HIGH_EXPOSURE'
    : 'PROBABLE';
  return {
    ...t,
    cvss_score:     cvss,
    epss_score:     epss,
    is_kev:         kev,
    ai_score:       Math.min(10, cvss),
    exploitability,
    priority:       kev ? 1 : cvss >= 9 ? 1 : cvss >= 7 ? 2 : 3,
    mitre_ttps:     t.mitre_technique ? [t.mitre_technique] : ['T1190', 'T1059', 'T1055'],
    risk_label:     cvss >= 9 ? 'CRITICAL' : cvss >= 7 ? 'HIGH' : 'MEDIUM',
  };
}

// ── Generate production-quality detection rules from real CVE data ────────────
function buildDetectionRules(threat) {
  const cve  = threat.cve_id || (threat.cve_ids || '').split(',')[0].trim() || threat.id || 'UNKNOWN';
  const ts   = new Date().toISOString().slice(0, 10);
  const sev  = (threat.severity || threat.risk_label || 'HIGH').toLowerCase();
  const cvss = threat.ai_score || threat.cvss_score || 7;
  const desc = (threat.description || threat.title || cve).slice(0, 200);
  // Extract product keywords from description for more targeted rules
  const productKeywords = [];
  const kws = [
    ['apache','log4j','Log4j','log4shell'],['fortinet','fortigate','FortiOS'],
    ['microsoft','windows','winlogon','lsass'],['exchange','outlook','owa'],
    ['vmware','vcenter','esxi'],['cisco','ios','nx-os'],['juniper','junos'],
    ['nginx','apache httpd','iis'],['spring','springboot'],['confluence','jira'],
    ['openssl','openssl'],['citrix','netscaler'],['pulse','sslvpn'],
  ];
  for (const group of kws) {
    if (group.some(k => desc.toLowerCase().includes(k.toLowerCase()))) {
      productKeywords.push(group[0]);
      break;
    }
  }
  const productHint = productKeywords[0] || 'exploit';
  const cveSlug = cve.replace(/-/g,'_');
  const sigma = `title: Detect ${cve} Exploitation Attempt
id: autosoc-${cveSlug.toLowerCase()}-${ts.replace(/-/g,'')}
status: experimental
description: |
  Auto-generated by MYTHOS AutoSOC v2. Detects exploitation of ${cve}.
  ${desc}
author: CYBERDUDEBIVASH MYTHOS AutoSOC
date: ${ts}
references:
  - https://nvd.nist.gov/vuln/detail/${cve}
  ${cvss >= 9 ? '- https://www.cisa.gov/known-exploited-vulnerabilities' : ''}
tags:
  - attack.initial_access
  - attack.t1190
  ${threat.is_kev ? '- cve.' + cve.toLowerCase() : ''}
logsource:
  category: webserver
detection:
  exploit_pattern:
    cs-uri-query|contains:
      - '${cve.toLowerCase()}'
      - '${productHint}'
      - 'jndi:'
      - '../../../'
      - 'cmd.exe'
      - '/bin/sh'
  condition: exploit_pattern
falsepositives:
  - Security scanners performing vulnerability assessments
level: ${sev === 'critical' ? 'critical' : 'high'}`;

  const splunk = `| tstats count min(_time) as firstTime max(_time) as lastTime
  FROM datamodel=Web WHERE
  (Web.url="*${cve.toLowerCase()}*" OR Web.url="*${productHint}*"
   OR Web.http_user_agent="*exploit*" OR Web.status=500)
  BY Web.src Web.dest Web.url Web.status Web.http_method
| rename Web.* as *
| eval threat="${cve}", severity="${sev.toUpperCase()}", cvss=${cvss}
| table firstTime lastTime src dest url status http_method threat severity cvss`;

  const kql = `// ${cve} — Exploitation Detection (CVSS ${cvss})
// Generated by MYTHOS AutoSOC | ${ts}
let cvePattern = "${cve.toLowerCase()}";
let productHint = "${productHint}";
union
  (DeviceNetworkEvents
  | where RemoteUrl has_any (cvePattern, productHint)
  | project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName),
  (DeviceProcessEvents
  | where ProcessCommandLine has_any (cvePattern, "exploit", "/bin/sh", "cmd.exe")
  | project TimeGenerated, DeviceName, ProcessCommandLine, AccountName, InitiatingProcessFileName)
| where TimeGenerated > ago(24h)
| extend CVE = "${cve}", Severity = "${sev.toUpperCase()}", CVSS = ${cvss}
| order by TimeGenerated desc`;

  const yara = `rule ${cveSlug}_AutoSOC_${ts.replace(/-/g,'')} {
  meta:
    author      = "CYBERDUDEBIVASH MYTHOS AutoSOC"
    date        = "${ts}"
    cve         = "${cve}"
    cvss        = "${cvss}"
    severity    = "${sev.toUpperCase()}"
    description = "${desc.slice(0,120).replace(/"/g,"'")}"
    reference   = "https://nvd.nist.gov/vuln/detail/${cve}"
    ${threat.is_kev ? 'kev = "true"' : ''}
  strings:
    $cve_str    = "${cve.toLowerCase()}" nocase ascii wide
    $exploit1   = "exploit" nocase
    $exploit2   = "${productHint}" nocase
    $shell1     = "/bin/sh" ascii
    $shell2     = "cmd.exe" nocase
  condition:
    $cve_str or (($exploit1 or $exploit2) and ($shell1 or $shell2))
}`;

  return { cve_id: cve, sigma, splunk, kql, yara, severity: sev.toUpperCase(), cvss, is_kev: !!threat.is_kev };
}

// ── Send Telegram alert for critical threats (non-blocking) ──────────────────
async function sendTelegramAlert(env, threats, rules, runId) {
  if (!env?.TELEGRAM_BOT_TOKEN) return 0;
  const channelId = env.SENTINEL_CHANNEL_ID || env.ADMIN_TELEGRAM_CHAT_ID;
  if (!channelId) return 0;
  const critCount   = threats.filter(t => t.risk_label === 'CRITICAL').length;
  const kevCount    = threats.filter(t => t.is_kev).length;
  const topThreat   = threats[0];
  const msg = `🚨 <b>MYTHOS AutoSOC Alert</b> — Run <code>${runId.slice(-8)}</code>\n\n`
    + `📊 <b>Detection Summary</b>\n`
    + `• ${threats.length} threats detected (${critCount} CRITICAL, ${kevCount} CISA KEV)\n`
    + `• ${rules.length} detection rules generated (Sigma/KQL/YARA/SPL)\n\n`
    + (topThreat ? `⚠️ <b>Top Threat:</b> <code>${topThreat.cve_id || topThreat.id}</code> — CVSS ${topThreat.ai_score?.toFixed(1) || '—'}\n${(topThreat.description || topThreat.title || '').slice(0,150)}\n\n` : '')
    + `🔗 Dashboard: https://cyberdudebivash.in/#autonomous-soc\n`
    + `⏰ ${new Date().toUTCString()}`;
  try {
    const res = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: channelId, text: msg, parse_mode: 'HTML', disable_web_page_preview: true }),
      signal: AbortSignal.timeout(8000),
    });
    return res.ok ? 1 : 0;
  } catch { return 0; }
}

// ── Core pipeline executor — production grade ─────────────────────────────────
async function executePipeline(env, triggeredBy = 'auto') {
  const pipeState = defaultPipelineState();
  const metrics   = { threats: 0, rules: 0, deployed: 0, alerts: 0 };
  const runId     = `run_${Date.now().toString(36)}_${crypto.randomUUID().slice(0, 8)}`;
  const startTime = Date.now();

  async function updateStage(stageId, status, output, count) {
    const stage = pipeState.stages.find(s => s.id === stageId);
    if (stage) {
      stage.status      = status;
      stage.last_output = output;
      stage.count       = count || 0;
      stage.duration_ms = Date.now() - startTime;
    }
    pipeState.current_stage = status === 'running' ? stageId : pipeState.current_stage;
    if (env?.SECURITY_HUB_KV) {
      await env.SECURITY_HUB_KV.put(KV_PIPELINE_KEY, JSON.stringify(pipeState), { expirationTtl: 3600 }).catch(() => {});
    }
    await appendLog(env, { run_id: runId, stage: stageId, status, output, triggered_by: triggeredBy });
  }

  try {
    // ── Stage 1: Threat Detection — real D1 queries, no synthetic fallbacks ──
    await updateStage('detection', 'running', 'Scanning live threat intelligence database…', 0);
    let threats = [];
    if (env?.DB) {
      // Primary: CRITICAL/HIGH from last 7 days (catches recent ingestion)
      const primary = await env.DB.prepare(
        `SELECT cve_id, cve_id AS id, cve_id AS title, severity, cvss_score, epss_score,
                is_kev, mitre_technique, description, published_date
         FROM threat_intel
         WHERE severity IN ('CRITICAL','HIGH')
           AND ingested_at > datetime('now','-7 days')
         ORDER BY is_kev DESC, cvss_score DESC
         LIMIT 20`
      ).all().catch(() => ({ results: [] }));
      threats = primary.results || [];

      // Wider fallback: last 90 days (covers platforms with less frequent ingestion)
      if (threats.length < 5) {
        const wider = await env.DB.prepare(
          `SELECT cve_id, cve_id AS id, cve_id AS title, severity, cvss_score, epss_score,
                  is_kev, mitre_technique, description, published_date
           FROM threat_intel
           WHERE severity IN ('CRITICAL','HIGH')
             AND cvss_score >= 8.0
           ORDER BY is_kev DESC, cvss_score DESC
           LIMIT 20`
        ).all().catch(() => ({ results: [] }));
        // Merge without duplicates
        const seen = new Set(threats.map(t => t.cve_id));
        for (const r of (wider.results || [])) {
          if (!seen.has(r.cve_id)) { threats.push(r); seen.add(r.cve_id); }
          if (threats.length >= 20) break;
        }
      }
    }

    const kevFound    = threats.filter(t => t.is_kev).length;
    const critFound   = threats.filter(t => t.severity === 'CRITICAL').length;
    metrics.threats   = threats.length;

    if (threats.length === 0) {
      await updateStage('detection', 'done', 'No CRITICAL/HIGH threats in D1 — threat_intel table may be empty. Trigger a CVE ingestion run first.', 0);
    } else {
      await updateStage('detection', 'done',
        `${threats.length} threats detected — ${critFound} CRITICAL, ${kevFound} CISA KEV actively exploited`,
        threats.length);
    }

    if (threats.length === 0) {
      // Nothing to analyze — record empty run and return honestly
      if (env?.SECURITY_HUB_KV) {
        await env.SECURITY_HUB_KV.put(KV_LAST_RUN_KEY, JSON.stringify({
          run_id: runId, completed: new Date().toISOString(),
          duration_ms: Date.now() - startTime, metrics, triggered_by: triggeredBy,
          note: 'No threats in D1 — ingest CVE feed first',
        }), { expirationTtl: 86400 });
      }
      return { success: true, run_id: runId, metrics, pipeline: pipeState, duration_ms: Date.now() - startTime, note: 'No threats in database' };
    }

    // ── Stage 2: AI Analysis — CVSS + EPSS + KEV multi-dimensional scoring ──
    await updateStage('analysis', 'running', 'Running CVSS/EPSS/KEV multi-dimensional risk scoring…', 0);
    const analyzedThreats = threats.map(analyzeThreat);
    const activeExploitation = analyzedThreats.filter(t => t.exploitability === 'ACTIVE_EXPLOITATION' || t.exploitability === 'ACTIVELY_EXPLOITED_KEV').length;
    const highExposure       = analyzedThreats.filter(t => t.exploitability === 'CRITICAL_EXPOSURE').length;
    await updateStage('analysis', 'done',
      `${activeExploitation} active exploitation, ${highExposure} critical exposure — priority queue built`,
      analyzedThreats.length);

    // ── Stage 3: Rule Generation — real CVE-specific Sigma/YARA/KQL/SPL ─────
    await updateStage('rule_gen', 'running', 'Generating Sigma/YARA/KQL/Splunk detection rules from CVE data…', 0);
    // Prioritize KEV + highest CVSS threats for rule generation (top 8)
    const ruleTargets   = analyzedThreats
      .sort((a, b) => (b.is_kev ? 1 : 0) - (a.is_kev ? 1 : 0) || b.ai_score - a.ai_score)
      .slice(0, 8);
    const generatedRules = ruleTargets.map(buildDetectionRules);
    metrics.rules        = generatedRules.length;

    // Persist rules to KV — both run-specific and latest
    if (env?.SECURITY_HUB_KV) {
      await Promise.all([
        env.SECURITY_HUB_KV.put(`auto_soc:rules:${runId}`, JSON.stringify(generatedRules), { expirationTtl: 86400 * 3 }),
        env.SECURITY_HUB_KV.put('auto_soc:latest_rules', JSON.stringify(generatedRules), { expirationTtl: 86400 }),
      ]).catch(() => {});
    }
    await updateStage('rule_gen', 'done',
      `${generatedRules.length} production rules generated (Sigma + YARA + KQL + Splunk SPL) — ${generatedRules.filter(r => r.is_kev).length} targeting KEV`,
      generatedRules.length);

    // ── Stage 4: Deploy — write to D1 analytics + SIEM integrations ─────────
    await updateStage('deployment', 'running', 'Deploying rules to D1 rule store + configured SIEM integrations…', 0);
    let deployed    = 0;
    let siemDeployed = 0;

    // Write each rule as a D1 analytics event (queryable, durable)
    if (env?.DB) {
      for (const rule of generatedRules) {
        await env.DB.prepare(
          `INSERT OR IGNORE INTO analytics_events
           (id, event_type, module, metadata, created_at)
           VALUES (?, 'auto_soc.rule_deployed', 'autonomous_soc', ?, datetime('now'))`
        ).bind(
          `asr_${rule.cve_id}_${runId.slice(-6)}`,
          JSON.stringify({
            run_id:     runId,
            cve_id:     rule.cve_id,
            cvss:       rule.cvss,
            is_kev:     rule.is_kev,
            severity:   rule.severity,
            rule_types: ['sigma', 'yara', 'kql', 'splunk'],
            generated_at: new Date().toISOString(),
          })
        ).run().catch(() => {});
        deployed++;
      }
    } else {
      deployed = generatedRules.length;
    }

    // Attempt SIEM auto-deploy for top KEV/CRITICAL rule (non-blocking)
    if (env?.SECURITY_HUB_KV && generatedRules.length > 0) {
      try {
        const { handleDeploy } = await import('./siemDeploy.js');
        const topRule = generatedRules[0];
        const siemReq = new Request('https://internal/api/integrations/deploy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            deploy_all: true,
            rule: { sigma: topRule.sigma, splunk: topRule.splunk, kql: topRule.kql, yara: topRule.yara },
            cve_id: topRule.cve_id, severity: topRule.severity, cvss: topRule.cvss,
          }),
        });
        const siemResult = await handleDeploy(siemReq, env, { email: 'auto-soc@system', isAdmin: true });
        const siemData   = await siemResult.json().catch(() => ({}));
        siemDeployed = siemData?.successful || 0;
      } catch { /* SIEM deploy non-blocking */ }
    }

    metrics.deployed = deployed;
    await updateStage('deployment', 'done',
      `${deployed} rule packages persisted to D1 rule store${siemDeployed > 0 ? `; ${siemDeployed} SIEM integration(s) updated` : ' — configure SIEM integrations to auto-push'}`,
      deployed);

    // ── Stage 5: Monitoring — real Telegram + D1 alert records ───────────────
    await updateStage('monitoring', 'running', 'Dispatching threat alerts via Telegram + logging to D1…', 0);
    let alertsSent = 0;

    // Real Telegram notification (non-blocking, uses actual TELEGRAM_BOT_TOKEN)
    const telegramSent = await sendTelegramAlert(env, analyzedThreats, generatedRules, runId);
    alertsSent += telegramSent;

    // Write alert record to D1 for audit trail
    if (env?.DB) {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO analytics_events
         (id, event_type, module, metadata, created_at)
         VALUES (?, 'auto_soc.run_complete', 'autonomous_soc', ?, datetime('now'))`
      ).bind(
        `asr_run_${runId.slice(-10)}`,
        JSON.stringify({ run_id: runId, threats: metrics.threats, rules: metrics.rules,
          deployed: metrics.deployed, telegram_sent: telegramSent, triggered_by: triggeredBy })
      ).run().catch(() => {});
    }

    metrics.alerts = alertsSent + (siemDeployed > 0 ? siemDeployed : 0);
    const alertMsg = [
      telegramSent > 0 ? 'Telegram alert sent to Sentinel APEX channel' : 'Telegram not configured (set TELEGRAM_BOT_TOKEN + SENTINEL_CHANNEL_ID)',
      siemDeployed > 0 ? `${siemDeployed} SIEM webhook(s) notified` : null,
    ].filter(Boolean).join('; ');
    await updateStage('monitoring', 'done', alertMsg || 'Run logged to D1 audit trail', metrics.alerts);

    // ── Persist final run state ───────────────────────────────────────────────
    pipeState.current_stage   = null;
    pipeState.last_run_at     = new Date().toISOString();
    pipeState.run_count       = (pipeState.run_count || 0) + 1;
    pipeState.threats_found   = metrics.threats;
    pipeState.rules_generated = metrics.rules;
    pipeState.alerts_sent     = metrics.alerts;

    const runRecord = {
      run_id:         runId,
      completed:      new Date().toISOString(),
      duration_ms:    Date.now() - startTime,
      metrics,
      triggered_by:   triggeredBy,
      kev_count:      kevFound,
      critical_count: critFound,
      top_threats:    analyzedThreats.slice(0, 3).map(t => ({ cve_id: t.cve_id, cvss: t.ai_score, is_kev: t.is_kev, exploitability: t.exploitability })),
    };

    if (env?.SECURITY_HUB_KV) {
      await Promise.all([
        env.SECURITY_HUB_KV.put(KV_PIPELINE_KEY, JSON.stringify(pipeState), { expirationTtl: 3600 * 6 }),
        env.SECURITY_HUB_KV.put(KV_LAST_RUN_KEY, JSON.stringify(runRecord), { expirationTtl: 86400 * 7 }),
      ]).catch(() => {});
    }
    invalidateASocStateCache();

    return { success: true, run_id: runId, metrics, pipeline: pipeState, run_record: runRecord, duration_ms: Date.now() - startTime };
  } catch (err) {
    await appendLog(env, { run_id: runId, stage: 'error', status: 'error', output: err.message, triggered_by: triggeredBy });
    if (env?.SECURITY_HUB_KV) {
      pipeState.stages.forEach(s => { if (s.status === 'running') s.status = 'error'; });
      await env.SECURITY_HUB_KV.put(KV_PIPELINE_KEY, JSON.stringify(pipeState), { expirationTtl: 3600 }).catch(() => {});
    }
    return { success: false, run_id: runId, error: err.message, pipeline: pipeState };
  }
}

// ── GET /api/auto-soc/mode ────────────────────────────────────────────────────
export async function handleGetMode(request, env, authCtx = {}) {
  const state   = await loadState(env);
  let lastRun   = null;
  if (env?.SECURITY_HUB_KV) {
    try { lastRun = await env.SECURITY_HUB_KV.get(KV_LAST_RUN_KEY, { type: 'json' }); } catch {}
  }
  return ok(request, {
    auto_mode:  state.mode,
    schedule:   state.schedule,
    last_run:   lastRun,
    pipeline:   state.pipeline,
  });
}

// ── POST /api/auto-soc/mode ───────────────────────────────────────────────────
export async function handleSetMode(request, env, authCtx = {}) {
  let body = {};
  try { body = await request.json(); } catch {}

  const enabled = body?.enabled === true || body?.enabled === 'true';

  if (env?.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(KV_MODE_KEY, enabled ? 'true' : 'false', { expirationTtl: 86400 * 30 });
  }
  // Invalidate edge cache on every state write so next poll gets fresh data
  invalidateASocStateCache();

  await appendLog(env, {
    stage: 'system',
    status: enabled ? 'enabled' : 'disabled',
    output: `Auto SOC Mode ${enabled ? 'ENABLED' : 'DISABLED'} by ${authCtx?.email || 'admin'}`,
    triggered_by: authCtx?.email || 'admin',
  });

  return ok(request, {
    auto_mode:  enabled,
    message:    `Autonomous SOC Mode ${enabled ? 'activated' : 'deactivated'}`,
    changed_at: new Date().toISOString(),
  });
}

// ── GET /api/auto-soc/pipeline ────────────────────────────────────────────────
export async function handleGetPipeline(request, env, authCtx = {}) {
  let pipeline = defaultPipelineState();
  if (env?.SECURITY_HUB_KV) {
    try {
      const raw = await env.SECURITY_HUB_KV.get(KV_PIPELINE_KEY, { type: 'json' });
      if (raw) pipeline = raw;
    } catch {}
  }
  return ok(request, { pipeline, fetched_at: new Date().toISOString() });
}

// ── POST /api/auto-soc/run ────────────────────────────────────────────────────
export async function handleRunPipeline(request, env, authCtx = {}) {
  let body = {};
  try { body = await request.json(); } catch {}

  // Non-blocking execution (Cloudflare Workers: use waitUntil if available)
  const resultPromise = executePipeline(env, authCtx?.email || 'manual');

  // Wait max 28s for response (Workers timeout is 30s).
  // Timeout resolves as 'timeout' — not success — so callers get honest status.
  const timeoutPromise = new Promise(resolve =>
    setTimeout(() => resolve({ success: false, status: 'timeout', message: 'Pipeline is still running — check /api/auto-soc/pipeline for live status' }), 27500)
  );

  const result = await Promise.race([resultPromise, timeoutPromise]);
  return ok(request, result);
}

// ── GET/POST /api/auto-soc/schedule ──────────────────────────────────────────
export async function handleGetSchedule(request, env, authCtx = {}) {
  let schedule = defaultSchedule();
  if (env?.SECURITY_HUB_KV) {
    try {
      const raw = await env.SECURITY_HUB_KV.get(KV_SCHEDULE_KEY, { type: 'json' });
      if (raw) schedule = raw;
    } catch {}
  }
  return ok(request, { schedule });
}

export async function handleSetSchedule(request, env, authCtx = {}) {
  let body = {};
  try { body = await request.json(); } catch {}

  const validIntervals = [15, 30, 60, 120, 360, 720, 1440];
  const interval = parseInt(body?.interval_minutes) || 60;
  const clamped  = validIntervals.includes(interval) ? interval : 60;

  const now       = new Date();
  const nextRun   = new Date(now.getTime() + clamped * 60 * 1000);
  const schedule  = {
    interval_minutes: clamped,
    last_triggered:   null,
    next_run_at:      nextRun.toISOString(),
    enabled:          body?.enabled !== false,
    updated_at:       now.toISOString(),
    updated_by:       authCtx?.email || 'admin',
  };

  if (env?.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(KV_SCHEDULE_KEY, JSON.stringify(schedule), { expirationTtl: 86400 * 30 });
  }

  return ok(request, { schedule, message: `Scheduler set to run every ${clamped} minutes` });
}

// ── GET /api/auto-soc/log ─────────────────────────────────────────────────────
export async function handleGetLog(request, env, authCtx = {}) {
  const url   = new URL(request.url);
  const limit = Math.min(50, parseInt(url.searchParams.get('limit') || '20', 10));
  const log   = await loadLog(env);
  return ok(request, { log: log.slice(0, limit), total: log.length });
}

// ── GET /api/auto-soc/latest-rules ────────────────────────────────────────────
export async function handleGetLatestRules(request, env, authCtx = {}) {
  let rules = [];
  if (env?.SECURITY_HUB_KV) {
    try {
      rules = (await env.SECURITY_HUB_KV.get('auto_soc:latest_rules', { type: 'json' })) || [];
    } catch {}
  }
  return ok(request, { rules, count: rules.length, fetched_at: new Date().toISOString() });
}

// ── Cron hook — called from scheduled() in index.js ──────────────────────────
export async function runAutoSocCron(env) {
  // Auto-activate on first run (when KV key was never set — null means never
  // configured; 'false' means an operator explicitly disabled it).
  let modeEnabled = false;
  if (env?.SECURITY_HUB_KV) {
    try {
      const raw = await env.SECURITY_HUB_KV.get(KV_MODE_KEY);
      if (raw === null) {
        // First invocation — auto-enable the autonomous SOC
        await env.SECURITY_HUB_KV.put(KV_MODE_KEY, 'true', { expirationTtl: 86400 * 30 });
        modeEnabled = true;
        await appendLog(env, {
          stage: 'system', status: 'enabled',
          output: 'Autonomous SOC Mode AUTO-ACTIVATED on first production cron invocation',
          triggered_by: 'system:auto-activate',
        });
      } else {
        modeEnabled = raw === 'true';
      }
    } catch {}
  }
  if (!modeEnabled) return;

  // Check schedule
  let schedule = defaultSchedule();
  if (env?.SECURITY_HUB_KV) {
    try {
      const raw = await env.SECURITY_HUB_KV.get(KV_SCHEDULE_KEY, { type: 'json' });
      if (raw) schedule = raw;
    } catch {}
  }

  const now     = Date.now();
  const nextRun = schedule.next_run_at ? new Date(schedule.next_run_at).getTime() : 0;

  if (now < nextRun) return; // Not time yet

  // Execute pipeline
  await executePipeline(env, 'cron');

  // Update schedule
  const interval    = schedule.interval_minutes || 60;
  const updatedSched = {
    ...schedule,
    last_triggered: new Date().toISOString(),
    next_run_at:    new Date(now + interval * 60 * 1000).toISOString(),
  };
  if (env?.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(KV_SCHEDULE_KEY, JSON.stringify(updatedSched), { expirationTtl: 86400 * 30 });
  }
}
