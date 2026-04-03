/**
 * CYBERDUDEBIVASH AI Security Hub — Alert Engine v5.0
 * Real-time security alerts via Telegram Bot + Email
 * Async, retry-safe, user-configurable per-account settings
 *
 * Channels: Telegram Bot API | Cloudflare Email Workers (SMTP relay)
 * Triggers: high_risk_scan | blacklist_detected | critical_cve
 */

const CONTACT_EMAIL     = 'bivash@cyberdudebivash.com';
const PLATFORM_URL      = 'https://tools.cyberdudebivash.com';
const TELEGRAM_API_BASE = 'https://api.telegram.org/bot';
const ALERT_TIMEOUT     = 6000; // 6s per alert delivery

// ─── Safe fetch for external alert APIs ──────────────────────────────────────
async function safeFetch(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ALERT_TIMEOUT);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timer);
    return { ok: res.ok, status: res.status };
  } catch {
    clearTimeout(timer);
    return { ok: false, status: 0, error: 'timeout_or_network' };
  }
}

// ─── Format risk emoji ────────────────────────────────────────────────────────
function riskEmoji(level) {
  return { CRITICAL:'🚨', HIGH:'🔴', MEDIUM:'🟡', LOW:'🟢' }[level] ?? '⚪';
}

// ─── Build Telegram message ───────────────────────────────────────────────────
function buildTelegramMessage(scanResult, triggerType, extra = {}) {
  const emoji  = riskEmoji(scanResult.risk_level);
  const target = scanResult.target ?? 'unknown';
  const module = (scanResult.module ?? 'scan').replace('_scanner','');
  const score  = scanResult.risk_score ?? 0;
  const level  = scanResult.risk_level ?? 'UNKNOWN';
  const grade  = scanResult.grade ?? 'N/A';
  const ts     = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false });

  let header = '';
  let body   = '';

  switch (triggerType) {
    case 'high_risk_scan':
      header = `${emoji} *HIGH RISK SCAN ALERT*`;
      body   = `*Target:* \`${target}\`\n*Module:* ${module}\n*Risk Score:* ${score}/100 (${level})\n*Grade:* ${grade}`;
      break;
    case 'blacklist_detected':
      header = `🚫 *BLACKLIST DETECTION ALERT*`;
      body   = `*Target:* \`${target}\`\n*Listed on:* ${extra.feeds_count ?? '?'} threat feeds\n*Risk Score:* ${score}/100`;
      break;
    case 'critical_cve':
      header = `⚡ *CRITICAL CVE MATCH*`;
      body   = `*CVE:* \`${extra.cve_id ?? 'unknown'}\`\n*CVSS:* ${extra.cvss ?? 'N/A'}\n*Affected:* ${extra.affected ?? 'unknown'}`;
      break;
    default:
      header = `🔔 *SECURITY ALERT*`;
      body   = `*Target:* \`${target}\`\n*Risk:* ${level}`;
  }

  // Top critical findings (max 3)
  const critFindings = (scanResult.findings ?? [])
    .filter(f => ['CRITICAL','HIGH'].includes(f.severity))
    .slice(0, 3)
    .map(f => `• *${f.id}* ${f.severity} — ${f.title}`)
    .join('\n');

  const findingsBlock = critFindings ? `\n\n*Top Findings:*\n${critFindings}` : '';
  const footer = `\n\n🕐 ${ts} IST\n[View Full Report](${PLATFORM_URL}) | [Sentinel APEX](https://t.me/cyberdudebivashSentinelApex)`;

  return `${header}\n\n${body}${findingsBlock}${footer}`;
}

// ─── Send Telegram message ────────────────────────────────────────────────────
async function sendTelegramAlert(botToken, chatId, text) {
  const url  = `${TELEGRAM_API_BASE}${botToken}/sendMessage`;
  const body = JSON.stringify({
    chat_id:    chatId,
    text,
    parse_mode: 'Markdown',
    disable_web_page_preview: true,
  });

  for (let attempt = 1; attempt <= 3; attempt++) {
    const res = await safeFetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
    if (res.ok) return { success: true, channel: 'telegram', attempt };
    if (res.status === 429) {
      await new Promise(r => setTimeout(r, attempt * 1000)); // backoff
      continue;
    }
    return { success: false, channel: 'telegram', status: res.status, attempt };
  }
  return { success: false, channel: 'telegram', error: 'max_retries' };
}

// ─── Send Email via Cloudflare Email Workers ──────────────────────────────────
// Requires Email Workers binding — falls back gracefully if not configured
async function sendEmailAlert(env, toEmail, subject, body) {
  if (!env?.EMAIL_SENDER) return { success: false, channel: 'email', error: 'email_worker_not_configured' };
  try {
    const message = {
      from: { email: 'alerts@cyberdudebivash.com', name: 'CYBERDUDEBIVASH Security Hub' },
      to:   [{ email: toEmail }],
      subject,
      content: [{ type: 'text/plain', value: body }],
    };
    await env.EMAIL_SENDER.send(message);
    return { success: true, channel: 'email' };
  } catch (e) {
    return { success: false, channel: 'email', error: e?.message };
  }
}

// ─── Build plain-text email body ──────────────────────────────────────────────
function buildEmailBody(scanResult, triggerType, extra = {}) {
  const target = scanResult.target ?? 'unknown';
  const score  = scanResult.risk_score ?? 0;
  const level  = scanResult.risk_level ?? 'UNKNOWN';
  const grade  = scanResult.grade ?? 'N/A';
  const ts     = new Date().toISOString();

  const findings = (scanResult.findings ?? [])
    .filter(f => ['CRITICAL','HIGH'].includes(f.severity))
    .slice(0, 5)
    .map(f => `  [${f.severity}] ${f.id} — ${f.title}\n  ${(f.description||'').slice(0,100)}`)
    .join('\n\n');

  return `
CYBERDUDEBIVASH AI Security Hub — Security Alert
================================================

Alert Type: ${triggerType.replace(/_/g,' ').toUpperCase()}
Target:     ${target}
Risk Score: ${score}/100 (${level})
Grade:      ${grade}
Timestamp:  ${ts}

${findings ? `TOP FINDINGS:\n${findings}\n` : ''}
---
View full report: ${PLATFORM_URL}
Contact support:  ${CONTACT_EMAIL}
Sentinel APEX:    https://t.me/cyberdudebivashSentinelApex

This alert was triggered by your configured security monitoring rules.
To manage alerts, visit: ${PLATFORM_URL}/settings/alerts
`.trim();
}

// ─── Fetch user alert config from D1 ─────────────────────────────────────────
async function getUserAlertConfig(env, userId) {
  if (!userId || !env?.DB) return null;
  try {
    return await env.DB.prepare(
      `SELECT ac.*, u.email FROM alert_configs ac
       JOIN users u ON ac.user_id = u.id
       WHERE ac.user_id = ? AND (ac.telegram_enabled = 1 OR ac.email_enabled = 1)`
    ).bind(userId).first();
  } catch { return null; }
}

// ─── Log alert delivery to D1 ────────────────────────────────────────────────
async function logAlert(env, userId, channel, triggerType, target, status, preview) {
  if (!env?.DB || !userId) return;
  try {
    await env.DB.prepare(
      `INSERT INTO alert_log (user_id, channel, trigger_type, target, message_preview, status)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(userId, channel, triggerType, target || null, (preview||'').slice(0, 200), status).run();
  } catch {}
}

// ─── Determine trigger type from scan result ──────────────────────────────────
function determineTrigger(scanResult, config) {
  const triggers = [];
  const threshold = config.min_risk_score ?? 70;

  if ((scanResult.risk_score ?? 0) >= threshold || scanResult.risk_level === 'CRITICAL') {
    triggers.push('high_risk_scan');
  }
  if (config.alert_on_blacklist && scanResult.blacklisted === true) {
    triggers.push('blacklist_detected');
  }
  return triggers;
}

// ─── Master alert trigger ─────────────────────────────────────────────────────
export async function triggerAlerts(env, scanResult, authCtx = {}) {
  const userId = authCtx.user_id;
  if (!userId) return; // No authenticated user — no alerts

  const config = await getUserAlertConfig(env, userId);
  if (!config) return; // No alert config or no channels enabled

  const triggers = determineTrigger(scanResult, config);
  if (triggers.length === 0) return; // No threshold crossed

  const deliveries = [];

  for (const triggerType of triggers) {
    // Telegram
    if (config.telegram_enabled && config.telegram_chat_id && env?.TELEGRAM_BOT_TOKEN) {
      const msg    = buildTelegramMessage(scanResult, triggerType);
      const result = await sendTelegramAlert(env.TELEGRAM_BOT_TOKEN, config.telegram_chat_id, msg);
      deliveries.push(result);
      await logAlert(env, userId, 'telegram', triggerType, scanResult.target, result.success ? 'sent' : 'failed', msg.slice(0, 100));
    }

    // Email
    if (config.email_enabled && config.alert_email) {
      const subject  = `[SECURITY ALERT] ${triggerType.replace(/_/g,' ')} — ${scanResult.target ?? 'unknown'}`;
      const body     = buildEmailBody(scanResult, triggerType);
      const result   = await sendEmailAlert(env, config.alert_email, subject, body);
      deliveries.push(result);
      await logAlert(env, userId, 'email', triggerType, scanResult.target, result.success ? 'sent' : 'failed', subject);
    }
  }

  return deliveries;
}

// ─── Platform-level admin alert (uses Worker-level bot token + chat) ──────────
export async function sendAdminAlert(env, message) {
  if (!env?.TELEGRAM_BOT_TOKEN || !env?.ADMIN_TELEGRAM_CHAT_ID) return;
  return sendTelegramAlert(env.TELEGRAM_BOT_TOKEN, env.ADMIN_TELEGRAM_CHAT_ID, message);
}

// ─── CVE alert broadcast (Sentinel APEX integration) ─────────────────────────
export async function broadcastCVEAlert(env, cve) {
  // Broadcast to Sentinel APEX Telegram channel (if configured)
  if (!env?.TELEGRAM_BOT_TOKEN || !env?.SENTINEL_CHANNEL_ID) return;

  const cvss  = cve.score ?? 'N/A';
  const emoji = parseFloat(cvss) >= 9.0 ? '🚨' : '🔴';
  const msg   = [
    `${emoji} *SENTINEL APEX — CVE ALERT*`,
    ``,
    `*${cve.id}* | CVSS: ${cvss}`,
    `*Severity:* ${cve.severity}`,
    ``,
    (cve.description ?? '').slice(0, 300),
    ``,
    `*Tags:* ${(cve.tags ?? []).join(', ') || 'N/A'}`,
    ``,
    `[NVD Detail](${cve.nvd_url ?? 'https://nvd.nist.gov/'})`,
    `[Join Sentinel APEX](https://t.me/cyberdudebivashSentinelApex)`,
  ].join('\n');

  return sendTelegramAlert(env.TELEGRAM_BOT_TOKEN, env.SENTINEL_CHANNEL_ID, msg);
}

// ─── Test alert (for user to verify their config) ────────────────────────────
export async function sendTestAlert(env, userId) {
  const config = await getUserAlertConfig(env, userId);
  if (!config) return { success: false, error: 'No alert configuration found' };

  const testMsg = {
    target: 'test.cyberdudebivash.com',
    module: 'domain_scanner',
    risk_score: 75,
    risk_level: 'HIGH',
    grade: 'D',
    blacklisted: false,
    findings: [{
      id: 'TEST-001', title: 'Test Alert', severity: 'HIGH',
      description: 'This is a test alert from CYBERDUDEBIVASH AI Security Hub.',
    }],
  };

  const results = [];

  if (config.telegram_enabled && config.telegram_chat_id && env?.TELEGRAM_BOT_TOKEN) {
    const msg = buildTelegramMessage(testMsg, 'high_risk_scan') + '\n\n✅ *Test alert — your Telegram is configured correctly!*';
    const r   = await sendTelegramAlert(env.TELEGRAM_BOT_TOKEN, config.telegram_chat_id, msg);
    results.push({ channel: 'telegram', ...r });
  }

  if (config.email_enabled && config.alert_email) {
    const r = await sendEmailAlert(env, config.alert_email, '[TEST] Security Hub Alert', buildEmailBody(testMsg, 'high_risk_scan'));
    results.push({ channel: 'email', ...r });
  }

  return { success: results.every(r => r.success), deliveries: results };
}
