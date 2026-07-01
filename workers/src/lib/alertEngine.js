/**
 * CYBERDUDEBIVASH® — Alert Engine v2.0 (EOP Phase 7)
 * Rate-limited, deduped alerts via Telegram + Email.
 *
 * Dedup: KV key `alert_dedup:<type>:<component>` with TTL 1800s (30 min).
 * If the key exists, the alert is suppressed to prevent storms.
 * Every sent alert is also recorded in the `ops_alert_log` D1 table for history.
 */

const DEDUP_TTL = 1800; // 30 minutes — same component+type won't re-alert within this window

const SEVERITY_EMOJI = {
  critical:  '🔴',
  major:     '🟠',
  minor:     '🟡',
  info:      '🔵',
};

/**
 * Send a rate-limited operational alert.
 *
 * @param {object} env
 * @param {object} opts
 * @param {string} opts.type        — unique alert category, e.g. 'db_failure', 'high_latency'
 * @param {string} opts.component   — which component, e.g. 'D1 Database', 'KV Store'
 * @param {string} opts.message     — human-readable message
 * @param {string} opts.severity    — 'critical' | 'major' | 'minor' | 'info'
 * @param {object} [opts.context]   — extra key/value pairs to include
 * @param {string[]} [opts.channels] — ['telegram','email'] (default: ['telegram'])
 * @returns {Promise<{sent: boolean, suppressed: boolean, reason?: string}>}
 */
export async function sendAlert(env, { type, component, message, severity = 'minor', context = {}, channels = ['telegram'] }) {
  const dedupKey = `alert_dedup:${type}:${component.replace(/\s+/g, '_').toLowerCase()}`;

  // Rate-limit check via KV
  if (env.KV) {
    try {
      const existing = await env.KV.get(dedupKey);
      if (existing) {
        return { sent: false, suppressed: true, reason: 'dedup_window_active' };
      }
    } catch (_) {}
  }

  const emoji = SEVERITY_EMOJI[severity] || '⚠️';
  const text = `${emoji} *[${severity.toUpperCase()}] ${component}*\n${message}` +
    (Object.keys(context).length ? `\n\`\`\`\n${JSON.stringify(context, null, 2).slice(0, 400)}\n\`\`\`` : '') +
    `\n_${new Date().toISOString()}_`;

  const sentVia = [];

  // Telegram
  if (channels.includes('telegram')) {
    const ok = await sendTelegram(env, text);
    if (ok) sentVia.push('telegram');
  }

  // Email (for critical/major)
  if (channels.includes('email') || severity === 'critical' || severity === 'major') {
    const ok = await sendEmailAlert(env, { type, component, message, severity, context });
    if (ok) sentVia.push('email');
  }

  // Set dedup key so we don't re-alert within the window
  if (env.KV && sentVia.length > 0) {
    await env.KV.put(dedupKey, '1', { expirationTtl: DEDUP_TTL }).catch(() => {});
  }

  // Record in ops_alert_log D1 table
  if (env.DB && sentVia.length > 0) {
    const id = `alrt-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 5)}`;
    await env.DB.prepare(
      `INSERT INTO ops_alert_log (id, alert_type, component, message, sent_via, sent_at)
       VALUES (?, ?, ?, ?, ?, datetime('now'))`
    ).bind(id, type, component, message.slice(0, 500), sentVia.join(','))
      .run().catch(() => {});
  }

  return { sent: sentVia.length > 0, suppressed: false, channels: sentVia };
}

/**
 * Clear the dedup lock for a component (call when incident resolves).
 */
export async function clearAlertDedup(env, type, component) {
  if (!env.KV) return;
  const key = `alert_dedup:${type}:${component.replace(/\s+/g, '_').toLowerCase()}`;
  await env.KV.delete(key).catch(() => {});
}

/**
 * Pre-built alert helpers for common scenarios.
 */
export const Alerts = {
  dbFailure: (env, error) => sendAlert(env, {
    type: 'db_failure', component: 'D1 Database',
    message: `D1 database unreachable: ${error}`, severity: 'critical',
  }),
  kvFailure: (env, error) => sendAlert(env, {
    type: 'kv_failure', component: 'KV Store',
    message: `KV store unreachable: ${error}`, severity: 'major',
  }),
  r2Failure: (env, error) => sendAlert(env, {
    type: 'r2_failure', component: 'R2 Storage',
    message: `R2 storage failure: ${error}`, severity: 'major',
  }),
  highLatency: (env, component, latencyMs) => sendAlert(env, {
    type: 'high_latency', component,
    message: `High latency detected: ${latencyMs}ms (threshold: 1000ms)`,
    severity: 'minor', context: { latency_ms: latencyMs },
  }),
  paymentFailure: (env, error, context) => sendAlert(env, {
    type: 'payment_failure', component: 'Payment System',
    message: `Payment processing failure: ${error}`, severity: 'major', context,
  }),
  authFailure: (env, error) => sendAlert(env, {
    type: 'auth_failure', component: 'Authentication',
    message: `Authentication system error: ${error}`, severity: 'major',
  }),
  schedulerFailure: (env, job, error) => sendAlert(env, {
    type: 'scheduler_failure', component: 'Scheduler',
    message: `Cron job '${job}' failed: ${error}`, severity: 'minor',
  }),
  intelStale: (env, ageHours) => sendAlert(env, {
    type: 'intel_stale', component: 'Threat Intelligence',
    message: `Threat intel feed is ${ageHours.toFixed(1)}h stale (threshold: 48h)`,
    severity: 'minor', context: { age_hours: ageHours },
  }),
  workerError: (env, area, error) => sendAlert(env, {
    type: 'worker_error', component: 'Worker',
    message: `Unhandled worker error in ${area}: ${error}`, severity: 'major',
  }),
};

// ── Private senders ───────────────────────────────────────────────────────────

async function sendTelegram(env, text) {
  if (!env.ADMIN_TELEGRAM_BOT_TOKEN || !env.ADMIN_TELEGRAM_CHAT_ID) return false;
  try {
    const resp = await fetch(
      `https://api.telegram.org/bot${env.ADMIN_TELEGRAM_BOT_TOKEN}/sendMessage`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id:    env.ADMIN_TELEGRAM_CHAT_ID,
          text:       text.slice(0, 4096),
          parse_mode: 'Markdown',
        }),
        signal: AbortSignal.timeout(8000),
      }
    );
    return resp.ok;
  } catch (_) {
    return false;
  }
}

async function sendEmailAlert(env, { type, component, message, severity, context }) {
  try {
    const { sendEmail } = await import('../services/emailEngine.js');
    await sendEmail(env, {
      to:      env.CONTACT || 'bivash@cyberdudebivash.com',
      subject: `[${severity.toUpperCase()}] ${component} — ${type}`,
      html: `<div style="font-family:monospace;background:#0f0f1a;color:#e2e8f0;padding:24px;border-radius:8px">
        <h2 style="color:${severity === 'critical' ? '#ef4444' : severity === 'major' ? '#f97316' : '#eab308'}">
          ${severity.toUpperCase()}: ${component}
        </h2>
        <p style="color:#94a3b8">${message}</p>
        ${Object.keys(context).length ? `<pre style="background:#1a1a2e;padding:12px;border-radius:4px;color:#7c3aed;font-size:12px">${JSON.stringify(context, null, 2)}</pre>` : ''}
        <p style="color:#475569;font-size:12px">${new Date().toISOString()}</p>
      </div>`,
    });
    return true;
  } catch (_) {
    return false;
  }
}
