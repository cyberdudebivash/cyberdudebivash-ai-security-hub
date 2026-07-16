/**
 * CYBERDUDEBIVASH AI Security Hub — Renewal Automation Engine
 * Phase 5 P0: Renewal reminders at T-30, T-14, T-7, T-1 days + expired recovery.
 *
 * Reads `renewal_queue` table populated by billingEngine.buildRenewalQueue().
 * Tracks which intervals have been notified via `notified_at` JSON field.
 * Sends emails directly via Resend; never blocks payment flows.
 *
 * Called from cron handler: '0 6 * * *' (daily 6am) and '0 0 * * *' (midnight).
 */

const REMINDER_INTERVALS = [
  { key: '30d', label: '30 days', min_days: 28, max_days: 32 },
  { key: '14d', label: '14 days', min_days: 12, max_days: 16 },
  { key: '7d',  label: '7 days',  min_days: 5,  max_days: 9  },
  { key: '1d',  label: '24 hours', min_days: 0,  max_days: 2  },
];

function formatINR(amount) {
  return `₹${(amount || 0).toLocaleString('en-IN')}`;
}

function buildReminderEmail(row, intervalKey) {
  const planUpper = (row.plan || 'Pro').replace('_', ' ').toUpperCase();
  const amount    = formatINR(row.amount_inr);
  const date      = row.renewal_date
    ? new Date(row.renewal_date).toLocaleDateString('en-IN', { day: '2-digit', month: 'long', year: 'numeric' })
    : 'soon';

  const subjects = {
    '30d': `Your CYBERDUDEBIVASH ${planUpper} subscription renews in 30 days`,
    '14d': `Renewal reminder: ${planUpper} subscription renews in 2 weeks`,
    '7d':  `⏰ 7 days to renewal — CYBERDUDEBIVASH ${planUpper}`,
    '1d':  `Action: Your subscription renews tomorrow`,
  };

  const intros = {
    '30d': `This is a friendly heads-up that your <strong>${planUpper}</strong> subscription will auto-renew on <strong>${date}</strong>.`,
    '14d': `Your <strong>${planUpper}</strong> subscription is set to renew on <strong>${date}</strong> — just 2 weeks away.`,
    '7d':  `Your <strong>${planUpper}</strong> subscription renews in 7 days on <strong>${date}</strong>.`,
    '1d':  `Your <strong>${planUpper}</strong> subscription renews <strong>tomorrow, ${date}</strong>.`,
  };

  const html = `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Subscription Renewal — CYBERDUDEBIVASH</title></head>
<body style="font-family:'Segoe UI',sans-serif;max-width:600px;margin:0 auto;padding:40px;color:#1a1a2e;background:#fff">
  <div style="margin-bottom:24px">
    <span style="font-size:20px;font-weight:900;color:#7c3aed">CYBERDUDEBIVASH®</span>
    <div style="font-size:12px;color:#666">AI Security Intelligence Platform</div>
  </div>

  <p>Hi,</p>
  <p>${intros[intervalKey]}</p>

  <div style="background:#f5f3ff;border-left:4px solid #7c3aed;padding:16px 20px;margin:24px 0;border-radius:0 8px 8px 0">
    <div style="font-size:13px;color:#666;margin-bottom:4px">Renewal amount</div>
    <div style="font-size:24px;font-weight:700;color:#7c3aed">${amount} + GST</div>
    <div style="font-size:13px;color:#666;margin-top:4px">Plan: ${planUpper} | Date: ${date}</div>
  </div>

  <p>No action needed if you wish to continue — your subscription will renew automatically.</p>
  <p>To manage your subscription or update payment details:</p>

  <a href="https://cyberdudebivash.in/billing"
     style="display:inline-block;background:#7c3aed;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;margin:8px 0">
    Manage Subscription
  </a>

  <p style="margin-top:24px;font-size:13px;color:#666">
    Questions? Reply to this email or contact
    <a href="mailto:billing@cyberdudebivash.in">billing@cyberdudebivash.in</a>
    or WhatsApp <a href="https://wa.me/918179881447">+91 81798 81447</a>.
  </p>
  <p style="font-size:13px;color:#666">— CYBERDUDEBIVASH Team</p>
</body>
</html>`;

  return { subject: subjects[intervalKey], html };
}

function buildExpiredEmail(row) {
  const planUpper = (row.plan || 'Pro').replace('_', ' ').toUpperCase();
  const amount    = formatINR(row.amount_inr);

  return {
    subject: `Your CYBERDUDEBIVASH subscription has expired — reactivate now`,
    html: `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Subscription Expired — CYBERDUDEBIVASH</title></head>
<body style="font-family:'Segoe UI',sans-serif;max-width:600px;margin:0 auto;padding:40px;color:#1a1a2e;background:#fff">
  <div style="margin-bottom:24px">
    <span style="font-size:20px;font-weight:900;color:#7c3aed">CYBERDUDEBIVASH®</span>
    <div style="font-size:12px;color:#666">AI Security Intelligence Platform</div>
  </div>

  <p>Hi,</p>
  <p>Your <strong>${planUpper}</strong> subscription has expired. Your access to premium security intelligence has been paused.</p>

  <div style="background:#fff0f0;border-left:4px solid #dc2626;padding:16px 20px;margin:24px 0;border-radius:0 8px 8px 0">
    <div style="font-weight:600;color:#dc2626">What you're missing:</div>
    <ul style="margin:8px 0;padding-left:20px;color:#444">
      <li>AI-powered threat analysis</li>
      <li>Real-time vulnerability scanning</li>
      <li>SIEM rule generation</li>
      <li>Priority support access</li>
    </ul>
  </div>

  <p>Reactivate today and get back to full protection in minutes:</p>

  <a href="https://cyberdudebivash.in/pricing"
     style="display:inline-block;background:#7c3aed;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;margin:8px 0">
    Reactivate Subscription — ${amount}
  </a>

  <p style="margin-top:24px;font-size:13px;color:#666">
    Need help? Contact us at
    <a href="mailto:support@cyberdudebivash.in">support@cyberdudebivash.in</a>
    or WhatsApp <a href="https://wa.me/918179881447">+91 81798 81447</a>.
  </p>
  <p style="font-size:13px;color:#666">— CYBERDUDEBIVASH Team</p>
</body>
</html>`,
  };
}

async function sendEmail(env, to, subject, html) {
  if (!env.RESEND_API_KEY || !to) return false;
  try {
    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from:    'CYBERDUDEBIVASH <noreply@cyberdudebivash.in>',
        to:      [to],
        subject,
        html,
      }),
    });
    return resp.ok;
  } catch { return false; }
}

/**
 * Main renewal automation function — call from cron.
 * Reads renewal_queue, sends reminders for each pending interval, marks sent in notified_at JSON.
 */
export async function runRenewalAutomation(env) {
  const db = env?.DB;
  if (!db) return { processed: 0, emails_sent: 0 };

  let processed   = 0;
  let emails_sent = 0;
  const errors    = [];

  try {
    const upcoming = await db.prepare(`
      SELECT * FROM renewal_queue
      WHERE status IN ('upcoming','failed')
      ORDER BY renewal_date ASC
      LIMIT 200
    `).all().catch(() => ({ results: [] }));

    const now = Date.now();

    for (const row of (upcoming?.results || [])) {
      let notified = {};
      try {
        notified = JSON.parse(row.notified_at || '{}');
        if (typeof notified !== 'object' || Array.isArray(notified)) notified = {};
      } catch { notified = {}; }

      const renewalMs  = new Date(row.renewal_date).getTime();
      const daysUntil  = (renewalMs - now) / 86400000;
      let   dirty      = false;

      // Check each reminder window
      for (const { key, min_days, max_days } of REMINDER_INTERVALS) {
        if (daysUntil >= min_days && daysUntil <= max_days && !notified[key]) {
          const { subject, html } = buildReminderEmail(row, key);
          const sent = await sendEmail(env, row.email, subject, html);
          if (sent) {
            notified[key] = new Date().toISOString();
            dirty         = true;
            emails_sent++;
          }
        }
      }

      // Expired recovery: renewal date passed by > 1 day and not yet churned
      if (daysUntil < -1 && row.status === 'upcoming' && !notified['expired']) {
        const { subject, html } = buildExpiredEmail(row);
        const sent = await sendEmail(env, row.email, subject, html);
        if (sent) {
          notified['expired'] = new Date().toISOString();
          dirty               = true;
          emails_sent++;
          await db.prepare(
            `UPDATE renewal_queue SET status='churned' WHERE id=?`
          ).bind(row.id).run().catch(() => {});
        }
      }

      if (dirty) {
        await db.prepare(
          `UPDATE renewal_queue SET notified_at=? WHERE id=?`
        ).bind(JSON.stringify(notified), row.id).run().catch(() => {});
        processed++;
      }
    }
  } catch (e) {
    errors.push(e.message);
  }

  return { processed, emails_sent, errors };
}

/**
 * Downgrade subscribers whose current_period_end has passed back to FREE.
 * Catches both explicit cancellations (handleCancelSubscription sets
 * cancel_at_period_end=1 but leaves status='active' until the period
 * actually ends) and silent non-renewal (no auto-recharge exists — see
 * runPaymentRecovery's TODO above) — both leave a subscription 'active'
 * with an elapsed current_period_end, so one query catches both.
 */
export async function enforceSubscriptionExpiry(env) {
  const db = env?.DB;
  if (!db) return { downgraded: 0 };

  try {
    const expired = await db.prepare(`
      SELECT s.id as sub_id, s.user_id, s.email
      FROM subscriptions s
      WHERE s.status = 'active'
        AND s.current_period_end IS NOT NULL
        AND s.current_period_end <= datetime('now')
      LIMIT 100
    `).all().catch(() => ({ results: [] }));

    const rows = expired?.results ?? [];
    if (rows.length === 0) return { downgraded: 0 };

    const now = new Date().toISOString();
    let downgraded = 0;
    for (const row of rows) {
      try {
        await db.batch([
          db.prepare(`UPDATE subscriptions
                      SET status = 'cancelled',
                          cancelled_at = COALESCE(cancelled_at, ?),
                          cancel_reason = COALESCE(cancel_reason, 'Subscription period ended without renewal'),
                          updated_at = ?
                      WHERE id = ?`).bind(now, now, row.sub_id),
          ...(row.user_id ? [db.prepare(`UPDATE users SET tier = 'FREE' WHERE id = ? AND tier NOT IN ('ENTERPRISE','MSSP')`).bind(row.user_id)] : []),
        ]);
        downgraded++;
      } catch (e) {
        console.error('[CRON] Expiry batch failed for sub', row.sub_id, e?.message);
      }
    }
    return { downgraded };
  } catch (e) {
    return { downgraded: 0, error: e.message };
  }
}

/**
 * Seed the renewal queue for subscriptions renewing within the next 35 days.
 * Extends billingEngine.buildRenewalQueue() which only looks 7 days ahead.
 */
export async function seedRenewalQueue35d(env) {
  const db = env?.DB;
  if (!db) return { queued: 0 };

  try {
    const renewing = await db.prepare(`
      SELECT s.id, s.user_id, s.email, s.plan, s.price_inr, s.current_period_end
      FROM subscriptions s
      WHERE s.status = 'active'
        AND s.cancel_at_period_end = 0
        AND s.current_period_end BETWEEN datetime('now') AND datetime('now','+35 days')
        AND CAST(s.id AS TEXT) NOT IN (SELECT subscription_id FROM renewal_queue WHERE status IN ('upcoming','processing'))
    `).all().catch(() => ({ results: [] }));

    let queued = 0;
    for (const sub of (renewing?.results || [])) {
      await db.prepare(`
        INSERT OR IGNORE INTO renewal_queue
          (subscription_id, user_id, email, plan, amount_inr, renewal_date, status)
        VALUES (?, ?, ?, ?, ?, ?, 'upcoming')
      `).bind(
        String(sub.id), sub.user_id || '', sub.email || '',
        sub.plan, sub.price_inr || 0,
        sub.current_period_end,
      ).run().catch(() => {});
      queued++;
    }
    return { queued };
  } catch (e) { return { queued: 0, error: e.message }; }
}
