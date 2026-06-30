/**
 * CYBERDUDEBIVASH AI Security Hub — Production Error Visibility (EBOC-1 / H-3)
 *
 * Cloudflare Tail Workers require a second deployable artifact and CI pipeline
 * change; out of scope for a same-session fix. This is the Stage-0-budget
 * equivalent: critical-path failures (payment, refund, report fulfillment)
 * are written to D1 for operator review and pushed to the existing Telegram
 * admin channel (TELEGRAM_BOT_TOKEN / ADMIN_TELEGRAM_CHAT_ID — already live)
 * so a production incident pages the operator instead of waiting for a
 * customer email.
 */
import { sendAdminAlert } from './alerts.js';

export async function logSystemError(env, { area, message, context = {}, notify = true }) {
  console.error(`[${area}]`, message, context);

  if (env?.DB) {
    const id = `err-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
    await env.DB.prepare(
      `INSERT INTO system_errors (id, area, message, context, created_at)
       VALUES (?, ?, ?, ?, datetime('now'))`
    ).bind(id, area, String(message).slice(0, 500), JSON.stringify(context).slice(0, 2000))
      .run().catch(e => console.error('system_errors INSERT failed:', e.message));
  }

  if (notify) {
    await sendAdminAlert(env, `🚨 *${area}*\n${message}\n${JSON.stringify(context).slice(0, 300)}`)
      .catch(() => {});
  }
}
