// ═══════════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH AI Security Hub — Automation Engine v8.2
// Phase 7: Auto-generate products, auto-email sequences, auto-upsell triggers,
//          cron-driven revenue workflows, and the full automation pipeline
//
// Called from:
//   • Cloudflare Cron Triggers (wrangler.toml scheduled)
//   • POST /api/automation/run  (admin manual trigger)
//   • Inline after CVE ingestion (generateAndPublishProducts)
// ═══════════════════════════════════════════════════════════════════════════

import { generateDefenseProducts, getProductCatalog } from './defenseSolutions.js';
import { runBulkOptimization }                        from './aiRevenueOptimizer.js';
import { recordRevenueEvent }                         from './revenueEngine.js';

// ── Automation job registry ───────────────────────────────────────────────────
export const AUTOMATION_JOBS = {
  // Runs every 6 hours
  DEFENSE_PRODUCT_GENERATOR: 'defense_product_generator',
  // Runs every 30 minutes
  UPSELL_EMAIL_QUEUE:        'upsell_email_queue',
  // Runs every 4 hours
  CHURN_PREVENTION:          'churn_prevention',
  // Runs daily at 09:00 UTC
  WEEKLY_DIGEST:             'weekly_digest',
  // Runs daily at 00:00 UTC
  REVENUE_SNAPSHOT:          'revenue_snapshot',
  // Runs every 12 hours
  AFFILIATE_REFRESH:         'affiliate_refresh',
  // Runs after every new CVE ingestion
  AUTO_PUBLISH_INTEL:        'auto_publish_intel',
};

// ─────────────────────────────────────────────────────────────────────────────
// MASTER CRON DISPATCHER
// Called from index.js scheduled() handler
// ─────────────────────────────────────────────────────────────────────────────

export async function runAutomationCron(env, cronExpression) {
  const results = {};
  const startedAt = Date.now();

  // Map cron expressions to jobs
  const jobs = [];

  // Every trigger: run product generation check + upsell queue
  jobs.push(
    runDefenseProductGenerator(env).then(r => { results.defense_products = r; }),
    processUpsellEmailQueue(env).then(r => { results.upsell_emails = r; }),
  );

  // Run bulk AI optimization every 4 hours
  jobs.push(
    runBulkOptimization(env).then(r => { results.bulk_ai = r; }).catch(e => { results.bulk_ai = { error: e.message }; })
  );

  // Churn prevention
  jobs.push(
    runChurnPrevention(env).then(r => { results.churn_prevention = r; }).catch(e => { results.churn_prevention = { error: e.message }; })
  );

  // Revenue snapshot
  jobs.push(
    captureRevenueSnapshot(env).then(r => { results.revenue_snapshot = r; }).catch(e => { results.revenue_snapshot = { error: e.message }; })
  );

  await Promise.allSettled(jobs);

  // Log automation run
  await env.SECURITY_HUB_KV?.put(
    `automation:last_run`,
    JSON.stringify({ ts: Date.now(), duration_ms: Date.now() - startedAt, results }),
    { expirationTtl: 86400 }
  ).catch(() => {});

  return {
    success:     true,
    jobs_run:    Object.keys(results).length,
    duration_ms: Date.now() - startedAt,
    results,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. DEFENSE PRODUCT AUTO-GENERATOR
// For every new CVE in the last 6h that doesn't have products generated yet
// ─────────────────────────────────────────────────────────────────────────────

export async function runDefenseProductGenerator(env) {
  try {
    // Fetch recent CVEs that haven't had products generated
    const since = new Date(Date.now() - 6 * 3600000).toISOString();
    const rows  = await env.DB.prepare(`
      SELECT id, cve_id, title, severity, cvss_score, description, published_at
      FROM threat_intel
      WHERE published_at >= ?
        AND (products_generated IS NULL OR products_generated = 0)
      ORDER BY cvss_score DESC
      LIMIT 20
    `).bind(since).all().catch(() => ({ results: [] }));

    const cves = rows.results || [];
    const generated = [];

    for (const cve of cves) {
      try {
        // Build intel entry for defenseSolutions generator
        const entry = {
          cveId:    cve.cve_id || cve.id,
          title:    cve.title || `${cve.cve_id} Security Vulnerability`,
          severity: cve.severity || 'HIGH',
          cvss:     parseFloat(cve.cvss_score || '7.5'),
          iocs:     [],
          tactics:  parseTactics(cve.description),
          products: parseProducts(cve.title || ''),
          ts:       cve.published_at || new Date().toISOString(),
        };

        // Generate all defense product content
        const products = generateDefenseProducts(entry);

        // Store in KV (available for download via signed URL)
        const productKeys = [];
        for (const [type, content] of Object.entries(products)) {
          if (!content) continue;
          const key = `product:${entry.cveId}:${type}`;
          await env.SECURITY_HUB_KV?.put(key, content, { expirationTtl: 86400 * 30 }).catch(() => {});
          productKeys.push({ type, key });
        }

        // Mark as generated in D1
        await env.DB.prepare(`
          UPDATE threat_intel
          SET products_generated = 1, products_generated_at = datetime('now')
          WHERE cve_id = ? OR id = ?
        `).bind(entry.cveId, entry.cveId).run().catch(() => {});

        // Create product listing entries
        await env.DB.prepare(`
          INSERT OR IGNORE INTO defense_solutions
            (id, cve_id, product_types, price_min, price_max, created_at)
          VALUES (?, ?, ?, 199, 9999, datetime('now'))
        `).bind(
          crypto.randomUUID(),
          entry.cveId,
          JSON.stringify(Object.keys(products)),
        ).run().catch(() => {});

        generated.push({ cveId: entry.cveId, products: Object.keys(products).length });
      } catch (e) {
        // Skip failing CVE, continue
      }
    }

    return { success: true, processed: cves.length, generated: generated.length, details: generated };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. UPSELL EMAIL QUEUE PROCESSOR
// Processes pending upsell & retention emails from KV queue
// ─────────────────────────────────────────────────────────────────────────────

export async function processUpsellEmailQueue(env) {
  const processed = [];
  const failed    = [];

  try {
    // Scan KV for queued emails (prefix scan via list)
    const prefixes = [
      'email:queue:retention:',
      'email:queue:purchase:',
      'upsell:pending:',
    ];

    for (const prefix of prefixes) {
      try {
        const list = await env.SECURITY_HUB_KV?.list({ prefix, limit: 50 });
        if (!list?.keys?.length) continue;

        for (const kvKey of list.keys) {
          try {
            const raw   = await env.SECURITY_HUB_KV?.get(kvKey.name);
            if (!raw) continue;
            const data  = JSON.parse(raw);

            // Route to correct email template
            const sent = await dispatchEmail(env, kvKey.name, data);

            if (sent) {
              await env.SECURITY_HUB_KV?.delete(kvKey.name).catch(() => {});
              processed.push({ key: kvKey.name, type: data.type || prefix });
            } else {
              failed.push({ key: kvKey.name, reason: 'dispatch_failed' });
            }
          } catch {
            failed.push({ key: kvKey.name, reason: 'parse_error' });
          }
        }
      } catch { /* prefix scan failed — KV may not support list */ }
    }

    return { success: true, processed: processed.length, failed: failed.length, details: processed };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. CHURN PREVENTION ENGINE
// Identifies at-risk users and triggers save sequences
// ─────────────────────────────────────────────────────────────────────────────

export async function runChurnPrevention(env) {
  try {
    // Users inactive for 7+ days on paid plans
    const atRisk = await env.DB.prepare(`
      SELECT l.id, l.email, l.plan, l.updated_at, l.lead_score,
             MAX(s.created_at) as last_scan_at
      FROM leads l
      LEFT JOIN scan_history s ON s.user_id = l.id
      WHERE l.plan != 'free'
        AND l.status = 'active'
        AND (s.created_at IS NULL OR s.created_at < datetime('now', '-7 days'))
      GROUP BY l.id
      ORDER BY l.lead_score DESC
      LIMIT 100
    `).all().catch(() => ({ results: [] }));

    const users = atRisk.results || [];
    let saved = 0, queued = 0;

    for (const user of users) {
      const daysSilent = user.last_scan_at
        ? Math.floor((Date.now() - new Date(user.last_scan_at).getTime()) / 86400000)
        : 999;

      // Already have a save email queued? Skip
      const existingKey = `churn:risk:${user.email}`;
      const existing    = await env.SECURITY_HUB_KV?.get(existingKey).catch(() => null);
      if (existing) continue;

      // Queue retention email
      const offer = daysSilent > 30
        ? { discount: 30, duration: '3 months', template: 'churn_save_hard' }
        : { discount: 20, duration: '2 months', template: 'churn_save_soft' };

      const payload = {
        type:        'retention',
        email:       user.email,
        plan:        user.plan,
        days_silent: daysSilent,
        offer,
        queued_at:   Date.now(),
      };

      await env.SECURITY_HUB_KV?.put(
        `email:queue:retention:${user.email}`,
        JSON.stringify(payload),
        { expirationTtl: 86400 * 3 }
      ).catch(() => {});

      await env.SECURITY_HUB_KV?.put(existingKey, '1', { expirationTtl: 86400 * 7 }).catch(() => {});

      queued++;
    }

    return { success: true, at_risk: users.length, emails_queued: queued, saved };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. AUTO-PUBLISH INTEL (called after CVE ingestion)
// Generates products + posts to social queue + sends alert emails
// ─────────────────────────────────────────────────────────────────────────────

export async function autoPublishIntel(env, intelEntry) {
  const results = {
    products_generated: false,
    social_queued:      false,
    alert_sent:         false,
    enterprise_notified:false,
  };

  try {
    const entry = {
      cveId:    intelEntry.cveId || intelEntry.cve_id,
      title:    intelEntry.title,
      severity: intelEntry.severity || 'HIGH',
      cvss:     parseFloat(intelEntry.cvss || '7.5'),
      iocs:     intelEntry.iocs || [],
      tactics:  intelEntry.tactics || [],
      products: intelEntry.products || [],
    };

    // 1. Generate defense products
    try {
      const products = generateDefenseProducts(entry);
      for (const [type, content] of Object.entries(products)) {
        if (content) {
          await env.SECURITY_HUB_KV?.put(`product:${entry.cveId}:${type}`, content, { expirationTtl: 86400 * 30 }).catch(() => {});
        }
      }
      results.products_generated = true;
    } catch { /* non-blocking */ }

    // 2. Queue social media post
    if (entry.severity === 'CRITICAL' || (entry.cvss >= 9.0)) {
      const socialPost = buildSocialPost(entry);
      await env.SECURITY_HUB_KV?.put(
        `social:queue:${entry.cveId}`,
        JSON.stringify({ ...socialPost, queued_at: Date.now() }),
        { expirationTtl: 86400 }
      ).catch(() => {});
      results.social_queued = true;
    }

    // 3. Alert email to all PRO/ENTERPRISE subscribers for CRITICAL
    if (entry.severity === 'CRITICAL' || entry.cvss >= 9.0) {
      await env.SECURITY_HUB_KV?.put(
        `email:queue:alert:${entry.cveId}`,
        JSON.stringify({
          type:      'threat_alert',
          cve_id:    entry.cveId,
          title:     entry.title,
          severity:  entry.severity,
          cvss:      entry.cvss,
          queued_at: Date.now(),
        }),
        { expirationTtl: 86400 }
      ).catch(() => {});
      results.alert_sent = true;
    }

    // 4. Enterprise notification (Slack/webhook if configured)
    if (env.ENTERPRISE_WEBHOOK_URL && entry.cvss >= 8.0) {
      fetch(env.ENTERPRISE_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text:     `🚨 *${entry.cveId}* — CVSS ${entry.cvss} — ${entry.title}`,
          severity: entry.severity,
          cve:      entry.cveId,
          url:      `https://cyberdudebivash.com/intel/${entry.cveId}`,
        }),
      }).catch(() => {});
      results.enterprise_notified = true;
    }

  } catch (e) {
    results.error = e.message;
  }

  return results;
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. REVENUE SNAPSHOT CAPTURE (daily cron)
// Stores daily revenue snapshot for trend tracking
// ─────────────────────────────────────────────────────────────────────────────

export async function captureRevenueSnapshot(env) {
  try {
    const today = new Date().toISOString().split('T')[0];

    // Check already captured today
    const existing = await env.SECURITY_HUB_KV?.get(`snapshot:revenue:${today}`).catch(() => null);
    if (existing) return { success: true, skipped: true, reason: 'Already captured today' };

    const [mrr, todayRev, totalRev, subs] = await Promise.all([
      env.DB.prepare(`
        SELECT COALESCE(SUM(CASE plan
          WHEN 'starter' THEN 499 WHEN 'pro' THEN 1499 WHEN 'enterprise' THEN 4999
          ELSE 0 END), 0) as mrr
        FROM leads WHERE plan != 'free' AND status = 'active'
      `).first(),
      env.DB.prepare(`SELECT COALESCE(SUM(amount),0) as r FROM revenue_events WHERE date(created_at) = date('now')`).first(),
      env.DB.prepare(`SELECT COALESCE(SUM(amount),0) as r FROM revenue_events`).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM leads WHERE plan != 'free' AND status = 'active'`).first(),
    ]);

    const snapshot = {
      date:        today,
      mrr:         mrr?.mrr     || 0,
      arr:         (mrr?.mrr || 0) * 12,
      today_rev:   todayRev?.r  || 0,
      total_rev:   totalRev?.r  || 0,
      subscribers: subs?.n      || 0,
      captured_at: new Date().toISOString(),
    };

    await env.SECURITY_HUB_KV?.put(
      `snapshot:revenue:${today}`,
      JSON.stringify(snapshot),
      { expirationTtl: 86400 * 90 }
    ).catch(() => {});

    // Also store in D1 for historical trend queries
    await env.DB.prepare(`
      INSERT OR REPLACE INTO revenue_snapshots
        (date, mrr, arr, daily_revenue, total_revenue, subscriber_count, captured_at)
      VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      snapshot.date,
      snapshot.mrr,
      snapshot.arr,
      snapshot.today_rev,
      snapshot.total_rev,
      snapshot.subscribers,
    ).run().catch(() => {});

    return { success: true, snapshot };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. AUTO-UPSELL TRIGGER (called inline on API responses)
// Inject upsell payload into any API response for the frontend to render
// ─────────────────────────────────────────────────────────────────────────────

export async function injectUpsell(env, responsePayload, authCtx) {
  if (!authCtx) return responsePayload; // anonymous — no upsell injection

  const plan = authCtx.plan || 'free';

  // Cache upsell for this user (2-min TTL to avoid repeated DB reads)
  const cacheKey = `upsell:inline:${authCtx.userId}`;
  try {
    const cached = await env.SECURITY_HUB_KV?.get(cacheKey);
    if (cached) {
      return { ...responsePayload, _upsell: JSON.parse(cached) };
    }
  } catch { /* miss */ }

  // Only inject for free/starter — pro/enterprise see minimal upsell
  if (['pro', 'enterprise'].includes(plan)) return responsePayload;

  const upgrades = {
    free:    { to: 'starter', price: 499, discount: 299, msg: '🔒 Unlock full features — ₹499/mo', url: '/upgrade?plan=starter' },
    starter: { to: 'pro',     price: 1499,discount: 1199, msg: '⚡ Upgrade to PRO for SIEM export + API access', url: '/upgrade?plan=pro' },
  };

  const upsell = upgrades[plan];
  if (!upsell) return responsePayload;

  await env.SECURITY_HUB_KV?.put(cacheKey, JSON.stringify(upsell), { expirationTtl: 120 }).catch(() => {});

  return { ...responsePayload, _upsell: upsell };
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. WEEKLY DIGEST EMAIL BUILDER
// Generates personalised weekly threat + revenue digest
// ─────────────────────────────────────────────────────────────────────────────

export async function buildWeeklyDigest(env, userEmail) {
  try {
    const since = new Date(Date.now() - 7 * 86400000).toISOString();

    const [cves, scans, spending] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as n FROM threat_intel WHERE published_at >= ?`).bind(since).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM scan_history WHERE created_at >= ? AND user_id = (SELECT id FROM leads WHERE email = ? LIMIT 1)`).bind(since, userEmail).first(),
      env.DB.prepare(`SELECT COALESCE(SUM(amount),0) as total FROM revenue_events WHERE email = ? AND created_at >= ?`).bind(userEmail, since).first(),
    ]);

    return {
      type:            'weekly_digest',
      email:           userEmail,
      subject:         `Your Weekly Threat Intel & Security Report`,
      stats: {
        new_cves:      cves?.n || 0,
        scans_run:     scans?.n || 0,
        amount_spent:  spending?.total || 0,
      },
      cta: {
        label: 'Run a New Scan',
        url:   'https://cyberdudebivash.com/#scan',
      },
    };
  } catch (e) {
    return { error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. SOCIAL MEDIA AUTO-POST
// Builds LinkedIn / Twitter content for critical CVEs
// ─────────────────────────────────────────────────────────────────────────────

function buildSocialPost(entry) {
  const { cveId, title, severity, cvss } = entry;
  const badge = severity === 'CRITICAL' ? '🚨 CRITICAL' : severity === 'HIGH' ? '⚠️ HIGH' : '📢';

  const linkedin = [
    `${badge} Security Alert: ${cveId}`,
    ``,
    `📊 CVSS Score: ${cvss}/10`,
    `🔒 ${title}`,
    ``,
    `Defense tools now available:`,
    `✅ Firewall Rules — ₹199`,
    `✅ IDS Signatures — ₹399`,
    `✅ IR Playbook — ₹999`,
    `✅ Full Defense Pack — ₹2,499`,
    ``,
    `🔗 https://cyberdudebivash.com/intel/${cveId}`,
    ``,
    `#CyberSecurity #ThreatIntel #${cveId.replace(/-/g, '')} #InfoSec`,
  ].join('\n');

  const twitter = `${badge} ${cveId} — CVSS ${cvss}\n${title.slice(0, 80)}...\n\nDefense tools available ▶ cyberdudebivash.com/intel/${cveId}\n#CyberSecurity #${cveId.replace(/-/g, '')}`;

  return { linkedin, twitter, cveId, severity, cvss };
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. MANUAL AUTOMATION TRIGGER HANDLER (for /api/automation/run)
// ─────────────────────────────────────────────────────────────────────────────

export async function handleAutomationRun(request, env, authCtx) {
  const CORS = { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' };

  if (authCtx?.role !== 'admin') {
    return new Response(JSON.stringify({ success: false, error: 'Admin required' }), { status: 403, headers: CORS });
  }

  const body = await request.json().catch(() => ({}));
  const job  = body.job || 'all';

  let result;
  try {
    switch (job) {
      case 'defense_products':
        result = await runDefenseProductGenerator(env);
        break;
      case 'upsell_emails':
        result = await processUpsellEmailQueue(env);
        break;
      case 'churn_prevention':
        result = await runChurnPrevention(env);
        break;
      case 'revenue_snapshot':
        result = await captureRevenueSnapshot(env);
        break;
      case 'bulk_ai':
        result = await runBulkOptimization(env);
        break;
      case 'all':
        result = await runAutomationCron(env, 'manual');
        break;
      default:
        return new Response(JSON.stringify({ success: false, error: `Unknown job: ${job}` }), { status: 400, headers: CORS });
    }
  } catch (e) {
    result = { success: false, error: e.message };
  }

  return new Response(JSON.stringify({ success: true, job, result }), { status: 200, headers: CORS });
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

async function dispatchEmail(env, key, data) {
  if (!env.RESEND_API_KEY) return false;

  const { email, type } = data;
  if (!email) return false;

  // Build email content from template
  const { subject, html } = buildEmailFromTemplate(type, data);
  if (!subject || !html) return false;

  try {
    const res = await fetch('https://api.resend.com/emails', {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      },
      body: JSON.stringify({
        from:    'CYBERDUDEBIVASH Security Hub <security@cyberdudebivash.com>',
        to:      [email],
        subject,
        html,
      }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

function buildEmailFromTemplate(type, data) {
  const templates = {
    retention: {
      subject: `We miss you — here's ${data.offer?.discount || 20}% off your ${data.plan?.toUpperCase()} plan`,
      html: `
        <div style="font-family:sans-serif;max-width:600px;margin:0 auto">
          <h2>👋 Hey there, we noticed you've been away</h2>
          <p>You haven't run a scan in <strong>${data.days_silent || 7} days</strong>. The threat landscape keeps evolving — let's get you back up to speed.</p>
          <div style="background:#f0f4ff;border-radius:8px;padding:20px;margin:20px 0">
            <h3 style="margin:0;color:#4f46e5">Special Offer: ${data.offer?.discount || 20}% Off</h3>
            <p>Use code <strong>COMEBACK${data.offer?.discount || 20}</strong> for ${data.offer?.discount || 20}% off your next ${data.offer?.duration || '2 months'}.</p>
          </div>
          <a href="https://cyberdudebivash.com/#scan" style="display:inline-block;background:#4f46e5;color:white;padding:12px 24px;border-radius:6px;text-decoration:none">Run a New Scan →</a>
          <p style="color:#888;font-size:12px;margin-top:30px"><a href="https://cyberdudebivash.com/unsubscribe?email=${encodeURIComponent(data.email)}">Unsubscribe</a></p>
        </div>`,
    },
    purchase_confirmation: {
      subject: `✅ Purchase Confirmed — ${data.product || data.plan}`,
      html: `
        <div style="font-family:sans-serif;max-width:600px;margin:0 auto">
          <h2>✅ Thank you for your purchase!</h2>
          <p>Your <strong>${data.product || data.plan}</strong> is ready.</p>
          ${data.plan ? `<p>Your account has been upgraded to <strong>${data.plan.toUpperCase()}</strong>. Reload the dashboard to access your new features.</p>` : ''}
          ${data.product ? `<p>Download your defense tools from your <a href="https://cyberdudebivash.com/user-dashboard.html">dashboard</a>.</p>` : ''}
          <p>Payment ID: <code>${data.payment_id || 'N/A'}</code></p>
          <p>Amount: <strong>₹${data.amount || 0}</strong></p>
          <a href="https://cyberdudebivash.com/user-dashboard.html" style="display:inline-block;background:#10b981;color:white;padding:12px 24px;border-radius:6px;text-decoration:none">Go to Dashboard →</a>
        </div>`,
    },
    threat_alert: {
      subject: `🚨 Critical Alert: ${data.cve_id} — CVSS ${data.cvss}`,
      html: `
        <div style="font-family:sans-serif;max-width:600px;margin:0 auto">
          <div style="background:#fee2e2;border-left:4px solid #ef4444;padding:16px;border-radius:4px">
            <h2 style="margin:0;color:#dc2626">🚨 Critical Security Alert</h2>
          </div>
          <h3>${data.cve_id} — ${data.title}</h3>
          <p><strong>CVSS Score:</strong> ${data.cvss}/10 | <strong>Severity:</strong> ${data.severity}</p>
          <p>Defense tools are now available for this vulnerability:</p>
          <ul>
            <li>Firewall Rules — ₹199</li>
            <li>IDS Signatures — ₹399</li>
            <li>IR Playbook — ₹999</li>
            <li>Full Defense Pack — ₹2,499</li>
          </ul>
          <a href="https://cyberdudebivash.com/intel/${data.cve_id}" style="display:inline-block;background:#ef4444;color:white;padding:12px 24px;border-radius:6px;text-decoration:none">Get Defense Tools →</a>
          <p style="color:#888;font-size:12px;margin-top:30px"><a href="https://cyberdudebivash.com/unsubscribe?email=">Unsubscribe from alerts</a></p>
        </div>`,
    },
  };

  return templates[type] || { subject: null, html: null };
}

function parseTactics(description) {
  if (!description) return ['Exploitation'];
  const tactics = [];
  const keywords = {
    'initial access': 'Initial Access',
    'execution': 'Execution',
    'privilege escalation': 'Privilege Escalation',
    'lateral movement': 'Lateral Movement',
    'exfiltration': 'Exfiltration',
    'persistence': 'Persistence',
    'command and control': 'Command and Control',
    'remote code': 'Execution',
    'sql injection': 'Initial Access',
    'xss': 'Initial Access',
    'buffer overflow': 'Execution',
  };
  const lower = description.toLowerCase();
  for (const [kw, tactic] of Object.entries(keywords)) {
    if (lower.includes(kw)) tactics.push(tactic);
  }
  return [...new Set(tactics)].slice(0, 4) || ['Exploitation'];
}

function parseProducts(title) {
  const products = [];
  const productMap = {
    'apache': 'Apache HTTP Server',
    'nginx': 'Nginx',
    'windows': 'Windows Server',
    'linux': 'Linux Kernel',
    'microsoft': 'Microsoft Products',
    'cisco': 'Cisco IOS',
    'openssl': 'OpenSSL',
    'java': 'Java Runtime',
    'php': 'PHP',
    'wordpress': 'WordPress',
  };
  const lower = title.toLowerCase();
  for (const [kw, product] of Object.entries(productMap)) {
    if (lower.includes(kw)) products.push(product);
  }
  return products.slice(0, 3);
}
