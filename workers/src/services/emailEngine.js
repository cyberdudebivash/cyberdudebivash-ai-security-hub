// ═══════════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH AI Security Hub — Email Drip Engine
// GTM Growth Engine Phase 3: Automated 4-Day Drip Sequence
// ═══════════════════════════════════════════════════════════════════════════



// ── Sequence configuration ───────────────────────────────────────────────────
export const DRIP_SEQUENCES = {
  welcome: {
    id:     'welcome',
    name:   'Welcome Drip',
    steps:  [0, 1, 2, 3],   // delay in days from signup
    trigger:'email_captured',
  },
  enterprise: {
    id:    'enterprise',
    name:  'Enterprise Sequence',
    steps: [0, 1, 3, 5, 7],
    trigger:'enterprise_lead_detected',
  },
  trial_expiry: {
    id:    'trial_expiry',
    name:  'Trial Expiry Nudge',
    steps: [0, 1],
    trigger:'trial_expiring',
  },
};

// ── Email sender defaults ────────────────────────────────────────────────────
const FROM_EMAIL   = 'Bivash @ Sentinel APEX <bivash@cyberdudebivash.in>';
const REPLY_TO     = 'bivashnayak.ai007@gmail.com';
const BASE_URL     = 'https://cyberdudebivash.in';
const TOOLS_URL    = 'https://tools.cyberdudebivash.com';
const UPGRADE_URL  = `${BASE_URL}/pricing`;
const UNSUBSCRIBE_URL = `${BASE_URL}/unsubscribe`;

// ─────────────────────────────────────────────────────────────────────────────
// EMAIL TEMPLATES
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Day 0 — Scan Report (immediate, post-capture)
 */
function templateDay0(lead, scanData = {}) {
  const { domain = 'your domain', risk_score = 0, critical = 0, high = 0, top_cve = null } = scanData;
  const riskLabel = risk_score >= 70 ? '🔴 CRITICAL RISK' : risk_score >= 40 ? '🟠 HIGH RISK' : '🟡 MEDIUM RISK';

  const subject = `⚠️ Your ${domain} Security Report — ${critical + high} Vulnerabilities Found`;

  const html = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0e1a">
<tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937;overflow:hidden">

  <!-- Header -->
  <tr><td style="background:linear-gradient(135deg,#1e40af,#7c3aed);padding:32px 40px;text-align:center">
    <div style="font-size:28px;font-weight:800;color:#fff;letter-spacing:-0.5px">🛡 Sentinel APEX</div>
    <div style="font-size:14px;color:#bfdbfe;margin-top:6px">AI-Powered Threat Intelligence Platform</div>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:40px">
    <h1 style="margin:0 0 8px;font-size:22px;color:#f1f5f9">Your Security Scan Report</h1>
    <p style="margin:0 0 24px;color:#94a3b8;font-size:15px">Scanned: <strong style="color:#e2e8f0">${domain}</strong></p>

    <!-- Risk Badge -->
    <div style="background:#1f2937;border-radius:8px;padding:20px;margin-bottom:24px;text-align:center">
      <div style="font-size:13px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">OVERALL RISK LEVEL</div>
      <div style="font-size:32px;font-weight:800">${riskLabel}</div>
      <div style="font-size:13px;color:#6b7280;margin-top:4px">Score: ${risk_score}/100</div>
    </div>

    <!-- Findings Grid -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:28px">
      <div style="background:#1f2937;border-radius:8px;padding:16px;text-align:center;border-left:3px solid #ef4444">
        <div style="font-size:32px;font-weight:800;color:#ef4444">${critical}</div>
        <div style="font-size:12px;color:#9ca3af;margin-top:4px">CRITICAL</div>
      </div>
      <div style="background:#1f2937;border-radius:8px;padding:16px;text-align:center;border-left:3px solid #f97316">
        <div style="font-size:32px;font-weight:800;color:#f97316">${high}</div>
        <div style="font-size:12px;color:#9ca3af;margin-top:4px">HIGH</div>
      </div>
    </div>

    ${top_cve ? `
    <!-- Top CVE -->
    <div style="background:#1a1032;border-radius:8px;padding:20px;margin-bottom:24px;border:1px solid #4f46e5">
      <div style="font-size:12px;color:#818cf8;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">⚡ TOP THREAT DETECTED</div>
      <div style="font-size:16px;font-weight:600;color:#e2e8f0;margin-bottom:4px">${top_cve.id}</div>
      <div style="font-size:14px;color:#94a3b8">${(top_cve.description || '').slice(0, 120)}...</div>
      <div style="margin-top:12px;font-size:13px;color:#6b7280">CVSS: <strong style="color:#ef4444">${top_cve.cvss || 'N/A'}</strong> · EPSS: <strong style="color:#f59e0b">${top_cve.epss_score ? (top_cve.epss_score * 100).toFixed(1) + '%' : 'N/A'}</strong></div>
    </div>` : ''}

    <!-- CTA -->
    <div style="text-align:center;margin-bottom:28px">
      <a href="${TOOLS_URL}?utm_source=email&utm_medium=drip&utm_campaign=day0&domain=${encodeURIComponent(domain)}"
         style="display:inline-block;background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:16px;font-weight:600">
        View Full Report →
      </a>
      <div style="margin-top:12px;font-size:13px;color:#6b7280">
        Free plan shows top 5 results. <a href="${UPGRADE_URL}?utm_source=email&utm_medium=drip&utm_campaign=day0_cta" style="color:#818cf8">Upgrade for full access</a>
      </div>
    </div>

    <hr style="border:none;border-top:1px solid #1f2937;margin:28px 0">
    <p style="color:#6b7280;font-size:13px;margin:0">
      You're receiving this because you scanned ${domain} on Sentinel APEX.
      <a href="${UNSUBSCRIBE_URL}?email={{EMAIL}}" style="color:#4b5563">Unsubscribe</a>
    </p>
  </td></tr>
</table>
</td></tr>
</table>
</body>
</html>`;

  const text = `Your ${domain} Security Report\n\nRisk Level: ${riskLabel}\nCritical: ${critical} | High: ${high}\n\nView your full report: ${TOOLS_URL}\n\nUpgrade for full access: ${UPGRADE_URL}`;

  return { subject, html, text };
}

/**
 * Day 1 — Risk Insights & Education
 */
function templateDay1(lead, scanData = {}) {
  const { domain = 'your domain', top_threats = [] } = scanData;
  const firstName = (lead.name || 'Security Pro').split(' ')[0];

  const subject = `📊 What your ${domain} risk score really means`;

  const threatSection = top_threats.slice(0, 3).map(t => `
    <div style="background:#1f2937;border-radius:8px;padding:16px;margin-bottom:12px;border-left:3px solid ${t.severity === 'CRITICAL' ? '#ef4444' : '#f97316'}">
      <div style="font-size:14px;font-weight:600;color:#e2e8f0;margin-bottom:4px">${t.id}</div>
      <div style="font-size:13px;color:#94a3b8">${(t.description || '').slice(0, 100)}...</div>
      <div style="font-size:12px;color:#6b7280;margin-top:6px">CVSS ${t.cvss || 'N/A'} · ${t.severity}</div>
    </div>`).join('');

  const html = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937">
  <tr><td style="background:linear-gradient(135deg,#1e40af,#7c3aed);padding:24px 40px;text-align:center">
    <div style="font-size:22px;font-weight:800;color:#fff">🛡 Sentinel APEX</div>
  </td></tr>
  <tr><td style="padding:40px">
    <h1 style="margin:0 0 8px;font-size:21px;color:#f1f5f9">Hi ${firstName},</h1>
    <p style="color:#94a3b8;font-size:15px;line-height:1.7">Yesterday you scanned <strong style="color:#e2e8f0">${domain}</strong>. Here's what the numbers actually mean for your security posture.</p>

    <h2 style="color:#f1f5f9;font-size:16px;margin:28px 0 12px">🔍 Understanding Your Threat Exposure</h2>
    <div style="background:#1f2937;border-radius:8px;padding:20px;margin-bottom:20px">
      <p style="margin:0;color:#94a3b8;font-size:14px;line-height:1.8">
        <strong style="color:#ef4444">CRITICAL vulnerabilities</strong> have a CVSS score ≥ 9.0 and are actively targeted by attackers. Average time-to-exploit after disclosure: <strong style="color:#f1f5f9">15 days</strong>.<br><br>
        <strong style="color:#f97316">HIGH vulnerabilities</strong> with EPSS scores above 0.70 have a 70%+ probability of being exploited in the next 30 days.
      </p>
    </div>

    ${threatSection ? `<h2 style="color:#f1f5f9;font-size:16px;margin:28px 0 12px">⚡ Your Top Threats</h2>${threatSection}` : ''}

    <div style="background:#1a1032;border-radius:8px;padding:20px;margin:24px 0;border:1px solid #4f46e5">
      <div style="font-size:14px;font-weight:600;color:#a5b4fc;margin-bottom:8px">💡 PRO Insight (Upgrade to unlock)</div>
      <p style="margin:0;color:#6b7280;font-size:13px;line-height:1.7">PRO subscribers get full IOC lists, exploit code availability status, MITRE ATT&CK mapping, and real-time alerts when new exploits for your vulnerabilities are discovered.</p>
    </div>

    <div style="text-align:center;margin:28px 0">
      <a href="${UPGRADE_URL}?utm_source=email&utm_medium=drip&utm_campaign=day1"
         style="display:inline-block;background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:16px;font-weight:600">
        Unlock Full Intelligence →
      </a>
    </div>

    <p style="color:#6b7280;font-size:13px"><a href="${UNSUBSCRIBE_URL}?email={{EMAIL}}" style="color:#4b5563">Unsubscribe</a></p>
  </td></tr>
</table>
</td></tr></table>
</body></html>`;

  const text = `Hi ${firstName},\n\nYour ${domain} scan results breakdown and what they mean for your security.\n\nUpgrade to see full intelligence: ${UPGRADE_URL}`;

  return { subject, html, text };
}

/**
 * Day 2 — Case Study / Social Proof
 */
function templateDay2(lead) {
  const firstName = (lead.name || 'Security Pro').split(' ')[0];
  const subject = `🏆 How SaaS teams use Sentinel APEX to stop breaches before they happen`;

  const html = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937">
  <tr><td style="background:linear-gradient(135deg,#1e40af,#7c3aed);padding:24px 40px;text-align:center">
    <div style="font-size:22px;font-weight:800;color:#fff">🛡 Sentinel APEX</div>
  </td></tr>
  <tr><td style="padding:40px">
    <h1 style="margin:0 0 16px;font-size:21px;color:#f1f5f9">Hi ${firstName},</h1>
    <p style="color:#94a3b8;font-size:15px;line-height:1.7">Here's a real scenario showing how Sentinel APEX stops breaches before attackers get in.</p>

    <!-- Case Study -->
    <div style="background:#1f2937;border-radius:12px;padding:28px;margin:24px 0;border-left:4px solid #10b981">
      <div style="font-size:12px;color:#10b981;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px">📋 CASE STUDY</div>
      <h3 style="margin:0 0 12px;color:#f1f5f9;font-size:17px">Mid-size SaaS company — 3 Critical CVEs, 0 Breaches</h3>
      <p style="margin:0 0 16px;color:#94a3b8;font-size:14px;line-height:1.8">
        A B2B SaaS platform with 200+ enterprise customers ran Sentinel APEX during their quarterly security review. The scan surfaced <strong style="color:#ef4444">CVE-2024-3400</strong> (Palo Alto PAN-OS, CVSS 10.0) in their VPN stack — a zero-day being actively exploited by state actors at the time.
      </p>
      <p style="margin:0 0 16px;color:#94a3b8;font-size:14px;line-height:1.8">
        Within 45 minutes of the alert, they patched the affected system and deployed WAF rules. The CISA KEV list confirmed 3 other organizations in their sector were breached via the same CVE that week.
      </p>
      <div style="background:#0d1a14;border-radius:8px;padding:16px">
        <div style="font-size:13px;color:#10b981;font-weight:600">Result: 0 breaches. $2.3M in potential breach costs avoided.</div>
      </div>
    </div>

    <!-- Stats -->
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin:24px 0">
      ${[
        ['15 days', 'avg time-to-exploit after CVE disclosure'],
        ['70%+', 'of breaches involve known, patchable CVEs'],
        ['4.5×', 'ROI on proactive threat intel vs. breach response'],
      ].map(([num, label]) => `
        <div style="background:#1f2937;border-radius:8px;padding:16px;text-align:center">
          <div style="font-size:24px;font-weight:800;color:#818cf8">${num}</div>
          <div style="font-size:11px;color:#6b7280;margin-top:4px;line-height:1.4">${label}</div>
        </div>`).join('')}
    </div>

    <!-- Features -->
    <h2 style="color:#f1f5f9;font-size:16px;margin:28px 0 12px">What PRO & Enterprise users get:</h2>
    ${[
      ['🔴', 'Real-time alerts when YOUR vulnerabilities are exploited'],
      ['🤖', 'AI SOC automation — detect, decide, respond in seconds'],
      ['🛡', 'Autonomous defense rules deployed to Cloudflare automatically'],
      ['📊', 'EPSS scores, IOC lists, MITRE ATT&CK mappings per CVE'],
      ['📡', 'Correlation engine — link CVEs to threat actor campaigns'],
    ].map(([icon, text]) => `
      <div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:12px">
        <div style="font-size:20px;flex-shrink:0">${icon}</div>
        <div style="font-size:14px;color:#94a3b8;line-height:1.6">${text}</div>
      </div>`).join('')}

    <div style="text-align:center;margin:32px 0">
      <a href="${UPGRADE_URL}?utm_source=email&utm_medium=drip&utm_campaign=day2"
         style="display:inline-block;background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:16px;font-weight:600">
        Start 14-Day Free Trial →
      </a>
      <div style="font-size:12px;color:#6b7280;margin-top:8px">Cancel anytime. No credit card required for Starter.</div>
    </div>

    <p style="color:#6b7280;font-size:13px"><a href="${UNSUBSCRIBE_URL}?email={{EMAIL}}" style="color:#4b5563">Unsubscribe</a></p>
  </td></tr>
</table>
</td></tr></table>
</body></html>`;

  const text = `Hi ${firstName},\n\nHow a SaaS company avoided a breach using Sentinel APEX — and how you can too.\n\nSee plans: ${UPGRADE_URL}`;

  return { subject, html, text };
}

/**
 * Day 3 — Upgrade Offer (urgency close)
 */
function templateDay3(lead, scanData = {}) {
  const firstName = (lead.name || 'Security Pro').split(' ')[0];
  const { critical = 0 } = scanData;
  const urgency = critical > 0 ? '🔴 You have unpatched CRITICAL vulnerabilities.' : '⚠️ Your threat exposure is unresolved.';

  const subject = `⏰ Last chance: Fix your security gaps before attackers find them`;

  const html = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937">
  <tr><td style="background:linear-gradient(135deg,#7c1d1d,#1e40af);padding:24px 40px;text-align:center">
    <div style="font-size:22px;font-weight:800;color:#fff">🛡 Sentinel APEX — Urgent Security Update</div>
  </td></tr>
  <tr><td style="padding:40px">
    <h1 style="margin:0 0 8px;font-size:21px;color:#f1f5f9">Hi ${firstName},</h1>
    <div style="background:#1a0808;border:1px solid #ef4444;border-radius:8px;padding:16px;margin:20px 0">
      <p style="margin:0;color:#fca5a5;font-size:15px;font-weight:600">${urgency}</p>
    </div>
    <p style="color:#94a3b8;font-size:15px;line-height:1.7">This is the last email in your free trial sequence. We want to make it count.</p>

    <!-- Pricing Table -->
    <h2 style="color:#f1f5f9;font-size:17px;margin:28px 0 16px">Choose your protection level:</h2>

    ${[
      { plan: 'STARTER', price: '₹499/mo', color: '#3b82f6', features: ['20 scans/day', 'Full reports', 'Basic IOC data', 'Email alerts'] },
      { plan: 'PRO', price: '₹1,499/mo', color: '#7c3aed', features: ['100 scans/day', 'Full IOC + correlations', 'EPSS scores', 'AI SOC detection', 'API access (1,000 calls/mo)'] },
      { plan: 'ENTERPRISE', price: '₹4,999/mo', color: '#10b981', features: ['Unlimited scans', 'Autonomous defense', 'Full SOC pipeline', 'Telegram alerting', 'Dedicated support'] },
    ].map(({ plan, price, color, features }) => `
      <div style="background:#1f2937;border-radius:8px;padding:20px;margin-bottom:12px;border-left:4px solid ${color}">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
          <div style="font-size:16px;font-weight:700;color:#f1f5f9">${plan}</div>
          <div style="font-size:16px;font-weight:700;color:${color}">${price}</div>
        </div>
        ${features.map(f => `<div style="font-size:13px;color:#94a3b8;margin-bottom:4px">✓ ${f}</div>`).join('')}
      </div>`).join('')}

    <div style="text-align:center;margin:32px 0">
      <a href="${UPGRADE_URL}?utm_source=email&utm_medium=drip&utm_campaign=day3&discount=APEX10"
         style="display:inline-block;background:linear-gradient(135deg,#dc2626,#7c3aed);color:#fff;text-decoration:none;padding:16px 40px;border-radius:8px;font-size:17px;font-weight:700">
        🔒 Secure Your Infrastructure Now →
      </a>
      <div style="font-size:13px;color:#f59e0b;margin-top:10px;font-weight:600">Use code APEX10 for 10% off your first month</div>
    </div>

    <p style="color:#94a3b8;font-size:14px;line-height:1.7;text-align:center">Questions? Reply to this email — I read every one personally.<br><strong>— Bivash, Founder</strong></p>

    <p style="color:#6b7280;font-size:13px"><a href="${UNSUBSCRIBE_URL}?email={{EMAIL}}" style="color:#4b5563">Unsubscribe</a></p>
  </td></tr>
</table>
</td></tr></table>
</body></html>`;

  const text = `Hi ${firstName},\n\n${urgency}\n\nUpgrade now: ${UPGRADE_URL}\n\nUse APEX10 for 10% off.`;

  return { subject, html, text };
}

// ─────────────────────────────────────────────────────────────────────────────
// SEQUENCE MANAGEMENT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Enroll a lead in a drip sequence
 */
export async function enrollInSequence(env, email, sequenceId = 'welcome', meta = {}) {
  const sequence = DRIP_SEQUENCES[sequenceId];
  if (!sequence) return { success: false, error: 'unknown_sequence' };

  const now = new Date().toISOString();

  try {
    // Check if already enrolled
    const existing = await env.DB.prepare(
      `SELECT id FROM email_sequences WHERE email = ? AND sequence_id = ? AND status = 'active' LIMIT 1`
    ).bind(email, sequenceId).first();

    if (existing) return { success: true, already_enrolled: true };

    await env.DB.prepare(`
      INSERT INTO email_sequences (id, email, sequence_id, current_step, status, meta, enrolled_at, next_send_at)
      VALUES (?, ?, ?, 0, 'active', ?, ?, ?)
    `).bind(
      crypto.randomUUID(), email, sequenceId, JSON.stringify(meta), now, now
    ).run();

    return { success: true, sequence: sequenceId };
  } catch (err) {
    console.error('[emailEngine] enrollInSequence error:', err.message);
    return { success: false, error: err.message };
  }
}

/**
 * Get emails due to be sent right now
 */
export async function getDueEmails(env, limit = 50) {
  try {
    const result = await env.DB.prepare(`
      SELECT es.*, l.name, l.domain, l.plan, l.lead_score
      FROM email_sequences es
      JOIN leads l ON l.email = es.email
      WHERE es.status = 'active'
        AND es.next_send_at <= datetime('now')
      LIMIT ?
    `).bind(limit).all();

    return result.results || [];
  } catch (err) {
    console.error('[emailEngine] getDueEmails error:', err.message);
    return [];
  }
}

/**
 * Mark a sequence step as sent and schedule the next
 */
export async function advanceSequence(env, sequenceRowId, nextStep, delayDays) {
  const nextSendAt = new Date(Date.now() + delayDays * 86400000).toISOString();
  const isDone = nextStep >= 4; // 4-day drip = steps 0–3

  try {
    await env.DB.prepare(`
      UPDATE email_sequences
      SET current_step = ?,
          status = ?,
          next_send_at = ?,
          last_sent_at = datetime('now')
      WHERE id = ?
    `).bind(
      nextStep,
      isDone ? 'completed' : 'active',
      nextSendAt,
      sequenceRowId
    ).run();
  } catch (err) {
    console.error('[emailEngine] advanceSequence error:', err.message);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// EMAIL SENDING (via MailChannels or Cloudflare Email Workers)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Send a single email via MailChannels API (Cloudflare-native, free)
 */
export async function sendEmail(env, { to, subject, html, text, replyTo = REPLY_TO }) {
  try {
    const payload = {
      personalizations: [{ to: [{ email: to }] }],
      from: { email: 'bivash@cyberdudebivash.in', name: 'Bivash @ Sentinel APEX' },
      reply_to: { email: replyTo },
      subject,
      content: [
        { type: 'text/plain', value: text },
        { type: 'text/html',  value: html  },
      ],
    };

    const resp = await fetch('https://api.mailchannels.net/tx/v1/send', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
    });

    const success = resp.status === 202 || resp.status === 200;
    return { success, status: resp.status };
  } catch (err) {
    console.error('[emailEngine] sendEmail error:', err.message);
    return { success: false, error: err.message };
  }
}

/**
 * Track email open/click event
 */
export async function trackEmailEvent(env, email, event, sequenceId, step) {
  try {
    await env.DB.prepare(`
      INSERT INTO email_tracking (id, email, sequence_id, step, event, created_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
    `).bind(crypto.randomUUID(), email, sequenceId, step, event).run();

    // Score the lead for engagement
    if (event === 'open' || event === 'click') {
      const now = new Date().toISOString();
      await env.DB.prepare(`
        UPDATE leads SET lead_score = MIN(lead_score + ?, 100), updated_at = ?
        WHERE email = ?
      `).bind(event === 'click' ? 20 : 10, now, email).run();
    }
  } catch {
    // Non-blocking
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// AUTOMATION: Run due drip emails
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Main drip runner — called by cron
 * Picks up all due email_sequences rows and sends the correct template
 */
export async function runDripAutomation(env) {
  const dueRows = await getDueEmails(env, 50);
  const results = { sent: 0, errors: 0, skipped: 0 };

  for (const row of dueRows) {
    const step       = row.current_step || 0;
    const email      = row.email;
    const lead       = { name: row.name, email, domain: row.domain, plan: row.plan };
    const meta       = JSON.parse(row.meta || '{}');
    const scanData   = meta.scanData || {};

    // Build template
    let template;
    try {
      switch (step) {
        case 0:  template = templateDay0(lead, scanData); break;
        case 1:  template = templateDay1(lead, scanData); break;
        case 2:  template = templateDay2(lead); break;
        case 3:  template = templateDay3(lead, scanData); break;
        default: await advanceSequence(env, row.id, step + 1, 0); continue;
      }
    } catch {
      results.skipped++;
      continue;
    }

    // Replace personalization tokens
    const html = template.html.replace(/\{\{EMAIL\}\}/g, encodeURIComponent(email));
    const text = template.text;

    // Send
    const result = await sendEmail(env, { to: email, subject: template.subject, html, text });

    if (result.success) {
      results.sent++;
      // Track in DB
      await env.DB.prepare(`
        INSERT INTO email_tracking (id, email, sequence_id, step, event, created_at)
        VALUES (?, ?, ?, ?, 'sent', datetime('now'))
      `).bind(crypto.randomUUID(), email, row.sequence_id, step).run().catch(() => {});
    } else {
      results.errors++;
    }

    // Advance sequence (next step is step+1, delay depends on step)
    const DELAYS = [0, 1, 1, 1]; // Day 0 → Day 1 → Day 2 → Day 3
    const delay = DELAYS[step] ?? 1;
    await advanceSequence(env, row.id, step + 1, delay);
  }

  return results;
}

/**
 * Send immediate welcome email (Day 0) on email capture
 */
export async function sendWelcomeEmail(env, email, lead, scanData = {}) {
  const template = templateDay0(lead, scanData);
  const html = template.html.replace(/\{\{EMAIL\}\}/g, encodeURIComponent(email));
  return sendEmail(env, { to: email, subject: template.subject, html, text: template.text });
}
