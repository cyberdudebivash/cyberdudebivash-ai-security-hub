// ═══════════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH AI Security Hub — Email Drip Engine
// GTM Growth Engine Phase 3: Automated 4-Day Drip Sequence
// ═══════════════════════════════════════════════════════════════════════════

import { ok, fail } from '../lib/response.js';

// ── Sequence configuration ───────────────────────────────────────────────────
export const DRIP_SEQUENCES = {
  welcome: {
    id:     'welcome',
    name:   'Welcome Drip',
    steps:  [0, 1, 2, 3],
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
  // ── Phase 4 post-purchase sequences ─────────────────────────────────────────
  subscription_activated: {
    id:    'subscription_activated',
    name:  'Subscription Onboarding',
    steps: [0, 2, 5],       // Day 0, Day 2, Day 5
    trigger:'subscription_payment_confirmed',
  },
  assessment_delivered: {
    id:    'assessment_delivered',
    name:  'Assessment Delivery',
    steps: [0, 3, 7],       // Day 0, Day 3, Day 7
    trigger:'assessment_payment_confirmed',
  },
  enterprise_nurture: {
    id:    'enterprise_nurture',
    name:  'Enterprise Nurture',
    steps: [0, 1, 3, 5, 7], // Day 0, 1, 3, 5, 7
    trigger:'enterprise_inquiry_received',
  },
  mssp_onboarded: {
    id:    'mssp_onboarded',
    name:  'MSSP Partner Onboarding',
    steps: [0, 3, 7],       // Day 0, Day 3, Day 7
    trigger:'mssp_partner_created',
  },
  // ── Phase 11 acquisition sequences ──────────────────────────────────────────
  upgrade_nudge: {
    id:    'upgrade_nudge',
    name:  'Quota Upgrade Nudge',
    steps: [0, 3],           // Day 0 (immediate), Day 3 (follow-up close)
    trigger:'quota_threshold_80pct',
  },
  enterprise_winback: {
    id:    'enterprise_winback',
    name:  'Enterprise Win-Back',
    steps: [0, 7, 14, 30],  // Day 0, 7, 14, 30
    trigger:'proposal_rejected',
  },
};

// ── Email sender defaults ────────────────────────────────────────────────────
const FROM_EMAIL   = 'Bivash @ Sentinel APEX <bivash@cyberdudebivash.in>';
const REPLY_TO     = 'bivashnayak.ai007@gmail.com';
const BASE_URL     = 'https://cyberdudebivash.in';
const TOOLS_URL    = 'https://tools.cyberdudebivash.com';
const UPGRADE_URL  = `${BASE_URL}/pricing`;
const UNSUBSCRIBE_URL = `${BASE_URL}/unsubscribe`;

// ── Shared HTML layout (Task 3 Phase 1) ─────────────────────────────────────
// New templates should build their body HTML and pass it here instead of
// hand-rolling the DOCTYPE/table/header boilerplate every template below
// this comment still repeats individually. The existing templates are
// intentionally NOT migrated to this helper — they're already shipped,
// revenue-facing emails, and this environment has no way to render/screenshot
// an HTML email to verify a refactor didn't introduce a visual regression.
// New event types added going forward should use this helper.
export function renderEmailLayout({ headerGradient = 'linear-gradient(135deg,#1e40af,#7c3aed)', headerTitle, headerSubtitle = '', bodyHtml }) {
  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0e1a">
<tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937;overflow:hidden">
  <tr><td style="background:${headerGradient};padding:32px 40px;text-align:center">
    <div style="font-size:26px;font-weight:800;color:#fff;letter-spacing:-0.5px">${headerTitle}</div>
    ${headerSubtitle ? `<div style="font-size:14px;color:#bfdbfe;margin-top:6px">${headerSubtitle}</div>` : ''}
  </td></tr>
  <tr><td style="padding:40px">
    ${bodyHtml}
  </td></tr>
</table>
</td></tr>
</table>
</body>
</html>`;
}

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
      { plan: 'STARTER', price: '₹999/mo', color: '#3b82f6', features: ['20 scans/day', 'Full reports', 'Basic IOC data', 'Email alerts'] },
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
// PHASE 4 POST-PURCHASE TEMPLATES
// ─────────────────────────────────────────────────────────────────────────────

function templateSubscriptionDay0(lead, meta = {}) {
  const tier   = meta.plan || meta.product || 'PRO';
  const apiKey = meta.api_key || '';
  const subject = `✅ Your ${tier} Plan is Active — Your API Key Inside`;
  const apiKeyBlock = apiKey
    ? `<div style="background:#0d1117;border-radius:8px;padding:16px 20px;margin:16px 0;border:1px solid #10b981">
        <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">YOUR API KEY</div>
        <code style="font-size:13px;color:#34d399;word-break:break-all;font-family:monospace">${apiKey}</code>
        <div style="font-size:12px;color:#6b7280;margin-top:8px">Use in header: <code style="color:#94a3b8">Authorization: Bearer ${apiKey}</code></div>
       </div>`
    : `<p style="margin:0 0 8px;color:#e2e8f0;font-size:14px">1. <strong>Get your API key</strong> from your dashboard at <a href="${BASE_URL}/user-dashboard" style="color:#34d399">user-dashboard</a></p>`;
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937">
<tr><td style="background:linear-gradient(135deg,#065f46,#047857);padding:28px 40px;text-align:center">
  <div style="font-size:26px;font-weight:800;color:#fff">🛡 CYBERDUDEBIVASH</div>
  <div style="font-size:13px;color:#a7f3d0;margin-top:4px">Your ${tier} Plan is now active</div>
</td></tr>
<tr><td style="padding:36px 40px">
  <h2 style="margin:0 0 16px;color:#f1f5f9;font-size:20px">Welcome to Sentinel APEX ${tier}</h2>
  <p style="color:#94a3b8;font-size:15px;line-height:1.7">Your subscription is active. Here's everything you need to get started:</p>
  <div style="background:#1f2937;border-radius:8px;padding:20px;margin:20px 0;border-left:4px solid #10b981">
    <div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px">GETTING STARTED</div>
    ${apiKeyBlock}
    <p style="margin:8px 0;color:#e2e8f0;font-size:14px">2. <strong>Run your first scan:</strong> POST /api/scan/domain with your API key in the Authorization header</p>
    <p style="margin:0;color:#e2e8f0;font-size:14px">3. <strong>Need help?</strong> WhatsApp <strong>+91 81798 81447</strong> or email contact@cyberdudebivash.in</p>
  </div>
  <div style="text-align:center;margin:28px 0">
    <a href="${BASE_URL}/user-dashboard" style="display:inline-block;background:linear-gradient(135deg,#065f46,#047857);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:15px;font-weight:600">Open Dashboard →</a>
  </div>
  <p style="color:#6b7280;font-size:13px">— Bivash, Founder · CYBERDUDEBIVASH PRIVATE LIMITED</p>
</td></tr>
</table></td></tr></table></body></html>`;
  return { subject, html, text: `Your ${tier} plan is active.${apiKey ? '\n\nYour API key: ' + apiKey : ''}\n\nDashboard: ${BASE_URL}/user-dashboard\n\nNeed help? WhatsApp +91 81798 81447` };
}

function templateSubscriptionDay2(lead, meta = {}) {
  const subject = 'Quick Start: 3 Scans to Run Today on Sentinel APEX';
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937">
<tr><td style="background:linear-gradient(135deg,#1e40af,#7c3aed);padding:28px 40px;text-align:center">
  <div style="font-size:26px;font-weight:800;color:#fff">🛡 CYBERDUDEBIVASH</div>
  <div style="font-size:13px;color:#bfdbfe;margin-top:4px">Getting Started Guide</div>
</td></tr>
<tr><td style="padding:36px 40px">
  <h2 style="margin:0 0 16px;color:#f1f5f9;font-size:20px">3 High-Value Scans to Run Today</h2>
  <p style="color:#94a3b8;font-size:15px">Here's how to get maximum ROI from your subscription in the first week:</p>
  ${[
    { icon: '🔍', title: 'Domain Security Scan', desc: 'POST /api/scan/domain — Maps your full attack surface in 90 seconds', priority: 'Start here' },
    { icon: '🤖', title: 'AI Security Scan', desc: 'POST /api/scan/ai — Detects AI/LLM vulnerabilities in your infrastructure', priority: 'High value' },
    { icon: '🛡', title: 'Compliance Check', desc: 'POST /api/generate/compliance — Generate ISO 27001 / SOC 2 gap analysis', priority: 'Quick win' },
  ].map(s => `<div style="background:#1f2937;border-radius:8px;padding:16px;margin-bottom:12px;border-left:3px solid #3b82f6">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <div style="font-size:15px;font-weight:600;color:#f1f5f9">${s.icon} ${s.title}</div>
      <span style="font-size:11px;color:#10b981;background:#064e3b;padding:3px 8px;border-radius:4px">${s.priority}</span>
    </div>
    <p style="margin:8px 0 0;color:#94a3b8;font-size:13px">${s.desc}</p>
  </div>`).join('')}
  <div style="text-align:center;margin:28px 0">
    <a href="${BASE_URL}/tools" style="display:inline-block;background:linear-gradient(135deg,#1e40af,#7c3aed);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:15px;font-weight:600">Open Platform →</a>
  </div>
</td></tr>
</table></td></tr></table></body></html>`;
  return { subject, html, text: `3 scans to run today on CYBERDUDEBIVASH:\n1. Domain Security: POST /api/scan/domain\n2. AI Security: POST /api/scan/ai\n3. Compliance: POST /api/generate/compliance\n\nOpen platform: ${BASE_URL}/tools` };
}

function templateSubscriptionDay5(lead, meta = {}) {
  const tier = meta.plan || 'PRO';
  const upgradeTarget = tier === 'STARTER' ? 'PRO' : 'ENTERPRISE';
  const subject = `📈 How ${tier} Users Double Their Security Coverage`;
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937">
<tr><td style="background:linear-gradient(135deg,#92400e,#d97706);padding:28px 40px;text-align:center">
  <div style="font-size:26px;font-weight:800;color:#fff">📈 Expand Your Coverage</div>
</td></tr>
<tr><td style="padding:36px 40px">
  <p style="color:#94a3b8;font-size:15px;line-height:1.7">You're getting great value from your ${tier} plan. Teams that upgrade to <strong style="color:#f1f5f9">${upgradeTarget}</strong> see 3x faster incident detection.</p>
  <div style="background:#1a1032;border-radius:8px;padding:20px;margin:20px 0;border:1px solid #4f46e5">
    <div style="font-size:13px;color:#818cf8;font-weight:600;margin-bottom:12px">WHAT ${upgradeTarget} UNLOCKS</div>
    ${tier === 'STARTER'
      ? `<p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ 100 scans/day (vs 20)</p><p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ Red Team simulator</p><p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ API access (1,000 calls/mo)</p><p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ SIEM export (JSON/CEF/STIX)</p>`
      : `<p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ Unlimited scans + multi-tenant org</p><p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ Autonomous SOC (24/7 auto-response)</p><p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ SLA support + dedicated engineer</p>`
    }
  </div>
  <div style="text-align:center;margin:28px 0">
    <a href="${UPGRADE_URL}?utm_source=email&utm_medium=lifecycle&utm_campaign=sub_d5" style="display:inline-block;background:linear-gradient(135deg,#92400e,#d97706);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:15px;font-weight:600">Upgrade to ${upgradeTarget} →</a>
    <p style="margin:12px 0 0;color:#6b7280;font-size:13px">Questions? Reply to this email — Bivash reads every one personally.</p>
  </div>
</td></tr>
</table></td></tr></table></body></html>`;
  return { subject, html, text: `Upgrade to ${upgradeTarget} for 3x faster incident detection.\nSee pricing: ${UPGRADE_URL}` };
}

function templateAssessmentDay0(lead, meta = {}) {
  const product = meta.product_name || 'Security Assessment';
  const subject = `✅ ${product} Confirmed — What Happens Next`;
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937">
<tr><td style="background:linear-gradient(135deg,#1e40af,#0284c7);padding:28px 40px;text-align:center">
  <div style="font-size:26px;font-weight:800;color:#fff">🛡 CYBERDUDEBIVASH</div>
  <div style="font-size:13px;color:#bae6fd;margin-top:4px">${product} — Payment Confirmed</div>
</td></tr>
<tr><td style="padding:36px 40px">
  <h2 style="margin:0 0 8px;color:#f1f5f9;font-size:20px">Your Assessment is Confirmed</h2>
  <p style="color:#94a3b8;font-size:15px;margin-bottom:24px">Thank you for your purchase. Here's exactly what happens next:</p>
  ${[
    { day: 'Within 2 hours', label: 'Analyst Assigned', desc: 'A senior security analyst will be assigned to your assessment and will email you to confirm scope.' },
    { day: 'Day 1–2',        label: 'Active Testing',   desc: 'We conduct automated + manual security testing across your specified scope.' },
    { day: 'Day 3',          label: 'Report Delivery',  desc: 'Full assessment report delivered to your email — executive summary + technical findings + remediation roadmap.' },
  ].map((s, i) => `<div style="display:flex;gap:16px;margin-bottom:20px">
    <div style="min-width:40px;height:40px;background:#1e40af;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#fff;flex-shrink:0;text-align:center;line-height:40px">${i + 1}</div>
    <div>
      <div style="font-size:12px;color:#60a5fa;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">${s.day}</div>
      <div style="font-size:15px;font-weight:600;color:#f1f5f9;margin-bottom:4px">${s.label}</div>
      <p style="margin:0;color:#94a3b8;font-size:14px">${s.desc}</p>
    </div>
  </div>`).join('')}
  <div style="background:#1f2937;border-radius:8px;padding:16px;margin-top:8px">
    <p style="margin:0;color:#94a3b8;font-size:14px">Questions? WhatsApp <strong style="color:#e2e8f0">+91 81798 81447</strong> · or reply to this email.<br>Bivash reads every message personally.</p>
  </div>
</td></tr>
</table></td></tr></table></body></html>`;
  return { subject, html, text: `Your ${product} is confirmed.\n\nWhat happens next:\n1. Analyst assigned within 2 hours\n2. Active testing Days 1-2\n3. Report delivered Day 3\n\nQuestions? WhatsApp +91 81798 81447` };
}

function templateAssessmentDay3(lead, meta = {}) {
  const product = meta.product_name || 'Security Assessment';
  const subject = `🔍 Your ${product} is in Progress — Check-In`;
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937">
<tr><td style="background:linear-gradient(135deg,#1e3a5f,#1e40af);padding:28px 40px;text-align:center">
  <div style="font-size:24px;font-weight:800;color:#fff">🔍 Assessment In Progress</div>
</td></tr>
<tr><td style="padding:36px 40px">
  <p style="color:#94a3b8;font-size:15px;line-height:1.7">Your ${product} is actively running. Our analyst is reviewing findings now.</p>
  <div style="background:#1f2937;border-radius:8px;padding:20px;margin:20px 0">
    <div style="font-size:13px;color:#60a5fa;font-weight:600;margin-bottom:8px">WHILE YOU WAIT — PREPARE YOUR TEAM</div>
    <p style="margin:0 0 8px;color:#e2e8f0;font-size:14px">✓ Identify your key stakeholders who should see the report</p>
    <p style="margin:0 0 8px;color:#e2e8f0;font-size:14px">✓ Prepare a list of your critical systems (for remediation priority)</p>
    <p style="margin:0;color:#e2e8f0;font-size:14px">✓ Block 1 hour for the executive brief we'll schedule after delivery</p>
  </div>
  <p style="color:#94a3b8;font-size:14px">Your report will arrive within the next 24 hours. Contact <a href="mailto:contact@cyberdudebivash.in" style="color:#60a5fa">contact@cyberdudebivash.in</a> if you have questions about scope.</p>
</td></tr>
</table></td></tr></table></body></html>`;
  return { subject, html, text: `Your ${product} is in progress. Report arriving within 24 hours.\n\nWhile you wait, prepare your team:\n- Identify key stakeholders\n- List critical systems\n- Block 1 hour for the executive brief\n\nQuestions: contact@cyberdudebivash.in` };
}

function templateAssessmentDay7(lead, meta = {}) {
  const subject = '🔄 Protect Your Business Year-Round — Upgrade to Continuous Monitoring';
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937">
<tr><td style="background:linear-gradient(135deg,#7c3aed,#4f46e5);padding:28px 40px;text-align:center">
  <div style="font-size:24px;font-weight:800;color:#fff">🔄 Stay Protected Year-Round</div>
</td></tr>
<tr><td style="padding:36px 40px">
  <p style="color:#94a3b8;font-size:15px;line-height:1.7">Your one-time assessment gave you a security snapshot. But threats evolve daily — <strong style="color:#f1f5f9">new CVEs are disclosed every 24 hours.</strong></p>
  <div style="background:#1a1032;border-radius:8px;padding:20px;margin:20px 0;border:1px solid #4f46e5">
    <div style="font-size:13px;color:#818cf8;font-weight:600;margin-bottom:12px">UPGRADE TO CONTINUOUS MONITORING</div>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ Real-time vulnerability alerts (new CVEs within hours)</p>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ Monthly automated re-assessments</p>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ AI threat predictions for your industry</p>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ Compliance dashboards (ISO 27001, SOC 2, DPDP 2023)</p>
  </div>
  <div style="text-align:center;margin:28px 0">
    <a href="${UPGRADE_URL}?utm_source=email&utm_medium=lifecycle&utm_campaign=assessment_d7" style="display:inline-block;background:linear-gradient(135deg,#7c3aed,#4f46e5);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:15px;font-weight:600">See Subscription Plans →</a>
    <p style="margin:12px 0 0;color:#6b7280;font-size:13px">Starting at ₹499/month. Cancel anytime.</p>
  </div>
</td></tr>
</table></td></tr></table></body></html>`;
  return { subject, html, text: `Stay protected year-round with continuous monitoring.\nNew CVEs disclosed every 24 hours — your one-time assessment is a snapshot, not a shield.\n\nSee subscription plans: ${UPGRADE_URL}\nStarting at ₹499/month.` };
}

function templateEnterpriseDay0(lead, meta = {}) {
  const company = meta.company || lead.name || 'your organization';
  const subject = `📥 Enterprise Inquiry Received — We'll Respond Within 4 Hours`;
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937">
<tr><td style="background:linear-gradient(135deg,#0f172a,#1e3a5f);padding:28px 40px;text-align:center;border-bottom:2px solid #1e40af">
  <div style="font-size:26px;font-weight:800;color:#fff">🏢 CYBERDUDEBIVASH Enterprise</div>
  <div style="font-size:13px;color:#94a3b8;margin-top:4px">Inquiry Received</div>
</td></tr>
<tr><td style="padding:36px 40px">
  <h2 style="margin:0 0 16px;color:#f1f5f9;font-size:20px">Thank you for reaching out, ${company}</h2>
  <p style="color:#94a3b8;font-size:15px;line-height:1.7">We've received your enterprise inquiry. A senior account executive will reach out within <strong style="color:#f1f5f9">4 business hours</strong> to schedule your discovery call.</p>
  <div style="background:#1f2937;border-radius:8px;padding:20px;margin:20px 0">
    <div style="font-size:13px;color:#60a5fa;font-weight:600;margin-bottom:12px">WHAT HAPPENS NEXT</div>
    <p style="margin:0 0 8px;color:#e2e8f0;font-size:14px"><strong>Step 1:</strong> Discovery Call (30 min) — We understand your threat landscape and compliance requirements</p>
    <p style="margin:0 0 8px;color:#e2e8f0;font-size:14px"><strong>Step 2:</strong> Custom Proposal — Tailored to your organization's size, industry, and risk profile</p>
    <p style="margin:0;color:#e2e8f0;font-size:14px"><strong>Step 3:</strong> Implementation — Dedicated engineer, SLA support, quarterly reviews</p>
  </div>
  <p style="color:#94a3b8;font-size:14px">For urgent matters: <a href="https://wa.me/918179881447" style="color:#34d399">WhatsApp +91 81798 81447</a></p>
  <p style="color:#6b7280;font-size:13px">— Bivash, Founder · contact@cyberdudebivash.in</p>
</td></tr>
</table></td></tr></table></body></html>`;
  return { subject, html, text: `Enterprise inquiry received for ${company}.\n\nWe'll respond within 4 business hours.\nUrgent: WhatsApp +91 81798 81447\n\n— Bivash, Founder` };
}

function templateEnterpriseDay1(lead, meta = {}) {
  const subject = '📊 How Enterprises Are Cutting Breach Risk by 73% with AI Security';
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937">
<tr><td style="background:linear-gradient(135deg,#0f172a,#1e3a5f);padding:28px 40px;text-align:center;border-bottom:2px solid #1e40af">
  <div style="font-size:24px;font-weight:800;color:#fff">📊 Enterprise Security Intelligence</div>
</td></tr>
<tr><td style="padding:36px 40px">
  <h2 style="margin:0 0 16px;color:#f1f5f9;font-size:20px">Why AI-Native Security Outperforms Traditional SIEM</h2>
  <p style="color:#94a3b8;font-size:15px;line-height:1.7">Enterprises using Sentinel APEX report a <strong style="color:#34d399">73% reduction in breach risk</strong> within 90 days of deployment.</p>
  ${[
    { stat: '73%', label: 'Breach risk reduction', color: '#ef4444' },
    { stat: '4.2h', label: 'Mean time to detect (vs 197h industry avg)', color: '#f59e0b' },
    { stat: '₹2.8Cr', label: 'Average annual savings vs traditional SIEM', color: '#10b981' },
  ].map(s => `<div style="display:flex;align-items:center;gap:16px;margin-bottom:16px;background:#1f2937;border-radius:8px;padding:16px">
    <div style="font-size:28px;font-weight:800;color:${s.color};min-width:80px">${s.stat}</div>
    <div style="font-size:14px;color:#94a3b8">${s.label}</div>
  </div>`).join('')}
  <div style="text-align:center;margin:28px 0">
    <a href="https://wa.me/918179881447?text=Hi%20Bivash%2C%20I%27d%20like%20to%20book%20a%20discovery%20call" style="display:inline-block;background:linear-gradient(135deg,#1e40af,#7c3aed);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:15px;font-weight:600">Book Discovery Call →</a>
  </div>
</td></tr>
</table></td></tr></table></body></html>`;
  return { subject, html, text: `Enterprises using Sentinel APEX report 73% breach risk reduction in 90 days.\n\nBook a discovery call: https://wa.me/918179881447` };
}

function templateEnterpriseDay3(lead, meta = {}) {
  const subject = '📅 Ready to See a Live Demo? Book 30 Minutes This Week';
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937">
<tr><td style="background:linear-gradient(135deg,#0f172a,#1e3a5f);padding:28px 40px;text-align:center">
  <div style="font-size:24px;font-weight:800;color:#fff">📅 Live Demo — 30 Minutes</div>
</td></tr>
<tr><td style="padding:36px 40px">
  <h2 style="margin:0 0 16px;color:#f1f5f9;font-size:20px">See Sentinel APEX Running on Your Domain</h2>
  <p style="color:#94a3b8;font-size:15px;line-height:1.7">In 30 minutes, I'll show you live threat intelligence running on your organization's domain — real CVEs, real attack paths, real compliance gaps.</p>
  <div style="background:#1f2937;border-radius:8px;padding:20px;margin:20px 0">
    <div style="font-size:13px;color:#60a5fa;font-weight:600;margin-bottom:12px">WHAT YOU'LL SEE IN THE DEMO</div>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ Live domain security scan (your domain, right now)</p>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ AI threat correlation with MITRE ATT&CK mapping</p>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ DPDP 2023 / ISO 27001 compliance dashboard</p>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ ROI calculator for your specific risk profile</p>
  </div>
  <div style="text-align:center;margin:28px 0">
    <a href="https://wa.me/918179881447?text=Hi%20Bivash%2C%20I%27d%20like%20to%20book%20a%2030-minute%20demo%20of%20Sentinel%20APEX" style="display:inline-block;background:linear-gradient(135deg,#1e40af,#7c3aed);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:15px;font-weight:600">Book 30-Minute Demo →</a>
    <p style="margin:12px 0 0;color:#6b7280;font-size:13px">Available Mon–Sat 9am–7pm IST · No sales pressure</p>
  </div>
</td></tr>
</table></td></tr></table></body></html>`;
  return { subject, html, text: `Book a 30-minute live demo — see Sentinel APEX running on your domain.\n\nBook via WhatsApp: https://wa.me/918179881447\nAvailable Mon-Sat 9am-7pm IST` };
}

function templateEnterpriseDay5(lead, meta = {}) {
  const company = meta.company || 'your organization';
  const subject = `📄 Custom Proposal Ready for ${company}`;
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937">
<tr><td style="background:linear-gradient(135deg,#0f172a,#1e3a5f);padding:28px 40px;text-align:center">
  <div style="font-size:24px;font-weight:800;color:#fff">📄 Your Custom Proposal</div>
</td></tr>
<tr><td style="padding:36px 40px">
  <h2 style="margin:0 0 16px;color:#f1f5f9;font-size:20px">Enterprise Security Proposal for ${company}</h2>
  <p style="color:#94a3b8;font-size:15px;line-height:1.7">Based on your inquiry, I've prepared a custom security proposal. Reply to this email or WhatsApp me and I'll send the full PDF proposal directly.</p>
  <div style="background:#1f2937;border-radius:8px;padding:20px;margin:20px 0">
    <div style="font-size:13px;color:#10b981;font-weight:600;margin-bottom:12px">WHAT'S IN YOUR PROPOSAL</div>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ Custom threat assessment for your industry</p>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ Recommended security stack with pricing</p>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ Implementation timeline (30-60-90 day plan)</p>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ ROI analysis and breach cost comparison</p>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ Reference contacts from similar deployments</p>
  </div>
  <div style="text-align:center;margin:28px 0">
    <a href="https://wa.me/918179881447?text=Hi%20Bivash%2C%20please%20send%20the%20enterprise%20proposal" style="display:inline-block;background:linear-gradient(135deg,#065f46,#047857);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:15px;font-weight:600">Request Proposal PDF →</a>
  </div>
  <p style="color:#6b7280;font-size:13px">— Bivash, Founder · contact@cyberdudebivash.in</p>
</td></tr>
</table></td></tr></table></body></html>`;
  return { subject, html, text: `Custom enterprise proposal ready for ${company}.\n\nReply to receive the full PDF proposal.\nWhatsApp: https://wa.me/918179881447\n\n— Bivash, Founder` };
}

function templateEnterpriseDay7(lead, meta = {}) {
  const subject = '⏰ One Week On — Ready to Move Forward?';
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937">
<tr><td style="background:linear-gradient(135deg,#4a1d96,#7c3aed);padding:28px 40px;text-align:center">
  <div style="font-size:24px;font-weight:800;color:#fff">⏰ Final Follow-Up</div>
</td></tr>
<tr><td style="padding:36px 40px">
  <h2 style="margin:0 0 16px;color:#f1f5f9;font-size:20px">Still Evaluating? I Can Help</h2>
  <p style="color:#94a3b8;font-size:15px;line-height:1.7">It's been a week since your enterprise inquiry. If you're still evaluating, I can answer any questions in 15 minutes — pricing, implementation complexity, compliance coverage, anything.</p>
  <div style="background:#1f2937;border-radius:8px;padding:20px;margin:20px 0">
    <p style="margin:0;color:#e2e8f0;font-size:15px;font-style:italic">"We deployed Sentinel APEX in 48 hours and found 3 critical vulnerabilities our existing tools missed. The ROI was visible in week one."</p>
    <p style="margin:12px 0 0;color:#94a3b8;font-size:13px">— CTO, Series B FinTech startup, Mumbai</p>
  </div>
  <div style="text-align:center;margin:28px 0">
    <a href="https://wa.me/918179881447?text=Hi%20Bivash%2C%20I%27m%20ready%20to%20move%20forward%20with%20the%20enterprise%20plan" style="display:inline-block;background:linear-gradient(135deg,#4a1d96,#7c3aed);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:15px;font-weight:600">Let's Talk →</a>
    <p style="margin:12px 0 0;color:#6b7280;font-size:13px">15-minute call. No pressure. Genuine conversation.</p>
  </div>
  <p style="color:#6b7280;font-size:13px">— Bivash · +91 81798 81447 · contact@cyberdudebivash.in</p>
</td></tr>
</table></td></tr></table></body></html>`;
  return { subject, html, text: `Still evaluating? I can answer any questions in 15 minutes.\nWhatsApp: https://wa.me/918179881447\n\n— Bivash, Founder` };
}

function templateMsspDay0(lead, meta = {}) {
  const company = meta.company || 'your company';
  const tier    = meta.tier || 'RESELLER';
  const subject = `🤝 Welcome to CYBERDUDEBIVASH MSSP Program — ${company}`;
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937">
<tr><td style="background:linear-gradient(135deg,#0f4c75,#1b6ca8);padding:28px 40px;text-align:center">
  <div style="font-size:26px;font-weight:800;color:#fff">🤝 MSSP Partner Program</div>
  <div style="font-size:13px;color:#bae6fd;margin-top:4px">${company} — ${tier} Tier</div>
</td></tr>
<tr><td style="padding:36px 40px">
  <h2 style="margin:0 0 16px;color:#f1f5f9;font-size:20px">Welcome to the MSSP Partner Network</h2>
  <p style="color:#94a3b8;font-size:15px;line-height:1.7">Your MSSP partner account has been created. You can now provision clients, customize your white-label portal, and start earning margin on every deployment.</p>
  <div style="background:#1f2937;border-radius:8px;padding:20px;margin:20px 0">
    <div style="font-size:13px;color:#38bdf8;font-weight:600;margin-bottom:12px">YOUR NEXT 3 ACTIONS</div>
    <p style="margin:0 0 8px;color:#e2e8f0;font-size:14px"><strong>1. Access MSSP Portal:</strong> <a href="${BASE_URL}/partner-portal" style="color:#38bdf8">cyberdudebivash.in/partner-portal</a> — enter this email to get a one-time login link, no password needed</p>
    <p style="margin:0 0 8px;color:#e2e8f0;font-size:14px"><strong>2. Set up white-label:</strong> Add your brand name, domain, and primary color</p>
    <p style="margin:0;color:#e2e8f0;font-size:14px"><strong>3. Onboard your first client:</strong> Use your Partner API key to provision client accounts</p>
  </div>
  <div style="background:#1a1032;border-radius:8px;padding:16px;margin:20px 0;border:1px solid #4f46e5">
    <div style="font-size:13px;color:#818cf8;font-weight:600;margin-bottom:8px">YOUR ${tier} BENEFITS</div>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ Up to 10 client seats</p>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ 20% margin on all client revenue</p>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ White-label dashboard + custom domain</p>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ Partner API key for automation</p>
  </div>
  <p style="color:#6b7280;font-size:13px">Questions? WhatsApp <strong style="color:#94a3b8">+91 81798 81447</strong> or email contact@cyberdudebivash.in</p>
</td></tr>
</table></td></tr></table></body></html>`;
  return { subject, html, text: `Welcome to CYBERDUDEBIVASH MSSP Program, ${company}!\n\nYour ${tier} account is ready.\nAccess portal: ${BASE_URL}/partner-portal (enter this email for a one-time login link)\n\nQuestions: WhatsApp +91 81798 81447` };
}

function templateMsspDay3(lead, meta = {}) {
  const subject = '📋 How to Onboard Your First 3 MSSP Clients (Step-by-Step)';
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937">
<tr><td style="background:linear-gradient(135deg,#0f4c75,#1b6ca8);padding:28px 40px;text-align:center">
  <div style="font-size:24px;font-weight:800;color:#fff">📋 Client Onboarding Guide</div>
</td></tr>
<tr><td style="padding:36px 40px">
  <h2 style="margin:0 0 16px;color:#f1f5f9;font-size:20px">Onboard Your First 3 Clients in 48 Hours</h2>
  <p style="color:#94a3b8;font-size:15px">Fastest path from partner to revenue:</p>
  ${[
    { step: 1, action: 'Identify target clients', detail: 'SMBs with 50–500 employees, in finance, healthcare, or tech — highest pain, fastest purchase decisions' },
    { step: 2, action: 'Use CYBERDUDEBIVASH demo', detail: 'Run a free scan on their domain at cyberdudebivash.in. Show them their risk score. Close the conversation in 20 minutes.' },
    { step: 3, action: 'Onboard via MSSP portal', detail: 'Create client account in your portal, assign their domain, provision access. Automated from there.' },
  ].map(s => `<div style="background:#1f2937;border-radius:8px;padding:16px;margin-bottom:12px">
    <div style="display:flex;align-items:center;gap:12px">
      <div style="min-width:32px;height:32px;background:#1b6ca8;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#fff;flex-shrink:0;line-height:32px;text-align:center">${s.step}</div>
      <div>
        <div style="font-size:15px;font-weight:600;color:#f1f5f9;margin-bottom:4px">${s.action}</div>
        <p style="margin:0;color:#94a3b8;font-size:13px">${s.detail}</p>
      </div>
    </div>
  </div>`).join('')}
  <p style="color:#6b7280;font-size:13px;margin-top:20px">Need help with a client pitch? Reply to this email — I'll send you a sales deck. — Bivash</p>
</td></tr>
</table></td></tr></table></body></html>`;
  return { subject, html, text: `Onboard your first 3 clients in 48 hours:\n1. Identify SMBs in finance/healthcare/tech\n2. Run a free scan on their domain to demonstrate value\n3. Onboard via MSSP portal\n\nNeed a sales deck? Reply to this email. — Bivash` };
}

function templateMsspDay7(lead, meta = {}) {
  const subject = '📈 Upgrade Your MSSP Tier — Unlock More Seats + Higher Margin';
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937">
<tr><td style="background:linear-gradient(135deg,#0f4c75,#1b6ca8);padding:28px 40px;text-align:center">
  <div style="font-size:24px;font-weight:800;color:#fff">📈 Scale Your MSSP Business</div>
</td></tr>
<tr><td style="padding:36px 40px">
  <p style="color:#94a3b8;font-size:15px;line-height:1.7">Partners who upgrade to <strong style="color:#f1f5f9">SILVER tier</strong> within their first 30 days add an average of 8 new clients in their second month.</p>
  <div style="background:#1f2937;border-radius:8px;padding:20px;margin:20px 0">
    <div style="font-size:13px;color:#38bdf8;font-weight:600;margin-bottom:12px">SILVER TIER UNLOCKS</div>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ 25 client seats (vs 10)</p>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ 25% margin (vs 20%)</p>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ Co-branded marketing materials</p>
    <p style="margin:4px 0;color:#e2e8f0;font-size:14px">✓ Partner success manager</p>
  </div>
  <div style="text-align:center;margin:28px 0">
    <a href="https://wa.me/918179881447?text=Hi%20Bivash%2C%20I%27d%20like%20to%20upgrade%20my%20MSSP%20tier" style="display:inline-block;background:linear-gradient(135deg,#0f4c75,#1b6ca8);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:15px;font-weight:600">Upgrade to SILVER →</a>
    <p style="margin:12px 0 0;color:#6b7280;font-size:13px">WhatsApp Bivash directly to discuss tier options</p>
  </div>
</td></tr>
</table></td></tr></table></body></html>`;
  return { subject, html, text: `Upgrade to SILVER MSSP tier — 25 client seats + 25% margin.\nWhatsApp Bivash: https://wa.me/918179881447` };
}

// ── upgrade_nudge templates ──────────────────────────────────────────────────

function templateUpgradeNudgeDay0(lead, meta) {
  const firstName = (lead?.name || 'Security Pro').split(' ')[0];
  const plan = (meta?.plan || 'free').toUpperCase();
  const used = meta?.scans_used ?? '?';
  const limit = meta?.scans_limit ?? '?';
  const upgradePlan = meta?.upgrade_plan || 'PRO';
  const subject = `⚡ You're at ${Math.round((used / limit) * 100)}% of your monthly scan quota`;
  const html = `<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#1e293b">
<h2 style="color:#dc2626">⚡ Heads up, ${firstName}</h2>
<p>You've used <strong>${used} of ${limit} scans</strong> on your ${plan} plan this month.</p>
<p>When you hit the limit, all scans are blocked until next month — including critical threat re-checks.</p>
<h3>Upgrade to ${upgradePlan} and get:</h3>
<ul>
  <li>${upgradePlan === 'PRO' ? 'Unlimited scans every month' : '10 scans per month (3× more)'}</li>
  <li>AI Threat Brain — deeper CVE and IOC analysis</li>
  <li>PDF reports for every scan</li>
  <li>Priority email support</li>
</ul>
<a href="${UPGRADE_URL}?plan=${upgradePlan.toLowerCase()}&utm_source=email&utm_medium=upgrade_nudge&utm_campaign=quota_80pct" style="display:inline-block;background:#2563eb;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;margin-top:12px">Upgrade to ${upgradePlan} — Starting ₹${upgradePlan === 'PRO' ? '1499' : '499'}/mo →</a>
<p style="margin-top:24px;font-size:13px;color:#64748b">Your quota resets on the 1st of next month. Upgrade anytime — your remaining scans this month carry forward.</p>
</body></html>`;
  return { subject, html, text: `You've used ${used}/${limit} scans on your ${plan} plan. Upgrade to ${upgradePlan} to avoid interruption: ${UPGRADE_URL}` };
}

function templateUpgradeNudgeDay3(lead, meta) {
  const firstName = (lead?.name || 'Security Pro').split(' ')[0];
  const upgradePlan = meta?.upgrade_plan || 'PRO';
  const subject = `🔒 3 days left — don't let threats go unchecked`;
  const html = `<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#1e293b">
<h2 style="color:#7c3aed">Still thinking, ${firstName}?</h2>
<p>Your scan quota is almost exhausted. Every day without monitoring is a day attackers have the advantage.</p>
<p><strong>New CVEs are published daily.</strong> PRO plan runs continuous monitoring so you're always current.</p>
<blockquote style="border-left:4px solid #7c3aed;padding:12px;background:#f5f3ff;margin:16px 0">"We caught a CVSS 9.3 vulnerability in our payment API on day 4 of the monitoring trial. It had been there for 6 months." — CTO, SaaS startup</blockquote>
<a href="${UPGRADE_URL}?plan=${upgradePlan.toLowerCase()}&utm_source=email&utm_medium=upgrade_nudge&utm_campaign=quota_followup" style="display:inline-block;background:#7c3aed;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">Upgrade Now — Cancel Anytime →</a>
</body></html>`;
  return { subject, html, text: `Your scan quota is almost exhausted, ${firstName}. Upgrade to ${upgradePlan} to keep monitoring: ${UPGRADE_URL}` };
}

// ── enterprise_winback templates ─────────────────────────────────────────────

function templateWinbackDay0(lead, meta) {
  const firstName = (lead?.name || 'there').split(' ')[0];
  const productName = meta?.product_name || 'Enterprise Security Assessment';
  const subject = `A quick follow-up on your ${productName} proposal`;
  const html = `<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#1e293b">
<p>Hi ${firstName},</p>
<p>I noticed the proposal for <strong>${productName}</strong> didn't move forward — no pressure, completely understand.</p>
<p>I wanted to briefly check: was it timing, budget, or something we could address?</p>
<p>If it was timing, I can hold the exact pricing for 30 days. If it was scope, we can restructure the engagement.</p>
<p>Even a 2-line reply helps us improve. And if circumstances have changed, I'm happy to revisit.</p>
<p>Either way, our free threat scan is always available at <a href="${BASE_URL}">${BASE_URL}</a> — no commitment.</p>
<p>— Bivash, Cyberdudebivash Security</p>
</body></html>`;
  return { subject, html, text: `Hi ${firstName}, following up on the ${productName} proposal. Was it timing or budget? Happy to revisit. — Bivash` };
}

function templateWinbackDay7(lead, meta) {
  const firstName = (lead?.name || 'there').split(' ')[0];
  const subject = `New: AI Security capabilities added since your last review`;
  const html = `<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#1e293b">
<h2>What's new since your proposal, ${firstName}</h2>
<p>We've shipped significant capabilities in the past few weeks that may be relevant to your security posture:</p>
<ul>
  <li><strong>MCP Security Analysis</strong> — AI tool chain threat modelling (new attack surface for LLM-driven apps)</li>
  <li><strong>Vibe Coding Risk Scoring</strong> — Assess AI-generated code for injection and logic flaws</li>
  <li><strong>OWASP LLM Top 10 Compliance</strong> — Automated check against all 10 LLM risk categories</li>
  <li><strong>Real-Time KEV Alerts</strong> — Notified within 2h of any CISA KEV match on your stack</li>
</ul>
<p>These are available on the Enterprise plan and can be added to your original scope at no extra cost.</p>
<a href="${BASE_URL}/pricing?utm_source=email&utm_medium=winback&utm_campaign=day7" style="display:inline-block;background:#f59e0b;color:#000;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">See Full Enterprise Capabilities →</a>
</body></html>`;
  return { subject, html, text: `Hi ${firstName}, we've added MCP security, vibe coding risk scoring, and real-time KEV alerts since your last review. See what's new: ${BASE_URL}/pricing` };
}

function templateWinbackDay14(lead, meta) {
  const firstName = (lead?.name || 'there').split(' ')[0];
  const subject = `Special offer: 3-month enterprise engagement (limited availability)`;
  const html = `<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#1e293b">
<h2 style="color:#059669">${firstName} — a limited offer for past prospects</h2>
<p>For prospects who reviewed our Enterprise assessment this quarter, we're offering a <strong>3-month engagement at 20% below our standard rate</strong> — no contract lock-in, cancel after month 1 if you're not satisfied.</p>
<p>This covers:</p>
<ul>
  <li>Full infrastructure and application security assessment</li>
  <li>AI/LLM security posture review</li>
  <li>Monthly executive threat briefing</li>
  <li>Dedicated Slack channel with our security team</li>
  <li>Remediation verification for all critical findings</li>
</ul>
<p><strong>Available to 3 companies this month.</strong> Spots fill based on start date, not sign-date.</p>
<a href="mailto:bivash@cyberdudebivash.in?subject=Re: Enterprise Security Engagement&body=Hi Bivash, I'm interested in the 3-month engagement offer." style="display:inline-block;background:#059669;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">Reply to Claim Your Spot →</a>
</body></html>`;
  return { subject, html, text: `${firstName}, we're offering a 3-month enterprise engagement at 20% below standard rate for past prospects. Limited to 3 spots this month. Reply to claim yours.` };
}

function templateWinbackDay30(lead, meta) {
  const firstName = (lead?.name || 'there').split(' ')[0];
  const subject = `Complimentary quarterly security assessment — for ${firstName}`;
  const html = `<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#1e293b">
<p>Hi ${firstName},</p>
<p>It's been about a month since we last connected. The threat landscape keeps shifting, with new CISA KEV advisories and AI-driven attack techniques targeting SaaS infrastructure appearing regularly.</p>
<p>We'd like to offer you a <strong>complimentary 30-minute security posture review</strong> — no pitch, no obligation. Just an honest look at where your current exposure stands vs. industry peers.</p>
<p>If anything's changed on your end — new products, new team members, new cloud infra — this is a fast way to understand your current risk profile.</p>
<a href="https://calendly.com/bivash-cyberdudebivash?utm_source=email&utm_medium=winback&utm_campaign=day30" style="display:inline-block;background:#1e293b;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">Book 30-Min Security Review (Free) →</a>
<p style="margin-top:24px;font-size:13px;color:#64748b">If you'd prefer not to receive these, just reply "unsubscribe" and I'll remove you immediately.</p>
</body></html>`;
  return { subject, html, text: `Hi ${firstName}, complimentary 30-min security posture review — no pitch, no obligation. Book here: https://calendly.com/bivash-cyberdudebivash` };
}

// ─── Template dispatcher for all sequences ────────────────────────────────────
function getSequenceTemplate(sequenceId, step, lead, meta) {
  switch (sequenceId) {
    case 'subscription_activated':
      if (step === 0) return templateSubscriptionDay0(lead, meta);
      if (step === 1) return templateSubscriptionDay2(lead, meta);
      if (step === 2) return templateSubscriptionDay5(lead, meta);
      return null;

    case 'assessment_delivered':
      if (step === 0) return templateAssessmentDay0(lead, meta);
      if (step === 1) return templateAssessmentDay3(lead, meta);
      if (step === 2) return templateAssessmentDay7(lead, meta);
      return null;

    case 'enterprise_nurture':
      if (step === 0) return templateEnterpriseDay0(lead, meta);
      if (step === 1) return templateEnterpriseDay1(lead, meta);
      if (step === 2) return templateEnterpriseDay3(lead, meta);
      if (step === 3) return templateEnterpriseDay5(lead, meta);
      if (step === 4) return templateEnterpriseDay7(lead, meta);
      return null;

    case 'mssp_onboarded':
      if (step === 0) return templateMsspDay0(lead, meta);
      if (step === 1) return templateMsspDay3(lead, meta);
      if (step === 2) return templateMsspDay7(lead, meta);
      return null;

    case 'upgrade_nudge':
      if (step === 0) return templateUpgradeNudgeDay0(lead, meta);
      if (step === 1) return templateUpgradeNudgeDay3(lead, meta);
      return null;

    case 'enterprise_winback':
      if (step === 0) return templateWinbackDay0(lead, meta);
      if (step === 1) return templateWinbackDay7(lead, meta);
      if (step === 2) return templateWinbackDay14(lead, meta);
      if (step === 3) return templateWinbackDay30(lead, meta);
      return null;

    default:
      return null;
  }
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
    // Atomic conditional insert — eliminates the SELECT-then-INSERT TOCTOU race
    const result = await env.DB.prepare(`
      INSERT INTO email_sequences (id, email, sequence_id, current_step, status, meta, enrolled_at, next_send_at)
      SELECT ?, ?, ?, 0, 'active', ?, ?, ?
      WHERE NOT EXISTS (
        SELECT 1 FROM email_sequences WHERE email = ? AND sequence_id = ? AND status = 'active'
      )
    `).bind(
      crypto.randomUUID(), email, sequenceId, JSON.stringify(meta), now, now,
      email, sequenceId,
    ).run();

    if ((result.meta?.changes ?? 1) === 0) return { success: true, already_enrolled: true };

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
      LEFT JOIN leads l ON l.email = es.email
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
 * Send a single email.
 *
 * Provider cascade (in priority order):
 *   1. Resend (resend.com) — primary; requires env.RESEND_API_KEY secret
 *   2. MailChannels         — Cloudflare-native fallback (still works on paid plans)
 *
 * Set secrets:
 *   npx wrangler secret put RESEND_API_KEY   ← get free key at resend.com (3,000 emails/mo)
 *
 * Resend setup:
 *   1. Sign up at https://resend.com (free tier: 3,000 emails/month)
 *   2. Verify your domain (cyberdudebivash.in) in the Resend dashboard
 *   3. Create an API key and run: npx wrangler secret put RESEND_API_KEY
 */
export async function sendEmail(env, { to, subject, html, text, replyTo = REPLY_TO }) {
  // ── 1. Resend (primary) ──────────────────────────────────────────────────
  if (env?.RESEND_API_KEY) {
    try {
      const payload = {
        from: FROM_EMAIL,
        to:   [to],
        subject,
        html,
        text,
        reply_to: replyTo,
        headers: { 'X-Platform': 'CYBERDUDEBIVASH-SentinelAPEX-8.1' },
      };
      const resp = await fetch('https://api.resend.com/emails', {
        method:  'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        },
        body: JSON.stringify(payload),
      });
      if (resp.status === 200 || resp.status === 201) {
        const body = await resp.json().catch(() => ({}));
        return { success: true, provider: 'resend', message_id: body.id };
      }
      const errBody = await resp.text().catch(() => '');
      console.warn('[emailEngine] Resend error:', resp.status, errBody.slice(0, 200));
      // Fall through to MailChannels
    } catch (err) {
      console.warn('[emailEngine] Resend fetch error:', err.message);
    }
  }

  // ── 2. MailChannels (fallback) ────────────────────────────────────────────
  try {
    const payload = {
      personalizations: [{ to: [{ email: to }] }],
      from: { email: 'bivash@cyberdudebivash.in', name: 'Bivash @ Sentinel APEX' },
      reply_to: { email: replyTo },
      subject,
      content: [
        { type: 'text/plain', value: text || '' },
        { type: 'text/html',  value: html  || '' },
      ],
    };
    const resp = await fetch('https://api.mailchannels.net/tx/v1/send', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
    });
    const success = resp.status === 202 || resp.status === 200;
    return { success, provider: 'mailchannels', status: resp.status };
  } catch (err) {
    console.error('[emailEngine] MailChannels error:', err.message);
    return { success: false, provider: 'none', error: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// DEAD LETTER QUEUE (Task 3 Phase 1)
// ─────────────────────────────────────────────────────────────────────────────
// Before this, a send that failed on both Resend and MailChannels was only
// ever console.error'd — the email content was gone with no way to inspect
// or redeliver it. sendEmailWithRetry() persists that failure to email_dlq
// instead, and runEmailDlqRetry() (cron-driven, alongside runDripAutomation)
// re-attempts pending rows with a bounded retry count.
async function ensureEmailDlqTable(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS email_dlq (
    id              TEXT PRIMARY KEY,
    to_email        TEXT NOT NULL,
    subject         TEXT NOT NULL,
    html            TEXT NOT NULL,
    text            TEXT,
    event_type      TEXT NOT NULL DEFAULT 'generic',
    attempts        INTEGER NOT NULL DEFAULT 1,
    last_error      TEXT,
    status          TEXT NOT NULL DEFAULT 'pending_retry',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_attempt_at TEXT,
    resolved_at     TEXT
  )`).run();
}

const MAX_DLQ_ATTEMPTS = 5;

/**
 * Send an email; on total failure (every provider in sendEmail's cascade
 * failed), persist it to email_dlq for a later cron retry instead of
 * silently dropping it. Same call signature as sendEmail() plus an optional
 * eventType tag for DLQ/admin visibility.
 */
export async function sendEmailWithRetry(env, { to, subject, html, text, replyTo, eventType = 'generic' }) {
  const result = await sendEmail(env, { to, subject, html, text, replyTo });
  if (result.success || !env?.DB) return result;

  try {
    await ensureEmailDlqTable(env.DB);
    await env.DB.prepare(`
      INSERT INTO email_dlq (id, to_email, subject, html, text, event_type, attempts, last_error, status, created_at, last_attempt_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, ?, 'pending_retry', datetime('now'), datetime('now'))
    `).bind(
      crypto.randomUUID(), to, subject, html, text || '', eventType,
      result.error || `provider=${result.provider}${result.status ? ' status=' + result.status : ''}`,
    ).run();
  } catch (e) {
    console.error('[emailEngine] DLQ insert failed:', e.message);
  }
  return result;
}

/**
 * Cron-driven DLQ sweep — retries pending_retry rows, marks them recovered
 * or (after MAX_DLQ_ATTEMPTS) failed_permanent.
 */
export async function runEmailDlqRetry(env, limit = 20) {
  if (!env?.DB) return { retried: 0, recovered: 0, permanentlyFailed: 0 };
  await ensureEmailDlqTable(env.DB).catch(() => {});

  const { results } = await env.DB.prepare(
    `SELECT * FROM email_dlq WHERE status = 'pending_retry' ORDER BY created_at ASC LIMIT ?`
  ).bind(limit).all().catch(() => ({ results: [] }));

  const out = { retried: 0, recovered: 0, permanentlyFailed: 0 };
  for (const row of results || []) {
    out.retried++;
    const result = await sendEmail(env, { to: row.to_email, subject: row.subject, html: row.html, text: row.text });
    if (result.success) {
      out.recovered++;
      await env.DB.prepare(
        `UPDATE email_dlq SET status = 'recovered', resolved_at = datetime('now') WHERE id = ?`
      ).bind(row.id).run().catch(() => {});
      continue;
    }
    const attempts = (row.attempts || 1) + 1;
    const lastError = result.error || `provider=${result.provider}${result.status ? ' status=' + result.status : ''}`;
    if (attempts >= MAX_DLQ_ATTEMPTS) {
      out.permanentlyFailed++;
      await env.DB.prepare(
        `UPDATE email_dlq SET status = 'failed_permanent', attempts = ?, last_error = ?, last_attempt_at = datetime('now') WHERE id = ?`
      ).bind(attempts, lastError, row.id).run().catch(() => {});
    } else {
      await env.DB.prepare(
        `UPDATE email_dlq SET attempts = ?, last_error = ?, last_attempt_at = datetime('now') WHERE id = ?`
      ).bind(attempts, lastError, row.id).run().catch(() => {});
    }
  }
  return out;
}

// ── GET /api/admin/email-dlq — ops visibility into undeliverable emails ────
export async function handleAdminListEmailDlq(request, env, authCtx) {
  if (authCtx?.isAdmin !== true) return fail(request, 'Admin access required', 403, 'ADMIN_ONLY');
  if (!env.DB) return ok(request, { rows: [] });
  await ensureEmailDlqTable(env.DB).catch(() => {});

  const url = new URL(request.url);
  const status = url.searchParams.get('status');
  const limit = Math.min(parseInt(url.searchParams.get('limit'), 10) || 50, 200);

  const query = status
    ? env.DB.prepare(`SELECT id, to_email, subject, event_type, attempts, last_error, status, created_at, last_attempt_at, resolved_at FROM email_dlq WHERE status = ? ORDER BY created_at DESC LIMIT ?`).bind(status, limit)
    : env.DB.prepare(`SELECT id, to_email, subject, event_type, attempts, last_error, status, created_at, last_attempt_at, resolved_at FROM email_dlq ORDER BY created_at DESC LIMIT ?`).bind(limit);

  const { results } = await query.all().catch(() => ({ results: [] }));
  return ok(request, { rows: results || [], count: (results || []).length });
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

    // Build template — dispatch by sequence_id, then step
    let template;
    try {
      const seqId = row.sequence_id || 'welcome';
      if (seqId === 'welcome' || seqId === 'enterprise' || seqId === 'trial_expiry') {
        // Legacy welcome/enterprise drip (original 4-day sequence)
        switch (step) {
          case 0:  template = templateDay0(lead, scanData); break;
          case 1:  template = templateDay1(lead, scanData); break;
          case 2:  template = templateDay2(lead); break;
          case 3:  template = templateDay3(lead, scanData); break;
          default: await advanceSequence(env, row.id, step + 1, 0); continue;
        }
      } else {
        // Phase 4 post-purchase sequences
        template = getSequenceTemplate(seqId, step, lead, meta);
        if (!template) { await advanceSequence(env, row.id, step + 1, 0); continue; }
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

    const DELAY_MAP = {
      welcome:                [0, 1, 1, 1],
      enterprise:             [0, 1, 2, 2, 2],
      trial_expiry:           [0, 1],
      subscription_activated: [0, 2, 3],
      assessment_delivered:   [0, 3, 4],
      enterprise_nurture:     [0, 1, 2, 2, 2],
      mssp_onboarded:         [0, 3, 4],
      upgrade_nudge:          [0, 3],
      enterprise_winback:     [0, 7, 7, 16],
    };
    const seqId  = row.sequence_id || 'welcome';
    const delays = DELAY_MAP[seqId] || [0, 1, 1, 1];
    const delay  = delays[step] ?? 1;

    if (result.success) {
      results.sent++;
      await env.DB.prepare(`
        INSERT INTO email_tracking (id, email, sequence_id, step, event, created_at)
        VALUES (?, ?, ?, ?, 'sent', datetime('now'))
      `).bind(crypto.randomUUID(), email, row.sequence_id, step).run().catch(() => {});
      await advanceSequence(env, row.id, step + 1, delay);
    } else {
      results.errors++;
      // Retry with backoff — do NOT advance step. Track retries in meta.
      const currentMeta  = JSON.parse(row.meta || '{}');
      const retryCount   = (currentMeta._retry_count || 0) + 1;
      if (retryCount >= 3) {
        // 3 consecutive failures — mark sequence step as permanently failed, advance past it
        await advanceSequence(env, row.id, step + 1, delay);
        await env.DB.prepare(`
          INSERT INTO email_tracking (id, email, sequence_id, step, event, created_at)
          VALUES (?, ?, ?, ?, 'failed_permanent', datetime('now'))
        `).bind(crypto.randomUUID(), email, row.sequence_id, step).run().catch(() => {});
      } else {
        // Exponential backoff retry: 1h, 2h (next cron pickup)
        const nextRetry = new Date(Date.now() + retryCount * 3600000).toISOString();
        await env.DB.prepare(`
          UPDATE email_sequences SET next_send_at = ?, meta = ? WHERE id = ?
        `).bind(nextRetry, JSON.stringify({ ...currentMeta, _retry_count: retryCount }), row.id).run().catch(() => {});
        // Track transient failures for email health monitoring
        await env.DB.prepare(`
          INSERT INTO email_tracking (id, email, sequence_id, step, event, created_at)
          VALUES (?, ?, ?, ?, 'failed_retry', datetime('now'))
        `).bind(crypto.randomUUID(), email, row.sequence_id, step).run().catch(() => {});
      }
    }
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

/**
 * Send purchase confirmation email after a successful Razorpay payment.
 * Call fire-and-forget (don't await in the critical path).
 *
 * @param {object} env                - Cloudflare Workers env
 * @param {object} opts
 * @param {string} opts.to            - customer email
 * @param {string} opts.productName   - human-readable product title
 * @param {number} opts.amountInr     - total paid in INR (customer-facing price)
 * @param {string} opts.paymentId     - Razorpay payment_id
 * @param {string} [opts.downloadUrl] - direct download/access URL (scan reports)
 * @param {string} [opts.invoiceNumber] - GST invoice number if created
 * @param {string} [opts.accessExpires] - ISO date when access expires
 */
export async function sendPurchaseConfirmation(env, {
  to, productName, amountInr, paymentId,
  downloadUrl = null, invoiceNumber = null, accessExpires = null,
}) {
  if (!to || !productName) return { success: false, reason: 'missing_params' };

  const subject = `✅ Purchase Confirmed — ${productName} | CYBERDUDEBIVASH`;
  const gstInclusive = amountInr;
  const baseAmt      = Math.round(gstInclusive / 1.18);
  const gstAmt       = gstInclusive - baseAmt;
  const expiryText   = accessExpires
    ? `<p style="color:#94a3b8;font-size:14px">Access valid until: <strong style="color:#e2e8f0">${new Date(accessExpires).toLocaleDateString('en-IN', { year:'numeric', month:'long', day:'numeric' })}</strong></p>`
    : '';
  const downloadBtn  = downloadUrl
    ? `<a href="${BASE_URL}${downloadUrl}" style="display:inline-block;margin-top:8px;padding:12px 28px;background:linear-gradient(135deg,#1e40af,#7c3aed);color:#fff;font-weight:700;font-size:15px;text-decoration:none;border-radius:8px">⬇️ Download Your Report</a>`
    : `<p style="color:#94a3b8;font-size:14px">Your access has been activated on the platform. Log in at <a href="${BASE_URL}" style="color:#60a5fa">${BASE_URL}</a> to access your purchase.</p>`;
  const invoiceLine  = invoiceNumber
    ? `<p style="color:#94a3b8;font-size:13px">GST Invoice: <strong style="color:#e2e8f0">${invoiceNumber}</strong> — available on request at <a href="mailto:contact@cyberdudebivash.in" style="color:#60a5fa">contact@cyberdudebivash.in</a></p>`
    : `<p style="color:#94a3b8;font-size:13px">GST invoice will be emailed within 24 hours. Contact <a href="mailto:contact@cyberdudebivash.in" style="color:#60a5fa">contact@cyberdudebivash.in</a> for urgent requests.</p>`;

  const html = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0e1a">
<tr><td align="center" style="padding:40px 20px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1f2937;overflow:hidden">
  <tr><td style="background:linear-gradient(135deg,#065f46,#1e40af);padding:32px 40px;text-align:center">
    <div style="font-size:28px;font-weight:800;color:#fff;letter-spacing:-0.5px">✅ Purchase Confirmed</div>
    <div style="font-size:14px;color:#bfdbfe;margin-top:6px">CYBERDUDEBIVASH® AI Security Hub</div>
  </td></tr>
  <tr><td style="padding:40px">
    <h2 style="margin:0 0 6px;font-size:20px;color:#f1f5f9">${productName}</h2>
    <p style="margin:0 0 24px;color:#6b7280;font-size:14px">Payment ID: ${paymentId}</p>
    <div style="background:#1f2937;border-radius:8px;padding:20px;margin-bottom:24px">
      <div style="display:flex;justify-content:space-between;border-bottom:1px solid #374151;padding-bottom:12px;margin-bottom:12px">
        <span style="color:#94a3b8;font-size:14px">${productName}</span>
        <span style="color:#e2e8f0;font-size:14px">₹${baseAmt.toLocaleString('en-IN')}</span>
      </div>
      <div style="display:flex;justify-content:space-between;border-bottom:1px solid #374151;padding-bottom:12px;margin-bottom:12px">
        <span style="color:#94a3b8;font-size:14px">GST @ 18% (GST: 21ARKPN8270G1ZP)</span>
        <span style="color:#e2e8f0;font-size:14px">₹${gstAmt.toLocaleString('en-IN')}</span>
      </div>
      <div style="display:flex;justify-content:space-between">
        <span style="color:#f1f5f9;font-weight:700;font-size:16px">Total Paid</span>
        <span style="color:#10b981;font-weight:800;font-size:18px">₹${gstInclusive.toLocaleString('en-IN')}</span>
      </div>
    </div>
    ${expiryText}
    <div style="text-align:center;margin:24px 0">${downloadBtn}</div>
    ${invoiceLine}
    <hr style="border:none;border-top:1px solid #1f2937;margin:28px 0">
    <p style="color:#6b7280;font-size:13px;text-align:center">
      Questions? Reply to this email or WhatsApp <strong style="color:#94a3b8">+91 8179881447</strong><br>
      CYBERDUDEBIVASH PRIVATE LIMITED · PAN: ARKPN8270G · GST: 21ARKPN8270G1ZP<br>
      29, Korai Rd, Ragadi, Odisha 755019, India
    </p>
  </td></tr>
</table>
</td></tr>
</table>
</body></html>`;

  return sendEmailWithRetry(env, {
    to,
    subject,
    html,
    text: `Purchase Confirmed: ${productName}\nAmount: ₹${gstInclusive}\nPayment ID: ${paymentId}\n\n${downloadUrl ? `Download: ${BASE_URL}${downloadUrl}` : 'Access your purchase at ' + BASE_URL}\n\nCYBERDUDEBIVASH PRIVATE LIMITED · GST: 21ARKPN8270G1ZP`,
    eventType: 'purchase_confirmation',
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// TASK 3 PHASE 1 — NEW EVENT TYPES (previously silent to the customer)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Payment failed — the Razorpay webhook already seeds a payment_recovery row
 * on payment.failed (handlers/payments.js) but never told the customer.
 * No charge occurred; this is purely informational + a retry nudge.
 */
export async function sendPaymentFailedEmail(env, { to, productName, amountInr, reason }) {
  if (!to) return { success: false, reason: 'missing_params' };

  const subject = `⚠️ Payment Failed — ${productName || 'Your Order'} | CYBERDUDEBIVASH`;
  const bodyHtml = `
    <h2 style="margin:0 0 8px;font-size:20px;color:#f1f5f9">Payment Didn't Go Through</h2>
    <p style="margin:0 0 20px;color:#94a3b8;font-size:15px">We couldn't process your payment for <strong style="color:#e2e8f0">${productName || 'your order'}</strong>${amountInr ? ` (₹${Number(amountInr).toLocaleString('en-IN')})` : ''}.</p>
    <div style="background:#1a0808;border:1px solid #ef4444;border-radius:8px;padding:16px;margin-bottom:24px">
      <p style="margin:0;color:#fca5a5;font-size:14px">${reason ? String(reason).slice(0, 200) : 'The payment provider declined this transaction.'}</p>
    </div>
    <p style="color:#94a3b8;font-size:14px;line-height:1.7">No charge was made — nothing on your account was affected. You can try again anytime.</p>
    <div style="text-align:center;margin:28px 0">
      <a href="${BASE_URL}/pricing" style="display:inline-block;background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:15px;font-weight:600">Try Again →</a>
    </div>
    <hr style="border:none;border-top:1px solid #1f2937;margin:28px 0">
    <p style="color:#6b7280;font-size:13px;margin:0">Questions? Reply to this email or WhatsApp <strong style="color:#94a3b8">+91 81798 81447</strong></p>`;

  const html = renderEmailLayout({
    headerGradient: 'linear-gradient(135deg,#7c1d1d,#1e40af)',
    headerTitle: '⚠️ Payment Failed',
    bodyHtml,
  });
  const text = `Payment failed for ${productName || 'your order'}${amountInr ? ` (₹${amountInr})` : ''}.\nReason: ${reason || 'declined by payment provider'}\n\nNo charge was made. Try again: ${BASE_URL}/pricing`;

  return sendEmailWithRetry(env, { to, subject, html, text, eventType: 'payment_failed' });
}

/**
 * Coupon redeemed confirmation — fired from lib/coupons.js
 * finalizeCouponRedemption() on the pending→redeemed transition.
 */
export async function sendCouponRedeemedEmail(env, { to, code, discountLabel, productName, finalAmountInr }) {
  if (!to || !code) return { success: false, reason: 'missing_params' };

  const subject = `✅ Coupon ${code} Applied — ${productName || 'Your Order'} | CYBERDUDEBIVASH`;
  const bodyHtml = `
    <h2 style="margin:0 0 8px;font-size:20px;color:#f1f5f9">Your Discount Was Applied</h2>
    <p style="margin:0 0 20px;color:#94a3b8;font-size:15px">Coupon <strong style="color:#e2e8f0">${code}</strong> was successfully redeemed on <strong style="color:#e2e8f0">${productName || 'your order'}</strong>.</p>
    <div style="background:#0d1a14;border:1px solid #10b981;border-radius:8px;padding:20px;margin-bottom:24px;text-align:center">
      <div style="font-size:13px;color:#6ee7b7;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Discount Applied</div>
      <div style="font-size:24px;font-weight:800;color:#10b981">${discountLabel || code}</div>
      ${finalAmountInr != null ? `<div style="font-size:13px;color:#6b7280;margin-top:6px">You paid: ₹${Number(finalAmountInr).toLocaleString('en-IN')}</div>` : ''}
    </div>
    <hr style="border:none;border-top:1px solid #1f2937;margin:28px 0">
    <p style="color:#6b7280;font-size:13px;margin:0">Questions? Reply to this email or WhatsApp <strong style="color:#94a3b8">+91 81798 81447</strong></p>`;

  const html = renderEmailLayout({
    headerGradient: 'linear-gradient(135deg,#065f46,#047857)',
    headerTitle: '✅ Coupon Applied',
    bodyHtml,
  });
  const text = `Coupon ${code} applied to ${productName || 'your order'}.\nDiscount: ${discountLabel || code}${finalAmountInr != null ? `\nYou paid: ₹${finalAmountInr}` : ''}`;

  return sendEmailWithRetry(env, { to, subject, html, text, eventType: 'coupon_redeemed' });
}

/**
 * Suspicious login alert — fired from handlers/auth.js handleLogin() when
 * the current request IP differs from the account's most recent known IP
 * (from refresh_tokens.ip_address). Never blocks the login itself.
 */
export async function sendSuspiciousLoginEmail(env, { to, ip, country, userAgent, previousIp }) {
  if (!to) return { success: false, reason: 'missing_params' };

  const subject = `🔐 New Sign-In to Your CYBERDUDEBIVASH Account`;
  const bodyHtml = `
    <h2 style="margin:0 0 8px;font-size:20px;color:#f1f5f9">New Sign-In Detected</h2>
    <p style="margin:0 0 20px;color:#94a3b8;font-size:15px">Your account was just accessed from a location we haven't seen before.</p>
    <div style="background:#1f2937;border-radius:8px;padding:20px;margin-bottom:24px">
      <div style="display:flex;justify-content:space-between;border-bottom:1px solid #374151;padding-bottom:10px;margin-bottom:10px">
        <span style="color:#94a3b8;font-size:13px">IP Address</span>
        <span style="color:#e2e8f0;font-size:13px">${ip || 'unknown'}</span>
      </div>
      <div style="display:flex;justify-content:space-between;border-bottom:1px solid #374151;padding-bottom:10px;margin-bottom:10px">
        <span style="color:#94a3b8;font-size:13px">Approx. Location</span>
        <span style="color:#e2e8f0;font-size:13px">${country || 'Unknown'}</span>
      </div>
      <div style="display:flex;justify-content:space-between">
        <span style="color:#94a3b8;font-size:13px">Device</span>
        <span style="color:#e2e8f0;font-size:13px;text-align:right;max-width:320px">${(userAgent || 'Unknown').slice(0, 80)}</span>
      </div>
    </div>
    <p style="color:#94a3b8;font-size:14px;line-height:1.7">If this was you, no action is needed. If you don't recognize this sign-in, change your password immediately and contact us.</p>
    <div style="text-align:center;margin:28px 0">
      <a href="${BASE_URL}/user-dashboard" style="display:inline-block;background:linear-gradient(135deg,#dc2626,#7c3aed);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:15px;font-weight:600">Review Account Activity →</a>
    </div>
    <hr style="border:none;border-top:1px solid #1f2937;margin:28px 0">
    <p style="color:#6b7280;font-size:13px;margin:0">Not you? Contact us immediately: WhatsApp <strong style="color:#94a3b8">+91 81798 81447</strong> or contact@cyberdudebivash.in</p>`;

  const html = renderEmailLayout({
    headerGradient: 'linear-gradient(135deg,#7c1d1d,#4a1d96)',
    headerTitle: '🔐 New Sign-In Alert',
    bodyHtml,
  });
  const text = `New sign-in to your CYBERDUDEBIVASH account.\nIP: ${ip || 'unknown'}${previousIp ? ` (previous: ${previousIp})` : ''}\nLocation: ${country || 'Unknown'}\nDevice: ${(userAgent || 'Unknown').slice(0, 80)}\n\nIf this wasn't you, change your password immediately and contact contact@cyberdudebivash.in`;

  return sendEmailWithRetry(env, { to, subject, html, text, eventType: 'suspicious_login' });
}
