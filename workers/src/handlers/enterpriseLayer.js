/**
 * CYBERDUDEBIVASH AI Security Hub v10.0
 * Enterprise Layer Handler — Phase 5
 * Consultation booking, custom threat reports, enterprise packages
 */
import { sendEmail } from '../services/emailEngine.js';

const FOUNDER_EMAIL = 'bivash@cyberdudebivash.com';

// ─── Enterprise package definitions ──────────────────────────────────────────
const ENTERPRISE_PACKAGES = {
  starter_enterprise: {
    id:          'starter_enterprise',
    name:        'Security Assessment',
    price_inr:   9999,
    price_usd:   120,
    description: 'Full security assessment of your infrastructure with actionable remediation roadmap',
    deliverables: [
      '50-page Security Assessment Report',
      'Executive risk summary (board-ready)',
      'Top 10 critical vulnerabilities ranked',
      'Custom remediation roadmap',
      '30-min consultation call',
      '1-month platform access (PRO)',
    ],
    turnaround: '3 business days',
    badge: 'MOST POPULAR',
    highlight: false,
  },
  threat_intel_report: {
    id:          'threat_intel_report',
    name:        'Threat Intelligence Report',
    price_inr:   14999,
    price_usd:   180,
    description: 'Industry-specific threat landscape analysis with IOCs, TTPs, and defensive recommendations',
    deliverables: [
      'Industry threat landscape (30 days)',
      'APT group targeting analysis',
      'IOC/TTP enrichment package',
      'Custom SIGMA/YARA rule set',
      'Executive + technical briefings',
      '1-hour consultation call',
      'STIX 2.1 threat feed (30 days)',
    ],
    turnaround: '5 business days',
    badge: 'ENTERPRISE GRADE',
    highlight: true,
  },
  mssp_package: {
    id:          'mssp_package',
    name:        'MSSP White-Label Package',
    price_inr:   49999,
    price_usd:   600,
    description: 'Full white-label cybersecurity platform for MSSPs — serve your own clients under your brand',
    deliverables: [
      'White-label dashboard (your branding)',
      'Unlimited client accounts',
      'Custom domain + SSL',
      'Full API access (unlimited)',
      'Reseller pricing (50% margin)',
      'Dedicated support channel',
      'Monthly threat intel briefings',
      'Co-marketing support',
    ],
    turnaround: 'Setup in 48 hours',
    badge: 'WHITE-LABEL',
    highlight: false,
  },
  annual_retainer: {
    id:          'annual_retainer',
    name:        'Annual Security Retainer',
    price_inr:   99999,
    price_usd:   1200,
    description: 'Year-round dedicated cybersecurity partnership — your always-on security intelligence team',
    deliverables: [
      'Monthly threat intel reports',
      '24 consultation calls/year',
      'Unlimited custom solutions',
      'Priority incident response',
      'C-suite security briefings',
      'Regulatory compliance tracking',
      'Custom playbook development',
      'SLA: 2-hour response time',
    ],
    turnaround: 'Immediate activation',
    badge: 'BEST VALUE',
    highlight: false,
  },
};

// ─── Consultation time slots ──────────────────────────────────────────────────
const CONSULTATION_SLOTS = [
  { id: 'slot_1', label: 'Morning (9 AM – 12 PM IST)',  tz: 'IST' },
  { id: 'slot_2', label: 'Afternoon (1 PM – 5 PM IST)', tz: 'IST' },
  { id: 'slot_3', label: 'Evening (6 PM – 8 PM IST)',   tz: 'IST' },
  { id: 'slot_4', label: 'US Morning (9 AM – 1 PM EST)', tz: 'EST' },
  { id: 'slot_5', label: 'EU Business (10 AM – 2 PM CET)', tz: 'CET' },
];

// ─── GET /api/enterprise/packages ────────────────────────────────────────────
export async function handleGetPackages(request, env) {
  const packages = Object.values(ENTERPRISE_PACKAGES);
  return json({ success: true, packages, consultation_slots: CONSULTATION_SLOTS });
}

// ─── POST /api/enterprise/book — consultation booking ────────────────────────
export async function handleBookConsultation(request, env, authCtx) {
  try {
    const body = await request.json();
    const {
      company_name, contact_name, email, phone,
      domain, requirements, package_interest,
      team_size, industry, annual_budget,
      urgency = 'normal', preferred_slot,
    } = body;

    if (!email || !requirements) {
      return json({ success: false, error: 'Email and requirements are required' }, 400);
    }

    const id = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO enterprise_leads
       (id, company_name, contact_name, email, phone, domain, requirements,
        package_interest, team_size, industry, annual_budget, urgency, source, status, notes)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      id,
      company_name || 'Unknown',
      contact_name || null,
      email,
      phone || null,
      domain || null,
      requirements,
      package_interest || 'enterprise',
      team_size || null,
      industry || null,
      annual_budget || null,
      urgency,
      authCtx?.userId ? 'authenticated_user' : 'website',
      'new',
      preferred_slot ? `Preferred slot: ${preferred_slot}` : null,
    ).run();

    // Queue notification email to admin
    await env.SECURITY_HUB_KV?.put(
      `email:queue:enterprise_lead:${id}`,
      JSON.stringify({
        type:         'enterprise_lead',
        id,
        company_name,
        email,
        contact_name,
        requirements,
        package_interest,
        urgency,
        preferred_slot,
        created_at: new Date().toISOString(),
      }),
      { expirationTtl: 86400 * 7 }
    );

    // Track funnel event
    await env.DB?.prepare(
      `INSERT INTO fomo_events (id, event_type, entity_type, display_name) VALUES (?,?,?,?)`
    ).bind(crypto.randomUUID(), 'signup', 'enterprise_lead', company_name?.slice(0, 40) || email).run().catch(() => {});

    // Customer confirmation + founder real-time alert (both fire-and-forget)
    Promise.all([
      sendConfirmationEmail(env, { email, contact_name, company_name, requirements, package_interest, id }),
      sendEmail(env, {
        to:      FOUNDER_EMAIL,
        subject: `🚨 NEW ENTERPRISE LEAD: ${company_name || email} [${urgency?.toUpperCase() || 'NORMAL'}]`,
        html:    `<h2 style="color:#ef4444">New Enterprise Inquiry — Act Fast</h2>
<table style="border-collapse:collapse;width:100%">
  <tr><td style="padding:6px 12px;color:#6b7280">Company</td><td style="padding:6px 12px;font-weight:700">${company_name || 'N/A'}</td></tr>
  <tr><td style="padding:6px 12px;color:#6b7280">Contact</td><td style="padding:6px 12px">${contact_name || 'N/A'}</td></tr>
  <tr><td style="padding:6px 12px;color:#6b7280">Email</td><td style="padding:6px 12px"><a href="mailto:${email}">${email}</a></td></tr>
  <tr><td style="padding:6px 12px;color:#6b7280">Phone</td><td style="padding:6px 12px">${phone || 'N/A'}</td></tr>
  <tr><td style="padding:6px 12px;color:#6b7280">Package</td><td style="padding:6px 12px">${package_interest || 'enterprise'}</td></tr>
  <tr><td style="padding:6px 12px;color:#6b7280">Urgency</td><td style="padding:6px 12px;color:#f59e0b;font-weight:700">${urgency?.toUpperCase()}</td></tr>
  <tr><td style="padding:6px 12px;color:#6b7280">Industry</td><td style="padding:6px 12px">${industry || 'N/A'}</td></tr>
  <tr><td style="padding:6px 12px;color:#6b7280">Team Size</td><td style="padding:6px 12px">${team_size || 'N/A'}</td></tr>
  <tr><td style="padding:6px 12px;color:#6b7280">Budget</td><td style="padding:6px 12px">${annual_budget || 'N/A'}</td></tr>
  <tr><td style="padding:6px 12px;color:#6b7280;vertical-align:top">Requirements</td><td style="padding:6px 12px">${requirements}</td></tr>
  <tr><td style="padding:6px 12px;color:#6b7280">Domain</td><td style="padding:6px 12px">${domain || 'N/A'}</td></tr>
  <tr><td style="padding:6px 12px;color:#6b7280">Booking ID</td><td style="padding:6px 12px;font-family:monospace">${id}</td></tr>
</table>
<p style="margin-top:20px"><a href="mailto:${email}?subject=Re: Enterprise Security Consultation Booking ${id.slice(0,8).toUpperCase()}" style="background:#10b981;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:700">Reply to ${email} Now →</a></p>`,
        text: `NEW ENTERPRISE LEAD\nCompany: ${company_name}\nContact: ${contact_name}\nEmail: ${email}\nPhone: ${phone}\nPackage: ${package_interest}\nUrgency: ${urgency}\nRequirements: ${requirements}\nBooking ID: ${id}`,
      }),
    ]).catch(() => {});

    return json({
      success: true,
      booking_id: id,
      message:    'Consultation request received. Our team will contact you within 4 business hours.',
      next_steps: [
        'Check your email for booking confirmation',
        'We\'ll send a calendar invite within 2 hours',
        'Prepare a list of your tech stack for the call',
      ],
    });
  } catch (err) {
    console.error('[enterpriseLayer] booking error:', err);
    return json({ success: false, error: 'Booking failed. Please email contact@cyberdudebivash.in' }, 500);
  }
}

// ─── POST /api/enterprise/report — order custom threat report ─────────────────
export async function handleOrderReport(request, env, authCtx) {
  try {
    const body = await request.json();
    const { email, company_name, package_id, domain, industry, requirements } = body;
    if (!email || !package_id) return json({ success: false, error: 'Email and package required' }, 400);

    const pkg = ENTERPRISE_PACKAGES[package_id];
    if (!pkg) return json({ success: false, error: 'Invalid package' }, 400);

    const id      = crypto.randomUUID();
    const orderId = `ENT-${Date.now().toString(36).toUpperCase()}`;

    // Initiate Razorpay order
    let razorpayOrderId = null;
    const rzKey    = env.RAZORPAY_KEY_ID;
    const rzSecret = env.RAZORPAY_KEY_SECRET;
    if (rzKey && rzSecret) {
      try {
        const r = await fetch('https://api.razorpay.com/v1/orders', {
          method:  'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Basic ${btoa(`${rzKey}:${rzSecret}`)}`,
          },
          body: JSON.stringify({
            amount:   pkg.price_inr * 100,
            currency: 'INR',
            receipt:  orderId,
            notes:    { enterprise_order_id: id, package_id, company: company_name, email },
          }),
        });
        if (r.ok) razorpayOrderId = (await r.json()).id;
      } catch {}
    }

    // Store lead
    await env.DB.prepare(
      `INSERT INTO enterprise_leads
       (id, company_name, email, domain, requirements, package_interest, industry, source, status, notes)
       VALUES (?,?,?,?,?,?,?,?,?,?)`
    ).bind(id, company_name || '', email, domain || null, requirements || '',
           package_id, industry || null, 'report_order', 'new',
           `Razorpay order: ${razorpayOrderId || 'pending'}`).run();

    return json({
      success: true,
      order: {
        order_id:        id,
        razorpay_order_id: razorpayOrderId,
        package:         pkg,
        amount_inr:      pkg.price_inr,
        amount_usd:      pkg.price_usd,
        razorpay_key:    rzKey,
        prefill:         { email, name: company_name || '' },
      },
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// ─── POST /api/enterprise/verify — verify enterprise payment ──────────────────
export async function handleVerifyEnterprisePayment(request, env, authCtx) {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, enterprise_order_id } = await request.json();
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return json({ success: false, error: 'Missing verification fields' }, 400);
    }

    const secret  = env.RAZORPAY_KEY_SECRET || '';
    const payload = `${razorpay_order_id}|${razorpay_payment_id}`;
    const key     = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sigBuf  = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
    const expected = Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2, '0')).join('');

    if (expected !== razorpay_signature && secret) {
      return json({ success: false, error: 'Signature mismatch' }, 400);
    }

    // Update lead status
    if (enterprise_order_id) {
      await env.DB.prepare(
        `UPDATE enterprise_leads SET status='qualified', notes=? WHERE id=?`
      ).bind(`Payment confirmed: ${razorpay_payment_id}`, enterprise_order_id).run();
    }

    // Queue delivery workflow
    await env.SECURITY_HUB_KV?.put(
      `email:queue:enterprise_paid:${enterprise_order_id}`,
      JSON.stringify({ type: 'enterprise_paid', order_id: enterprise_order_id, payment_id: razorpay_payment_id }),
      { expirationTtl: 86400 * 30 }
    );

    return json({
      success: true,
      message: 'Payment confirmed! Our team will begin work immediately and deliver within the promised timeframe.',
      next_steps: [
        'You\'ll receive a confirmation email within 10 minutes',
        'Our lead analyst will contact you within 4 hours',
        'Delivery timeline starts from today',
      ],
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// ─── GET /api/enterprise/stats — admin dashboard stats ───────────────────────
export async function handleEnterpriseStats(request, env, authCtx) {
  if (authCtx?.role !== 'admin') return json({ error: 'Admin only' }, 403);
  try {
    const [total, byStatus, recent] = await Promise.all([
      env.DB.prepare(
        `SELECT COUNT(*) as total, package_interest FROM enterprise_leads GROUP BY package_interest`
      ).all(),
      env.DB.prepare(
        `SELECT status, COUNT(*) as cnt FROM enterprise_leads GROUP BY status`
      ).all(),
      env.DB.prepare(
        `SELECT id, company_name, email, package_interest, status, urgency, created_at
         FROM enterprise_leads ORDER BY created_at DESC LIMIT 10`
      ).all(),
    ]);
    return json({ success: true, breakdown: total.results, by_status: byStatus.results, recent_leads: recent.results });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// ─── Email helper ─────────────────────────────────────────────────────────────
async function sendConfirmationEmail(env, { email, contact_name, company_name, requirements, package_interest, id }) {
  try {
    await sendEmail(env, {
      to:      email,
      subject: `[Booking Confirmed] Enterprise Security Consultation — ${id.slice(0,8).toUpperCase()}`,
      html: `<div style="font-family:sans-serif;max-width:600px;margin:0 auto;background:#0a0a1a;color:#fff;padding:32px;border-radius:12px">
        <div style="font-size:24px;font-weight:900;margin-bottom:4px">🛡️ CYBERDUDEBIVASH AI Security Hub</div>
        <div style="color:#00d4ff;font-size:13px;margin-bottom:24px">Sentinel APEX — Enterprise Security</div>
        <h2 style="color:#00d4ff">Consultation Request Confirmed</h2>
        <p>Hi ${contact_name || 'there'},</p>
        <p>We've received your enterprise consultation request for <strong>${company_name || 'your organization'}</strong>.</p>
        <div style="background:#1a1a2e;border-radius:8px;padding:16px;margin:20px 0">
          <div style="font-size:12px;color:#888;margin-bottom:8px">BOOKING REFERENCE</div>
          <div style="font-family:monospace;font-size:18px;color:#00d4ff;font-weight:900">${id.slice(0,8).toUpperCase()}</div>
        </div>
        <p><strong>Package Interest:</strong> ${package_interest || 'Enterprise'}<br>
        <strong>Requirements:</strong> ${requirements.slice(0, 200)}...</p>
        <div style="background:rgba(0,212,255,.08);border-left:3px solid #00d4ff;padding:12px 16px;margin:20px 0;border-radius:0 8px 8px 0">
          <strong>What happens next:</strong><br>
          ✅ Our lead analyst reviews your requirements within 4 hours<br>
          📅 You'll receive a calendar invite within 2 hours<br>
          📊 Custom proposal sent before the call
        </div>
        <p>For urgent matters, reply to this email or contact <a href="mailto:contact@cyberdudebivash.in" style="color:#00d4ff">contact@cyberdudebivash.in</a> · WhatsApp +91 8179881447</p>
        <hr style="border-color:#333;margin:24px 0">
        <div style="font-size:11px;color:#555">CYBERDUDEBIVASH PRIVATE LIMITED · PAN: ARKPN8270G · Odisha, India</div>
      </div>`,
      text: `Booking Confirmed — Ref: ${id.slice(0,8).toUpperCase()}\n\nHi ${contact_name || 'there'},\n\nYour enterprise consultation request has been received.\nPackage: ${package_interest}\nRef: ${id}\n\nOur team will contact you within 4 business hours.\ncontact@cyberdudebivash.in · +91 8179881447`,
    });
  } catch { /* non-critical */ }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
