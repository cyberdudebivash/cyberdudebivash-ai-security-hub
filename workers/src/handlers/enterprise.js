/**
 * Enterprise Contact Handler — /api/contact/enterprise
 * Captures enterprise inquiries, stores in KV, triggers notification stub.
 * POST /api/contact/enterprise
 */
import { parseBody, validateString } from '../middleware/validation.js';
import { sendEmail } from '../services/emailEngine.js';

const FOUNDER_EMAIL = 'bivash@cyberdudebivash.com';

function genEnterpriseId() {
  return 'ent_' + Date.now().toString(36) + Math.random().toString(36).slice(2,8);
}

const PACKAGE_PRICES = {
  starter:    '₹9,999/mo',
  growth:     '₹24,999/mo',
  enterprise: 'Custom (from ₹49,999/mo)',
};

export async function handleEnterpriseContact(request, env) {
  const body = await parseBody(request);

  const companyName  = (body?.company_name  || body?.company || '').trim();
  const domain       = (body?.domain || '').trim();
  const contactEmail = (body?.email  || body?.contact_email || '').trim();
  const requirements = (body?.requirements  || body?.message || '').trim();
  const phone        = (body?.phone || '').trim();
  const package_type = (body?.package || 'enterprise').toLowerCase();

  if (!companyName || companyName.length < 2) {
    return Response.json({ error: 'company_name is required (min 2 chars)' }, { status: 400 });
  }
  if (!contactEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(contactEmail)) {
    return Response.json({ error: 'A valid email address is required' }, { status: 400 });
  }
  if (!requirements || requirements.length < 10) {
    return Response.json({ error: 'requirements must be at least 10 characters' }, { status: 400 });
  }

  const contactId = genEnterpriseId();
  const record = {
    contact_id:   contactId,
    company_name: companyName,
    domain:       domain || null,
    contact_email: contactEmail,
    requirements,
    phone:        phone || null,
    package_type,
    ip:           request.headers.get('CF-Connecting-IP') || 'unknown',
    country:      request.headers.get('CF-IPCountry') || 'unknown',
    submitted_at: new Date().toISOString(),
    status:       'new',
    assigned_to:  null,
  };

  if (env?.SECURITY_HUB_KV) {
    try {
      await Promise.all([
        env.SECURITY_HUB_KV.put(`enterprise:${contactId}`, JSON.stringify(record), { expirationTtl: 7776000 }),
        env.SECURITY_HUB_KV.put(`enterprise:email:${contactEmail}`, contactId),
        env.SECURITY_HUB_KV.put(`stats:enterprise:total`,
          String((parseInt(await env.SECURITY_HUB_KV.get('stats:enterprise:total') || '0')) + 1)),
      ]);
    } catch { /* non-blocking */ }
  }

  // Fire-and-forget: customer acknowledgment + founder alert
  Promise.all([
    sendEmail(env, {
      to:      contactEmail,
      subject: `✅ Inquiry Received — CYBERDUDEBIVASH Enterprise [Ref: ${contactId.slice(0,8).toUpperCase()}]`,
      html:    `<div style="font-family:sans-serif;background:#0a0e1a;color:#e2e8f0;padding:32px;border-radius:12px;max-width:600px;margin:0 auto">
        <h2 style="color:#00d4ff">Enterprise Inquiry Confirmed</h2>
        <p>Hi there,</p>
        <p>We've received your enterprise security inquiry for <strong>${companyName}</strong>.</p>
        <p><strong>Reference:</strong> <code style="background:#1f2937;padding:3px 8px;border-radius:4px">${contactId.slice(0,8).toUpperCase()}</code></p>
        <p><strong>Package Interest:</strong> ${package_type} — ${PACKAGE_PRICES[package_type] || 'Contact for pricing'}</p>
        <div style="background:rgba(0,212,255,.08);border-left:3px solid #00d4ff;padding:12px 16px;margin:20px 0;border-radius:0 8px 8px 0">
          Our security architect will review your requirements and respond within <strong>24 business hours</strong>.
        </div>
        <p>For urgent matters: <a href="mailto:bivash@cyberdudebivash.com" style="color:#60a5fa">bivash@cyberdudebivash.com</a> · WhatsApp +91 8179881447</p>
      </div>`,
      text: `Inquiry received. Ref: ${contactId.slice(0,8).toUpperCase()}. We'll respond within 24h. Contact: bivash@cyberdudebivash.com`,
    }).catch(() => {}),
    sendEmail(env, {
      to:      FOUNDER_EMAIL,
      subject: `🚨 ENTERPRISE CONTACT: ${companyName} [${package_type.toUpperCase()}]`,
      html:    `<h2 style="color:#ef4444">New Enterprise Contact Form Submission</h2>
<table style="border-collapse:collapse"><tr><td style="padding:6px 12px;color:#6b7280">Company</td><td style="padding:6px 12px;font-weight:700">${companyName}</td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Email</td><td style="padding:6px 12px"><a href="mailto:${contactEmail}">${contactEmail}</a></td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Phone</td><td style="padding:6px 12px">${record.phone || 'N/A'}</td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Package</td><td style="padding:6px 12px">${package_type} — ${PACKAGE_PRICES[package_type] || 'custom'}</td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Domain</td><td style="padding:6px 12px">${domain || 'N/A'}</td></tr>
<tr><td style="padding:6px 12px;color:#6b7280;vertical-align:top">Requirements</td><td style="padding:6px 12px">${requirements}</td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Ref</td><td style="padding:6px 12px;font-family:monospace">${contactId}</td></tr></table>
<p><a href="mailto:${contactEmail}?subject=Re: Enterprise Inquiry ${contactId.slice(0,8).toUpperCase()}" style="background:#10b981;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:700">Reply Now →</a></p>`,
      text: `ENTERPRISE LEAD\nCompany: ${companyName}\nEmail: ${contactEmail}\nPackage: ${package_type}\nRequirements: ${requirements}\nRef: ${contactId}`,
    }).catch(() => {}),
  ]).catch(() => {});

  return Response.json({
    status: 'ok',
    contact_id: contactId,
    message: 'Enterprise inquiry received. Our team will contact you within 24 hours.',
    estimated_response: '< 24 business hours',
    direct_contact: {
      email:   'bivashnayak.ai007@gmail.com',
      phone:   '+918179881447',
      discord: 'cybercoder127001',
    },
    packages: PACKAGE_PRICES,
    next_steps: [
      'Our security architect will review your requirements',
      'We will schedule a technical discovery call',
      'Custom proposal delivered within 48 hours',
    ],
  }, { status: 201 });
}
