/**
 * Enterprise Contact Handler — /api/contact/enterprise
 * Captures enterprise inquiries, stores in KV, triggers notification stub.
 * POST /api/contact/enterprise
 */
import { parseBody, validateString } from '../middleware/validation.js';

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

  // Notification stub — replace with actual email/webhook in production
  // e.g. await sendSlackNotification(env.SLACK_WEBHOOK, record);
  // e.g. await sendEmail(env.RESEND_API_KEY, 'bivashnayak.ai007@gmail.com', record);

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
