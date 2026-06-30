/**
 * Academy Marketplace Handler
 * GET  /api/academy/catalog       — list all courses
 * POST /api/academy/purchase      — create Razorpay order
 * POST /api/academy/verify        — verify payment + grant access + notify founder
 */

const FOUNDER_EMAIL = 'bivash@cyberdudebivash.com';

export const ACADEMY_CATALOG = {
  ULTIMATE_BUNDLE_2026: {
    id: 'ULTIMATE_BUNDLE_2026', name: 'CYBERDUDEBIVASH Ultimate Bundle 2026 (4 Courses)',
    price_inr: 1999, type: 'bundle',
    description: 'All 4 courses in one: SOC Playbook + AI Security + Cyber Mega (Part 1+2). Best value.',
    includes: ['SOC Analyst Survival Playbook 2026', 'Complete AI Security Training Bundle 2026',
               'Cybersecurity Mega Course Part 1', 'Cybersecurity Mega Course Part 2'],
  },
  SOC_PLAYBOOK_2026: {
    id: 'SOC_PLAYBOOK_2026', name: 'SOC Analyst Survival Playbook 2026',
    price_inr: 999, type: 'course',
    description: 'Complete SOC analyst guide: SIEM, SOAR, threat hunting, incident escalation playbooks, real-world case studies.',
  },
  AI_SECURITY_BUNDLE_2026: {
    id: 'AI_SECURITY_BUNDLE_2026', name: 'Complete AI Security Training Bundle 2026',
    price_inr: 1199, type: 'bundle',
    description: 'AI-powered security training: LLM threat models, adversarial AI, AI-assisted threat hunting, defense automation.',
  },
  CYBER_MEGA_PART1: {
    id: 'CYBER_MEGA_PART1', name: 'Cybersecurity Mega Course — Part 1',
    price_inr: 699, type: 'course',
    description: 'Foundations: network security, cryptography, web vulnerabilities, recon, OSINT, ethical hacking basics.',
  },
  CYBER_MEGA_PART2: {
    id: 'CYBER_MEGA_PART2', name: 'Cybersecurity Mega Course — Part 2',
    price_inr: 799, type: 'course',
    description: 'Advanced track: exploit development, red team ops, Active Directory attacks, cloud security, DFIR.',
  },
  CYBER_MEGA_BUNDLE_BOTH: {
    id: 'CYBER_MEGA_BUNDLE_BOTH', name: 'Cybersecurity Mega Course — Part 1 + Part 2',
    price_inr: 1299, type: 'bundle',
    description: 'Full Cybersecurity Mega Course: Part 1 (foundations) + Part 2 (advanced) at a bundle discount.',
    includes: ['Cybersecurity Mega Course Part 1', 'Cybersecurity Mega Course Part 2'],
  },
  OSINT_STARTER_BUNDLE: {
    id: 'OSINT_STARTER_BUNDLE', name: 'OSINT Starter Bundle',
    price_inr: 499, type: 'course',
    description: 'OSINT fundamentals: Maltego, Shodan, Google dorking, social media OSINT, corporate intelligence gathering.',
  },
  PYTHON_JAVA_AUTOMATION_PACK: {
    id: 'PYTHON_JAVA_AUTOMATION_PACK', name: 'Python + Java Automation Engineering Pack',
    price_inr: 899, type: 'course',
    description: 'Security automation: Python scripting for scanning, log analysis, API integrations; Java for enterprise security tools.',
  },
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

// GET /api/academy/catalog
export async function handleListAcademy(request, env) {
  return json({ success: true, courses: Object.values(ACADEMY_CATALOG) });
}

// POST /api/academy/purchase
export async function handlePurchaseAcademy(request, env) {
  try {
    const body = await request.json();
    const { product_id, email } = body;
    const course = ACADEMY_CATALOG[product_id];
    if (!course) return json({ success: false, error: 'Course not found' }, 404);
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
      return json({ success: false, error: 'Valid email required' }, 400);
    }

    const amount = course.price_inr * 100; // paise
    let razorpayOrderId = null;
    const rzKey    = env.RAZORPAY_KEY_ID;
    const rzSecret = env.RAZORPAY_KEY_SECRET;
    if (rzKey && rzSecret) {
      const r = await fetch('https://api.razorpay.com/v1/orders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Basic ${btoa(`${rzKey}:${rzSecret}`)}` },
        body: JSON.stringify({ amount, currency: 'INR', receipt: `acad_${product_id}_${Date.now()}`, notes: { product_id, email } }),
      });
      if (r.ok) razorpayOrderId = (await r.json()).id;
    }

    return json({
      success: true,
      order: {
        razorpay_order_id: razorpayOrderId,
        product_id,
        product_name: course.name,
        amount,
        currency: 'INR',
        razorpay_key: rzKey,
        prefill: { email },
      },
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// POST /api/academy/verify
export async function handleVerifyAcademy(request, env) {
  try {
    const body = await request.json().catch(() => ({}));
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, product_id, email } = body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature || !product_id) {
      return json({ success: false, error: 'Missing verification fields' }, 400);
    }
    const course = ACADEMY_CATALOG[product_id];
    if (!course) return json({ success: false, error: 'Course not found' }, 404);

    // HMAC-SHA256 verify
    const secret  = env.RAZORPAY_KEY_SECRET || '';
    const payload = `${razorpay_order_id}|${razorpay_payment_id}`;
    const key     = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sigBuf  = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
    const expected = Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
    if (!secret || expected !== razorpay_signature) {
      return json({ success: false, error: 'Payment signature verification failed' }, 400);
    }

    // Idempotency check
    if (env.DB) {
      const existing = await env.DB.prepare(
        `SELECT id FROM payments WHERE razorpay_order_id = ? AND status = 'paid' LIMIT 1`
      ).bind(razorpay_order_id).first().catch(() => null);
      if (existing) {
        return json({ success: true, access_granted: true, product_name: course.name,
          delivery_note: 'Your course materials will be sent to your email within 24 hours.', duplicate: true });
      }
    }

    // Record in D1
    const purchaseId = `ac_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
    if (env.DB) {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO payments (id, user_id, module, target, amount, currency, razorpay_order_id, razorpay_payment_id, status, email, created_at)
         VALUES (?,?,?,?,?,?,?,?,'paid',?,datetime('now'))`
      ).bind(purchaseId, email || null, 'academy', product_id,
             course.price_inr * 100, 'INR', razorpay_order_id, razorpay_payment_id, email || null)
       .run().catch(e => console.warn('[Academy] D1 error:', e.message));
    }

    // KV access grant (365 days)
    const accessKey = `access:academy:${product_id}:${email || razorpay_payment_id}`;
    await env.SECURITY_HUB_KV?.put(accessKey, JSON.stringify({
      granted_at: new Date().toISOString(),
      payment_id: razorpay_payment_id,
      course_name: course.name,
    }), { expirationTtl: 365 * 86400 }).catch(() => {});

    // Fire-and-forget: GST invoice + customer confirmation + founder delivery alert
    Promise.all([
      (async () => {
        try {
          const { createInvoice } = await import('../services/v24/billingEngine.js');
          if (env.DB && course.price_inr) {
            await createInvoice(env.DB, {
              userId: email || purchaseId, email: email || 'noreply@buyer',
              lineItems: [{ description: course.name, amount_inr: course.price_inr, quantity: 1 }],
              paymentId: razorpay_payment_id, paymentMethod: 'razorpay',
            });
          }
        } catch (e) { console.warn('[Academy] invoice error:', e.message); }
      })(),
      (async () => {
        try {
          const { sendPurchaseConfirmation } = await import('../services/emailEngine.js');
          if (email) {
            await sendPurchaseConfirmation(env, {
              to: email, productName: course.name, amountInr: course.price_inr,
              paymentId: razorpay_payment_id,
            });
          }
        } catch (e) { console.warn('[Academy] confirmation email error:', e.message); }
      })(),
      (async () => {
        try {
          const { sendEmail } = await import('../services/emailEngine.js');
          const includesList = course.includes
            ? `<p><strong>Includes:</strong> ${course.includes.join(', ')}</p>` : '';
          await sendEmail(env, {
            to: FOUNDER_EMAIL,
            subject: `🎓 ACADEMY SALE: ${course.name} [₹${course.price_inr}] — ${email || 'unknown'}`,
            html: `<h2 style="color:#f59e0b">Academy Course Sale</h2>
<table style="border-collapse:collapse;font-family:sans-serif">
<tr><td style="padding:6px 12px;color:#6b7280">Course</td><td style="padding:6px 12px;font-weight:700">${course.name}</td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Type</td><td style="padding:6px 12px">${course.type}</td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Price</td><td style="padding:6px 12px;font-weight:700;color:#f59e0b">₹${course.price_inr.toLocaleString('en-IN')}</td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Student Email</td><td style="padding:6px 12px"><a href="mailto:${email}">${email || 'N/A'}</a></td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Payment ID</td><td style="padding:6px 12px;font-family:monospace">${razorpay_payment_id}</td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Order ID</td><td style="padding:6px 12px;font-family:monospace">${razorpay_order_id}</td></tr>
</table>
${includesList}
<p style="margin-top:20px;padding:12px 16px;background:#fef3c7;border-radius:8px;color:#92400e;font-weight:600">⚡ ACTION REQUIRED: Send course materials for "${course.name}" to ${email} within 24 hours.</p>
<p><a href="mailto:${email}?subject=Your ${encodeURIComponent(course.name)} — CYBERDUDEBIVASH Academy" style="background:#f59e0b;color:#000;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:700">Deliver Course Now →</a></p>`,
            text: `ACADEMY SALE: ${course.name} ₹${course.price_inr} to ${email}. Payment: ${razorpay_payment_id}. DELIVER WITHIN 24H.`,
          });
        } catch (e) { console.warn('[Academy] founder alert error:', e.message); }
      })(),
    ]).catch(() => {});

    return json({
      success: true,
      access_granted: true,
      product_name: course.name,
      payment_id: razorpay_payment_id,
      delivery_note: `${course.name} materials will be sent to ${email} within 24 hours. Check your inbox (and spam).`,
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}
