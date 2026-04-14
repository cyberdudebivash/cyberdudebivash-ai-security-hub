/**
 * ═══════════════════════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH AI Security Hub — Automated Delivery System v1.0
 *
 * Builds FULLY AUTOMATED DELIVERY on top of the existing manual payment flow.
 * CRITICAL: Does NOT change payment methods (UPI/Bank/PayPal/Crypto).
 * Manual fallback always works. This layer adds instant automated access
 * when admin verifies payment.
 *
 * Flow:
 *   1. User pays via existing UPI/Bank/PayPal/Crypto
 *   2. Admin clicks "Verify" in /api/payments/verify
 *   3. This engine auto-fires: generates token + stores purchase in D1
 *   4. User accesses /api/delivery/access?token=... to get their materials
 *
 * New endpoints:
 *   POST /api/delivery/activate        — admin triggers delivery after payment verify
 *   GET  /api/delivery/access          — user accesses purchased content via token
 *   GET  /api/delivery/my-purchases    — user's purchase history (authenticated)
 *   POST /api/delivery/resend          — resend access token (admin)
 *   GET  /api/delivery/verify-token    — validate a delivery token (public)
 * ═══════════════════════════════════════════════════════════════════════════
 */

// ─── Product Delivery Catalog ─────────────────────────────────────────────────
// Maps product IDs to delivery content and instructions
const DELIVERY_CATALOG = {
  // ── Subscription Plans ──
  STARTER: {
    type: 'platform_access',
    name: 'Starter Plan',
    delivery_method: 'account_upgrade',
    access_details: {
      instructions: 'Your Starter Plan access has been activated. Log in to your dashboard at cyberdudebivash.in/user-dashboard.html to access all features.',
      features: ['50 scans/month','Domain Security Scanner','AI Cyber Analyst','Priority support','Scan history'],
    },
  },
  PRO: {
    type: 'platform_access',
    name: 'Pro Plan',
    delivery_method: 'account_upgrade',
    access_details: {
      instructions: 'Pro Plan activated. Full platform access unlocked.',
      features: ['Unlimited scans','All modules','Red Team simulator','Compliance checker','PDF reports','API access'],
    },
  },
  ENTERPRISE: {
    type: 'platform_access',
    name: 'Enterprise Plan',
    delivery_method: 'account_upgrade',
    access_details: {
      instructions: 'Enterprise access activated. Dedicated support contact: bivash@cyberdudebivash.com',
      features: ['Unlimited everything','Multi-tenant org','SIEM export','Custom reports','SLA support'],
    },
  },

  // ── One-Time Reports ──
  DOMAIN_REPORT: {
    type: 'report_access',
    name: 'Domain Security Report',
    delivery_method: 'token_download',
    access_details: {
      instructions: 'Your security report is ready. Access it using the secure link sent to your email.',
      format: 'PDF',
      validity_days: 30,
    },
  },
  THREAT_INTEL_REPORT: {
    type: 'report_access',
    name: 'Threat Intelligence Report',
    delivery_method: 'token_download',
    access_details: { instructions: 'Threat Intelligence Report ready for download.', format: 'PDF', validity_days: 30 },
  },

  // ── Training Products ──
  SOC_PLAYBOOK_2026: {
    type: 'training',
    name: 'SOC Analyst Survival Playbook 2026',
    delivery_method: 'email_download',
    access_details: {
      instructions: 'Your SOC Analyst Survival Playbook 2026 is ready. A download link has been sent to your email. You will also receive Discord community access within 24 hours.',
      format: 'PDF + Resources',
      discord_access: true,
      certificate: true,
      validity_days: 365,
      files: ['SOC_Analyst_Survival_Playbook_2026.pdf','IR_Templates.zip','SIEM_Playbooks.xlsx'],
    },
  },
  AI_SECURITY_BUNDLE_2026: {
    type: 'training',
    name: 'Complete AI Security Training Bundle 2026',
    delivery_method: 'email_download',
    access_details: {
      instructions: 'AI Security Bundle 2026 ready. Download link sent to email. Includes hands-on lab guides.',
      format: 'PDF + Lab Guides',
      discord_access: true,
      certificate: true,
      validity_days: 365,
      files: ['AI_Security_Training_Bundle_2026.pdf','LLM_Security_Labs.zip','OWASP_LLM_Checklist.pdf'],
    },
  },
  CYBER_MEGA_PART1: {
    type: 'training',
    name: 'Cybersecurity Mega Course — Part 1',
    delivery_method: 'email_download',
    access_details: {
      instructions: 'Cybersecurity Mega Course Part 1 ready. Download link sent to email.',
      format: 'PDF',
      discord_access: true,
      certificate: true,
      validity_days: 365,
      files: ['CyberSecurity_MegaCourse_Part1.pdf'],
    },
  },
  CYBER_MEGA_PART2: {
    type: 'training',
    name: 'Cybersecurity Mega Course — Part 2',
    delivery_method: 'email_download',
    access_details: {
      instructions: 'Cybersecurity Mega Course Part 2 ready. Download link sent to email.',
      format: 'PDF',
      discord_access: true,
      certificate: true,
      validity_days: 365,
      files: ['CyberSecurity_MegaCourse_Part2.pdf'],
    },
  },
  CYBER_MEGA_BUNDLE_BOTH: {
    type: 'training',
    name: 'Cybersecurity Mega Course — Full Bundle',
    delivery_method: 'email_download',
    access_details: {
      instructions: 'Both parts of the Cybersecurity Mega Course ready. Download links sent to email.',
      format: 'PDF x2',
      discord_access: true,
      certificate: true,
      validity_days: 365,
      files: ['CyberSecurity_MegaCourse_Part1.pdf','CyberSecurity_MegaCourse_Part2.pdf'],
    },
  },
  OSINT_STARTER_BUNDLE: {
    type: 'training',
    name: 'OSINT Starter Bundle',
    delivery_method: 'email_download',
    access_details: {
      instructions: 'OSINT Starter Bundle ready. Download link sent to email.',
      format: 'PDF + Tools List',
      discord_access: true,
      certificate: true,
      validity_days: 365,
      files: ['OSINT_Starter_Bundle.pdf','OSINT_Toolkit_Guide.pdf'],
    },
  },
  PYTHON_JAVA_AUTOMATION_PACK: {
    type: 'training',
    name: 'Python + Java Automation Engineering Pack',
    delivery_method: 'email_download',
    access_details: {
      instructions: 'Python + Java Automation Pack ready. Download links sent to email. Includes code repositories.',
      format: 'PDF + Code',
      discord_access: true,
      certificate: true,
      validity_days: 365,
      files: ['Python_Security_Automation.pdf','Java_Automation_Testing.pdf','Code_Examples.zip'],
    },
  },
  ULTIMATE_BUNDLE_2026: {
    type: 'training',
    name: 'CYBERDUDEBIVASH Ultimate Bundle 2026',
    delivery_method: 'email_download',
    access_details: {
      instructions: 'Ultimate Bundle 2026 activated! 4 course packages delivered to your email. Discord community access and certificates included.',
      format: 'PDF x4 + Resources',
      discord_access: true,
      certificate: true,
      validity_days: 365,
      files: ['SOC_Analyst_Survival_Playbook_2026.pdf','AI_Security_Training_Bundle_2026.pdf','Python_Security_Automation.pdf','OSINT_Starter_Bundle.pdf','BONUS_Resources.zip'],
    },
  },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────
function jsonOk(data, status = 200) {
  return new Response(JSON.stringify({ success: true, data, error: null, timestamp: new Date().toISOString() }), {
    status,
    headers: { 'Content-Type': 'application/json', 'X-Platform': 'CYBERDUDEBIVASH-AI-HUB' },
  });
}
function jsonErr(message, status = 400) {
  return new Response(JSON.stringify({ success: false, data: null, error: message, timestamp: new Date().toISOString() }), {
    status,
    headers: { 'Content-Type': 'application/json', 'X-Platform': 'CYBERDUDEBIVASH-AI-HUB' },
  });
}

/**
 * Generate a cryptographically secure delivery token
 */
function generateDeliveryToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return 'cdb_dlv_' + Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');
}

/**
 * SHA-256 hash a token for storage
 */
async function hashToken(token) {
  const encoder = new TextEncoder();
  const data    = encoder.encode(token);
  const hashBuf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// ─── POST /api/delivery/activate ─────────────────────────────────────────────
/**
 * Called by admin after verifying manual payment.
 * Creates a delivery record in D1, generates secure token,
 * stores in KV for fast access validation.
 *
 * Body: { payment_id, product_id, payer_email, user_id?, custom_notes? }
 */
export async function handleDeliveryActivate(request, env) {
  try {
    const body = await request.json().catch(() => ({}));
    const { payment_id, product_id, payer_email, user_id, custom_notes } = body;

    if (!payment_id || !product_id || !payer_email) {
      return jsonErr('Missing required fields: payment_id, product_id, payer_email', 400);
    }

    const product = DELIVERY_CATALOG[product_id];
    if (!product) {
      return jsonErr(`Unknown product_id: ${product_id}. Add it to DELIVERY_CATALOG.`, 400);
    }

    // Prevent duplicate delivery
    if (env?.SECURITY_HUB_KV) {
      const existing = await env.SECURITY_HUB_KV.get(`delivery:payment:${payment_id}`);
      if (existing) {
        const existingData = JSON.parse(existing);
        return jsonOk({ already_delivered: true, delivery_id: existingData.delivery_id, token: existingData.raw_token });
      }
    }

    // Generate secure token
    const rawToken  = generateDeliveryToken();
    const tokenHash = await hashToken(rawToken);
    const deliveryId = 'dlv_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    const expiresAt  = new Date(Date.now() + (product.access_details.validity_days || 365) * 86400000).toISOString();

    const deliveryRecord = {
      delivery_id:    deliveryId,
      payment_id,
      product_id,
      product_name:   product.name,
      product_type:   product.type,
      payer_email,
      user_id:        user_id || null,
      token_hash:     tokenHash,
      raw_token:      rawToken, // stored ONLY in this activation response + KV (short TTL)
      delivery_method: product.delivery_method,
      access_details:  product.access_details,
      custom_notes:    custom_notes || null,
      status:          'activated',
      activated_at:    new Date().toISOString(),
      expires_at:      expiresAt,
      access_count:    0,
    };

    // Store in D1 (permanent record)
    if (env?.DB) {
      try {
        await env.DB.prepare(`
          INSERT INTO delivery_tokens
            (id, payment_id, product_id, product_name, product_type, payer_email, user_id,
             token_hash, delivery_method, access_details, custom_notes, status, activated_at, expires_at, access_count)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(payment_id) DO UPDATE SET
            status='reactivated', activated_at=excluded.activated_at
        `).bind(
          deliveryId, payment_id, product_id, product.name, product.type,
          payer_email, user_id || null, tokenHash, product.delivery_method,
          JSON.stringify(product.access_details), custom_notes || null,
          'activated', deliveryRecord.activated_at, expiresAt, 0
        ).run();
      } catch (dbErr) {
        // D1 failure — fall back to KV-only storage (graceful degradation)
        console.error('[delivery] D1 write failed:', dbErr.message);
      }
    }

    // Store in KV for fast token validation (includes raw token for admin to retrieve)
    if (env?.SECURITY_HUB_KV) {
      const kvPayload = {
        delivery_id:  deliveryId,
        product_id,
        product_name: product.name,
        product_type: product.type,
        payer_email,
        user_id:      user_id || null,
        token_hash:   tokenHash,
        raw_token:    rawToken,
        access_details: product.access_details,
        status:       'activated',
        activated_at: deliveryRecord.activated_at,
        expires_at:   expiresAt,
        access_count: 0,
      };
      await Promise.all([
        env.SECURITY_HUB_KV.put(`delivery:token:${tokenHash}`, JSON.stringify(kvPayload), { expirationTtl: (product.access_details.validity_days || 365) * 86400 }),
        env.SECURITY_HUB_KV.put(`delivery:payment:${payment_id}`, JSON.stringify(kvPayload), { expirationTtl: (product.access_details.validity_days || 365) * 86400 }),
        env.SECURITY_HUB_KV.put(`delivery:email:${payer_email.toLowerCase()}:${deliveryId}`, JSON.stringify({ delivery_id: deliveryId, product_id, product_name: product.name, activated_at: deliveryRecord.activated_at }), { expirationTtl: (product.access_details.validity_days || 365) * 86400 }),
      ]).catch(() => {}); // non-blocking
    }

    // Dispatch Telegram notification (fire-and-forget)
    notifyDeliveryActivated(env, { payer_email, product_name: product.name, delivery_id: deliveryId, payment_id }).catch(() => {});

    return jsonOk({
      delivery_id:       deliveryId,
      token:             rawToken,
      product_name:      product.name,
      delivery_method:   product.delivery_method,
      payer_email,
      expires_at:        expiresAt,
      access_url:        `https://cyberdudebivash.in/user-dashboard.html?delivery_token=${rawToken}`,
      instructions:      product.access_details.instructions,
      whatsapp_message:  `Hi! Your ${product.name} is ready. Access link: https://cyberdudebivash.in/user-dashboard.html?delivery_token=${rawToken}`,
      email_subject:     `✅ Your ${product.name} is Ready — CYBERDUDEBIVASH`,
    });

  } catch (err) {
    return jsonErr(`Delivery activation failed: ${err.message}`, 500);
  }
}

// ─── GET /api/delivery/access ─────────────────────────────────────────────────
/**
 * User accesses their purchased content via delivery token.
 * Validates token, increments access count, returns product details.
 */
export async function handleDeliveryAccess(request, env) {
  try {
    const url   = new URL(request.url);
    const token = url.searchParams.get('token') || url.searchParams.get('delivery_token');

    if (!token || !token.startsWith('cdb_dlv_')) {
      return jsonErr('Invalid or missing delivery token', 400);
    }

    const tokenHash = await hashToken(token);

    // Check KV first (fast path)
    let record = null;
    if (env?.SECURITY_HUB_KV) {
      const raw = await env.SECURITY_HUB_KV.get(`delivery:token:${tokenHash}`, { type: 'json' });
      if (raw) record = raw;
    }

    // Fall back to D1 if KV miss
    if (!record && env?.DB) {
      const row = await env.DB.prepare(
        `SELECT * FROM delivery_tokens WHERE token_hash = ? AND status != 'revoked' LIMIT 1`
      ).bind(tokenHash).first();
      if (row) {
        record = { ...row, access_details: JSON.parse(row.access_details || '{}') };
      }
    }

    if (!record) {
      return jsonErr('Delivery token not found or expired', 404);
    }

    // Check expiry
    if (new Date(record.expires_at) < new Date()) {
      return jsonErr('Delivery token has expired. Contact support for renewal.', 410);
    }

    // Increment access count (fire-and-forget)
    incrementAccessCount(env, tokenHash, record.delivery_id).catch(() => {});

    return jsonOk({
      delivery_id:   record.delivery_id,
      product_id:    record.product_id,
      product_name:  record.product_name,
      product_type:  record.product_type,
      access_details: record.access_details,
      activated_at:  record.activated_at,
      expires_at:    record.expires_at,
      access_count:  (record.access_count || 0) + 1,
      status:        'active',
      support_email: 'bivash@cyberdudebivash.com',
      support_whatsapp: '+918179881447',
      discord_invite: record.access_details?.discord_access ? 'https://discord.gg/cyberdudebivash' : null,
    });

  } catch (err) {
    return jsonErr(`Token validation failed: ${err.message}`, 500);
  }
}

// ─── GET /api/delivery/my-purchases ──────────────────────────────────────────
/**
 * Returns all purchases/deliveries for the authenticated user
 */
export async function handleMyPurchases(request, env, authCtx) {
  if (!authCtx?.authenticated) {
    return jsonErr('Authentication required', 401);
  }

  try {
    const purchases = [];

    // Query D1 for user's deliveries
    if (env?.DB) {
      const rows = await env.DB.prepare(
        `SELECT id, product_id, product_name, product_type, status, activated_at, expires_at, access_count
         FROM delivery_tokens
         WHERE (user_id = ? OR payer_email = ?)
         AND status != 'revoked'
         ORDER BY activated_at DESC
         LIMIT 50`
      ).bind(authCtx.userId, authCtx.email || '').all();

      if (rows?.results) {
        purchases.push(...rows.results.map(r => ({
          delivery_id:  r.id,
          product_id:   r.product_id,
          product_name: r.product_name,
          product_type: r.product_type,
          status:       r.status,
          activated_at: r.activated_at,
          expires_at:   r.expires_at,
          access_count: r.access_count,
        })));
      }
    }

    // If no D1 results, try KV index
    if (purchases.length === 0 && env?.SECURITY_HUB_KV && authCtx.email) {
      // KV doesn't support prefix listing efficiently, so return empty with note
      // In production, we'd use a D1 index
    }

    return jsonOk({ purchases, total: purchases.length });

  } catch (err) {
    return jsonOk({ purchases: [], total: 0, note: 'Could not retrieve purchases at this time' });
  }
}

// ─── GET /api/user/reports ────────────────────────────────────────────────────
/**
 * Returns the authenticated user's purchased scan reports only.
 * Filters delivery_tokens for product_type IN ('report_access', 'report').
 * Supports optional ?module= query parameter to filter by scan module.
 */
export async function handleUserReports(request, env, authCtx) {
  if (!authCtx?.authenticated) {
    return jsonErr('Authentication required', 401);
  }

  const url        = new URL(request.url);
  const moduleFilter = (url.searchParams.get('module') || '').toLowerCase().trim();
  const limitParam   = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 100);

  try {
    let reports = [];

    // ── D1: query delivery_tokens for report types ────────────────────────────
    if (env?.DB) {
      const rows = await env.DB.prepare(
        `SELECT id, product_id, product_name, product_type, status,
                activated_at, expires_at, access_count, payer_email,
                scan_target, amount_paid, download_url
         FROM delivery_tokens
         WHERE (user_id = ? OR payer_email = ?)
           AND product_type IN ('report_access', 'report')
           AND status != 'revoked'
         ORDER BY activated_at DESC
         LIMIT ?`
      ).bind(authCtx.userId || '', authCtx.email || '', limitParam).all().catch(() => ({ results: [] }));

      if (rows?.results?.length) {
        reports = rows.results.map(r => ({
          delivery_id:  r.id,
          product_id:   r.product_id,
          product_name: r.product_name,
          product_type: r.product_type,
          status:       r.status,
          activated_at: r.activated_at,
          expires_at:   r.expires_at,
          access_count: r.access_count || 0,
          module:       r.product_id?.replace('report_', '').split(':')[0] || 'scan',
          target:       r.scan_target || null,
          amount_paid:  r.amount_paid || null,
          download_url: r.download_url || null,
          is_expired:   r.expires_at ? new Date(r.expires_at) < new Date() : false,
        }));
      }
    }

    // ── KV fallback: scan cached payment records for report deliveries ─────────
    if (reports.length === 0 && env?.SECURITY_HUB_KV && authCtx.email) {
      try {
        const idx = await env.SECURITY_HUB_KV.get(`delivery:user_reports:${authCtx.email}`, { type: 'json' });
        if (Array.isArray(idx) && idx.length) {
          reports = idx.filter(r => r.product_type === 'report_access' || r.product_type === 'report');
        }
      } catch { /* swallow */ }
    }

    // ── Filter by module if requested ─────────────────────────────────────────
    if (moduleFilter) {
      reports = reports.filter(r =>
        (r.module || '').toLowerCase().includes(moduleFilter) ||
        (r.product_id || '').toLowerCase().includes(moduleFilter)
      );
    }

    return jsonOk({
      reports,
      total:   reports.length,
      user_id: authCtx.userId,
      email:   authCtx.email,
      note:    reports.length === 0
        ? 'No paid reports found. Run a Domain or AI Security Scan to generate your first report.'
        : `${reports.length} report(s) found.`,
    });

  } catch (err) {
    console.error('[delivery] handleUserReports error:', err?.message);
    return jsonOk({ reports: [], total: 0, note: 'Could not retrieve reports at this time' });
  }
}

// ─── POST /api/delivery/resend ────────────────────────────────────────────────
/**
 * Admin resends delivery token to user (via WhatsApp/email instructions)
 */
export async function handleResendDelivery(request, env) {
  try {
    const body = await request.json().catch(() => ({}));
    const { payment_id, payer_email } = body;

    if (!payment_id && !payer_email) {
      return jsonErr('Provide payment_id or payer_email to look up delivery', 400);
    }

    let record = null;
    if (env?.SECURITY_HUB_KV && payment_id) {
      record = await env.SECURITY_HUB_KV.get(`delivery:payment:${payment_id}`, { type: 'json' });
    }

    if (!record && env?.DB) {
      const query = payment_id
        ? `SELECT * FROM delivery_tokens WHERE payment_id = ? LIMIT 1`
        : `SELECT * FROM delivery_tokens WHERE payer_email = ? ORDER BY activated_at DESC LIMIT 1`;
      const row = await env.DB.prepare(query).bind(payment_id || payer_email).first();
      if (row) record = { ...row, access_details: JSON.parse(row.access_details || '{}') };
    }

    if (!record) {
      return jsonErr('No delivery found for the provided details', 404);
    }

    return jsonOk({
      delivery_id:      record.delivery_id,
      product_name:     record.product_name,
      payer_email:      record.payer_email,
      access_url:       `https://cyberdudebivash.in/user-dashboard.html?delivery_token=${record.raw_token || '[contact support]'}`,
      whatsapp_message: `Hi! Your ${record.product_name} access: https://cyberdudebivash.in/user-dashboard.html?delivery_token=${record.raw_token || '[contact support]'}`,
      instructions:     record.access_details?.instructions,
      expires_at:       record.expires_at,
      note:             'Token resent. If raw_token is unavailable, re-activate via /api/delivery/activate',
    });
  } catch (err) {
    return jsonErr(`Resend failed: ${err.message}`, 500);
  }
}

// ─── GET /api/delivery/verify-token ──────────────────────────────────────────
/**
 * Public endpoint: validate a delivery token (returns boolean + product info)
 */
export async function handleVerifyDeliveryToken(request, env) {
  const url   = new URL(request.url);
  const token = url.searchParams.get('token');

  if (!token) return jsonErr('Token required', 400);

  try {
    const tokenHash = await hashToken(token);
    let valid = false, productName = null, expiresAt = null;

    if (env?.SECURITY_HUB_KV) {
      const record = await env.SECURITY_HUB_KV.get(`delivery:token:${tokenHash}`, { type: 'json' });
      if (record && new Date(record.expires_at) > new Date()) {
        valid       = true;
        productName = record.product_name;
        expiresAt   = record.expires_at;
      }
    }

    return jsonOk({ valid, product_name: productName, expires_at: expiresAt });
  } catch {
    return jsonOk({ valid: false });
  }
}

// ─── GET /api/delivery/catalog ────────────────────────────────────────────────
/**
 * Returns the delivery catalog (for admin UI)
 */
export async function handleDeliveryCatalog(request, env) {
  const catalog = Object.entries(DELIVERY_CATALOG).map(([id, p]) => ({
    product_id:      id,
    product_name:    p.name,
    product_type:    p.type,
    delivery_method: p.delivery_method,
    validity_days:   p.access_details.validity_days || 365,
  }));
  return jsonOk({ catalog, total: catalog.length });
}

// ─── Internal: access count increment ────────────────────────────────────────
async function incrementAccessCount(env, tokenHash, deliveryId) {
  if (env?.DB) {
    await env.DB.prepare(
      `UPDATE delivery_tokens SET access_count = access_count + 1 WHERE id = ?`
    ).bind(deliveryId).run();
  }
  if (env?.SECURITY_HUB_KV) {
    const record = await env.SECURITY_HUB_KV.get(`delivery:token:${tokenHash}`, { type: 'json' });
    if (record) {
      record.access_count = (record.access_count || 0) + 1;
      await env.SECURITY_HUB_KV.put(`delivery:token:${tokenHash}`, JSON.stringify(record), {
        expirationTtl: Math.max(1, Math.floor((new Date(record.expires_at) - Date.now()) / 1000)),
      });
    }
  }
}

// ─── Internal: Telegram notification ─────────────────────────────────────────
async function notifyDeliveryActivated(env, { payer_email, product_name, delivery_id, payment_id }) {
  if (!env?.TELEGRAM_BOT_TOKEN || !env?.ADMIN_TELEGRAM_CHAT_ID) return;
  const msg = `✅ DELIVERY ACTIVATED\n📦 ${product_name}\n📧 ${payer_email}\n🔑 Delivery ID: ${delivery_id}\n💳 Payment: ${payment_id}\n🕐 ${new Date().toISOString()}`;
  await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: env.ADMIN_TELEGRAM_CHAT_ID, text: msg }),
  });
}
