/**
 * Tools & AI Marketplace Handler
 * GET  /api/tools/catalog         — list all tools
 * POST /api/tools/purchase        — create Razorpay order
 * POST /api/tools/verify          — verify payment + grant access + notify founder
 */

const FOUNDER_EMAIL = 'bivash@cyberdudebivash.com';

export const TOOLS_CATALOG = {
  domain_scanner:     { id: 'domain_scanner',     name: 'Domain Security Scanner Report',       price_inr: 999,  category: 'report',     description: 'Full domain security audit: DNS, SSL, open ports, WHOIS risk, subdomain exposure' },
  'domain-report':    { id: 'domain-report',       name: 'Domain Security Full Report',          price_inr: 999,  category: 'report',     description: 'Full domain security audit — identical to domain_scanner, legacy product ID' },
  ai_analyzer:        { id: 'ai_analyzer',         name: 'AI Security Analyzer Report',          price_inr: 499,  category: 'report',     description: 'AI-driven security posture analysis with remediation roadmap' },
  red_team:           { id: 'red_team',            name: 'Red Team Simulator Report',            price_inr: 999,  category: 'report',     description: 'MITRE ATT&CK-mapped red team simulation with attack chain visualization' },
  compliance:         { id: 'compliance',          name: 'Compliance Checker Report',            price_inr: 799,  category: 'report',     description: 'Multi-framework compliance gap analysis (ISO 27001, SOC2, PCI DSS, HIPAA)' },
  identity_zero_trust:{ id: 'identity_zero_trust', name: 'Identity Zero Trust Report',           price_inr: 699,  category: 'report',     description: 'Zero Trust identity security assessment with implementation guide' },
  sigma_apt29:        { id: 'sigma_apt29',         name: 'Sigma Rule: APT29 Detection',          price_inr: 1299, category: 'detection',  description: 'Production-ready Sigma rules to detect APT29 (Cozy Bear) TTPs in SIEM' },
  yara_ransomware:    { id: 'yara_ransomware',     name: 'YARA Rule: Ransomware Family Pack',    price_inr: 899,  category: 'detection',  description: '50+ YARA rules covering major ransomware families (LockBit, Conti, BlackCat)' },
  fw_zerotrust:       { id: 'fw_zerotrust',        name: 'Firewall Script: Zero Trust',          price_inr: 799,  category: 'script',     description: 'Production firewall ruleset enforcing Zero Trust microsegmentation' },
  ir_ransomware:      { id: 'ir_ransomware',       name: 'IR Playbook: Ransomware Response',     price_inr: 1499, category: 'playbook',   description: '72-hour ransomware IR playbook — containment, forensics, recovery, comms' },
  sigma_lateral:      { id: 'sigma_lateral',       name: 'Sigma Rule: Lateral Movement',        price_inr: 1099, category: 'detection',  description: 'Sigma rules for detecting lateral movement: Pass-the-Hash, WMI, PsExec, RDP' },
  yara_infostealer:   { id: 'yara_infostealer',    name: 'YARA Rule: Infostealer Detection Pack', price_inr: 799, category: 'detection',  description: 'YARA rules for Redline, Vidar, Raccoon, AZORult and 20+ infostealer families' },
  fw_waf:             { id: 'fw_waf',              name: 'Firewall Script: WAF Rules (OWASP)',   price_inr: 699,  category: 'script',     description: 'OWASP Top 10 WAF rules for nginx/Apache/HAProxy with ModSecurity config' },
  py_scanner:         { id: 'py_scanner',          name: 'Python Scanner: Vulnerability Scanner', price_inr: 1199, category: 'script',   description: 'Production Python script for automated CVE scanning and CVSS scoring' },
  fw_bundle:          { id: 'fw_bundle',           name: 'Enterprise Firewall Bundle',           price_inr: 1299, category: 'bundle',    description: 'Complete enterprise firewall config bundle: perimeter + Zero Trust + WAF rules' },
  apt_sigma:          { id: 'apt_sigma',           name: 'APT Detection Sigma Pack',             price_inr: 1099, category: 'bundle',    description: 'Comprehensive Sigma rule pack covering APT29, APT41, Lazarus, FIN7 TTPs' },
  zt_identity:        { id: 'zt_identity',         name: 'Zero Trust Identity Scripts',          price_inr: 999,  category: 'bundle',    description: 'Zero Trust identity enforcement scripts for AD, Azure AD, Okta environments' },
  yara_malware:       { id: 'yara_malware',        name: 'YARA Malware Pack',                    price_inr: 899,  category: 'bundle',    description: '100+ YARA rules for detecting malware across ransomware, RATs, loaders, infostealers' },
  webapp_scanner:     { id: 'webapp_scanner',      name: 'Web App Security Scanner',             price_inr: 1199, category: 'script',    description: 'Automated web application vulnerability scanner — OWASP Top 10, SQLi, XSS, SSRF' },

  // ── Homepage Production Apps Suite ────────────────────────────────────────
  ai_security_toolkit:        { id: 'ai_security_toolkit',        name: 'AI Security Toolkit',            price_inr: 499,  category: 'toolkit',   description: 'Complete OWASP LLM Top 10 implementation guide — checklists, test cases, remediation templates for every LLM vulnerability class' },
  compliance_starter_pack:    { id: 'compliance_starter_pack',    name: 'Compliance Starter Pack',        price_inr: 999,  category: 'toolkit',   description: 'ISO 27001:2022 gap analysis templates, SoA document, 25-policy library, and ISMS implementation roadmap with PDCA cycle' },
  red_team_playbook:          { id: 'red_team_playbook',          name: 'Red Team Playbook',              price_inr: 1499, category: 'playbook',  description: '12 adversary simulation scenarios mapped to MITRE ATT&CK v15 — AI-specific attack chains, tools list, rules of engagement, final report template' },
  zero_trust_blueprint:       { id: 'zero_trust_blueprint',       name: 'Zero Trust Blueprint',           price_inr: 799,  category: 'toolkit',   description: 'Zero Trust Architecture guide: NIST SP 800-207 controls, microsegmentation designs, identity-first access models, vendor evaluation matrix' },
  domain_security_checklist:  { id: 'domain_security_checklist',  name: 'Domain Security Checklist',      price_inr: 499,  category: 'checklist', description: '100-point hardening checklist: TLS 1.3, DNSSEC, DMARC/SPF/DKIM, HTTP security headers, subdomain takeover prevention, certificate pinning guide' },
  dpdp_compliance_kit:        { id: 'dpdp_compliance_kit',        name: 'DPDP Act Compliance Kit',        price_inr: 699,  category: 'toolkit',   description: 'India DPDP Act 2023 compliance kit — Data Fiduciary obligations, consent templates, DPO appointment guide, breach notification SOP, audit checklist' },
  ai_governance_toolkit:      { id: 'ai_governance_toolkit',      name: 'AI Governance Toolkit',          price_inr: 1299, category: 'toolkit',   description: 'EU AI Act readiness + NIST AI RMF implementation — AI system risk classification, conformity assessment templates, IR playbook for AI systems' },
  soc_analyst_runbook:        { id: 'soc_analyst_runbook',        name: 'SOC Analyst Runbook',            price_inr: 1799, category: 'playbook',  description: 'Tier 1-3 SOC analyst runbooks: 20 IR playbooks (phishing, ransomware, insider threat, APT), escalation matrix, SIEM alert triage guide' },
  enterprise_security_bundle: { id: 'enterprise_security_bundle', name: 'Enterprise Security Bundle',     price_inr: 4499, category: 'bundle',    description: 'All 8 products bundled: AI Toolkit + Compliance Pack + Red Team Playbook + Zero Trust Blueprint + Domain Checklist + DPDP Kit + AI Governance + SOC Runbook' },
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

// GET /api/tools/catalog
export async function handleListTools(request, env) {
  return json({ success: true, tools: Object.values(TOOLS_CATALOG) });
}

// POST /api/tools/purchase
export async function handlePurchaseTool(request, env) {
  try {
    const body = await request.json();
    const { product_id, email, currency = 'INR' } = body;
    const tool = TOOLS_CATALOG[product_id];
    if (!tool) return json({ success: false, error: 'Product not found' }, 404);
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
      return json({ success: false, error: 'Valid email required' }, 400);
    }

    const amount = tool.price_inr * 100; // paise
    let razorpayOrderId = null;
    const rzKey    = env.RAZORPAY_KEY_ID;
    const rzSecret = env.RAZORPAY_KEY_SECRET;
    if (rzKey && rzSecret) {
      const r = await fetch('https://api.razorpay.com/v1/orders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Basic ${btoa(`${rzKey}:${rzSecret}`)}` },
        body: JSON.stringify({ amount, currency: 'INR', receipt: `tool_${product_id}_${Date.now()}`, notes: { product_id, email } }),
        signal: AbortSignal.timeout(8000),
      });
      if (r.ok) razorpayOrderId = (await r.json()).id;
    }

    return json({
      success: true,
      order: {
        razorpay_order_id: razorpayOrderId,
        product_id,
        product_name: tool.name,
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

// POST /api/tools/verify
export async function handleVerifyTool(request, env) {
  try {
    const body = await request.json().catch(() => ({}));
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, product_id, email } = body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature || !product_id) {
      return json({ success: false, error: 'Missing verification fields' }, 400);
    }
    const tool = TOOLS_CATALOG[product_id];
    if (!tool) return json({ success: false, error: 'Product not found' }, 404);

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
        return json({ success: true, access_granted: true, product_name: tool.name,
          delivery_note: 'Your tool/file will be delivered to your email within 24 hours.', duplicate: true });
      }
    }

    // Record in D1
    const purchaseId = `tl_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
    if (env.DB) {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO payments (id, user_id, module, target, amount, currency, razorpay_order_id, razorpay_payment_id, status, email, created_at)
         VALUES (?,?,?,?,?,?,?,?,'paid',?,datetime('now'))`
      ).bind(purchaseId, email || null, 'tool', product_id,
             tool.price_inr * 100, 'INR', razorpay_order_id, razorpay_payment_id, email || null)
       .run().catch(e => console.warn('[ToolsMarketplace] D1 error:', e.message));
    }

    // KV access grant (365 days)
    const accessKey = `access:tool:${product_id}:${email || razorpay_payment_id}`;
    await env.SECURITY_HUB_KV?.put(accessKey, JSON.stringify({
      granted_at: new Date().toISOString(),
      payment_id: razorpay_payment_id,
      product_name: tool.name,
    }), { expirationTtl: 365 * 86400 }).catch(() => {});

    // Fire-and-forget: GST invoice + customer email + founder delivery alert
    Promise.all([
      (async () => {
        try {
          const { createInvoice } = await import('../services/v24/billingEngine.js');
          if (env.DB && tool.price_inr) {
            await createInvoice(env.DB, {
              userId: email || purchaseId, email: email || 'noreply@buyer',
              lineItems: [{ description: tool.name, amount_inr: tool.price_inr, quantity: 1 }],
              paymentId: razorpay_payment_id, paymentMethod: 'razorpay',
            });
          }
        } catch (e) { console.warn('[ToolsMarketplace] invoice error:', e.message); }
      })(),
      (async () => {
        try {
          const { sendPurchaseConfirmation } = await import('../services/emailEngine.js');
          if (email) {
            await sendPurchaseConfirmation(env, {
              to: email, productName: tool.name, amountInr: tool.price_inr,
              paymentId: razorpay_payment_id,
            });
          }
        } catch (e) { console.warn('[ToolsMarketplace] confirmation email error:', e.message); }
      })(),
      (async () => {
        try {
          const { sendEmail } = await import('../services/emailEngine.js');
          await sendEmail(env, {
            to: FOUNDER_EMAIL,
            subject: `🔧 TOOL SOLD: ${tool.name} [₹${tool.price_inr}] — ${email || 'unknown'}`,
            html: `<h2 style="color:#10b981">Tool Marketplace Sale</h2>
<table style="border-collapse:collapse;font-family:sans-serif">
<tr><td style="padding:6px 12px;color:#6b7280">Product</td><td style="padding:6px 12px;font-weight:700">${tool.name}</td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Category</td><td style="padding:6px 12px">${tool.category}</td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Price</td><td style="padding:6px 12px;font-weight:700;color:#10b981">₹${tool.price_inr.toLocaleString('en-IN')}</td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Buyer Email</td><td style="padding:6px 12px"><a href="mailto:${email}">${email || 'N/A'}</a></td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Payment ID</td><td style="padding:6px 12px;font-family:monospace">${razorpay_payment_id}</td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Order ID</td><td style="padding:6px 12px;font-family:monospace">${razorpay_order_id}</td></tr>
</table>
<p style="margin-top:20px;padding:12px 16px;background:#fef3c7;border-radius:8px;color:#92400e;font-weight:600">⚡ ACTION REQUIRED: Deliver ${tool.name} to ${email} within 24 hours.</p>
<p><a href="mailto:${email}?subject=Your ${encodeURIComponent(tool.name)} — CYBERDUDEBIVASH" style="background:#10b981;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:700">Send File Now →</a></p>`,
            text: `TOOL SOLD: ${tool.name} ₹${tool.price_inr} to ${email}. Payment: ${razorpay_payment_id}. DELIVER WITHIN 24H.`,
          });
        } catch (e) { console.warn('[ToolsMarketplace] founder alert error:', e.message); }
      })(),
    ]).catch(() => {});

    return json({
      success: true,
      access_granted: true,
      product_name: tool.name,
      payment_id: razorpay_payment_id,
      delivery_note: `${tool.name} will be delivered to ${email} within 24 hours. Check your inbox (and spam).`,
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}
