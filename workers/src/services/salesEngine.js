// ═══════════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH AI Security Hub — Sales Intelligence Engine
// GTM Growth Engine Phase 4: Enterprise Lead Detection + Outreach Generation
// ═══════════════════════════════════════════════════════════════════════════



// ── Enterprise domain signals ────────────────────────────────────────────────
const FREE_PROVIDERS = new Set([
  'gmail.com','yahoo.com','hotmail.com','outlook.com','icloud.com',
  'protonmail.com','mail.com','yandex.com','zoho.com','aol.com',
]);

// Known high-value TLDs / domain patterns for enterprise scoring
const ENTERPRISE_INDICATORS = {
  tld_boost: {
    'co.in': 15, 'com': 5, 'io': 20, 'ai': 25, 'net': 5,
    'org': 10, 'co': 15, 'tech': 20, 'dev': 15,
  },
  keyword_boost: {
    'bank': 40, 'finance': 35, 'health': 30, 'hospital': 30,
    'insurance': 35, 'government': 40, 'gov': 40, 'defense': 45,
    'security': 25, 'cyber': 25, 'infosec': 25, 'cloud': 20,
    'saas': 20, 'enterprise': 30, 'corp': 25, 'tech': 15,
    'solutions': 15, 'systems': 15, 'consulting': 20,
  },
};

// ── ICP (Ideal Customer Profile) definition ──────────────────────────────────
export const ICP_CRITERIA = {
  min_lead_score:   50,
  is_enterprise:    true,
  plan:             ['free', 'starter'],    // Not yet converted to PRO/Enterprise
  min_scan_count:   2,
  has_critical:     false,                  // optional boost
};

// ─────────────────────────────────────────────────────────────────────────────
// ENTERPRISE LEAD DETECTION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute an enterprise score for a domain/email
 * @param {string} email
 * @param {object} signals - { scan_count, lead_score, has_critical, repeated_usage }
 * @returns {{ enterprise_score: number, signals: object }}
 */
export function scoreEnterpriseLead(email, signals = {}) {
  const domain = email?.split('@')[1]?.toLowerCase() || '';
  let score = 0;
  const reasons = [];

  // Not a free email provider
  if (!FREE_PROVIDERS.has(domain)) {
    score += 30;
    reasons.push('corporate_email');
  } else {
    return { enterprise_score: 0, signals: { is_free_email: true }, reasons };
  }

  // TLD signals
  const tld = domain.split('.').slice(-2).join('.');
  const shortTld = domain.split('.').pop();
  const tldScore = ENTERPRISE_INDICATORS.tld_boost[tld] || ENTERPRISE_INDICATORS.tld_boost[shortTld] || 0;
  if (tldScore > 0) {
    score += tldScore;
    reasons.push(`tld:${tld}`);
  }

  // Domain keyword signals
  const domainName = domain.split('.')[0];
  for (const [keyword, boost] of Object.entries(ENTERPRISE_INDICATORS.keyword_boost)) {
    if (domainName.includes(keyword)) {
      score += boost;
      reasons.push(`keyword:${keyword}`);
      break; // one keyword match max
    }
  }

  // Behavioral signals
  if ((signals.scan_count || 0) >= 5) {
    score += 20;
    reasons.push('high_scan_volume');
  } else if ((signals.scan_count || 0) >= 2) {
    score += 10;
    reasons.push('multiple_scans');
  }

  if (signals.has_critical) {
    score += 15;
    reasons.push('critical_vuln_found');
  }

  if (signals.repeated_usage) {
    score += 15;
    reasons.push('repeated_visitor');
  }

  if ((signals.lead_score || 0) >= 70) {
    score += 20;
    reasons.push('high_lead_score');
  }

  return {
    enterprise_score: Math.min(score, 100),
    is_enterprise:    score >= 40,
    tier:             score >= 80 ? 'hot' : score >= 55 ? 'warm' : 'cool',
    reasons,
  };
}

/**
 * Detect enterprise leads from D1 (for batch processing)
 * @param {object} env
 * @param {number} limit
 */
export async function detectEnterpriseLeads(env, limit = 100) {
  try {
    const result = await env.DB.prepare(`
      SELECT email, name, domain, plan, lead_score, scan_count, is_enterprise,
             created_at, updated_at
      FROM leads
      WHERE is_enterprise = 1
        AND plan IN ('free','starter')
        AND lead_score >= 30
      ORDER BY lead_score DESC, updated_at DESC
      LIMIT ?
    `).bind(limit).all();

    const leads = result.results || [];
    const qualified = [];

    for (const lead of leads) {
      const { enterprise_score, tier, reasons } = scoreEnterpriseLead(lead.email, {
        scan_count:     lead.scan_count || 0,
        lead_score:     lead.lead_score || 0,
        repeated_usage: true,
      });

      if (enterprise_score >= 40) {
        qualified.push({
          ...lead,
          enterprise_score,
          tier,
          qualification_reasons: reasons,
        });
      }
    }

    return qualified;
  } catch (err) {
    console.error('[salesEngine] detectEnterpriseLeads error:', err.message);
    return [];
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// OUTREACH GENERATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate a personalised cold email for a lead
 */
export function generateColdEmail(lead) {
  const firstName = (lead.name || '').split(' ')[0] || 'there';
  const company   = lead.domain?.replace('www.', '').split('.')[0] || 'your company';
  const companyTitled = company.charAt(0).toUpperCase() + company.slice(1);

  const urgencyLines = lead.has_critical
    ? `I noticed ${companyTitled} has at least one CRITICAL severity vulnerability (CVSS ≥ 9.0) in your current exposure scan. These are being actively exploited in the wild — average time to exploitation after disclosure is 15 days.`
    : `I noticed ${companyTitled} has appeared in our threat intelligence feed with ${lead.lead_score >= 60 ? 'high' : 'moderate'} exposure signals.`;

  const subject = lead.has_critical
    ? `⚠️ Critical vulnerability detected on ${lead.domain} — urgent`
    : `${companyTitled}'s cybersecurity exposure — a quick note`;

  const body = `Hi ${firstName},

${urgencyLines}

I'm Bivash, founder of Sentinel APEX — an AI-powered threat intelligence platform that monitors CVEs, CISA KEV entries, and live exploit data to give security teams real-time visibility into what's actually dangerous right now.

We currently protect several SaaS and enterprise teams in India and Southeast Asia, and I wanted to reach out personally because ${companyTitled} showed up in our detection pipeline.

Would a 15-minute call make sense to walk you through what we're seeing? No pitch deck, just the data.

If you'd rather start with a free deep-scan, you can do that here: https://tools.cyberdudebivash.com

Best,
Bivash Nayak
Founder, Sentinel APEX
bivashnayak.ai007@gmail.com
https://cyberdudebivash.in`;

  return { subject, body, channel: 'email', lead_email: lead.email };
}

/**
 * Generate a LinkedIn outreach message
 */
export function generateLinkedInMessage(lead) {
  const firstName = (lead.name || '').split(' ')[0] || 'there';
  const company   = lead.domain?.replace('www.', '').split('.')[0] || 'your company';
  const companyTitled = company.charAt(0).toUpperCase() + company.slice(1);

  const message = `Hi ${firstName},

I came across ${companyTitled} while analyzing threat intelligence data for enterprise customers in your sector. We detected some vulnerability signals worth a quick conversation.

I'm building Sentinel APEX — an AI-driven security platform that gives teams real-time CVE intelligence, EPSS-ranked exploit predictions, and autonomous defense automation.

Would love to share what we're seeing. Open to a quick 15-min chat?

— Bivash`;

  return { message: message.trim(), channel: 'linkedin', lead_email: lead.email };
}

/**
 * Generate a proposal draft for a hot enterprise lead
 */
export function generateProposalDraft(lead) {
  const company     = lead.domain?.replace('www.', '').split('.')[0] || 'Your Company';
  const companyFull = company.charAt(0).toUpperCase() + company.slice(1);
  const plan        = 'Enterprise';
  const price       = '₹4,999/month';

  const proposal = `
═══════════════════════════════════════════════════════════
SENTINEL APEX — Enterprise Security Proposal
Prepared for: ${companyFull}
Date: ${new Date().toLocaleDateString('en-IN')}
═══════════════════════════════════════════════════════════

EXECUTIVE SUMMARY
─────────────────
${companyFull} currently has measurable vulnerability exposure across its public-facing infrastructure. Sentinel APEX provides an AI-powered threat intelligence and SOC automation layer that reduces mean-time-to-detect (MTTD) from weeks to minutes.

WHAT WE DETECTED
─────────────────
• Lead Score:        ${lead.lead_score}/100
• Enterprise Score:  ${lead.enterprise_score || 'N/A'}/100
• Current Plan:      ${lead.plan || 'Free'}
• Scan Count:        ${lead.scan_count || 0} scans

PROPOSED SOLUTION: ${plan.toUpperCase()} PLAN
─────────────────────────────────────────────
✓ Unlimited CVE scans (NVD + CISA KEV + GitHub Advisory)
✓ AI SOC pipeline: Detect → Decide → Respond → Defend
✓ Autonomous defense rules (Cloudflare WAF + Zero Trust)
✓ Real-time Telegram alerts for CRITICAL/KEV events
✓ CVE correlation engine (APT mapping, campaign tracking)
✓ EPSS scores + IOC lists per vulnerability
✓ Enterprise API (unlimited calls/month)
✓ Dedicated support + SLA

INVESTMENT
──────────
${price} (billed monthly)
Annual plan available: ₹47,990/year (save ₹11,998)

NEXT STEPS
──────────
1. 30-min technical deep-dive call
2. Free 14-day Enterprise trial
3. Integration with your existing security stack

Reply to this email or book a call: https://calendly.com/bivash-cyberdudebivash

═══════════════════════════════════════════════════════════
Bivash Nayak | Founder, Sentinel APEX
bivashnayak.ai007@gmail.com | +91-XXXXXXXXXX
https://cyberdudebivash.in
═══════════════════════════════════════════════════════════`;

  return { proposal: proposal.trim(), channel: 'proposal', lead_email: lead.email };
}

// ─────────────────────────────────────────────────────────────────────────────
// PIPELINE ORCHESTRATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate a full outreach bundle for a lead
 */
export function generateOutreachBundle(lead) {
  return {
    lead_email:     lead.email,
    lead_score:     lead.lead_score,
    enterprise_score: lead.enterprise_score,
    tier:           lead.tier,
    cold_email:     generateColdEmail(lead),
    linkedin:       generateLinkedInMessage(lead),
    proposal:       lead.enterprise_score >= 70 ? generateProposalDraft(lead) : null,
    recommended_action: lead.enterprise_score >= 70 ? 'send_proposal' :
                        lead.enterprise_score >= 50 ? 'send_email_and_linkedin' : 'send_email',
    generated_at:   new Date().toISOString(),
  };
}

/**
 * Store outreach in D1 for tracking
 */
export async function storeOutreach(env, outreachBundle) {
  try {
    const now = new Date().toISOString();
    await env.DB.prepare(`
      INSERT INTO sales_outreach (id, email, outreach_type, subject, body, status, created_at)
      VALUES (?, ?, ?, ?, ?, 'draft', ?)
    `).bind(
      crypto.randomUUID(),
      outreachBundle.lead_email,
      outreachBundle.recommended_action,
      outreachBundle.cold_email?.subject || '',
      outreachBundle.cold_email?.body || '',
      now
    ).run();
  } catch (err) {
    console.error('[salesEngine] storeOutreach error:', err.message);
  }
}

/**
 * Run the full enterprise sales pipeline
 * Detects → Scores → Generates outreach → Stores
 */
export async function runSalesPipeline(env) {
  const leads = await detectEnterpriseLeads(env, 50);
  const results = { processed: 0, outreach_generated: 0, proposals: 0 };

  for (const lead of leads) {
    const bundle = generateOutreachBundle(lead);
    await storeOutreach(env, bundle);
    results.processed++;
    results.outreach_generated++;
    if (bundle.proposal) results.proposals++;
  }

  return {
    ...results,
    enterprise_leads_found: leads.length,
    hot_leads: leads.filter(l => l.tier === 'hot').length,
  };
}

/**
 * Get stored outreach items
 */
export async function getOutreachQueue(env, { status = 'draft', limit = 20 } = {}) {
  try {
    const result = await env.DB.prepare(`
      SELECT * FROM sales_outreach
      WHERE status = ?
      ORDER BY created_at DESC
      LIMIT ?
    `).bind(status, limit).all();
    return result.results || [];
  } catch {
    return [];
  }
}

/**
 * Mark outreach as sent
 */
export async function markOutreachSent(env, outreachId) {
  try {
    await env.DB.prepare(`
      UPDATE sales_outreach SET status = 'sent', sent_at = datetime('now')
      WHERE id = ?
    `).bind(outreachId).run();
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}
