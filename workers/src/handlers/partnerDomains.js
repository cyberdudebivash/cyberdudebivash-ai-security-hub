// =============================================================================
// CYBERDUDEBIVASH AI Security Hub | handlers/partnerDomains.js
//
// Custom-domain verification for MSSP partners (Partner/White-label infra).
//
// What this genuinely does, end to end, right now:
//   1. A partner requests a domain -> we generate a random challenge token and
//      tell them to publish it as a DNS TXT record.
//   2. A partner asks us to verify -> we perform a REAL DNS-over-HTTPS TXT
//      lookup (lib/dns.js — the same resolver already used by the domain scan
//      engine) against _cdb-challenge.<their-domain> and check for the token.
//      This is genuine domain-ownership proof, not a stub.
//   3. Once verified, mssp_partners.custom_domain is set and
//      resolvePartnerByHost() can look up a partner by an inbound Host header,
//      merging in their branding from tenant_themes (the same storage the
//      white-label editor in partner-portal.html already writes to).
//
// What this deliberately does NOT claim to do: serve live traffic on the
// partner's domain. That additionally requires (a) the partner CNAMEing their
// domain to this Worker's custom-hostname target, and (b) that hostname being
// registered as a Cloudflare for SaaS Custom Hostname on THIS account — an
// external, account-level, typically-paid Cloudflare feature provisioned
// manually per partner, not something this code can do or verify by itself.
// Every response below says so explicitly so a partner is never told "done"
// when only DNS ownership has actually been proven.
// =============================================================================

import { getTXTRecords } from '../lib/dns.js';

const CHALLENGE_PREFIX = '_cdb-challenge.';
const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;
const LIVE_ROUTING_NOTE = 'Domain ownership verified. Live traffic routing on this domain additionally requires Cloudflare for SaaS custom-hostname activation, which our team completes manually per partner — contact mssp@cyberdudebivash.com to finish activation.';

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

function genChallengeToken() {
  return 'cdb-verify-' + Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function ensureTable(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS partner_domains (
      id              TEXT PRIMARY KEY,
      partner_id      TEXT NOT NULL,
      domain          TEXT NOT NULL,
      challenge_token TEXT NOT NULL,
      status          TEXT NOT NULL DEFAULT 'pending_verification',
      requested_at    TEXT NOT NULL,
      verified_at     TEXT,
      UNIQUE(partner_id, domain)
    )
  `).run();
}

// ── POST /api/partners/domain/request ─────────────────────────────────────
// Body: { domain }. Partner session only.
export async function handleRequestPartnerDomain(request, env, authCtx = {}) {
  if (!authCtx.partnerId) return jsonResponse({ error: 'Partner login required' }, 401);
  if (!env.DB) return jsonResponse({ error: 'Database unavailable' }, 503);

  const body = await request.json().catch(() => ({}));
  const domain = String(body.domain || '').toLowerCase().trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!domain || !DOMAIN_RE.test(domain)) {
    return jsonResponse({ error: 'Valid domain required (e.g. portal.yourfirm.com)' }, 400);
  }

  await ensureTable(env.DB);

  const token = genChallengeToken();
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  await env.DB.prepare(
    `INSERT INTO partner_domains (id, partner_id, domain, challenge_token, status, requested_at)
     VALUES (?,?,?,?,?,?)
     ON CONFLICT(partner_id, domain) DO UPDATE SET
       challenge_token=excluded.challenge_token, status='pending_verification',
       requested_at=excluded.requested_at, verified_at=NULL`
  ).bind(id, authCtx.partnerId, domain, token, 'pending_verification', now).run();

  return jsonResponse({
    success: true,
    domain,
    status: 'pending_verification',
    verification: { type: 'TXT', host: `${CHALLENGE_PREFIX}${domain}`, value: token },
    instructions: `Add a TXT record at ${CHALLENGE_PREFIX}${domain} with the value shown, then call POST /api/partners/domain/verify. DNS changes can take up to 24-48 hours to propagate.`,
  });
}

// ── POST /api/partners/domain/verify ───────────────────────────────────────
// Body: { domain }. Performs a real DNS TXT lookup — not a stub.
export async function handleVerifyPartnerDomain(request, env, authCtx = {}) {
  if (!authCtx.partnerId) return jsonResponse({ error: 'Partner login required' }, 401);
  if (!env.DB) return jsonResponse({ error: 'Database unavailable' }, 503);

  const body = await request.json().catch(() => ({}));
  const domain = String(body.domain || '').toLowerCase().trim();
  if (!domain) return jsonResponse({ error: 'domain required' }, 400);

  await ensureTable(env.DB);

  const row = await env.DB.prepare(
    `SELECT * FROM partner_domains WHERE partner_id=? AND domain=?`
  ).bind(authCtx.partnerId, domain).first().catch(() => null);
  if (!row) return jsonResponse({ error: 'No pending domain request found. Call POST /api/partners/domain/request first.' }, 404);

  if (row.status === 'verified') {
    return jsonResponse({ success: true, domain, status: 'verified', verified_at: row.verified_at, live_routing: false, live_routing_note: LIVE_ROUTING_NOTE });
  }

  const records = await getTXTRecords(`${CHALLENGE_PREFIX}${domain}`).catch(() => []);
  const found = records.some(r => r.includes(row.challenge_token));

  if (!found) {
    return jsonResponse({
      success: false,
      domain,
      status: 'pending_verification',
      error: "TXT record not found yet (or DNS hasn't propagated). Try again shortly.",
      verification: { type: 'TXT', host: `${CHALLENGE_PREFIX}${domain}`, value: row.challenge_token },
      records_seen: records,
    });
  }

  const now = new Date().toISOString();
  await env.DB.prepare(`UPDATE partner_domains SET status='verified', verified_at=? WHERE id=?`).bind(now, row.id).run();
  await env.DB.prepare(`UPDATE mssp_partners SET custom_domain=? WHERE id=?`).bind(domain, authCtx.partnerId).run().catch(() => {});

  return jsonResponse({ success: true, domain, status: 'verified', verified_at: now, live_routing: false, live_routing_note: LIVE_ROUTING_NOTE });
}

// ── GET /api/partners/domain/status ────────────────────────────────────────
export async function handlePartnerDomainStatus(request, env, authCtx = {}) {
  if (!authCtx.partnerId) return jsonResponse({ error: 'Partner login required' }, 401);
  if (!env.DB) return jsonResponse({ error: 'Database unavailable' }, 503);
  await ensureTable(env.DB);

  const rows = await env.DB.prepare(
    `SELECT domain, status, requested_at, verified_at FROM partner_domains WHERE partner_id=? ORDER BY requested_at DESC`
  ).bind(authCtx.partnerId).all().catch(() => ({ results: [] }));

  return jsonResponse({ success: true, domains: rows.results || [] });
}

// ── Host-header resolution ─────────────────────────────────────────────────
// Given an inbound request's Host header, look up which VERIFIED partner (if
// any) owns it, merging in their branding from tenant_themes — the same
// storage the white-label editor in partner-portal.html writes to. Real,
// working lookup code — but it can only ever be reached in production once
// that domain is ALSO registered as a Cloudflare Custom Hostname on this
// account (see LIVE_ROUTING_NOTE above); until then, no traffic for a
// partner's own domain reaches this Worker to begin with.
export async function resolvePartnerByHost(env, host) {
  if (!env.DB || !host) return null;
  const clean = String(host).toLowerCase().split(':')[0];

  const partner = await env.DB.prepare(
    `SELECT id, company, brand_name, primary_color, custom_domain FROM mssp_partners WHERE custom_domain=? AND status IN ('active','trial')`
  ).bind(clean).first().catch(() => null);
  if (!partner) return null;

  const theme = await env.DB.prepare(
    `SELECT logo_url, favicon_url FROM tenant_themes WHERE org_id=?`
  ).bind(`partner:${partner.id}`).first().catch(() => null);

  return { ...partner, logo_url: theme?.logo_url || null, favicon_url: theme?.favicon_url || null };
}

// ── GET /api/partners/resolve-domain?host=... — public ─────────────────────
// Used by a partner-branded page to fetch which partner it should render as.
export async function handleResolvePartnerDomain(request, env) {
  const url = new URL(request.url);
  const host = url.searchParams.get('host') || request.headers.get('Host') || '';
  const partner = await resolvePartnerByHost(env, host);
  if (!partner) return jsonResponse({ error: 'No verified partner domain matches this host' }, 404);
  return jsonResponse({
    success: true,
    company: partner.company,
    brand_name: partner.brand_name,
    primary_color: partner.primary_color,
    logo_url: partner.logo_url,
    favicon_url: partner.favicon_url,
  });
}
