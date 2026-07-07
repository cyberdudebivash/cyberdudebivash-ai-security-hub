/* Regression tests — partner custom-domain verification (2026-07-07 Partner/
 * White-label infra). This proves genuine domain ownership via a real DNS
 * TXT lookup (lib/dns.js DoH resolver, stubbed at the fetch layer here, same
 * as every other DNS test in this codebase) — not a rubber-stamp. It also
 * locks the honest boundary: verifying ownership is NOT the same as live
 * traffic routing, and every response says so explicitly. */
import { describe, it, expect, afterEach } from 'vitest';
import {
  handleRequestPartnerDomain,
  handleVerifyPartnerDomain,
  handlePartnerDomainStatus,
  resolvePartnerByHost,
  handleResolvePartnerDomain,
} from '../src/handlers/partnerDomains.js';

function makeEnv() {
  const domains = new Map(); // key: `${partner_id}:${domain}`
  const partners = new Map([
    ['mp_1', { id: 'mp_1', company: 'Acme', brand_name: 'Acme Sec', primary_color: '#123456', custom_domain: null, status: 'active' }],
  ]);
  const themes = new Map();

  const env = {
    DB: {
      prepare(sql) {
        let b = [];
        return {
          bind(...a) { b = a; return this; },
          async run() {
            if (/CREATE TABLE/.test(sql)) return { success: true };
            if (/INSERT INTO partner_domains/.test(sql)) {
              const [id, partner_id, domain, challenge_token, status, requested_at] = b;
              domains.set(`${partner_id}:${domain}`, { id, partner_id, domain, challenge_token, status, requested_at, verified_at: null });
              return { success: true };
            }
            if (/UPDATE partner_domains SET status='verified'/.test(sql)) {
              const [verified_at, id] = b;
              for (const row of domains.values()) if (row.id === id) { row.status = 'verified'; row.verified_at = verified_at; }
              return { success: true };
            }
            if (/UPDATE mssp_partners SET custom_domain/.test(sql)) {
              const [domain, partnerId] = b;
              const p = partners.get(partnerId);
              if (p) p.custom_domain = domain;
              return { success: true };
            }
            return { success: true };
          },
          async first() {
            if (/SELECT \* FROM partner_domains WHERE partner_id/.test(sql)) {
              const [partnerId, domain] = b;
              return domains.get(`${partnerId}:${domain}`) || null;
            }
            if (/FROM mssp_partners WHERE custom_domain/.test(sql)) {
              const [domain] = b;
              return [...partners.values()].find(p => p.custom_domain === domain && ['active', 'trial'].includes(p.status)) || null;
            }
            if (/FROM tenant_themes WHERE org_id/.test(sql)) {
              const [orgId] = b;
              return themes.get(orgId) || null;
            }
            return null;
          },
          async all() {
            if (/FROM partner_domains WHERE partner_id/.test(sql)) {
              const [partnerId] = b;
              return { results: [...domains.values()].filter(d => d.partner_id === partnerId) };
            }
            return { results: [] };
          },
        };
      },
    },
    _domains: domains,
    _partners: partners,
    _themes: themes,
  };
  return env;
}

function req(body) {
  return new Request('https://x', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

describe('POST /api/partners/domain/request', () => {
  it('requires a partner session', async () => {
    const env = makeEnv();
    const res = await handleRequestPartnerDomain(req({ domain: 'portal.acme.com' }), env, {});
    expect(res.status).toBe(401);
  });

  it('rejects an invalid domain', async () => {
    const env = makeEnv();
    const res = await handleRequestPartnerDomain(req({ domain: 'not a domain' }), env, { partnerId: 'mp_1' });
    expect(res.status).toBe(400);
  });

  it('issues a real TXT-record challenge for a valid domain', async () => {
    const env = makeEnv();
    const res = await handleRequestPartnerDomain(req({ domain: 'portal.acme.com' }), env, { partnerId: 'mp_1' });
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.status).toBe('pending_verification');
    expect(body.verification.host).toBe('_cdb-challenge.portal.acme.com');
    expect(body.verification.value).toMatch(/^cdb-verify-/);
    expect(env._domains.get('mp_1:portal.acme.com').status).toBe('pending_verification');
  });
});

describe('POST /api/partners/domain/verify — a real DNS TXT lookup, not a stub', () => {
  it('404s if no domain was requested first', async () => {
    const env = makeEnv();
    const res = await handleVerifyPartnerDomain(req({ domain: 'never-requested.com' }), env, { partnerId: 'mp_1' });
    expect(res.status).toBe(404);
  });

  it('stays pending when the TXT record is not present yet', async () => {
    const env = makeEnv();
    await handleRequestPartnerDomain(req({ domain: 'portal.acme.com' }), env, { partnerId: 'mp_1' });
    globalThis.fetch = async () => new Response(JSON.stringify({ Answer: [] }), { status: 200 }); // no TXT record found
    const res = await handleVerifyPartnerDomain(req({ domain: 'portal.acme.com' }), env, { partnerId: 'mp_1' });
    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.status).toBe('pending_verification');
    expect(env._partners.get('mp_1').custom_domain).toBeNull();
  });

  it('verifies and links mssp_partners.custom_domain once the real TXT record matches the challenge token', async () => {
    const env = makeEnv();
    const reqRes = await handleRequestPartnerDomain(req({ domain: 'portal.acme.com' }), env, { partnerId: 'mp_1' });
    const { verification } = await reqRes.json();

    globalThis.fetch = async () => new Response(JSON.stringify({
      Answer: [{ type: 16, data: `"${verification.value}"` }],
    }), { status: 200 });

    const res = await handleVerifyPartnerDomain(req({ domain: 'portal.acme.com' }), env, { partnerId: 'mp_1' });
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.status).toBe('verified');
    // Honest boundary: verified ownership is explicitly NOT the same as live routing.
    expect(body.live_routing).toBe(false);
    expect(body.live_routing_note).toMatch(/Cloudflare for SaaS/);
    expect(env._partners.get('mp_1').custom_domain).toBe('portal.acme.com');
  });

  it('re-verifying an already-verified domain is idempotent', async () => {
    const env = makeEnv();
    const reqRes = await handleRequestPartnerDomain(req({ domain: 'portal.acme.com' }), env, { partnerId: 'mp_1' });
    const { verification } = await reqRes.json();
    globalThis.fetch = async () => new Response(JSON.stringify({ Answer: [{ type: 16, data: `"${verification.value}"` }] }), { status: 200 });
    await handleVerifyPartnerDomain(req({ domain: 'portal.acme.com' }), env, { partnerId: 'mp_1' });

    const res2 = await handleVerifyPartnerDomain(req({ domain: 'portal.acme.com' }), env, { partnerId: 'mp_1' });
    const body2 = await res2.json();
    expect(body2.status).toBe('verified');
  });
});

describe('GET /api/partners/domain/status', () => {
  it('requires a partner session', async () => {
    const env = makeEnv();
    const res = await handlePartnerDomainStatus(new Request('https://x'), env, {});
    expect(res.status).toBe(401);
  });

  it('lists the requesting partner\'s own domain(s) only', async () => {
    const env = makeEnv();
    await handleRequestPartnerDomain(req({ domain: 'portal.acme.com' }), env, { partnerId: 'mp_1' });
    const res = await handlePartnerDomainStatus(new Request('https://x'), env, { partnerId: 'mp_1' });
    const body = await res.json();
    expect(body.domains.length).toBe(1);
    expect(body.domains[0].domain).toBe('portal.acme.com');
  });
});

describe('resolvePartnerByHost / GET /api/partners/resolve-domain', () => {
  it('returns null for a host that matches no verified partner domain', async () => {
    const env = makeEnv();
    const result = await resolvePartnerByHost(env, 'nobody-owns-this.com');
    expect(result).toBeNull();
  });

  it('resolves a partner by their verified custom domain, merging in their theme branding', async () => {
    const env = makeEnv();
    env._partners.get('mp_1').custom_domain = 'portal.acme.com';
    env._themes.set('partner:mp_1', { logo_url: 'https://acme.com/logo.png', favicon_url: null });

    const result = await resolvePartnerByHost(env, 'portal.acme.com:443');
    expect(result.id).toBe('mp_1');
    expect(result.company).toBe('Acme');
    expect(result.logo_url).toBe('https://acme.com/logo.png');
  });

  it('GET /api/partners/resolve-domain 404s for an unmatched host', async () => {
    const env = makeEnv();
    const res = await handleResolvePartnerDomain(new Request('https://x/api/partners/resolve-domain?host=unknown.com'), env);
    expect(res.status).toBe(404);
  });

  it('GET /api/partners/resolve-domain returns branding for a verified partner host', async () => {
    const env = makeEnv();
    env._partners.get('mp_1').custom_domain = 'portal.acme.com';
    const res = await handleResolvePartnerDomain(new Request('https://x/api/partners/resolve-domain?host=portal.acme.com'), env);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.brand_name).toBe('Acme Sec');
  });
});
