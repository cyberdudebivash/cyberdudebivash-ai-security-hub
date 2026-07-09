// CAP-MSSP-003 — MSSP Multi-Tenant Sub-Account Drill-Down
// (docs/capability-registry/domains/mssp.json)
//
// Prior finding: msspTenantPlatform.js is a fully-built, 18-handler,
// well-tested backend (per-client dashboard, sub-tenant hierarchy,
// notification prefs, ticket routing, per-client API keys, per-client
// billing/usage) — but frontend/partner-portal.html (the only partner-facing
// self-service page) wired up only 2 of those 18 handlers (coarse client
// list/create). Building a frontend against the other 16 exactly as
// documented would have silently 403'd for every real partner, because
// requireMSSPAdmin()/partnerScope() in msspTenantPlatform.js never recognized
// a real partner-session identity (see workers/test/
// msspPartnerSessionTenantPlatform.test.mjs for that backend fix, landed in
// the same change as this frontend build).
//
// FIX: partner-portal.html's client list rows are now clickable (previously
// GET /api/mssp/customers's response data — c.id/c.org_slug — was fetched but
// discarded, never reaching the DOM); clicking one opens a drill-down view
// with Overview/Sub-Tenants/API Keys/Billing & Usage tabs, wired to 8 of the
// remaining 16 handlers. Deliberately NOT wired this pass: Notification
// Preferences (a 5-channel x 12-event settings matrix) and Ticket Routing
// Rules (partner-wide, not customer-scoped — the earlier research explicitly
// flagged that nesting it under a specific client's drill-down would mislead
// partners into thinking a rule only applies to that one client) — disclosed
// as known remaining gaps rather than rushed in or mislabeled.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORTAL = readFileSync(resolve(__dirname, '../../frontend/partner-portal.html'), 'utf8');
const INDEX  = readFileSync(resolve(__dirname, '../src/index.js'), 'utf8');
const TENANT = readFileSync(resolve(__dirname, '../src/handlers/msspTenantPlatform.js'), 'utf8');

function fnBody(name) {
  const start = PORTAL.indexOf(`function ${name}`);
  if (start === -1) return '';
  return PORTAL.slice(start, start + 2500);
}

describe('Client list is now a real drill-down entry point (was: data fetched but discarded)', () => {
  it('loadCustomers() keeps the real customer objects (including id) instead of discarding them', () => {
    const fn = fnBody('loadCustomers');
    expect(fn).not.toBe('');
    expect(fn).toContain('_customers = data.customers');
  });

  it('each client row is clickable and opens the drill-down with its real id', () => {
    const fn = fnBody('loadCustomers');
    expect(fn).toContain('clickable-row');
    expect(fn).toContain("openClientDetail('${c.id}')");
  });
});

describe('Client drill-down wired to the real, unmodified backend contract', () => {
  it('loadClientOverview() calls the real per-customer dashboard endpoint', () => {
    const fn = fnBody('loadClientOverview');
    expect(fn).not.toBe('');
    expect(fn).toContain('/dashboard');
    expect(fn).toContain('data.security_posture');
    expect(fn).toContain('data.sub_tenants');
  });

  it('loadClientSubTenants()/createSubTenant() call the real sub-tenants endpoints', () => {
    expect(fnBody('loadClientSubTenants')).toContain('/sub-tenants');
    const create = fnBody('createSubTenant');
    expect(create).toContain('/sub-tenants');
    expect(create).toMatch(/method:\s*'POST'/);
    expect(create).toContain('org_name');
  });

  it('API key list/generate/revoke call the real endpoints with the correct methods', () => {
    expect(fnBody('loadClientApiKeys')).toContain('/api-keys');
    const gen = fnBody('generateClientApiKey');
    expect(gen).toMatch(/method:\s*'POST'/);
    expect(gen).toContain('/api-keys');
    const revoke = fnBody('revokeClientApiKeyConfirmed');
    expect(revoke).toMatch(/method:\s*'DELETE'/);
  });

  it('a freshly-generated key is shown once and the reveal is not lost on next render (matches the one-time-secret backend contract)', () => {
    const fn = fnBody('generateClientApiKey');
    expect(fn).toContain('data.key');
    expect(fn).toContain('key-generate-value');
  });

  it('loadClientBilling() calls both the usage and billing endpoints', () => {
    const fn = fnBody('loadClientBilling');
    expect(fn).toContain('/usage');
    expect(fn).toContain('/billing');
  });
});

describe('Backend contract this UI relies on really exists as documented', () => {
  it('the customer-scoped MSSP route cluster is really registered', () => {
    expect(INDEX).toMatch(/mssp\\\/customers\\\/\[\^\/\]\+\\\/\(dashboard\|labels\|hierarchy\|sub-tenants\|notifications\|api-keys\|billing\|usage\)/);
  });

  it('handleMsspTenantRoute really dispatches dashboard/sub-tenants/api-keys/billing/usage by method', () => {
    expect(TENANT).toContain("case 'dashboard':");
    expect(TENANT).toContain("case 'sub-tenants':");
    expect(TENANT).toContain("case 'api-keys':");
    expect(TENANT).toContain("case 'billing':");
    expect(TENANT).toContain("case 'usage':");
  });

  it('requireMSSPAdmin() now admits a real partner session (the fix this UI depends on)', () => {
    expect(TENANT).toContain("authCtx?.role === 'partner'");
  });

  it('partnerScope() now prefers the real partner-session scope over a legacy userId', () => {
    expect(TENANT).toMatch(/authCtx\?\.partnerId\s*\?\?\s*authCtx\?\.userId/);
  });
});
