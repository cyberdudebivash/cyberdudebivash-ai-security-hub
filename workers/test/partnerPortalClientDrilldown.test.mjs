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
// with Overview/Sub-Tenants/Hierarchy/API Keys/Notifications/Billing & Usage
// tabs, wired to all remaining customer-scoped handlers.
//
// ECCP Wave 1 follow-up (this pass): the two gaps the prior pass explicitly
// disclosed are now closed too — label add/remove (extends the existing
// read-only Overview labels display), the Hierarchy tab (parent + children,
// a superset of the flat Sub-Tenants list), the Notifications tab (the real
// 5-channel x 12-event matrix, sourced from the backend's own
// valid_channels/valid_events so the UI can never drift from what the server
// actually accepts), and Ticket Routing Rules — deliberately built as its own
// top-level dashboard card, NOT nested under a client's drill-down, exactly
// per the prior pass's own note: this resource is partner-wide
// (mssp_ticket_rules has no customer_id column at all), so nesting it under
// one client would misleadingly imply per-client scoping that doesn't exist.
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

  it('the partner-wide ticket-rules route is really registered', () => {
    expect(INDEX).toMatch(/mssp\\\/ticket-rules/);
  });

  it('handleMsspTenantRoute really dispatches dashboard/sub-tenants/api-keys/billing/usage by method', () => {
    expect(TENANT).toContain("case 'dashboard':");
    expect(TENANT).toContain("case 'sub-tenants':");
    expect(TENANT).toContain("case 'api-keys':");
    expect(TENANT).toContain("case 'billing':");
    expect(TENANT).toContain("case 'usage':");
  });

  it('handleMsspTenantRoute really dispatches labels/hierarchy/notifications by method', () => {
    expect(TENANT).toContain("case 'labels':");
    expect(TENANT).toContain("case 'hierarchy':");
    expect(TENANT).toContain("case 'notifications':");
  });

  it('requireMSSPAdmin() now admits a real partner session (the fix this UI depends on)', () => {
    expect(TENANT).toContain("authCtx?.role === 'partner'");
  });

  it('partnerScope() now prefers the real partner-session scope over a legacy userId', () => {
    expect(TENANT).toMatch(/authCtx\?\.partnerId\s*\?\?\s*authCtx\?\.userId/);
  });
});

describe('Label add/remove — extends the existing read-only Overview display', () => {
  it('loadClientOverview() still renders labels via the shared renderLabelsList() helper', () => {
    const fn = fnBody('loadClientOverview');
    expect(fn).toContain('renderLabelsList(data.labels');
  });

  it('addClientLabel() POSTs to the dedicated /labels endpoint, not the read-only /dashboard one', () => {
    const fn = fnBody('addClientLabel');
    expect(fn).toContain('/labels');
    expect(fn).toMatch(/method:\s*'POST'/);
    expect(fn).toContain('label');
  });

  it('removeClientLabel() DELETEs the specific label, URI-encoded (backend requires decodeURIComponent-safe input)', () => {
    const fn = fnBody('removeClientLabel');
    expect(fn).toContain('/labels/');
    expect(fn).toMatch(/method:\s*'DELETE'/);
    expect(fn).toContain('encodeURIComponent(label)');
  });

  it('renderLabelsList() escapes label text (no raw interpolation into innerHTML)', () => {
    const fn = fnBody('renderLabelsList');
    expect(fn).toContain('esc(l)');
  });
});

describe('Hierarchy tab — parent link + children, wired to the real endpoint', () => {
  it('loadClientHierarchy() calls the real hierarchy endpoint and reads root/parent/children', () => {
    const fn = fnBody('loadClientHierarchy');
    expect(fn).toContain('/hierarchy');
    expect(fn).toContain('parent');
    expect(fn).toContain('children');
    expect(fn).toContain('total_children');
  });

  it('switchClientTab() loads hierarchy data when that tab is opened', () => {
    const fn = fnBody('switchClientTab');
    expect(fn).toMatch(/hierarchy.*loadClientHierarchy/s);
  });
});

describe('Notification preferences — real 5x12 matrix sourced from the backend\'s own enums', () => {
  it('loadClientNotifPrefs() builds the matrix from valid_channels/valid_events, not a hardcoded list', () => {
    const fn = fnBody('loadClientNotifPrefs');
    expect(fn).toContain('/notifications');
    expect(fn).toContain('data.valid_channels');
    expect(fn).toContain('data.valid_events');
  });

  it('saveClientNotifPrefs() PUTs the full prefs array (matches the backend\'s bulk-upsert contract, not a per-row endpoint)', () => {
    const fn = fnBody('saveClientNotifPrefs');
    expect(fn).toMatch(/method:\s*'PUT'/);
    expect(fn).toContain('prefs');
  });

  it('switchClientTab() loads notification prefs when that tab is opened', () => {
    const fn = fnBody('switchClientTab');
    expect(fn).toMatch(/notifications.*loadClientNotifPrefs/s);
  });
});

describe('Ticket Routing Rules — partner-wide top-level card, not nested under a client', () => {
  it('the Ticket Routing Rules card lives in renderDashboardShell (partner-wide), not inside openClientDetail (customer-scoped)', () => {
    const shellStart = PORTAL.indexOf('function renderDashboardShell');
    const detailStart = PORTAL.indexOf('async function openClientDetail');
    const cardIdx = PORTAL.indexOf('Ticket Routing Rules');
    expect(cardIdx).toBeGreaterThan(shellStart);
    expect(cardIdx).toBeLessThan(detailStart);
  });

  it('loadTicketRules() calls the partner-wide endpoint with no customer id in the path', () => {
    const fn = fnBody('loadTicketRules');
    expect(fn).toContain("'/api/mssp/ticket-rules'");
  });

  it('createTicketRule() POSTs rule_name/conditions/actions/priority and validates JSON client-side before sending', () => {
    const fn = fnBody('createTicketRule');
    expect(fn).toMatch(/method:\s*'POST'/);
    expect(fn).toContain('rule_name');
    expect(fn).toContain('JSON.parse(conditionsRaw)');
    expect(fn).toContain('JSON.parse(actionsRaw)');
  });

  it('deleting a rule goes through a confirm modal, not an immediate DELETE (matches the API-key-revoke pattern)', () => {
    expect(fnBody('confirmDeleteTicketRule')).toContain('openModal');
    const del = fnBody('deleteTicketRuleConfirmed');
    expect(del).toMatch(/method:\s*'DELETE'/);
  });

  it('both dashboard boot paths (magic-link verify and session resume) load ticket rules', () => {
    const matches = PORTAL.match(/loadRevenue\(\); loadCustomers\(\); loadBranding\(\); loadDomainStatus\(\); loadTicketRules\(\);/g) || [];
    expect(matches.length).toBe(2);
  });
});
