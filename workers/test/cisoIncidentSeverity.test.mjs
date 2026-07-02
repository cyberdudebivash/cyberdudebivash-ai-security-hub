// Phase 3 regression test — handleCreateIncident was migrated from a
// locally-redefined severity list to the shared lib/contracts.js
// normalizeSeverity(). Confirms the migration is behavior-preserving:
// same 4 accepted values (still excluding INFO, a deliberate domain
// narrowing), same case-insensitivity, same rejection for invalid input.
import { describe, it, expect } from 'vitest';
import { handleCreateIncident } from '../src/handlers/cisoMetrics.js';

function req(body) {
  return new Request('https://x/api/ciso/incidents', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

describe('handleCreateIncident — severity contract', () => {
  it('accepts lowercase severity and normalizes it to canonical uppercase', async () => {
    const res = await handleCreateIncident(req({ title: 'Suspicious login pattern', severity: 'high' }), {}, { authenticated: true, user_id: 'u_test', email: 'a@b.com' });
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.incident.severity).toBe('HIGH');
  });

  it('defaults to MEDIUM when severity is omitted', async () => {
    const res = await handleCreateIncident(req({ title: 'Unusual outbound traffic' }), {}, { authenticated: true, user_id: 'u_test' });
    const body = await res.json();
    expect(body.data.incident.severity).toBe('MEDIUM');
  });

  it('rejects an invalid severity with 400 INVALID_SEV', async () => {
    const res = await handleCreateIncident(req({ title: 'Test incident title', severity: 'urgent' }), {}, { authenticated: true, user_id: 'u_test' });
    const body = await res.json();
    expect(res.status).toBe(400);
    expect(body.code).toBe('INVALID_SEV');
  });

  it('rejects INFO — a deliberate domain narrowing of the 5-value shared enum', async () => {
    const res = await handleCreateIncident(req({ title: 'Test incident title', severity: 'info' }), {}, { authenticated: true, user_id: 'u_test' });
    expect(res.status).toBe(400);
  });

  it('requires authentication', async () => {
    const res = await handleCreateIncident(req({ title: 'Test incident title' }), {}, {});
    expect(res.status).toBe(401);
  });
});
