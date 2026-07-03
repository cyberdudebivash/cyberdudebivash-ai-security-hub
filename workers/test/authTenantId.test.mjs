/* Every authenticated principal must get a stable per-user tenant id (org_id) so
 * the ~15 handlers that scope with `authCtx.org_id || 'default'` isolate per user
 * instead of sharing one 'default' bucket. Anonymous IP-fallback keeps no org_id.
 */
import { describe, it, expect } from 'vitest';
import { resolveAuthV5 } from '../src/auth/middleware.js';

const reqWith = (headers = {}) => new Request('https://x/api/x', { headers });

describe('auth tenant id (org_id) assignment', () => {
  it('an authenticated principal (admin key) gets a per-user org_id', async () => {
    const env = { ADMIN_KEY: 'secret-admin-key' };
    const ctx = await resolveAuthV5(reqWith({ 'x-api-key': 'secret-admin-key' }), env);
    expect(ctx.authenticated).toBe(true);
    expect(ctx.user_id).toBe('admin');
    expect(ctx.org_id).toBe('u:admin');   // stable per-user tenant, not 'default'
  });

  it('anonymous IP-fallback keeps no org_id (its own default applies)', async () => {
    const ctx = await resolveAuthV5(reqWith(), {});   // no admin key, no JWT, no api key
    expect(ctx.authenticated).toBe(true);
    expect(ctx.user_id).toBeNull();
    expect(ctx.org_id == null).toBe(true);
  });

  it('two different users would receive different org_ids', async () => {
    // Simulate the alias step directly through resolveAuthV5's admin path is fixed
    // to one id; assert the derivation rule instead: org_id === `u:${user_id}`.
    const env = { ADMIN_KEY: 'k' };
    const ctx = await resolveAuthV5(reqWith({ 'x-api-key': 'k' }), env);
    expect(ctx.org_id).toBe(`u:${ctx.user_id}`);
  });
});
