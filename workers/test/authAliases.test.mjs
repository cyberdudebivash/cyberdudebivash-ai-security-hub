/* Regression tests — Fix #3: authCtx.userId / authCtx.keyId aliases.
 * resolveAuthV5 populates snake_case user_id/key_id; consumers (org CRUD, RBAC,
 * anomaly detection, audit logging, marketplace getUserId) read camelCase.
 * These guards prove every keyless auth path now exposes both aliases. */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolveAuthV5 } from '../src/auth/middleware.js';

describe('resolveAuthV5 — camelCase aliases', () => {
  it('admin_key path exposes userId & keyId aliased from user_id/key_id', async () => {
    const req = new Request('https://x/api/scan/domain', {
      method: 'POST', headers: { 'x-api-key': 'SECRET-ADMIN' },
    });
    const ctx = await resolveAuthV5(req, { ADMIN_KEY: 'SECRET-ADMIN' });
    expect(ctx.authenticated).toBe(true);
    expect(ctx.userId).toBe(ctx.user_id);
    expect(ctx.keyId).toBe(ctx.key_id);
    expect(ctx.userId).toBe('admin');
  });

  it('ip_fallback path defines userId & keyId keys (null, not undefined)', async () => {
    const ctx = await resolveAuthV5(new Request('https://x/'), {});
    expect('userId' in ctx).toBe(true);
    expect('keyId' in ctx).toBe(true);
    expect(ctx.userId).toBeNull();
    expect(ctx.keyId).toBeNull();
  });
});

describe('orgManagement — scan_history column drift', () => {
  it('queries use the real scan_history.target column, never target_summary', () => {
    const src = readFileSync(
      fileURLToPath(new URL('../src/handlers/orgManagement.js', import.meta.url)),
      'utf8',
    );
    // No bare sh.target_summary read should remain (alias `AS target_summary` is fine).
    expect(/sh\.target_summary/.test(src)).toBe(false);
    expect(/sh\.target AS target_summary/.test(src)).toBe(true);
  });
});
