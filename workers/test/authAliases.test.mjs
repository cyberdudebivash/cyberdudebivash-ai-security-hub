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

// Regression: authCtx.id was never populated anywhere in this auth layer —
// only user_id/userId existed — yet notificationPlatform.js, reportingEngine.js,
// workflowAutomation.js, globalSearch.js, and productAnalytics.js all read
// req.user.id / authCtx.id directly with no fallback, silently collapsing
// every real caller onto a shared 'unknown' row (userId = undefined || 'unknown').
describe('resolveAuthV5 — .id alias (fixes notificationPlatform.js and 4 sibling handlers)', () => {
  it('admin_key path exposes .id aliased from user_id, not undefined', async () => {
    const req = new Request('https://x/api/scan/domain', {
      method: 'POST', headers: { 'x-api-key': 'SECRET-ADMIN' },
    });
    const ctx = await resolveAuthV5(req, { ADMIN_KEY: 'SECRET-ADMIN' });
    expect(ctx.id).toBe(ctx.user_id);
    expect(ctx.id).toBe('admin');
  });

  it('ip_fallback (genuinely anonymous) path defines .id as null, not undefined', async () => {
    const ctx = await resolveAuthV5(new Request('https://x/'), {});
    expect('id' in ctx).toBe(true);
    expect(ctx.id).toBeNull();
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
