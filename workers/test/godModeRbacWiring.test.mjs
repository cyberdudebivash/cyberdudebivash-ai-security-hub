// CAP-MYTHOS-001 — rbac.js declared an 'admin:infra:operate' permission
// specifically for "god-mode / autonomous orchestration" (inline comment,
// rbac.js:103) but mythosGodModeHandler.js never imported or referenced it —
// the /run trigger used only its own bespoke isValidAdminKey()/ENTERPRISE-tier
// check. Wires the RBAC permission in as an ADDITIONAL valid path (not a
// replacement), so a real named SUPERADMIN/owner user can trigger a run
// without needing the shared ADMIN_KEY secret or an ENTERPRISE subscription —
// without narrowing either pre-existing path.
//
// Also removes dead auth plumbing: the /ciso and /hunt-pack routes resolved
// an authCtx via resolveAuthV5 on every request but the handler bodies never
// read it (both are deliberately public reads, per frontend/api-docs.html).
// Router simplified to match the already-unauthenticated /status,
// /compliance, /aspm routes.
import { describe, it, expect } from 'vitest';
import {
  handleGodModeRun, handleGodModeCISOIntel, handleGodModeHuntPack,
} from '../src/handlers/mythosGodModeHandler.js';

function req(headers = {}, opts = {}) {
  return new Request('https://x/test', { headers, ...opts });
}

describe('CAP-MYTHOS-001 — admin:infra:operate wired into handleGodModeRun as an additional path', () => {
  it('still denies a caller with none of the three valid paths', async () => {
    const res = await handleGodModeRun(req(), {}, { tier: 'FREE', email: 'nobody@example.com' }, {});
    expect(res.status).toBe(403);
  });

  it('ADMIN_KEY path is unchanged (regression guard)', async () => {
    const res = await handleGodModeRun(req({ 'x-api-key': 'k' }), { ADMIN_KEY: 'k' }, {}, {});
    expect(res.status).not.toBe(403);
  });

  it('ENTERPRISE tier path is unchanged (regression guard)', async () => {
    const res = await handleGodModeRun(req(), {}, { tier: 'ENTERPRISE' }, {});
    expect(res.status).not.toBe(403);
  });

  it('NEW: a real SUPERADMIN-role authCtx (already resolved this request, e.g. a staff session) is now admitted', async () => {
    const res = await handleGodModeRun(req(), {}, { platformRoles: ['SUPERADMIN'] }, {});
    expect(res.status).not.toBe(403);
  });

  it('NEW: the legacy single-owner-email path (isOwner) is now admitted too', async () => {
    const res = await handleGodModeRun(req(), {}, { email: 'bivash@cyberdudebivash.com' }, {});
    expect(res.status).not.toBe(403);
  });

  it('a platformRoles list without SUPERADMIN is still denied (not every staff role qualifies)', async () => {
    const res = await handleGodModeRun(req(), {}, { platformRoles: ['VIEWER'] }, {});
    expect(res.status).toBe(403);
  });
});

describe('CAP-MYTHOS-001 — /ciso and /hunt-pack work called with no authCtx (dead plumbing removed)', () => {
  it('handleGodModeCISOIntel runs fine with just (request, env)', async () => {
    const res = await handleGodModeCISOIntel(req(), { SECURITY_HUB_KV: { get: async () => null } });
    const body = await res.json();
    expect(body.success).toBe(false); // honest 404-shaped body, no snapshot in this fake KV
  });

  it('handleGodModeHuntPack runs fine with just (request, env)', async () => {
    const res = await handleGodModeHuntPack(req(), { SECURITY_HUB_KV: { get: async () => null } });
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.hunt_pack).toBeNull();
  });
});
