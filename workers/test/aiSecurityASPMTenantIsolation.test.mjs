// CAP-SEC-AUDIT (Enterprise Production Certification Program, 2026-07-12) —
// workers/src/handlers/aiSecurityASPM.js's handleScanAIAsset. Zero prior test
// coverage for this module. A manual OWASP-style sweep found: the handler
// correctly required a real logged-in user (authCtx?.userId), but its asset
// lookup ('SELECT * FROM ai_assets WHERE id=?') had no ownership check at
// all — any authenticated user, including a brand-new FREE-tier signup,
// could scan, read the full posture findings for, and overwrite the
// security_score/risk_score of ANY OTHER tenant's AI asset just by knowing
// (or guessing — asset IDs come from a weak, non-CSPRNG genId()) its id.
//
// Fixed: both the SELECT and the final UPDATE now scope by org_id, using the
// exact same authCtx.orgId||authCtx.userId derivation already used by this
// file's sibling functions (handleRegisterAIAsset/handleListAIAssets), so
// this fix doesn't desync from how assets are already being stored.
import { describe, it, expect, beforeEach } from 'vitest';
import { handleRegisterAIAsset, handleScanAIAsset } from '../src/handlers/aiSecurityASPM.js';

function makeDB() {
  const assets = new Map();
  return {
    _assets: assets,
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async run() {
              if (sql.startsWith('INSERT INTO ai_assets')) {
                const [id, org_id, name, asset_type] = args;
                assets.set(id, { id, org_id, name, asset_type, exposure: 'internal', endpoint_url: null, security_score: null, risk_score: null });
              } else if (sql.startsWith('UPDATE ai_assets')) {
                const [security_score, risk_score, id, org_id] = args;
                const a = assets.get(id);
                if (a && a.org_id === org_id) { a.security_score = security_score; a.risk_score = risk_score; }
              } else if (sql.startsWith('INSERT OR IGNORE INTO ai_findings')) {
                // no-op for this test's purposes
              }
              return { success: true };
            },
            async first() {
              if (sql.includes('WHERE id=? AND org_id=?')) {
                const [id, org_id] = args;
                const a = assets.get(id);
                return (a && a.org_id === org_id) ? a : null;
              }
              return assets.get(args[0]) || null;
            },
          };
        },
      };
    },
  };
}

function req(url, { method = 'POST', body } = {}) {
  return { url, method, json: async () => body ?? {} };
}

const userA = { authenticated: true, userId: 'user-A', email: 'a@example.com' };
const userB = { authenticated: true, userId: 'user-B', email: 'b@example.com' };

describe('handleScanAIAsset — cross-tenant IDOR closed', () => {
  let env;
  beforeEach(() => { env = { DB: makeDB() }; });

  async function registerAssetAs(authCtx) {
    const res = await handleRegisterAIAsset(req('https://x/api/ai-security/assets/register', {
      body: { name: 'Prod GPT-4 Wrapper', asset_type: 'model' },
    }), env, authCtx);
    const body = await res.json();
    return body.asset_id;
  }

  it('anonymous scan is rejected', async () => {
    const res = await handleScanAIAsset(req('https://x/api/ai-security/assets/whatever/scan'), env, {});
    expect(res.status).toBe(401);
  });

  it('the owner can scan their own asset', async () => {
    const assetId = await registerAssetAs(userA);
    const res = await handleScanAIAsset(req(`https://x/api/ai-security/assets/${assetId}/scan`), env, userA);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.asset_id).toBe(assetId);
  });

  it('user B cannot scan (read posture findings for) user A\'s asset by ID', async () => {
    const assetId = await registerAssetAs(userA);
    const res = await handleScanAIAsset(req(`https://x/api/ai-security/assets/${assetId}/scan`), env, userB);
    expect(res.status).toBe(404);
  });

  it('user B\'s rejected scan attempt does not mutate user A\'s asset scores', async () => {
    const assetId = await registerAssetAs(userA);
    await handleScanAIAsset(req(`https://x/api/ai-security/assets/${assetId}/scan`), env, userB);
    const stored = env.DB._assets.get(assetId);
    expect(stored.security_score).toBeNull();
    expect(stored.risk_score).toBeNull();
  });

  it('a real scan by the owner does write real scores to the asset row', async () => {
    const assetId = await registerAssetAs(userA);
    await handleScanAIAsset(req(`https://x/api/ai-security/assets/${assetId}/scan`), env, userA);
    const stored = env.DB._assets.get(assetId);
    expect(typeof stored.security_score).toBe('number');
    expect(typeof stored.risk_score).toBe('number');
  });
});
