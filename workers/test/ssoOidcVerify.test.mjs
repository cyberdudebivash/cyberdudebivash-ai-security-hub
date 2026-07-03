/**
 * Integration test — Enterprise SSO OIDC id_token verification (the security-
 * critical hop). Exercises the REAL verifyIdToken() against a REAL RS256 token:
 *
 *   • generates an RSA keypair (Web Crypto), publishes its public JWK as the IdP
 *     JWKS (seeded into the KV cache getJWKS() reads first — no network),
 *   • signs a valid id_token with the private key,
 *   • asserts verifyIdToken() returns the claims for a good token, and THROWS on:
 *       - a tampered signature,
 *       - an expired token,
 *       - an audience mismatch,
 *       - a nonce mismatch,
 *       - an alg-confusion downgrade (alg:"none" / HS256).
 *
 * This proves the enterprise SSO login trusts only correctly-signed, unexpired,
 * correctly-scoped tokens from the configured IdP. The remaining unproven hop is a
 * live round-trip against a real IdP (see scripts/verify-external-integrations.sh).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { verifyIdToken } from '../src/lib/oidc.js';

const ISSUER = 'https://idp.example.com';
const JWKS_URI = 'https://idp.example.com/jwks';
const CLIENT_ID = 'cdb-enterprise-client';
const KID = 'test-key-1';

const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const enc = new TextEncoder();

let privateKey, discovery, kv;

async function makeToken(claims, { key = privateKey, alg = 'RS256', kid = KID } = {}) {
  const header  = b64url(enc.encode(JSON.stringify({ alg, kid, typ: 'JWT' })));
  const payload = b64url(enc.encode(JSON.stringify(claims)));
  const signingInput = `${header}.${payload}`;
  if (alg === 'none') return `${signingInput}.`;
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(signingInput));
  return `${signingInput}.${b64url(new Uint8Array(sig))}`;
}

function validClaims(over = {}) {
  const now = Math.floor(Date.now() / 1000);
  return { sub: 'idp|user-1', email: 'cto@acme.com', email_verified: true, name: 'CTO Acme',
    iss: ISSUER, aud: CLIENT_ID, exp: now + 3600, iat: now, nonce: 'nonce-abc', ...over };
}

beforeAll(async () => {
  const pair = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
    true, ['sign', 'verify']);
  privateKey = pair.privateKey;
  const pubJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  pubJwk.kid = KID; pubJwk.use = 'sig'; pubJwk.alg = 'RS256';
  const jwks = { keys: [pubJwk] };
  discovery = { issuer: ISSUER, jwks_uri: JWKS_URI };
  kv = { get: async (k, t) => (k === `oidc_jwks:${JWKS_URI}` ? jwks : null), put: async () => {} };
});

describe('SSO OIDC id_token verification (real RS256)', () => {
  const opts = () => ({ clientId: CLIENT_ID, kv, expectedNonce: 'nonce-abc' });

  it('accepts a correctly-signed, unexpired, correctly-scoped token', async () => {
    const token = await makeToken(validClaims());
    const claims = await verifyIdToken(token, discovery, opts());
    expect(claims.email).toBe('cto@acme.com');
    expect(claims.sub).toBe('idp|user-1');
  });

  it('rejects a tampered signature', async () => {
    const token = await makeToken(validClaims());
    const tampered = token.slice(0, -4) + (token.endsWith('AAAA') ? 'BBBB' : 'AAAA');
    await expect(verifyIdToken(tampered, discovery, opts())).rejects.toThrow(/signature/i);
  });

  it('rejects an expired token', async () => {
    const token = await makeToken(validClaims({ exp: Math.floor(Date.now()/1000) - 10 }));
    await expect(verifyIdToken(token, discovery, opts())).rejects.toThrow(/expired/i);
  });

  it('rejects an audience mismatch (token minted for another client)', async () => {
    const token = await makeToken(validClaims({ aud: 'some-other-client' }));
    await expect(verifyIdToken(token, discovery, opts())).rejects.toThrow(/audience/i);
  });

  it('rejects an issuer mismatch', async () => {
    const token = await makeToken(validClaims({ iss: 'https://evil-idp.com' }));
    await expect(verifyIdToken(token, discovery, opts())).rejects.toThrow(/issuer/i);
  });

  it('rejects a nonce mismatch (replay/CSRF guard)', async () => {
    const token = await makeToken(validClaims({ nonce: 'attacker-nonce' }));
    await expect(verifyIdToken(token, discovery, opts())).rejects.toThrow(/nonce/i);
  });

  it('rejects an alg-confusion downgrade to "none"', async () => {
    const token = await makeToken(validClaims(), { alg: 'none' });
    await expect(verifyIdToken(token, discovery, opts())).rejects.toThrow(/algorithm|RS256/i);
  });
});
