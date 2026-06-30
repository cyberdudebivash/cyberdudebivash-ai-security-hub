/* Enterprise SSO (OIDC) — lib/oidc.js
 * The security-critical surface is id_token verification: signature, issuer,
 * audience, expiry, nonce. These tests use a real RS256 keypair (via Web
 * Crypto, same primitive the production code uses) and assert that
 * verifyIdToken accepts only a token that is genuinely signed by the
 * "IdP" key and rejects every tampered variant. */
import { describe, it, expect, beforeAll } from 'vitest';
import {
  generatePKCE, generateState, discoverOIDC, buildAuthUrl,
  exchangeCode, verifyIdToken,
} from '../src/lib/oidc.js';

function b64url(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function encodeJSON(obj) { return b64url(new TextEncoder().encode(JSON.stringify(obj))); }

function makeKV() {
  const store = new Map();
  return {
    async get(k, type) {
      const v = store.get(k);
      if (v === undefined) return null;
      return type === 'json' ? JSON.parse(v) : v;
    },
    async put(k, v) { store.set(k, v); },
  };
}

describe('PKCE + state generation', () => {
  it('generates a code_verifier and an S256 code_challenge that are not equal', async () => {
    const { codeVerifier, codeChallenge } = await generatePKCE();
    expect(codeVerifier.length).toBeGreaterThan(20);
    expect(codeChallenge.length).toBeGreaterThan(20);
    expect(codeVerifier).not.toBe(codeChallenge);
  });

  it('generates a fresh value every call (no static/predictable state)', async () => {
    const a = await generatePKCE();
    const b = await generatePKCE();
    expect(a.codeVerifier).not.toBe(b.codeVerifier);
    expect(generateState()).not.toBe(generateState());
  });
});

describe('discoverOIDC', () => {
  const issuer = 'https://idp.example.com';
  const doc = {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
  };

  it('fetches and caches the discovery document', async () => {
    let fetchCount = 0;
    globalThis.fetch = async (url) => {
      fetchCount++;
      expect(url).toBe(`${issuer}/.well-known/openid-configuration`);
      return new Response(JSON.stringify(doc), { status: 200 });
    };
    const kv = makeKV();
    const d1 = await discoverOIDC(issuer, kv);
    const d2 = await discoverOIDC(issuer, kv); // should hit cache, not fetch again
    expect(d1.token_endpoint).toBe(doc.token_endpoint);
    expect(d2.token_endpoint).toBe(doc.token_endpoint);
    expect(fetchCount).toBe(1);
  });

  it('throws if the discovery document is missing required endpoints', async () => {
    globalThis.fetch = async () => new Response(JSON.stringify({ issuer }), { status: 200 });
    await expect(discoverOIDC(issuer, makeKV())).rejects.toThrow(/required endpoints/);
  });

  it('throws on a non-200 discovery response', async () => {
    globalThis.fetch = async () => new Response('not found', { status: 404 });
    await expect(discoverOIDC(issuer, makeKV())).rejects.toThrow(/discovery failed/);
  });
});

describe('buildAuthUrl', () => {
  it('includes PKCE challenge and state in the authorization URL', () => {
    const discovery = { authorization_endpoint: 'https://idp.example.com/authorize' };
    const url = buildAuthUrl(discovery, {
      clientId: 'client123', redirectUri: 'https://app.example.com/cb',
      state: 'state123', codeChallenge: 'challenge123',
    });
    const parsed = new URL(url);
    expect(parsed.searchParams.get('client_id')).toBe('client123');
    expect(parsed.searchParams.get('code_challenge')).toBe('challenge123');
    expect(parsed.searchParams.get('code_challenge_method')).toBe('S256');
    expect(parsed.searchParams.get('response_type')).toBe('code');
  });
});

describe('exchangeCode', () => {
  it('POSTs the authorization code + PKCE verifier to the token endpoint', async () => {
    let capturedBody;
    globalThis.fetch = async (url, opts) => {
      capturedBody = new URLSearchParams(opts.body);
      return new Response(JSON.stringify({ access_token: 'at', id_token: 'it' }), { status: 200 });
    };
    const discovery = { token_endpoint: 'https://idp.example.com/token' };
    const result = await exchangeCode(discovery, {
      clientId: 'cid', clientSecret: 'secret', redirectUri: 'https://app/cb',
      code: 'authcode', codeVerifier: 'verifier123',
    });
    expect(result.id_token).toBe('it');
    expect(capturedBody.get('code')).toBe('authcode');
    expect(capturedBody.get('code_verifier')).toBe('verifier123');
    expect(capturedBody.get('client_secret')).toBe('secret');
    expect(capturedBody.get('grant_type')).toBe('authorization_code');
  });

  it('throws with the IdP error body on a failed exchange', async () => {
    globalThis.fetch = async () => new Response('invalid_grant', { status: 400 });
    const discovery = { token_endpoint: 'https://idp.example.com/token' };
    await expect(exchangeCode(discovery, {
      clientId: 'cid', redirectUri: 'https://app/cb', code: 'bad', codeVerifier: 'v',
    })).rejects.toThrow(/Token exchange failed/);
  });
});

describe('verifyIdToken — RS256 signature + claims validation', () => {
  const issuer = 'https://idp.example.com';
  const clientId = 'enterprise-client-id';
  let privateKey, publicJwk, kid;

  beforeAll(async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true, ['sign', 'verify']
    );
    privateKey = keyPair.privateKey;
    publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    kid = 'test-key-1';
    publicJwk.kid = kid;
    publicJwk.use = 'sig';
    publicJwk.alg = 'RS256';
  });

  function discoveryFor(jwksUri) {
    return { issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: jwksUri };
  }

  async function signToken(payload, { alg = 'RS256', signingKey = privateKey, headerKid = kid } = {}) {
    const header = encodeJSON({ alg, typ: 'JWT', kid: headerKid });
    const body   = encodeJSON(payload);
    const signingInput = `${header}.${body}`;
    const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', signingKey, new TextEncoder().encode(signingInput));
    return `${signingInput}.${b64url(sig)}`;
  }

  function mockJWKSFetch() {
    globalThis.fetch = async (url) => {
      if (url === 'https://idp.example.com/jwks') {
        return new Response(JSON.stringify({ keys: [publicJwk] }), { status: 200 });
      }
      return new Response('not found', { status: 404 });
    };
  }

  it('accepts a genuinely-signed, well-formed id_token', async () => {
    mockJWKSFetch();
    const now = Math.floor(Date.now() / 1000);
    const token = await signToken({
      iss: issuer, aud: clientId, sub: 'user-123', email: 'ciso@fortune500.example.com',
      email_verified: true, name: 'Test User', nonce: 'expected-nonce',
      iat: now, exp: now + 300,
    });
    const claims = await verifyIdToken(token, discoveryFor('https://idp.example.com/jwks'), {
      clientId, kv: makeKV(), expectedNonce: 'expected-nonce',
    });
    expect(claims.email).toBe('ciso@fortune500.example.com');
    expect(claims.sub).toBe('user-123');
  });

  it('rejects a token with a tampered payload (signature no longer matches)', async () => {
    mockJWKSFetch();
    const now = Math.floor(Date.now() / 1000);
    const token = await signToken({ iss: issuer, aud: clientId, sub: 'victim', email: 'victim@corp.com', iat: now, exp: now + 300 });
    const [h, , s] = token.split('.');
    const forgedPayload = encodeJSON({ iss: issuer, aud: clientId, sub: 'attacker', email: 'attacker@evil.com', iat: now, exp: now + 300 });
    const forged = `${h}.${forgedPayload}.${s}`;
    await expect(verifyIdToken(forged, discoveryFor('https://idp.example.com/jwks'), { clientId, kv: makeKV() }))
      .rejects.toThrow(/signature verification failed/);
  });

  it('rejects a token signed with an unrelated key (not in the IdP JWKS)', async () => {
    mockJWKSFetch();
    const otherKeyPair = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true, ['sign', 'verify']
    );
    const now = Math.floor(Date.now() / 1000);
    const token = await signToken(
      { iss: issuer, aud: clientId, sub: 'user-123', email: 'x@corp.com', iat: now, exp: now + 300 },
      { signingKey: otherKeyPair.privateKey, headerKid: kid } // claims to be `kid` but isn't signed by it
    );
    await expect(verifyIdToken(token, discoveryFor('https://idp.example.com/jwks'), { clientId, kv: makeKV() }))
      .rejects.toThrow(/signature verification failed/);
  });

  it('rejects alg:none / non-RS256 tokens outright (no algorithm confusion)', async () => {
    mockJWKSFetch();
    const now = Math.floor(Date.now() / 1000);
    const header = encodeJSON({ alg: 'none', typ: 'JWT', kid });
    const body = encodeJSON({ iss: issuer, aud: clientId, sub: 'x', email: 'x@corp.com', iat: now, exp: now + 300 });
    const token = `${header}.${body}.`;
    await expect(verifyIdToken(token, discoveryFor('https://idp.example.com/jwks'), { clientId, kv: makeKV() }))
      .rejects.toThrow(/Unsupported id_token algorithm/);
  });

  it('rejects an expired token', async () => {
    mockJWKSFetch();
    const now = Math.floor(Date.now() / 1000);
    const token = await signToken({ iss: issuer, aud: clientId, sub: 'x', email: 'x@corp.com', iat: now - 600, exp: now - 300 });
    await expect(verifyIdToken(token, discoveryFor('https://idp.example.com/jwks'), { clientId, kv: makeKV() }))
      .rejects.toThrow(/expired/);
  });

  it('rejects a token with the wrong audience (issued for a different client)', async () => {
    mockJWKSFetch();
    const now = Math.floor(Date.now() / 1000);
    const token = await signToken({ iss: issuer, aud: 'someone-elses-client-id', sub: 'x', email: 'x@corp.com', iat: now, exp: now + 300 });
    await expect(verifyIdToken(token, discoveryFor('https://idp.example.com/jwks'), { clientId, kv: makeKV() }))
      .rejects.toThrow(/audience mismatch/);
  });

  it('rejects a token from an unexpected issuer', async () => {
    mockJWKSFetch();
    const now = Math.floor(Date.now() / 1000);
    const token = await signToken({ iss: 'https://attacker-controlled-idp.example.com', aud: clientId, sub: 'x', email: 'x@corp.com', iat: now, exp: now + 300 });
    await expect(verifyIdToken(token, discoveryFor('https://idp.example.com/jwks'), { clientId, kv: makeKV() }))
      .rejects.toThrow(/issuer mismatch/);
  });

  it('rejects a token with a nonce that does not match the login request (replay protection)', async () => {
    mockJWKSFetch();
    const now = Math.floor(Date.now() / 1000);
    const token = await signToken({ iss: issuer, aud: clientId, sub: 'x', email: 'x@corp.com', nonce: 'wrong-nonce', iat: now, exp: now + 300 });
    await expect(verifyIdToken(token, discoveryFor('https://idp.example.com/jwks'), { clientId, kv: makeKV(), expectedNonce: 'expected-nonce' }))
      .rejects.toThrow(/nonce mismatch/);
  });

  it('rejects a token whose kid does not match any JWKS key', async () => {
    mockJWKSFetch();
    const now = Math.floor(Date.now() / 1000);
    const token = await signToken(
      { iss: issuer, aud: clientId, sub: 'x', email: 'x@corp.com', iat: now, exp: now + 300 },
      { headerKid: 'unknown-key-id' }
    );
    await expect(verifyIdToken(token, discoveryFor('https://idp.example.com/jwks'), { clientId, kv: makeKV() }))
      .rejects.toThrow(/No matching JWKS key/);
  });
});
