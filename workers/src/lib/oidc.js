/**
 * CYBERDUDEBIVASH AI Security Hub — Enterprise SSO (OIDC) v1.0
 *
 * Generic OpenID Connect relying-party implementation: works against any
 * standards-compliant IdP (Okta, Azure AD / Entra ID, Google Workspace,
 * OneLogin, Auth0, PingFederate, ...) without a per-vendor integration.
 *
 * Deliberately OIDC, not SAML 2.0: Cloudflare Workers has no mature XML-dsig
 * library, and a hand-rolled SAML signature verifier is a security liability,
 * not a feature. Every enterprise IdP that supports SAML also supports OIDC.
 *
 * Uses only Web Crypto API (RS256 JWT verification via importKey/verify) —
 * no external dependencies, fully edge-native, matches the existing
 * auth/jwt.js HS256 implementation's approach.
 */

const DISCOVERY_CACHE_TTL = 3600;  // 1 hour
const JWKS_CACHE_TTL      = 3600;  // 1 hour
const STATE_TTL            = 600;   // 10 minutes (PKCE state + verifier)

// ─── Base64URL helpers ─────────────────────────────────────────────────────
function b64url(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function b64urlDecode(str) {
  const pad = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = pad + '='.repeat((4 - (pad.length % 4)) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

// ─── PKCE (RFC 7636) — required for the authorization code flow ───────────
export async function generatePKCE() {
  const verifierBytes = new Uint8Array(32);
  crypto.getRandomValues(verifierBytes);
  const codeVerifier = b64url(verifierBytes);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
  const codeChallenge = b64url(digest);
  return { codeVerifier, codeChallenge };
}

export function generateState() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── OIDC discovery document (.well-known/openid-configuration) ───────────
export async function discoverOIDC(issuer, kv) {
  const normalizedIssuer = issuer.replace(/\/$/, '');
  const cacheKey = `oidc_discovery:${normalizedIssuer}`;

  if (kv) {
    const cached = await kv.get(cacheKey, 'json').catch(() => null);
    if (cached) return cached;
  }

  const resp = await fetch(`${normalizedIssuer}/.well-known/openid-configuration`, {
    signal: AbortSignal.timeout(8000),
  });
  if (!resp.ok) throw new Error(`OIDC discovery failed for ${normalizedIssuer}: HTTP ${resp.status}`);
  const doc = await resp.json();

  if (!doc.authorization_endpoint || !doc.token_endpoint || !doc.jwks_uri) {
    throw new Error('OIDC discovery document missing required endpoints');
  }

  if (kv) await kv.put(cacheKey, JSON.stringify(doc), { expirationTtl: DISCOVERY_CACHE_TTL }).catch(() => {});
  return doc;
}

// ─── JWKS fetch + cache ─────────────────────────────────────────────────────
async function getJWKS(jwksUri, kv) {
  const cacheKey = `oidc_jwks:${jwksUri}`;
  if (kv) {
    const cached = await kv.get(cacheKey, 'json').catch(() => null);
    if (cached) return cached;
  }
  const resp = await fetch(jwksUri, { signal: AbortSignal.timeout(8000) });
  if (!resp.ok) throw new Error(`JWKS fetch failed: HTTP ${resp.status}`);
  const jwks = await resp.json();
  if (kv) await kv.put(cacheKey, JSON.stringify(jwks), { expirationTtl: JWKS_CACHE_TTL }).catch(() => {});
  return jwks;
}

// ─── Build the IdP authorization redirect URL ──────────────────────────────
export function buildAuthUrl(discovery, { clientId, redirectUri, scope = 'openid email profile', state, codeChallenge }) {
  const params = new URLSearchParams({
    client_id:             clientId,
    redirect_uri:          redirectUri,
    response_type:         'code',
    scope,
    state,
    code_challenge:        codeChallenge,
    code_challenge_method: 'S256',
  });
  return `${discovery.authorization_endpoint}?${params.toString()}`;
}

// ─── Exchange authorization code for tokens (incl. id_token) ──────────────
export async function exchangeCode(discovery, { clientId, clientSecret, redirectUri, code, codeVerifier }) {
  const body = new URLSearchParams({
    grant_type:    'authorization_code',
    code,
    redirect_uri:  redirectUri,
    client_id:     clientId,
    code_verifier: codeVerifier,
  });
  // Confidential client: most enterprise IdPs require client_secret for token exchange.
  if (clientSecret) body.set('client_secret', clientSecret);

  const resp = await fetch(discovery.token_endpoint, {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
    signal:  AbortSignal.timeout(8000),
  });
  if (!resp.ok) {
    const txt = await resp.text().catch(() => '');
    throw new Error(`Token exchange failed: HTTP ${resp.status} ${txt.slice(0, 200)}`);
  }
  return resp.json(); // { access_token, id_token, refresh_token?, expires_in, token_type }
}

// ─── Verify an RS256 id_token against the IdP's published JWKS ────────────
// Validates: signature, issuer, audience, expiry, not-before, nonce (if provided).
export async function verifyIdToken(idToken, discovery, { clientId, kv, expectedNonce } = {}) {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Malformed id_token');
  const [headerB64, payloadB64, sigB64] = parts;

  const header  = JSON.parse(new TextDecoder().decode(b64urlDecode(headerB64)));
  const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(payloadB64)));

  if (header.alg !== 'RS256') {
    throw new Error(`Unsupported id_token algorithm: ${header.alg} (only RS256 is accepted)`);
  }

  const jwks = await getJWKS(discovery.jwks_uri, kv);
  const jwk = jwks.keys?.find(k => k.kid === header.kid && (k.use === 'sig' || !k.use));
  if (!jwk) throw new Error('No matching JWKS key for id_token kid');

  const key = await crypto.subtle.importKey(
    'jwk', jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['verify']
  );

  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5', key,
    b64urlDecode(sigB64),
    new TextEncoder().encode(`${headerB64}.${payloadB64}`)
  );
  if (!valid) throw new Error('id_token signature verification failed');

  const now = Math.floor(Date.now() / 1000);
  if (!payload.exp || payload.exp < now) throw new Error('id_token expired');
  if (payload.nbf && payload.nbf > now) throw new Error('id_token not yet valid');

  const issuerOk = payload.iss === discovery.issuer || payload.iss === discovery.issuer?.replace(/\/$/, '');
  if (!issuerOk) throw new Error(`id_token issuer mismatch: expected ${discovery.issuer}, got ${payload.iss}`);

  const audOk = Array.isArray(payload.aud) ? payload.aud.includes(clientId) : payload.aud === clientId;
  if (!audOk) throw new Error('id_token audience mismatch');

  if (expectedNonce && payload.nonce !== expectedNonce) throw new Error('id_token nonce mismatch');

  return payload; // { sub, email, email_verified, name, iss, aud, exp, iat, ... }
}
