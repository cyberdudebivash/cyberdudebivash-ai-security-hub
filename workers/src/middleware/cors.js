/**
 * CORS middleware — P0 FIX v14.0
 * Production origins only. Localhost origins are injected ONLY when
 * ENVIRONMENT !== 'production', preventing dev origins leaking to prod.
 */

const PROD_ORIGINS = [
  'https://cyberdudebivash.in',
  'https://www.cyberdudebivash.in',
  'https://cyberdudebivash.pages.dev',
  'https://security.cyberdudebivash.in',
  'https://tools.cyberdudebivash.com',
  'https://intel.cyberdudebivash.com',
];

const DEV_ORIGINS = [
  'http://localhost:3000',
  'http://localhost:8080',
  'http://localhost:5173',
  'http://127.0.0.1:5500',
  'http://127.0.0.1:3000',
];

/**
 * Build the allowed-origin list based on runtime environment.
 * @param {object} env - Cloudflare Worker env bindings
 * @returns {string[]}
 */
function getAllowedOrigins(env) {
  const isProd = (env?.ENVIRONMENT || 'production') === 'production';
  return isProd ? PROD_ORIGINS : [...PROD_ORIGINS, ...DEV_ORIGINS];
}

/**
 * Return CORS response headers for a given request.
 * Unknown origins receive the primary production domain as ACAO,
 * which browsers will reject — this is the correct secure behaviour.
 * @param {Request} request
 * @param {object}  env
 */
export function corsHeaders(request, env) {
  const origin  = request?.headers?.get('Origin') || '';
  const allowed = getAllowedOrigins(env);
  const allowedOrigin = allowed.includes(origin) ? origin : PROD_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin':      allowedOrigin,
    'Access-Control-Allow-Methods':     'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers':     'Content-Type, Authorization, X-API-Key, X-Session-Token, X-Request-ID',
    'Access-Control-Expose-Headers':    'X-Request-ID, X-RateLimit-Remaining, X-RateLimit-Reset',
    'Access-Control-Max-Age':           '86400',
    'Access-Control-Allow-Credentials': 'true',
  };
}

/**
 * Wrap a Response with CORS headers.
 * @param {Response} response
 * @param {Request}  request
 * @param {object}   env
 */
export function withCors(response, request, env) {
  const headers = new Headers(response.headers);
  const ch = corsHeaders(request, env);
  Object.entries(ch).forEach(([k, v]) => headers.set(k, v));
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
