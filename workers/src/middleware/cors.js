/**
 * CORS middleware — allows cyberdudebivash.in origins + localhost dev
 */
const ALLOWED_ORIGINS = [
  'https://cyberdudebivash.in',
  'https://www.cyberdudebivash.in',
  'https://cyberdudebivash.pages.dev',
  'https://security.cyberdudebivash.in',
  'http://localhost:3000',
  'http://localhost:8080',
  'http://127.0.0.1:5500',
];

export function corsHeaders(request) {
  const origin = request?.headers?.get('Origin') || '';
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin':  allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key, X-Session-Token',
    'Access-Control-Max-Age':       '86400',
    'Access-Control-Allow-Credentials': 'true',
  };
}

export function withCors(response, request) {
  const headers = new Headers(response.headers);
  const ch = corsHeaders(request);
  Object.entries(ch).forEach(([k, v]) => headers.set(k, v));
  return new Response(response.body, { status: response.status, headers });
}
