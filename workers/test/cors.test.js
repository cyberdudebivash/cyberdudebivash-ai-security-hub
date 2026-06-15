// CORS allowlist contract (security: prevents dev origins leaking to prod and
// prevents arbitrary cross-origin credentialed access).
import { describe, it, expect } from 'vitest';
import { corsHeaders } from '../src/middleware/cors.js';

function reqWithOrigin(origin) {
  return new Request('https://api.cyberdudebivash.in/x', {
    headers: origin ? { Origin: origin } : {},
  });
}

describe('corsHeaders', () => {
  it('echoes a known production origin', () => {
    const h = corsHeaders(reqWithOrigin('https://cyberdudebivash.in'), { ENVIRONMENT: 'production' });
    expect(h['Access-Control-Allow-Origin']).toBe('https://cyberdudebivash.in');
  });

  it('falls back to the primary prod domain for unknown origins (browser will reject)', () => {
    const h = corsHeaders(reqWithOrigin('https://evil.example.com'), { ENVIRONMENT: 'production' });
    expect(h['Access-Control-Allow-Origin']).toBe('https://cyberdudebivash.in');
    expect(h['Access-Control-Allow-Origin']).not.toBe('https://evil.example.com');
    expect(h['Access-Control-Allow-Origin']).not.toBe('*');
  });

  it('does NOT allow localhost origins in production', () => {
    const h = corsHeaders(reqWithOrigin('http://localhost:3000'), { ENVIRONMENT: 'production' });
    expect(h['Access-Control-Allow-Origin']).not.toBe('http://localhost:3000');
  });

  it('DOES allow localhost origins outside production', () => {
    const h = corsHeaders(reqWithOrigin('http://localhost:3000'), { ENVIRONMENT: 'development' });
    expect(h['Access-Control-Allow-Origin']).toBe('http://localhost:3000');
  });

  it('defaults to production behaviour when ENVIRONMENT is unset', () => {
    const h = corsHeaders(reqWithOrigin('http://localhost:3000'), {});
    expect(h['Access-Control-Allow-Origin']).not.toBe('http://localhost:3000');
  });

  it('always sets the standard CORS method/credential headers', () => {
    const h = corsHeaders(reqWithOrigin('https://cyberdudebivash.in'), {});
    expect(h['Access-Control-Allow-Methods']).toContain('POST');
    expect(h['Access-Control-Allow-Credentials']).toBe('true');
  });
});
