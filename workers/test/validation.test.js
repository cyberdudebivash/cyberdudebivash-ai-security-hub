// Input-validation contract for all scan endpoints (security: untrusted input).
import { describe, it, expect } from 'vitest';
import { validateDomain, validateString, validateEnum } from '../src/middleware/validation.js';

describe('validateDomain', () => {
  it('accepts a valid domain and normalises it', () => {
    const r = validateDomain('Example.COM');
    expect(r.valid).toBe(true);
    expect(r.value).toBe('example.com');
  });

  it('strips protocol and path', () => {
    expect(validateDomain('https://example.com/path?q=1').value).toBe('example.com');
  });

  it('rejects non-string / empty input', () => {
    expect(validateDomain(undefined).valid).toBe(false);
    expect(validateDomain('').valid).toBe(false);
    expect(validateDomain(123).valid).toBe(false);
  });

  it('rejects too-short and too-long domains', () => {
    expect(validateDomain('a.b').valid).toBe(false);            // < 4 chars
    const long = 'a'.repeat(250) + '.com';
    expect(validateDomain(long).valid).toBe(false);            // > 253 chars
  });

  it('rejects malformed domains', () => {
    for (const bad of ['not a domain', 'http://', 'example', '-bad.com', 'foo..com']) {
      expect(validateDomain(bad).valid, bad).toBe(false);
    }
  });
});

describe('validateString', () => {
  it('enforces min/max length', () => {
    expect(validateString('hi', 'name', 3).valid).toBe(false);
    expect(validateString('hello', 'name', 1, 4).valid).toBe(false);
    expect(validateString('  ok  ', 'name', 1, 10)).toEqual({ valid: true, value: 'ok' });
  });

  it('requires a string', () => {
    expect(validateString(null, 'name').valid).toBe(false);
  });
});

describe('validateEnum', () => {
  const allowed = ['iso27001', 'soc2', 'gdpr'];
  it('returns the value when allowed (case-insensitive)', () => {
    expect(validateEnum('SOC2', 'framework', allowed, 'iso27001').value).toBe('soc2');
  });
  it('falls back to default for unknown / missing values', () => {
    expect(validateEnum('bogus', 'framework', allowed, 'iso27001').value).toBe('iso27001');
    expect(validateEnum(undefined, 'framework', allowed, 'gdpr').value).toBe('gdpr');
  });
});
