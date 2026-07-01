// TOTP (RFC 6238) — lib/totp.js
// Tests use the actual Web Crypto implementation (same primitive as production).
import { describe, it, expect } from 'vitest';
import {
  generateSecret, generateTOTP, verifyTOTP,
  buildOtpauthUrl, generateBackupCodes, hashBackupCode, verifyBackupCode,
} from '../src/lib/totp.js';

describe('generateSecret', () => {
  it('produces a non-empty base32 string', () => {
    const s = generateSecret();
    expect(s).toMatch(/^[A-Z2-7]+$/);
    expect(s.length).toBeGreaterThan(10);
  });

  it('produces a different secret on every call (no static secret)', () => {
    expect(generateSecret()).not.toBe(generateSecret());
  });
});

describe('generateTOTP + verifyTOTP', () => {
  it('verifies the TOTP code it just generated against the same secret', async () => {
    const secret = generateSecret();
    const code   = await generateTOTP(secret);
    expect(code).toMatch(/^\d{6}$/);
    expect(await verifyTOTP(secret, code)).toBe(true);
  });

  it('rejects a code with the wrong secret', async () => {
    const s1 = generateSecret();
    const s2 = generateSecret();
    const code = await generateTOTP(s1);
    expect(await verifyTOTP(s2, code)).toBe(false);
  });

  it('rejects a mutated code (single digit off)', async () => {
    const secret = generateSecret();
    const code   = await generateTOTP(secret);
    const bad    = String((parseInt(code, 10) + 1) % 1000000).padStart(6, '0');
    if (bad !== code) expect(await verifyTOTP(secret, bad)).toBe(false);
  });

  it('rejects a non-numeric token immediately (no HMAC call)', async () => {
    const secret = generateSecret();
    expect(await verifyTOTP(secret, 'abcdef')).toBe(false);
    expect(await verifyTOTP(secret, '12345')).toBe(false);  // 5 digits
    expect(await verifyTOTP(secret, '1234567')).toBe(false); // 7 digits
  });

  it('accepts a code one step in the past (±30s clock skew tolerance)', async () => {
    const secret = generateSecret();
    const now    = Date.now();
    const pastCode = await generateTOTP(secret, { now: now - 30_000 });
    expect(await verifyTOTP(secret, pastCode)).toBe(true);
  });

  it('accepts a code one step in the future (pre-generated code)', async () => {
    const secret = generateSecret();
    const now    = Date.now();
    const futureCode = await generateTOTP(secret, { now: now + 30_000 });
    expect(await verifyTOTP(secret, futureCode)).toBe(true);
  });

  it('rejects a code two time steps in the past (outside clock skew window)', async () => {
    const secret = generateSecret();
    const now    = Date.now();
    const staleCode = await generateTOTP(secret, { now: now - 90_000 });
    // stale code might accidentally match current — only assert if it's genuinely different
    const current = await generateTOTP(secret, { now });
    if (staleCode !== current) {
      expect(await verifyTOTP(secret, staleCode)).toBe(false);
    }
  });

  it('two calls with identical time produce identical codes (deterministic)', async () => {
    const secret = generateSecret();
    const t = Date.now();
    expect(await generateTOTP(secret, { now: t })).toBe(await generateTOTP(secret, { now: t }));
  });
});

describe('buildOtpauthUrl', () => {
  it('produces an otpauth://totp/ URL containing the secret and email', () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const url    = buildOtpauthUrl(secret, 'ciso@fortune500.example.com');
    expect(url).toMatch(/^otpauth:\/\/totp\//);
    expect(url).toContain(`secret=${secret}`);
    expect(url).toContain('ciso%40fortune500.example.com');
    expect(url).toContain('algorithm=SHA1');
    expect(url).toContain('digits=6');
    expect(url).toContain('period=30');
  });
});

describe('backup codes', () => {
  it('generates the right count and format', () => {
    const codes = generateBackupCodes(8);
    expect(codes).toHaveLength(8);
    for (const c of codes) expect(c).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}$/);
  });

  it('generates unique codes', () => {
    const codes = generateBackupCodes(8);
    expect(new Set(codes).size).toBe(8);
  });

  it('verifies a correct backup code against its hash', async () => {
    const codes  = generateBackupCodes(8);
    const hashes = await Promise.all(codes.map(hashBackupCode));
    for (const c of codes) {
      expect(await verifyBackupCode(c, hashes)).toBe(true);
    }
  });

  it('rejects a code not in the hash list', async () => {
    const codes  = generateBackupCodes(8);
    const hashes = await Promise.all(codes.map(hashBackupCode));
    const other  = generateBackupCodes(1)[0];
    expect(await verifyBackupCode(other, hashes)).toBe(false);
  });

  it('is case-insensitive and hyphen-tolerant on input', async () => {
    const codes  = generateBackupCodes(1);
    const hashes = await Promise.all(codes.map(hashBackupCode));
    const lower  = codes[0].toLowerCase();
    const noDash = codes[0].replace('-', '');
    expect(await verifyBackupCode(lower, hashes)).toBe(true);
    expect(await verifyBackupCode(noDash, hashes)).toBe(true);
  });

  it('hashing is deterministic (same code → same hash)', async () => {
    const code = generateBackupCodes(1)[0];
    expect(await hashBackupCode(code)).toBe(await hashBackupCode(code));
  });
});
