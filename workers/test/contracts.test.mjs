// Phase 3 — Enterprise Engineering Platform Standardization Program.
// lib/contracts.js is the new canonical severity/status/timestamp module —
// these tests lock in its behavior, and specifically the real-world drift
// cases (operational/active/ONLINE all meaning "ok") Phase 2's audit found.
import { describe, it, expect } from 'vitest';
import {
  SEVERITY, SEVERITY_ORDER, SEVERITY_WEIGHT, normalizeSeverity, isValidSeverity,
  STATUS, normalizeStatus, isValidStatus,
  nowISO, withTimestamp,
} from '../src/lib/contracts.js';

describe('SEVERITY', () => {
  it('exposes the 5 canonical uppercase values', () => {
    expect(Object.values(SEVERITY)).toEqual(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
  });

  it('normalizeSeverity is case-insensitive', () => {
    expect(normalizeSeverity('critical')).toBe('CRITICAL');
    expect(normalizeSeverity('Critical')).toBe('CRITICAL');
    expect(normalizeSeverity('CRITICAL')).toBe('CRITICAL');
  });

  it('normalizeSeverity returns null for unrecognized input, never a guess', () => {
    expect(normalizeSeverity('urgent')).toBeNull();
    expect(normalizeSeverity('')).toBeNull();
    expect(normalizeSeverity(null)).toBeNull();
    expect(normalizeSeverity(undefined)).toBeNull();
    expect(normalizeSeverity(42)).toBeNull();
  });

  it('isValidSeverity matches normalizeSeverity', () => {
    expect(isValidSeverity('high')).toBe(true);
    expect(isValidSeverity('urgent')).toBe(false);
  });

  it('SEVERITY_WEIGHT orders CRITICAL highest, INFO lowest', () => {
    for (let i = 0; i < SEVERITY_ORDER.length - 1; i++) {
      expect(SEVERITY_WEIGHT[SEVERITY_ORDER[i]]).toBeGreaterThan(SEVERITY_WEIGHT[SEVERITY_ORDER[i + 1]]);
    }
  });
});

describe('STATUS', () => {
  it('is anchored to the real /api/health values, not an invented vocabulary', () => {
    expect(Object.values(STATUS)).toEqual(['ok', 'degraded', 'error', 'stale']);
  });

  it('normalizeStatus maps every real-world drift case found in Phase 2 to "ok"', () => {
    // These exact aliases were found live in the codebase this engagement —
    // frontend/dashboard-live.js checked for 'operational', /api/health only
    // ever returned 'ok'. This test exists so that specific bug class can
    // never silently reappear under a different alias.
    for (const alias of ['operational', 'active', 'ACTIVE', 'healthy', 'online', 'up', 'running', 'enabled', 'available']) {
      expect(normalizeStatus(alias), `"${alias}" should normalize to ok`).toBe('ok');
    }
  });

  it('normalizeStatus maps degraded/error/stale aliases correctly', () => {
    expect(normalizeStatus('warning')).toBe('degraded');
    expect(normalizeStatus('down')).toBe('error');
    expect(normalizeStatus('offline')).toBe('error');
    expect(normalizeStatus('cached')).toBe('stale');
  });

  it('normalizeStatus is case-insensitive on both canonical and alias forms', () => {
    expect(normalizeStatus('OK')).toBe('ok');
    expect(normalizeStatus('Operational')).toBe('ok');
  });

  it('normalizeStatus returns null for unrecognized input, never a guess', () => {
    expect(normalizeStatus('purple')).toBeNull();
    expect(isValidStatus('purple')).toBe(false);
  });
});

describe('Timestamps', () => {
  it('nowISO returns a real ISO-8601 UTC string', () => {
    const ts = nowISO();
    expect(ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(new Date(ts).toISOString()).toBe(ts);
  });

  it('withTimestamp adds a timestamp without clobbering existing fields', () => {
    const result = withTimestamp({ foo: 'bar' });
    expect(result.foo).toBe('bar');
    expect(typeof result.timestamp).toBe('string');
  });

  it('withTimestamp does not override a caller-supplied timestamp field ordering issue', () => {
    // Caller-supplied fields spread after `timestamp` win, matching the
    // documented "don't clobber one the caller already set" contract.
    const result = withTimestamp({ timestamp: 'custom-value' });
    expect(result.timestamp).toBe('custom-value');
  });
});
