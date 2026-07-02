// GUI↔backend auth contract guard for the customer self-service dashboard
// (frontend/user-dashboard.html), which is linked from the homepage page-card
// and footer.
//
// Regression: the dashboard loaded the current user via GET /api/auth/profile,
// which does NOT exist as a GET route (only GET /api/auth/me and
// PUT /api/auth/profile exist). Every load 404'd, tripping the dashboard's
// `if (!res.ok) doLogout()` guard — so a customer who signed in (or reloaded)
// was immediately kicked back to the login screen. The whole dashboard was
// unusable. Separately, "Save profile" PUT sent {name} while the backend only
// reads full_name, so profile edits silently no-op'd.
//
// This test asserts the served HTML uses the endpoints/fields the backend
// actually implements. Pure static parse — no browser/network.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DASH  = readFileSync(resolve(__dirname, '../../frontend/user-dashboard.html'), 'utf8');
const INDEX = readFileSync(resolve(__dirname, '../src/index.js'), 'utf8');
const AUTH  = readFileSync(resolve(__dirname, '../src/handlers/auth.js'), 'utf8');

describe('user-dashboard.html — auth load contract', () => {
  it('loads the current user from GET /api/auth/me (a route that exists)', () => {
    expect(DASH).toContain("apiFetch('/api/auth/me')");
  });

  it('never GETs /api/auth/profile (no such GET route → 404 → forced logout)', () => {
    // The only /api/auth/profile call left may be the PUT (save).
    const getProfile = /apiFetch\(\s*'\/api\/auth\/profile'\s*\)/.test(DASH);
    expect(getProfile).toBe(false);
  });

  it('backend really exposes GET /api/auth/me and PUT (not GET) /api/auth/profile', () => {
    expect(INDEX).toContain("path === '/api/auth/me' && method === 'GET'");
    expect(INDEX).toContain("path === '/api/auth/profile' && method === 'PUT'");
    // Guard against a GET /api/auth/profile route silently appearing and masking
    // the contract — if one is ever added, update this test deliberately.
    expect(INDEX).not.toContain("path === '/api/auth/profile' && method === 'GET'");
  });
});

describe('user-dashboard.html — profile save contract', () => {
  it('sends full_name (the field the PUT handler reads), not name', () => {
    // The save PUT must carry full_name.
    expect(DASH).toMatch(/method:\s*'PUT'[\s\S]{0,120}full_name/);
  });

  it('backend PUT /api/auth/profile reads full_name', () => {
    expect(AUTH).toContain('body?.full_name');
  });
});
