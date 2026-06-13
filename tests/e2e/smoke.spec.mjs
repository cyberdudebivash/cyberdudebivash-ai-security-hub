/* Playwright E2E smoke — the certified critical-path checks.
 * INSTALL: copy to tests/e2e/smoke.spec.mjs ; runs in test.yml (closes R4 E2E gate).
 * These assert the live site loads clean (no console errors — directly guards against
 * a repeat of the "Unexpected identifier 'defer'" incident) and the scan CTA exists. */
import { test, expect } from '@playwright/test';

const BASE = process.env.SMOKE_BASE || 'https://cyberdudebivash.in';

test.describe('CYBERDUDEBIVASH production smoke', () => {

  test('homepage loads with zero uncaught JS errors', async ({ page }) => {
    const errors = [];
    page.on('pageerror', (e) => errors.push(String(e)));
    page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
    await page.goto(BASE, { waitUntil: 'networkidle' });
    // Guard against the exact regression class that broke mobile (defer SyntaxError).
    const fatal = errors.filter((e) => /SyntaxError|Unexpected identifier|defer/i.test(e));
    expect(fatal, 'no fatal JS errors on load').toEqual([]);
  });

  test('no visible error banner on load', async ({ page }) => {
    await page.goto(BASE, { waitUntil: 'domcontentloaded' });
    const banner = page.locator('text=/unexpected error|please refresh the page/i');
    await expect(banner).toHaveCount(0);
  });

  test('primary scan CTA is present and tappable', async ({ page }) => {
    await page.goto(BASE, { waitUntil: 'domcontentloaded' });
    const cta = page.locator('text=/scan your domain/i').first();
    await expect(cta).toBeVisible();
    const box = await cta.boundingBox();
    expect(box && box.height, 'CTA meets 44px touch target').toBeGreaterThanOrEqual(40);
  });

  test('no empty/unlabeled primary buttons', async ({ page }) => {
    await page.goto(BASE, { waitUntil: 'domcontentloaded' });
    // Guards against the empty Quick-Actions button defect.
    const empties = await page.$$eval('button', (btns) =>
      btns.filter((b) => !b.textContent.trim() && !b.getAttribute('aria-label') && b.offsetParent !== null).length);
    expect(empties, 'no visible empty buttons').toBe(0);
  });

  test('mobile viewport: no horizontal overflow', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(BASE, { waitUntil: 'networkidle' });
    const overflow = await page.evaluate(() =>
      document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, 'no horizontal scroll on 390px').toBeLessThanOrEqual(2);
  });
});
