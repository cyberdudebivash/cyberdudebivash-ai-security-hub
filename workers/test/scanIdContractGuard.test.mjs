/* scan_id contract guard.
 *
 * Journey-3 defect: the domain scan returned scan_id only NESTED inside
 * scan_metadata, but the "run scan → generate report" UI (and API integrators)
 * read it at the TOP level — so a fresh scan's id was lost and report
 * generation for the just-run scan silently failed (had to round-trip through
 * /api/scan/history to recover it). Fix: expose scan_id at the top level of the
 * scan response, and have the UI read the nested field as a fallback.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const read = (p) => readFileSync(resolve(root, p), 'utf8');

describe('scan response exposes scan_id at the top level', () => {
  const domain = read('src/handlers/domain.js');
  it('buildRealResult and the cached path both return top-level scan_id', () => {
    // Two response objects — both must carry scan_id at the top level.
    const topLevel = domain.match(/scan_id:\s*scanId,/g) || [];
    expect(topLevel.length).toBeGreaterThanOrEqual(2);
  });
});

describe('UI recovers scan_id from either location', () => {
  const html = read('../frontend/index.html');
  it('_saveScanToHistory falls back to scan_metadata.scan_id', () => {
    expect(/data\.scan_id\s*\|\|\s*\(data\.scan_metadata\s*&&\s*data\.scan_metadata\.scan_id\)/.test(html)).toBe(true);
  });
});
