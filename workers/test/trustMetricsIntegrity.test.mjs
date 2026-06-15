// Trust/marketing integrity + MSSP table structural guard for frontend/index.html.
// Prevents (a) re-introducing fabricated "verified paying customers"/client counts,
// and (b) the MSSP comparison column regressing to missing cells (the 6-col header
// with 5-cell rows bug). Pure static parse — no browser/network.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const HTML = readFileSync(resolve(__dirname, '../../frontend/index.html'), 'utf8');

describe('homepage truthfulness (no fabricated social proof)', () => {
  it('does not claim verified paying customers / enterprise client counts', () => {
    expect(HTML).not.toContain('Verified paying customers');
    expect(HTML).not.toContain('Enterprise accounts');
  });

  it('removed the customer-count tile IDs', () => {
    expect(HTML).not.toContain('id="tm-teams"');
    expect(HTML).not.toContain('id="cdb-exec-clients"');
    expect(HTML).not.toContain('id="cdb-exec-api-reqs"');
  });

  it('replaced them with truthful capability metrics', () => {
    expect(HTML).toContain('Live Threat Feeds');
    expect(HTML).toContain('AI Security Engines');
    expect(HTML).toContain('Compliance Frameworks');
  });
});

describe('plan comparison table — MSSP column integrity', () => {
  // Isolate the comparison table: from the MSSP <th> to the next </table>.
  const msspTh = HTML.indexOf('>MSSP</th>');
  const tableEnd = HTML.indexOf('</table>', msspTh);
  const table = HTML.slice(msspTh, tableEnd);

  it('the comparison table exists with an MSSP header', () => {
    expect(msspTh).toBeGreaterThan(0);
    expect(tableEnd).toBeGreaterThan(msspTh);
  });

  it('every feature data row has 6 cells (no empty MSSP column)', () => {
    const rows = table.split('<tr').slice(1);
    const offenders = [];
    for (const r of rows) {
      if (r.includes('colspan')) continue;       // section header rows
      const tds = (r.match(/<td/g) || []).length;
      if (tds === 0) continue;                    // header <th> row
      if (tds !== 6) offenders.push(tds + ':' + (r.match(/>([^<]+)</)?.[1] || '').trim());
    }
    expect(offenders, `rows without 6 cells: ${offenders.join(' | ')}`).toEqual([]);
  });

  it('section header rows span all 6 columns', () => {
    const colspans = [...table.matchAll(/colspan="(\d+)"/g)].map(m => m[1]);
    expect(colspans.length).toBeGreaterThan(0);
    expect(colspans.every(c => c === '6'), `found colspans: ${colspans.join(',')}`).toBe(true);
  });
});
