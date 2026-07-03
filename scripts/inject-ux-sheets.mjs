// Idempotently inject the three zero-regression shared stylesheets into every
// frontend/*.html, immediately before </head>. Skips any sheet already linked.
// Purely additive: no existing markup is altered or removed.
import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const DIR = path.resolve(process.cwd(), 'frontend');
const SHEETS = [
  '/assets/cdb-ui-polish.css',
  '/assets/cdb-mobile-responsive.css',
  '/assets/cdb-ux-upgrade.css',
];
const MARKER_BEGIN = '<!-- CDB UX layer (auto-injected, zero-regression) -->';

const files = (await readdir(DIR)).filter(f => f.endsWith('.html'));
let changed = 0, skipped = 0;
const report = [];

for (const f of files) {
  const fp = path.join(DIR, f);
  let html = await readFile(fp, 'utf8');

  // FIRST </head> is the document head. (Some pages contain a second </head>
  // inside a JS template literal that builds a print/popup document — never
  // target that one.)
  const closeIdx = html.indexOf('</head>');
  if (closeIdx === -1) { report.push(`SKIP (no </head>): ${f}`); skipped++; continue; }

  // Only add sheets not already present (idempotent + respects existing links).
  const toAdd = SHEETS.filter(s => !html.includes(s));
  if (toAdd.length === 0) { skipped++; continue; }

  const links = toAdd.map(s => `  <link rel="stylesheet" href="${s}">`).join('\n');
  const block = `${MARKER_BEGIN}\n${links}\n`;
  html = html.slice(0, closeIdx) + block + html.slice(closeIdx);

  // Safety: structure must be unchanged except for the insertion.
  const heads = (html.match(/<\/head>/g) || []).length;
  if (heads !== ((await readFile(fp, 'utf8')).match(/<\/head>/g) || []).length) {
    report.push(`ABORT (head count changed): ${f}`); continue;
  }

  await writeFile(fp, html);
  report.push(`+${toAdd.length} sheet(s): ${f}`);
  changed++;
}

console.log(report.join('\n'));
console.log(`\n── ${changed} files updated, ${skipped} already complete, ${files.length} total ──`);
