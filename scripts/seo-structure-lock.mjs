#!/usr/bin/env node
// SEO structure lock — guards the discovery layer of the platform.
//
// Locks in place after the 2026-07-04 fix (OBJ-10): frontend/index.html shipped
// with a premature `</head></html>` at ~line 486, which pushed every Open Graph
// tag, Twitter Card tag, and all six JSON-LD blocks outside the <head> (and
// outside the document entirely). Search engines and link-preview crawlers
// read metadata from <head>; the result was no rich results and blank URL
// previews. This lock fails the build if any public page regresses.
//
// Run: node scripts/seo-structure-lock.mjs

import { readFileSync } from 'node:fs';

const PUBLIC_PAGES = [
  'index', 'about', 'contact', 'services', 'booking', 'academy', 'tools',
  'security-assessment', 'ai-security-assessment', 'ciso-hub', 'mcp-security',
  'agent-threats', 'ai-governance-frameworks', 'api-docs', 'attack-library',
  'gadgets', 'intel-hub', 'privacy-policy', 'refund-policy', 'sitemap',
  'terms-of-service', 'upgrade',
];

let failures = 0;
const fail = (msg) => { failures++; console.error(`  FAIL  ${msg}`); };
const pass = (msg) => console.log(`  ok    ${msg}`);

for (const page of PUBLIC_PAGES) {
  const path = `frontend/${page}.html`;
  let src;
  try { src = readFileSync(path, 'utf-8'); }
  catch { fail(`${page}: cannot read ${path}`); continue; }

  console.log(`\n${page}`);

  // ── Structural integrity ────────────────────────────────────────────────
  const headClose = src.indexOf('</head>');
  // Real <body> tag at start of line — comments mentioning "<body>" don't count.
  const bodyMatch = /^<body[ >]/m.exec(src);
  const bodyOpen = bodyMatch ? bodyMatch.index : -1;

  if ((src.match(/<\/head>/g) || []).length !== 1) fail(`${page}: expected exactly one </head>`);
  else if (bodyOpen !== -1 && headClose > bodyOpen) fail(`${page}: </head> appears after <body>`);
  else pass('single </head>, closed before <body>');

  const htmlCloses = (src.match(/<\/html>/g) || []).length;
  if (htmlCloses !== 1) fail(`${page}: expected exactly one </html>, found ${htmlCloses}`);
  else if (src.indexOf('</html>') < headClose) fail(`${page}: </html> appears before </head> (premature document close)`);
  else pass('document closes once, at the end');

  // ── Metadata present and inside <head> ──────────────────────────────────
  const inHead = (needle, label) => {
    const pos = src.indexOf(needle);
    if (pos === -1) fail(`${page}: missing ${label}`);
    else if (pos > headClose) fail(`${page}: ${label} is outside <head> (pos ${pos} > </head> ${headClose})`);
    else pass(`${label} inside <head>`);
  };
  inHead('property="og:title"', 'og:title');
  inHead('property="og:image"', 'og:image');
  inHead('name="twitter:card"', 'twitter:card');
  inHead('rel="canonical"', 'canonical');
  inHead('name="description"', 'meta description');

  // ── JSON-LD must be inside <head> and parse as JSON ─────────────────────
  const ldBlocks = [...src.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)];
  let ldOk = true;
  for (const [i, m] of ldBlocks.entries()) {
    if (m.index > headClose) { fail(`${page}: JSON-LD block ${i + 1} outside <head>`); ldOk = false; }
    try { JSON.parse(m[1]); }
    catch (e) { fail(`${page}: JSON-LD block ${i + 1} invalid JSON: ${e.message}`); ldOk = false; }
  }
  if (ldOk) pass(`${ldBlocks.length} JSON-LD block(s) valid, inside <head>`);
}

// ── Homepage-specific: the six required schemas ───────────────────────────
const home = readFileSync('frontend/index.html', 'utf-8');
for (const t of ['"Organization"', '"WebSite"', '"SoftwareApplication"', '"FAQPage"', '"BreadcrumbList"']) {
  if (!home.includes(`"@type": ${t}`) && !home.includes(`"@type":${t}`)) fail(`index: missing ${t} JSON-LD schema`);
}
if (!home.includes('contact@cyberdudebivash.in')) fail('index: Organization contact email missing');
if (!home.includes('"postalCode": "755019"')) fail('index: Organization postal address missing');

console.log(failures === 0
  ? `\nSEO STRUCTURE LOCK: ALL GREEN (${PUBLIC_PAGES.length} pages)`
  : `\nSEO STRUCTURE LOCK: ${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
