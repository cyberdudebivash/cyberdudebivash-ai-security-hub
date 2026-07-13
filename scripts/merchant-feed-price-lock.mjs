#!/usr/bin/env node
// Merchant Center feed price/drift lock.
//
// frontend/merchant-center-feed.xml hand-duplicates product name/price/
// description from 3 backend catalogs (globalScale.js, marketplaceCheckout-
// Handler.js, toolsMarketplace.js) because none of them are reachable at a
// bare (non-/api/*) URL Cloudflare's live Route config would actually route
// to the Worker — see the feed file's own header comment. Nothing enforces
// those numbers staying in sync, so this locks it: fails the build if any
// listed product's feed price drifts from its live backend price, if a
// listed product no longer exists in its backend catalog, or if a product
// already known to be price-conflicted across catalogs (and therefore
// deliberately excluded from the feed) reappears in it.
//
// Run: node scripts/merchant-feed-price-lock.mjs

import { readFileSync } from 'node:fs';

const FEED = readFileSync('frontend/merchant-center-feed.xml', 'utf-8');
const GLOBAL_SCALE  = readFileSync('workers/src/services/globalScale.js', 'utf-8');
const MARKETPLACE   = readFileSync('workers/src/handlers/marketplaceCheckoutHandler.js', 'utf-8');
const TOOLS         = readFileSync('workers/src/handlers/toolsMarketplace.js', 'utf-8');

let failures = 0;
const fail = (msg) => { failures++; console.error(`  FAIL  ${msg}`); };
const pass = (msg) => console.log(`  ok    ${msg}`);

// id -> how to find its live price. divisor converts the matched raw number
// to rupees (marketplaceCheckoutHandler stores paise; the other two store
// rupees directly).
const PRICE_SOURCES = {
  soc2:                       { src: GLOBAL_SCALE, re: /soc2:\s*\{[^}]*?price_inr:\s*(\d+)/,             divisor: 1 },
  gdpr:                       { src: GLOBAL_SCALE, re: /gdpr:\s*\{[^}]*?price_inr:\s*(\d+)/,              divisor: 1 },
  hipaa:                      { src: GLOBAL_SCALE, re: /hipaa:\s*\{[^}]*?price_inr:\s*(\d+)/,             divisor: 1 },
  pci_dss:                    { src: GLOBAL_SCALE, re: /pci_dss:\s*\{[^}]*?price_inr:\s*(\d+)/,           divisor: 1 },

  'dp-ransomware-2025':       { src: MARKETPLACE,  re: /'dp-ransomware-2025':\s*\{[^}]*?amount:\s*(\d+)/, divisor: 100 },
  'dp-apt-north-korea':       { src: MARKETPLACE,  re: /'dp-apt-north-korea':\s*\{[^}]*?amount:\s*(\d+)/, divisor: 100 },
  'dp-ai-threats-2025':       { src: MARKETPLACE,  re: /'dp-ai-threats-2025':\s*\{[^}]*?amount:\s*(\d+)/, divisor: 100 },
  'dp-cloud-misconfig':       { src: MARKETPLACE,  re: /'dp-cloud-misconfig':\s*\{[^}]*?amount:\s*(\d+)/, divisor: 100 },
  'pb-ai-governance':         { src: MARKETPLACE,  re: /'pb-ai-governance':\s*\{[^}]*?amount:\s*(\d+)/,   divisor: 100 },
  'ir-q2-2025-threat':        { src: MARKETPLACE,  re: /'ir-q2-2025-threat':\s*\{[^}]*?amount:\s*(\d+)/,  divisor: 100 },
  'ir-owasp-llm-2025':        { src: MARKETPLACE,  re: /'ir-owasp-llm-2025':\s*\{[^}]*?amount:\s*(\d+)/,  divisor: 100 },
  'aa-threat-hunter':         { src: MARKETPLACE,  re: /'aa-threat-hunter':\s*\{[^}]*?amount:\s*(\d+)/,   divisor: 100 },
  'aa-soc-copilot-7d':        { src: MARKETPLACE,  re: /'aa-soc-copilot-7d':\s*\{[^}]*?amount:\s*(\d+)/,  divisor: 100 },

  ai_security_toolkit:        { src: TOOLS, re: /ai_security_toolkit:\s*\{[^}]*?price_inr:\s*(\d+)/,        divisor: 1 },
  red_team_playbook:          { src: TOOLS, re: /red_team_playbook:\s*\{[^}]*?price_inr:\s*(\d+)/,          divisor: 1 },
  zero_trust_blueprint:       { src: TOOLS, re: /zero_trust_blueprint:\s*\{[^}]*?price_inr:\s*(\d+)/,       divisor: 1 },
  domain_security_checklist:  { src: TOOLS, re: /domain_security_checklist:\s*\{[^}]*?price_inr:\s*(\d+)/,  divisor: 1 },
  ai_governance_toolkit:      { src: TOOLS, re: /ai_governance_toolkit:\s*\{[^}]*?price_inr:\s*(\d+)/,      divisor: 1 },
  soc_analyst_runbook:        { src: TOOLS, re: /soc_analyst_runbook:\s*\{[^}]*?price_inr:\s*(\d+)/,        divisor: 1 },
};

// Products deliberately excluded from the feed because the same conceptual
// product is sold at a different price through another catalog — see the
// feed's own header comment for the full reasoning. If one of these ever
// shows up as a <g:id> in the feed, someone re-added a conflicted product
// without re-auditing the conflict — that's exactly the Merchant Center
// suspension risk this feed was built to avoid.
const KNOWN_CONFLICTED_IDS = [
  'iso27001', 'cp-iso27001-2022', 'compliance_starter_pack',
  'dpdp', 'dpdp_compliance_kit',
  'nist_csf', 'cp-nist-csf-2',
  'pb-ransomware-ir', 'ir_ransomware',
  'compliance', 'enterprise_security_bundle',
];

// ── Extract every <item>'s g:id / g:price from the feed ─────────────────────
const feedItems = [...FEED.matchAll(/<g:id>(.*?)<\/g:id>[\s\S]*?<g:price>([\d.]+) INR<\/g:price>/g)]
  .map(([, id, price]) => ({ id, price: Number(price) }));

if (feedItems.length === 0) fail('no <item> blocks parsed from merchant-center-feed.xml — regex or file broken');

for (const { id, price } of feedItems) {
  const source = PRICE_SOURCES[id];
  if (!source) {
    fail(`${id}: no price source registered in this lock script — add one before shipping, don't assume it's still correct`);
    continue;
  }
  const m = source.re.exec(source.src);
  if (!m) {
    fail(`${id}: not found in its backend catalog anymore — product may have been renamed/removed, feed is now selling something that doesn't exist`);
    continue;
  }
  const livePrice = Number(m[1]) / source.divisor;
  if (livePrice !== price) {
    fail(`${id}: feed price ₹${price} != live backend price ₹${livePrice} — update merchant-center-feed.xml`);
    continue;
  }
  pass(`${id}: ₹${price} matches live backend`);
}

for (const id of KNOWN_CONFLICTED_IDS) {
  if (feedItems.some(i => i.id === id)) {
    fail(`${id}: reappeared in the feed — this product's price still conflicts with another catalog per the feed's header comment; re-audit before re-adding`);
  }
}

console.log(failures === 0
  ? `\nMERCHANT FEED PRICE LOCK: ALL GREEN (${feedItems.length} items)`
  : `\nMERCHANT FEED PRICE LOCK: ${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
