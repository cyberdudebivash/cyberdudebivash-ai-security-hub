#!/usr/bin/env node
// Fetches this platform's own live public CVE feed and converts it into a
// NewsArticle JSON-LD graph at frontend/seo-intel.json. Deliberately reuses
// the feed this Worker already serves (GET /api/feed.json — see
// workers/src/handlers/, already allow-listed for crawlers in
// frontend/robots.txt) instead of standing up a second, duplicate feed
// source. `frontend/` is deployed to Cloudflare Pages verbatim
// (`wrangler pages deploy frontend`, see .github/workflows/deploy.yml) —
// no build step — so anything written here is directly web-accessible at
// https://cyberdudebivash.in/seo-intel.json once committed and deployed.
//
// NewsArticle chosen over SpecialAnnouncement: schema.org's
// SpecialAnnouncement type was purpose-built for official COVID-19
// announcements — reusing it for general CVE alerts stretches its
// documented intent. NewsArticle fits threat bulletins cleanly.
//
// Zero runtime dependencies — Node 22 has native fetch; nothing else needed.

import { writeFile, rename, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const FEED_URL = 'https://cyberdudebivash.in/api/feed.json';
const FETCH_TIMEOUT_MS = 15_000;
const MAX_ARTICLES = 25;
const OUTPUT_PATH = join(
  dirname(dirname(dirname(fileURLToPath(import.meta.url)))),
  'frontend',
  'seo-intel.json',
);

const PUBLISHER = {
  '@type': 'Organization',
  '@id': 'https://cyberdudebivash.in/#organization',
  name: 'CYBERDUDEBIVASH PRIVATE LIMITED',
  logo: {
    '@type': 'ImageObject',
    url: 'https://cyberdudebivash.in/og-image-v3.png',
  },
};

/** @throws on network failure, non-2xx status, or malformed JSON — never swallows. */
async function fetchLatestFeed(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { accept: 'application/json', 'user-agent': 'cyberdudebivash-seo-feed/1.0' },
    });
    if (!res.ok) {
      throw new Error(`${url} returned HTTP ${res.status}`);
    }
    const body = await res.json();
    if (!Array.isArray(body?.items)) {
      throw new Error(`${url} response missing an "items" array — feed shape may have changed`);
    }
    return body;
  } finally {
    clearTimeout(timeout);
  }
}

function severityToUrgency(severity) {
  const s = String(severity ?? '').toUpperCase();
  if (s === 'CRITICAL' || s === 'HIGH') return 'High';
  if (s === 'MEDIUM') return 'Moderate';
  return 'Low';
}

/** One real feed item -> one schema.org NewsArticle node. Nothing invented:
 * fields absent from the source item are simply omitted from the output. */
function itemToNewsArticle(item) {
  const headline = typeof item.title === 'string' && item.title.trim().length > 0
    ? item.title.trim()
    : `Threat advisory ${item.id ?? item.cve ?? ''}`.trim();

  const node = {
    '@type': 'NewsArticle',
    headline: headline.slice(0, 110), // Google's practical headline length guidance
    url: `https://cyberdudebivash.in/cve/${encodeURIComponent(item.cve ?? item.id ?? '')}`,
    publisher: PUBLISHER,
    articleSection: 'Threat Intelligence',
    isAccessibleForFree: true,
  };
  if (item.summary) node.description = String(item.summary).slice(0, 500);
  if (item.published_at) {
    node.datePublished = item.published_at;
    node.dateModified = item.published_at;
  }
  if (item.severity) node.keywords = item.severity;
  if (typeof item.cvss === 'number') {
    node.about = { '@type': 'Thing', name: 'CVSS score', additionalProperty: { '@type': 'PropertyValue', name: 'cvss', value: item.cvss } };
  }
  if (item.severity) node.urgency = severityToUrgency(item.severity); // non-standard extra signal, harmless if ignored
  return node;
}

function buildFeedDocument(feed) {
  const items = feed.items.slice(0, MAX_ARTICLES).map(itemToNewsArticle);
  return {
    '@context': 'https://schema.org',
    '@type': 'ItemList',
    '@id': 'https://cyberdudebivash.in/seo-intel.json#feed',
    name: 'CYBERDUDEBIVASH AI Security Hub — Live CVE Threat Feed',
    description: 'Auto-generated NewsArticle structured-data feed of the latest CVE threat intelligence, sourced from this platform\'s own public feed.',
    numberOfItems: items.length,
    dateModified: new Date().toISOString(),
    itemListElement: items.map((node, i) => ({
      '@type': 'ListItem',
      position: i + 1,
      item: node,
    })),
    _generatedBy: 'scripts/seo/generate-seo-feed.mjs',
    _sourceFeed: FEED_URL,
    _sourceGeneratedAt: feed.generated_at ?? null,
    _sourceItemCount: feed.count ?? feed.items.length,
  };
}

async function writeAtomic(path, contents) {
  await mkdir(dirname(path), { recursive: true });
  const tmpPath = `${path}.tmp-${process.pid}`;
  await writeFile(tmpPath, contents, 'utf8');
  await rename(tmpPath, path); // atomic on the same filesystem — no reader ever sees a partial file
}

async function main() {
  const feed = await fetchLatestFeed(FEED_URL);
  const document = buildFeedDocument(feed);
  await writeAtomic(OUTPUT_PATH, `${JSON.stringify(document, null, 2)}\n`);
  console.log(`generate-seo-feed: wrote ${document.numberOfItems} articles to ${OUTPUT_PATH}`);
}

main().catch((err) => {
  console.error('generate-seo-feed: failed —', err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
