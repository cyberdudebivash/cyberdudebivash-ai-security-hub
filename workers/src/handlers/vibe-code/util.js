/**
 * CYBERDUDEBIVASH — Vibe Code Scanner :: shared pure utilities
 * Imported by both engine.js and rules.js. Imports nothing from them, so no
 * circular dependency exists.
 */
'use strict';

export const LIMITS = Object.freeze({
  MAX_BYTES: 2_000_000,        // 2 MB hard cap on a single submission
  MAX_LINES: 60_000,
  MAX_FINDINGS: 500,           // stop reporting past this; report truncation
  MAX_LINE_SCAN_LEN: 4_000,    // ignore absurdly long minified lines per-rule
});

/** Shannon entropy in bits/char — distinguishes real secrets from short tokens. */
export function shannonEntropy(str) {
  if (!str) return 0;
  const freq = Object.create(null);
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let e = 0;
  const len = str.length;
  for (const k in freq) {
    const p = freq[k] / len;
    e -= p * Math.log2(p);
  }
  return e;
}

/**
 * Iterate regex matches over a scan view, yielding {match, offset, line}.
 * Skips matches that land on pathologically long (likely minified) lines.
 * view: 'mask' (strings/comments blanked) or 'raw' (original source).
 */
export function* matches(ctx, re, view = 'mask') {
  const hay = view === 'raw' ? ctx.raw : ctx.mask;
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(hay)) !== null) {
    const off = m.index;
    const line = ctx.lineOf(off);
    if ((ctx.rawLines[line - 1] || '').length <= LIMITS.MAX_LINE_SCAN_LEN) {
      yield { match: m, offset: off, line };
    }
    if (m.index === re.lastIndex) re.lastIndex++; // guard zero-width loops
  }
}

/**
 * True if any line within [line-radius, line+radius] (1-based) matches `re`.
 * Cheap proximity heuristic: "is there an auth check near this handler",
 * "is this query parameterized", etc.
 */
export function nearbyMatch(ctx, line, re, radius = 6) {
  const start = Math.max(0, line - 1 - radius);
  const end = Math.min(ctx.rawLines.length, line - 1 + radius + 1);
  for (let i = start; i < end; i++) {
    re.lastIndex = 0;
    if (re.test(ctx.rawLines[i] || '')) return true;
  }
  return false;
}

/** Convenience: raw line text by 1-based number. */
export function lineText(ctx, line) {
  return ctx.rawLines[line - 1] || '';
}
