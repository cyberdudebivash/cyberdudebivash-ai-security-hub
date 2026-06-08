/**
 * CYBERDUDEBIVASH — Vibe Code Security Scanner :: Detection Engine
 * ---------------------------------------------------------------
 * A fast, context-aware heuristic scanner for security flaws that AI coding
 * assistants (Cursor, Copilot, Claude Code, ChatGPT, v0, etc.) commonly emit.
 *
 * What makes this production-grade and not a regex grep:
 *   1. Context masking  — string literals & comments are masked before
 *      structural rules run, so a SQL-looking string in a comment or a log
 *      message does not produce a false injection finding.
 *   2. Confidence model — every finding carries HIGH/MEDIUM/LOW confidence so
 *      consumers can tune signal-to-noise.
 *   3. Dedup + caps     — findings deduplicated per (rule,line); input size and
 *      finding count are bounded so a huge/hostile paste can't exhaust a Worker.
 *   4. Framework mapping — CWE + OWASP (Web) + OWASP LLM Top 10 on every rule.
 *   5. AI-specific rules — insecure-output-handling, prompt injection, and
 *      "agent executes model output" RCE chains that generic SAST does not model.
 *
 * Pure ECMAScript. No Node built-ins. Runs unmodified on Cloudflare Workers.
 */
'use strict';

import { LIMITS } from './util.js';
import { RULES } from './rules.js';

const SEVERITY_WEIGHT = { CRITICAL: 10, HIGH: 6, MEDIUM: 3, LOW: 1, INFO: 0 };
const CONFIDENCE_MULT = { HIGH: 1.0, MEDIUM: 0.65, LOW: 0.35 };

// ----------------------------------------------------------------------------
// Language inference
// ----------------------------------------------------------------------------
export function inferLanguage(code, hint) {
  if (hint) {
    const h = String(hint).toLowerCase();
    if (/\b(ts|typescript|tsx)\b/.test(h)) return 'typescript';
    if (/\b(js|javascript|jsx|node|react)\b/.test(h)) return 'javascript';
    if (/\b(py|python)\b/.test(h)) return 'python';
    if (/\b(go|golang)\b/.test(h)) return 'go';
  }
  const py = (code.match(/^\s*(def |import |from \w+ import|class \w+\s*[:(]|if __name__)/gm) || []).length;
  const js = (code.match(/\b(const|let|var|function|=>|require\(|export )\b/g) || []).length;
  const go = (code.match(/(\bfunc\s|\bpackage\s|:=|\bimport\s*\()/g) || []).length;
  if (py >= js && py >= go && py > 0) return 'python';
  if (go > js && go > 0) return 'go';
  return 'javascript';
}

// ----------------------------------------------------------------------------
// Masking: copy of source with string/comment *contents* replaced by spaces
// (newlines preserved) so offsets/line numbers stay identical.
// ----------------------------------------------------------------------------
function buildMask(code, lang) {
  const out = code.split('');
  const n = code.length;
  let i = 0;
  const isPy = lang === 'python';
  const blank = (s, e) => { for (let k = s; k < e && k < n; k++) { const c = out[k]; if (c !== '\n' && c !== '\r') out[k] = ' '; } };

  while (i < n) {
    const c = code[i], c2 = code[i + 1];
    if (!isPy && c === '/' && c2 === '/') { let j = i + 2; while (j < n && code[j] !== '\n') j++; blank(i, j); i = j; continue; }
    if (isPy && c === '#') { let j = i + 1; while (j < n && code[j] !== '\n') j++; blank(i, j); i = j; continue; }
    if (!isPy && c === '/' && c2 === '*') { let j = i + 2; while (j < n && !(code[j] === '*' && code[j + 1] === '/')) j++; j += 2; blank(i, j); i = j; continue; }
    if (isPy && (code.startsWith('"""', i) || code.startsWith("'''", i))) {
      const q = code.substr(i, 3); let j = i + 3; while (j < n && !code.startsWith(q, j)) j++; j += 3; blank(i + 3, j - 3); i = j; continue;
    }
    if (c === '"' || c === "'") {
      const quote = c; let j = i + 1;
      while (j < n) {
        if (code[j] === '\\') { j += 2; continue; }
        if (code[j] === quote) { j++; break; }
        if (code[j] === '\n') { j++; break; }
        j++;
      }
      blank(i + 1, j - 1);
      i = j; continue;
    }
    // JS template literal: blank literal text but KEEP ${...} expressions intact
    // (the interpolated expression is real, potentially-tainted code).
    if (!isPy && c === '`') {
      i++; // keep opening backtick
      while (i < n) {
        if (code[i] === '\\') { i += 2; continue; }
        if (code[i] === '`') { i++; break; }
        if (code[i] === '$' && code[i + 1] === '{') {
          i += 2; let depth = 1;
          while (i < n && depth > 0) {
            if (code[i] === '{') depth++;
            else if (code[i] === '}') depth--;
            i++;
          }
          continue; // expression left intact
        }
        if (code[i] !== '\n' && code[i] !== '\r') out[i] = ' ';
        i++;
      }
      continue;
    }
    i++;
  }
  return out.join('');
}

function buildLineIndex(code) {
  const starts = [0];
  for (let i = 0; i < code.length; i++) if (code[i] === '\n') starts.push(i + 1);
  return starts;
}
function lineFromOffset(lineStarts, offset) {
  let lo = 0, hi = lineStarts.length - 1, ans = 0;
  while (lo <= hi) { const mid = (lo + hi) >> 1; if (lineStarts[mid] <= offset) { ans = mid; lo = mid + 1; } else hi = mid - 1; }
  return ans + 1;
}
function snippetAt(rawLines, line) {
  const t = (rawLines[line - 1] || '').trim();
  return t.length > 200 ? t.slice(0, 197) + '...' : t;
}

function makeContext(code, lang) {
  const lineStarts = buildLineIndex(code);
  const rawLines = code.split('\n');
  const mask = buildMask(code, lang);
  return {
    lang,
    raw: code,
    mask,
    rawLines,
    maskLines: mask.split('\n'),
    lineStarts,
    lineOf: (off) => lineFromOffset(lineStarts, off),
    snippet: (line) => snippetAt(rawLines, line),
  };
}

// ----------------------------------------------------------------------------
// Risk score / grade — weighted by severity and confidence, with diminishing
// returns so a file with 50 lows doesn't outscore one with a single critical.
// ----------------------------------------------------------------------------
export function scoreFindings(findings) {
  let raw = 0;
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
    raw += SEVERITY_WEIGHT[f.severity] * CONFIDENCE_MULT[f.confidence];
  }
  const risk = Math.min(100, Math.round(100 * (1 - Math.exp(-raw / 22))));
  let grade;
  if (counts.CRITICAL > 0 || risk >= 80) grade = 'F';
  else if (risk >= 60) grade = 'D';
  else if (risk >= 40) grade = 'C';
  else if (risk >= 20) grade = 'B';
  else if (risk > 0) grade = 'A';
  else grade = 'A+';
  return { risk_score: risk, grade, severity_counts: counts };
}

// ----------------------------------------------------------------------------
// MAIN ENTRY
// ----------------------------------------------------------------------------
export function scanVibeCode(code, opts = {}) {
  const started = Date.now();
  if (typeof code !== 'string') return { ok: false, error: 'INVALID_INPUT', message: 'code must be a string' };

  const inputTruncated = code.length > LIMITS.MAX_BYTES;
  if (inputTruncated) code = code.slice(0, LIMITS.MAX_BYTES);

  const lang = inferLanguage(code, opts.language);
  const ctx = makeContext(code, lang);
  const totalLines = ctx.rawLines.length;

  const findings = [];
  const seen = new Set();
  let findingsTruncated = false, rulesErrored = 0;

  for (const rule of RULES) {
    if (rule.langs && !rule.langs.includes('*') && !rule.langs.includes(lang)) continue;
    let produced;
    try { produced = rule.detect(ctx) || []; }
    catch (e) { rulesErrored++; continue; } // one bad rule never sinks the scan
    for (const f of produced) {
      const key = f.rule_id + '|' + f.line;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(f);
      if (findings.length >= LIMITS.MAX_FINDINGS) { findingsTruncated = true; break; }
    }
    if (findingsTruncated) break;
  }

  const sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const confRank = { HIGH: 3, MEDIUM: 2, LOW: 1 };
  findings.sort((a, b) =>
    (sevRank[b.severity] - sevRank[a.severity]) ||
    (confRank[b.confidence] - confRank[a.confidence]) ||
    (a.line - b.line));

  const score = scoreFindings(findings);

  return {
    ok: true,
    engine: 'cdb-vibe-scanner',
    engine_version: '2.0.0',
    scanned_at: new Date().toISOString(),
    language: lang,
    stats: {
      lines_scanned: totalLines,
      bytes_scanned: code.length,
      rules_evaluated: RULES.length,
      rules_errored: rulesErrored,
      duration_ms: Date.now() - started,
      input_truncated: inputTruncated,
      findings_truncated: findingsTruncated,
    },
    ...score,
    total_findings: findings.length,
    findings,
  };
}
