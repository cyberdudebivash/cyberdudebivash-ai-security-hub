/**
 * CYBERDUDEBIVASH MYTHOS — Validation Engine v1.0
 * ═══════════════════════════════════════════════
 * Validates all generated security artifacts.
 * Runs safety gates, syntax checks, quality scoring.
 * Returns structured errors + fix hints for self-correction loop.
 */

// ── Safety gate: patterns that must NEVER appear in generated artifacts ───────
const DANGEROUS_PATTERNS = [
  { re: /rm\s+-rf\s+\/(?!\w)/i,           msg: 'Destructive rm -rf /' },
  { re: /:\(\)\{.*\|.*&\}/,               msg: 'Fork bomb pattern' },
  { re: /mkfs\./i,                         msg: 'Filesystem format command' },
  { re: /dd\s+if=.*of=\/dev\//i,           msg: 'Disk wipe via dd' },
  { re: />\s*\/dev\/sd[a-z]/i,             msg: 'Direct disk overwrite' },
  { re: /base64\s+.*\|\s*(bash|sh)/i,      msg: 'base64-decode pipe to shell' },
  { re: /eval\s*\(\s*(atob|Buffer\.from)/i,msg: 'eval encoded payload' },
  { re: /chmod\s+[0-7]*7[0-7]*\s+\//i,    msg: 'chmod world-writable on root' },
];

// ── YARA syntax validator ─────────────────────────────────────────────────────
function validateYARA(content) {
  const errors = [], warnings = [];
  if (!content || content.trim().length < 60) { errors.push('Content empty or too short'); return { valid: false, errors, warnings }; }
  if (!/rule\s+\w+\s*\{/.test(content))        errors.push('Missing rule declaration: rule NAME { }');
  if (!/condition\s*:/i.test(content))          errors.push('Missing condition: block');
  const opens  = (content.match(/\{/g) || []).length;
  const closes = (content.match(/\}/g) || []).length;
  if (opens !== closes) errors.push(`Brace mismatch: ${opens} open vs ${closes} close`);
  if (!/strings\s*:/i.test(content) && !/condition\s*:\s*\n?\s*(true|false)/i.test(content))
    warnings.push('No strings: block — consider adding IOC patterns');
  return { valid: errors.length === 0, errors, warnings };
}

// ── Sigma YAML validator ──────────────────────────────────────────────────────
function validateSigma(content) {
  const errors = [], warnings = [];
  if (!content || content.trim().length < 80) { errors.push('Content empty or too short'); return { valid: false, errors, warnings }; }
  const required = ['title:', 'status:', 'logsource:', 'detection:', 'condition:'];
  required.forEach(f => { if (!content.includes(f)) errors.push(`Missing required Sigma field: ${f}`); });
  if (!/status:\s*(stable|test|experimental|deprecated)/i.test(content))
    warnings.push('status should be one of: stable | test | experimental | deprecated');
  if (content.split('\n').some(l => /\t/.test(l) && l.trim()))
    errors.push('Tab characters found — Sigma requires spaces only for indentation');
  return { valid: errors.length === 0, errors, warnings };
}

// ── Python validator ──────────────────────────────────────────────────────────
function validatePython(content) {
  const errors = [], warnings = [];
  if (!content || content.trim().length < 120) { errors.push('Script too short'); return { valid: false, errors, warnings }; }
  const opens  = (content.match(/\(/g) || []).length;
  const closes = (content.match(/\)/g) || []).length;
  if (Math.abs(opens - closes) > 4) errors.push(`Parenthesis mismatch: ${opens} open vs ${closes} close`);
  if (!content.includes('import ')) warnings.push('No import statements found');
  if (!content.includes('if __name__') && !content.includes('def main'))
    warnings.push('No entry point (if __name__ == "__main__") found');
  return { valid: errors.length === 0, errors, warnings };
}

// ── Bash validator ────────────────────────────────────────────────────────────
function validateBash(content) {
  const errors = [], warnings = [];
  if (!content || content.trim().length < 60) { errors.push('Script too short'); return { valid: false, errors, warnings }; }
  if (!content.startsWith('#!/bin/bash') && !content.startsWith('#!/usr/bin/env bash'))
    warnings.push('Missing bash shebang (#!/bin/bash)');
  if (!content.includes('set -e') && !content.includes('set -o errexit'))
    warnings.push('Missing "set -e" — script will not exit on errors');
  return { valid: errors.length === 0, errors, warnings };
}

// ── General content validator ─────────────────────────────────────────────────
function validateGeneral(content, type) {
  const errors = [], warnings = [];
  const MIN = { exec_briefing: 500, ir_playbook: 400, api_module: 200, threat_hunt_pack: 300 };
  const min = MIN[type] || 100;
  if (!content || content.trim().length < min)
    errors.push(`Content too short: ${(content || '').trim().length} chars (min ${min})`);
  const placeholders = (content || '').match(/\[PLACEHOLDER\]|\[TODO\]|\[INSERT\]|\[REPLACE ME\]|\bTBD\b/gi) || [];
  if (placeholders.length) errors.push(`${placeholders.length} unreplaced placeholder(s) found`);
  return { valid: errors.length === 0, errors, warnings };
}

// ── Safety gate ───────────────────────────────────────────────────────────────
function checkSafety(content) {
  const violations = [];
  for (const { re, msg } of DANGEROUS_PATTERNS) {
    if (re.test(content)) violations.push(msg);
  }
  return { safe: violations.length === 0, violations };
}

// ── Quality score 0–100 ───────────────────────────────────────────────────────
function computeScore(content, errors, warnings) {
  let score = 100;
  score -= errors.length   * 20;
  score -= warnings.length *  5;
  if ((content || '').length > 2000) score = Math.min(100, score + 5);
  if ((content || '').length > 5000) score = Math.min(100, score + 5);
  return Math.max(0, score);
}

// ── Fix hints for self-correction ─────────────────────────────────────────────
function buildHints(type, errors) {
  const hints = [];
  if (errors.some(e => /rule declaration/i.test(e)))   hints.push('Add YARA rule block: rule NAME { strings: { } condition: any of them }');
  if (errors.some(e => /condition/i.test(e)))           hints.push('Add condition: block to YARA rule');
  if (errors.some(e => /brace/i.test(e)))               hints.push('Fix brace mismatch — every { needs a matching }');
  if (errors.some(e => /sigma field/i.test(e)))         hints.push('Add missing Sigma fields: title, status, logsource, detection, condition');
  if (errors.some(e => /tab/i.test(e)))                 hints.push('Replace all tabs with 2-space indentation');
  if (errors.some(e => /short/i.test(e)))               hints.push('Expand content — implement complete functional artifact');
  if (errors.some(e => /placeholder/i.test(e)))         hints.push('Replace all [PLACEHOLDER], TBD markers with real values');
  if (errors.some(e => /parenthesis/i.test(e)))         hints.push('Fix parenthesis mismatch in Python code');
  return hints;
}

// ── MASTER validate function (exported) ──────────────────────────────────────
export function validateArtifact(content, type) {
  if (!content) return { valid: false, safe: false, errors: ['Empty content'], warnings: [], hints: ['Generate non-empty content'], type, score: 0 };
  const safety = checkSafety(content);
  let typeResult;
  switch (type) {
    case 'yara_rule':                         typeResult = validateYARA(content);    break;
    case 'sigma_rule':                        typeResult = validateSigma(content);   break;
    case 'python_scanner':
    case 'python_detection':                  typeResult = validatePython(content);  break;
    case 'hardening_script':
    case 'firewall_script':                   typeResult = validateBash(content);    break;
    default:                                  typeResult = validateGeneral(content, type); break;
  }
  const allErrors = [...typeResult.errors, ...(safety.safe ? [] : safety.violations)];
  return {
    valid:    allErrors.length === 0,
    safe:     safety.safe,
    errors:   allErrors,
    warnings: typeResult.warnings,
    hints:    buildHints(type, allErrors),
    type,
    length:   content.length,
    score:    computeScore(content, allErrors, typeResult.warnings),
  };
}

// ── Self-correction helper ────────────────────────────────────────────────────
export function buildCorrectionRequest(content, validation, intel) {
  return {
    needs_correction:  !validation.valid || !validation.safe,
    original_length:   content?.length || 0,
    errors:            validation.errors,
    warnings:          validation.warnings,
    hints:             validation.hints,
    correction_prompt: validation.errors.length
      ? `Fix these issues in the ${validation.type} artifact for ${intel?.id || 'CVE'}:\n${validation.errors.join('\n')}\nHints:\n${validation.hints.join('\n')}`
      : null,
  };
}
