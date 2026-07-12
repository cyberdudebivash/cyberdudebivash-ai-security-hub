/* Security fix (CodeQL, High severity, "Incomplete string escaping or encoding"
 * — flagged on the PR that introduced frontend/user-dashboard.html's API Keys
 * "Usage" button, workers/test/userDashboardApiKeysUsageClickFix.test.mjs).
 *
 * The new button built its onclick attribute as:
 *   onclick="viewKeyUsage('${k.id}', '${label.replace(/'/g, "\\'")}')"
 * This only escapes a literal ' — it does not escape a literal \ first. A key
 * name ending in a raw backslash (e.g. "evil\") neutralizes the escape: the
 * label's trailing \ combines with the escaper's own inserted \ and collapses
 * into a single \, which the browser's JS parser reads as an escaped quote —
 * terminating the string one character early and letting the rest of the
 * label run as trailing script inside the onclick handler.
 *
 * Found while auditing this same file for the fix: a pre-existing (not part
 * of this PR) organization-member "Remove" button had the identical flaw,
 * plus a worse one — its escaper (orgEsc) never escaped a literal " either,
 * so a member's full_name/email containing a `"` could break straight out of
 * the double-quoted onclick="..." attribute with no JS-string layer needed at
 * all. Both are fixed with one new helper, jsAttrEsc().
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../../frontend/user-dashboard.html', import.meta.url), 'utf8');

function fnBody(name) {
  const marker = `function ${name}(`;
  const start = html.indexOf(marker);
  expect(start, `${name} should be defined`).toBeGreaterThan(-1);
  const bodyStart = html.indexOf('{', start);
  let depth = 0, i = bodyStart;
  for (; i < html.length; i++) {
    if (html[i] === '{') depth++;
    else if (html[i] === '}') { depth--; if (depth === 0) break; }
  }
  return html.slice(start, i + 1);
}

// Re-implements jsAttrEsc()'s exact algorithm (HTML-escape &<>" via the same
// rules as mfaEsc, then \ -> \\, then ' -> \') so this test can prove the
// real fix neutralizes the exploit end-to-end, independent of a DOM/browser.
function mfaEsc(s) { return String(s).replace(/[&<>"]/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' }[c])); }
function jsAttrEsc(s) { return mfaEsc(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'"); }
// Simulates the browser's HTML-attribute-value decoding of exactly the 4
// entities mfaEsc ever produces — the first of the two real parse stages an
// onclick="...'${escaped}'..." attribute goes through.
function htmlDecodeMfaEntities(s) { return s.replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&'); }

describe('user-dashboard.html — incomplete onclick-attribute escaping (CodeQL High) fixed with a real jsAttrEsc() helper', () => {
  it('defines jsAttrEsc() escaping backslashes before quotes, on top of HTML-escaping', () => {
    expect(html.indexOf('function jsAttrEsc(')).toBeGreaterThan(-1);
    const body = fnBody('jsAttrEsc');
    expect(body).toContain('mfaEsc(s)');
    expect(body).toContain("replace(/\\\\/g, '\\\\\\\\')");
    expect(body).toContain('replace(/\'/g, "\\\\\'")');
  });

  it('the API Keys "Usage" button (this session\'s own new code) now escapes through jsAttrEsc(), not a bare quote-only replace', () => {
    const body = fnBody('renderKeys');
    expect(body).toContain('jsAttrEsc(k.name || k.key_prefix || k.id)');
    expect(body).not.toMatch(/\(k\.name[\s\S]{0,40}\)\.replace\(\/'\/g/);
  });

  it('the organization "Remove member" button (pre-existing code, found during this same fix) also now uses jsAttrEsc(), not the unescaped-quote orgEsc()', () => {
    const idx = html.indexOf('confirmRemoveMember(');
    expect(idx).toBeGreaterThan(-1);
    const context = html.slice(html.lastIndexOf('`', idx), html.indexOf('`', idx) + 1);
    expect(context).toContain('jsAttrEsc(m.full_name || m.email || m.user_id)');
    expect(context).not.toContain('orgEsc(m.full_name || m.email || m.user_id).replace');
  });

  it('the member-role <select>\'s aria-label uses mfaEsc (escapes ") instead of orgEsc (does not) for its attribute-context label', () => {
    const idx = html.indexOf('const memberLabel =');
    expect(idx).toBeGreaterThan(-1);
    const line = html.slice(idx, html.indexOf(';', idx) + 1);
    expect(line).toContain('mfaEsc(m.full_name || m.email || m.user_id)');
  });

  it('end-to-end: a label ending in a raw backslash no longer terminates the JS string early — the exact exploit CodeQL flagged', () => {
    const evilLabel = "evil\\";
    const escaped = jsAttrEsc(evilLabel);
    const postHtmlDecode = htmlDecodeMfaEntities(escaped); // stage 1: browser attribute decoding
    // eslint-disable-next-line no-new-func
    const reconstructed = new Function(`return '${postHtmlDecode}'`)(); // stage 2: real JS string-literal parse
    expect(reconstructed).toBe(evilLabel);
  });

  it('end-to-end: a label with embedded quotes and an injection attempt round-trips to exactly itself, breaking out of neither the attribute nor the string', () => {
    const evilLabel = 'x"><img src=x onerror=alert(1)>\'; alert(2); //';
    const escaped = jsAttrEsc(evilLabel);
    const postHtmlDecode = htmlDecodeMfaEntities(escaped);
    // eslint-disable-next-line no-new-func
    const reconstructed = new Function(`return '${postHtmlDecode}'`)();
    expect(reconstructed).toBe(evilLabel);
  });
});
