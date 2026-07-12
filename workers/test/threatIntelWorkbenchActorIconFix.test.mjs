/* P3 (Tier-3, cosmetic/minor class) — every APT actor card on
 * threat-intel-workbench.html's "APT Actor Profiles" panel (grid + detail
 * modal) rendered a raw keyword string ("bear", "dragon", "typhoon", …)
 * crammed into a 36px icon box, instead of an emoji glyph.
 *
 * ROOT CAUSE: workers/src/services/aptActorProfiles.js's `icon` field is a
 * semantic keyword, not a display-ready glyph. Every one of the 15 actors
 * in APT_ACTORS has this field set to a non-empty string, so the frontend's
 * `${a.icon || '🎭'}` fallback never actually triggered for any real actor —
 * it always rendered the literal keyword text instead.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { APT_ACTORS } from '../src/services/aptActorProfiles.js';

const html = readFileSync(new URL('../../frontend/threat-intel-workbench.html', import.meta.url), 'utf8');

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

describe('threat-intel-workbench.html — APT actor icons rendered raw keyword text instead of an emoji (static parse + real data)', () => {
  it('defines an actorIconEmoji() keyword→glyph translator', () => {
    const start = html.indexOf('function actorIconEmoji(');
    expect(start).toBeGreaterThan(-1);
  });

  it('every real actor in APT_ACTORS has its icon keyword mapped — no orphan keyword falls through to the generic 🎭 fallback', () => {
    const mapMatch = html.match(/const ACTOR_ICON_EMOJI = \{([\s\S]*?)\};/);
    expect(mapMatch, 'ACTOR_ICON_EMOJI map should exist').not.toBeNull();
    const mappedKeywords = [...mapMatch[1].matchAll(/(\w+):\s*'/g)].map(m => m[1]);

    const actorIcons = Object.values(APT_ACTORS).map(a => a.icon).filter(Boolean);
    expect(actorIcons.length).toBeGreaterThan(0); // sanity: the real dataset does set icon on actors

    const orphans = actorIcons.filter(kw => !mappedKeywords.includes(kw));
    expect(orphans).toEqual([]);
  });

  it('the actor grid card renders through actorIconEmoji(), not the raw keyword-or-mask fallback', () => {
    const body = fnBody('renderActorGrid');
    expect(body).toContain('actorIconEmoji(a)');
    expect(body).not.toMatch(/a\.icon\s*\|\|\s*'🎭'/);
  });

  it('the actor detail modal renders through actorIconEmoji() too, not just the grid card', () => {
    const body = fnBody('showActorDetail');
    expect(body).toContain('actorIconEmoji(a)');
    expect(body).not.toMatch(/a\.icon\s*\|\|\s*'🎭'/);
  });

  it('an unrecognized/missing icon keyword still degrades to the generic mask emoji rather than printing raw text', () => {
    expect(html).toContain("return ACTOR_ICON_EMOJI[a.icon] || '🎭';");
  });
});
