/**
 * CYBERDUDEBIVASH AI Security Hub — APT Intelligence Engine v1.0
 *
 * Replaces the previously-hardcoded APT group list (APT29, Lazarus, Fancy
 * Bear — invented, unattributed) with attribution derived from two real,
 * independently verifiable sources:
 *
 *   1. CISA Cybersecurity Advisories (https://www.cisa.gov/cybersecurity-advisories/all.xml)
 *      — official US government advisories. Many explicitly name the actor
 *      in the title/summary (e.g. "AA24-038A: PRC State-Sponsored Actors...
 *      Volt Typhoon"). Fetched live, cached 1h.
 *
 *   2. Correlation against this platform's own `threat_intel` table (D1) —
 *      CVE title/description text is scanned for an actor name or known
 *      alias; a match is written back to the row's `apt_groups` column so
 *      it persists and compounds over time.
 *
 * KNOWN_THREAT_ACTORS is a static reference table of publicly documented
 * group names/aliases (MITRE ATT&CK / CISA naming conventions). It is NOT
 * claimed activity — it is only used to recognize a real actor name when
 * one appears in real CISA/NVD text. No group is ever reported as "active"
 * without a live, cited piece of evidence (a specific advisory URL or CVE).
 *
 * If nothing correlates, the platform reports an empty list — this is the
 * honest, correct behavior demanded by the IBM audit; the difference from
 * before is that it now *can* be non-empty when real evidence exists.
 */

// ─── Reference table: publicly documented threat actor names/aliases ────────
// Source: MITRE ATT&CK Groups (attack.mitre.org/groups) + CISA advisory
// naming conventions. Canonical name is what we report; aliases are only
// used for text matching against live advisory/CVE content.
export const KNOWN_THREAT_ACTORS = [
  { canonical: 'APT28',           aliases: ['apt28', 'fancy bear', 'sofacy', 'sednit', 'strontium', 'forest blizzard'] },
  { canonical: 'APT29',           aliases: ['apt29', 'cozy bear', 'midnight blizzard', 'nobelium', 'the dukes'] },
  { canonical: 'APT41',           aliases: ['apt41', 'double dragon', 'barium', 'winnti group'] },
  { canonical: 'Lazarus Group',   aliases: ['lazarus', 'hidden cobra', 'zinc', 'diamond sleet', 'guardians of peace'] },
  { canonical: 'Volt Typhoon',    aliases: ['volt typhoon', 'bronze silhouette', 'vanguard panda'] },
  { canonical: 'Salt Typhoon',    aliases: ['salt typhoon'] },
  { canonical: 'Sandworm',        aliases: ['sandworm', 'voodoo bear', 'iridium', 'seashell blizzard'] },
  { canonical: 'Scattered Spider',aliases: ['scattered spider', 'unc3944', 'muddled libra', 'octo tempest'] },
  { canonical: 'APT35',           aliases: ['apt35', 'charming kitten', 'phosphorus', 'mint sandstorm'] },
  { canonical: 'APT34',           aliases: ['apt34', 'oilrig', 'helix kitten'] },
  { canonical: 'MuddyWater',      aliases: ['muddywater', 'mercury', 'static kitten'] },
  { canonical: 'Kimsuky',         aliases: ['kimsuky', 'velvet chollima', 'emerald sleet'] },
  { canonical: 'Turla',           aliases: ['turla', 'snake', 'uroburos', 'secret blizzard'] },
  { canonical: 'FIN7',            aliases: ['fin7', 'carbon spider', 'sangria tempest'] },
  { canonical: 'FIN11',           aliases: ['fin11'] },
  { canonical: 'Cl0p',            aliases: ['cl0p', 'clop', 'ta505'] },
  { canonical: 'LockBit',         aliases: ['lockbit'] },
  { canonical: 'BlackCat/ALPHV',  aliases: ['blackcat', 'alphv'] },
  { canonical: 'Play',            aliases: ['play ransomware'] },
  { canonical: 'Medusa',          aliases: ['medusa ransomware', 'medusa gang'] },
  { canonical: 'BlackBasta',      aliases: ['black basta', 'blackbasta'] },
  { canonical: 'UNC4899',         aliases: ['unc4899'] },
  { canonical: 'UTA0218',         aliases: ['uta0218'] },
  { canonical: 'APT40',           aliases: ['apt40', 'leviathan', 'bronze mohawk'] },
  { canonical: 'APT31',           aliases: ['apt31', 'zirconium', 'judgment panda'] },
  { canonical: 'Earth Lusca',     aliases: ['earth lusca'] },
  { canonical: 'Silk Typhoon',    aliases: ['silk typhoon', 'hafnium'] },
  { canonical: 'Flax Typhoon',    aliases: ['flax typhoon'] },
];

const CISA_ADVISORIES_RSS   = 'https://www.cisa.gov/cybersecurity-advisories/all.xml';
const KV_ADVISORY_CACHE_KEY = 'aptintel:cisa_advisories:v1';
const ADVISORY_CACHE_TTL    = 3600; // 1 hour — advisories publish a few times/week; keeps this genuinely fresh
const CVE_REGEX = /CVE-\d{4}-\d{4,7}/gi;

function matchActors(text) {
  if (!text) return [];
  const lower = String(text).toLowerCase();
  const hits = [];
  for (const actor of KNOWN_THREAT_ACTORS) {
    if (actor.aliases.some(a => lower.includes(a))) hits.push(actor.canonical);
  }
  return [...new Set(hits)];
}

// ─── Fetch + parse the live CISA advisories feed ─────────────────────────────
async function fetchCisaAdvisories(env) {
  if (env?.SECURITY_HUB_KV) {
    const cached = await env.SECURITY_HUB_KV.get(KV_ADVISORY_CACHE_KEY, { type: 'json' }).catch(() => null);
    if (cached) return cached;
  }

  let items = [];
  try {
    const resp = await fetch(CISA_ADVISORIES_RSS, {
      headers: { 'User-Agent': 'CYBERDUDEBIVASH-SecurityHub/1.0' },
      signal: AbortSignal.timeout(8000),
    });
    if (resp.ok) {
      const xml = await resp.text();
      // Lightweight RSS <item> extraction — no XML dependency needed for this shape.
      const itemBlocks = xml.match(/<item>[\s\S]*?<\/item>/g) || [];
      items = itemBlocks.slice(0, 60).map(block => {
        const title = (block.match(/<title>([\s\S]*?)<\/title>/) || [])[1] || '';
        const link  = (block.match(/<link>([\s\S]*?)<\/link>/) || [])[1] || '';
        const desc  = (block.match(/<description>([\s\S]*?)<\/description>/) || [])[1] || '';
        const pub   = (block.match(/<pubDate>([\s\S]*?)<\/pubDate>/) || [])[1] || '';
        return {
          title: title.replace(/<!\[CDATA\[|\]\]>/g, '').trim(),
          url:   link.trim(),
          summary: desc.replace(/<!\[CDATA\[|\]\]>/g, '').replace(/<[^>]+>/g, '').trim().slice(0, 300),
          published: pub ? new Date(pub).toISOString() : null,
        };
      });
    }
  } catch { /* network unavailable — return empty, caller handles gracefully */ }

  if (env?.SECURITY_HUB_KV) {
    env.SECURITY_HUB_KV.put(KV_ADVISORY_CACHE_KEY, JSON.stringify(items), { expirationTtl: ADVISORY_CACHE_TTL }).catch(() => {});
  }
  return items;
}

// ─── Correlate live CISA advisories against the known-actor table ───────────
// Returns real evidence entries: {group, source:'CISA Advisory', url, date, matched_cves}
async function correlateAdvisories(env) {
  const advisories = await fetchCisaAdvisories(env);
  const evidence = [];
  for (const adv of advisories) {
    const text = `${adv.title} ${adv.summary}`;
    const matched = matchActors(text);
    if (!matched.length) continue;
    const cves = [...new Set((text.match(CVE_REGEX) || []).map(c => c.toUpperCase()))];
    for (const group of matched) {
      evidence.push({
        group,
        source: 'CISA Advisory',
        title: adv.title,
        url: adv.url,
        date: adv.published,
        matched_cves: cves,
      });
    }
  }
  return evidence;
}

// ─── Backfill: scan D1 threat_intel rows and tag apt_groups where a real
//    actor name/alias appears in the CVE's own title/description ───────────
export async function correlateAptGroupsInD1(env) {
  if (!env?.DB) return { scanned: 0, tagged: 0, skipped: 'no_db' };

  let rows;
  try {
    rows = await env.DB.prepare(`
      SELECT id, cve_id, title, description
      FROM threat_intel
      WHERE (apt_groups IS NULL OR apt_groups = '' OR apt_groups = '[]')
        AND COALESCE(published_at, ingested_at) > datetime('now', '-30 days')
      ORDER BY COALESCE(published_at, ingested_at) DESC
      LIMIT 200
    `).all();
  } catch (e) {
    return { scanned: 0, tagged: 0, error: e?.message };
  }

  const candidates = rows?.results || [];
  let tagged = 0;
  for (const row of candidates) {
    const matched = matchActors(`${row.title || ''} ${row.description || ''}`);
    if (!matched.length) continue;
    try {
      await env.DB.prepare(`UPDATE threat_intel SET apt_groups = ? WHERE id = ?`)
        .bind(JSON.stringify(matched), row.id).run();
      tagged++;
    } catch { /* column may not exist on this row's schema generation — skip safely */ }
  }

  return { scanned: candidates.length, tagged };
}

// ─── Public aggregate: real, currently-active APT groups with cited evidence ─
// This is what /api/apt-intel/groups and the dashboard's APT panel consume.
// Never fabricates — returns [] when no live evidence exists.
export async function getActiveAptGroups(env, { limit = 8 } = {}) {
  const [advisoryEvidence, d1Evidence] = await Promise.all([
    correlateAdvisories(env).catch(() => []),
    (async () => {
      if (!env?.DB) return [];
      try {
        const rows = await env.DB.prepare(`
          SELECT cve_id, id, title, apt_groups, published_at, ingested_at
          FROM threat_intel
          WHERE apt_groups IS NOT NULL AND apt_groups != '' AND apt_groups != '[]'
          ORDER BY COALESCE(published_at, ingested_at) DESC
          LIMIT 50
        `).all();
        const out = [];
        for (const r of rows?.results || []) {
          let groups = [];
          try { groups = JSON.parse(r.apt_groups); } catch {}
          for (const g of (Array.isArray(groups) ? groups : [])) {
            out.push({
              group: g,
              source: 'CVE correlation',
              title: r.title,
              url: r.cve_id ? `https://nvd.nist.gov/vuln/detail/${r.cve_id}` : null,
              date: r.published_at || r.ingested_at || null,
              matched_cves: r.cve_id ? [r.cve_id] : [],
            });
          }
        }
        return out;
      } catch { return []; }
    })(),
  ]);

  const allEvidence = [...advisoryEvidence, ...d1Evidence];

  // Group by canonical actor name, merge evidence, rank by evidence count then recency.
  const byGroup = new Map();
  for (const ev of allEvidence) {
    if (!byGroup.has(ev.group)) byGroup.set(ev.group, []);
    byGroup.get(ev.group).push(ev);
  }

  const result = [...byGroup.entries()].map(([group, evidenceList]) => {
    const sorted = evidenceList.sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));
    return {
      group,
      mentions: evidenceList.length,
      last_seen: sorted[0]?.date || null,
      evidence: sorted.slice(0, 3).map(e => ({
        source: e.source, title: e.title, url: e.url, date: e.date, matched_cves: e.matched_cves,
      })),
    };
  }).sort((a, b) => {
    const dateDiff = new Date(b.last_seen || 0) - new Date(a.last_seen || 0);
    if (dateDiff !== 0) return dateDiff;
    return b.mentions - a.mentions;
  });

  return result.slice(0, limit);
}

// ─── HTTP handler: GET /api/apt-intel/groups ─────────────────────────────────
export async function handleAptIntelGroups(request, env) {
  const groups = await getActiveAptGroups(env);
  return Response.json({
    active_apt_groups: groups,
    total: groups.length,
    sources: ['CISA Cybersecurity Advisories (live)', 'Platform CVE correlation (D1)'],
    methodology: 'A group is only reported when its name or a known alias appears in a live CISA advisory or an ingested CVE record. No activity is inferred or invented.',
    generated_at: new Date().toISOString(),
  });
}
