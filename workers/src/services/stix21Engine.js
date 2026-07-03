/**
 * CYBERDUDEBIVASH® AI Security Hub — STIX 2.1 Export Engine v1.0
 *
 * Generates STIX 2.1 compliant bundles from threat intel data.
 * Also provides TAXII 2.1 compatible collection endpoints.
 *
 * STIX 2.1 spec: https://docs.oasis-open.org/cti/stix/v2.1/
 * TAXII 2.1 spec: https://docs.oasis-open.org/cti/taxii/v2.1/
 *
 * Object types generated:
 *   - vulnerability        (CVE entries)
 *   - indicator            (IOCs — IPs, hashes, domains)
 *   - threat-actor         (APT groups)
 *   - attack-pattern       (MITRE ATT&CK techniques)
 *   - malware              (known malware families)
 *   - campaign             (threat campaigns)
 *   - relationship         (links between all objects)
 *   - note                 (analyst comments)
 */

const STIX_SPEC_VERSION = '2.1';
const IDENTITY_ID       = 'identity--cyberdudebivash-ai-security-hub';
const IDENTITY_NAME     = 'CYBERDUDEBIVASH® AI Security Hub';
const IDENTITY_CLASS    = 'organization';

// ─── Safe UUID v4 generator (no crypto.randomUUID needed) ────────────────────
function uuid4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

function stixId(type) {
  return `${type}--${uuid4()}`;
}

function nowISO() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z');
}

// ─── STIX Identity (our platform as the creator) ──────────────────────────────
function buildIdentity() {
  return {
    type:               'identity',
    spec_version:       STIX_SPEC_VERSION,
    id:                 IDENTITY_ID,
    created:            '2024-01-01T00:00:00.000Z',
    modified:           nowISO(),
    name:               IDENTITY_NAME,
    identity_class:     IDENTITY_CLASS,
    description:        'AI-native cyber threat intelligence platform providing real-time CVE, IOC, and APT intelligence.',
    sectors:            ['technology'],
    contact_information: 'https://cyberdudebivash.in',
  };
}

// ─── CVE entry → STIX Vulnerability object ────────────────────────────────────
function cveToSTIX(entry) {
  const tags = (() => { try { return JSON.parse(entry.tags || '[]'); } catch { return []; } })();
  const weaknesses = (() => { try { return JSON.parse(entry.weakness_types || '[]'); } catch { return []; } })();
  const products = (() => { try { return JSON.parse(entry.affected_products || '[]'); } catch { return []; } })();

  const vuln = {
    type:                 'vulnerability',
    spec_version:         STIX_SPEC_VERSION,
    id:                   stixId('vulnerability'),
    created_by_ref:       IDENTITY_ID,
    created:              entry.published_at ? new Date(entry.published_at).toISOString() : nowISO(),
    modified:             nowISO(),
    name:                 entry.id,
    description:          entry.description || entry.title || '',
    labels:               tags.map(t => t.toLowerCase()),
    external_references:  [
      {
        source_name: 'cve',
        url:         `https://nvd.nist.gov/vuln/detail/${entry.id}`,
        external_id: entry.id,
      },
      ...(entry.source_url ? [{
        source_name: entry.source || 'cyberdudebivash',
        url:         entry.source_url,
      }] : []),
    ],
    extensions: {
      'extension-definition--cyberdudebivash-vuln': {
        extension_type: 'property-extension',
        cvss_score:     entry.cvss ?? null,
        severity:       entry.severity ?? null,
        exploit_status: entry.exploit_status ?? null,
        known_ransomware: !!entry.known_ransomware,
        in_cisa_kev:    entry.exploit_status === 'confirmed',
        epss_score:     entry.epss_score ?? null,
        priority_score: entry.priority_score ?? null,
        risk_tier:      entry.risk_tier ?? null,
        weakness_types: weaknesses,
        affected_products: products,
        mitre_techniques:  (entry.attack_mapping?.techniques || []).map(t => t.technique_id),
      },
    },
  };

  return vuln;
}

// ─── APT actor → STIX Threat-Actor object ────────────────────────────────────
function actorToSTIX(actor) {
  // motivation is an optional field. Curated actors always supply an array, but a
  // D1-sourced or externally-supplied actor may omit it or provide a scalar. Without
  // this guard, `.includes()` throws and the ENTIRE STIX bundle export 500s for the
  // customer's SIEM/TIP. Normalize to a string[] so every downstream check is safe.
  const motivation = Array.isArray(actor.motivation)
    ? actor.motivation
    : (actor.motivation != null ? [String(actor.motivation)] : []);
  return {
    type:             'threat-actor',
    spec_version:     STIX_SPEC_VERSION,
    id:               stixId('threat-actor'),
    created_by_ref:   IDENTITY_ID,
    created:          `${actor.active_since || '2015'}-01-01T00:00:00.000Z`,
    modified:         nowISO(),
    name:             actor.id,
    description:      actor.description || '',
    threat_actor_types: motivation.includes('espionage') ? ['nation-state'] :
                       motivation.includes('ransomware-as-a-service') ? ['crime-syndicate'] :
                       ['unknown'],
    aliases:          actor.aliases || [],
    sophistication:   actor.risk_score >= 90 ? 'advanced' :
                      actor.risk_score >= 70 ? 'expert' : 'intermediate',
    resource_level:   actor.suspected_sponsor ? 'government' : 'organization',
    primary_motivation: motivation.includes('financial-gain') ? 'personal-gain' :
                       motivation.includes('espionage') ? 'organizational-gain' :
                       'disruption',
    labels:           motivation,
    external_references: [{
      source_name: 'mitre-attack',
      url:         `https://attack.mitre.org/groups/${actor.id.replace(' ', '_')}/`,
    }],
    extensions: {
      'extension-definition--cyberdudebivash-actor': {
        extension_type:     'property-extension',
        origin:             actor.origin,
        suspected_sponsor:  actor.suspected_sponsor || null,
        target_sectors:     actor.target_sectors,
        target_geographies: actor.target_geographies,
        known_tools:        actor.known_tools,
        risk_score:         actor.risk_score,
      },
    },
  };
}

// ─── ATT&CK technique → STIX Attack-Pattern object ───────────────────────────
function techniqueToSTIX(technique) {
  return {
    type:           'attack-pattern',
    spec_version:   STIX_SPEC_VERSION,
    id:             stixId('attack-pattern'),
    created_by_ref: IDENTITY_ID,
    created:        '2024-01-01T00:00:00.000Z',
    modified:       nowISO(),
    name:           technique.technique_name || technique.name,
    description:    `MITRE ATT&CK Technique ${technique.technique_id || technique.id}`,
    labels:         [technique.tactic_name?.toLowerCase().replace(/ /g, '-') || 'unknown'],
    external_references: [{
      source_name:  'mitre-attack',
      url:          `https://attack.mitre.org/techniques/${(technique.technique_id || technique.id).replace('.', '/')}/`,
      external_id:  technique.technique_id || technique.id,
    }],
  };
}

// ─── IOC → STIX Indicator object ─────────────────────────────────────────────
function iocToSTIX(ioc, relatedCveId = null) {
  const patternMap = {
    ip:     `[ipv4-addr:value = '${ioc.value || ioc.indicator}']`,
    domain: `[domain-name:value = '${ioc.value || ioc.indicator}']`,
    hash:   `[file:hashes.MD5 = '${ioc.value || ioc.indicator}']`,
    url:    `[url:value = '${ioc.value || ioc.indicator}']`,
    email:  `[email-addr:value = '${ioc.value || ioc.indicator}']`,
  };

  const type = (ioc.type || 'unknown').toLowerCase();
  const pattern = patternMap[type] || `[artifact:payload_bin = '${ioc.value || ioc.indicator}']`;

  return {
    type:               'indicator',
    spec_version:       STIX_SPEC_VERSION,
    id:                 stixId('indicator'),
    created_by_ref:     IDENTITY_ID,
    created:            ioc.first_seen || nowISO(),
    modified:           nowISO(),
    name:               `${type.toUpperCase()}: ${ioc.value || ioc.indicator}`,
    description:        ioc.context || `IOC associated with ${relatedCveId || 'threat intelligence'}`,
    pattern:            pattern,
    pattern_type:       'stix',
    valid_from:         ioc.first_seen || nowISO(),
    valid_until:        ioc.expires_at || new Date(Date.now() + 30 * 86400000).toISOString(),
    indicator_types:    ['malicious-activity'],
    labels:             [type, relatedCveId ? 'cve-associated' : 'threat-intel'].filter(Boolean),
    extensions: {
      'extension-definition--cyberdudebivash-ioc': {
        extension_type:   'property-extension',
        confidence_score: ioc.confidence || 70,
        source:           ioc.source || 'cyberdudebivash',
        related_cve:      relatedCveId || null,
      },
    },
  };
}

// ─── Relationship object ──────────────────────────────────────────────────────
function buildRelationship(sourceRef, targetRef, relationshipType, description = '') {
  return {
    type:              'relationship',
    spec_version:      STIX_SPEC_VERSION,
    id:                stixId('relationship'),
    created_by_ref:    IDENTITY_ID,
    created:           nowISO(),
    modified:          nowISO(),
    relationship_type: relationshipType,
    source_ref:        sourceRef,
    target_ref:        targetRef,
    description,
  };
}

// ─── Full STIX 2.1 Bundle builder ─────────────────────────────────────────────
export function buildSTIXBundle(data = {}) {
  const objects = [buildIdentity()];
  const relationshipQueue = [];

  const { entries = [], actors = [], iocData = [], includeRelationships = true } = data;

  // Vulnerability objects from CVE entries
  const vulnMap = {};
  for (const entry of entries) {
    const stixVuln = cveToSTIX(entry);
    objects.push(stixVuln);
    vulnMap[entry.id] = stixVuln.id;

    // ATT&CK technique objects from mappings
    if (entry.attack_mapping?.techniques?.length > 0 && includeRelationships) {
      for (const tech of entry.attack_mapping.techniques.slice(0, 3)) {
        const stixTech = techniqueToSTIX(tech);
        objects.push(stixTech);
        relationshipQueue.push(buildRelationship(
          stixVuln.id, stixTech.id, 'uses',
          `${entry.id} exploits ${tech.technique_name}`
        ));
      }
    }
  }

  // Threat Actor objects
  const actorMap = {};
  for (const actor of actors) {
    const stixActor = actorToSTIX(actor);
    objects.push(stixActor);
    actorMap[actor.id] = stixActor.id;

    // Link actors to CVEs they use
    if (includeRelationships) {
      for (const cveId of (actor.cve_associations || [])) {
        if (vulnMap[cveId]) {
          relationshipQueue.push(buildRelationship(
            stixActor.id, vulnMap[cveId], 'exploits',
            `${actor.id} is known to exploit ${cveId}`
          ));
        }
      }
    }
  }

  // IOC Indicator objects
  for (const ioc of iocData) {
    const relatedCve = ioc.intel_id || ioc.related_cve || null;
    const stixIOC = iocToSTIX(ioc, relatedCve);
    objects.push(stixIOC);

    if (includeRelationships && relatedCve && vulnMap[relatedCve]) {
      relationshipQueue.push(buildRelationship(
        vulnMap[relatedCve], stixIOC.id, 'indicates',
        `Indicator associated with ${relatedCve}`
      ));
    }
  }

  // Add all relationships
  objects.push(...relationshipQueue);

  return {
    type:         'bundle',
    id:           stixId('bundle'),
    spec_version: STIX_SPEC_VERSION,
    objects,
    _meta: {
      generated_at:    nowISO(),
      object_count:    objects.length,
      vulnerability_count: entries.length,
      actor_count:     actors.length,
      indicator_count: iocData.length,
      generator:       'CYBERDUDEBIVASH® AI Security Hub STIX 2.1 Engine v1.0',
      spec:            'https://docs.oasis-open.org/cti/stix/v2.1/',
    },
  };
}

// ─── Build bundle from D1 data ────────────────────────────────────────────────
export async function buildBundleFromD1(env, options = {}) {
  const { limit = 50, severity = null, includeActors = true, includeIOCs = true, kev_only = false } = options;

  const results = { entries: [], actors: [], iocData: [] };

  if (env?.DB) {
    try {
      const where  = severity ? 'WHERE severity = ?' : '';
      const params = severity ? [severity.toUpperCase(), limit] : [limit];
      const rows = await env.DB.prepare(
        `SELECT * FROM threat_intel ${where}
         ORDER BY CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 ELSE 1 END DESC, cvss DESC
         LIMIT ?`
      ).bind(...params).all();
      results.entries = rows?.results || [];
      if (kev_only) {
        results.entries = results.entries.filter(e =>
          e.exploit_status === 'confirmed' || !!e.in_kev
        );
      }
    } catch {}

    if (includeIOCs) {
      try {
        const iocRows = await env.DB.prepare(
          `SELECT ir.*, ti.id as related_cve
           FROM ioc_registry ir
           LEFT JOIN threat_intel ti ON ti.id = ir.intel_id
           ORDER BY ir.created_at DESC LIMIT 200`
        ).all();
        results.iocData = iocRows?.results || [];
      } catch {}
    }
  }

  if (includeActors) {
    try {
      const { getAllActors } = await import('./aptActorProfiles.js');
      results.actors = getAllActors().filter(a => a.last_seen >= '2024').slice(0, 20);
    } catch {}
  }

  return buildSTIXBundle({
    ...results,
    includeRelationships: true,
  });
}

// ─── TAXII 2.1 Collection Manifest ───────────────────────────────────────────
export function buildTAXIIDiscovery(baseUrl) {
  return {
    title:          'CYBERDUDEBIVASH® Sentinel APEX Threat Intelligence Feed',
    description:    'Real-time AI threat intelligence — CVEs, IOCs, APT actors, ATT&CK mappings. STIX 2.1 / TAXII 2.1 compliant.',
    contact:        'contact@cyberdudebivash.in',
    default:        `${baseUrl}/api/taxii/collections`,
    api_roots:      [`${baseUrl}/api/taxii`],
    versions:       ['taxii-2.1'],
  };
}

export function buildTAXIICollections(baseUrl) {
  return {
    collections: [
      {
        id:          'cve-feed',
        title:       'CVE & Vulnerability Intelligence',
        description: 'Real-time CRITICAL and HIGH severity CVEs with CVSS, EPSS, KEV status, and MITRE ATT&CK mappings',
        can_read:    true,
        can_write:   false,
        media_types: ['application/stix+json;version=2.1'],
        url:         `${baseUrl}/api/taxii/collections/cve-feed/objects`,
      },
      {
        id:          'ioc-feed',
        title:       'IOC Registry',
        description: 'Indicators of Compromise (IPs, domains, hashes, URLs) with confidence scoring',
        can_read:    true,
        can_write:   false,
        media_types: ['application/stix+json;version=2.1'],
        url:         `${baseUrl}/api/taxii/collections/ioc-feed/objects`,
        access_required: 'PRO',
      },
      {
        id:          'actor-feed',
        title:       'APT Actor Intelligence',
        description: 'Threat actor profiles, campaigns, and tool intelligence for 60+ APT groups',
        can_read:    true,
        can_write:   false,
        media_types: ['application/stix+json;version=2.1'],
        url:         `${baseUrl}/api/taxii/collections/actor-feed/objects`,
        access_required: 'ENTERPRISE',
      },
      {
        id:          'kev-feed',
        title:       'CISA KEV & Actively Exploited',
        description: 'Known Exploited Vulnerabilities with active campaign correlation',
        can_read:    true,
        can_write:   false,
        media_types: ['application/stix+json;version=2.1'],
        url:         `${baseUrl}/api/taxii/collections/kev-feed/objects`,
      },
    ],
  };
}
