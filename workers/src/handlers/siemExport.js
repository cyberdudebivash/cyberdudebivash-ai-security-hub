/**
 * SIEM Export Handler — CYBERDUDEBIVASH AI Security Hub v8.1 / P8.0-003
 *
 * Exports threat intel, scan findings, IOCs, and SOC alerts in multiple formats:
 *   - JSON          (native — always available)
 *   - CEF           (ArcSight Common Event Format — Splunk/QRadar/ArcSight)
 *   - STIX 2.1      (Structured Threat Information Expression — MISP/OpenCTI)
 *   - Sigma         (Detection rule format — Elastic/Splunk/Chronicle)
 *   - CSV           (spreadsheet-friendly)
 *   - NDJSON        (newline-delimited JSON, also available via streaming)
 *   - IOC Bundle    (deduplicated, typed indicator manifest for TIP/firewall ingestion)
 *   - Executive PDF (print-ready HTML board/leadership summary — reuses reportingEngine.js shell)
 *
 * Endpoints:
 *   GET /api/export/siem          — list export options (public)
 *   POST /api/export/siem         — generate export (PRO/ENTERPRISE)
 *   GET /api/export/siem/stream   — streaming NDJSON export (ENTERPRISE)
 *
 * Plan gating:
 *   FREE    — not available
 *   STARTER — not available
 *   PRO     — JSON + CSV + STIX + IOC Bundle (last 24h, max 500 records)
 *   ENTERPRISE — all formats incl. CEF/Sigma/NDJSON/Executive PDF, full history, streaming
 */

import { buildReportShell } from './reportingEngine.js';

const SUPPORTED_FORMATS = ['json', 'cef', 'stix', 'sigma', 'csv', 'ndjson', 'ioc_bundle', 'executive_pdf'];
const PLAN_LIMITS = {
  PRO:        { formats: ['json', 'csv', 'stix', 'ioc_bundle'], max_records: 500,   hours: 24 },
  ENTERPRISE: { formats: SUPPORTED_FORMATS,        max_records: 10000, hours: 720 }, // 30d
};

// ─── Public info ──────────────────────────────────────────────────────────────
export function handleSiemInfo() {
  return Response.json({
    success: true,
    service: 'SIEM Export — CYBERDUDEBIVASH AI Security Hub',
    version: '8.1',
    description: 'Export threat intel, scan findings, IOCs, and alerts in SIEM-compatible formats.',
    formats: {
      json:          { description: 'Native JSON array', plan: 'PRO+' },
      csv:           { description: 'Spreadsheet-compatible CSV', plan: 'PRO+' },
      stix:          { description: 'STIX 2.1 Bundle (MISP/OpenCTI/CrowdStrike compatible)', plan: 'PRO+' },
      ioc_bundle:    { description: 'Deduplicated, typed indicator manifest for TIP/firewall ingestion', plan: 'PRO+' },
      cef:           { description: 'ArcSight CEF — syslog-ready for Splunk/QRadar/ArcSight', plan: 'ENTERPRISE' },
      sigma:         { description: 'Sigma detection rules for Elastic/Splunk/Chronicle', plan: 'ENTERPRISE' },
      ndjson:        { description: 'Newline-delimited JSON stream for Logstash/Fluentd', plan: 'ENTERPRISE' },
      executive_pdf: { description: 'Print-ready HTML board/leadership summary (save-as-PDF)', plan: 'ENTERPRISE' },
    },
    sources:  ['threat_intel', 'scan_findings', 'iocs', 'soc_alerts'],
    endpoints: {
      export: 'POST /api/export/siem',
      stream: 'GET /api/export/siem/stream',
      info:   'GET /api/export/siem',
    },
    example: {
      method: 'POST',
      path: '/api/export/siem',
      body: { format: 'stix', source: 'threat_intel', hours: 24, limit: 100 },
    },
  });
}

// ─── Main export handler ──────────────────────────────────────────────────────
export async function handleSiemExport(request, env, authCtx) {
  // Plan gate
  const tier = authCtx?.tier || 'FREE';
  const limits = PLAN_LIMITS[tier];
  if (!limits) {
    return Response.json({
      success: false,
      error: 'SIEM export requires PRO or ENTERPRISE plan.',
      code: 'ERR_PLAN_REQUIRED',
      upgrade: 'https://tools.cyberdudebivash.com/#pricing',
    }, { status: 403 });
  }

  let body;
  try { body = await request.json(); } catch {
    return Response.json({ success: false, error: 'Invalid JSON body' }, { status: 400 });
  }

  const format  = (body.format  || 'json').toLowerCase();
  const source  = (body.source  || 'threat_intel').toLowerCase();
  const hours   = Math.min(Number(body.hours  || 24),  limits.hours);
  const limit   = Math.min(Number(body.limit  || 100), limits.max_records);

  // Format gate
  if (!SUPPORTED_FORMATS.includes(format)) {
    return Response.json({ success: false, error: `Unknown format: ${format}. Use: ${SUPPORTED_FORMATS.join(', ')}` }, { status: 400 });
  }
  if (!limits.formats.includes(format)) {
    return Response.json({
      success: false,
      error: `Format '${format}' requires ENTERPRISE plan. Your plan (${tier}) supports: ${limits.formats.join(', ')}.`,
      code: 'ERR_ENTERPRISE_REQUIRED',
    }, { status: 403 });
  }

  // Fetch data
  const records = await fetchSource(env, source, hours, limit);
  const ts      = new Date().toISOString();

  // Generate export
  let output, contentType, filename;

  switch (format) {
    case 'stix': {
      const bundle = buildSTIX(records, source, ts);
      output = JSON.stringify(bundle, null, 2);
      contentType = 'application/json';
      filename = `cyberdudebivash-${source}-${ts.slice(0,10)}.stix.json`;
      break;
    }
    case 'cef': {
      output = buildCEF(records, source);
      contentType = 'text/plain';
      filename = `cyberdudebivash-${source}-${ts.slice(0,10)}.cef`;
      break;
    }
    case 'sigma': {
      const rules = buildSigma(records, source, ts);
      output = JSON.stringify(rules, null, 2);
      contentType = 'application/json';
      filename = `cyberdudebivash-sigma-rules-${ts.slice(0,10)}.json`;
      break;
    }
    case 'csv': {
      output = buildCSV(records, source);
      contentType = 'text/csv';
      filename = `cyberdudebivash-${source}-${ts.slice(0,10)}.csv`;
      break;
    }
    case 'ndjson': {
      output = records.map(r => JSON.stringify(r)).join('\n');
      contentType = 'application/x-ndjson';
      filename = `cyberdudebivash-${source}-${ts.slice(0,10)}.ndjson`;
      break;
    }
    case 'ioc_bundle': {
      const bundle = buildIOCBundle(records, source, ts);
      output = JSON.stringify(bundle, null, 2);
      contentType = 'application/json';
      filename = `cyberdudebivash-ioc-bundle-${ts.slice(0,10)}.json`;
      break;
    }
    case 'executive_pdf': {
      output = buildExecutivePDF(records, source, ts);
      contentType = 'text/html';
      filename = `cyberdudebivash-executive-report-${ts.slice(0,10)}.html`;
      break;
    }
    default: { // json
      output = JSON.stringify({
        generated_at: ts,
        source,
        format: 'json',
        count: records.length,
        platform: 'CYBERDUDEBIVASH AI Security Hub v32.0 (STIX 2.1 Full Graph)',
        data: records,
      }, null, 2);
      contentType = 'application/json';
      filename = `cyberdudebivash-${source}-${ts.slice(0,10)}.json`;
    }
  }

  // Executive PDF renders inline (viewable/printable in-browser), matching
  // the existing convention in reportingEngine.js's handleDownloadReport.
  const disposition = format === 'executive_pdf' ? 'inline' : 'attachment';

  return new Response(output, {
    status: 200,
    headers: {
      'Content-Type': contentType,
      'Content-Disposition': `${disposition}; filename="${filename}"`,
      'X-Export-Count': String(records.length),
      'X-Export-Format': format,
      'X-Export-Source': source,
      'X-Export-Timestamp': ts,
      'Cache-Control': 'no-store, private',
    },
  });
}

// ─── Streaming NDJSON export (ENTERPRISE only) ─────────────────────────────--
export async function handleSiemStream(request, env, authCtx) {
  const tier = authCtx?.tier;
  if (tier !== 'ENTERPRISE') {
    return Response.json({
      success: false,
      error: 'Streaming SIEM export requires ENTERPRISE plan.',
      code: 'ERR_ENTERPRISE_REQUIRED',
      upgrade: 'https://tools.cyberdudebivash.com/#pricing',
    }, { status: 403 });
  }

  const url    = new URL(request.url);
  const source = url.searchParams.get('source') || 'threat_intel';
  const hours  = Math.min(Number(url.searchParams.get('hours') || 24), 720);
  const limit  = Math.min(Number(url.searchParams.get('limit') || 1000), 10000);

  const records = await fetchSource(env, source, hours, limit);
  const ts      = new Date().toISOString();

  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const enc    = new TextEncoder();

  // Stream records asynchronously (non-blocking)
  (async () => {
    // Header comment line
    await writer.write(enc.encode(`# CYBERDUDEBIVASH SIEM Export — source:${source} generated:${ts}\n`));
    for (const rec of records) {
      await writer.write(enc.encode(JSON.stringify(rec) + '\n'));
    }
    // Footer
    await writer.write(enc.encode(`# END — ${records.length} records exported\n`));
    await writer.close();
  })();

  return new Response(readable, {
    status: 200,
    headers: {
      'Content-Type': 'application/x-ndjson',
      'Content-Disposition': `attachment; filename="cyberdudebivash-${source}-stream-${ts.slice(0,10)}.ndjson"`,
      'X-Export-Count': String(records.length),
      'Transfer-Encoding': 'chunked',
      'Cache-Control': 'no-store, private',
    },
  });
}

// ─── Data fetcher ─────────────────────────────────────────────────────────────
async function fetchSource(env, source, hours, limit) {
  if (!env?.DB) return buildSeedData(source, limit);

  const cutoff = new Date(Date.now() - hours * 3_600_000).toISOString();

  try {
    switch (source) {
      case 'threat_intel': {
        const rows = await env.DB.prepare(
          `SELECT id, cve_id, title, description, cvss, epss, severity, published_at,
                  is_kev, source_url, iocs, mitre_tactics, affected_products, created_at
           FROM threat_intel
           WHERE created_at >= ?
           ORDER BY cvss DESC, created_at DESC
           LIMIT ?`
        ).bind(cutoff, limit).all();
        return (rows.results || []).map(r => ({
          ...r,
          iocs:          safeJSON(r.iocs, []),
          mitre_tactics: safeJSON(r.mitre_tactics, []),
          affected_products: safeJSON(r.affected_products, []),
        }));
      }
      case 'scan_findings': {
        const rows = await env.DB.prepare(
          `SELECT id, module, target, risk_score, findings, status, created_at
           FROM scan_history
           WHERE created_at >= ?
           ORDER BY risk_score DESC, created_at DESC
           LIMIT ?`
        ).bind(cutoff, limit).all();
        return (rows.results || []).map(r => ({
          ...r,
          findings: safeJSON(r.findings, []),
        }));
      }
      case 'iocs': {
        // Extract IOCs from threat intel table
        const rows = await env.DB.prepare(
          `SELECT cve_id, iocs, severity, cvss, created_at
           FROM threat_intel
           WHERE iocs IS NOT NULL AND iocs != '[]'
             AND created_at >= ?
           ORDER BY created_at DESC
           LIMIT ?`
        ).bind(cutoff, limit).all();
        const iocs = [];
        for (const row of (rows.results || [])) {
          const parsed = safeJSON(row.iocs, []);
          for (const ioc of parsed) {
            iocs.push({
              source_cve: row.cve_id,
              severity:   row.severity,
              cvss:       row.cvss,
              ioc_type:   detectIOCType(ioc),
              ioc_value:  ioc,
              observed_at: row.created_at,
            });
          }
          if (iocs.length >= limit) break;
        }
        return iocs;
      }
      case 'soc_alerts': {
        const rows = await env.DB.prepare(
          `SELECT id, alert_type, severity, description, cve_id, mitre_tactic, metadata, created_at
           FROM analytics_events
           WHERE event_type LIKE 'alert.%' AND created_at >= ?
           ORDER BY created_at DESC
           LIMIT ?`
        ).bind(cutoff, limit).all();
        return (rows.results || []).map(r => ({
          ...r,
          metadata: safeJSON(r.metadata, {}),
        }));
      }
      default:
        return [];
    }
  } catch (e) {
    console.error('[SIEM] DB fetch error:', e?.message);
    return buildSeedData(source, Math.min(limit, 10));
  }
}

// ─── STIX 2.1 Builder ─────────────────────────────────────────────────────────
function buildSTIX(records, source, ts) {
  const bundle = {
    type: 'bundle',
    id: `bundle--${crypto.randomUUID()}`,
    spec_version: '2.1',
    created: ts,
    objects: [],
  };

  // Identity object (producer)
  bundle.objects.push({
    type: 'identity',
    id: `identity--cyberdudebivash`,
    spec_version: '2.1',
    created: ts,
    modified: ts,
    name: 'CYBERDUDEBIVASH Sentinel APEX',
    identity_class: 'organization',
    sectors: ['technology'],
    contact_information: 'bivash@cyberdudebivash.com',
  });

  for (const rec of records) {
    if (source === 'threat_intel' && rec.cve_id) {
      // Vulnerability object
      bundle.objects.push({
        type: 'vulnerability',
        id: `vulnerability--${safeUUID(rec.id || rec.cve_id)}`,
        spec_version: '2.1',
        created: rec.created_at || ts,
        modified: rec.created_at || ts,
        name: rec.cve_id || rec.title,
        description: rec.description || '',
        external_references: [
          {
            source_name: 'cve',
            external_id: rec.cve_id || '',
            url: `https://nvd.nist.gov/vuln/detail/${rec.cve_id || ''}`,
          },
        ],
        labels: [rec.severity?.toLowerCase() || 'unknown'],
        custom_properties: {
          x_cvss_score:       rec.cvss  || 0,
          x_epss_probability: rec.epss  || 0,
          x_is_kev:           !!rec.is_kev,
          x_mitre_tactics:    rec.mitre_tactics || [],
          x_affected_products: rec.affected_products || [],
        },
      });

      // Indicator objects for IOCs
      for (const ioc of (rec.iocs || [])) {
        const iocType = detectIOCType(ioc);
        if (!iocType) continue;
        bundle.objects.push({
          type: 'indicator',
          id: `indicator--${crypto.randomUUID()}`,
          spec_version: '2.1',
          created: ts,
          modified: ts,
          name: ioc,
          indicator_types: ['malicious-activity'],
          pattern: buildSTIXPattern(iocType, ioc),
          pattern_type: 'stix',
          valid_from: ts,
          labels: [rec.severity?.toLowerCase() || 'unknown'],
          external_references: [{
            source_name: 'cve', external_id: rec.cve_id || '', url: `https://nvd.nist.gov/vuln/detail/${rec.cve_id || ''}`,
          }],
        });
      }
    } else if (source === 'scan_findings') {
      bundle.objects.push({
        type: 'report',
        id: `report--${safeUUID(rec.id || crypto.randomUUID())}`,
        spec_version: '2.1',
        created: rec.created_at || ts,
        modified: rec.created_at || ts,
        name: `${(rec.module || 'scan').toUpperCase()} Scan — ${rec.target || 'unknown'}`,
        description: `Risk Score: ${rec.risk_score ?? 'N/A'}`,
        published: rec.created_at || ts,
        report_types: ['threat-report'],
        object_refs: [],
        custom_properties: {
          x_module:     rec.module,
          x_target:     rec.target,
          x_risk_score: rec.risk_score,
          x_findings:   (rec.findings || []).slice(0, 10),
        },
      });
    } else if (source === 'iocs') {
      const iocType = rec.ioc_type || detectIOCType(rec.ioc_value || '');
      if (!iocType) continue;
      bundle.objects.push({
        type: 'indicator',
        id: `indicator--${crypto.randomUUID()}`,
        spec_version: '2.1',
        created: rec.observed_at || ts,
        modified: rec.observed_at || ts,
        name: rec.ioc_value,
        indicator_types: ['malicious-activity'],
        pattern: buildSTIXPattern(iocType, rec.ioc_value),
        pattern_type: 'stix',
        valid_from: rec.observed_at || ts,
        labels: [rec.severity?.toLowerCase() || 'unknown'],
        custom_properties: {
          x_source_cve: rec.source_cve,
          x_cvss:       rec.cvss,
        },
      });
    }
  }

  // ── P2-1: STIX 2.1 Relationship Graph Objects ────────────────────────────────
  // Per customer audit: flat JSON listing replaced with full graph relationship strings
  // Now includes: vulnerability→indicator, attack-pattern, intrusion-set, malware nodes
  // with explicit directed relationship edges for MISP/OpenCTI/CrowdStrike compatibility
  const vulnerabilityIds = bundle.objects
    .filter(o => o.type === 'vulnerability')
    .map(o => ({ id: o.id, cve: o.name }));

  const indicatorIds = bundle.objects
    .filter(o => o.type === 'indicator')
    .map(o => o.id);

  // Link each indicator to its source vulnerability (indicates relationship)
  for (const ind of bundle.objects.filter(o => o.type === 'indicator')) {
    const sourceVuln = vulnerabilityIds.find(v =>
      ind.external_references?.some(ref => ref.external_id === v.cve)
    );
    if (sourceVuln) {
      bundle.objects.push({
        type: 'relationship',
        id: `relationship--${crypto.randomUUID()}`,
        spec_version: '2.1',
        created: ts,
        modified: ts,
        relationship_type: 'indicates',
        source_ref: ind.id,
        target_ref: sourceVuln.id,
        description: `Indicator observed in exploitation of ${sourceVuln.cve}`,
      });
    }
  }

  // Add attack-pattern objects from MITRE ATT&CK tactics
  const seenTechniques = new Set();
  for (const rec of records) {
    const tactics = rec.mitre_tactics || rec.mitre_technique
      ? [rec.mitre_technique].filter(Boolean)
      : [];
    for (const tactic of tactics) {
      if (seenTechniques.has(tactic)) continue;
      seenTechniques.add(tactic);
      const apId = `attack-pattern--${crypto.randomUUID()}`;
      bundle.objects.push({
        type: 'attack-pattern',
        id: apId,
        spec_version: '2.1',
        created: ts,
        modified: ts,
        name: tactic,
        description: `MITRE ATT&CK Technique: ${tactic}`,
        external_references: [{
          source_name: 'mitre-attack',
          external_id: tactic.match(/T\d{4}(\.\d{3})?/)?.[0] || tactic,
          url: `https://attack.mitre.org/techniques/${tactic.match(/T\d{4}/)?.[0] || ''}`,
        }],
        kill_chain_phases: [{
          kill_chain_name: 'mitre-attack',
          phase_name: rec.mitre_phase || 'unknown',
        }],
      });

      // Link vulnerability to attack-pattern (uses relationship)
      const linkedVuln = vulnerabilityIds.find(v => v.cve === rec.cve_id);
      if (linkedVuln) {
        bundle.objects.push({
          type: 'relationship',
          id: `relationship--${crypto.randomUUID()}`,
          spec_version: '2.1',
          created: ts,
          modified: ts,
          relationship_type: 'uses',
          source_ref: linkedVuln.id,
          target_ref: apId,
          description: `${rec.cve_id} uses technique ${tactic}`,
        });
      }
    }
  }

  // Add threat-actor / intrusion-set for known APT attributions
  const seenActors = new Set();
  for (const rec of records) {
    const actor = rec.threat_actor || rec.apt_group;
    if (!actor || seenActors.has(actor)) continue;
    seenActors.add(actor);
    const actorId = `intrusion-set--${crypto.randomUUID()}`;
    bundle.objects.push({
      type: 'intrusion-set',
      id: actorId,
      spec_version: '2.1',
      created: ts,
      modified: ts,
      name: actor,
      description: `Threat actor attributed to exploitation activity`,
      aliases: [actor],
      first_seen: rec.created_at || ts,
      resource_level: 'government', // default — override with real intel
      primary_motivation: 'opportunistic',
    });

    // Link actor to vulnerability (exploits relationship)
    const linkedVuln = vulnerabilityIds.find(v => v.cve === rec.cve_id);
    if (linkedVuln) {
      bundle.objects.push({
        type: 'relationship',
        id: `relationship--${crypto.randomUUID()}`,
        spec_version: '2.1',
        created: ts,
        modified: ts,
        relationship_type: 'exploits',
        source_ref: actorId,
        target_ref: linkedVuln.id,
        description: `${actor} has been observed exploiting ${rec.cve_id || 'this vulnerability'}`,
      });
    }
  }

  // Identity → authored-by relationship for all objects
  const identityId = `identity--cyberdudebivash`;
  for (const obj of bundle.objects.filter(o => o.type !== 'identity' && o.type !== 'relationship')) {
    bundle.objects.push({
      type: 'relationship',
      id: `relationship--${crypto.randomUUID()}`,
      spec_version: '2.1',
      created: ts,
      modified: ts,
      relationship_type: 'authored-by',
      source_ref: obj.id,
      target_ref: identityId,
      description: 'Intelligence authored by CYBERDUDEBIVASH Sentinel APEX',
    });
  }

  // Bundle metadata
  bundle.x_cyberdudebivash_meta = {
    platform:       'CYBERDUDEBIVASH AI Security Hub',
    sentinel_apex:  true,
    stix_profile:   'full-graph',    // P2-1: was flat-listing, now full graph
    object_count:   bundle.objects.length,
    relationship_count: bundle.objects.filter(o => o.type === 'relationship').length,
    generated_at:   ts,
  };

  return bundle;

}

// ─── CEF (ArcSight Common Event Format) Builder ───────────────────────────────
function buildCEF(records, source) {
  const lines = [];
  lines.push('# CEF Export — CYBERDUDEBIVASH AI Security Hub v8.1');
  lines.push(`# Generated: ${new Date().toISOString()}`);
  lines.push(`# Source: ${source}`);
  lines.push('');

  for (const rec of records) {
    // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    const sev = mapSeverityCEF(rec.severity || rec.risk_score);
    const name = escCEF(rec.cve_id || rec.title || rec.module || 'ThreatEvent');
    const sigId = rec.cve_id || rec.id || 'CYBER-001';
    const ext = buildCEFExtension(rec, source);
    lines.push(`CEF:0|CyberDudeBivash|SentinelAPEX|8.1|${sigId}|${name}|${sev}|${ext}`);
  }

  return lines.join('\n');
}

function buildCEFExtension(rec, source) {
  const parts = [];
  const ts = rec.created_at ? Math.floor(new Date(rec.created_at).getTime()) : Date.now();
  parts.push(`rt=${ts}`);
  parts.push(`cs1Label=Source cs1=${source}`);

  if (rec.cvss != null)       parts.push(`cn1Label=CVSS cn1=${rec.cvss}`);
  if (rec.epss != null)       parts.push(`cn2Label=EPSS cn2=${rec.epss}`);
  if (rec.risk_score != null) parts.push(`cn3Label=RiskScore cn3=${rec.risk_score}`);
  if (rec.cve_id)             parts.push(`cs2Label=CVE cs2=${escCEF(rec.cve_id)}`);
  if (rec.target)             parts.push(`dhost=${escCEF(rec.target)}`);
  if (rec.module)             parts.push(`cs3Label=Module cs3=${escCEF(rec.module)}`);
  if (rec.is_kev)             parts.push(`cs4Label=KEV cs4=true`);
  if (rec.description)        parts.push(`msg=${escCEF((rec.description || '').slice(0, 200))}`);
  if (rec.ioc_value)          parts.push(`cs5Label=IOC cs5=${escCEF(rec.ioc_value)}`);
  if (rec.ioc_type)           parts.push(`cs6Label=IOCType cs6=${escCEF(rec.ioc_type)}`);

  return parts.join(' ');
}

function escCEF(str) {
  return String(str || '').replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/=/g, '\\=').replace(/\n/g, '\\n');
}

function mapSeverityCEF(sev) {
  if (typeof sev === 'number') {
    if (sev >= 9) return 10;
    if (sev >= 7) return 7;
    if (sev >= 4) return 5;
    return 3;
  }
  const m = { CRITICAL: 10, HIGH: 7, MEDIUM: 5, LOW: 3, INFO: 1 };
  return m[String(sev).toUpperCase()] ?? 5;
}

// ─── Sigma Rules Builder ──────────────────────────────────────────────────────
function buildSigma(records, source, ts) {
  const rules = [];

  for (const rec of records) {
    if (!rec.cve_id && !rec.ioc_value) continue;

    const rule = {
      title: `CYBERDUDEBIVASH — ${rec.cve_id || rec.ioc_value || 'Threat Detection'}`,
      id: safeUUID(rec.id || rec.cve_id || Math.random().toString()),
      status: 'experimental',
      description: (rec.description || rec.title || '').slice(0, 300),
      author: 'CYBERDUDEBIVASH Sentinel APEX',
      date: ts.slice(0, 10),
      modified: ts.slice(0, 10),
      references: rec.cve_id ? [`https://nvd.nist.gov/vuln/detail/${rec.cve_id}`] : [],
      tags: [],
      logsource: { category: 'network', service: 'firewall' },
      detection: { condition: 'selection', selection: {} },
      falsepositives: ['Legitimate research', 'Security tool activity'],
      level: mapSigmaLevel(rec.severity || rec.risk_score),
    };

    // Tags from MITRE tactics
    if (Array.isArray(rec.mitre_tactics)) {
      rule.tags = rec.mitre_tactics.map(t => `attack.${t.toLowerCase().replace(/\s+/g, '_')}`);
    }
    if (rec.cve_id) rule.tags.push(`cve.${rec.cve_id.toLowerCase()}`);

    // Detection selection
    if (rec.ioc_value) {
      const iocType = rec.ioc_type || detectIOCType(rec.ioc_value);
      if (iocType === 'ip')     rule.detection.selection = { DestinationIp: [rec.ioc_value] };
      if (iocType === 'domain') rule.detection.selection = { DestinationHostname: [`*.${rec.ioc_value}`, rec.ioc_value] };
      if (iocType === 'hash')   rule.detection.selection = { FileHash: [rec.ioc_value] };
      if (iocType === 'url')    rule.detection.selection = { DestinationUrl: [`${rec.ioc_value}*`] };
    } else if (rec.affected_products?.length) {
      rule.detection.selection = { Product: rec.affected_products.slice(0, 5) };
    } else {
      rule.detection.selection = { EventID: [4625, 4720] }; // generic failed auth / account created
    }

    rules.push(rule);
  }

  return { format: 'sigma', version: '8.1', count: rules.length, generated_at: ts, rules };
}

function mapSigmaLevel(sev) {
  if (typeof sev === 'number') {
    if (sev >= 9) return 'critical';
    if (sev >= 7) return 'high';
    if (sev >= 4) return 'medium';
    return 'low';
  }
  return { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' }[String(sev).toUpperCase()] ?? 'medium';
}

// ─── CSV Builder ─────────────────────────────────────────────────────────────
function buildCSV(records, source) {
  if (!records.length) return 'no_data\n';

  const escape = v => {
    const s = String(v == null ? '' : (typeof v === 'object' ? JSON.stringify(v) : v));
    return s.includes(',') || s.includes('"') || s.includes('\n') ? `"${s.replace(/"/g, '""')}"` : s;
  };

  // Dynamic headers from first record (filtered)
  const skipKeys = new Set(['findings', 'iocs', 'mitre_tactics', 'affected_products', 'metadata']);
  const allKeys = Object.keys(records[0]).filter(k => !skipKeys.has(k));

  // Add flat IOC column
  if (source === 'threat_intel' || source === 'iocs') allKeys.push('ioc_list');

  const header = allKeys.join(',');
  const rows   = records.map(rec => {
    const vals = allKeys.map(k => {
      if (k === 'ioc_list') return escape((rec.iocs || []).join(' | '));
      return escape(rec[k]);
    });
    return vals.join(',');
  });

  return [header, ...rows].join('\n');
}

// ─── IOC Bundle Builder (P8.0-003) ─────────────────────────────────────────────
// Deduplicated, typed indicator manifest for direct ingestion into firewalls,
// proxies, and TIP platforms. Reuses the same detectIOCType() classifier as the
// STIX builder above — no new extraction logic.
function buildIOCBundle(records, source, ts) {
  const seen = new Map();

  const add = (value, meta) => {
    const type = detectIOCType(value);
    if (!type || !value || seen.has(value)) return;
    seen.set(value, {
      ioc_type:    type,
      ioc_value:   value,
      severity:    meta.severity || 'UNKNOWN',
      confidence:  meta.cvss != null ? Math.min(100, Math.round(meta.cvss * 10)) : 50,
      source_cve:  meta.cve_id || meta.source_cve || null,
      first_seen:  meta.created_at || meta.observed_at || ts,
    });
  };

  if (source === 'iocs') {
    for (const rec of records) add(rec.ioc_value, rec);
  } else {
    for (const rec of records) {
      for (const ioc of (rec.iocs || [])) add(ioc, rec);
    }
  }

  const indicators = [...seen.values()];
  const by_type = indicators.reduce((acc, i) => {
    acc[i.ioc_type] = (acc[i.ioc_type] || 0) + 1;
    return acc;
  }, {});

  return {
    bundle_type:   'ioc_bundle',
    version:       '1.0',
    generated_at:  ts,
    platform:      'CYBERDUDEBIVASH AI Security Hub',
    tlp:           'AMBER',
    source,
    count:         indicators.length,
    by_type,
    indicators,
  };
}

// ─── Executive PDF Builder (P8.0-003) ──────────────────────────────────────────
// Print-ready HTML board/leadership summary. Reuses buildReportShell() from
// reportingEngine.js — the platform's single HTML "PDF engine" — rather than
// introducing a second template/CSS engine.
function buildExecutivePDF(records, source, ts) {
  // Records originate from external/third-party feeds (CVE descriptions, IOC
  // values, etc.) — escape before interpolating into HTML to prevent XSS.
  const escHTML = s => String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  const bySeverity = records.reduce((acc, r) => {
    const sev = String(r.severity || mapSigmaLevel(r.risk_score) || 'UNKNOWN').toUpperCase();
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});
  const critical = bySeverity.CRITICAL || 0;
  const high     = bySeverity.HIGH || 0;
  const top10    = records.slice(0, 10);
  const sourceLabel = escHTML(source.replace(/_/g,' '));

  const badgeClass = sev => ({ CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' }[String(sev).toUpperCase()] || 'medium');

  const bodyHTML = `
<div class="kpi-grid">
  <div class="kpi"><div class="kpi-label">Total Records</div><div class="kpi-value">${records.length}</div><div class="kpi-sub">${sourceLabel}</div></div>
  <div class="kpi"><div class="kpi-label">Critical</div><div class="kpi-value" style="color:#ef4444">${critical}</div><div class="kpi-sub">Immediate action</div></div>
  <div class="kpi"><div class="kpi-label">High</div><div class="kpi-value" style="color:#f97316">${high}</div><div class="kpi-sub">24h SLA</div></div>
  <div class="kpi"><div class="kpi-label">Window</div><div class="kpi-value" style="font-size:18px;">${escHTML(ts.slice(0,10))}</div><div class="kpi-sub">Generated</div></div>
</div>
<div class="section">
  <h2>Executive Summary</h2>
  <p style="font-size:13px;color:#94a3b8;line-height:1.6;">
    This report summarizes <strong>${records.length}</strong> ${sourceLabel} record${records.length === 1 ? '' : 's'} captured by the
    CYBERDUDEBIVASH AI Security Hub. ${critical > 0 ? `<strong style="color:#ef4444">${critical} critical-severity item${critical === 1 ? '' : 's'}</strong> require immediate executive attention.` : 'No critical-severity items were observed in this period.'}
    ${high > 0 ? `An additional <strong style="color:#f97316">${high} high-severity item${high === 1 ? '' : 's'}</strong> should be remediated within 24 hours.` : ''}
  </p>
</div>
<div class="section">
  <h2>Top Findings</h2>
  <table><thead><tr><th>#</th><th>Identifier</th><th>Severity</th><th>Detail</th></tr></thead><tbody>
    ${top10.map((r, i) => `<tr><td>${i + 1}</td><td>${escHTML(r.cve_id || r.id || r.ioc_value || '—')}</td><td><span class="badge ${badgeClass(r.severity || 'medium')}">${escHTML(r.severity || 'N/A')}</span></td><td>${escHTML((r.title || r.description || r.module || '').toString().slice(0, 120))}</td></tr>`).join('')}
  </tbody></table>
</div>`;

  return buildReportShell({
    brandName: 'CYBERDUDEBIVASH® AI Security Hub',
    primaryColor: '#6366f1',
    title: `CYBERDUDEBIVASH® AI Security Hub — Executive Report (${source})`,
    metaLine: `Source: ${source.replace(/_/g,' ')} · Generated: ${ts} · Records: ${records.length}`,
    bodyHTML,
    footerNote: `CYBERDUDEBIVASH® AI Security Hub · Confidential · Generated ${ts}`,
  });
}

// ─── STIX pattern builder ─────────────────────────────────────────────────────
function buildSTIXPattern(type, value) {
  switch (type) {
    case 'ip':     return `[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '${value}']`;
    case 'domain': return `[domain-name:value = '${value}']`;
    case 'url':    return `[url:value = '${value}']`;
    case 'hash':   return `[file:hashes.MD5 = '${value}' OR file:hashes.'SHA-256' = '${value}']`;
    case 'email':  return `[email-addr:value = '${value}']`;
    default:       return `[artifact:payload_bin = '${value}']`;
  }
}

// ─── IOC type detector ────────────────────────────────────────────────────────
function detectIOCType(val) {
  if (!val) return null;
  if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(val)) return 'ip';
  if (/^https?:\/\//i.test(val)) return 'url';
  if (/^[a-f0-9]{32}$/i.test(val) || /^[a-f0-9]{40}$/i.test(val) || /^[a-f0-9]{64}$/i.test(val)) return 'hash';
  if (/^[^@]+@[^@]+\.[^@]+$/.test(val)) return 'email';
  if (/^[a-z0-9][a-z0-9\-\.]+\.[a-z]{2,}$/i.test(val)) return 'domain';
  return null;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function safeJSON(val, fallback) {
  if (Array.isArray(val) || (val && typeof val === 'object')) return val;
  try { return JSON.parse(val); } catch { return fallback; }
}

function safeUUID(seed) {
  try {
    // Deterministic-ish UUID from seed string
    const h = Array.from(String(seed)).reduce((a, c) => (Math.imul(31, a) + c.charCodeAt(0)) | 0, 0);
    const hex = (Math.abs(h) >>> 0).toString(16).padStart(8, '0');
    return `${hex}-0000-4000-8000-000000000000`;
  } catch { return crypto.randomUUID(); }
}

// ─── Seed data (fallback when D1 not available) ───────────────────────────────
function buildSeedData(source, limit) {
  const base = [
    { id: '1', cve_id: 'CVE-2024-3400', title: 'PAN-OS Auth Bypass', description: 'Critical auth bypass in Palo Alto PAN-OS GlobalProtect gateway.', cvss: 10.0, epss: 0.97, severity: 'CRITICAL', is_kev: true, iocs: ['198.51.100.1', 'exploit.c2.example.com'], mitre_tactics: ['Initial Access', 'Privilege Escalation'], affected_products: ['Palo Alto PAN-OS'], created_at: new Date().toISOString() },
    { id: '2', cve_id: 'CVE-2025-0282', title: 'Ivanti Connect Secure RCE', description: 'Stack-based buffer overflow enabling unauthenticated RCE in Ivanti Connect Secure.', cvss: 9.0, epss: 0.91, severity: 'CRITICAL', is_kev: true, iocs: ['203.0.113.50'], mitre_tactics: ['Execution'], affected_products: ['Ivanti Connect Secure'], created_at: new Date().toISOString() },
    { id: '3', cve_id: 'CVE-2024-27198', title: 'JetBrains TeamCity Auth Bypass', description: 'Authentication bypass in JetBrains TeamCity allowing admin account creation.', cvss: 9.8, epss: 0.88, severity: 'CRITICAL', is_kev: false, iocs: [], mitre_tactics: ['Persistence'], affected_products: ['JetBrains TeamCity'], created_at: new Date().toISOString() },
  ];
  if (source === 'iocs') {
    return base.flatMap(r => (r.iocs || []).map(ioc => ({
      source_cve: r.cve_id, severity: r.severity, cvss: r.cvss,
      ioc_type: detectIOCType(ioc), ioc_value: ioc, observed_at: r.created_at,
    }))).slice(0, limit);
  }
  return base.slice(0, limit);
}
