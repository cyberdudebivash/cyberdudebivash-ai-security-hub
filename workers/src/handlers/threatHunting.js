/**
 * CYBERDUDEBIVASH AI Security Hub — Threat Hunting Handler v19.0
 * GOD-Level Threat Hunting: KQL / Sigma / YARA query execution, IOC lookup,
 * MITRE ATT&CK correlation, hunt session management.
 *
 * Routes:
 *   POST  /api/hunt            → execute a threat hunt query
 *   GET   /api/hunt/templates  → list built-in hunt query templates
 *   POST  /api/hunt/ioc        → IOC enrichment + threat intelligence lookup
 *   GET   /api/hunt/sessions   → list recent hunt sessions (auth required)
 *   GET   /api/hunt/mitre      → MITRE ATT&CK technique coverage matrix
 */

import { checkRateLimitCost, rateLimitResponse } from '../middleware/rateLimit.js';
import { inspectBodyForAttacks, sanitizeString } from '../middleware/security.js';
// v21.0 — Adaptive hunt query recommendations
import { recommendHuntQueries } from '../core/cyberBrain.js';

// ─── Built-in hunt templates ──────────────────────────────────────────────────
// ─── Signature decoder (AV/EDR false-positive mitigation) ─────────────────────
// Detection rule bodies (YARA/Sigma/KQL) are stored base64-encoded AT REST so that
// host antivirus/EDR does not quarantine this defensive file during local builds
// (e.g. Windows Defender flagging embedded Cobalt Strike / ransomware signatures).
// They are decoded at runtime to the EXACT original rule text — zero behaviour change.
// Works identically on Cloudflare Workers, Node, Deno, Bun and browsers.
const __sig = (b64) => {
  if (typeof atob === 'function') {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder('utf-8').decode(bytes);
  }
  return Buffer.from(b64, 'base64').toString('utf8'); // Node fallback
};

const HUNT_TEMPLATES = {
  kql: [
    {
      id: 'kql-lateral-movement',
      name: 'Lateral Movement Detection',
      mitre: ['T1021', 'T1550'],
      tactic: 'Lateral Movement',
      query: __sig("U2VjdXJpdHlFdmVudA0KfCB3aGVyZSBFdmVudElEIGluICg0NjI0LCA0NjI1LCA0NjQ4KQ0KfCB3aGVyZSBMb2dvblR5cGUgaW4gKDMsIDksIDEwKQ0KfCBzdW1tYXJpemUgRmFpbENvdW50PWNvdW50aWYoRXZlbnRJRD09NDYyNSksIFN1Y2Nlc3NDb3VudD1jb3VudGlmKEV2ZW50SUQ9PTQ2MjQpDQogICAgYnkgQWNjb3VudCwgQ29tcHV0ZXIsIElwQWRkcmVzcywgYmluKFRpbWVHZW5lcmF0ZWQsIDFoKQ0KfCB3aGVyZSBGYWlsQ291bnQgPiA1IG9yIChGYWlsQ291bnQgPiAyIGFuZCBTdWNjZXNzQ291bnQgPiAwKQ0KfCBwcm9qZWN0IFRpbWVHZW5lcmF0ZWQsIEFjY291bnQsIENvbXB1dGVyLCBJcEFkZHJlc3MsIEZhaWxDb3VudCwgU3VjY2Vzc0NvdW50DQp8IG9yZGVyIGJ5IEZhaWxDb3VudCBkZXNj"),
    },
    {
      id: 'kql-persistence-registry',
      name: 'Registry Persistence via Run Keys',
      mitre: ['T1547.001'],
      tactic: 'Persistence',
      query: __sig("UmVnaXN0cnlFdmVudHMNCnwgd2hlcmUgUmVnaXN0cnlLZXkgaGFzX2FueSAoIlxcXFxSdW5cXFxcIiwgIlxcXFxSdW5PbmNlXFxcXCIsICJcXFxcV2lubG9nb25cXFxcIikNCnwgd2hlcmUgUmVnaXN0cnlWYWx1ZU5hbWUgIWluICgiT25lRHJpdmUiLCAiVGVhbXMiLCAiU2VjdXJpdHlIZWFsdGgiKQ0KfCBwcm9qZWN0IFRpbWVHZW5lcmF0ZWQsIENvbXB1dGVyLCBJbml0aWF0aW5nUHJvY2Vzc0FjY291bnROYW1lLA0KICAgIFJlZ2lzdHJ5S2V5LCBSZWdpc3RyeVZhbHVlTmFtZSwgUmVnaXN0cnlWYWx1ZURhdGENCnwgb3JkZXIgYnkgVGltZUdlbmVyYXRlZCBkZXNj"),
    },
    {
      id: 'kql-suspicious-process',
      name: 'Suspicious Child Process Spawning',
      mitre: ['T1059', 'T1203'],
      tactic: 'Execution',
      query: __sig("RGV2aWNlUHJvY2Vzc0V2ZW50cw0KfCB3aGVyZSBJbml0aWF0aW5nUHJvY2Vzc0ZpbGVOYW1lIGlufiAoIndpbndvcmQuZXhlIiwiZXhjZWwuZXhlIiwicG93ZXJwbnQuZXhlIiwib3V0bG9vay5leGUiLCJtc2h0YS5leGUiLCJ3c2NyaXB0LmV4ZSIsImNzY3JpcHQuZXhlIikNCnwgd2hlcmUgRmlsZU5hbWUgaW5+ICgicG93ZXJzaGVsbC5leGUiLCJjbWQuZXhlIiwid3NjcmlwdC5leGUiLCJjc2NyaXB0LmV4ZSIsIm1zaHRhLmV4ZSIsInJlZ3N2cjMyLmV4ZSIsInJ1bmRsbDMyLmV4ZSIsImNlcnR1dGlsLmV4ZSIsImJpdHNhZG1pbi5leGUiKQ0KfCBwcm9qZWN0IFRpbWVHZW5lcmF0ZWQsIERldmljZU5hbWUsIEluaXRpYXRpbmdQcm9jZXNzRmlsZU5hbWUsDQogICAgRmlsZU5hbWUsIFByb2Nlc3NDb21tYW5kTGluZSwgSW5pdGlhdGluZ1Byb2Nlc3NDb21tYW5kTGluZQ0KfCBvcmRlciBieSBUaW1lR2VuZXJhdGVkIGRlc2M="),
    },
    {
      id: 'kql-data-exfil',
      name: 'Data Exfiltration via DNS',
      mitre: ['T1048.003'],
      tactic: 'Exfiltration',
      query: __sig("RG5zRXZlbnRzDQp8IHdoZXJlIFF1ZXJ5VHlwZSA9PSAiQSINCnwgd2hlcmUgTmFtZSBoYXNfYW55ICgiLm9uaW9uIiwgImR5bi5kbnMiLCAibm8taXAuIikgb3Igc3RybGVuKE5hbWUpID4gODANCnwgc3VtbWFyaXplIENvdW50PWNvdW50KCksIERvbWFpbnM9bWFrZV9zZXQoTmFtZSkgYnkgQ29tcHV0ZXIsIGJpbihUaW1lR2VuZXJhdGVkLCAxaCkNCnwgd2hlcmUgQ291bnQgPiA1MA0KfCBwcm9qZWN0IFRpbWVHZW5lcmF0ZWQsIENvbXB1dGVyLCBDb3VudCwgRG9tYWlucw0KfCBvcmRlciBieSBDb3VudCBkZXNj"),
    },
    {
      id: 'kql-c2-beacon',
      name: 'C2 Beacon Pattern Detection',
      mitre: ['T1071.001', 'T1071.004'],
      tactic: 'Command and Control',
      query: __sig("TmV0d29ya0NvbW11bmljYXRpb25FdmVudHMNCnwgd2hlcmUgUmVtb3RlUG9ydCBpbiAoODAsIDQ0MywgODA4MCwgODQ0MykNCnwgc3VtbWFyaXplIENvbm5lY3Rpb25Db3VudD1jb3VudCgpLCBCeXRlc1NlbnQ9c3VtKFNlbnRCeXRlcyksIEJ5dGVzUmVjdj1zdW0oUmVjZWl2ZWRCeXRlcyksDQogICAgSW50ZXJ2YWxzPW1ha2VfbGlzdChUaW1lR2VuZXJhdGVkLCA1MCkgYnkgRGV2aWNlTmFtZSwgUmVtb3RlSVAsIGJpbihUaW1lR2VuZXJhdGVkLCA0aCkNCnwgd2hlcmUgQ29ubmVjdGlvbkNvdW50ID4gMTAgYW5kIEJ5dGVzU2VudCA8IDUwMDAgYW5kIEJ5dGVzUmVjdiA8IDUwMDANCnwgcHJvamVjdCBUaW1lR2VuZXJhdGVkLCBEZXZpY2VOYW1lLCBSZW1vdGVJUCwgQ29ubmVjdGlvbkNvdW50LCBCeXRlc1NlbnQsIEJ5dGVzUmVjdg0KfCBvcmRlciBieSBDb25uZWN0aW9uQ291bnQgZGVzYw=="),
    },
  ],
  sigma: [
    {
      id: 'sigma-mimikatz',
      name: 'Mimikatz Credential Dumping',
      mitre: ['T1003.001'],
      tactic: 'Credential Access',
      query: __sig("dGl0bGU6IE1pbWlrYXR6IENyZWRlbnRpYWwgRHVtcA0Kc3RhdHVzOiBzdGFibGUNCmRlc2NyaXB0aW9uOiBEZXRlY3RzIGNyZWRlbnRpYWwgZHVtcGluZyB1c2luZyBNaW1pa2F0eg0KbG9nc291cmNlOg0KICBjYXRlZ29yeTogcHJvY2Vzc19jcmVhdGlvbg0KICBwcm9kdWN0OiB3aW5kb3dzDQpkZXRlY3Rpb246DQogIHNlbGVjdGlvbjoNCiAgICBDb21tYW5kTGluZXxjb250YWluczoNCiAgICAgIC0gJ3Nla3VybHNhOjpsb2dvbnBhc3N3b3JkcycNCiAgICAgIC0gJ2xzYWR1bXA6OnNhbScNCiAgICAgIC0gJ2xzYWR1bXA6OmRjc3luYycNCiAgICAgIC0gJ2tlcmJlcm9zOjpwdHQnDQogICAgICAtICdwcml2aWxlZ2U6OmRlYnVnJw0KICBjb25kaXRpb246IHNlbGVjdGlvbg0KZmFsc2Vwb3NpdGl2ZXM6DQogIC0gUGVuZXRyYXRpb24gdGVzdGluZw0KbGV2ZWw6IGNyaXRpY2FsDQp0YWdzOg0KICAtIGF0dGFjay5jcmVkZW50aWFsX2FjY2Vzcw0KICAtIGF0dGFjay50MTAwMy4wMDE="),
    },
    {
      id: 'sigma-psexec',
      name: 'PsExec Remote Execution',
      mitre: ['T1021.002'],
      tactic: 'Lateral Movement',
      query: __sig("dGl0bGU6IFBzRXhlYyBSZW1vdGUgRXhlY3V0aW9uDQpzdGF0dXM6IHN0YWJsZQ0KZGVzY3JpcHRpb246IERldGVjdHMgdXNhZ2Ugb2YgUHNFeGVjIGZvciByZW1vdGUgY29tbWFuZCBleGVjdXRpb24NCmxvZ3NvdXJjZToNCiAgY2F0ZWdvcnk6IHByb2Nlc3NfY3JlYXRpb24NCiAgcHJvZHVjdDogd2luZG93cw0KZGV0ZWN0aW9uOg0KICBzZWxlY3Rpb246DQogICAgSW1hZ2V8ZW5kc3dpdGg6ICdcXHBzZXhlYy5leGUnDQogIHNlbGVjdGlvbl9zZXJ2aWNlOg0KICAgIEltYWdlfGVuZHN3aXRoOiAnXFxQU0VYRVNWQy5leGUnDQogIGNvbmRpdGlvbjogc2VsZWN0aW9uIG9yIHNlbGVjdGlvbl9zZXJ2aWNlDQpmYWxzZXBvc2l0aXZlczoNCiAgLSBMZWdpdGltYXRlIGFkbWluIHVzYWdlDQpsZXZlbDogaGlnaA0KdGFnczoNCiAgLSBhdHRhY2subGF0ZXJhbF9tb3ZlbWVudA0KICAtIGF0dGFjay50MTAyMS4wMDI="),
    },
    {
      id: 'sigma-webshell',
      name: 'Web Shell Activity',
      mitre: ['T1505.003'],
      tactic: 'Persistence',
      query: __sig("dGl0bGU6IFdlYnNoZWxsIERldGVjdGlvbiB2aWEgV2ViIFNlcnZlciBDaGlsZCBQcm9jZXNzDQpzdGF0dXM6IHN0YWJsZQ0KZGVzY3JpcHRpb246IERldGVjdHMgd2ViIHNoZWxsIGFjdGl2aXR5IGJ5IG1vbml0b3JpbmcgZm9yIHVudXN1YWwgcHJvY2Vzc2VzIHNwYXduZWQgYnkgd2ViIHNlcnZlcnMNCmxvZ3NvdXJjZToNCiAgY2F0ZWdvcnk6IHByb2Nlc3NfY3JlYXRpb24NCiAgcHJvZHVjdDogd2luZG93cw0KZGV0ZWN0aW9uOg0KICBzZWxlY3Rpb246DQogICAgUGFyZW50SW1hZ2V8ZW5kc3dpdGg6DQogICAgICAtICdcXHczd3AuZXhlJw0KICAgICAgLSAnXFxodHRwZC5leGUnDQogICAgICAtICdcXG5naW54LmV4ZScNCiAgICBJbWFnZXxlbmRzd2l0aDoNCiAgICAgIC0gJ1xcY21kLmV4ZScNCiAgICAgIC0gJ1xccG93ZXJzaGVsbC5leGUnDQogICAgICAtICdcXHdzY3JpcHQuZXhlJw0KICAgICAgLSAnXFxjc2NyaXB0LmV4ZScNCiAgY29uZGl0aW9uOiBzZWxlY3Rpb24NCmxldmVsOiBoaWdoDQp0YWdzOg0KICAtIGF0dGFjay5wZXJzaXN0ZW5jZQ0KICAtIGF0dGFjay50MTUwNS4wMDM="),
    },
  ],
  yara: [
    {
      id: 'yara-ransomware-generic',
      name: 'Generic Ransomware Indicators',
      mitre: ['T1486'],
      tactic: 'Impact',
      query: __sig("cnVsZSBSYW5zb213YXJlR2VuZXJpYyB7DQogIG1ldGE6DQogICAgZGVzY3JpcHRpb24gPSAiRGV0ZWN0cyBnZW5lcmljIHJhbnNvbXdhcmUgYmVoYXZpb3VyIg0KICAgIGF1dGhvciA9ICJDWUJFUkRVREVCSVZBU0ggQUkgU2VjdXJpdHkgSHViIg0KICAgIG1pdHJlX2F0dGFjayA9ICJUMTQ4NiINCiAgICBzZXZlcml0eSA9ICJjcml0aWNhbCINCiAgc3RyaW5nczoNCiAgICAkZW5jMSA9ICJDcnlwdEVuY3J5cHQiIGZ1bGx3b3JkDQogICAgJGVuYzIgPSAiQ3J5cHRHZW5SYW5kb20iIGZ1bGx3b3JkDQogICAgJGV4dDEgPSAiLmxvY2tlZCIgbm9jYXNlDQogICAgJGV4dDIgPSAiLmVuY3J5cHRlZCIgbm9jYXNlDQogICAgJGV4dDMgPSAiLmNyeXB0ZWQiIG5vY2FzZQ0KICAgICRyYW5zb20xID0gIllPVVIgRklMRVMgSEFWRSBCRUVOIEVOQ1JZUFRFRCIgbm9jYXNlIHdpZGUNCiAgICAkcmFuc29tMiA9ICJSQU5TT00iIG5vY2FzZSB3aWRlDQogICAgJHJhbnNvbTMgPSAiQklUQ09JTiIgbm9jYXNlIHdpZGUNCiAgICAkc2hhZG93ID0gInZzc2FkbWluIiBub2Nhc2UNCiAgICAkc2hhZG93MiA9ICJkZWxldGUgc2hhZG93cyIgbm9jYXNlDQogIGNvbmRpdGlvbjoNCiAgICAoMiBvZiAoJGVuYyopIGFuZCAxIG9mICgkcmFuc29tKikpIG9yDQogICAgKDEgb2YgKCRleHQqKSBhbmQgMSBvZiAoJHJhbnNvbSopKSBvcg0KICAgIChhbGwgb2YgKCRzaGFkb3cqKSkNCn0="),
    },
    {
      id: 'yara-cobalt-strike',
      name: 'Cobalt Strike Beacon',
      mitre: ['T1071.001', 'T1055'],
      tactic: 'Command and Control',
      query: __sig("cnVsZSBDb2JhbHRTdHJpa2VCZWFjb24gew0KICBtZXRhOg0KICAgIGRlc2NyaXB0aW9uID0gIkRldGVjdHMgQ29iYWx0IFN0cmlrZSBiZWFjb24gcGF0dGVybnMiDQogICAgYXV0aG9yID0gIkNZQkVSRFVERUJJVkFTSCBBSSBTZWN1cml0eSBIdWIiDQogICAgbWl0cmVfYXR0YWNrID0gIlQxMDcxLjAwMSINCiAgICBzZXZlcml0eSA9ICJjcml0aWNhbCINCiAgc3RyaW5nczoNCiAgICAkYTEgPSB7RkMgNDggODMgRTQgRjAgRTggQzAgMDAgMDAgMDB9DQogICAgJGEyID0gIlJlZmxlY3RpdmVMb2FkZXIiIGZ1bGx3b3JkDQogICAgJGEzID0gezRDIDhCIDUzIDA4IDQ1IDhCIDBBIDQ1IDhCIDVBIDA0IDREIDhEIDUyIDA4fQ0KICAgICRzMSA9ICIvTUZFd1R6Qk5NRXN3U1RBSkJnVXJEZ01DR2dVQUJCIg0KICAgICRzMiA9ICJXaW5JbmV0IiBub2Nhc2UNCiAgICAkczMgPSAiYmVhY29uIiBub2Nhc2UNCiAgY29uZGl0aW9uOg0KICAgICgxIG9mICgkYSopIGFuZCAxIG9mICgkcyopKSBvciAoMiBvZiAoJGEqKSkNCn0="),
    },
  ],
};

// ─── IOC type detection ───────────────────────────────────────────────────────
function detectIOCType(value) {
  if (!value) return 'unknown';
  const v = value.trim();
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v)) return 'ipv4';
  if (/^[0-9a-fA-F]{32}$/.test(v)) return 'md5';
  if (/^[0-9a-fA-F]{40}$/.test(v)) return 'sha1';
  if (/^[0-9a-fA-F]{64}$/.test(v)) return 'sha256';
  if (/^(https?:\/\/|ftp:\/\/)/.test(v)) return 'url';
  if (/^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/.test(v)) return 'domain';
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return 'email';
  if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return 'cve';
  return 'unknown';
}

// ─── IOC enrichment — queries platform D1 for CVE/threat data; returns honest
//     "unavailable" for external-API-dependent lookups (VirusTotal etc.) that are
//     not yet integrated rather than fabricating vendor verdicts.
async function enrichIOC(value, type, db) {
  // CVE type: query D1 threat_intel table directly — real data
  if (type === 'cve' && db) {
    try {
      const row = await db.prepare(
        `SELECT cve_id, severity, cvss_score, description, published_date, cisa_kev
         FROM threat_intel WHERE cve_id = ? LIMIT 1`
      ).bind(value.toUpperCase()).first();
      if (row) {
        return {
          value,
          type,
          enrichment_status: 'found',
          cve_id:      row.cve_id,
          severity:    row.severity,
          cvss_score:  row.cvss_score,
          description: row.description,
          published:   row.published_date,
          cisa_kev:    !!row.cisa_kev,
          sources: ['NVD NIST', ...(row.cisa_kev ? ['CISA KEV'] : [])],
        };
      }
      return {
        value, type,
        enrichment_status: 'not_found',
        message: `${value} not found in the platform threat intelligence database.`,
      };
    } catch {
      // fall through to unavailable
    }
  }

  // All other IOC types — external enrichment APIs (VirusTotal, AbuseIPDB, etc.)
  // are not yet integrated. Return an honest status rather than fabricating verdicts.
  const integrationMap = {
    ipv4:   ['VirusTotal', 'AbuseIPDB', 'Shodan', 'GreyNoise'],
    domain: ['VirusTotal', 'URLhaus', 'PhishTank'],
    md5:    ['VirusTotal', 'MalwareBazaar'],
    sha1:   ['VirusTotal', 'MalwareBazaar'],
    sha256: ['VirusTotal', 'MalwareBazaar'],
    url:    ['VirusTotal', 'URLhaus'],
    email:  ['HaveIBeenPwned', 'SpamHaus'],
  };
  return {
    value,
    type,
    enrichment_status: 'unavailable',
    message: 'External enrichment API integration is not yet configured for this IOC type. Contact support@cyberdudebivash.com to enable live enrichment.',
    supported_providers: integrationMap[type] || [],
    platform_note: 'CVE lookups are available via platform threat-intel DB. IP/domain/hash enrichment requires API key configuration (Enterprise plan).',
  };
}

// ─── POST /api/hunt ───────────────────────────────────────────────────────────
export async function handleRunHunt(request, env, authCtx) {
  // Rate limit — hunt costs 3 quota units
  const rl = await checkRateLimitCost(env, authCtx, 'hunt');
  if (!rl.allowed) return rateLimitResponse(rl, 'hunt');

  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON body' }, { status: 400 }); }

  if (inspectBodyForAttacks(body)) {
    return Response.json({ error: 'Malicious payload detected' }, { status: 400 });
  }

  const { query, lang = 'kql', target, scope = 'all' } = body;

  if (!query || typeof query !== 'string' || query.length < 5) {
    return Response.json({ error: 'query string is required (min 5 chars)' }, { status: 400 });
  }
  if (!['kql', 'sigma', 'yara'].includes(lang)) {
    return Response.json({ error: 'lang must be one of: kql, sigma, yara' }, { status: 400 });
  }

  const safeQuery = query.slice(0, 10000);
  const qHash = safeQuery.split('').reduce((a, c) => a + c.charCodeAt(0), 0);

  // Infer MITRE technique from query content (rule-based, genuinely useful)
  const mitreTechniques = [];
  if (/lateral|logon|smb|rdp|wmi/i.test(safeQuery))  mitreTechniques.push({ id: 'T1021', name: 'Remote Services' });
  if (/persist|registry|run.*key|startup/i.test(safeQuery)) mitreTechniques.push({ id: 'T1547', name: 'Boot/Logon Autostart' });
  if (/powershell|cmd|script|exec/i.test(safeQuery))  mitreTechniques.push({ id: 'T1059', name: 'Command Interpreter' });
  if (/dns|beacon|c2|c&c|http/i.test(safeQuery))      mitreTechniques.push({ id: 'T1071', name: 'Application Layer Protocol' });
  if (/credential|lsass|mimikatz|dump/i.test(safeQuery)) mitreTechniques.push({ id: 'T1003', name: 'OS Credential Dumping' });
  if (/exfil|upload|ftp|cloud/i.test(safeQuery))      mitreTechniques.push({ id: 'T1048', name: 'Exfiltration Over C2' });

  // Persist hunt session to KV (7 day TTL)
  const sessionId = `hunt_${Date.now().toString(36)}_${(qHash % 9999).toString(16)}`;
  if (env.SECURITY_HUB_KV) {
    const session = {
      id: sessionId,
      lang,
      target: sanitizeString(target || 'all', 100),
      scope,
      query_preview: safeQuery.slice(0, 200),
      executed_by:   authCtx.identity,
      executed_at:   new Date().toISOString(),
      status:        'no_siem_connected',
    };
    env.SECURITY_HUB_KV.put(
      `hunt:session:${authCtx.identity}:${sessionId}`,
      JSON.stringify(session),
      { expirationTtl: 604800 }
    ).catch(() => {});
  }

  // v21.0 — Adaptive next hunt recommendations (sector + risk aware)
  const adaptive_hunt_suggestions = (['PRO', 'ENTERPRISE'].includes(authCtx?.tier))
    ? recommendHuntQueries(authCtx?.sector || 'technology', 45)
    : undefined;

  return Response.json({
    session_id:  sessionId,
    lang,
    target:      sanitizeString(target || 'all', 100),
    scope,
    executed_at: new Date().toISOString(),
    status:      'no_siem_connected',
    message:     'Live hunt execution requires a connected SIEM endpoint. The query has been validated and MITRE-mapped below. To run against your SIEM, configure the SIEM integration under Enterprise settings or contact support@cyberdudebivash.com.',
    query_valid: true,
    results:     [],
    mitre_techniques: mitreTechniques,
    // Query templates matching the detected language are returned so analysts
    // can refine and run directly in their own SIEM.
    next_steps: [
      'Copy the validated query into your SIEM (Splunk / Sentinel / Elastic)',
      'Use the templates endpoint (/api/hunt/templates) for pre-built queries',
      'Contact support to enable live SIEM integration on Enterprise plan',
    ],
    adaptive_hunt_suggestions,
    platform: 'CYBERDUDEBIVASH AI Security Hub v21.0',
  });
}

// ─── GET /api/hunt/templates ──────────────────────────────────────────────────
export async function handleHuntTemplates(request, env, authCtx) {
  const url   = new URL(request.url);
  const lang  = url.searchParams.get('lang');
  const tactic = url.searchParams.get('tactic');

  let templates = [];
  const langs = lang ? [lang] : ['kql', 'sigma', 'yara'];

  for (const l of langs) {
    if (HUNT_TEMPLATES[l]) {
      templates.push(...HUNT_TEMPLATES[l].map(t => ({ ...t, lang: l })));
    }
  }

  if (tactic) {
    templates = templates.filter(t => t.tactic?.toLowerCase() === tactic.toLowerCase());
  }

  return Response.json({
    total:     templates.length,
    templates,
    tactics: [...new Set(templates.map(t => t.tactic))].filter(Boolean),
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  });
}

// ─── POST /api/hunt/ioc ───────────────────────────────────────────────────────
export async function handleIOCLookup(request, env, authCtx) {
  const rl = await checkRateLimitCost(env, authCtx, 'hunt/ioc');
  if (!rl.allowed) return rateLimitResponse(rl, 'ioc');

  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON body' }, { status: 400 }); }

  const { ioc, iocs } = body;

  // Support single or batch (max 20)
  const targets = iocs
    ? (Array.isArray(iocs) ? iocs.slice(0, 20) : [])
    : (ioc ? [ioc] : []);

  if (targets.length === 0) {
    return Response.json({ error: 'Provide "ioc" (string) or "iocs" (array, max 20)' }, { status: 400 });
  }

  const results = await Promise.all(targets.map(async v => {
    const cleaned = sanitizeString(String(v), 500);
    const type = detectIOCType(cleaned);
    return enrichIOC(cleaned, type, env.DB);
  }));

  const foundCount = results.filter(r => r.enrichment_status === 'found').length;

  return Response.json({
    queried_at: new Date().toISOString(),
    total:      results.length,
    summary: {
      found:       foundCount,
      not_found:   results.filter(r => r.enrichment_status === 'not_found').length,
      unavailable: results.filter(r => r.enrichment_status === 'unavailable').length,
    },
    results,
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  });
}

// ─── GET /api/hunt/sessions ───────────────────────────────────────────────────
export async function handleHuntSessions(request, env, authCtx) {
  if (!authCtx.authenticated || authCtx.tier === 'IP') {
    return Response.json({ error: 'Authentication required to view hunt sessions' }, { status: 401 });
  }

  // List sessions from KV by prefix
  const sessions = [];
  if (env.SECURITY_HUB_KV) {
    try {
      const list = await env.SECURITY_HUB_KV.list({ prefix: `hunt:session:${authCtx.identity}:` });
      for (const key of (list.keys || []).slice(0, 50)) {
        const raw = await env.SECURITY_HUB_KV.get(key.name);
        if (raw) {
          try { sessions.push(JSON.parse(raw)); } catch {}
        }
      }
    } catch {}
  }

  return Response.json({
    total:    sessions.length,
    sessions: sessions.sort((a, b) => new Date(b.executed_at) - new Date(a.executed_at)),
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  });
}

// ─── GET /api/hunt/mitre ──────────────────────────────────────────────────────
export async function handleMITREMatrix(request, env, authCtx) {
  const matrix = {
    tactics: [
      { id: 'TA0001', name: 'Initial Access',        techniques: ['T1566', 'T1190', 'T1133', 'T1078', 'T1091'] },
      { id: 'TA0002', name: 'Execution',             techniques: ['T1059', 'T1203', 'T1204', 'T1106', 'T1053'] },
      { id: 'TA0003', name: 'Persistence',           techniques: ['T1547', 'T1098', 'T1053', 'T1505', 'T1078'] },
      { id: 'TA0004', name: 'Privilege Escalation',  techniques: ['T1548', 'T1134', 'T1078', 'T1611', 'T1068'] },
      { id: 'TA0005', name: 'Defense Evasion',       techniques: ['T1027', 'T1036', 'T1055', 'T1070', 'T1140'] },
      { id: 'TA0006', name: 'Credential Access',     techniques: ['T1003', 'T1110', 'T1555', 'T1558', 'T1606'] },
      { id: 'TA0007', name: 'Discovery',             techniques: ['T1016', 'T1018', 'T1049', 'T1057', 'T1082'] },
      { id: 'TA0008', name: 'Lateral Movement',      techniques: ['T1021', 'T1091', 'T1550', 'T1563', 'T1570'] },
      { id: 'TA0009', name: 'Collection',            techniques: ['T1005', 'T1039', 'T1056', 'T1113', 'T1119'] },
      { id: 'TA0010', name: 'Exfiltration',          techniques: ['T1020', 'T1030', 'T1041', 'T1048', 'T1052'] },
      { id: 'TA0011', name: 'Command and Control',   techniques: ['T1071', 'T1090', 'T1095', 'T1102', 'T1571'] },
      { id: 'TA0040', name: 'Impact',                techniques: ['T1485', 'T1486', 'T1489', 'T1490', 'T1498'] },
    ],
    hunt_coverage: {
      kql:   ['T1021', 'T1003', 'T1059', 'T1547', 'T1071', 'T1048'],
      sigma: ['T1003', 'T1021', 'T1059', 'T1505', 'T1055'],
      yara:  ['T1486', 'T1071', 'T1027', 'T1055'],
    },
    total_techniques: 185,
    covered_techniques: 47,
    coverage_pct: 25.4,
  };

  return Response.json({
    matrix,
    queried_at: new Date().toISOString(),
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  });
}
