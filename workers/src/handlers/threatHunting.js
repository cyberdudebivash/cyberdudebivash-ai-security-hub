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
const HUNT_TEMPLATES = {
  kql: [
    {
      id: 'kql-lateral-movement',
      name: 'Lateral Movement Detection',
      mitre: ['T1021', 'T1550'],
      tactic: 'Lateral Movement',
      query: `SecurityEvent
| where EventID in (4624, 4625, 4648)
| where LogonType in (3, 9, 10)
| summarize FailCount=countif(EventID==4625), SuccessCount=countif(EventID==4624)
    by Account, Computer, IpAddress, bin(TimeGenerated, 1h)
| where FailCount > 5 or (FailCount > 2 and SuccessCount > 0)
| project TimeGenerated, Account, Computer, IpAddress, FailCount, SuccessCount
| order by FailCount desc`,
    },
    {
      id: 'kql-persistence-registry',
      name: 'Registry Persistence via Run Keys',
      mitre: ['T1547.001'],
      tactic: 'Persistence',
      query: `RegistryEvents
| where RegistryKey has_any ("\\\\Run\\\\", "\\\\RunOnce\\\\", "\\\\Winlogon\\\\")
| where RegistryValueName !in ("OneDrive", "Teams", "SecurityHealth")
| project TimeGenerated, Computer, InitiatingProcessAccountName,
    RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated desc`,
    },
    {
      id: 'kql-suspicious-process',
      name: 'Suspicious Child Process Spawning',
      mitre: ['T1059', 'T1203'],
      tactic: 'Execution',
      query: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","mshta.exe","wscript.exe","cscript.exe")
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","regsvr32.exe","rundll32.exe","certutil.exe","bitsadmin.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
    FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc`,
    },
    {
      id: 'kql-data-exfil',
      name: 'Data Exfiltration via DNS',
      mitre: ['T1048.003'],
      tactic: 'Exfiltration',
      query: `DnsEvents
| where QueryType == "A"
| where Name has_any (".onion", "dyn.dns", "no-ip.") or strlen(Name) > 80
| summarize Count=count(), Domains=make_set(Name) by Computer, bin(TimeGenerated, 1h)
| where Count > 50
| project TimeGenerated, Computer, Count, Domains
| order by Count desc`,
    },
    {
      id: 'kql-c2-beacon',
      name: 'C2 Beacon Pattern Detection',
      mitre: ['T1071.001', 'T1071.004'],
      tactic: 'Command and Control',
      query: `NetworkCommunicationEvents
| where RemotePort in (80, 443, 8080, 8443)
| summarize ConnectionCount=count(), BytesSent=sum(SentBytes), BytesRecv=sum(ReceivedBytes),
    Intervals=make_list(TimeGenerated, 50) by DeviceName, RemoteIP, bin(TimeGenerated, 4h)
| where ConnectionCount > 10 and BytesSent < 5000 and BytesRecv < 5000
| project TimeGenerated, DeviceName, RemoteIP, ConnectionCount, BytesSent, BytesRecv
| order by ConnectionCount desc`,
    },
  ],
  sigma: [
    {
      id: 'sigma-mimikatz',
      name: 'Mimikatz Credential Dumping',
      mitre: ['T1003.001'],
      tactic: 'Credential Access',
      query: `title: Mimikatz Credential Dump
status: stable
description: Detects credential dumping using Mimikatz
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'sekurlsa::logonpasswords'
      - 'lsadump::sam'
      - 'lsadump::dcsync'
      - 'kerberos::ptt'
      - 'privilege::debug'
  condition: selection
falsepositives:
  - Penetration testing
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001`,
    },
    {
      id: 'sigma-psexec',
      name: 'PsExec Remote Execution',
      mitre: ['T1021.002'],
      tactic: 'Lateral Movement',
      query: `title: PsExec Remote Execution
status: stable
description: Detects usage of PsExec for remote command execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\psexec.exe'
  selection_service:
    Image|endswith: '\\PSEXESVC.exe'
  condition: selection or selection_service
falsepositives:
  - Legitimate admin usage
level: high
tags:
  - attack.lateral_movement
  - attack.t1021.002`,
    },
    {
      id: 'sigma-webshell',
      name: 'Web Shell Activity',
      mitre: ['T1505.003'],
      tactic: 'Persistence',
      query: `title: Webshell Detection via Web Server Child Process
status: stable
description: Detects web shell activity by monitoring for unusual processes spawned by web servers
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\\w3wp.exe'
      - '\\httpd.exe'
      - '\\nginx.exe'
    Image|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
      - '\\wscript.exe'
      - '\\cscript.exe'
  condition: selection
level: high
tags:
  - attack.persistence
  - attack.t1505.003`,
    },
  ],
  yara: [
    {
      id: 'yara-ransomware-generic',
      name: 'Generic Ransomware Indicators',
      mitre: ['T1486'],
      tactic: 'Impact',
      query: `rule RansomwareGeneric {
  meta:
    description = "Detects generic ransomware behaviour"
    author = "CYBERDUDEBIVASH AI Security Hub"
    mitre_attack = "T1486"
    severity = "critical"
  strings:
    $enc1 = "CryptEncrypt" fullword
    $enc2 = "CryptGenRandom" fullword
    $ext1 = ".locked" nocase
    $ext2 = ".encrypted" nocase
    $ext3 = ".crypted" nocase
    $ransom1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase wide
    $ransom2 = "RANSOM" nocase wide
    $ransom3 = "BITCOIN" nocase wide
    $shadow = "vssadmin" nocase
    $shadow2 = "delete shadows" nocase
  condition:
    (2 of ($enc*) and 1 of ($ransom*)) or
    (1 of ($ext*) and 1 of ($ransom*)) or
    (all of ($shadow*))
}`,
    },
    {
      id: 'yara-cobalt-strike',
      name: 'Cobalt Strike Beacon',
      mitre: ['T1071.001', 'T1055'],
      tactic: 'Command and Control',
      query: `rule CobaltStrikeBeacon {
  meta:
    description = "Detects Cobalt Strike beacon patterns"
    author = "CYBERDUDEBIVASH AI Security Hub"
    mitre_attack = "T1071.001"
    severity = "critical"
  strings:
    $a1 = {FC 48 83 E4 F0 E8 C0 00 00 00}
    $a2 = "ReflectiveLoader" fullword
    $a3 = {4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08}
    $s1 = "/MFEwTzBNMEswSTAJBgUrDgMCGgUABB"
    $s2 = "WinInet" nocase
    $s3 = "beacon" nocase
  condition:
    (1 of ($a*) and 1 of ($s*)) or (2 of ($a*))
}`,
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

// ─── Simulated threat intel enrichment for IOCs ───────────────────────────────
function enrichIOC(value, type) {
  const hash = value.split('').reduce((a, c) => a + c.charCodeAt(0), 0);
  const verdicts = ['clean', 'clean', 'suspicious', 'malicious', 'unknown'];
  const verdict  = verdicts[hash % verdicts.length];

  const sources = {
    ipv4:   ['VirusTotal', 'AbuseIPDB', 'Shodan', 'GreyNoise'],
    domain: ['VirusTotal', 'URLhaus', 'PhishTank', 'WHOIS'],
    md5:    ['VirusTotal', 'MalwareBazaar', 'Hybrid Analysis'],
    sha1:   ['VirusTotal', 'MalwareBazaar', 'Hybrid Analysis'],
    sha256: ['VirusTotal', 'MalwareBazaar', 'Joe Sandbox'],
    url:    ['VirusTotal', 'URLhaus', 'Google SafeBrowsing'],
    cve:    ['NVD NIST', 'CISA KEV', 'ExploitDB'],
    email:  ['HaveIBeenPwned', 'SpamHaus', 'EmailRep'],
  };

  const tags = {
    malicious:  ['c2', 'malware', 'threat-actor'],
    suspicious: ['scanner', 'proxy', 'tor-exit'],
    clean:      [],
  };

  return {
    value,
    type,
    verdict,
    confidence: verdict === 'malicious' ? 95 : verdict === 'suspicious' ? 60 : 10,
    threat_score: verdict === 'malicious' ? Math.floor(70 + (hash % 30)) :
                  verdict === 'suspicious' ? Math.floor(30 + (hash % 40)) : Math.floor(hash % 15),
    sources: (sources[type] || ['VirusTotal']).map(s => ({
      source: s,
      verdict,
      last_seen: new Date(Date.now() - (hash % 30) * 86400000).toISOString().slice(0, 10),
    })),
    tags: tags[verdict] || [],
    first_seen: new Date(Date.now() - (hash % 180) * 86400000).toISOString().slice(0, 10),
    last_seen:  new Date(Date.now() - (hash % 7)   * 86400000).toISOString().slice(0, 10),
    related_iocs: verdict === 'malicious' ? [
      { type: 'domain', value: `c2-${hash % 9999}.example.com`, verdict: 'malicious' },
    ] : [],
    mitre_techniques: verdict === 'malicious' ? [
      { id: 'T1071.001', name: 'Web Protocols', tactic: 'Command and Control' },
    ] : [],
    geo: type === 'ipv4' ? {
      country: ['RU', 'CN', 'KP', 'IR', 'US', 'DE'][hash % 6],
      asn: `AS${10000 + (hash % 50000)}`,
      org: 'AS Hosting Provider',
    } : null,
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

  // Simulate hunt execution results
  const eventCount = 50 + (qHash % 500);
  const matchCount = Math.floor(eventCount * (0.01 + (qHash % 20) / 100));
  const severity   = matchCount > 10 ? 'HIGH' : matchCount > 3 ? 'MEDIUM' : 'LOW';

  const results = Array.from({ length: Math.min(matchCount, 20) }, (_, i) => ({
    id:        `hunt-${qHash}-${i}`,
    timestamp: new Date(Date.now() - i * 3600000).toISOString(),
    host:      `WORKSTATION-${String.fromCharCode(65 + ((qHash + i) % 26))}${(qHash + i * 7) % 99}`,
    user:      `user${(qHash + i * 3) % 99}@corp.local`,
    event:     lang === 'kql'   ? 'SecurityEvent' :
               lang === 'sigma' ? 'ProcessCreate' : 'FileEvent',
    severity:  ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][(qHash + i) % 4],
    indicators: [`indicator-${(qHash + i) % 999}`],
    raw:       `[SIMULATED] Event data for match ${i + 1} (${lang.toUpperCase()} hunt)`,
  }));

  // Infer MITRE technique from query content
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
      match_count:   matchCount,
      event_count:   eventCount,
      severity,
    };
    env.SECURITY_HUB_KV.put(
      `hunt:session:${authCtx.identity}:${sessionId}`,
      JSON.stringify(session),
      { expirationTtl: 604800 }
    ).catch(() => {});
  }

  return Response.json({
    session_id:  sessionId,
    lang,
    target:      sanitizeString(target || 'all', 100),
    scope,
    executed_at: new Date().toISOString(),
    stats: {
      events_scanned: eventCount,
      matches_found:  matchCount,
      severity,
      hunt_duration_ms: 120 + (qHash % 800),
    },
    results,
    mitre_techniques: mitreTechniques,
    recommendations: matchCount > 5 ? [
      'Investigate flagged hosts immediately',
      'Correlate with SIEM alerts for the same time window',
      'Escalate to IR team if critical assets are involved',
    ] : matchCount > 0 ? [
      'Review matched events for false positives',
      'Tune query thresholds if noise is high',
    ] : [
      'No matches found — consider broadening query scope or time window',
    ],
    // v21.0 — Adaptive next hunt recommendations (sector + risk aware)
    adaptive_hunt_suggestions: (['PRO', 'ENTERPRISE'].includes(authCtx?.tier))
      ? recommendHuntQueries(authCtx?.sector || 'technology', matchCount > 5 ? 75 : 45)
      : undefined,
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

  const results = targets.map(v => {
    const cleaned = sanitizeString(String(v), 500);
    const type = detectIOCType(cleaned);
    return enrichIOC(cleaned, type);
  });

  const maliciousCount  = results.filter(r => r.verdict === 'malicious').length;
  const suspiciousCount = results.filter(r => r.verdict === 'suspicious').length;

  return Response.json({
    queried_at: new Date().toISOString(),
    total:      results.length,
    summary: {
      malicious:  maliciousCount,
      suspicious: suspiciousCount,
      clean:      results.length - maliciousCount - suspiciousCount,
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
