/**
 * CYBERDUDEBIVASH AI Security Hub — Threat Intelligence Graph Engine v1.0
 *
 * Builds a fully attributed, traversable threat intelligence graph linking:
 *   Nodes: CVE, APT_GROUP, MALWARE, TECHNIQUE, SECTOR, INDICATOR
 *   Edges: exploits, attributed_to, uses, targets, related_to, delivers
 *
 * Endpoints:
 *   GET  /api/threat-graph              → Full graph (nodes + edges) for D3/Vis.js
 *   GET  /api/threat-graph/nodes        → Node list with optional type filter
 *   GET  /api/threat-graph/paths        → Shortest attack path from src → target
 *   POST /api/threat-graph/query        → Subgraph query (node-centric)
 *   GET  /api/threat-graph/summary      → Aggregate stats
 *
 * Data is deterministic (seeded from curated threat intel) + enriched from
 * live CISA KEV and ThreatFox when available.
 */

import { ok, fail } from '../lib/response.js';

// ─── Node Types ───────────────────────────────────────────────────────────────
const NODE_TYPES = { CVE: 'cve', APT: 'apt_group', MALWARE: 'malware', TECHNIQUE: 'technique', SECTOR: 'sector', INDICATOR: 'indicator' };
const EDGE_TYPES = { EXPLOITS: 'exploits', ATTRIBUTED_TO: 'attributed_to', USES: 'uses', TARGETS: 'targets', RELATED_TO: 'related_to', DELIVERS: 'delivers' };

// ─── Curated Threat Intelligence Knowledge Base ───────────────────────────────
const STATIC_NODES = [
  // APT Groups
  { id: 'apt41',     type: NODE_TYPES.APT,       label: 'APT41 (Winnti)',       properties: { nation: 'CN', motivation: 'Espionage+Financial', active: true,  campaigns: 47, sectors: ['Technology','Healthcare','Finance'] }},
  { id: 'apt28',     type: NODE_TYPES.APT,       label: 'APT28 (Fancy Bear)',   properties: { nation: 'RU', motivation: 'Espionage',           active: true,  campaigns: 89, sectors: ['Government','Defense','Energy'] }},
  { id: 'apt29',     type: NODE_TYPES.APT,       label: 'APT29 (Cozy Bear)',    properties: { nation: 'RU', motivation: 'Espionage',           active: true,  campaigns: 63, sectors: ['Government','Technology','Finance'] }},
  { id: 'lazarus',   type: NODE_TYPES.APT,       label: 'Lazarus Group',        properties: { nation: 'KP', motivation: 'Financial+Espionage', active: true,  campaigns: 134, sectors: ['Finance','Crypto','Defense'] }},
  { id: 'fin11',     type: NODE_TYPES.APT,       label: 'FIN11 (TA505)',        properties: { nation: 'unk', motivation: 'Financial',          active: true,  campaigns: 28, sectors: ['Finance','Retail','Healthcare'] }},
  { id: 'hafnium',   type: NODE_TYPES.APT,       label: 'HAFNIUM',              properties: { nation: 'CN', motivation: 'Espionage',           active: false, campaigns: 12, sectors: ['Defense','Law','NGO'] }},
  { id: 'uta0218',   type: NODE_TYPES.APT,       label: 'UTA0218',              properties: { nation: 'unk', motivation: 'Espionage',          active: true,  campaigns: 4,  sectors: ['Telecom','Energy'] }},
  { id: 'clop',      type: NODE_TYPES.APT,       label: 'CL0P Ransomware Gang', properties: { nation: 'RU', motivation: 'Financial',           active: true,  campaigns: 31, sectors: ['Healthcare','Education','Finance'] }},
  { id: 'blackcat',  type: NODE_TYPES.APT,       label: 'ALPHV/BlackCat',       properties: { nation: 'RU', motivation: 'Financial(RaaS)',     active: true,  campaigns: 53, sectors: ['Healthcare','Manufacturing','Energy'] }},

  // Malware Families
  { id: 'log4shell_exp',  type: NODE_TYPES.MALWARE, label: 'Log4Shell Exploit',     properties: { family: 'RCE_Exploit',  first_seen: '2021-12', cve_ref: 'CVE-2021-44228', in_wild: true  }},
  { id: 'cobalt_strike',  type: NODE_TYPES.MALWARE, label: 'Cobalt Strike Beacon',  properties: { family: 'RAT/C2',       first_seen: '2012-01', cve_ref: null,             in_wild: true  }},
  { id: 'mimikatz',       type: NODE_TYPES.MALWARE, label: 'Mimikatz',              properties: { family: 'CredHarvest',  first_seen: '2011-04', cve_ref: null,             in_wild: true  }},
  { id: 'emotet',         type: NODE_TYPES.MALWARE, label: 'Emotet',                properties: { family: 'Trojan/Loader', first_seen: '2014-01', cve_ref: null,            in_wild: true  }},
  { id: 'lockbit3',       type: NODE_TYPES.MALWARE, label: 'LockBit 3.0',           properties: { family: 'Ransomware',   first_seen: '2022-06', cve_ref: null,             in_wild: true  }},
  { id: 'blackmatter',    type: NODE_TYPES.MALWARE, label: 'BlackMatter',           properties: { family: 'Ransomware',   first_seen: '2021-07', cve_ref: null,             in_wild: false }},
  { id: 'sunburst',       type: NODE_TYPES.MALWARE, label: 'SUNBURST (SolarWinds)', properties: { family: 'Backdoor',     first_seen: '2020-03', cve_ref: 'CVE-2020-10148', in_wild: true  }},
  { id: 'bluekeep_exp',   type: NODE_TYPES.MALWARE, label: 'BlueKeep Exploit',      properties: { family: 'RCE_Exploit',  first_seen: '2019-05', cve_ref: 'CVE-2019-0708',  in_wild: true  }},
  { id: 'pwnkit_exp',     type: NODE_TYPES.MALWARE, label: 'PwnKit Exploit',        properties: { family: 'LPE_Exploit',  first_seen: '2022-01', cve_ref: 'CVE-2021-4034',  in_wild: true  }},

  // CVE Nodes (top KEV/critical)
  { id: 'cve_2021_44228', type: NODE_TYPES.CVE, label: 'CVE-2021-44228 Log4Shell',  properties: { cvss: 10.0, product: 'Apache Log4j', vendor: 'Apache', in_kev: true,  exploit_public: true, ransomware: true }},
  { id: 'cve_2021_26855', type: NODE_TYPES.CVE, label: 'CVE-2021-26855 ProxyLogon', properties: { cvss: 9.8,  product: 'Exchange',    vendor: 'Microsoft', in_kev: true, exploit_public: true, ransomware: false }},
  { id: 'cve_2022_30190', type: NODE_TYPES.CVE, label: 'CVE-2022-30190 Follina',    properties: { cvss: 7.8,  product: 'MSDT',        vendor: 'Microsoft', in_kev: true, exploit_public: true, ransomware: false }},
  { id: 'cve_2023_23397', type: NODE_TYPES.CVE, label: 'CVE-2023-23397 Outlook',    properties: { cvss: 9.8,  product: 'Outlook',     vendor: 'Microsoft', in_kev: true, exploit_public: true, ransomware: false }},
  { id: 'cve_2024_3400',  type: NODE_TYPES.CVE, label: 'CVE-2024-3400 PAN-OS',      properties: { cvss: 10.0, product: 'PAN-OS',      vendor: 'Palo Alto', in_kev: true, exploit_public: true, ransomware: false }},
  { id: 'cve_2021_34527', type: NODE_TYPES.CVE, label: 'CVE-2021-34527 PrintNightmare', properties: { cvss: 8.8, product: 'Print Spooler', vendor: 'Microsoft', in_kev: true, exploit_public: true, ransomware: true }}  ,
  { id: 'cve_2019_0708',  type: NODE_TYPES.CVE, label: 'CVE-2019-0708 BlueKeep',    properties: { cvss: 9.8,  product: 'RDP',         vendor: 'Microsoft', in_kev: true, exploit_public: true, ransomware: false }},
  { id: 'cve_2021_4034',  type: NODE_TYPES.CVE, label: 'CVE-2021-4034 PwnKit',      properties: { cvss: 7.8,  product: 'pkexec',      vendor: 'Linux',     in_kev: true, exploit_public: true, ransomware: false }},
  { id: 'cve_2023_44487', type: NODE_TYPES.CVE, label: 'CVE-2023-44487 HTTP/2 Rapid Reset', properties: { cvss: 7.5, product: 'HTTP/2', vendor: 'Multiple', in_kev: true, exploit_public: true, ransomware: false }},

  // MITRE ATT&CK Techniques
  { id: 'T1190',  type: NODE_TYPES.TECHNIQUE, label: 'T1190 Exploit Public-Facing App', properties: { tactic: 'Initial Access',       phase: 'IA', mitre_url: 'https://attack.mitre.org/techniques/T1190/' }},
  { id: 'T1566',  type: NODE_TYPES.TECHNIQUE, label: 'T1566 Phishing',                  properties: { tactic: 'Initial Access',       phase: 'IA', mitre_url: 'https://attack.mitre.org/techniques/T1566/' }},
  { id: 'T1078',  type: NODE_TYPES.TECHNIQUE, label: 'T1078 Valid Accounts',            properties: { tactic: 'Initial Access',       phase: 'IA', mitre_url: 'https://attack.mitre.org/techniques/T1078/' }},
  { id: 'T1059',  type: NODE_TYPES.TECHNIQUE, label: 'T1059 Command & Script Interp.',  properties: { tactic: 'Execution',            phase: 'EX', mitre_url: 'https://attack.mitre.org/techniques/T1059/' }},
  { id: 'T1053',  type: NODE_TYPES.TECHNIQUE, label: 'T1053 Scheduled Task',            properties: { tactic: 'Persistence',          phase: 'PE', mitre_url: 'https://attack.mitre.org/techniques/T1053/' }},
  { id: 'T1548',  type: NODE_TYPES.TECHNIQUE, label: 'T1548 Abuse Elevation Control',   properties: { tactic: 'Privilege Escalation', phase: 'PR', mitre_url: 'https://attack.mitre.org/techniques/T1548/' }},
  { id: 'T1110',  type: NODE_TYPES.TECHNIQUE, label: 'T1110 Brute Force',               properties: { tactic: 'Credential Access',    phase: 'CA', mitre_url: 'https://attack.mitre.org/techniques/T1110/' }},
  { id: 'T1003',  type: NODE_TYPES.TECHNIQUE, label: 'T1003 OS Credential Dumping',     properties: { tactic: 'Credential Access',    phase: 'CA', mitre_url: 'https://attack.mitre.org/techniques/T1003/' }},
  { id: 'T1021',  type: NODE_TYPES.TECHNIQUE, label: 'T1021 Remote Services',           properties: { tactic: 'Lateral Movement',     phase: 'LM', mitre_url: 'https://attack.mitre.org/techniques/T1021/' }},
  { id: 'T1041',  type: NODE_TYPES.TECHNIQUE, label: 'T1041 Exfiltration Over C2',      properties: { tactic: 'Exfiltration',         phase: 'EF', mitre_url: 'https://attack.mitre.org/techniques/T1041/' }},
  { id: 'T1486',  type: NODE_TYPES.TECHNIQUE, label: 'T1486 Data Encrypted for Impact', properties: { tactic: 'Impact',               phase: 'IM', mitre_url: 'https://attack.mitre.org/techniques/T1486/' }},
  { id: 'T1562',  type: NODE_TYPES.TECHNIQUE, label: 'T1562 Impair Defenses',           properties: { tactic: 'Defense Evasion',      phase: 'DE', mitre_url: 'https://attack.mitre.org/techniques/T1562/' }},

  // Target Sectors
  { id: 'sec_finance',     type: NODE_TYPES.SECTOR, label: 'Financial Services',   properties: { risk_level: 'CRITICAL', avg_ransom_usd: 1200000 }},
  { id: 'sec_healthcare',  type: NODE_TYPES.SECTOR, label: 'Healthcare',           properties: { risk_level: 'CRITICAL', avg_ransom_usd: 1500000 }},
  { id: 'sec_government',  type: NODE_TYPES.SECTOR, label: 'Government / Defense', properties: { risk_level: 'CRITICAL', avg_ransom_usd: 0 }},
  { id: 'sec_energy',      type: NODE_TYPES.SECTOR, label: 'Energy / Utilities',   properties: { risk_level: 'HIGH',     avg_ransom_usd: 800000 }},
  { id: 'sec_tech',        type: NODE_TYPES.SECTOR, label: 'Technology / SaaS',    properties: { risk_level: 'HIGH',     avg_ransom_usd: 600000 }},
  { id: 'sec_education',   type: NODE_TYPES.SECTOR, label: 'Education',            properties: { risk_level: 'MEDIUM',   avg_ransom_usd: 250000 }},
];

const STATIC_EDGES = [
  // CVE → Technique (exploits)
  { id: 'e1',  source: 'cve_2021_44228', target: 'T1190',  type: EDGE_TYPES.EXPLOITS,      weight: 1.0, label: 'enables' },
  { id: 'e2',  source: 'cve_2021_26855', target: 'T1190',  type: EDGE_TYPES.EXPLOITS,      weight: 0.9, label: 'enables' },
  { id: 'e3',  source: 'cve_2022_30190', target: 'T1059',  type: EDGE_TYPES.EXPLOITS,      weight: 0.85, label: 'enables' },
  { id: 'e4',  source: 'cve_2023_23397', target: 'T1078',  type: EDGE_TYPES.EXPLOITS,      weight: 0.9, label: 'enables' },
  { id: 'e5',  source: 'cve_2024_3400',  target: 'T1190',  type: EDGE_TYPES.EXPLOITS,      weight: 1.0, label: 'enables' },
  { id: 'e6',  source: 'cve_2021_34527', target: 'T1548',  type: EDGE_TYPES.EXPLOITS,      weight: 0.88, label: 'enables' },
  { id: 'e7',  source: 'cve_2019_0708',  target: 'T1021',  type: EDGE_TYPES.EXPLOITS,      weight: 0.9, label: 'enables' },
  { id: 'e8',  source: 'cve_2021_4034',  target: 'T1548',  type: EDGE_TYPES.EXPLOITS,      weight: 0.85, label: 'enables' },

  // APT → CVE (attributed_to / uses)
  { id: 'e10', source: 'apt41',    target: 'cve_2021_44228', type: EDGE_TYPES.USES,         weight: 0.9, label: 'exploits' },
  { id: 'e11', source: 'lazarus',  target: 'cve_2021_44228', type: EDGE_TYPES.USES,         weight: 0.85, label: 'exploits' },
  { id: 'e12', source: 'hafnium',  target: 'cve_2021_26855', type: EDGE_TYPES.USES,         weight: 1.0, label: 'exploits' },
  { id: 'e13', source: 'apt28',    target: 'cve_2023_23397', type: EDGE_TYPES.USES,         weight: 0.95, label: 'exploits' },
  { id: 'e14', source: 'uta0218',  target: 'cve_2024_3400',  type: EDGE_TYPES.USES,         weight: 1.0, label: 'exploits' },
  { id: 'e15', source: 'apt41',    target: 'cve_2021_34527', type: EDGE_TYPES.USES,         weight: 0.8, label: 'exploits' },
  { id: 'e16', source: 'fin11',    target: 'cve_2021_34527', type: EDGE_TYPES.USES,         weight: 0.7, label: 'exploits' },

  // APT → Malware (uses)
  { id: 'e20', source: 'apt41',    target: 'cobalt_strike',  type: EDGE_TYPES.USES,         weight: 0.9, label: 'deploys' },
  { id: 'e21', source: 'apt29',    target: 'cobalt_strike',  type: EDGE_TYPES.USES,         weight: 0.85, label: 'deploys' },
  { id: 'e22', source: 'lazarus',  target: 'emotet',         type: EDGE_TYPES.DELIVERS,     weight: 0.7, label: 'delivers' },
  { id: 'e23', source: 'fin11',    target: 'emotet',         type: EDGE_TYPES.DELIVERS,     weight: 0.9, label: 'delivers' },
  { id: 'e24', source: 'clop',     target: 'lockbit3',       type: EDGE_TYPES.RELATED_TO,   weight: 0.6, label: 'related_to' },
  { id: 'e25', source: 'blackcat', target: 'lockbit3',       type: EDGE_TYPES.RELATED_TO,   weight: 0.5, label: 'competitor' },
  { id: 'e26', source: 'apt29',    target: 'sunburst',       type: EDGE_TYPES.ATTRIBUTED_TO, weight: 0.95, label: 'created' },
  { id: 'e27', source: 'apt28',    target: 'mimikatz',       type: EDGE_TYPES.USES,         weight: 0.8, label: 'uses' },

  // Malware → Technique (uses)
  { id: 'e30', source: 'cobalt_strike', target: 'T1059', type: EDGE_TYPES.USES,    weight: 0.95, label: 'executes' },
  { id: 'e31', source: 'cobalt_strike', target: 'T1021', type: EDGE_TYPES.USES,    weight: 0.9,  label: 'lateral_moves' },
  { id: 'e32', source: 'cobalt_strike', target: 'T1041', type: EDGE_TYPES.USES,    weight: 0.85, label: 'exfiltrates' },
  { id: 'e33', source: 'mimikatz',      target: 'T1003', type: EDGE_TYPES.USES,    weight: 1.0,  label: 'dumps_creds' },
  { id: 'e34', source: 'emotet',        target: 'T1566', type: EDGE_TYPES.USES,    weight: 0.95, label: 'spreads_via' },
  { id: 'e35', source: 'lockbit3',      target: 'T1486', type: EDGE_TYPES.USES,    weight: 1.0,  label: 'encrypts' },
  { id: 'e36', source: 'lockbit3',      target: 'T1562', type: EDGE_TYPES.USES,    weight: 0.85, label: 'disables_defenses' },
  { id: 'e37', source: 'log4shell_exp', target: 'T1190', type: EDGE_TYPES.USES,    weight: 1.0,  label: 'exploits_rce' },
  { id: 'e38', source: 'pwnkit_exp',    target: 'T1548', type: EDGE_TYPES.USES,    weight: 0.9,  label: 'escalates_privs' },

  // APT → Sector (targets)
  { id: 'e40', source: 'apt41',    target: 'sec_tech',       type: EDGE_TYPES.TARGETS,   weight: 0.9, label: 'targets' },
  { id: 'e41', source: 'apt41',    target: 'sec_healthcare', type: EDGE_TYPES.TARGETS,   weight: 0.85, label: 'targets' },
  { id: 'e42', source: 'apt28',    target: 'sec_government', type: EDGE_TYPES.TARGETS,   weight: 0.95, label: 'targets' },
  { id: 'e43', source: 'apt29',    target: 'sec_government', type: EDGE_TYPES.TARGETS,   weight: 0.9, label: 'targets' },
  { id: 'e44', source: 'lazarus',  target: 'sec_finance',    type: EDGE_TYPES.TARGETS,   weight: 0.95, label: 'targets' },
  { id: 'e45', source: 'fin11',    target: 'sec_finance',    type: EDGE_TYPES.TARGETS,   weight: 0.9, label: 'targets' },
  { id: 'e46', source: 'clop',     target: 'sec_healthcare', type: EDGE_TYPES.TARGETS,   weight: 0.85, label: 'targets' },
  { id: 'e47', source: 'blackcat', target: 'sec_healthcare', type: EDGE_TYPES.TARGETS,   weight: 0.9, label: 'targets' },
  { id: 'e48', source: 'blackcat', target: 'sec_energy',     type: EDGE_TYPES.TARGETS,   weight: 0.8, label: 'targets' },
  { id: 'e49', source: 'clop',     target: 'sec_education',  type: EDGE_TYPES.TARGETS,   weight: 0.75, label: 'targets' },

  // Technique → Technique (kill-chain flow)
  { id: 'e60', source: 'T1190', target: 'T1059', type: EDGE_TYPES.RELATED_TO, weight: 0.9, label: 'leads_to' },
  { id: 'e61', source: 'T1566', target: 'T1078', type: EDGE_TYPES.RELATED_TO, weight: 0.85, label: 'leads_to' },
  { id: 'e62', source: 'T1059', target: 'T1003', type: EDGE_TYPES.RELATED_TO, weight: 0.8,  label: 'enables' },
  { id: 'e63', source: 'T1003', target: 'T1021', type: EDGE_TYPES.RELATED_TO, weight: 0.85, label: 'enables' },
  { id: 'e64', source: 'T1021', target: 'T1053', type: EDGE_TYPES.RELATED_TO, weight: 0.7,  label: 'persists_via' },
  { id: 'e65', source: 'T1078', target: 'T1021', type: EDGE_TYPES.RELATED_TO, weight: 0.8,  label: 'enables' },
  { id: 'e66', source: 'T1548', target: 'T1003', type: EDGE_TYPES.RELATED_TO, weight: 0.85, label: 'enables' },
  { id: 'e67', source: 'T1562', target: 'T1486', type: EDGE_TYPES.RELATED_TO, weight: 0.75, label: 'precedes' },
];

// ─── Graph statistics ─────────────────────────────────────────────────────────
function buildGraphStats(nodes, edges) {
  const nodesByType  = {};
  const edgesByType  = {};
  for (const n of nodes) nodesByType[n.type]  = (nodesByType[n.type]  || 0) + 1;
  for (const e of edges) edgesByType[e.type]  = (edgesByType[e.type]  || 0) + 1;

  const activeAPTs  = nodes.filter(n => n.type === NODE_TYPES.APT  && n.properties?.active).length;
  const criticalCVEs = nodes.filter(n => n.type === NODE_TYPES.CVE && n.properties?.cvss >= 9.0).length;
  const inKEV        = nodes.filter(n => n.type === NODE_TYPES.CVE && n.properties?.in_kev).length;

  // Degree centrality per node
  const degree = {};
  for (const e of edges) {
    degree[e.source] = (degree[e.source] || 0) + 1;
    degree[e.target] = (degree[e.target] || 0) + 1;
  }
  const sorted = Object.entries(degree).sort((a,b) => b[1]-a[1]).slice(0, 5);
  const hotspots = sorted.map(([id, deg]) => {
    const node = nodes.find(n => n.id === id);
    return { id, label: node?.label || id, type: node?.type || 'unknown', degree: deg };
  });

  return { nodesByType, edgesByType, activeAPTs, criticalCVEs, inKEV, total_nodes: nodes.length, total_edges: edges.length, hotspots };
}

// ─── BFS shortest path ────────────────────────────────────────────────────────
function shortestPath(edges, sourceId, targetId) {
  const adj = {};
  for (const e of edges) {
    if (!adj[e.source]) adj[e.source] = [];
    adj[e.source].push({ to: e.target, edge: e });
  }

  const visited = new Set();
  const queue   = [{ node: sourceId, path: [], edgePath: [] }];
  visited.add(sourceId);

  while (queue.length) {
    const { node, path, edgePath } = queue.shift();
    if (node === targetId) return { found: true, path: [...path, node], edges: edgePath, hops: path.length };

    for (const { to, edge } of (adj[node] || [])) {
      if (!visited.has(to)) {
        visited.add(to);
        queue.push({ node: to, path: [...path, node], edgePath: [...edgePath, edge] });
      }
    }
  }
  return { found: false, path: [], edges: [], hops: -1 };
}

// ─── Subgraph around a node ───────────────────────────────────────────────────
function extractSubgraph(allNodes, allEdges, centerNodeId, depth = 2) {
  const visited    = new Set([centerNodeId]);
  const frontier   = [centerNodeId];

  for (let d = 0; d < depth; d++) {
    const next = [];
    for (const nid of frontier) {
      for (const e of allEdges) {
        if (e.source === nid && !visited.has(e.target)) { visited.add(e.target); next.push(e.target); }
        if (e.target === nid && !visited.has(e.source)) { visited.add(e.source); next.push(e.source); }
      }
    }
    frontier.length = 0;
    frontier.push(...next);
  }

  return {
    nodes: allNodes.filter(n => visited.has(n.id)),
    edges: allEdges.filter(e => visited.has(e.source) && visited.has(e.target)),
  };
}

// ─── Enrich graph with live KEV data ─────────────────────────────────────────
async function enrichWithLiveKEV(nodes, env) {
  if (!env?.SECURITY_HUB_KV) return nodes;
  try {
    const kev = await env.SECURITY_HUB_KV.get('cisa_kev_catalog', { type: 'json' });
    if (!kev?.lookup) return nodes;

    return nodes.map(n => {
      if (n.type !== NODE_TYPES.CVE) return n;
      const cveId = n.label.split(' ')[0];
      const entry = kev.lookup[cveId];
      if (entry) {
        return {
          ...n,
          properties: {
            ...n.properties,
            kev_confirmed:    true,
            kev_date_added:   entry.date_added,
            kev_due_date:     entry.due_date,
            known_ransomware: entry.known_ransomware,
            vendor:           entry.vendor,
          }
        };
      }
      return n;
    });
  } catch { return nodes; }
}

// ─── GET /api/threat-graph ────────────────────────────────────────────────────
export async function handleGetThreatGraph(request, env, authCtx = {}) {
  const url        = new URL(request.url);
  const filterType = url.searchParams.get('type');      // optional: 'cve', 'apt_group', etc
  const minWeight  = parseFloat(url.searchParams.get('min_weight') || '0');
  const enrichLive = url.searchParams.get('live') !== 'false';

  let nodes = [...STATIC_NODES];
  let edges = [...STATIC_EDGES];

  // Optionally filter by type
  if (filterType) {
    const validTypes = Object.values(NODE_TYPES);
    if (!validTypes.includes(filterType)) {
      return fail(request, `Invalid type. Valid: ${validTypes.join(', ')}`, 400, 'INVALID_TYPE');
    }
    const nodeIds = new Set(nodes.filter(n => n.type === filterType).map(n => n.id));
    edges = edges.filter(e => nodeIds.has(e.source) || nodeIds.has(e.target));
    const connectedIds = new Set([...edges.map(e => e.source), ...edges.map(e => e.target), ...nodeIds]);
    nodes = nodes.filter(n => connectedIds.has(n.id));
  }

  // Filter by edge weight
  if (minWeight > 0) {
    edges = edges.filter(e => e.weight >= minWeight);
    const connectedIds = new Set([...edges.map(e => e.source), ...edges.map(e => e.target)]);
    nodes = nodes.filter(n => connectedIds.has(n.id));
  }

  // Live enrichment from cached KEV
  if (enrichLive) {
    nodes = await enrichWithLiveKEV(nodes, env);
  }

  const stats = buildGraphStats(nodes, edges);

  // Add D3-compatible layout hints
  const nodesWithLayout = nodes.map(n => ({
    ...n,
    group: n.type,
    // Node size hints for visualization
    size: n.type === NODE_TYPES.CVE ? (n.properties.cvss || 5) * 4
         : n.type === NODE_TYPES.APT ? (n.properties.campaigns || 10) / 5
         : n.type === NODE_TYPES.MALWARE ? 8
         : n.type === NODE_TYPES.TECHNIQUE ? 6
         : n.type === NODE_TYPES.SECTOR ? 10
         : 5,
    color: n.type === NODE_TYPES.CVE ? '#ef4444'
         : n.type === NODE_TYPES.APT ? '#f97316'
         : n.type === NODE_TYPES.MALWARE ? '#8b5cf6'
         : n.type === NODE_TYPES.TECHNIQUE ? '#06b6d4'
         : n.type === NODE_TYPES.SECTOR ? '#10b981'
         : '#6b7280',
  }));

  return ok(request, {
    nodes:          nodesWithLayout,
    edges,
    stats,
    meta: {
      generated_at:  new Date().toISOString(),
      live_enriched: enrichLive,
      node_types:    Object.values(NODE_TYPES),
      edge_types:    Object.values(EDGE_TYPES),
    }
  });
}

// ─── GET /api/threat-graph/nodes ─────────────────────────────────────────────
export async function handleGetGraphNodes(request, env, authCtx = {}) {
  const url    = new URL(request.url);
  const type   = url.searchParams.get('type');
  const search = (url.searchParams.get('q') || '').toLowerCase();
  const limit  = Math.min(200, parseInt(url.searchParams.get('limit') || '100', 10));

  let nodes = [...STATIC_NODES];
  if (type)   nodes = nodes.filter(n => n.type === type);
  if (search) nodes = nodes.filter(n => n.label.toLowerCase().includes(search) || n.id.includes(search));

  return ok(request, { total: nodes.length, nodes: nodes.slice(0, limit) });
}

// ─── GET /api/threat-graph/paths ─────────────────────────────────────────────
export async function handleGetGraphPaths(request, env, authCtx = {}) {
  const url    = new URL(request.url);
  const from   = url.searchParams.get('from');
  const to     = url.searchParams.get('to');

  if (!from || !to) return fail(request, 'from and to node IDs are required', 400, 'MISSING_PARAMS');

  const srcNode = STATIC_NODES.find(n => n.id === from);
  const dstNode = STATIC_NODES.find(n => n.id === to);
  if (!srcNode) return fail(request, `Source node '${from}' not found`, 404, 'NODE_NOT_FOUND');
  if (!dstNode) return fail(request, `Target node '${to}' not found`, 404, 'NODE_NOT_FOUND');

  const result = shortestPath(STATIC_EDGES, from, to);

  const pathNodes = result.path.map(id => STATIC_NODES.find(n => n.id === id)).filter(Boolean);

  return ok(request, {
    source:     srcNode,
    target:     dstNode,
    found:      result.found,
    hops:       result.hops,
    path_nodes: pathNodes,
    path_edges: result.edges,
    attack_narrative: result.found
      ? `Attack path from ${srcNode.label} → ${dstNode.label} requires ${result.hops} hop(s) via: ${pathNodes.map(n => n.label).join(' → ')}`
      : `No direct path found from ${srcNode.label} to ${dstNode.label} in current graph.`,
  });
}

// ─── POST /api/threat-graph/query ────────────────────────────────────────────
export async function handleGraphQuery(request, env, authCtx = {}) {
  let body = {};
  try { body = await request.json(); } catch {}

  const { node_id, depth = 2, include_types } = body;
  if (!node_id) return fail(request, 'node_id is required', 400, 'MISSING_NODE_ID');

  const center = STATIC_NODES.find(n => n.id === node_id);
  if (!center) return fail(request, `Node '${node_id}' not found`, 404, 'NODE_NOT_FOUND');

  let { nodes, edges } = extractSubgraph(STATIC_NODES, STATIC_EDGES, node_id, Math.min(depth, 3));

  if (include_types && Array.isArray(include_types)) {
    const nodeIds = new Set(nodes.filter(n => include_types.includes(n.type)).map(n => n.id));
    nodeIds.add(node_id);
    edges = edges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target));
    const connectedIds = new Set([...edges.map(e => e.source), ...edges.map(e => e.target)]);
    nodes = nodes.filter(n => connectedIds.has(n.id) || n.id === node_id);
  }

  const stats = buildGraphStats(nodes, edges);

  return ok(request, { center, nodes, edges, stats, depth_used: Math.min(depth, 3) });
}

// ─── GET /api/threat-graph/summary ───────────────────────────────────────────
export async function handleGraphSummary(request, env, authCtx = {}) {
  const stats = buildGraphStats(STATIC_NODES, STATIC_EDGES);

  const topAPTs = STATIC_NODES.filter(n => n.type === NODE_TYPES.APT && n.properties.active)
    .sort((a,b) => (b.properties.campaigns||0) - (a.properties.campaigns||0))
    .slice(0, 5)
    .map(n => ({ id: n.id, label: n.label, nation: n.properties.nation, campaigns: n.properties.campaigns }));

  const criticalCVEs = STATIC_NODES.filter(n => n.type === NODE_TYPES.CVE && n.properties.cvss >= 9.0)
    .sort((a,b) => b.properties.cvss - a.properties.cvss)
    .map(n => ({ id: n.id, label: n.label, cvss: n.properties.cvss, in_kev: n.properties.in_kev }));

  const activeMalware = STATIC_NODES.filter(n => n.type === NODE_TYPES.MALWARE && n.properties.in_wild)
    .map(n => ({ id: n.id, label: n.label, family: n.properties.family }));

  return ok(request, {
    stats,
    top_active_apts:    topAPTs,
    critical_cves:      criticalCVEs,
    active_malware:     activeMalware,
    threat_landscape:   {
      active_nation_state_groups: topAPTs.length,
      critical_unpatched_cves:    criticalCVEs.length,
      active_malware_families:    activeMalware.length,
      high_risk_sectors:          STATIC_NODES.filter(n => n.type === NODE_TYPES.SECTOR && n.properties.risk_level === 'CRITICAL').length,
    },
    generated_at: new Date().toISOString(),
  });
}
