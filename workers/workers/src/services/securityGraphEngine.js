/**
 * CYBERDUDEBIVASH AI Security Hub — Unified Security Graph Engine v19.0
 * Extends threatGraph.js with live asset nodes, dynamic vulnerability edges,
 * IOC nodes from ThreatFusion, and AI-powered attack path traversal.
 *
 * Graph schema:
 *   Nodes: ASSET | CVE | APT_GROUP | MALWARE | TECHNIQUE | IOC | SECTOR
 *   Edges: exposes | exploits | attributed_to | uses | targets | delivers | related_to | owned_by
 *
 * Visual-ready JSON for D3.js / Vis.js / Cytoscape.js
 *
 * Endpoints:
 *   GET  /api/security-graph           → full graph
 *   GET  /api/security-graph/nodes     → filtered node list
 *   POST /api/security-graph/asset     → register an asset node
 *   POST /api/security-graph/query     → subgraph: expand from node
 *   GET  /api/security-graph/paths     → attack path: src → target
 *   GET  /api/security-graph/summary   → graph stats + risk surface
 */

// ─── Static graph seeds (curated threat intel) ───────────────────────────────
const SEED_APTS = [
  { id: 'apt41',    label: 'APT41',          type: 'apt_group', color: '#ff4444', size: 18, nation: 'CN', sectors: ['tech','healthcare','finance'] },
  { id: 'apt28',    label: 'APT28',          type: 'apt_group', color: '#ff6666', size: 16, nation: 'RU', sectors: ['gov','defense','energy'] },
  { id: 'apt29',    label: 'APT29',          type: 'apt_group', color: '#ff8888', size: 16, nation: 'RU', sectors: ['gov','tech','finance'] },
  { id: 'lazarus',  label: 'Lazarus Group',  type: 'apt_group', color: '#ffaaaa', size: 17, nation: 'KP', sectors: ['finance','crypto'] },
  { id: 'lockbit',  label: 'LockBit 3.0',   type: 'apt_group', color: '#ff2222', size: 15, nation: 'RU', sectors: ['healthcare','manufacturing'] },
  { id: 'clop',     label: 'CL0P',          type: 'apt_group', color: '#ff3333', size: 14, nation: 'RU', sectors: ['healthcare','education'] },
];

const SEED_CVES = [
  { id: 'cve_2021_44228', label: 'Log4Shell',    type: 'cve', cvss: 10.0, kev: true,  color: '#ff0000', size: 20 },
  { id: 'cve_2024_3400',  label: 'PAN-OS RCE',   type: 'cve', cvss: 10.0, kev: true,  color: '#ff0000', size: 20 },
  { id: 'cve_2023_23397', label: 'Outlook RCE',  type: 'cve', cvss: 9.8,  kev: true,  color: '#ff2200', size: 18 },
  { id: 'cve_2024_21413', label: 'Outlook Moniker',type:'cve', cvss: 9.8, kev: true,  color: '#ff2200', size: 18 },
  { id: 'cve_2021_26855', label: 'ProxyLogon',   type: 'cve', cvss: 9.8,  kev: true,  color: '#ff2200', size: 18 },
  { id: 'cve_2024_6387',  label: 'RegreSSHion',  type: 'cve', cvss: 8.1,  kev: false, color: '#ff6600', size: 15 },
  { id: 'cve_2023_44487', label: 'HTTP/2 RReset', type:'cve', cvss: 7.5,  kev: true,  color: '#ff8800', size: 14 },
];

const SEED_MALWARE = [
  { id: 'cobalt_strike', label: 'Cobalt Strike',  type: 'malware', family: 'C2/RAT',     color: '#aa00ff', size: 14 },
  { id: 'mimikatz',      label: 'Mimikatz',       type: 'malware', family: 'CredDump',   color: '#cc00ff', size: 13 },
  { id: 'lockbit3_bin',  label: 'LockBit 3.0 Bin',type: 'malware', family: 'Ransomware', color: '#ff0044', size: 15 },
  { id: 'emotet',        label: 'Emotet',         type: 'malware', family: 'Trojan',     color: '#dd00ff', size: 12 },
  { id: 'clop_clop',     label: 'CL0P Ransomware',type: 'malware', family: 'Ransomware', color: '#ff0044', size: 14 },
];

const SEED_TECHNIQUES = [
  { id: 'T1190', label: 'Exploit Public App',    type: 'technique', tactic: 'Initial Access',      color: '#00aaff', size: 14 },
  { id: 'T1566', label: 'Phishing',              type: 'technique', tactic: 'Initial Access',      color: '#00aaff', size: 14 },
  { id: 'T1078', label: 'Valid Accounts',        type: 'technique', tactic: 'Persistence',         color: '#0088ff', size: 13 },
  { id: 'T1059', label: 'Command Interpreter',   type: 'technique', tactic: 'Execution',           color: '#0066ff', size: 13 },
  { id: 'T1486', label: 'Data Encryption/Impact',type: 'technique', tactic: 'Impact',              color: '#ff4400', size: 15 },
  { id: 'T1071', label: 'App Layer Protocol C2', type: 'technique', tactic: 'C2',                  color: '#00ffaa', size: 12 },
  { id: 'T1055', label: 'Process Injection',     type: 'technique', tactic: 'Defense Evasion',     color: '#00cc88', size: 12 },
  { id: 'T1003', label: 'OS Cred Dumping',       type: 'technique', tactic: 'Credential Access',   color: '#ffaa00', size: 13 },
  { id: 'T1021', label: 'Remote Services',       type: 'technique', tactic: 'Lateral Movement',    color: '#ff8800', size: 13 },
  { id: 'T1041', label: 'Exfil over C2',         type: 'technique', tactic: 'Exfiltration',        color: '#ff6600', size: 12 },
];

const SEED_EDGES = [
  // APT → Technique
  { source: 'apt41',    target: 'T1190', type: 'uses', weight: 0.9 },
  { source: 'apt41',    target: 'T1059', type: 'uses', weight: 0.8 },
  { source: 'apt28',    target: 'T1566', type: 'uses', weight: 0.9 },
  { source: 'apt29',    target: 'T1078', type: 'uses', weight: 0.85 },
  { source: 'lazarus',  target: 'T1486', type: 'uses', weight: 0.7 },
  { source: 'lazarus',  target: 'T1190', type: 'uses', weight: 0.9 },
  { source: 'lockbit',  target: 'T1486', type: 'uses', weight: 0.99 },
  { source: 'clop',     target: 'T1190', type: 'uses', weight: 0.85 },
  // APT → CVE
  { source: 'apt41',    target: 'cve_2021_44228', type: 'exploits', weight: 0.8 },
  { source: 'apt28',    target: 'cve_2023_23397', type: 'exploits', weight: 0.85 },
  { source: 'lazarus',  target: 'cve_2024_3400',  type: 'exploits', weight: 0.75 },
  { source: 'clop',     target: 'cve_2021_26855', type: 'exploits', weight: 0.8 },
  // CVE → Malware
  { source: 'cve_2021_44228', target: 'cobalt_strike', type: 'delivers', weight: 0.9 },
  { source: 'cve_2021_26855', target: 'cobalt_strike', type: 'delivers', weight: 0.85 },
  // Malware → Technique
  { source: 'cobalt_strike',  target: 'T1071', type: 'uses', weight: 0.95 },
  { source: 'cobalt_strike',  target: 'T1055', type: 'uses', weight: 0.8 },
  { source: 'mimikatz',       target: 'T1003', type: 'uses', weight: 0.99 },
  { source: 'lockbit3_bin',   target: 'T1486', type: 'uses', weight: 0.99 },
  { source: 'lockbit3_bin',   target: 'T1041', type: 'uses', weight: 0.7 },
  // Technique chains
  { source: 'T1190', target: 'T1059', type: 'enables', weight: 0.8 },
  { source: 'T1059', target: 'T1055', type: 'enables', weight: 0.7 },
  { source: 'T1055', target: 'T1003', type: 'enables', weight: 0.75 },
  { source: 'T1003', target: 'T1021', type: 'enables', weight: 0.8 },
  { source: 'T1021', target: 'T1041', type: 'enables', weight: 0.7 },
];

// ─── Build full graph ─────────────────────────────────────────────────────────
export function buildSecurityGraph(assets = [], userVulns = [], userIOCs = []) {
  const nodes = [
    ...SEED_APTS,
    ...SEED_CVES,
    ...SEED_MALWARE,
    ...SEED_TECHNIQUES,
  ];
  const edges = [...SEED_EDGES];

  // Add dynamic asset nodes
  for (const asset of assets) {
    const assetNode = {
      id:    `asset_${asset.id || asset.name?.replace(/\s/g,'_').slice(0,20)}`,
      label: asset.name || asset.domain || 'Unknown Asset',
      type:  'asset',
      color: '#00ff88',
      size:  16,
      asset_type:       asset.type || 'server',
      risk_score:       asset.risk_score || 0,
      internet_facing:  asset.internet_facing !== false,
    };
    nodes.push(assetNode);

    // Connect asset to CVEs if vulns provided
    for (const vuln of (asset.vulns || userVulns)) {
      const cveNodeId = `cve_${(vuln.cve_id || '').replace(/-/g,'_').toLowerCase()}`;
      const exists = nodes.find(n => n.id === cveNodeId);
      if (!exists) {
        nodes.push({
          id:    cveNodeId,
          label: vuln.cve_id || 'Unknown CVE',
          type:  'cve',
          cvss:  vuln.cvss_score || 0,
          kev:   vuln.in_kev || false,
          color: (vuln.cvss_score || 0) >= 9.0 ? '#ff0000' : '#ff8800',
          size:  Math.min(20, Math.max(8, Math.floor((vuln.cvss_score || 5) * 2))),
        });
      }
      edges.push({ source: assetNode.id, target: cveNodeId, type: 'exposes', weight: 0.9 });
    }
  }

  // Add IOC nodes from ThreatFusion
  for (const ioc of userIOCs.slice(0, 20)) {
    const iocId = `ioc_${ioc.type}_${(ioc.value||'').slice(0,20).replace(/[^a-z0-9]/gi,'_')}`;
    if (!nodes.find(n => n.id === iocId)) {
      nodes.push({
        id:         iocId,
        label:      ioc.value?.slice(0, 30) || ioc.type,
        type:       'ioc',
        ioc_type:   ioc.type,
        color:      ioc.severity === 'CRITICAL' ? '#ff0000' : ioc.severity === 'HIGH' ? '#ff8800' : '#ffdd00',
        size:       ioc.confidence >= 80 ? 14 : 10,
        confidence: ioc.confidence,
        source:     ioc.source,
      });
      // Link IOC → technique
      if (ioc.mitre_technique) {
        const techNode = nodes.find(n => n.id === ioc.mitre_technique);
        if (techNode) edges.push({ source: iocId, target: ioc.mitre_technique, type: 'related_to', weight: 0.6 });
      }
    }
  }

  return { nodes, edges };
}

// ─── Graph traversal: BFS shortest path ──────────────────────────────────────
export function findAttackPath(graph, sourceId, targetId, maxDepth = 6) {
  const { nodes, edges } = graph;
  const nodeMap = new Map(nodes.map(n => [n.id, n]));
  const adj     = new Map();

  for (const edge of edges) {
    if (!adj.has(edge.source)) adj.set(edge.source, []);
    adj.get(edge.source).push({ to: edge.target, type: edge.type, weight: edge.weight });
  }

  // BFS
  const queue   = [[sourceId, [sourceId], []]]; // [node, path, edgeTypes]
  const visited = new Set([sourceId]);

  while (queue.length > 0) {
    const [current, path, edgeTypes] = queue.shift();
    if (path.length > maxDepth) continue;
    if (current === targetId) {
      return {
        found: true,
        path:  path.map(id => nodeMap.get(id) || { id, label: id }),
        edge_types: edgeTypes,
        path_length: path.length - 1,
        risk_score: Math.round(90 - path.length * 5),
      };
    }
    for (const neighbor of (adj.get(current) || [])) {
      if (!visited.has(neighbor.to)) {
        visited.add(neighbor.to);
        queue.push([neighbor.to, [...path, neighbor.to], [...edgeTypes, neighbor.type]]);
      }
    }
  }
  return { found: false, path: [], path_length: -1, message: 'No path found between nodes' };
}

// ─── Subgraph expansion ───────────────────────────────────────────────────────
export function expandNode(graph, nodeId, depth = 2) {
  const { nodes, edges } = graph;
  const nodeMap   = new Map(nodes.map(n => [n.id, n]));
  const included  = new Set([nodeId]);

  const traverse = (id, d) => {
    if (d <= 0) return;
    for (const e of edges) {
      if (e.source === id && !included.has(e.target)) {
        included.add(e.target);
        traverse(e.target, d - 1);
      }
      if (e.target === id && !included.has(e.source)) {
        included.add(e.source);
        traverse(e.source, d - 1);
      }
    }
  };
  traverse(nodeId, depth);

  return {
    center:  nodeMap.get(nodeId) || { id: nodeId },
    nodes:   [...included].map(id => nodeMap.get(id)).filter(Boolean),
    edges:   edges.filter(e => included.has(e.source) && included.has(e.target)),
    node_count: included.size,
  };
}

// ─── Handler: GET /api/security-graph ─────────────────────────────────────────
export async function handleSecurityGraph(request, env, authCtx) {
  const graph = buildSecurityGraph();
  return Response.json({
    nodes:       graph.nodes,
    edges:       graph.edges,
    node_count:  graph.nodes.length,
    edge_count:  graph.edges.length,
    by_type:     graph.nodes.reduce((acc, n) => { acc[n.type] = (acc[n.type]||0)+1; return acc; }, {}),
    generated_at: new Date().toISOString(),
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  });
}

// ─── Handler: GET /api/security-graph/nodes ───────────────────────────────────
export async function handleSecurityGraphNodes(request, env, authCtx) {
  const url  = new URL(request.url);
  const type = url.searchParams.get('type');
  const q    = url.searchParams.get('q')?.toLowerCase();
  const graph = buildSecurityGraph();

  let filtered = graph.nodes;
  if (type) filtered = filtered.filter(n => n.type === type);
  if (q)    filtered = filtered.filter(n => n.label?.toLowerCase().includes(q) || n.id?.toLowerCase().includes(q));

  return Response.json({ nodes: filtered, total: filtered.length, platform: 'CYBERDUDEBIVASH AI Security Hub v19.0' });
}

// ─── Handler: POST /api/security-graph/asset ──────────────────────────────────
export async function handleRegisterAsset(request, env, authCtx) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }
  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON body' }, { status: 400 }); }

  const { name, type = 'server', internet_facing = true, tags = [] } = body;
  if (!name) return Response.json({ error: 'name is required' }, { status: 400 });

  const asset = {
    id:             `asset_${Date.now().toString(36)}`,
    name,
    type,
    internet_facing,
    tags,
    owner:          authCtx.identity,
    org_id:         authCtx.orgId || null,
    registered_at:  new Date().toISOString(),
    risk_score:     0,
  };

  if (env?.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(
      `asset:${authCtx.identity}:${asset.id}`,
      JSON.stringify(asset),
      { expirationTtl: 7776000 } // 90 days
    ).catch(() => {});
  }

  const graph = buildSecurityGraph([asset]);
  const assetNode = graph.nodes.find(n => n.type === 'asset');

  return Response.json({ success: true, asset, graph_node: assetNode }, { status: 201 });
}

// ─── Handler: POST /api/security-graph/query ──────────────────────────────────
export async function handleGraphQuery(request, env, authCtx) {
  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON body' }, { status: 400 }); }

  const { node_id, depth = 2 } = body;
  if (!node_id) return Response.json({ error: 'node_id is required' }, { status: 400 });

  const graph  = buildSecurityGraph();
  const result = expandNode(graph, node_id, Math.min(depth, 4));

  return Response.json({ ...result, platform: 'CYBERDUDEBIVASH AI Security Hub v19.0' });
}

// ─── Handler: GET /api/security-graph/paths ───────────────────────────────────
export async function handleGraphPaths(request, env, authCtx) {
  const url      = new URL(request.url);
  const source   = url.searchParams.get('source');
  const target   = url.searchParams.get('target');
  const maxDepth = Math.min(parseInt(url.searchParams.get('depth') || '6', 10), 8);

  if (!source || !target) {
    return Response.json({ error: 'source and target query params required' }, { status: 400 });
  }

  const graph = buildSecurityGraph();
  const path  = findAttackPath(graph, source, target, maxDepth);

  return Response.json({ source, target, ...path, platform: 'CYBERDUDEBIVASH AI Security Hub v19.0' });
}

// ─── Handler: GET /api/security-graph/summary ─────────────────────────────────
export async function handleGraphSummary(request, env, authCtx) {
  const graph = buildSecurityGraph();
  const aptCount = graph.nodes.filter(n => n.type === 'apt_group').length;
  const kevCount = graph.nodes.filter(n => n.type === 'cve' && n.kev).length;

  return Response.json({
    node_count:      graph.nodes.length,
    edge_count:      graph.edges.length,
    apt_groups:      aptCount,
    kev_cves:        kevCount,
    malware_families: graph.nodes.filter(n => n.type === 'malware').length,
    techniques:      graph.nodes.filter(n => n.type === 'technique').length,
    avg_connectivity: +(graph.edges.length / graph.nodes.length).toFixed(2),
    most_connected: graph.nodes.map(n => ({
      id:   n.id,
      label: n.label,
      type:  n.type,
      degree: graph.edges.filter(e => e.source === n.id || e.target === n.id).length,
    })).sort((a, b) => b.degree - a.degree).slice(0, 5),
    generated_at: new Date().toISOString(),
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  });
}
