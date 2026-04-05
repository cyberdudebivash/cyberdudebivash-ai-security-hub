/**
 * CYBERDUDEBIVASH AI Security Hub — IOC Graph Engine v1.0
 * Sentinel APEX Phase 4: IOC Relationship Graph
 *
 * Builds a directed relationship graph:
 *   IP → domain (resolution / co-occurrence)
 *   domain → CVE  (referenced in threat intel)
 *   CVE → hash    (malware sample associated with CVE exploit)
 *   hash → IP     (C2 server associated with malware sample)
 *   CVE → CVE     (same campaign / vendor family)
 *
 * Output: { nodes: [...], edges: [...] }
 * Frontend: D3.js / Cytoscape.js ready
 */

// ─── Node type definitions ────────────────────────────────────────────────────
const NODE_TYPES = {
  cve:    { color: '#ef4444', shape: 'circle',   label: 'CVE'    },
  ip:     { color: '#f97316', shape: 'square',   label: 'IP'     },
  domain: { color: '#3b82f6', shape: 'triangle', label: 'Domain' },
  hash:   { color: '#8b5cf6', shape: 'diamond',  label: 'Hash'   },
  url:    { color: '#06b6d4', shape: 'circle',   label: 'URL'    },
  actor:  { color: '#dc2626', shape: 'star',     label: 'Actor'  },
};

// ─── Edge type definitions ─────────────────────────────────────────────────────
const EDGE_TYPES = {
  exploits:      { color: '#ef4444', weight: 3, label: 'exploits'       },
  resolves_to:   { color: '#f97316', weight: 2, label: 'resolves_to'    },
  references:    { color: '#3b82f6', weight: 1, label: 'references'     },
  associated:    { color: '#8b5cf6', weight: 2, label: 'associated'     },
  c2_server:     { color: '#dc2626', weight: 3, label: 'C2_server'      },
  co_occurrence: { color: '#6b7280', weight: 1, label: 'co_occurrence'  },
  targets:       { color: '#ef4444', weight: 2, label: 'targets'        },
};

// ─── Parse IOC list from entry ─────────────────────────────────────────────────
function parseIOCList(iocListStr) {
  try {
    const parsed = typeof iocListStr === 'string' ? JSON.parse(iocListStr) : iocListStr;
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

// ─── Safe node ID ──────────────────────────────────────────────────────────────
function nodeId(type, value) {
  return `${type}:${value.replace(/[^a-zA-Z0-9\-_.]/g, '_')}`;
}

// ─── Build graph from threat intel entries + IOC registry rows ────────────────
export function buildGraph(entries = [], iocRows = [], correlations = []) {
  const nodes = new Map(); // id → node
  const edges = [];
  const edgeSet = new Set(); // dedup

  function addNode(type, value, meta = {}) {
    const id = nodeId(type, value);
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        type,
        label:    value.length > 40 ? value.slice(0, 37) + '...' : value,
        value,
        ...NODE_TYPES[type],
        ...meta,
      });
    }
    return id;
  }

  function addEdge(sourceId, targetId, edgeType, meta = {}) {
    const key = `${sourceId}→${edgeType}→${targetId}`;
    if (edgeSet.has(key)) return;
    edgeSet.add(key);
    edges.push({
      id:     key,
      source: sourceId,
      target: targetId,
      ...EDGE_TYPES[edgeType],
      ...meta,
    });
  }

  // ── Step 1: Add CVE nodes from threat intel entries ──────────────────────────
  for (const entry of entries) {
    const cveNode = addNode('cve', entry.id, {
      severity:    entry.severity,
      cvss:        entry.cvss,
      title:       entry.title,
      exploited:   entry.exploit_status === 'confirmed',
      epss_score:  entry.epss_score || 0,
      kev:         !!entry.known_ransomware,
    });

    // ── Step 2: Link IOCs from this CVE entry ─────────────────────────────────
    const iocList = parseIOCList(entry.ioc_list);
    for (const ioc of iocList) {
      const iocType  = ioc.type || 'ip';
      const iocValue = ioc.value || ioc;
      if (!iocValue || typeof iocValue !== 'string') continue;

      if (['ip', 'ipv4', 'ipv6'].includes(iocType)) {
        const ipNode = addNode('ip', iocValue, { defanged: ioc.defanged });
        addEdge(ipNode, cveNode, 'references', { label: 'C2 or scanner' });
      } else if (['domain', 'hostname'].includes(iocType)) {
        const domNode = addNode('domain', iocValue, { defanged: ioc.defanged });
        addEdge(domNode, cveNode, 'references');
      } else if (['md5', 'sha1', 'sha256', 'hash'].includes(iocType)) {
        const hashNode = addNode('hash', iocValue, { hash_type: iocType });
        addEdge(cveNode, hashNode, 'associated', { label: 'malware sample' });
      } else if (['url'].includes(iocType)) {
        const urlNode = addNode('url', iocValue, { defanged: ioc.defanged });
        addEdge(urlNode, cveNode, 'references', { label: 'exploit URL' });
      }
    }
  }

  // ── Step 3: Link IOC registry rows (from D1) ──────────────────────────────
  for (const row of iocRows) {
    const cveRef = row.intel_id;
    const type   = row.type || 'ip';
    const value  = row.value || '';
    if (!value) continue;

    let iocNodeId;
    if (['ipv4', 'ipv6', 'ip'].includes(type)) {
      iocNodeId = addNode('ip', value, { defanged: row.defanged });
    } else if (['domain', 'hostname'].includes(type)) {
      iocNodeId = addNode('domain', value, { defanged: row.defanged });
    } else if (['md5', 'sha1', 'sha256'].includes(type)) {
      iocNodeId = addNode('hash', value, { hash_type: type });
    } else if (['url'].includes(type)) {
      iocNodeId = addNode('url', value, { defanged: row.defanged });
    } else {
      continue;
    }

    // Link IOC to its parent CVE entry
    const cveId = nodeId('cve', cveRef);
    if (nodes.has(cveId) && iocNodeId) {
      addEdge(iocNodeId, cveId, 'references');
    }
  }

  // ── Step 4: Link correlated CVE ↔ CVE relationships ──────────────────────
  for (const corr of correlations) {
    const sourceId = nodeId('cve', corr.cve_id);
    for (const related of (corr.related_cves || [])) {
      const targetId = nodeId('cve', related.id);
      if (nodes.has(sourceId) && nodes.has(targetId)) {
        addEdge(sourceId, targetId, 'co_occurrence', {
          label:  related.reasons?.[0] || 'related',
          weight: Math.ceil((related.score || 25) / 25),
        });
      }
    }

    // Link CVE to threat actor node
    if (corr.threat_actor) {
      const actorId = addNode('actor', corr.threat_actor, {
        campaign: corr.campaign,
        mitre:    corr.mitre_tactics,
      });
      const cveId = nodeId('cve', corr.cve_id);
      if (nodes.has(cveId)) {
        addEdge(actorId, cveId, 'exploits', { label: corr.campaign || 'attributed' });
      }
    }
  }

  // ── Step 5: Cross-link IPs → domains (co-occurrence heuristic) ───────────
  const ipNodes     = [...nodes.values()].filter(n => n.type === 'ip');
  const domainNodes = [...nodes.values()].filter(n => n.type === 'domain');

  // If IP and domain both connect to same CVE → likely same infrastructure
  for (const ip of ipNodes) {
    for (const dom of domainNodes) {
      // Find shared CVE neighbors
      const ipTargets  = edges.filter(e => e.source === ip.id).map(e => e.target);
      const domTargets = edges.filter(e => e.source === dom.id).map(e => e.target);
      const shared     = ipTargets.filter(t => domTargets.includes(t));
      if (shared.length > 0) {
        addEdge(ip.id, dom.id, 'resolves_to', { label: 'same CVE infrastructure', weight: shared.length });
      }
    }
  }

  return {
    nodes: [...nodes.values()],
    edges,
    stats: {
      total_nodes: nodes.size,
      total_edges: edges.length,
      node_types:  countByType([...nodes.values()], 'type'),
      edge_types:  countByType(edges, 'label'),
    },
    generated_at: new Date().toISOString(),
  };
}

// ─── Count by field ───────────────────────────────────────────────────────────
function countByType(arr, field) {
  const counts = {};
  for (const item of arr) {
    const key = item[field] || 'unknown';
    counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
}

// ─── Build graph from D1 (fetches entries + IOCs) ─────────────────────────────
export async function buildGraphFromD1(env, limit = 50) {
  if (!env?.DB) return buildGraph([], [], []);

  try {
    const [entriesRes, iocRes] = await Promise.all([
      env.DB.prepare(
        `SELECT id, title, severity, cvss, exploit_status, known_ransomware,
                ioc_list, epss_score
         FROM threat_intel
         WHERE severity IN ('CRITICAL','HIGH')
         ORDER BY cvss DESC LIMIT ?`
      ).bind(limit).all(),
      env.DB.prepare(
        `SELECT i.intel_id, i.type, i.value, i.defanged
         FROM ioc_registry i
         INNER JOIN threat_intel t ON i.intel_id = t.id
         LIMIT 200`
      ).all(),
    ]);

    return buildGraph(
      entriesRes?.results || [],
      iocRes?.results     || [],
      []
    );
  } catch (err) {
    return buildGraph([], [], []);
  }
}

// ─── Subgraph: get neighborhood of a given node (1-hop) ──────────────────────
export function getNeighborhood(graph, nodeId, depth = 1) {
  const targetNode = graph.nodes.find(n => n.id === nodeId || n.value === nodeId);
  if (!targetNode) return { nodes: [], edges: [] };

  const visited   = new Set([targetNode.id]);
  const nodeIds   = new Set([targetNode.id]);
  const edgeList  = [];

  for (let d = 0; d < depth; d++) {
    for (const edge of graph.edges) {
      if (visited.has(edge.source)) {
        nodeIds.add(edge.target);
        edgeList.push(edge);
      }
      if (visited.has(edge.target)) {
        nodeIds.add(edge.source);
        edgeList.push(edge);
      }
    }
    for (const id of nodeIds) visited.add(id);
  }

  return {
    nodes: graph.nodes.filter(n => nodeIds.has(n.id)),
    edges: edgeList.filter((e, i, a) => a.findIndex(x => x.id === e.id) === i),
  };
}
