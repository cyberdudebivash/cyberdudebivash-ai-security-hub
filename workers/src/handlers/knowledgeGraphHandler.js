import { isRealUser } from '../auth/middleware.js';
import { mapToAttack } from '../services/mitreAttackService.js';
/**
 * CYBERDUDEBIVASH AI Security Hub — P12.3 Knowledge Graph
 *
 * Endpoints:
 *   GET  /api/knowledge-graph        — full multi-domain relationship graph
 *   POST /api/knowledge-graph/query  — subgraph expansion from a node
 *
 * Reuses existing D1 tables — NO new tables.
 * Node types: CVE | ACTOR | ASSET | DECISION | INDUSTRY | CAMPAIGN
 * Edge types: targets | uses | mitigates | impacts | correlates
 *
 * Output: D3.js / Cytoscape.js ready { nodes, edges }
 *
 * Tier gate: PRO / ENTERPRISE / MSSP / OWNER / ADMIN
 */

// ─── Tier gate ────────────────────────────────────────────────────────────────
const ALLOWED_TIERS = new Set(['PRO', 'ENTERPRISE', 'MSSP', 'OWNER', 'ADMIN']);

function checkTier(authCtx) {
  if (!isRealUser(authCtx)) {
    return Response.json(
      { success: false, error: 'Authentication required', service: 'CDB-KNOWLEDGE-GRAPH' },
      { status: 401 }
    );
  }
  if (!ALLOWED_TIERS.has((authCtx.tier || '').toUpperCase())) {
    return Response.json(
      { success: false, error: 'PRO plan or above required for Knowledge Graph', upgrade: 'https://tools.cyberdudebivash.com/#pricing', service: 'CDB-KNOWLEDGE-GRAPH' },
      { status: 403 }
    );
  }
  return null;
}

// ─── KV helpers ───────────────────────────────────────────────────────────────
async function kvGet(env, key) {
  if (!env?.SECURITY_HUB_KV) return null;
  try {
    const raw = await env.SECURITY_HUB_KV.get(key);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

async function kvSet(env, key, value, ttl = 300) {
  if (!env?.SECURITY_HUB_KV) return;
  try { await env.SECURITY_HUB_KV.put(key, JSON.stringify(value), { expirationTtl: ttl }); }
  catch {}
}

// ─── D1 row fetchers ──────────────────────────────────────────────────────────
// threat_intel's only guaranteed columns are the self-healing set written by
// storeInD1()/ensureThreatIntelColumns() (services/threatIngestion.js) — there
// is no `cve_id`, `cvss_score`, or `mitre_technique` column. Those names only
// exist in schema_master.sql, a manual, workflow_dispatch-gated migration that
// production has never run. Querying them directly throws, is swallowed by
// .catch(() => []), and the graph silently returns success:true while empty.
// Alias the real self-healed columns and compute the MITRE correlation live
// via the already-production mapToAttack() engine instead of a column that
// will never exist.
async function fetchVulnRows(db) {
  if (!db) return [];
  const rows = await db.prepare(
    `SELECT id AS cve_id, cvss AS cvss_score, severity, actively_exploited, source,
            title, description, tags, weakness_types, exploit_status, known_ransomware
     FROM threat_intel ORDER BY cvss DESC LIMIT 100`
  ).all().then(r => r.results || []).catch(() => []);

  return rows.map(v => ({
    ...v,
    mitre_technique: mapToAttack(v).primary_technique?.technique_id || null,
  }));
}

// threat_actors is self-healed by services/threatActorEngine.js's
// ensureThreatActorsTable() with column `target_sectors`, not `sector` — and
// target_sectors is a JSON array (an actor can target several industries), not
// a single string. Parse it for real multi-industry edges, while keeping a
// joined `sector` string for the frontend's describeRealNode() tooltip, which
// already reads node.sector as display text.
async function fetchActorRows(db) {
  if (!db) return [];
  const rows = await db.prepare(
    `SELECT name, target_sectors, active FROM threat_actors LIMIT 50`
  ).all().then(r => r.results || []).catch(() => []);

  return rows.map(a => {
    let sectors = [];
    try {
      const parsed = JSON.parse(a.target_sectors || '[]');
      if (Array.isArray(parsed)) sectors = parsed.filter(Boolean);
    } catch {}
    return { ...a, sectors, sector: sectors.join(', ') };
  });
}

async function fetchAssetRows(db) {
  if (!db) return [];
  return db.prepare(
    `SELECT asset_value, asset_type FROM customer_assets LIMIT 100`
  ).all().then(r => r.results || []).catch(() => []);
}

// soc_decisions column names already match; the table itself is self-healed
// by services/decisionEngine.js's ensureSocDecisionsTable().
async function fetchDecisionRows(db) {
  if (!db) return [];
  return db.prepare(
    `SELECT id, cve_id, decision, priority, confidence, risk_score FROM soc_decisions LIMIT 50`
  ).all().then(r => r.results || []).catch(() => []);
}

// ─── Graph builder ────────────────────────────────────────────────────────────
function buildGraph(vulnRows = [], actorRows = [], assetRows = [], decisionRows = []) {
  const nodes = [];
  const edges = [];
  const nodeIds = new Set();

  const addNode = (id, type, label, props = {}) => {
    if (!nodeIds.has(id)) {
      nodeIds.add(id);
      nodes.push({ id, type, label, ...props });
    }
  };

  const addEdge = (source, target, type, weight = 1) => {
    if (nodeIds.has(source) && nodeIds.has(target)) {
      edges.push({ id: `${source}__${type}__${target}`, source, target, type, weight });
    }
  };

  // CVE nodes
  for (const v of vulnRows.slice(0, 100)) {
    addNode(v.cve_id, 'CVE', v.cve_id, {
      cvss:     v.cvss_score,
      severity: v.severity,
      kev:      Boolean(v.actively_exploited),
      source:   v.source,
    });

    // Industry node from sector data (derive from actor targeting patterns)
    if (v.source === 'cisa_kev') {
      addNode('industry:critical_infrastructure', 'INDUSTRY', 'Critical Infrastructure', { sector: 'multi' });
    }
  }

  // Actor nodes + edges
  for (const a of actorRows.slice(0, 50)) {
    const actorId = `actor:${a.name.replace(/\s+/g, '_')}`;
    addNode(actorId, 'ACTOR', a.name, { sector: a.sector, active: Boolean(a.active) });

    const sectors = Array.isArray(a.sectors) ? a.sectors : [];

    // Actor targets high-severity/KEV CVEs (correlation, not fabrication)
    if (sectors.length > 0) {
      for (const v of vulnRows.filter(v => v.source === 'cisa_kev' || v.cvss_score >= 9).slice(0, 20)) {
        addEdge(actorId, v.cve_id, 'targets', 1);
      }
    }

    // Industry node + edge — one per real target sector. target_sectors is a
    // JSON array; a single actor commonly targets several industries.
    for (const sector of sectors) {
      const industryId = `industry:${sector.toLowerCase().replace(/\s+/g, '_')}`;
      addNode(industryId, 'INDUSTRY', sector, { sector });
      addEdge(actorId, industryId, 'targets', 1);
    }
  }

  // Asset nodes + edges
  const watchlistAssets = assetRows.filter(a => a.asset_type === 'cve_watchlist');
  const techAssets      = assetRows.filter(a => a.asset_type === 'technology');

  for (const a of techAssets.slice(0, 50)) {
    const assetId = `asset:${a.asset_value.replace(/\s+/g, '_')}`;
    addNode(assetId, 'ASSET', a.asset_value, { asset_type: a.asset_type });
  }

  for (const a of watchlistAssets.slice(0, 50)) {
    const assetId = `asset:${a.asset_value.replace(/\s+/g, '_')}`;
    addNode(assetId, 'ASSET', a.asset_value, { asset_type: a.asset_type });
    // Direct CVE → Asset impact edge
    if (nodeIds.has(a.asset_value)) {
      addEdge(a.asset_value, assetId, 'impacts', 1);
    }
    // CVEs in watchlist are correlated with threat actors
    for (const actor of actorRows.filter(a => a.active).slice(0, 5)) {
      const actorId = `actor:${actor.name.replace(/\s+/g, '_')}`;
      addEdge(actorId, assetId, 'targets', 1);
    }
  }

  // Decision nodes + mitigates edges
  for (const d of decisionRows.slice(0, 50)) {
    const decId = `decision:${d.id}`;
    addNode(decId, 'DECISION', `${d.decision} — ${d.cve_id}`, {
      priority:   d.priority,
      confidence: d.confidence,
      risk_score: d.risk_score,
      cve_id:     d.cve_id,
    });
    // Decision mitigates its CVE
    if (nodeIds.has(d.cve_id)) {
      addEdge(decId, d.cve_id, 'mitigates', 1);
    }
  }

  // Correlates edges between CVEs sharing the same MITRE technique
  const mitreGroups = {};
  for (const v of vulnRows) {
    if (v.mitre_technique) {
      if (!mitreGroups[v.mitre_technique]) mitreGroups[v.mitre_technique] = [];
      mitreGroups[v.mitre_technique].push(v.cve_id);
    }
  }
  for (const [technique, cveIds] of Object.entries(mitreGroups)) {
    if (cveIds.length > 1) {
      // Create a CAMPAIGN node for shared-technique groups
      const campId = `campaign:${technique}`;
      addNode(campId, 'CAMPAIGN', `${technique} Campaign`, { technique });
      for (const cveId of cveIds.slice(0, 10)) {
        if (nodeIds.has(cveId)) addEdge(campId, cveId, 'uses', 1);
      }
    }
  }

  return {
    nodes,
    edges,
    node_counts: {
      cve:      nodes.filter(n => n.type === 'CVE').length,
      actor:    nodes.filter(n => n.type === 'ACTOR').length,
      asset:    nodes.filter(n => n.type === 'ASSET').length,
      decision: nodes.filter(n => n.type === 'DECISION').length,
      industry: nodes.filter(n => n.type === 'INDUSTRY').length,
      campaign: nodes.filter(n => n.type === 'CAMPAIGN').length,
    },
  };
}

// ─── P12.3 — GET /api/knowledge-graph ────────────────────────────────────────
export async function handleKnowledgeGraph(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  const userId = authCtx.userId || authCtx.user_id || null;
  const ck     = `kg:v1:full:${userId || 'platform'}`;
  const cached = await kvGet(env, ck);
  if (cached) return Response.json({ ...cached, _cache: 'HIT' });

  const db = env.DB;
  let vulnRows = [], actorRows = [], assetRows = [], decisionRows = [];

  if (db) {
    [vulnRows, actorRows, assetRows, decisionRows] = await Promise.all([
      fetchVulnRows(db),
      fetchActorRows(db),
      fetchAssetRows(db),
      fetchDecisionRows(db),
    ]);
  }

  const graph = buildGraph(vulnRows, actorRows, assetRows, decisionRows);

  const body = {
    success:      true,
    service:      'CDB-KNOWLEDGE-GRAPH',
    generated_at: new Date().toISOString(),
    format:       'd3-ready',
    nodes:        graph.nodes,
    edges:        graph.edges,
    node_counts:  graph.node_counts,
    edge_count:   graph.edges.length,
    note:         'Read-only relationship graph. Use POST /api/knowledge-graph/query to expand a subgraph.',
  };

  await kvSet(env, ck, body, 300);
  return Response.json(body);
}

// ─── P12.3 — POST /api/knowledge-graph/query ─────────────────────────────────
export async function handleKnowledgeGraphQuery(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  let body = {};
  try { body = await request.json(); } catch {}

  const { node_id, node_type, depth = 1 } = body;
  if (!node_id) return Response.json({ success: false, error: 'node_id required' }, { status: 400 });

  const effectiveDepth = Math.min(Math.max(1, Number(depth) || 1), 2);

  const db = env.DB;
  let vulnRows = [], actorRows = [], assetRows = [], decisionRows = [];

  if (db) {
    [vulnRows, actorRows, assetRows, decisionRows] = await Promise.all([
      fetchVulnRows(db),
      fetchActorRows(db),
      fetchAssetRows(db),
      fetchDecisionRows(db),
    ]);
  }

  const { nodes, edges } = buildGraph(vulnRows, actorRows, assetRows, decisionRows);

  // BFS up to effectiveDepth from node_id
  const visited = new Set([node_id]);
  let frontier = new Set([node_id]);

  for (let d = 0; d < effectiveDepth; d++) {
    const next = new Set();
    for (const e of edges) {
      if (frontier.has(e.source) && !visited.has(e.target)) {
        visited.add(e.target); next.add(e.target);
      }
      if (frontier.has(e.target) && !visited.has(e.source)) {
        visited.add(e.source); next.add(e.source);
      }
    }
    frontier = next;
    if (frontier.size === 0) break;
  }

  const subNodes = nodes.filter(n => visited.has(n.id));
  const subEdges = edges.filter(e => visited.has(e.source) && visited.has(e.target));

  return Response.json({
    success:      true,
    service:      'CDB-KNOWLEDGE-GRAPH-QUERY',
    generated_at: new Date().toISOString(),
    query:        { node_id, node_type, depth: effectiveDepth },
    nodes:        subNodes,
    edges:        subEdges,
    node_count:   subNodes.length,
    edge_count:   subEdges.length,
    note:         subNodes.length === 0 ? 'Node not found in graph. Ensure it exists in threat_intel, threat_actors, customer_assets, or soc_decisions.' : null,
  });
}
