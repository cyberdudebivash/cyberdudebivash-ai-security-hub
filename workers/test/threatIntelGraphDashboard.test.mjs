// CAP-TIH-004 — workers/src/handlers/threatGraph.js (a real, working curated
// threat-intelligence knowledge graph: APT groups, malware, CVEs, MITRE ATT&CK
// techniques, sectors, BFS shortest-path, live CISA-KEV + D1 enrichment) had
// zero frontend callers — exhaustive grep of frontend/*.html for /api/threat-graph
// previously returned no matches. This locks in the fix: a real "Global Intel
// Graph" dashboard tab now calls all 5 real sub-routes and renders the real
// response. Named distinctly from the dashboard's pre-existing "Threat Graph"
// tab (built entirely client-side from the user's own scan history, no backend
// call at all) to avoid presenting two unrelated features under the same name.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  handleGetThreatGraph, handleGetGraphNodes, handleGetGraphPaths,
  handleGraphQuery, handleGraphSummary,
} from '../src/handlers/threatGraph.js';

const root = resolve(import.meta.dirname, '..');
const dash = readFileSync(resolve(root, '../frontend/user-dashboard.html'), 'utf8');

function req(url, opts) { return new Request(url, opts); }

// threatGraph.js responds via lib/response.js's ok()/fail() helpers, which
// wrap every body as { success, data, error, timestamp } — a different
// convention from intelligencePreview.js's flat Response.json(). Every
// assertion below reads through .data to match the real wire shape.
describe('CAP-TIH-004 — threatGraph.js backend, real data only', () => {
  it('summary returns real top APTs and critical CVEs derived from the curated knowledge base', async () => {
    const res = await handleGraphSummary(req('https://x/api/threat-graph/summary'), {});
    const { data } = await res.json();
    expect(data.top_active_apts.length).toBeGreaterThan(0);
    expect(data.critical_cves.length).toBeGreaterThan(0);
    for (const apt of data.top_active_apts) expect(apt.label).toBeTruthy();
  });

  it('node search filters by type and query text', async () => {
    const res = await handleGetGraphNodes(req('https://x/api/threat-graph/nodes?type=apt_group&q=apt29'), {});
    const { data } = await res.json();
    expect(data.nodes.length).toBeGreaterThan(0);
    expect(data.nodes.every(n => n.type === 'apt_group')).toBe(true);
    expect(data.nodes.some(n => n.id === 'apt29')).toBe(true);
  });

  it('path finder returns a real BFS shortest path between two connected nodes', async () => {
    const res = await handleGetGraphPaths(req('https://x/api/threat-graph/paths?from=apt41&to=sec_tech'), {});
    const { data } = await res.json();
    expect(data.found).toBe(true);
    expect(data.path_nodes[0].id).toBe('apt41');
    expect(data.path_nodes[data.path_nodes.length - 1].id).toBe('sec_tech');
  });

  it('path finder honestly reports no path when target node does not exist', async () => {
    const res = await handleGetGraphPaths(req('https://x/api/threat-graph/paths?from=apt41&to=not_a_real_node'), {});
    expect(res.status).toBe(404);
  });

  it('subgraph query returns real neighbors within the requested depth', async () => {
    const res = await handleGraphQuery(req('https://x/api/threat-graph/query', {
      method: 'POST', body: JSON.stringify({ node_id: 'lockbit3', depth: 2 }),
    }), {});
    const { data } = await res.json();
    expect(data.center.id).toBe('lockbit3');
    expect(data.nodes.length).toBeGreaterThan(1);
  });

  it('full graph endpoint is honestly labeled as curated + live, not fabricated as fully live', async () => {
    const res = await handleGetThreatGraph(req('https://x/api/threat-graph?live=false'), {});
    const { data } = await res.json();
    expect(data.meta.knowledge_base).toMatch(/curated/i);
    expect(data.nodes.length).toBeGreaterThan(0);
    expect(data.edges.length).toBeGreaterThan(0);
  });
});

describe('user-dashboard.html — Global Intel Graph tab (CAP-TIH-004)', () => {
  it('has a real nav-item distinct from the existing client-side "Threat Graph" tab', () => {
    expect(dash).toContain(`data-page="intel-graph" onclick="showPage('intel-graph',this)"`);
    expect(dash).toContain(`data-page="threatgraph" onclick="showPage('threatgraph',this);initThreatGraph()"`);
  });

  // 2026-07-13: intelGraphSummary() moved off the nav-item onclick and into
  // showPage()'s id-dispatch block — a deep link (?tab=intel-graph) calls
  // showPage() directly and never runs the nav item's onclick, so a browser
  // click-through pass caught the summary card never loading on that path.
  it('auto-loads the summary from showPage(), not a nav-item onclick side-call', () => {
    const showPageStart = dash.indexOf('function showPage(id, el)');
    const showPageFn = dash.slice(showPageStart, dash.indexOf('\n  }', showPageStart) + 4);
    expect(showPageFn).toContain(`id === 'intel-graph'`);
    expect(showPageFn).toContain('intelGraphSummary()');
  });

  it('has a real page section with all 4 tools', () => {
    expect(dash).toContain('id="page-intel-graph"');
    expect(dash).toContain('id="intel-graph-summary"');
    expect(dash).toContain('id="intel-graph-nodes-result"');
    expect(dash).toContain('id="intel-graph-path-result"');
    expect(dash).toContain('id="intel-graph-query-result"');
  });

  it('each tool calls a real, distinct /api/threat-graph* sub-route', () => {
    expect(dash).toContain(`intelGraphGet('/api/threat-graph/summary')`);
    expect(dash).toContain('/api/threat-graph/nodes?');
    expect(dash).toContain('/api/threat-graph/paths?from=');
    expect(dash).toContain(`apiFetch('/api/threat-graph/query'`);
  });

  it('unwraps the real {success,data,error} envelope from lib/response.js, not the flat shape used by /api/preview/*', () => {
    expect(dash).toContain('body?.data || {}');
    expect(dash).toMatch(/intelGraphGet\(path\)[\s\S]{0,200}body\?\.data/);
  });

  it('the page explicitly tells the customer how this differs from the existing Threat Graph tab (no silent name collision)', () => {
    const start = dash.indexOf('id="page-intel-graph"');
    const section = dash.slice(start, start + 800);
    expect(section).toMatch(/distinct from .Threat Graph./i);
  });

  // CodeQL js/xss-through-dom (PR #218): intelGraphQuery()'s data.center-missing
  // fallback rendered the raw node-ID input into innerHTML unescaped. The real
  // backend (handleGetGraphPaths) also echoes raw from/to query params straight
  // back in its 404 error text, which intelGraphPath() renders — same sink.
  // Live payload-execution proof of this fix lives in a Playwright pass (not
  // committed here, no browser runtime in this suite); this locks the escaping
  // calls themselves so a future edit can't silently drop them.
  describe('XSS hardening — CodeQL alert #144 (PR #218)', () => {
    it('defines an escapeHtml() helper', () => {
      expect(dash).toMatch(/function escapeHtml\(s\)\s*\{/);
    });

    it('intelGraphQuery() escapes the node-ID fallback before it can reach innerHTML', () => {
      const start = dash.indexOf('async function intelGraphQuery');
      const fn = dash.slice(start, dash.indexOf('\n  }', start) + 4);
      expect(fn).toContain('data.center?.label || escapeHtml(nodeId)');
    });

    it('intelGraphPath() escapes both the server-echoed error and the attack narrative', () => {
      const start = dash.indexOf('async function intelGraphPath');
      const fn = dash.slice(start, dash.indexOf('\n  }', start) + 4);
      expect(fn).toContain('escapeHtml(error ||');
      expect(fn).toContain('escapeHtml(data.attack_narrative)');
    });

    it('intelGraphNodes() and intelGraphSummary() escape their error fallbacks too (defense in depth)', () => {
      const nodesStart = dash.indexOf('async function intelGraphNodes');
      const nodesFn = dash.slice(nodesStart, dash.indexOf('\n  }', nodesStart) + 4);
      expect(nodesFn).toContain('escapeHtml(error ||');

      const summaryStart = dash.indexOf('async function intelGraphSummary');
      const summaryFn = dash.slice(summaryStart, dash.indexOf('\n  }', summaryStart) + 4);
      expect(summaryFn).toContain('escapeHtml(error ||');
    });
  });
});
