/* Regression tests — real DevSecOps scanners (closes Oracle-audit gap #2:
 * devsecops.html previously advertised SAST/SCA/SBOM as live platform
 * capabilities with no automated backend behind four of its six pillars).
 * Proves: SAST delegates to the real static-analysis engine and finds real
 * issues; SCA correctly calls OSV.dev and maps its response; SBOM produces
 * valid CycloneDX structure; all three validate input and fail safely. */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  handleDevSecOpsSAST,
  handleDevSecOpsSCA,
  handleDevSecOpsSBOM,
  handleDevSecOpsAIBOM,
} from '../src/handlers/devsecopsScanners.js';

function reqWithBody(body) {
  return { json: async () => body };
}

describe('DevSecOps SAST — real engine, not a stub', () => {
  it('finds a real SQL injection pattern in submitted code', async () => {
    const code = `
      function getUser(req, db) {
        const id = req.query.id;
        return db.query("SELECT * FROM users WHERE id = " + id);
      }
    `;
    const res = await handleDevSecOpsSAST(reqWithBody({ code, language: 'javascript' }), {}, {});
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.total_findings).toBeGreaterThan(0);
    expect(body.findings.some(f => /sql|injection/i.test(f.rule_id + f.title))).toBe(true);
  });

  it('rejects a request with no code', async () => {
    const res = await handleDevSecOpsSAST(reqWithBody({}), {}, {});
    expect(res.status).toBe(400);
  });

  it('rejects invalid JSON body', async () => {
    const res = await handleDevSecOpsSAST({ json: async () => { throw new Error('bad json'); } }, {}, {});
    expect(res.status).toBe(400);
  });
});

describe('DevSecOps SCA — real OSV.dev integration', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()); });

  it('calls the real OSV.dev batch endpoint with correctly shaped queries', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ results: [{ vulns: [{ id: 'GHSA-test-1234' }] }, { vulns: [] }] }),
    });

    const res = await handleDevSecOpsSCA(reqWithBody({
      ecosystem: 'npm',
      dependencies: [{ name: 'lodash', version: '4.17.15' }, { name: 'express', version: '4.18.2' }],
    }), {}, {});
    const body = await res.json();

    expect(global.fetch).toHaveBeenCalledWith(
      'https://api.osv.dev/v1/querybatch',
      expect.objectContaining({ method: 'POST' })
    );
    const sentBody = JSON.parse(global.fetch.mock.calls[0][1].body);
    expect(sentBody.queries).toEqual([
      { version: '4.17.15', package: { name: 'lodash', ecosystem: 'npm' } },
      { version: '4.18.2', package: { name: 'express', ecosystem: 'npm' } },
    ]);

    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.vulnerable_packages).toBe(1);
    expect(body.total_vulnerabilities).toBe(1);
    expect(body.findings[0].package).toBe('lodash');
    expect(body.findings[0].vulnerability_ids).toEqual(['GHSA-test-1234']);
  });

  it('rejects an invalid ecosystem', async () => {
    const res = await handleDevSecOpsSCA(reqWithBody({ ecosystem: 'not-real', dependencies: [{ name: 'x', version: '1' }] }), {}, {});
    expect(res.status).toBe(400);
  });

  it('rejects an empty dependencies array', async () => {
    const res = await handleDevSecOpsSCA(reqWithBody({ ecosystem: 'npm', dependencies: [] }), {}, {});
    expect(res.status).toBe(400);
  });

  it('fails safely (502, not a crash) when OSV.dev is unreachable', async () => {
    global.fetch.mockRejectedValueOnce(new Error('network down'));
    const res = await handleDevSecOpsSCA(reqWithBody({
      ecosystem: 'npm', dependencies: [{ name: 'lodash', version: '4.17.15' }],
    }), {}, {});
    const body = await res.json();
    expect(res.status).toBe(502);
    expect(body.success).toBe(false);
    expect(body.error).toMatch(/OSV\.dev/);
  });

  it('caps dependency count and reports truncation', async () => {
    global.fetch.mockResolvedValueOnce({ ok: true, json: async () => ({ results: Array(150).fill({ vulns: [] }) }) });
    const manyDeps = Array.from({ length: 200 }, (_, i) => ({ name: `pkg${i}`, version: '1.0.0' }));
    const res = await handleDevSecOpsSCA(reqWithBody({ ecosystem: 'npm', dependencies: manyDeps }), {}, {});
    const body = await res.json();
    expect(body.dependencies_scanned).toBe(150);
    expect(body.dependencies_truncated).toBe(true);
  });
});

describe('DevSecOps SBOM — real CycloneDX generation', () => {
  it('produces a valid CycloneDX 1.5 structure with correct purls', async () => {
    const res = await handleDevSecOpsSBOM(reqWithBody({
      project_name: 'test-app',
      ecosystem: 'npm',
      dependencies: [{ name: 'lodash', version: '4.17.15' }],
    }), {}, {});
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.sbom.bomFormat).toBe('CycloneDX');
    expect(body.sbom.specVersion).toBe('1.5');
    expect(body.sbom.metadata.component.name).toBe('test-app');
    expect(body.sbom.components).toHaveLength(1);
    expect(body.sbom.components[0].purl).toBe('pkg:npm/lodash@4.17.15');
  });

  it('rejects an empty dependencies array', async () => {
    const res = await handleDevSecOpsSBOM(reqWithBody({ dependencies: [] }), {}, {});
    expect(res.status).toBe(400);
  });
});

describe('DevSecOps AI-BOM — AI/ML classification + real cross-references', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()); });

  function fakeDB(rows) {
    return {
      DB: {
        prepare: () => ({
          bind: () => ({ all: async () => ({ results: rows }) }),
        }),
      },
    };
  }

  it('classifies known AI/ML packages and leaves ordinary packages unflagged', async () => {
    global.fetch.mockResolvedValueOnce({ ok: true, json: async () => ({ results: [{}, {}, {}] }) });
    const res = await handleDevSecOpsAIBOM(reqWithBody({
      project_name: 'my-agent-app',
      ecosystem: 'PyPI',
      dependencies: [
        { name: 'langchain', version: '0.1.0' },
        { name: 'openai', version: '1.30.0' },
        { name: 'requests', version: '2.31.0' },
      ],
    }), fakeDB([]), {});
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.component_count).toBe(3);
    expect(body.ai_component_count).toBe(2);
    expect(body.ai_components.map(c => c.name).sort()).toEqual(['langchain', 'openai']);

    const langchainComponent = body.sbom.components.find(c => c.name === 'langchain');
    expect(langchainComponent.properties).toContainEqual({ name: 'cdb:ai-ml-component', value: 'true' });
    const requestsComponent = body.sbom.components.find(c => c.name === 'requests');
    expect(requestsComponent.properties).toBeUndefined();
  });

  it('cross-references detected frameworks against the real agent_threat_advisories table', async () => {
    global.fetch.mockResolvedValueOnce({ ok: true, json: async () => ({ results: [{}] }) });
    const advisoryRows = [{ advisory_id: 'AGT-001', framework: 'langchain', severity: 'HIGH', cvss_score: 7.5 }];
    const res = await handleDevSecOpsAIBOM(reqWithBody({
      ecosystem: 'PyPI',
      dependencies: [{ name: 'langchain', version: '0.1.0' }],
    }), fakeDB(advisoryRows), {});
    const body = await res.json();

    expect(body.advisory_lookup_available).toBe(true);
    expect(body.frameworks_detected).toEqual(['langchain']);
    expect(body.agent_advisories).toEqual(advisoryRows);
    expect(body.ai_risk_score).toBeGreaterThan(0);
    expect(body.ai_risk_level).not.toBe('NONE');
  });

  it('does not attempt an advisory lookup for AI packages with no matching framework key', async () => {
    global.fetch.mockResolvedValueOnce({ ok: true, json: async () => ({ results: [{}] }) });
    const res = await handleDevSecOpsAIBOM(reqWithBody({
      ecosystem: 'PyPI',
      dependencies: [{ name: 'anthropic', version: '0.30.0' }],
    }), fakeDB([]), {});
    const body = await res.json();

    expect(body.ai_component_count).toBe(1);
    expect(body.frameworks_detected).toEqual([]);
    expect(body.agent_advisories).toEqual([]);
  });

  it('degrades gracefully (no crash) when the database binding is unavailable', async () => {
    global.fetch.mockResolvedValueOnce({ ok: true, json: async () => ({ results: [{}] }) });
    const res = await handleDevSecOpsAIBOM(reqWithBody({
      ecosystem: 'PyPI',
      dependencies: [{ name: 'langchain', version: '0.1.0' }],
    }), {}, {});
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.advisory_lookup_available).toBe(false);
    expect(body.agent_advisories).toEqual([]);
  });

  it('degrades gracefully (still returns the BOM) when OSV.dev is unreachable', async () => {
    global.fetch.mockRejectedValueOnce(new Error('network down'));
    const res = await handleDevSecOpsAIBOM(reqWithBody({
      ecosystem: 'PyPI',
      dependencies: [{ name: 'langchain', version: '0.1.0' }],
    }), fakeDB([]), {});
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.osv_lookup_available).toBe(false);
    expect(body.sbom.components).toHaveLength(1);
  });

  it('does not claim live model introspection anywhere in the response', async () => {
    global.fetch.mockResolvedValueOnce({ ok: true, json: async () => ({ results: [{}] }) });
    const res = await handleDevSecOpsAIBOM(reqWithBody({
      ecosystem: 'PyPI',
      dependencies: [{ name: 'langchain', version: '0.1.0' }],
    }), fakeDB([]), {});
    const body = await res.json();
    expect(body.note).toMatch(/does not introspect live model weights/i);
  });

  it('rejects an empty dependencies array', async () => {
    const res = await handleDevSecOpsAIBOM(reqWithBody({ dependencies: [] }), {}, {});
    expect(res.status).toBe(400);
  });

  it('rejects invalid JSON body', async () => {
    const res = await handleDevSecOpsAIBOM({ json: async () => { throw new Error('bad json'); } }, {}, {});
    expect(res.status).toBe(400);
  });
});
