/* Tests — AI-specific threat intel filter (runs on the existing CTI pipeline's
 * already-fetched NVD/CISA-KEV/GitHub entries, no new network calls). Verifies
 * AI/LLM-ecosystem detection, OWASP LLM Top 10 heuristic mapping, and that only
 * real, source-attributed entries get written to ai_threat_feed. */
import { describe, it, expect } from 'vitest';
import { isAIRelated, mapToOwaspLLM, mapToMitreAttack, mapToMitreAtlas, classifyFeedType, runAIThreatIngestion } from '../src/services/aiThreatIngestion.js';

// ── In-memory D1 ────────────────────────────────────────────────────────────
// failOn: optional id whose INSERT throws once per batch call (simulates a
// single bad row so the per-row fallback path can be exercised).
function memDB({ failBatchOnce = false } = {}) {
  const rows = new Map();
  let batchCalls = 0;
  const mk = (sql) => ({
    _sql: sql, _b: [],
    bind(...a) { this._b = a; return this; },
    async run() {
      if (/^\s*INSERT INTO ai_threat_feed/i.test(sql)) {
        const [id, feed_type, title, description, severity, cve_id,
          affected_frameworks, iocs, mitigations, owasp_ref, attack_ref, atlas_ref,
          source_url, published_at, metadata] = this._b;
        rows.set(id, { id, feed_type, title, description, severity, cve_id,
          affected_frameworks, iocs, mitigations, owasp_ref, attack_ref, atlas_ref,
          source_url, published_at, metadata });
      }
      return { success: true };
    },
  });
  return {
    rows,
    prepare(sql) { return mk(sql); },
    async batch(stmts) {
      batchCalls += 1;
      if (failBatchOnce && batchCalls === 1) throw new Error('simulated batch failure');
      for (const s of stmts) await s.run();
      return stmts.map(() => ({ success: true }));
    },
  };
}

const AI_CVE = {
  id: 'CVE-2024-5184', title: 'Embedchain RAG Framework SSRF', severity: 'CRITICAL',
  source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-5184',
  published_at: '2024-05-20', exploit_status: 'unconfirmed',
  description: 'Embedchain allows retrieval of arbitrary URLs via RAG pipeline indirect injection.',
  affected_products: '["cpe:2.3:a:embedchain_project:embedchain"]', iocs: '[]',
};

const UNRELATED_CVE = {
  id: 'CVE-2024-3400', title: 'PAN-OS Command Injection', severity: 'CRITICAL',
  source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-3400',
  published_at: '2024-04-12', exploit_status: 'confirmed',
  description: 'A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS.',
  affected_products: '["cpe:2.3:o:paloaltonetworks:pan-os"]', iocs: '[]',
};

const GHSA_PROMPT_INJECTION = {
  id: 'GHSA-test-0001', title: 'LangChain prompt injection via tool output', severity: 'HIGH',
  source: 'github', source_url: 'https://github.com/advisories/GHSA-test-0001',
  published_at: '2024-06-01', exploit_status: 'unconfirmed',
  description: 'LangChain agents are vulnerable to indirect prompt injection through tool outputs.',
  affected_products: '[]', iocs: '[]',
};

describe('isAIRelated', () => {
  it('matches entries referencing AI/LLM ecosystem products', () => {
    const r = isAIRelated(AI_CVE);
    expect(r.matched).toBe(true);
    expect(r.matchedKeywords).toContain('embedchain');
  });

  it('does not match unrelated generic CVEs (no false positives)', () => {
    const r = isAIRelated(UNRELATED_CVE);
    expect(r.matched).toBe(false);
    expect(r.matchedKeywords).toHaveLength(0);
  });

  it('matches GitHub advisories for AI frameworks by keyword', () => {
    const r = isAIRelated(GHSA_PROMPT_INJECTION);
    expect(r.matched).toBe(true);
    expect(r.matchedKeywords).toEqual(expect.arrayContaining(['langchain', 'prompt injection']));
  });

  it('is resilient to malformed affected_products JSON', () => {
    const r = isAIRelated({ ...AI_CVE, affected_products: 'not-json' });
    expect(r.matched).toBe(true); // still matches via title/description
  });
});

describe('mapToOwaspLLM', () => {
  it('maps prompt injection language to LLM01', () => {
    expect(mapToOwaspLLM('this is a prompt injection via rag pipeline')).toBe('LLM01');
  });
  it('maps data poisoning language to LLM04', () => {
    expect(mapToOwaspLLM('a training data poisoning attack')).toBe('LLM04');
  });
  it('returns null when no confident mapping exists', () => {
    expect(mapToOwaspLLM('a generic buffer overflow in a network device')).toBeNull();
  });
});

describe('mapToMitreAtlas', () => {
  it('maps prompt injection language to AML.T0051', () => {
    expect(mapToMitreAtlas('this is a prompt injection via rag pipeline')).toBe('AML.T0051');
  });
  it('maps jailbreak language to AML.T0054', () => {
    expect(mapToMitreAtlas('a many-shot jailbreak technique')).toBe('AML.T0054');
  });
  it('maps training data poisoning language to AML.T0020', () => {
    expect(mapToMitreAtlas('a training data poisoning attack')).toBe('AML.T0020');
  });
  it('returns null when no confident mapping exists', () => {
    expect(mapToMitreAtlas('a generic buffer overflow in a network device')).toBeNull();
  });
});

describe('mapToMitreAttack', () => {
  it('maps remote code execution language to T1059', () => {
    expect(mapToMitreAttack('allows remote code execution via crafted payload')).toBe('T1059');
  });
  it('maps SSRF language to T1190', () => {
    expect(mapToMitreAttack('a server-side request forgery in the rag pipeline')).toBe('T1190');
  });
  it('returns null when no confident mapping exists', () => {
    expect(mapToMitreAttack('a generic information disclosure issue')).toBeNull();
  });
});

describe('classifyFeedType', () => {
  it('classifies prompt-injection language as prompt_attack, matching the schema enum', () => {
    expect(classifyFeedType('a prompt injection via tool output', false)).toBe('prompt_attack');
  });
  it('classifies agent-framework/MCP language as agent_threat', () => {
    expect(classifyFeedType('a flaw in an mcp server implementation', false)).toBe('agent_threat');
  });
  it('falls back to vulnerability for CVE entries with no other signal', () => {
    expect(classifyFeedType('a buffer overflow in embedchain', true)).toBe('vulnerability');
  });
  it('falls back to advisory for non-CVE entries with no other signal', () => {
    expect(classifyFeedType('a buffer overflow in embedchain', false)).toBe('advisory');
  });
});

describe('runAIThreatIngestion', () => {
  it('filters a mixed batch and only stores AI-relevant, source-attributed rows', async () => {
    const env = { DB: memDB() };
    const result = await runAIThreatIngestion(env, [AI_CVE, UNRELATED_CVE, GHSA_PROMPT_INJECTION]);

    expect(result.matched).toBe(2);
    expect(result.inserted).toBe(2);
    expect(result.errors).toHaveLength(0);
    expect(env.DB.rows.has('ai_CVE-2024-5184')).toBe(true);
    expect(env.DB.rows.has('ai_CVE-2024-3400')).toBe(false);

    const stored = env.DB.rows.get('ai_CVE-2024-5184');
    expect(stored.cve_id).toBe('CVE-2024-5184');
    expect(stored.source_url).toBe('https://nvd.nist.gov/vuln/detail/CVE-2024-5184');
    expect(stored.owasp_ref).toBe('LLM01');
    expect(stored.atlas_ref).toBe('AML.T0051');
    expect(stored.attack_ref).toBe('T1190');
    expect(typeof stored.published_at).toBe('number');
  });

  it('does not set cve_id for non-CVE (GHSA) entries', async () => {
    const env = { DB: memDB() };
    await runAIThreatIngestion(env, [GHSA_PROMPT_INJECTION]);
    const stored = env.DB.rows.get('ai_GHSA-test-0001');
    expect(stored.cve_id).toBeNull();
  });

  it('is a no-op with no DB binding or empty input', async () => {
    expect(await runAIThreatIngestion({}, [AI_CVE])).toEqual({ matched: 0, inserted: 0, errors: [] });
    expect(await runAIThreatIngestion({ DB: memDB() }, [])).toEqual({ matched: 0, inserted: 0, errors: [] });
  });

  it('stores matched_keywords provenance in metadata', async () => {
    const env = { DB: memDB() };
    await runAIThreatIngestion(env, [AI_CVE]);
    const stored = env.DB.rows.get('ai_CVE-2024-5184');
    const meta = JSON.parse(stored.metadata);
    expect(meta.ingested_from).toBe('cti_pipeline_filter');
    expect(meta.matched_keywords).toContain('embedchain');
  });

  it('skips entries with no id rather than writing a malformed row', async () => {
    const env = { DB: memDB() };
    const result = await runAIThreatIngestion(env, [{ ...AI_CVE, id: undefined }]);
    expect(result.matched).toBe(0);
    expect(env.DB.rows.size).toBe(0);
  });

  it('falls back to per-row inserts when a batch write fails, so one bad row does not drop the rest', async () => {
    const env = { DB: memDB({ failBatchOnce: true }) };
    const result = await runAIThreatIngestion(env, [AI_CVE, GHSA_PROMPT_INJECTION]);
    expect(result.inserted).toBe(2);
    expect(env.DB.rows.has('ai_CVE-2024-5184')).toBe(true);
    expect(env.DB.rows.has('ai_GHSA-test-0001')).toBe(true);
  });
});
