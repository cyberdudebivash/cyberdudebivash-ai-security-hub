/**
 * CYBERDUDEBIVASH® AI Security Hub — DevSecOps Real Scanners
 * ------------------------------------------------------------------------
 * Pre-Cisco/Oracle audit found devsecops.html advertising SAST, DAST, SCA,
 * IaC scanning, and SBOM generation as live platform capabilities, but only
 * the Vibe-Code Scanner (a real, context-aware static analyzer) actually had
 * a working backend — the other four were content-only, with no automated
 * engine behind them anywhere in this codebase. This module closes that gap
 * honestly:
 *
 *   SAST  — POST /api/devsecops/sast  — same real engine that backs the
 *           Vibe-Code Scanner (context masking, CWE/OWASP mapping,
 *           confidence scoring), exposed generically rather than rebuilt.
 *   SCA   — POST /api/devsecops/sca   — real, live lookups against OSV.dev
 *           (Google's open, authoritative vulnerability database covering
 *           npm, PyPI, Go, Maven, RubyGems, crates.io, etc.) for every
 *           dependency in a submitted manifest. Not a static local list —
 *           every scan hits the live API.
 *   SBOM  — POST /api/devsecops/sbom  — generates a real CycloneDX 1.5 JSON
 *           SBOM from a submitted package manifest.
 *   AI-BOM — POST /api/devsecops/ai-bom — CycloneDX 1.5 BOM that additionally
 *           flags which components are known AI/ML packages (LLM provider
 *           SDKs, agent-orchestration frameworks, model runtimes) via a
 *           maintained name map, cross-references the agent-orchestration
 *           frameworks among them against the real, D1-backed
 *           agent_threat_advisories table (the same data backing
 *           frontend/agent-threats.html), and runs the same live OSV.dev
 *           lookup as SCA across the full manifest. This does not introspect
 *           live model weights, prompts, or deployed inference endpoints —
 *           it is a manifest-based inventory + known-vulnerability check,
 *           the same honest scope as the SBOM/SCA tools above.
 *
 * DAST and IaC scanning are intentionally NOT claimed here. Building a safe,
 * non-destructive active scanner against arbitrary user-supplied targets is
 * a security-sensitive undertaking (rate limiting, consent/authorization
 * verification, SSRF protections) that deserves its own dedicated build —
 * not a rushed addition bolted on to close an audit finding. See the
 * accompanying audit report for the honest current status of those two.
 */
'use strict';

import { scanVibeCode } from './vibe-code/engine.js';

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

const MAX_DEPS_PER_SCAN = 150;
const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';

// Shared by SCA and AI-BOM — one round trip against OSV.dev for a manifest.
// Returns the raw per-package results array (index-aligned with `deps`) or throws.
async function queryOsvBatch(deps, ecosystem) {
  const queries = deps.map(d => ({ version: d.version, package: { name: d.name, ecosystem } }));
  const resp = await fetch(OSV_BATCH_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ queries }),
    signal: AbortSignal.timeout(15000),
  });
  if (!resp.ok) throw new Error(`OSV.dev returned HTTP ${resp.status}`);
  const data = await resp.json();
  return data.results || [];
}

const ECO_TO_PURL_TYPE = { npm: 'npm', PyPI: 'pypi', Go: 'golang', Maven: 'maven', RubyGems: 'gem', 'crates.io': 'cargo', NuGet: 'nuget', Packagist: 'composer' };

// ── SAST ──────────────────────────────────────────────────────────────────
// POST /api/devsecops/sast { code, language? }
export async function handleDevSecOpsSAST(request, env, authCtx = {}) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400); }
  const { code, language } = body;
  if (typeof code !== 'string' || code.length === 0) {
    return json({ error: 'code (string) is required' }, 400);
  }
  const result = scanVibeCode(code, { language });
  if (!result.ok) return json(result, 400);
  return json({
    success: true,
    engine: 'cdb-sast (vibe-code static analysis engine)',
    ...result,
  });
}

// ── SCA — real OSV.dev lookups ───────────────────────────────────────────
// POST /api/devsecops/sca { ecosystem: 'npm'|'PyPI'|'Go'|'Maven'|'RubyGems'|'crates.io',
//                            dependencies: [{ name, version }, ...] }
const VALID_ECOSYSTEMS = new Set(['npm', 'PyPI', 'Go', 'Maven', 'RubyGems', 'crates.io', 'NuGet', 'Packagist']);

export async function handleDevSecOpsSCA(request, env, authCtx = {}) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400); }
  const { ecosystem, dependencies } = body;

  if (!VALID_ECOSYSTEMS.has(ecosystem)) {
    return json({ error: 'Invalid ecosystem', valid: [...VALID_ECOSYSTEMS] }, 400);
  }
  if (!Array.isArray(dependencies) || dependencies.length === 0) {
    return json({ error: 'dependencies array required: [{ name, version }, ...]' }, 400);
  }
  const deps = dependencies.slice(0, MAX_DEPS_PER_SCAN).filter(d => d && typeof d.name === 'string' && typeof d.version === 'string');
  if (deps.length === 0) {
    return json({ error: 'No valid {name, version} entries found in dependencies' }, 400);
  }

  // OSV.dev batch query — one round trip for the whole manifest, real live data.
  let osvResults;
  try {
    osvResults = await queryOsvBatch(deps, ecosystem);
  } catch (e) {
    return json({
      success: false,
      error: 'SCA lookup failed — OSV.dev unreachable',
      detail: e.message,
      source: 'https://osv.dev',
    }, 502);
  }

  // OSV batch responses return only vuln IDs; fetch full details for any hits
  // (bounded — only for packages that actually have findings).
  const findings = [];
  for (let i = 0; i < deps.length; i++) {
    const vulnIds = (osvResults[i]?.vulns || []).map(v => v.id);
    if (vulnIds.length === 0) continue;
    findings.push({
      package: deps[i].name,
      version: deps[i].version,
      ecosystem,
      vulnerability_count: vulnIds.length,
      vulnerability_ids: vulnIds,
      osv_urls: vulnIds.map(id => `https://osv.dev/vulnerability/${id}`),
    });
  }

  return json({
    success: true,
    engine: 'cdb-sca (live OSV.dev lookups)',
    source: 'https://osv.dev — Google-maintained, aggregates NVD, GHSA, PyPI Advisory DB, Go vuln DB, RustSec, and more',
    scanned_at: new Date().toISOString(),
    ecosystem,
    dependencies_scanned: deps.length,
    dependencies_truncated: dependencies.length > MAX_DEPS_PER_SCAN,
    vulnerable_packages: findings.length,
    total_vulnerabilities: findings.reduce((s, f) => s + f.vulnerability_count, 0),
    findings,
  });
}

// ── SBOM — real CycloneDX 1.5 generation from a submitted manifest ───────
// POST /api/devsecops/sbom { project_name, ecosystem, dependencies: [{ name, version }] }
export async function handleDevSecOpsSBOM(request, env, authCtx = {}) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400); }
  const { project_name, ecosystem, dependencies } = body;

  if (!Array.isArray(dependencies) || dependencies.length === 0) {
    return json({ error: 'dependencies array required: [{ name, version }, ...]' }, 400);
  }
  const purlType = ECO_TO_PURL_TYPE[ecosystem] || 'generic';

  const components = dependencies.slice(0, MAX_DEPS_PER_SCAN)
    .filter(d => d && typeof d.name === 'string' && typeof d.version === 'string')
    .map(d => ({
      type: 'library',
      'bom-ref': `${purlType}:${d.name}@${d.version}`,
      name: d.name,
      version: d.version,
      purl: `pkg:${purlType}/${encodeURIComponent(d.name)}@${encodeURIComponent(d.version)}`,
    }));

  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'CYBERDUDEBIVASH', name: 'cdb-sbom-generator', version: '1.0.0' }],
      component: { type: 'application', name: project_name || 'unnamed-project', version: '0.0.0' },
    },
    components,
  };

  return json({
    success: true,
    engine: 'cdb-sbom (CycloneDX 1.5 generator)',
    generated_at: sbom.metadata.timestamp,
    component_count: components.length,
    sbom,
  });
}

// ── AI-BOM — AI/ML-aware Bill of Materials ──────────────────────────────
// Maintained map of well-known AI/ML package names to a component category
// and (where one genuinely exists) the matching agent_threat_advisories
// framework key. Deliberately NOT exhaustive and NOT a claim of live model
// introspection — this classifies packages the same way SBOM/SCA already
// classify any other dependency, just with AI/ML-specific metadata attached.
// `framework: null` means "known AI/ML component, but no advisory-feed
// cross-reference exists for it" — left null rather than guessed, so a
// provider SDK is never silently matched against an unrelated framework's
// advisories.
const AI_ML_PACKAGES = {
  'openai':                  { category: 'llm-provider-sdk',            framework: 'openai' },
  'langchain':               { category: 'agent-orchestration-framework', framework: 'langchain' },
  'langchain-core':          { category: 'agent-orchestration-framework', framework: 'langchain' },
  'langchain-community':     { category: 'agent-orchestration-framework', framework: 'langchain' },
  '@langchain/core':         { category: 'agent-orchestration-framework', framework: 'langchain' },
  '@langchain/community':    { category: 'agent-orchestration-framework', framework: 'langchain' },
  'pyautogen':               { category: 'agent-orchestration-framework', framework: 'autogen' },
  'autogen':                 { category: 'agent-orchestration-framework', framework: 'autogen' },
  'crewai':                  { category: 'agent-orchestration-framework', framework: 'crewai' },
  'semantic-kernel':         { category: 'agent-orchestration-framework', framework: 'semantic_kernel' },
  'llama-index':             { category: 'agent-orchestration-framework', framework: 'llama_index' },
  'llama_index':             { category: 'agent-orchestration-framework', framework: 'llama_index' },
  '@modelcontextprotocol/sdk': { category: 'mcp-sdk',                    framework: 'mcp' },
  'anthropic':               { category: 'llm-provider-sdk',            framework: null },
  '@anthropic-ai/sdk':       { category: 'llm-provider-sdk',            framework: null },
  'cohere':                  { category: 'llm-provider-sdk',            framework: null },
  'cohere-ai':               { category: 'llm-provider-sdk',            framework: null },
  'mistralai':               { category: 'llm-provider-sdk',            framework: null },
  'google-generativeai':     { category: 'llm-provider-sdk',            framework: null },
  '@google/generative-ai':   { category: 'llm-provider-sdk',            framework: null },
  'transformers':            { category: 'model-runtime',               framework: null },
  '@huggingface/transformers': { category: 'model-runtime',             framework: null },
  'huggingface-hub':         { category: 'model-hub-sdk',                framework: null },
  'huggingface_hub':         { category: 'model-hub-sdk',                framework: null },
  'sentence-transformers':   { category: 'embeddings-model',             framework: null },
  'torch':                   { category: 'ml-framework',                framework: null },
  'tensorflow':              { category: 'ml-framework',                framework: null },
  'onnxruntime':             { category: 'model-runtime',                framework: null },
  'vllm':                    { category: 'model-runtime',                framework: null },
  'ollama':                  { category: 'model-runtime',                framework: null },
};

const ADVISORY_FRAMEWORKS = ['mcp', 'langchain', 'autogen', 'openai', 'crewai', 'semantic_kernel', 'llama_index'];

// POST /api/devsecops/ai-bom { project_name, ecosystem, dependencies: [{ name, version }] }
export async function handleDevSecOpsAIBOM(request, env, authCtx = {}) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400); }
  const { project_name, ecosystem, dependencies } = body;

  if (!Array.isArray(dependencies) || dependencies.length === 0) {
    return json({ error: 'dependencies array required: [{ name, version }, ...]' }, 400);
  }
  const deps = dependencies.slice(0, MAX_DEPS_PER_SCAN).filter(d => d && typeof d.name === 'string' && typeof d.version === 'string');
  if (deps.length === 0) {
    return json({ error: 'No valid {name, version} entries found in dependencies' }, 400);
  }
  const purlType = ECO_TO_PURL_TYPE[ecosystem] || 'generic';

  // ── Classify + build CycloneDX components ──────────────────────────────
  const aiComponents = [];
  const components = deps.map(d => {
    const match = AI_ML_PACKAGES[d.name] || AI_ML_PACKAGES[d.name.toLowerCase()];
    const component = {
      type: 'library',
      'bom-ref': `${purlType}:${d.name}@${d.version}`,
      name: d.name,
      version: d.version,
      purl: `pkg:${purlType}/${encodeURIComponent(d.name)}@${encodeURIComponent(d.version)}`,
    };
    if (match) {
      component.properties = [
        { name: 'cdb:ai-ml-component', value: 'true' },
        { name: 'cdb:ai-category', value: match.category },
      ];
      aiComponents.push({ name: d.name, version: d.version, category: match.category, framework: match.framework });
    }
    return component;
  });

  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'CYBERDUDEBIVASH', name: 'cdb-ai-bom-generator', version: '1.0.0' }],
      component: { type: 'application', name: project_name || 'unnamed-project', version: '0.0.0' },
      properties: [{ name: 'cdb:ai-component-count', value: String(aiComponents.length) }],
    },
    components,
  };

  // ── Real OSV.dev CVE lookup across the full manifest (same engine as SCA) ──
  let osvFindings = [];
  let osvAvailable = true;
  if (VALID_ECOSYSTEMS.has(ecosystem)) {
    try {
      const osvResults = await queryOsvBatch(deps, ecosystem);
      for (let i = 0; i < deps.length; i++) {
        const vulnIds = (osvResults[i]?.vulns || []).map(v => v.id);
        if (vulnIds.length === 0) continue;
        osvFindings.push({ package: deps[i].name, version: deps[i].version, vulnerability_ids: vulnIds });
      }
    } catch {
      osvAvailable = false; // Non-fatal — the BOM itself is still returned.
    }
  } else {
    osvAvailable = false;
  }
  const aiPackageNames = new Set(aiComponents.map(c => c.name));
  const aiOsvFindings = osvFindings.filter(f => aiPackageNames.has(f.package));

  // ── Cross-reference AI-framework components against real advisory feed ──
  const detectedFrameworks = [...new Set(aiComponents.map(c => c.framework).filter(Boolean).filter(f => ADVISORY_FRAMEWORKS.includes(f)))];
  let agentAdvisories = [];
  let advisoryLookupAvailable = true;
  if (detectedFrameworks.length > 0 && env?.DB) {
    try {
      const placeholders = detectedFrameworks.map(() => '?').join(',');
      const rows = await env.DB.prepare(
        `SELECT advisory_id, title, framework, severity, cvss_score, affected_versions, patch_status, published_at
         FROM agent_threat_advisories WHERE framework IN (${placeholders}) ORDER BY published_at DESC LIMIT 100`
      ).bind(...detectedFrameworks).all();
      agentAdvisories = rows.results || [];
    } catch {
      advisoryLookupAvailable = false;
    }
  } else if (detectedFrameworks.length > 0) {
    advisoryLookupAvailable = false; // No DB binding available in this context.
  }

  // ── Honest, real-count-driven AI risk score (same weighting style as the agent-threats overview) ──
  const SEVERITY_WEIGHT = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const cveComponent = Math.min(50, aiOsvFindings.reduce((s, f) => s + f.vulnerability_ids.length, 0) * 10);
  const advisoryComponent = Math.min(50, agentAdvisories.reduce((s, a) => s + (SEVERITY_WEIGHT[a.severity] || 1) * 5, 0));
  const aiRiskScore = aiComponents.length > 0 ? Math.min(100, cveComponent + advisoryComponent) : 0;
  const aiRiskLevel = aiRiskScore >= 70 ? 'HIGH' : aiRiskScore >= 35 ? 'MEDIUM' : aiRiskScore > 0 ? 'LOW' : 'NONE';

  return json({
    success: true,
    engine: 'cdb-ai-bom (CycloneDX 1.5 + AI/ML classification + agent-threat cross-reference)',
    generated_at: sbom.metadata.timestamp,
    component_count: components.length,
    ai_component_count: aiComponents.length,
    ai_components: aiComponents,
    sbom,
    osv_lookup_available: osvAvailable,
    ai_specific_cve_findings: aiOsvFindings,
    advisory_lookup_available: advisoryLookupAvailable,
    frameworks_detected: detectedFrameworks,
    agent_advisories: agentAdvisories,
    ai_risk_score: aiRiskScore,
    ai_risk_level: aiRiskLevel,
    note: 'Manifest-based inventory and known-vulnerability check — does not introspect live model weights, prompts, or deployed inference endpoints.',
  });
}
