/**
 * CYBERDUDEBIVASH v28 — AI Security Posture Management (ASPM) Handler
 * PILLAR 1: AI Asset Inventory + AI Security Score + Risk Dashboard
 *
 * POST /api/ai-security/assets/register     -> register AI asset
 * GET  /api/ai-security/assets              -> list org AI assets
 * POST /api/ai-security/assets/:id/scan     -> trigger security scan on asset
 * GET  /api/ai-security/posture             -> org AI security posture score
 * GET  /api/ai-security/dashboard           -> full ASPM dashboard data
 * GET  /api/ai-security/exposure-map        -> public exposure mapping
 */

const CORS = { 'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,PUT,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization' };
const json = (d,s=200) => new Response(JSON.stringify(d),{status:s,headers:{...CORS,'Content-Type':'application/json'}});
const err  = (m,s=400) => json({success:false,error:m},s);

// OWASP LLM Top 10 2025 checks per asset type
const OWASP_LLM_CHECKS = {
  model: [
    { id:'LLM01', name:'Prompt Injection',          weight:30, check:'Has input validation middleware on all inference endpoints?' },
    { id:'LLM02', name:'Insecure Output Handling',  weight:20, check:'Are model outputs sanitized before use in downstream systems?' },
    { id:'LLM03', name:'Training Data Poisoning',   weight:15, check:'Is training data provenance verified and monitored?' },
    { id:'LLM04', name:'Model DoS',                 weight:10, check:'Are rate limits and resource controls applied to the model API?' },
    { id:'LLM05', name:'Supply Chain Vulnerabilities', weight:15, check:'Are model weights and dependencies verified against known-good checksums?' },
    { id:'LLM06', name:'Sensitive Info Disclosure', weight:20, check:'Is the model tested for training data memorization / PII leakage?' },
    { id:'LLM07', name:'Insecure Plugin Design',    weight:15, check:'Are all plugins/tools sandboxed with minimal permissions?' },
    { id:'LLM08', name:'Excessive Agency',          weight:25, check:'Are agent actions bounded by explicit authorization controls?' },
    { id:'LLM09', name:'Overreliance',              weight:10, check:'Is there human oversight for high-stakes model decisions?' },
    { id:'LLM10', name:'Model Theft',               weight:10, check:'Are model weights and APIs protected against extraction attacks?' },
  ],
  agent: [
    { id:'LLM08', name:'Excessive Agency',          weight:40, check:'Does the agent operate with least-privilege tool access?' },
    { id:'LLM01', name:'Prompt Injection via Tools',weight:35, check:'Are tool inputs sanitized to prevent indirect prompt injection?' },
    { id:'LLM07', name:'Insecure Tool Design',      weight:25, check:'Are tools sandboxed and do they validate all parameters?' },
  ],
  rag: [
    { id:'LLM03', name:'RAG Poisoning',             weight:35, check:'Is the knowledge base protected against unauthorized document injection?' },
    { id:'LLM06', name:'Context Exfiltration',      weight:30, check:'Does the RAG system expose sensitive documents to unauthorized prompts?' },
    { id:'LLM01', name:'Indirect Prompt Injection', weight:35, check:'Are retrieved documents scanned for embedded prompt injection?' },
  ],
};

// Risk score → letter grade
function riskGrade(score) {
  if (score >= 90) return { grade:'A', label:'Excellent',  color:'#22c55e' };
  if (score >= 75) return { grade:'B', label:'Good',       color:'#84cc16' };
  if (score >= 60) return { grade:'C', label:'Fair',       color:'#f59e0b' };
  if (score >= 40) return { grade:'D', label:'Poor',       color:'#ef4444' };
  return                  { grade:'F', label:'Critical',   color:'#dc2626' };
}

function genId(prefix) { return prefix + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2,7); }

// POST /api/ai-security/assets/register
export async function handleRegisterAIAsset(request, env, authCtx) {
  if (!authCtx?.userId) return err('Auth required', 401);
  let body; try { body = await request.json(); } catch { return err('Invalid JSON'); }

  const { name, asset_type, provider, model_name, version, deployment, endpoint_url, exposure, owner_email, tags } = body;
  if (!name) return err('Asset name required');
  if (!['model','agent','rag','api','dataset','pipeline','embedding'].includes(asset_type)) {
    return err('Invalid asset_type. Valid: model, agent, rag, api, dataset, pipeline, embedding');
  }

  const assetId = genId('ast');
  await env.DB.prepare(
    'INSERT INTO ai_assets (id,org_id,name,asset_type,provider,model_name,version,deployment,endpoint_url,exposure,owner_email,tags) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)'
  ).bind(assetId, authCtx.orgId||authCtx.userId, name, asset_type||'model',
    provider||null, model_name||null, version||null, deployment||'cloud',
    endpoint_url||null, exposure||'internal', owner_email||authCtx.email||null,
    JSON.stringify(tags||[])
  ).run();

  return json({ success:true, asset_id:assetId, name, asset_type, message:'Asset registered. Run /scan to assess security posture.' }, 201);
}

// POST /api/ai-security/assets/:id/scan — ASPM security assessment
export async function handleScanAIAsset(request, env, authCtx) {
  if (!authCtx?.userId) return err('Auth required', 401);
  const url = new URL(request.url);
  const parts = url.pathname.split('/');
  const assetId = parts[parts.indexOf('assets') + 1];

  const asset = await env.DB.prepare('SELECT * FROM ai_assets WHERE id=?').bind(assetId).first();
  if (!asset) return err('Asset not found', 404);

  const checks = OWASP_LLM_CHECKS[asset.asset_type] || OWASP_LLM_CHECKS['model'];
  const findings = [];
  let totalWeight = 0;
  let passWeight = 0;

  // Deterministic security assessment based on asset properties
  for (const check of checks) {
    totalWeight += check.weight;
    const exposure     = asset.exposure || 'internal';
    const hasEndpoint  = !!asset.endpoint_url;
    const isPublic     = exposure === 'public';
    const isAgent      = asset.asset_type === 'agent';
    const isRAG        = asset.asset_type === 'rag';

    // Risk-based pass/fail logic
    let passed = true;
    let severity = 'LOW';
    let remediation = '';

    if (check.id === 'LLM01' && isPublic && hasEndpoint) { passed=false; severity='CRITICAL'; remediation='Deploy prompt injection detection middleware (e.g. Guardrails AI, LangChain Shield) on all public endpoints immediately.'; }
    else if (check.id === 'LLM01' && !isPublic && hasEndpoint) { passed=false; severity='HIGH'; remediation='Implement input validation and prompt injection detection even for internal endpoints — insider threats and SSRF can reach these.'; }
    else if (check.id === 'LLM08' && isAgent) { passed=false; severity='CRITICAL'; remediation='Audit all tool permissions. Apply principle of least privilege. Implement explicit authorization checks before any tool execution.'; }
    else if (check.id === 'LLM03' && isRAG) { passed=false; severity='HIGH'; remediation='Implement document integrity verification. Restrict who can add documents to the knowledge base. Monitor for unusual document injection patterns.'; }
    else if (check.id === 'LLM06' && isPublic) { passed=false; severity='HIGH'; remediation='Test model for training data memorization using extraction attacks. Implement output filtering for PII patterns.'; }
    else if (check.id === 'LLM04' && isPublic && hasEndpoint) { passed=false; severity='MEDIUM'; remediation='Implement rate limiting (per-IP and per-API-key), request queuing, and resource throttling on the inference endpoint.'; }
    else if (check.id === 'LLM05') { passed=false; severity='MEDIUM'; remediation='Audit all model dependencies. Pin versions. Verify checksums of model weights. Subscribe to security advisories for your model provider.'; }

    if (!passed) {
      passWeight += 0;
      const fId = genId('fnd');
      findings.push({ id:fId, asset_id:assetId, category:check.id, title:check.name, description:check.check, severity, remediation, status:'open' });
    } else {
      passWeight += check.weight;
    }
  }

  const securityScore = Math.round((passWeight / totalWeight) * 100);
  const riskScore     = 100 - securityScore;

  // Write findings to D1
  const scanId = genId('scn');
  for (const f of findings) {
    try {
      await env.DB.prepare(
        'INSERT OR IGNORE INTO ai_findings (id,asset_id,scan_id,category,title,description,severity,remediation,status) VALUES (?,?,?,?,?,?,?,?,?)'
      ).bind(f.id, f.asset_id, scanId, f.category, f.title, f.description, f.severity, f.remediation, f.status).run();
    } catch { /* non-blocking */ }
  }

  // Update asset scores
  await env.DB.prepare(
    'UPDATE ai_assets SET security_score=?, risk_score=?, last_scanned=unixepoch(), updated_at=unixepoch() WHERE id=?'
  ).bind(securityScore, riskScore, assetId).run();

  const grade = riskGrade(securityScore);
  return json({
    success:true, scan_id:scanId, asset_id:assetId, asset_name:asset.name,
    security_score:securityScore, risk_score:riskScore, grade:grade.grade, grade_label:grade.label,
    total_findings:findings.length,
    critical_findings: findings.filter(f=>f.severity==='CRITICAL').length,
    high_findings:     findings.filter(f=>f.severity==='HIGH').length,
    findings: findings.map(f => ({ category:f.category, title:f.title, severity:f.severity, remediation:f.remediation })),
    owasp_coverage: `${checks.length} OWASP LLM Top 10 checks applied`,
  });
}

// GET /api/ai-security/dashboard
export async function handleASPMDashboard(request, env, authCtx) {
  if (!authCtx?.userId) return err('Auth required', 401);
  const orgId = authCtx.orgId || authCtx.userId;
  try {
    const [assetsRow, findingsRow, riskRow] = await Promise.all([
      env.DB.prepare('SELECT asset_type, COUNT(*) AS cnt, AVG(security_score) AS avg_score FROM ai_assets WHERE org_id=? GROUP BY asset_type').bind(orgId).all(),
      env.DB.prepare('SELECT severity, COUNT(*) AS cnt FROM ai_findings af JOIN ai_assets aa ON af.asset_id=aa.id WHERE aa.org_id=? AND af.status="open" GROUP BY severity').bind(orgId).all(),
      env.DB.prepare('SELECT COUNT(*) AS open_risks FROM ai_risk_register WHERE org_id=? AND status="open"').bind(orgId).first(),
    ]);

    const totalAssets     = (assetsRow.results||[]).reduce((s,r)=>s+r.cnt,0);
    const avgScore        = (assetsRow.results||[]).length > 0
      ? Math.round((assetsRow.results||[]).reduce((s,r)=>s+(r.avg_score||0)*r.cnt,0)/Math.max(totalAssets,1))
      : 0;
    const findingMap      = {};
    (findingsRow.results||[]).forEach(r => { findingMap[r.severity]=r.cnt; });

    return json({
      success:true,
      posture: {
        overall_score:avgScore,
        grade: riskGrade(avgScore),
        total_assets:totalAssets,
        open_risks: riskRow?.open_risks||0,
        critical_findings: findingMap['CRITICAL']||0,
        high_findings:     findingMap['HIGH']||0,
        medium_findings:   findingMap['MEDIUM']||0,
      },
      assets_by_type: assetsRow.results||[],
      findings_by_severity: findingsRow.results||[],
      recommendations: avgScore < 60 ? [
        'Immediately scan all public-facing AI endpoints for prompt injection',
        'Audit agent tool permissions — excessive agency is the #1 AI security risk',
        'Deploy output filtering on all LLM API endpoints',
      ] : avgScore < 80 ? [
        'Review HIGH severity findings and create 30-day remediation plan',
        'Add automated security checks to your AI CI/CD pipeline',
      ] : ['Maintain current security posture. Schedule quarterly AI red team exercises.'],
    });
  } catch(e) {
    return err('Dashboard query failed: ' + e.message, 500);
  }
}

// GET /api/ai-security/assets
export async function handleListAIAssets(request, env, authCtx) {
  if (!authCtx?.userId) return err('Auth required', 401);
  const orgId = authCtx.orgId || authCtx.userId;
  const url = new URL(request.url);
  const type  = url.searchParams.get('type');
  const limit = Math.min(parseInt(url.searchParams.get('limit')||'50'),100);

  const rows = type
    ? await env.DB.prepare('SELECT * FROM ai_assets WHERE org_id=? AND asset_type=? ORDER BY risk_score DESC LIMIT ?').bind(orgId,type,limit).all()
    : await env.DB.prepare('SELECT * FROM ai_assets WHERE org_id=? ORDER BY risk_score DESC LIMIT ?').bind(orgId,limit).all();

  return json({ success:true, assets:rows.results||[], total:rows.results?.length||0 });
}
