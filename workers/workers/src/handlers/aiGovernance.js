/**
 * CYBERDUDEBIVASH v28 — AI Governance Center Handler
 * PILLAR 2: NIST AI RMF | ISO 42001 | OWASP LLM | EU AI Act | DPDP
 *
 * POST /api/ai-security/governance/assess    -> start governance assessment
 * GET  /api/ai-security/governance/:id       -> get assessment + gaps + roadmap
 * POST /api/ai-security/governance/:id/answer -> answer governance question
 * GET  /api/ai-security/governance/frameworks -> list available frameworks
 * GET  /api/ai-security/risk-register        -> org AI risk register
 * POST /api/ai-security/risk-register        -> add risk item
 */

// CORS applied by centralized withCors() in index.js — no per-handler wildcard
const json = (d,s=200) => new Response(JSON.stringify(d),{status:s,headers:{'Content-Type':'application/json'}});
const err  = (m,s=400) => json({success:false,error:m},s);
const genId = (p) => p+'_'+Date.now().toString(36)+Math.random().toString(36).slice(2,7);

// Framework definitions ────────────────────────────────────────────────────────
const FRAMEWORKS = {

  NIST_AI_RMF: {
    name: 'NIST AI Risk Management Framework (AI RMF 1.0)',
    version: '1.0',
    published: '2023-01',
    applicability: 'All AI systems in US federal agencies and recommended for all AI developers',
    functions: {
      GOVERN: {
        label: 'GOVERN', color: '#818cf8',
        controls: [
          { id:'GOVERN-1.1', title:'AI risk policies', desc:'Organizational risk policies for AI design, development, deployment exist and are enforced.', weight:15 },
          { id:'GOVERN-1.2', title:'Accountability',   desc:'Roles, responsibilities, and accountability for AI risk management are established.', weight:10 },
          { id:'GOVERN-2.1', title:'AI literacy',      desc:'AI risk awareness and literacy training exists for all relevant personnel.', weight:8 },
          { id:'GOVERN-3.1', title:'Team diversity',   desc:'AI teams include diverse expertise including ethics, legal, and domain expertise.', weight:7 },
          { id:'GOVERN-4.1', title:'Risk tolerance',   desc:'AI risk tolerance is established and communicated across the organization.', weight:10 },
          { id:'GOVERN-6.1', title:'Policy updates',   desc:'AI policies are updated regularly and reflect the current AI risk landscape.', weight:5 },
        ]
      },
      MAP: {
        label: 'MAP', color: '#22c55e',
        controls: [
          { id:'MAP-1.1', title:'AI context',          desc:'The context for AI system deployment is understood: purpose, stakeholders, use constraints.', weight:10 },
          { id:'MAP-2.1', title:'Risk classification',  desc:'AI risks are categorized and mapped to organizational risk management processes.', weight:12 },
          { id:'MAP-3.1', title:'Bias assessment',     desc:'AI system bias and fairness risks are identified and assessed.', weight:10 },
          { id:'MAP-5.1', title:'Impact assessment',   desc:'Societal and environmental impacts of the AI system are assessed.', weight:8 },
        ]
      },
      MEASURE: {
        label: 'MEASURE', color: '#f59e0b',
        controls: [
          { id:'MEASURE-1.1', title:'Risk metrics',    desc:'AI risk metrics and measurement approaches are established and applied.', weight:12 },
          { id:'MEASURE-2.1', title:'Testing',         desc:'AI system robustness, accuracy, and reliability are tested regularly.', weight:15 },
          { id:'MEASURE-2.5', title:'Security testing',desc:'AI-specific attacks (prompt injection, adversarial inputs) are tested systematically.', weight:18 },
          { id:'MEASURE-3.1', title:'Monitoring',      desc:'AI system performance is monitored continuously in production.', weight:12 },
        ]
      },
      MANAGE: {
        label: 'MANAGE', color: '#ef4444',
        controls: [
          { id:'MANAGE-1.1', title:'Risk response',    desc:'Identified AI risks have documented response plans.', weight:15 },
          { id:'MANAGE-2.1', title:'Incident response',desc:'An AI-specific incident response plan exists and has been tested.', weight:18 },
          { id:'MANAGE-3.1', title:'Risk treatment',   desc:'AI risks are prioritized, tracked, and treated according to risk tolerance.', weight:12 },
          { id:'MANAGE-4.1', title:'Lessons learned',  desc:'AI incidents and near-misses are documented and used to improve risk management.', weight:8 },
        ]
      },
    }
  },

  ISO_42001: {
    name: 'ISO/IEC 42001:2023 — AI Management System',
    version: '2023',
    published: '2023-12',
    applicability: 'Organizations developing or using AI systems — first auditable AI management standard',
    functions: {
      CONTEXT: {
        label: 'Context (Clause 4)', color: '#818cf8',
        controls: [
          { id:'4.1', title:'Organizational context',     desc:'Internal and external issues relevant to AI management are identified.', weight:8 },
          { id:'4.2', title:'Stakeholder needs',          desc:'Interested parties and their requirements for the AI management system are understood.', weight:7 },
          { id:'4.4', title:'AIMS scope',                 desc:'The scope of the AI management system is defined and documented.', weight:10 },
        ]
      },
      LEADERSHIP: {
        label: 'Leadership (Clause 5)', color: '#22c55e',
        controls: [
          { id:'5.1', title:'Leadership commitment',      desc:'Top management demonstrates commitment to the AI management system.', weight:12 },
          { id:'5.2', title:'AI policy',                  desc:'An AI policy is established, communicated, and maintained.', weight:15 },
          { id:'5.3', title:'Roles and responsibilities', desc:'AI-related roles, responsibilities, and authorities are assigned.', weight:10 },
        ]
      },
      OPERATION: {
        label: 'Operation (Clause 8)', color: '#f59e0b',
        controls: [
          { id:'8.1', title:'Operational planning',       desc:'Operational planning and controls for AI are implemented.', weight:12 },
          { id:'8.2', title:'AI risk assessment',         desc:'AI-specific risk assessment is performed and documented.', weight:18 },
          { id:'8.3', title:'AI impact assessment',       desc:'AI system impact assessments are conducted before deployment.', weight:15 },
          { id:'8.4', title:'AI objectives',              desc:'AI system objectives and success criteria are defined and measurable.', weight:8 },
        ]
      },
      EVALUATION: {
        label: 'Evaluation (Clause 9)', color: '#ef4444',
        controls: [
          { id:'9.1', title:'Monitoring and measurement', desc:'AI performance, risk, and compliance are monitored and measured.', weight:12 },
          { id:'9.2', title:'Internal audit',             desc:'Internal audits of the AI management system are conducted.', weight:10 },
          { id:'9.3', title:'Management review',          desc:'Top management reviews the AI management system regularly.', weight:8 },
        ]
      },
    }
  },

  EU_AI_ACT: {
    name: 'EU AI Act (Regulation 2024/1689)',
    version: '2024',
    published: '2024-08',
    applicability: 'All AI systems placed on EU market or affecting EU persons. High-risk systems require conformity assessment.',
    functions: {
      PROHIBITED: {
        label: 'Prohibited AI Checks', color: '#ef4444',
        controls: [
          { id:'AIA-P1', title:'No subliminal manipulation', desc:'AI system does not use subliminal techniques to impair decision-making.', weight:30 },
          { id:'AIA-P2', title:'No social scoring',          desc:'AI system does not conduct social scoring of individuals for general purposes.', weight:30 },
          { id:'AIA-P3', title:'No real-time biometrics',    desc:'Real-time remote biometric identification in public spaces is not deployed without authorization.', weight:20 },
        ]
      },
      HIGH_RISK: {
        label: 'High-Risk Requirements', color: '#f59e0b',
        controls: [
          { id:'AIA-H1', title:'Risk management system',     desc:'A risk management system for the AI system is implemented and maintained throughout the lifecycle.', weight:20 },
          { id:'AIA-H2', title:'Data governance',            desc:'Training, validation, and testing datasets meet quality criteria and are free from bias.', weight:18 },
          { id:'AIA-H3', title:'Technical documentation',    desc:'Technical documentation is prepared before placing on market and kept up to date.', weight:12 },
          { id:'AIA-H4', title:'Logging and traceability',   desc:'Automatic recording of events enables post-deployment monitoring and traceability.', weight:15 },
          { id:'AIA-H5', title:'Transparency',               desc:'High-risk AI systems are transparent — users are informed they are interacting with AI.', weight:12 },
          { id:'AIA-H6', title:'Human oversight',            desc:'Measures enable human oversight to minimize risk during use.', weight:20 },
          { id:'AIA-H7', title:'Accuracy and robustness',    desc:'System achieves appropriate levels of accuracy, robustness, and cybersecurity.', weight:15 },
        ]
      },
      GPTS: {
        label: 'GPAI Model Requirements', color: '#818cf8',
        controls: [
          { id:'AIA-G1', title:'Transparency to providers', desc:'GPAI model providers maintain technical documentation and cooperate with downstream providers.', weight:15 },
          { id:'AIA-G2', title:'Copyright compliance',      desc:'Training data respects copyright law; summary of training data available.', weight:12 },
          { id:'AIA-G3', title:'Systemic risk assessment',  desc:'For models >10^25 FLOPs: adversarial testing and systemic risk assessment conducted.', weight:20 },
        ]
      },
    }
  },

};

// POST /api/ai-security/governance/assess ─────────────────────────────────────
export async function handleGovernanceAssess(request, env, authCtx) {
  if (!authCtx?.userId) return err('Auth required', 401);
  let body; try { body = await request.json(); } catch { return err('Invalid JSON'); }

  const framework = (body.framework||'NIST_AI_RMF').toUpperCase();
  if (!FRAMEWORKS[framework]) return err('Invalid framework. Valid: ' + Object.keys(FRAMEWORKS).join(', '));

  const fw = FRAMEWORKS[framework];
  const id = genId('gov');
  const allControls = Object.values(fw.functions).flatMap(fn => fn.controls);
  const questions = allControls.map(c => ({ id:c.id, question:c.desc, weight:c.weight, answered:false }));

  await env.DB.prepare(
    'INSERT INTO ai_governance_assessments (id,org_id,email,framework,status,answers) VALUES (?,?,?,?,?,?)'
  ).bind(id, authCtx.orgId||authCtx.userId, authCtx.email||body.email||'', framework, 'in_progress', JSON.stringify({})).run();

  return json({
    success:true, assessment_id:id, framework, framework_name:fw.name,
    total_controls:allControls.length, questions,
    instructions:'Answer each question via POST /api/ai-security/governance/' + id + '/answer',
    next: '/api/ai-security/governance/' + id,
  }, 201);
}

// POST /api/ai-security/governance/:id/answer ─────────────────────────────────
export async function handleGovernanceAnswer(request, env, authCtx) {
  if (!authCtx?.userId) return err('Auth required', 401);
  const url = new URL(request.url);
  const id  = url.pathname.split('/').slice(-2)[0];
  let body; try { body = await request.json(); } catch { return err('Invalid JSON'); }

  const row = await env.DB.prepare('SELECT * FROM ai_governance_assessments WHERE id=?').bind(id).first();
  if (!row) return err('Assessment not found', 404);

  const answers = JSON.parse(row.answers || '{}');
  const { control_id, answer, evidence } = body;  // answer: true|false|'partial'
  if (!control_id) return err('control_id required');

  answers[control_id] = { answer: !!answer, partial: answer==='partial', evidence:evidence||null, ts:Date.now() };

  const fw = FRAMEWORKS[row.framework];
  const allControls = Object.values(fw.functions).flatMap(fn => fn.controls);

  // Compute score from answers so far
  let totalWeight = 0; let earnedWeight = 0;
  const gaps = []; const roadmap = [];

  for (const ctrl of allControls) {
    totalWeight += ctrl.weight;
    const ans = answers[ctrl.id];
    if (!ans) continue;  // not yet answered
    if (ans.answer)           earnedWeight += ctrl.weight;
    else if (ans.partial)     earnedWeight += ctrl.weight * 0.5;
    else {
      gaps.push({ id:ctrl.id, title:ctrl.title, weight:ctrl.weight, priority:ctrl.weight>=15?'HIGH':'MEDIUM' });
      roadmap.push({ control_id:ctrl.id, title:'Implement: '+ctrl.title, priority:ctrl.weight>=15?'P1':'P2', effort_days: ctrl.weight>=15?30:14 });
    }
  }

  const answeredCount = Object.keys(answers).length;
  const score = totalWeight > 0 ? Math.round((earnedWeight/totalWeight)*100) : 0;
  const riskTier = score>=80?'LIMITED':score>=60?'HIGH':'UNACCEPTABLE';
  const completed = answeredCount >= allControls.length;

  await env.DB.prepare(
    'UPDATE ai_governance_assessments SET answers=?,overall_score=?,risk_tier=?,gaps=?,roadmap=?,status=?,completed_at=? WHERE id=?'
  ).bind(
    JSON.stringify(answers), score, riskTier,
    JSON.stringify(gaps.slice(0,10)), JSON.stringify(roadmap.slice(0,10)),
    completed?'completed':'in_progress', completed?Math.floor(Date.now()/1000):null, id
  ).run();

  return json({
    success:true, assessment_id:id, control_id,
    progress:{ answered:answeredCount, total:allControls.length, pct:Math.round((answeredCount/allControls.length)*100) },
    current_score:score, risk_tier:riskTier,
    top_gaps: gaps.slice(0,3).map(g=>g.title),
    completed, message: completed?'Assessment complete. Full report available.':'Keep answering to complete assessment.',
  });
}

// GET /api/ai-security/governance/frameworks ──────────────────────────────────
export async function handleListFrameworks(request, env) {
  return json({ success:true, frameworks: Object.entries(FRAMEWORKS).map(([k,v])=>({ id:k, name:v.name, version:v.version, published:v.published, applicability:v.applicability, total_controls:Object.values(v.functions).reduce((s,fn)=>s+fn.controls.length,0) })) });
}

// GET /api/ai-security/governance/:id ─────────────────────────────────────────
export async function handleGetGovernanceAssessment(request, env, authCtx) {
  if (!authCtx?.userId) return err('Auth required', 401);
  const id = new URL(request.url).pathname.split('/').pop();
  const row = await env.DB.prepare('SELECT * FROM ai_governance_assessments WHERE id=?').bind(id).first();
  if (!row) return err('Assessment not found', 404);
  return json({ success:true, assessment:{ ...row, answers:JSON.parse(row.answers||'{}'), gaps:JSON.parse(row.gaps||'[]'), roadmap:JSON.parse(row.roadmap||'[]') }});
}
