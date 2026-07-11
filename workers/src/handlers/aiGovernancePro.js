// =============================================================================
// AI GOVERNANCE PRO — Complete AI Governance, Risk Management & Compliance
// CYBERDUDEBIVASH AI Security Hub | handlers/aiGovernancePro.js
// Differentiator: FULL (CrowdStrike=Partial, Palo Alto=Partial, Wiz=None, SentinelOne=None)
// Implements: EU AI Act, NIST AI RMF, ISO 42001, AI ASPM, Shadow AI Detection
// =============================================================================

import { isRealUser } from '../auth/middleware.js';

const EU_AI_ACT = {
  PROHIBITED: {
    code: 'EU-PROHIBITED', label: 'Prohibited AI',
    description: 'Prohibited AI Systems (Art. 5)',
    examples: ['Social scoring by public authorities','Real-time remote biometric surveillance in public spaces',
      'Subliminal/manipulative techniques','Exploitation of vulnerabilities based on age/disability'],
    penalty_max: '€35,000,000 or 7% global annual turnover'
  },
  HIGH: {
    code: 'EU-HIGH', label: 'High Risk',
    description: 'High-Risk AI Systems (Annex III)',
    domains: ['Critical infrastructure','Education & vocational training','Employment & workers management',
      'Essential private/public services (credit scoring)','Law enforcement','Migration & border control',
      'Administration of justice & democratic processes','Biometric identification'],
    obligations: ['Conformity assessment before market','Registration in EU AI database',
      'Post-market monitoring plan','Human oversight measures','Technical documentation (Annex IV)',
      'Logging & auditability','Accuracy/robustness/cybersecurity requirements'],
    penalty_max: '€15,000,000 or 3% global annual turnover'
  },
  LIMITED: {
    code: 'EU-LIMITED', label: 'Limited Risk',
    description: 'Limited Risk AI Systems',
    examples: ['Chatbots','Emotion recognition','Deepfake generators','AI-generated content'],
    obligations: ['Transparency to users that they interact with AI','Disclosure of AI-generated content'],
    penalty_max: '€7,500,000 or 1.5% global annual turnover'
  },
  MINIMAL: {
    code: 'EU-MINIMAL', label: 'Minimal Risk',
    description: 'Minimal Risk AI Systems',
    examples: ['AI-enabled video games','Spam filters','AI in manufacturing for non-safety uses'],
    obligations: ['Voluntary codes of conduct recommended'],
    penalty_max: 'No mandatory requirements'
  }
};

const NIST_AI_RMF = {
  GOVERN: {
    description: 'Cultivate organisational culture & accountability for AI risk',
    subcategories: {
      'GOV-1.1': 'Organisational policies for AI risk management are established',
      'GOV-1.2': 'Accountability for implementing AI risk management is in place',
      'GOV-1.3': 'Org leadership is responsible for AI risk decisions',
      'GOV-1.4': 'Org teams with AI risk expertise are established',
      'GOV-1.5': 'Organisational risk tolerance for AI is established',
      'GOV-1.6': 'AI risk management policies cover development lifecycle',
      'GOV-1.7': 'Processes for transparency and accountability are in place',
      'GOV-2.1': 'AI risk management functions established across org',
      'GOV-2.2': 'AI risk team composition defined and documented',
      'GOV-4.1': 'Org risk tolerance communicated to teams',
      'GOV-5.1': 'Org risks from third-party AI are managed',
      'GOV-6.1': 'Policies cover AI risk throughout lifecycle',
      'GOV-6.2': 'AI risk management continuous improvement occurs'
    }
  },
  MAP: {
    description: 'Categorise AI risks, contexts, and affected stakeholders',
    subcategories: {
      'MAP-1.1': 'Context for AI system established and understood',
      'MAP-1.5': 'Organisational risk tolerance applied to AI context',
      'MAP-1.6': 'AI system purpose, benefits, costs documented',
      'MAP-2.1': 'Scientific findings mapped to AI system requirements',
      'MAP-2.2': 'Scientific/technical standards applied to AI design',
      'MAP-3.1': 'AI system impact categorised with affected parties identified',
      'MAP-3.5': 'AI risks considered in data sourcing and acquisition',
      'MAP-5.1': 'Likelihood of AI risks estimated',
      'MAP-5.2': 'Practices for risk identification documented'
    }
  },
  MEASURE: {
    description: 'Analyse and assess AI risks',
    subcategories: {
      'MEASURE-1.1': 'AI risk assessment conducted',
      'MEASURE-2.1': 'Test sets representative of deployment context',
      'MEASURE-2.2': 'AI system evaluated for accuracy/reliability',
      'MEASURE-2.3': 'AI system performance across groups measured',
      'MEASURE-2.5': 'Fairness/bias metrics established and applied',
      'MEASURE-2.6': 'Explainability and interpretability assessed',
      'MEASURE-2.7': 'Security and privacy risks assessed',
      'MEASURE-2.8': 'Human factors in AI system evaluated',
      'MEASURE-2.9': 'Risk tradeoffs documented',
      'MEASURE-2.10': 'Privacy risks associated with AI training data assessed',
      'MEASURE-2.11': 'Fairness and bias in AI outputs measured',
      'MEASURE-3.1': 'AI risk monitoring mechanisms established',
      'MEASURE-4.1': 'Risk measurement plans reviewed and updated'
    }
  },
  MANAGE: {
    description: 'Prioritise and address AI risks',
    subcategories: {
      'MANAGE-1.1': 'Risks based on assessments prioritised and responded to',
      'MANAGE-1.3': 'Risk response plans documented',
      'MANAGE-2.2': 'Mechanisms for managing identified risks established',
      'MANAGE-2.4': 'Risk control plans aligned with org risk tolerance',
      'MANAGE-3.1': 'Responses to identified AI risks implemented',
      'MANAGE-3.2': 'AI risk treatment options identified',
      'MANAGE-4.1': 'Residual risks monitored and communicated',
      'MANAGE-4.2': 'Risk management lessons learned documented'
    }
  }
};

const ISO_42001_CONTROLS = {
  'A.2': { title: 'Policies for AI in organisations', controls: ['A.2.1 AI policy','A.2.2 AI-specific risks','A.2.3 Roles & responsibilities'] },
  'A.3': { title: 'Internal organisation', controls: ['A.3.1 Top mgmt commitment','A.3.2 AI risk ownership','A.3.3 Separation of duties'] },
  'A.4': { title: 'Resources for AI systems', controls: ['A.4.1 Infrastructure','A.4.2 Human resources','A.4.3 Knowledge','A.4.4 Awareness','A.4.5 Training','A.4.6 Competence','A.4.7 Communication'] },
  'A.5': { title: 'Assessing impacts of AI systems', controls: ['A.5.1 AI impact assessment','A.5.2 Societal impact'] },
  'A.6': { title: 'AI system life cycle', controls: ['A.6.1 AI system requirements','A.6.2 AI system design'] },
  'A.7': { title: 'Data for AI systems', controls: ['A.7.1 Data management','A.7.2 Data quality','A.7.3 Data provenance','A.7.4 Data acquisition','A.7.5 Data preparation','A.7.6 Data annotation','A.7.7 Data retention & disposal'] },
  'A.8': { title: 'Information for interested parties', controls: ['A.8.1 Transparency','A.8.2 Responsible use guidance','A.8.3 Disclosure','A.8.4 Users information'] },
  'A.9': { title: 'Use of AI systems', controls: ['A.9.1 Intended use','A.9.2 Human oversight','A.9.3 Incident management','A.9.4 Monitoring'] },
  'A.10': { title: 'Third-party and customer relationships', controls: ['A.10.1 Supplier relationships','A.10.2 Due diligence','A.10.3 Contractual requirements','A.10.4 Monitoring suppliers','A.10.5 Customer obligations'] }
};

function scoreAIModelRisk(model) {
  const factors = [];
  let total = 0;
  const typeRisk = { generative_text:18, generative_multimodal:20, generative_image:15,
    reinforcement:16, classification:10, regression:7, recommendation:12,
    nlp:13, computer_vision:11, speech:9, decision_tree:5, ensemble:8, other:10 };
  const t = typeRisk[model.model_type] ?? 10;
  total += t; factors.push({ name:'Model Type', score:t, max:20 });
  const dataSens = { phi:20, pii:18, financial:16, secret:20, confidential:14, internal:8, public:2 };
  const d = dataSens[model.data_classification] ?? 10;
  total += d; factors.push({ name:'Data Sensitivity', score:d, max:20 });
  const deploy = { production_customer_facing:15, production_internal:10, staging:5, development:2, research:3, batch_processing:7 };
  const dp = deploy[model.deployment_context] ?? 8;
  total += dp; factors.push({ name:'Deployment Context', score:dp, max:15 });
  const auto = { fully_autonomous:15, human_on_loop:12, human_in_loop:8, advisory_only:4, decision_support:6 };
  const au = auto[model.autonomy_level] ?? 8;
  total += au; factors.push({ name:'Autonomy Level', score:au, max:15 });
  const domain = { healthcare:15, law_enforcement:15, critical_infrastructure:15, financial:14, legal:14,
    hr_employment:13, education:12, marketing:5, internal_tools:4, research:6, entertainment:3 };
  const dm = domain[model.impact_domain] ?? 8;
  total += dm; factors.push({ name:'Impact Domain', score:dm, max:15 });
  const xai = { black_box:10, post_hoc_only:6, partially_explainable:4, interpretable:2, fully_explainable:0 };
  const xp = xai[model.explainability] ?? 5;
  total += xp; factors.push({ name:'Explainability', score:xp, max:10 });
  const bias = model.bias_tested ? 0 : 5;
  total += bias; factors.push({ name:'Bias Testing Gap', score:bias, max:5 });
  const level = total >= 75 ? 'CRITICAL' : total >= 55 ? 'HIGH' : total >= 35 ? 'MEDIUM' : 'LOW';
  const euCat = total >= 70 ? 'HIGH' : total >= 45 ? 'LIMITED' : 'MINIMAL';
  const recommendations = [];
  if (total >= 75) {
    recommendations.push({ priority:'CRITICAL', action:'Immediate human oversight implementation', sla:'24h' });
    recommendations.push({ priority:'CRITICAL', action:'EU AI Act Annex III conformity assessment', sla:'30 days' });
  }
  if (!model.bias_tested) recommendations.push({ priority:'HIGH', action:'Implement bias/fairness testing suite', sla:'2 weeks' });
  if (model.explainability === 'black_box') recommendations.push({ priority:'HIGH', action:'Add SHAP/LIME post-hoc explainability', sla:'1 month' });
  if (model.autonomy_level === 'fully_autonomous') recommendations.push({ priority:'HIGH', action:'Add human-in-the-loop checkpoints for critical decisions', sla:'1 week' });
  if (model.deployment_context === 'production_customer_facing') recommendations.push({ priority:'MEDIUM', action:'Implement production monitoring & drift detection', sla:'2 weeks' });
  return { score:total, maxScore:100, riskLevel:level, euAiActCategory:euCat,
    nistProfile: level === 'CRITICAL' ? 'MANAGE-3.1 immediate action required' : level === 'HIGH' ? 'MEASURE-2.1 assessment required' : 'MAP-3.1 baseline documentation',
    factors, recommendations };
}

function evaluatePolicyViolations(model, policies) {
  const violations = [];
  for (const policy of policies) {
    for (const rule of (policy.rules || [])) {
      let violated = false;
      switch (rule.type) {
        case 'max_risk_score': violated = (model.riskScore?.score ?? 999) > rule.value; break;
        case 'requires_bias_testing': violated = rule.value && !model.bias_tested; break;
        case 'prohibited_model_types': violated = rule.value.includes(model.model_type); break;
        case 'prohibited_data_classifications': violated = rule.value.includes(model.data_classification); break;
        case 'requires_explainability': violated = rule.value && ['black_box','post_hoc_only'].includes(model.explainability); break;
        case 'prohibited_domains': violated = rule.value.includes(model.impact_domain); break;
        case 'requires_human_oversight': violated = rule.value && model.autonomy_level === 'fully_autonomous'; break;
        case 'max_autonomy_level': {
          const levels = ['advisory_only','decision_support','human_in_loop','human_on_loop','fully_autonomous'];
          violated = levels.indexOf(model.autonomy_level) > levels.indexOf(rule.value); break;
        }
      }
      if (violated) violations.push({ policyId:policy.id, policyName:policy.name, ruleType:rule.type,
        severity:rule.severity||'HIGH', message:rule.message||`Policy violation: ${rule.type}` });
    }
  }
  return violations;
}

const KNOWN_SHADOW_AI_TOOLS = [
  { name:'OpenAI ChatGPT / GPT-4 API', domains:['api.openai.com','chat.openai.com'], risk:'HIGH', category:'LLM', dataEgressRisk:'HIGH', gdprConcerns:true },
  { name:'Anthropic Claude API', domains:['api.anthropic.com','claude.ai'], risk:'MEDIUM', category:'LLM', dataEgressRisk:'MEDIUM', gdprConcerns:true },
  { name:'Google Gemini API', domains:['generativelanguage.googleapis.com','aistudio.google.com'], risk:'HIGH', category:'LLM', dataEgressRisk:'HIGH', gdprConcerns:true },
  { name:'GitHub Copilot', domains:['copilot.github.com','copilot-proxy.githubusercontent.com'], risk:'MEDIUM', category:'Code AI', dataEgressRisk:'MEDIUM', gdprConcerns:false },
  { name:'Hugging Face Inference API', domains:['api-inference.huggingface.co'], risk:'HIGH', category:'Model Hub', dataEgressRisk:'HIGH', gdprConcerns:true },
  { name:'Replicate.com', domains:['api.replicate.com'], risk:'HIGH', category:'Model API', dataEgressRisk:'HIGH', gdprConcerns:true },
  { name:'Together AI', domains:['api.together.xyz'], risk:'HIGH', category:'LLM API', dataEgressRisk:'HIGH', gdprConcerns:true },
  { name:'Cohere API', domains:['api.cohere.ai'], risk:'MEDIUM', category:'LLM API', dataEgressRisk:'MEDIUM', gdprConcerns:true },
  { name:'Midjourney', domains:['midjourney.com'], risk:'LOW', category:'Image AI', dataEgressRisk:'MEDIUM', gdprConcerns:false },
  { name:'Stable Diffusion API', domains:['stablediffusionapi.com','clipdrop.co'], risk:'MEDIUM', category:'Image AI', dataEgressRisk:'LOW', gdprConcerns:false },
  { name:'Perplexity AI', domains:['api.perplexity.ai','perplexity.ai'], risk:'MEDIUM', category:'Search AI', dataEgressRisk:'HIGH', gdprConcerns:true },
  { name:'Runway ML', domains:['api.runwayml.com'], risk:'MEDIUM', category:'Video AI', dataEgressRisk:'MEDIUM', gdprConcerns:false },
  { name:'Jasper AI', domains:['jasper.ai'], risk:'MEDIUM', category:'Content AI', dataEgressRisk:'HIGH', gdprConcerns:true },
  { name:'Grammarly AI', domains:['api.grammarly.com'], risk:'LOW', category:'Writing AI', dataEgressRisk:'MEDIUM', gdprConcerns:true },
  { name:'Notion AI', domains:['notion.so','notion-api.workers.dev'], risk:'LOW', category:'Productivity AI', dataEgressRisk:'LOW', gdprConcerns:false }
];

// Every route below manages an org's confidential AI model/risk inventory —
// requires a real logged-in principal, and org_id is always derived from the
// authenticated session (authCtx.org_id, already uniquely namespaced per user
// by withAuthAliases), never trusted from client body/query params. Previously
// every route here accepted an arbitrary client-supplied org_id with zero auth
// at all, letting anyone read/write/delete any other org's AI governance data.
export async function handleAIGovernancePro(request, env, authCtx) {
  if (!isRealUser(authCtx)) {
    return new Response(JSON.stringify({ error: 'Authentication required' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }
  const orgId = authCtx.org_id || `u:${authCtx.user_id ?? authCtx.userId}`;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  if (path === '/api/ai-governance/models' && method === 'POST') return registerModel(request, env, orgId);
  if (path === '/api/ai-governance/models' && method === 'GET') return listModels(request, env, orgId);
  if (path.match(/^\/api\/ai-governance\/models\/[\w-]+$/) && method === 'GET') return getModel(request, env, orgId);
  if (path.match(/^\/api\/ai-governance\/models\/[\w-]+$/) && method === 'PUT') return updateModel(request, env, orgId);
  if (path.match(/^\/api\/ai-governance\/models\/[\w-]+$/) && method === 'DELETE') return deleteModel(request, env, orgId);
  if (path === '/api/ai-governance/risk-score' && method === 'POST') return calculateRiskScore(request, env);
  if (path.match(/^\/api\/ai-governance\/risk-score\/[\w-]+$/) && method === 'GET') return getModelRiskScore(request, env, orgId);
  if (path === '/api/ai-governance/policies' && method === 'POST') return createPolicy(request, env, orgId);
  if (path === '/api/ai-governance/policies' && method === 'GET') return listPolicies(request, env, orgId);
  if (path.match(/^\/api\/ai-governance\/policies\/[\w-]+\/evaluate$/) && method === 'POST') return evaluatePolicy(request, env, orgId);
  if (path === '/api/ai-governance/compliance/eu-ai-act' && method === 'POST') return euAiActCheck(request, env);
  if (path === '/api/ai-governance/compliance/nist-ai-rmf' && method === 'POST') return nistAiRmfAssessment(request, env);
  if (path === '/api/ai-governance/compliance/iso-42001' && method === 'POST') return iso42001GapAnalysis(request, env);
  if (path === '/api/ai-governance/shadow-ai/detect' && method === 'POST') return detectShadowAI(request, env, orgId);
  if (path === '/api/ai-governance/shadow-ai/inventory' && method === 'GET') return shadowAIInventory(request, env, orgId);
  if (path === '/api/ai-governance/dashboard' && method === 'GET') return governanceDashboard(request, env, orgId);
  if (path === '/api/ai-governance/reports/generate' && method === 'POST') return generateGovernanceReport(request, env, orgId);
  return new Response(JSON.stringify({ error:'Not found' }), { status:404, headers:{ 'Content-Type':'application/json' } });
}

async function registerModel(request, env, orgId) {
  try {
    const body = await request.json();
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const riskScore = scoreAIModelRisk(body);
    await env.DB.prepare(`INSERT INTO ai_model_registry
      (id,org_id,name,version,model_type,data_classification,deployment_context,autonomy_level,
       impact_domain,explainability,bias_tested,risk_score,risk_level,eu_ai_act_category,
       owner_email,status,metadata,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind(id, orgId, body.name, body.version||'1.0', body.model_type,
        body.data_classification, body.deployment_context, body.autonomy_level,
        body.impact_domain, body.explainability, body.bias_tested ? 1 : 0,
        riskScore.score, riskScore.riskLevel, riskScore.euAiActCategory,
        body.owner_email, 'active', JSON.stringify(body.metadata||{}), now, now).run();
    return new Response(JSON.stringify({ success:true, id, name:body.name,
      riskAssessment:riskScore, complianceFlags:{ euAiAct:EU_AI_ACT[riskScore.euAiActCategory] },
      message:`Model registered. Risk level: ${riskScore.riskLevel}. EU AI Act: ${riskScore.euAiActCategory}.`
    }), { status:201, headers:{ 'Content-Type':'application/json' } });
  } catch(e) { return new Response(JSON.stringify({ error:e.message }), { status:500, headers:{ 'Content-Type':'application/json' } }); }
}

async function listModels(request, env, orgId) {
  try {
    const url = new URL(request.url);
    const riskLevel = url.searchParams.get('risk_level');
    const limit = parseInt(url.searchParams.get('limit')||'50');
    const offset = parseInt(url.searchParams.get('offset')||'0');
    let q = 'SELECT * FROM ai_model_registry WHERE org_id = ? AND status != ?';
    const params = [orgId,'deleted'];
    if (riskLevel) { q += ' AND risk_level = ?'; params.push(riskLevel); }
    q += ` ORDER BY risk_score DESC LIMIT ${limit} OFFSET ${offset}`;
    const { results } = await env.DB.prepare(q).bind(...params).all();
    const countResult = await env.DB.prepare('SELECT COUNT(*) as cnt FROM ai_model_registry WHERE org_id = ? AND status != ?').bind(orgId,'deleted').first();
    const summary = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 };
    for (const m of results) summary[m.risk_level] = (summary[m.risk_level]||0) + 1;
    return new Response(JSON.stringify({ models:results, total:countResult?.cnt||0, summary,
      euAiActBreakdown:{ HIGH:results.filter(m=>m.eu_ai_act_category==='HIGH').length,
        LIMITED:results.filter(m=>m.eu_ai_act_category==='LIMITED').length,
        MINIMAL:results.filter(m=>m.eu_ai_act_category==='MINIMAL').length }
    }), { headers:{ 'Content-Type':'application/json' } });
  } catch(e) { return new Response(JSON.stringify({ error:e.message }), { status:500, headers:{ 'Content-Type':'application/json' } }); }
}

async function getModel(request, env, orgId) {
  const id = new URL(request.url).pathname.split('/').pop();
  try {
    const model = await env.DB.prepare('SELECT * FROM ai_model_registry WHERE id = ? AND org_id = ?').bind(id, orgId).first();
    if (!model) return new Response(JSON.stringify({ error:'Model not found' }), { status:404, headers:{ 'Content-Type':'application/json' } });
    return new Response(JSON.stringify({ model, euAiActDetails:EU_AI_ACT[model.eu_ai_act_category]||{} }), { headers:{ 'Content-Type':'application/json' } });
  } catch(e) { return new Response(JSON.stringify({ error:e.message }), { status:500, headers:{ 'Content-Type':'application/json' } }); }
}

async function updateModel(request, env, orgId) {
  const id = new URL(request.url).pathname.split('/').pop();
  try {
    const existing = await env.DB.prepare('SELECT id FROM ai_model_registry WHERE id = ? AND org_id = ?').bind(id, orgId).first();
    if (!existing) return new Response(JSON.stringify({ error:'Model not found' }), { status:404, headers:{ 'Content-Type':'application/json' } });
    const body = await request.json();
    const riskScore = scoreAIModelRisk(body);
    const now = new Date().toISOString();
    await env.DB.prepare(`UPDATE ai_model_registry SET name=?,version=?,model_type=?,data_classification=?,
      deployment_context=?,autonomy_level=?,impact_domain=?,explainability=?,bias_tested=?,
      risk_score=?,risk_level=?,eu_ai_act_category=?,updated_at=? WHERE id=? AND org_id=?`)
      .bind(body.name,body.version,body.model_type,body.data_classification,body.deployment_context,
        body.autonomy_level,body.impact_domain,body.explainability,body.bias_tested?1:0,
        riskScore.score,riskScore.riskLevel,riskScore.euAiActCategory,now,id,orgId).run();
    return new Response(JSON.stringify({ success:true, riskAssessment:riskScore }), { headers:{ 'Content-Type':'application/json' } });
  } catch(e) { return new Response(JSON.stringify({ error:e.message }), { status:500, headers:{ 'Content-Type':'application/json' } }); }
}

async function deleteModel(request, env, orgId) {
  const id = new URL(request.url).pathname.split('/').pop();
  try {
    const existing = await env.DB.prepare('SELECT id FROM ai_model_registry WHERE id = ? AND org_id = ?').bind(id, orgId).first();
    if (!existing) return new Response(JSON.stringify({ error:'Model not found' }), { status:404, headers:{ 'Content-Type':'application/json' } });
    await env.DB.prepare('UPDATE ai_model_registry SET status=? WHERE id=? AND org_id=?').bind('deleted',id,orgId).run();
    return new Response(JSON.stringify({ success:true, message:'Model deregistered' }), { headers:{ 'Content-Type':'application/json' } });
  } catch(e) { return new Response(JSON.stringify({ error:e.message }), { status:500, headers:{ 'Content-Type':'application/json' } }); }
}

async function calculateRiskScore(request, env) {
  try {
    const body = await request.json();
    const score = scoreAIModelRisk(body);
    return new Response(JSON.stringify({ ...score, euAiActDetails:EU_AI_ACT[score.euAiActCategory], assessedAt:new Date().toISOString() }), { headers:{ 'Content-Type':'application/json' } });
  } catch(e) { return new Response(JSON.stringify({ error:e.message }), { status:500, headers:{ 'Content-Type':'application/json' } }); }
}

async function getModelRiskScore(request, env, orgId) {
  const id = new URL(request.url).pathname.split('/').pop();
  try {
    const model = await env.DB.prepare('SELECT * FROM ai_model_registry WHERE id = ? AND org_id = ?').bind(id, orgId).first();
    if (!model) return new Response(JSON.stringify({ error:'Not found' }), { status:404, headers:{ 'Content-Type':'application/json' } });
    const score = scoreAIModelRisk(model);
    return new Response(JSON.stringify({ modelId:id, modelName:model.name, ...score }), { headers:{ 'Content-Type':'application/json' } });
  } catch(e) { return new Response(JSON.stringify({ error:e.message }), { status:500, headers:{ 'Content-Type':'application/json' } }); }
}

async function createPolicy(request, env, orgId) {
  try {
    const body = await request.json();
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    await env.DB.prepare(`INSERT INTO ai_governance_policies (id,org_id,name,description,rules,enforcement_level,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)`)
      .bind(id, orgId, body.name, body.description||'', JSON.stringify(body.rules||[]), body.enforcement_level||'WARN', now, now).run();
    return new Response(JSON.stringify({ success:true, id, message:`Policy "${body.name}" created` }), { status:201, headers:{ 'Content-Type':'application/json' } });
  } catch(e) { return new Response(JSON.stringify({ error:e.message }), { status:500, headers:{ 'Content-Type':'application/json' } }); }
}

async function listPolicies(request, env, orgId) {
  try {
    const { results } = await env.DB.prepare('SELECT * FROM ai_governance_policies WHERE org_id = ? ORDER BY created_at DESC').bind(orgId).all();
    return new Response(JSON.stringify({ policies:results, total:results.length }), { headers:{ 'Content-Type':'application/json' } });
  } catch(e) { return new Response(JSON.stringify({ error:e.message }), { status:500, headers:{ 'Content-Type':'application/json' } }); }
}

async function evaluatePolicy(request, env, orgId) {
  const parts = new URL(request.url).pathname.split('/');
  const policyId = parts[parts.length - 2];
  try {
    const body = await request.json();
    const policy = await env.DB.prepare('SELECT * FROM ai_governance_policies WHERE id = ? AND org_id = ?').bind(policyId, orgId).first();
    if (!policy) return new Response(JSON.stringify({ error:'Policy not found' }), { status:404, headers:{ 'Content-Type':'application/json' } });
    const rules = JSON.parse(policy.rules||'[]');
    const riskScore = scoreAIModelRisk(body.model);
    const violations = evaluatePolicyViolations({ ...body.model, riskScore }, [{ ...policy, rules }]);
    return new Response(JSON.stringify({ policyId, policyName:policy.name, enforcement:policy.enforcement_level,
      passed:violations.length===0, violationCount:violations.length, violations, modelRiskScore:riskScore,
      evaluatedAt:new Date().toISOString()
    }), { headers:{ 'Content-Type':'application/json' } });
  } catch(e) { return new Response(JSON.stringify({ error:e.message }), { status:500, headers:{ 'Content-Type':'application/json' } }); }
}

async function euAiActCheck(request, env) {
  try {
    const body = await request.json();
    const riskScore = scoreAIModelRisk(body);
    const category = EU_AI_ACT[riskScore.euAiActCategory];
    const checklistItems = [];
    if (riskScore.euAiActCategory === 'HIGH') {
      [['Conformity assessment completed','conformity_assessed'],['Registered in EU AI database','eu_registered'],
       ['Post-market monitoring plan','monitoring_plan'],['Human oversight measures documented','human_oversight'],
       ['Technical documentation (Annex IV)','technical_docs'],['Logging & auditability implemented','audit_logs'],
       ['Accuracy/robustness/cybersecurity','quality_tested']
      ].forEach(([check,field]) => checklistItems.push({ check, required:true, status:body[field]?'PASS':'FAIL' }));
    } else if (riskScore.euAiActCategory === 'LIMITED') {
      checklistItems.push({ check:'Transparency disclosure to users', required:true, status:body.transparency_notice?'PASS':'FAIL' });
      checklistItems.push({ check:'AI-generated content marked', required:!!body.generates_content, status:body.content_marked?'PASS':(body.generates_content?'FAIL':'N/A') });
    } else {
      checklistItems.push({ check:'No mandatory requirements', required:false, status:'PASS', note:'Voluntary codes of conduct recommended' });
    }
    const failCount = checklistItems.filter(c=>c.status==='FAIL').length;
    return new Response(JSON.stringify({
      category:riskScore.euAiActCategory, categoryDetails:category,
      complianceScore:Math.round(((checklistItems.length-failCount)/Math.max(checklistItems.length,1))*100),
      compliant:failCount===0, failCount, checklistItems, riskScore:riskScore.score,
      assessedAt:new Date().toISOString(),
      nextSteps:failCount>0?(category?.obligations||[]):['Maintain compliance posture','Annual review recommended']
    }), { headers:{ 'Content-Type':'application/json' } });
  } catch(e) { return new Response(JSON.stringify({ error:e.message }), { status:500, headers:{ 'Content-Type':'application/json' } }); }
}

async function nistAiRmfAssessment(request, env) {
  try {
    const body = await request.json();
    const responses = body.responses||{};
    const results = {};
    let totalScore=0, totalItems=0;
    for (const [func,data] of Object.entries(NIST_AI_RMF)) {
      const funcResults = { function:func, description:data.description, subcategories:{}, score:0, maxScore:0 };
      for (const [code,description] of Object.entries(data.subcategories)) {
        const resp = responses[code]||{ status:'NOT_IMPLEMENTED', notes:'' };
        const score = { FULLY_IMPLEMENTED:3, PARTIALLY_IMPLEMENTED:2, PLANNED:1, NOT_IMPLEMENTED:0 }[resp.status]??0;
        funcResults.subcategories[code] = { description, ...resp, score, maxScore:3 };
        funcResults.score += score; funcResults.maxScore += 3;
      }
      const pct = funcResults.score/funcResults.maxScore;
      funcResults.maturityLevel = pct>=0.8?'OPTIMIZING':pct>=0.6?'MANAGED':pct>=0.4?'DEFINED':pct>=0.2?'INITIAL':'INCOMPLETE';
      results[func] = funcResults;
      totalScore += funcResults.score; totalItems += funcResults.maxScore;
    }
    const overallPct = totalScore/totalItems;
    const overallMaturity = overallPct>=0.8?'OPTIMIZING':overallPct>=0.6?'MANAGED':overallPct>=0.4?'DEFINED':overallPct>=0.2?'INITIAL':'INCOMPLETE';
    return new Response(JSON.stringify({
      overallScore:totalScore, overallMaxScore:totalItems,
      overallPercentage:Math.round(overallPct*100), overallMaturity, functions:results,
      assessedAt:new Date().toISOString(),
      nextPriorityActions:Object.values(results)
        .flatMap(f=>Object.entries(f.subcategories).filter(([,v])=>v.status==='NOT_IMPLEMENTED').map(([k,v])=>({code:k,description:v.description})))
        .slice(0,5)
    }), { headers:{ 'Content-Type':'application/json' } });
  } catch(e) { return new Response(JSON.stringify({ error:e.message }), { status:500, headers:{ 'Content-Type':'application/json' } }); }
}

async function iso42001GapAnalysis(request, env) {
  try {
    const body = await request.json();
    const implemented = body.implemented_controls||[];
    const gaps=[], compliant=[];
    for (const [section,data] of Object.entries(ISO_42001_CONTROLS)) {
      for (const control of data.controls) {
        if (implemented.includes(control)) compliant.push({ section, control, title:data.title });
        else gaps.push({ section, control, title:data.title, severity:section<'A.5'?'HIGH':section<'A.8'?'MEDIUM':'LOW' });
      }
    }
    const total = gaps.length+compliant.length;
    return new Response(JSON.stringify({
      totalControls:total, implemented:compliant.length, gaps:gaps.length,
      compliancePercentage:Math.round((compliant.length/total)*100),
      certificationReady:gaps.length===0,
      criticalGaps:gaps.filter(g=>g.severity==='HIGH'),
      allGaps:gaps, implementedControls:compliant,
      estimatedRemediationWeeks:Math.ceil(gaps.length*1.5),
      assessedAt:new Date().toISOString()
    }), { headers:{ 'Content-Type':'application/json' } });
  } catch(e) { return new Response(JSON.stringify({ error:e.message }), { status:500, headers:{ 'Content-Type':'application/json' } }); }
}

async function detectShadowAI(request, env, orgId) {
  try {
    const body = await request.json();
    const dnsLogs = body.dns_logs||[];
    const networkLogs = body.network_logs||[];
    const detected = [];
    for (const tool of KNOWN_SHADOW_AI_TOOLS) {
      const match = tool.domains.some(d=>dnsLogs.some(l=>l.includes(d))||networkLogs.some(l=>l.includes(d)));
      if (match) detected.push({ ...tool, detectedVia:'DNS/Network', firstSeen:new Date().toISOString() });
    }
    const result = { orgId, detected, detectedCount:detected.length,
      highRiskCount:detected.filter(t=>t.risk==='HIGH').length,
      dataEgressRisks:detected.filter(t=>t.dataEgressRisk==='HIGH'),
      gdprConcerns:detected.filter(t=>t.gdprConcerns),
      allKnownRisks:KNOWN_SHADOW_AI_TOOLS,
      recommendations:detected.length>0?['Block unauthorized AI API endpoints at firewall/proxy level',
        'Implement AI usage policy and training for employees','Deploy approved AI tools through sanctioned channels',
        'Enable DLP rules for AI platforms in your CASB solution']:['No shadow AI detected. Maintain monitoring posture.'],
      scannedAt:new Date().toISOString()
    };
    await env.KV.put(`shadow_ai:${orgId}`, JSON.stringify(result), { expirationTtl:3600 });
    return new Response(JSON.stringify(result), { headers:{ 'Content-Type':'application/json' } });
  } catch(e) { return new Response(JSON.stringify({ error:e.message }), { status:500, headers:{ 'Content-Type':'application/json' } }); }
}

async function shadowAIInventory(request, env, orgId) {
  try {
    const cached = await env.KV.get(`shadow_ai:${orgId}`,'json');
    return new Response(JSON.stringify(cached||{ orgId, detected:[],
      message:'No scan results found. Run POST /api/ai-governance/shadow-ai/detect first.',
      knownThreats:KNOWN_SHADOW_AI_TOOLS.length, scannedAt:null
    }), { headers:{ 'Content-Type':'application/json' } });
  } catch(e) { return new Response(JSON.stringify({ error:e.message }), { status:500, headers:{ 'Content-Type':'application/json' } }); }
}

async function governanceDashboard(request, env, orgId) {
  try {
    const { results:models } = await env.DB.prepare(
      'SELECT risk_level,eu_ai_act_category,COUNT(*) as cnt FROM ai_model_registry WHERE org_id=? AND status!=? GROUP BY risk_level,eu_ai_act_category'
    ).bind(orgId,'deleted').all();
    const { results:policies } = await env.DB.prepare(
      'SELECT COUNT(*) as cnt,enforcement_level FROM ai_governance_policies WHERE org_id=? GROUP BY enforcement_level'
    ).bind(orgId).all();
    const shadow = await env.KV.get(`shadow_ai:${orgId}`,'json');
    const totalModels = models.reduce((s,m)=>s+(m.cnt||0),0);
    return new Response(JSON.stringify({
      summary:{
        totalModels, totalPolicies:policies.reduce((s,p)=>s+(p.cnt||0),0),
        shadowAIDetected:shadow?.detectedCount||0,
        riskBreakdown:{ CRITICAL:models.filter(m=>m.risk_level==='CRITICAL').reduce((s,m)=>s+m.cnt,0),
          HIGH:models.filter(m=>m.risk_level==='HIGH').reduce((s,m)=>s+m.cnt,0),
          MEDIUM:models.filter(m=>m.risk_level==='MEDIUM').reduce((s,m)=>s+m.cnt,0),
          LOW:models.filter(m=>m.risk_level==='LOW').reduce((s,m)=>s+m.cnt,0) },
        euAiActBreakdown:{ HIGH:models.filter(m=>m.eu_ai_act_category==='HIGH').reduce((s,m)=>s+m.cnt,0),
          LIMITED:models.filter(m=>m.eu_ai_act_category==='LIMITED').reduce((s,m)=>s+m.cnt,0),
          MINIMAL:models.filter(m=>m.eu_ai_act_category==='MINIMAL').reduce((s,m)=>s+m.cnt,0) }
      },
      complianceStatus:{ euAiAct:'Monitoring', nistAiRmf:'In Progress', iso42001:'Gap Analysis Available' },
      lastUpdated:new Date().toISOString()
    }), { headers:{ 'Content-Type':'application/json' } });
  } catch(e) { return new Response(JSON.stringify({ error:e.message }), { status:500, headers:{ 'Content-Type':'application/json' } }); }
}

async function generateGovernanceReport(request, env, orgId) {
  try {
    const { results:models } = await env.DB.prepare(
      'SELECT * FROM ai_model_registry WHERE org_id=? AND status!=? ORDER BY risk_score DESC'
    ).bind(orgId,'deleted').all();
    const criticalModels = models.filter(m=>m.risk_level==='CRITICAL');
    const highModels = models.filter(m=>m.risk_level==='HIGH');
    const shadow = await env.KV.get(`shadow_ai:${orgId}`,'json');
    const report = {
      reportId:crypto.randomUUID(), reportType:'AI_GOVERNANCE_FULL', orgId,
      generatedAt:new Date().toISOString(), generatedBy:'CYBERDUDEBIVASH AI Security Hub',
      executiveSummary:{
        totalAIModels:models.length, criticalRisk:criticalModels.length, highRisk:highModels.length,
        euHighRisk:models.filter(m=>m.eu_ai_act_category==='HIGH').length,
        overallGovernanceScore:models.length>0?Math.round(100-(models.reduce((s,m)=>s+m.risk_score,0)/models.length)):100,
        message:criticalModels.length>0?`URGENT: ${criticalModels.length} critical-risk AI models require immediate remediation`:
          highModels.length>0?`${highModels.length} high-risk AI models require attention within 30 days`:
          'AI model portfolio risk is within acceptable bounds'
      },
      modelInventory:models,
      criticalFindings:criticalModels.map(m=>({ modelId:m.id, modelName:m.name, riskScore:m.risk_score,
        euAiActCategory:m.eu_ai_act_category, recommendedAction:'Immediate human oversight & conformity assessment' })),
      complianceFrameworks:{ euAiAct:EU_AI_ACT, nistAiRmf:Object.keys(NIST_AI_RMF), iso42001:Object.keys(ISO_42001_CONTROLS) },
      shadowAIStatus:shadow||{ detected:[] }
    };
    await env.KV.put(`gov_report:${orgId}:latest`, JSON.stringify(report), { expirationTtl:86400 });
    return new Response(JSON.stringify(report), { headers:{ 'Content-Type':'application/json' } });
  } catch(e) { return new Response(JSON.stringify({ error:e.message }), { status:500, headers:{ 'Content-Type':'application/json' } }); }
}
