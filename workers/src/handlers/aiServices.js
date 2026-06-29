/**
 * CYBERDUDEBIVASH v28 — AI Security Services Handler
 * PILLAR 6: Service Delivery Workflows
 *
 * POST /api/ai-security/services/scope        -> scoping call request
 * POST /api/ai-security/services/book         -> book AI security service
 * GET  /api/ai-security/services/catalog      -> service catalog with pricing
 * GET  /api/ai-security/services/:id          -> service engagement status
 */

const CORS = { 'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization' };
const json = (d,s=200) => new Response(JSON.stringify(d),{status:s,headers:{...CORS,'Content-Type':'application/json'}});
const err  = (m,s=400) => json({success:false,error:m},s);

export const AI_SERVICE_CATALOG = [
  {
    id: 'ai_security_assessment',
    name: 'AI Security Assessment',
    tagline: 'OWASP LLM Top 10 + NIST AI RMF gap analysis for your AI systems',
    price_inr: 24999,
    price_label: '₹24,999',
    delivery_days: 5,
    tier: 'standard',
    deliverables: [
      'Complete OWASP LLM Top 10 assessment across all AI endpoints',
      'AI asset inventory (models, agents, RAG systems, APIs)',
      'Prompt injection and jailbreak vulnerability findings',
      'NIST AI RMF compliance gap analysis',
      'Risk-prioritized remediation roadmap (30/60/90 day)',
      '60-minute expert walkthrough call',
      'GST-compliant invoice',
    ],
    ideal_for: 'Organizations deploying LLMs, chatbots, or AI APIs for the first time',
    process: ['Intake questionnaire (Day 1)','Asset discovery and scanning (Days 2-3)','Manual testing and analysis (Days 3-4)','Report writing and review (Day 5)','Delivery and walkthrough call'],
  },
  {
    id: 'ai_governance_assessment',
    name: 'AI Governance Assessment',
    tagline: 'ISO 42001 / EU AI Act / NIST AI RMF compliance readiness assessment',
    price_inr: 49999,
    price_label: '₹49,999',
    delivery_days: 10,
    tier: 'premium',
    deliverables: [
      'Full NIST AI RMF (GOVERN/MAP/MEASURE/MANAGE) gap analysis',
      'ISO 42001 readiness assessment with control-by-control scoring',
      'EU AI Act risk classification (prohibited / high-risk / GPAI)',
      'DPDP Act 2023 AI compliance checklist',
      'AI Risk Register (top 20 organizational AI risks)',
      'AI Governance Policy templates (3 documents)',
      'Board-ready executive presentation',
      '90-minute leadership briefing call',
    ],
    ideal_for: 'Enterprises with multiple AI deployments needing regulatory compliance',
    process: ['Executive interviews (Days 1-2)','Documentation review (Days 2-4)','Framework mapping (Days 4-7)','Gap analysis and roadmap (Days 7-9)','Report and briefing (Days 9-10)'],
  },
  {
    id: 'ai_redteam_engagement',
    name: 'AI Red Team Engagement',
    tagline: 'Adversarial testing: prompt injection, jailbreaking, agent takeover, RAG poisoning',
    price_inr: 99999,
    price_label: '₹99,999',
    delivery_days: 14,
    tier: 'premium',
    deliverables: [
      'Full adversarial testing across all 6 attack categories',
      'Prompt injection: 50+ payload variants',
      'Jailbreak testing with latest published techniques (MSJ, PAIR, Crescendo)',
      'Agent takeover and tool abuse testing',
      'RAG poisoning and context manipulation testing',
      'Data exfiltration attempt log',
      'MITRE ATT&CK mapping for all successful attacks',
      'Executive red team report with video evidence',
      'Detailed remediation guide per finding',
      '120-minute debrief session with attack replay',
    ],
    ideal_for: 'Organizations with production AI systems handling sensitive data or critical decisions',
    process: ['Scoping and target enumeration (Days 1-2)','Reconnaissance and profiling (Days 2-4)','Attack execution (Days 4-10)','Evidence collection and analysis (Days 10-12)','Report writing (Days 12-13)','Debrief (Day 14)'],
  },
  {
    id: 'managed_ai_security',
    name: 'Managed AI Security',
    tagline: 'Ongoing AI security monitoring, threat intelligence, and quarterly red teaming',
    price_inr: 49999,
    price_label: '₹49,999/month',
    delivery_days: null,
    tier: 'enterprise',
    is_recurring: true,
    deliverables: [
      'Continuous AI threat intelligence feed (Sentinel APEX)',
      'Monthly AI security posture report',
      'Quarterly AI red team exercise (1 engagement/quarter)',
      'Incident response support for AI security events',
      'New AI deployment security review (2/month)',
      'Dedicated security analyst (4 hours/week)',
      'Quarterly executive briefing',
      'Priority access to new AI security advisories',
    ],
    ideal_for: 'Enterprises with mature AI programs needing ongoing security assurance',
  },
  {
    id: 'executive_ai_risk_advisory',
    name: 'Executive AI Risk Advisory',
    tagline: 'Board-level AI risk briefing and strategic AI security roadmap',
    price_inr: 149999,
    price_label: '₹1,49,999',
    delivery_days: 21,
    tier: 'enterprise',
    deliverables: [
      'Board-ready AI risk presentation (customized)',
      'AI risk appetite statement draft',
      'Strategic AI security roadmap (12-18 month)',
      'AI governance policy suite (5 documents)',
      'Regulatory risk assessment (EU AI Act + DPDP + sector-specific)',
      'AI vendor security assessment framework',
      'CISO-to-board communication templates',
      'Three advisory sessions (2 hours each)',
    ],
    ideal_for: 'C-suite and board requiring strategic AI risk guidance for governance and compliance',
  },
];

// GET /api/ai-security/services/catalog ───────────────────────────────────────
export async function handleServiceCatalog(request, env) {
  return json({ success:true, catalog:AI_SERVICE_CATALOG, contact:{ email:'contact@cyberdudebivash.in', whatsapp:'+91 81798 81447', book:'/booking.html' } });
}

// POST /api/ai-security/services/book ─────────────────────────────────────────
export async function handleBookAIService(request, env, authCtx) {
  let body; try { body = await request.json(); } catch { return err('Invalid JSON'); }

  const { service_id, email, company, domain, phone, ai_systems, notes } = body;
  if (!service_id || !email) return err('service_id and email required');

  const service = AI_SERVICE_CATALOG.find(s => s.id === service_id);
  if (!service) return err('Invalid service_id. See /api/ai-security/services/catalog');

  const engId  = 'aisvc_' + Date.now().toString(36) + Math.random().toString(36).slice(2,6);
  const scope  = { ai_systems: ai_systems||[], notes: notes||'', domain: domain||'' };

  try {
    await env.DB.prepare(
      'INSERT INTO ai_service_engagements (id,email,company,service_type,scope,status,price_inr,deliverables) VALUES (?,?,?,?,?,?,?,?)'
    ).bind(engId, email, company||null, service_id, JSON.stringify(scope), 'scoping', service.price_inr, JSON.stringify(service.deliverables)).run();
  } catch(e) {
    return err('Booking failed: ' + e.message, 500);
  }

  // Track funnel event
  try {
    await env.DB.prepare('INSERT INTO funnel_events (id,email,stage,meta) VALUES (?,?,?,?)')
      .bind('fev_'+Date.now().toString(36), email, 'ai_service_booked', JSON.stringify({service_id, price:service.price_inr})).run();
  } catch { /* non-blocking */ }

  return json({
    success:true, engagement_id:engId, service_id, service_name:service.name,
    price_inr:service.price_inr, price_label:service.price_label,
    delivery_days:service.delivery_days, status:'scoping',
    next_steps: ['We will contact you at '+email+' within 4 business hours to schedule a scoping call.','WhatsApp for faster response: +91 81798 81447'],
    what_to_prepare: ['List of AI systems in scope (models, APIs, agents)','Your primary compliance requirements','Key stakeholder contacts'],
  }, 201);
}

// GET /api/ai-security/services/:id ───────────────────────────────────────────
export async function handleGetAIServiceEngagement(request, env, authCtx) {
  if (!authCtx?.userId) return err('Auth required', 401);
  const id = new URL(request.url).pathname.split('/').pop();
  const row = await env.DB.prepare('SELECT * FROM ai_service_engagements WHERE id=?').bind(id).first();
  if (!row) return err('Engagement not found', 404);
  if (authCtx.role!=='admin' && authCtx.email!==row.email) return err('Access denied', 403);
  return json({ success:true, engagement:{ ...row, scope:JSON.parse(row.scope||'{}'), deliverables:JSON.parse(row.deliverables||'[]') }});
}
