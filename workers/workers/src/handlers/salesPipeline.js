/**
 * CYBERDUDEBIVASH AI Security Hub — Sales CRM Pipeline
 * Phase 4: ₹1CR Revenue Engine
 *
 * Full B2B sales pipeline: Lead → Qualified → Demo Booked → Demo Done →
 * Proposal Sent → Negotiation → Closed Won/Lost
 *
 * Endpoints:
 *   POST /api/sales/leads                  → submit lead (public inquiry form)
 *   GET  /api/sales/leads                  → list leads (admin)
 *   GET  /api/sales/leads/:id              → single lead detail
 *   PUT  /api/sales/leads/:id/stage        → advance pipeline stage
 *   POST /api/sales/leads/:id/note         → add CRM note
 *   POST /api/sales/demo/book              → book demo slot (public)
 *   GET  /api/sales/demo/slots             → available demo slots
 *   GET  /api/sales/pipeline               → full pipeline board view
 *   GET  /api/sales/metrics                → pipeline metrics + revenue forecast
 *   POST /api/sales/leads/:id/qualify      → mark as qualified with ICP score
 *   POST /api/sales/leads/:id/close        → close won/lost with deal value
 */

import { ok, fail } from '../lib/response.js';

const KV_LEADS_INDEX  = 'crm:leads_index';
const KV_LEAD_PREFIX  = 'crm:lead:';
const KV_DEMO_SLOTS   = 'crm:demo_slots';
const KV_DEMO_BOOKINGS= 'crm:demo_bookings';
const KV_METRICS_SNAP = 'crm:metrics_snapshot';

// ── Pipeline stages (ordered) ─────────────────────────────────────────────────
const STAGES = ['NEW','QUALIFIED','DEMO_BOOKED','DEMO_DONE','PROPOSAL_SENT','NEGOTIATION','CLOSED_WON','CLOSED_LOST'];

// ── ICP scoring criteria ──────────────────────────────────────────────────────
const SECTOR_SCORES = {
  FINANCE:      30, BANKING: 30, INSURANCE: 25,
  HEALTHCARE:   25, PHARMA: 22,
  GOVERNMENT:   28, DEFENSE: 35,
  TECHNOLOGY:   20, SAAS: 18,
  ENERGY:       24, OIL_GAS: 26,
  RETAIL:       15, ECOMMERCE: 14,
  MANUFACTURING:18, OTHER: 10,
};

const SIZE_SCORES = {
  '1-10': 5, '11-50': 10, '51-200': 18, '201-500': 25,
  '501-1000': 30, '1001-5000': 35, '5000+': 40,
};

function calculateICPScore(lead) {
  let score = 0;
  score += SECTOR_SCORES[(lead.sector || '').toUpperCase()] || 10;
  score += SIZE_SCORES[lead.company_size] || 5;
  if (lead.has_existing_siem)     score += 15;
  if (lead.has_compliance_need)   score += 15;
  if (lead.budget_range === 'HIGH') score += 20;
  if (lead.budget_range === 'MED')  score += 10;
  if (lead.urgency === 'IMMEDIATE') score += 15;
  if (lead.urgency === 'QUARTER')   score += 8;
  if (lead.role && /CISO|CTO|CSO|VP|Director/i.test(lead.role)) score += 10;
  return Math.min(100, score);
}

function estimateDealValue(lead, icpScore) {
  const base = icpScore >= 80 ? 500000
             : icpScore >= 60 ? 200000
             : icpScore >= 40 ? 100000
             : 50000;
  const sizeMultiplier = SIZE_SCORES[lead.company_size] / 20 || 1;
  const urgencyBonus   = lead.urgency === 'IMMEDIATE' ? 1.3 : 1.0;
  return Math.round(base * sizeMultiplier * urgencyBonus);
}

function generateLeadId() {
  return 'lead_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
async function loadLeads(env) {
  if (!env?.SECURITY_HUB_KV) return [];
  try { return (await env.SECURITY_HUB_KV.get(KV_LEADS_INDEX, { type: 'json' })) || []; } catch { return []; }
}

async function saveLeads(env, leads) {
  if (!env?.SECURITY_HUB_KV) return;
  await env.SECURITY_HUB_KV.put(KV_LEADS_INDEX, JSON.stringify(leads.slice(0, 5000)), { expirationTtl: 86400 * 365 * 2 });
}

async function loadLead(env, id) {
  if (!env?.SECURITY_HUB_KV) return null;
  try { return await env.SECURITY_HUB_KV.get(`${KV_LEAD_PREFIX}${id}`, { type: 'json' }); } catch { return null; }
}

async function saveLead(env, lead) {
  if (!env?.SECURITY_HUB_KV) return;
  await env.SECURITY_HUB_KV.put(`${KV_LEAD_PREFIX}${lead.id}`, JSON.stringify(lead), { expirationTtl: 86400 * 365 * 2 });
}

// ── POST /api/sales/leads ─────────────────────────────────────────────────────
export async function handleCreateLead(request, env) {
  let body = {};
  try { body = await request.json(); } catch {}

  const { name, email, company, phone, sector, company_size, role, message,
          has_existing_siem, has_compliance_need, budget_range, urgency,
          source = 'website_form' } = body;

  if (!name || !email || !company) {
    return fail(request, 'name, email, and company are required', 400, 'MISSING_FIELDS');
  }

  const now    = new Date().toISOString();
  const id     = generateLeadId();
  const icpScore = calculateICPScore({ sector, company_size, has_existing_siem, has_compliance_need, budget_range, urgency, role });
  const dealEst  = estimateDealValue({ company_size, urgency }, icpScore);

  const lead = {
    id, name, email, company,
    phone:              phone    || null,
    sector:             sector   || 'UNKNOWN',
    company_size:       company_size || 'UNKNOWN',
    role:               role     || null,
    message:            message  || '',
    has_existing_siem:  !!has_existing_siem,
    has_compliance_need:!!has_compliance_need,
    budget_range:       budget_range || 'UNKNOWN',
    urgency:            urgency  || 'UNKNOWN',
    source,
    stage:              'NEW',
    icp_score:          icpScore,
    deal_value_est_inr: dealEst,
    priority:           icpScore >= 70 ? 'HIGH' : icpScore >= 40 ? 'MEDIUM' : 'LOW',
    notes:              [],
    timeline:           [{ stage: 'NEW', ts: now, actor: 'system', note: 'Lead created via ' + source }],
    demo_booked_at:     null,
    demo_slot:          null,
    proposal_sent_at:   null,
    closed_at:          null,
    close_reason:       null,
    actual_deal_value:  null,
    created_at:         now,
    updated_at:         now,
    owner:              null,
  };

  await saveLead(env, lead);

  const leads = await loadLeads(env);
  leads.unshift({
    id, name, email, company, stage: 'NEW', icp_score: icpScore,
    deal_value_est_inr: dealEst, priority: lead.priority,
    source, created_at: now,
  });
  await saveLeads(env, leads);

  // Track in analytics
  try {
    if (env?.SECURITY_HUB_DB) {
      await env.SECURITY_HUB_DB.prepare(
        `INSERT OR IGNORE INTO analytics_events (event_type, user_id, metadata, created_at)
         VALUES ('lead_created', ?, ?, datetime('now'))`
      ).bind(email, JSON.stringify({ company, icp_score: icpScore, deal_est: dealEst, source })).run();
    }
  } catch {}

  return ok(request, {
    submitted: true,
    lead_id:   id,
    icp_score: icpScore,
    priority:  lead.priority,
    message:   'Thank you! Our enterprise sales team will contact you within 4 hours.',
    expected_contact_by: new Date(Date.now() + 4 * 3600000).toISOString(),
  });
}

// ── GET /api/sales/leads ──────────────────────────────────────────────────────
export async function handleListLeads(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  const url    = new URL(request.url);
  const stage  = url.searchParams.get('stage');
  const limit  = Math.min(100, parseInt(url.searchParams.get('limit') || '50', 10));
  const q      = (url.searchParams.get('q') || '').toLowerCase();

  let leads = await loadLeads(env);

  if (stage) leads = leads.filter(l => l.stage === stage);
  if (q)     leads = leads.filter(l =>
    (l.name    || '').toLowerCase().includes(q) ||
    (l.company || '').toLowerCase().includes(q) ||
    (l.email   || '').toLowerCase().includes(q)
  );

  leads.sort((a, b) => (b.icp_score || 0) - (a.icp_score || 0));

  const stageCounts = STAGES.reduce((acc, s) => {
    acc[s] = leads.filter(l => l.stage === s).length;
    return acc;
  }, {});

  return ok(request, { total: leads.length, stage_counts: stageCounts, leads: leads.slice(0, limit) });
}

// ── GET /api/sales/leads/:id ──────────────────────────────────────────────────
export async function handleGetLead(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');
  const id = new URL(request.url).pathname.split('/').slice(-1)[0];
  const lead = await loadLead(env, id);
  if (!lead) return fail(request, 'Lead not found', 404, 'NOT_FOUND');
  return ok(request, lead);
}

// ── PUT /api/sales/leads/:id/stage ────────────────────────────────────────────
export async function handleAdvanceStage(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  const parts = new URL(request.url).pathname.split('/');
  const id    = parts[parts.length - 2];
  let body = {};
  try { body = await request.json(); } catch {}

  const lead = await loadLead(env, id);
  if (!lead) return fail(request, 'Lead not found', 404, 'NOT_FOUND');

  const { stage, note = '' } = body;
  if (!STAGES.includes(stage)) return fail(request, 'Invalid stage', 400, 'INVALID_STAGE');

  const now = new Date().toISOString();
  lead.stage      = stage;
  lead.updated_at = now;
  lead.timeline.push({ stage, ts: now, actor: authCtx.email || 'admin', note });

  if (stage === 'CLOSED_WON' || stage === 'CLOSED_LOST') {
    lead.closed_at    = now;
    lead.close_reason = body.reason || null;
    if (body.actual_value) lead.actual_deal_value = parseInt(body.actual_value, 10);
  }

  await saveLead(env, lead);

  // Sync index
  const leads = await loadLeads(env);
  const idx = leads.findIndex(l => l.id === id);
  if (idx >= 0) { leads[idx].stage = stage; leads[idx].updated_at = now; }
  await saveLeads(env, leads);

  return ok(request, { updated: true, stage, lead_id: id });
}

// ── POST /api/sales/leads/:id/note ───────────────────────────────────────────
export async function handleAddNote(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  const parts = new URL(request.url).pathname.split('/');
  const id    = parts[parts.length - 2];
  let body = {};
  try { body = await request.json(); } catch {}

  const lead = await loadLead(env, id);
  if (!lead) return fail(request, 'Lead not found', 404, 'NOT_FOUND');

  const note = { ts: new Date().toISOString(), author: authCtx.email || 'admin', text: body.text || '', type: body.type || 'NOTE' };
  lead.notes.push(note);
  lead.updated_at = note.ts;
  await saveLead(env, lead);
  return ok(request, { added: true, note });
}

// ── POST /api/sales/leads/:id/qualify ────────────────────────────────────────
export async function handleQualifyLead(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  const parts = new URL(request.url).pathname.split('/');
  const id    = parts[parts.length - 2];
  let body = {};
  try { body = await request.json(); } catch {}

  const lead = await loadLead(env, id);
  if (!lead) return fail(request, 'Lead not found', 404, 'NOT_FOUND');

  const icpScore = body.icp_score !== undefined ? parseInt(body.icp_score) : lead.icp_score;
  const dealEst  = body.deal_value_est_inr || estimateDealValue(lead, icpScore);
  const now      = new Date().toISOString();

  lead.stage              = 'QUALIFIED';
  lead.icp_score          = icpScore;
  lead.deal_value_est_inr = dealEst;
  lead.priority           = icpScore >= 70 ? 'HIGH' : icpScore >= 40 ? 'MEDIUM' : 'LOW';
  lead.updated_at         = now;
  lead.timeline.push({ stage: 'QUALIFIED', ts: now, actor: authCtx.email || 'admin', note: body.qualify_note || 'Manually qualified' });
  lead.owner              = body.owner || lead.owner;

  await saveLead(env, lead);

  const leads = await loadLeads(env);
  const idx = leads.findIndex(l => l.id === id);
  if (idx >= 0) { leads[idx].stage = 'QUALIFIED'; leads[idx].icp_score = icpScore; leads[idx].priority = lead.priority; }
  await saveLeads(env, leads);

  return ok(request, { qualified: true, icp_score: icpScore, deal_value_est_inr: dealEst, priority: lead.priority });
}

// ── POST /api/sales/leads/:id/close ──────────────────────────────────────────
export async function handleCloseLead(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  const parts = new URL(request.url).pathname.split('/');
  const id    = parts[parts.length - 2];
  let body = {};
  try { body = await request.json(); } catch {}

  const lead = await loadLead(env, id);
  if (!lead) return fail(request, 'Lead not found', 404, 'NOT_FOUND');

  const won = body.outcome === 'WON';
  const now = new Date().toISOString();

  lead.stage             = won ? 'CLOSED_WON' : 'CLOSED_LOST';
  lead.closed_at         = now;
  lead.close_reason      = body.reason || null;
  lead.actual_deal_value = body.actual_value ? parseInt(body.actual_value, 10) : null;
  lead.updated_at        = now;
  lead.timeline.push({ stage: lead.stage, ts: now, actor: authCtx.email || 'admin', note: body.reason || '' });

  await saveLead(env, lead);

  const leads = await loadLeads(env);
  const idx = leads.findIndex(l => l.id === id);
  if (idx >= 0) {
    leads[idx].stage      = lead.stage;
    leads[idx].closed_at  = now;
    if (body.actual_value) leads[idx].actual_deal_value = lead.actual_deal_value;
  }
  await saveLeads(env, leads);

  return ok(request, { closed: true, outcome: won ? 'WON' : 'LOST', deal_value: lead.actual_deal_value });
}

// ── POST /api/sales/demo/book ─────────────────────────────────────────────────
export async function handleBookDemo(request, env) {
  let body = {};
  try { body = await request.json(); } catch {}

  const { lead_id, name, email, company, preferred_slot, timezone = 'Asia/Kolkata', use_case = '' } = body;
  if (!email || !preferred_slot) return fail(request, 'email and preferred_slot are required', 400, 'MISSING_FIELDS');

  const booking = {
    id:             'demo_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
    lead_id:        lead_id || null,
    name:           name    || 'Prospect',
    email,
    company:        company || 'Unknown',
    slot:           preferred_slot,
    timezone,
    use_case,
    status:         'CONFIRMED',
    booked_at:      new Date().toISOString(),
    meet_link:      'https://meet.google.com/cdb-demo-' + Math.random().toString(36).slice(2, 8),
    confirmation_sent: false,
  };

  if (env?.SECURITY_HUB_KV) {
    let bookings = [];
    try { bookings = (await env.SECURITY_HUB_KV.get(KV_DEMO_BOOKINGS, { type: 'json' })) || []; } catch {}
    bookings.unshift(booking);
    await env.SECURITY_HUB_KV.put(KV_DEMO_BOOKINGS, JSON.stringify(bookings.slice(0, 500)), { expirationTtl: 86400 * 90 });
  }

  // Advance lead stage if lead_id provided
  if (lead_id && env?.SECURITY_HUB_KV) {
    try {
      const lead = await loadLead(env, lead_id);
      if (lead && lead.stage === 'QUALIFIED') {
        lead.stage          = 'DEMO_BOOKED';
        lead.demo_booked_at = booking.booked_at;
        lead.demo_slot      = preferred_slot;
        lead.updated_at     = booking.booked_at;
        lead.timeline.push({ stage: 'DEMO_BOOKED', ts: booking.booked_at, actor: 'system', note: 'Demo booked for slot: ' + preferred_slot });
        await saveLead(env, lead);
      }
    } catch {}
  }

  return ok(request, {
    booked:    true,
    booking_id: booking.id,
    slot:      preferred_slot,
    meet_link: booking.meet_link,
    message:   'Demo confirmed! You will receive a calendar invite at ' + email + ' within 15 minutes.',
  });
}

// ── GET /api/sales/demo/slots ─────────────────────────────────────────────────
export async function handleGetDemoSlots(request, env) {
  const now  = new Date();
  const slots = [];

  // Generate next 7 business days × 3 slots/day
  for (let d = 1; d <= 10 && slots.length < 21; d++) {
    const date = new Date(now);
    date.setDate(date.getDate() + d);
    const dow = date.getDay();
    if (dow === 0 || dow === 6) continue; // skip weekends

    const dateStr = date.toISOString().slice(0, 10);
    ['10:00', '14:00', '16:00'].forEach(time => {
      slots.push({
        slot:      `${dateStr}T${time}:00+05:30`,
        label:     date.toLocaleDateString('en-IN', { weekday: 'long', month: 'short', day: 'numeric' }) + ' at ' + time + ' IST',
        available: true,
        duration:  30,
      });
    });
  }

  return ok(request, { slots, timezone: 'Asia/Kolkata' });
}

// ── GET /api/sales/pipeline ───────────────────────────────────────────────────
export async function handleGetPipeline(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  const leads = await loadLeads(env);
  const board = {};
  STAGES.forEach(s => {
    board[s] = leads.filter(l => l.stage === s).map(l => ({
      id:                 l.id,
      name:               l.name,
      company:            l.company,
      icp_score:          l.icp_score,
      deal_value_est_inr: l.deal_value_est_inr || 0,
      priority:           l.priority,
      created_at:         l.created_at,
    }));
  });

  const pipeline_value = leads
    .filter(l => !['CLOSED_LOST'].includes(l.stage))
    .reduce((s, l) => s + (l.deal_value_est_inr || 0), 0);

  return ok(request, { board, pipeline_value_inr: pipeline_value, stages: STAGES });
}

// ── GET /api/sales/metrics ────────────────────────────────────────────────────
export async function handleGetMetrics(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  const leads = await loadLeads(env);
  const won   = leads.filter(l => l.stage === 'CLOSED_WON');
  const lost  = leads.filter(l => l.stage === 'CLOSED_LOST');
  const open  = leads.filter(l => !['CLOSED_WON','CLOSED_LOST'].includes(l.stage));

  const total_pipeline_inr    = open.reduce((s, l) => s + (l.deal_value_est_inr || 0), 0);
  const total_closed_won_inr  = won.reduce((s, l) => s + (l.actual_deal_value || l.deal_value_est_inr || 0), 0);
  const win_rate              = (won.length + lost.length) > 0
    ? parseFloat(((won.length / (won.length + lost.length)) * 100).toFixed(1)) : 0;

  // Stage velocity (avg days per stage) — simplified
  const high_priority = open.filter(l => l.priority === 'HIGH').length;

  return ok(request, {
    total_leads:          leads.length,
    open_leads:           open.length,
    closed_won:           won.length,
    closed_lost:          lost.length,
    win_rate,
    total_pipeline_inr,
    total_closed_won_inr,
    high_priority_leads:  high_priority,
    avg_deal_value_inr:   won.length ? Math.round(total_closed_won_inr / won.length) : 0,
    revenue_target_inr:   10000000, // ₹1CR
    revenue_progress_pct: parseFloat(((total_closed_won_inr / 10000000) * 100).toFixed(1)),
    generated_at:         new Date().toISOString(),
  });
}
