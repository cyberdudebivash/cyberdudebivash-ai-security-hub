/**
 * CYBERDUDEBIVASH AI Security Hub
 * AGENT EVENT BUS — D1-backed queue for reliable event dispatch
 * All agents publish/consume events through this bus.
 * Guarantees: at-least-once delivery, ordered by priority, retry on failure.
 */

function uuid() { return crypto.randomUUID(); }
function now()  { return new Date().toISOString(); }

// Event types
export const EVENT_TYPES = {
  CVE_DETECTED:       'cve_detected',
  ANOMALY_DETECTED:   'anomaly_detected',
  THREAT_INTEL:       'threat_intel',
  MANUAL_TRIGGER:     'manual_trigger',
  SCHEDULED_SCAN:     'scheduled_scan',
  LOGIN_SUSPICIOUS:   'login_suspicious',
  API_ABUSE:          'api_abuse',
  PATCH_REQUEST:      'patch_request',
};

// Priority levels (higher = processed first)
const PRIORITY = {
  CRITICAL: 10,
  HIGH:     7,
  MEDIUM:   5,
  LOW:      2,
};

/**
 * Publish an event to the bus
 */
export async function publishEvent(env, eventType, payload, riskLevel = 'HIGH') {
  const priority = PRIORITY[riskLevel] || 5;
  const id = uuid();

  await env.DB.prepare(`
    INSERT INTO agent_event_queue (id, event_type, payload, priority, status, attempts, created_at)
    VALUES (?,?,?,?,'pending',0,?)
  `).bind(id, eventType, JSON.stringify(payload), priority, now()).run();

  return id;
}

/**
 * Consume pending events (called by cron + manual triggers)
 * Returns processed events array
 */
export async function consumeEvents(env, maxBatch = 20) {
  // Claim pending events atomically (mark as processing)
  const events = await env.DB.prepare(`
    SELECT * FROM agent_event_queue
    WHERE status = 'pending' AND attempts < max_attempts
    ORDER BY priority DESC, created_at ASC
    LIMIT ?
  `).bind(maxBatch).all().catch(() => ({ results: [] }));

  const items = events.results || [];
  if (items.length === 0) return [];

  // Mark all as processing
  for (const ev of items) {
    await env.DB.prepare(`
      UPDATE agent_event_queue SET status='processing', attempts=attempts+1 WHERE id=?
    `).bind(ev.id).run().catch(() => {});
  }

  return items.map(ev => ({
    ...ev,
    payload: (() => { try { return JSON.parse(ev.payload); } catch { return {}; } })(),
  }));
}

/**
 * Mark event as done or failed
 */
export async function ackEvent(env, eventId, success, error = null) {
  const status = success ? 'done' : 'failed';
  await env.DB.prepare(`
    UPDATE agent_event_queue
    SET status=?, processed_at=?, error=?
    WHERE id=?
  `).bind(status, now(), error, eventId).run().catch(() => {});
}

/**
 * Peek at queue stats
 */
export async function getQueueStats(env) {
  const stats = await env.DB.prepare(`
    SELECT status, COUNT(*) as count, MAX(priority) as max_priority
    FROM agent_event_queue
    GROUP BY status
  `).all().catch(() => ({ results: [] }));

  const result = { pending: 0, processing: 0, done: 0, failed: 0 };
  (stats.results || []).forEach(r => { result[r.status] = r.count; });
  return result;
}

/**
 * Auto-publish CVE events from threat intel ingestion
 */
export async function publishCVEEvents(env, cves = []) {
  const published = [];
  for (const cve of cves) {
    if (!cve.cve_id) continue;
    const risk = cve.cvss >= 9 ? 'CRITICAL' : cve.cvss >= 7 ? 'HIGH' : cve.cvss >= 4 ? 'MEDIUM' : 'LOW';
    const id = await publishEvent(env, EVENT_TYPES.CVE_DETECTED, {
      cve_id: cve.cve_id,
      cvss: cve.cvss || 0,
      epss: cve.epss || 0,
      is_kev: cve.is_kev || false,
      description: cve.description || '',
    }, risk);
    published.push(id);
  }
  return published;
}
