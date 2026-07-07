-- =============================================================================
-- CYBERDUDEBIVASH AI Security Hub — Fix: 53 columns missing in production
-- =============================================================================
-- Generated after a two-stage audit of the nightly D1 Schema Drift Check's
-- column-drift findings (29 tables, 2026-07-07): first, which columns the
-- reference schema defines that production lacks; second, a general-purpose
-- agent checked EVERY one of those columns against actual usage in
-- workers/src/ — SQL context only (.prepare() calls, template-literal SQL,
-- CREATE INDEX, ON CONFLICT targets), not just a name match — to separate
-- genuinely live-code-dependent columns from dead/aspirational schema.
--
-- Standout finding: workers/src/services/funnelEngine.js:85-87 already
-- contains a comment proving a prior engineer discovered production's
-- `leads` table was missing name/source/funnel_stage and partially patched
-- around it in one function — three OTHER files still assume those columns
-- exist directly. Same bug class as the 21-missing-table fix (renewal_queue
-- etc.), just column-level instead of table-level. `proposals` (all 14 of
-- its columns) is the largest single blast radius: the entire enterprise
-- proposal generate/view/send/accept/reject flow, routed at POST
-- /api/proposals, with no .catch() at the query level — a missing column
-- there is a hard 500, not a silent degrade. `api_keys` (org_id, status) is
-- similarly a hard-500 case for the whole Developer Portal API-key feature.
--
-- Nine columns (api_usage_log.email/logged_at, proposals.deal_id,
-- report_access.report_id, revenue_snapshots.org_id/period/snapshot_date,
-- threat_intel.solution_generated/threat_class) aren't defined in
-- schema_master.sql at all — they exist only as untyped "healed" columns in
-- schema_bootstrap.sql (lab-bootstrap-d1.mjs's --heal mechanism bolts on a
-- bare, typeless ALTER TABLE ADD COLUMN whenever a later CREATE INDEX
-- references a column no CREATE TABLE defined, just to keep replaying).
-- Their real, well-typed definitions were traced to the specific historical
-- migration file that originally introduced each one (schema_gtm_only.sql,
-- schema_v23_migrate.sql, schema_v39_marketplace.sql, schema_phase2.sql,
-- schema_phase4.sql, schema_v40_godmode_intel_columns.sql — the last of
-- which is a complete, ready-made, already-correct ALTER TABLE pair that
-- was apparently written and committed but never applied).
--
-- Every NOT NULL from a source file was re-checked for a paired DEFAULT —
-- SQLite refuses to ADD COLUMN NOT NULL without one on a table that may
-- already have rows. Two were dropped to plain nullable columns where the
-- source definition assumed CREATE-time (fresh table), not retrofit-time,
-- semantics: email_sequences.sequence_id and report_access.report_id.
--
-- Separately, empirically confirmed: SQLite refuses ADD COLUMN with ANY
-- non-constant default (datetime('now'), or any function call) on a table
-- that already has rows — regardless of NOT NULL. Every one of these 16
-- tables is actively written by live code today (that's why they need this
-- fix), so none can be assumed empty. Four columns that copied a source
-- file's `DEFAULT (datetime('now'))` verbatim were changed to plain
-- nullable columns with no default: analytics_events.occurred_at,
-- api_usage_log.logged_at, email_sequences.enrolled_at,
-- scan_history.created_at. Existing rows get NULL for these — correct,
-- since they genuinely have no historical value for a column that didn't
-- exist yet.
-- report_access.report_id specifically: schema_v39_marketplace.sql's
-- report_access design (user_id/report_id/order_id/granted_via) is a
-- different, never-actually-deployed competing shape from what's actually
-- live (schema_bootstrap.sql's token/module/r2_key/expires_at design, the
-- one workers/src/handlers/payments.js writes) — only report_id itself,
-- confirmed used in a JOIN by workers/src/handlers/secureDownload.js:419,
-- is added here; the rest of that competing design is not.
--
-- revenue_snapshots needed more than ADD COLUMN: workers/src/handlers/
-- revenueMetrics.js:209 does `INSERT ... ON CONFLICT(period) DO UPDATE`,
-- and revenueIntelligence.js:83 does `ON CONFLICT(org_id, snapshot_date)
-- DO UPDATE` — both require a UNIQUE constraint SQLite doesn't infer from
-- a bare column add. Adding CREATE UNIQUE INDEX after the ADD COLUMN is
-- safe even with existing rows: every existing row gets NULL for the new
-- column(s), and SQL treats NULL as never equal to NULL for uniqueness
-- purposes, so a fresh UNIQUE index over all-NULL (or partially-NULL)
-- existing values cannot violate the constraint.
--
-- Deliberately EXCLUDES columns confirmed dead by the same audit — adding
-- unused columns is schema clutter with no offsetting benefit:
--   alert_log (alert_type, component — belong to a separate, already-
--     documented ops_alert_log table), cti_actors (active_since — only in
--     static hardcoded APT-profile data), defense_purchases (all 6 — code
--     uses differently-named columns), defense_solutions (badge — always
--     computed from a static lookup), mythos_runs (error_message),
--     scan_jobs (error/result/updated_at — despite 21 files using this
--     table, none use these 3; scan results live in R2, not D1), and the
--     non-real subsets of crm_leads/cti_iocs/mssp_clients (7/3/5 columns
--     respectively — code there consistently uses differently-named
--     columns for the same concepts).
--
-- Also NOT fixed here (separate, distinct bug — not a missing-column
-- issue): workers/src/handlers/secureDownload.js:487 references
-- report_access.download_count/last_downloaded, but the real (both live
-- and reference-agreed) column names are downloaded_count/
-- last_downloaded_at — a naming-mismatch bug in the code itself, not
-- something a schema migration can safely paper over without guessing
-- intent. Flagged for a follow-up, not touched.
--
-- Verified by reconstructing every target table in its exact current
-- (incomplete) production shape — sourced from schema_bootstrap.sql itself,
-- not an empty database — and confirming every ALTER/CREATE INDEX statement
-- applies with zero errors. See verify-column-fix.mjs in the same session.
-- =============================================================================

-- analytics_events.ip_country
ALTER TABLE analytics_events ADD COLUMN ip_country     TEXT;

-- analytics_events.occurred_at (NOT NULL + non-constant default dropped —
-- SQLite refuses ADD COLUMN with a non-constant default on a non-empty
-- table, confirmed empirically; see header)
ALTER TABLE analytics_events ADD COLUMN occurred_at    TEXT;

-- analytics_events.org_id
ALTER TABLE analytics_events ADD COLUMN org_id         TEXT DEFAULT 'default';

-- analytics_events.properties_json
ALTER TABLE analytics_events ADD COLUMN properties_json TEXT DEFAULT '{}';

-- analytics_events.session_id
ALTER TABLE analytics_events ADD COLUMN session_id     TEXT;

-- analytics_events.tier
ALTER TABLE analytics_events ADD COLUMN tier           TEXT DEFAULT 'FREE';

-- api_keys.org_id
ALTER TABLE api_keys ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';

-- api_keys.status
ALTER TABLE api_keys ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE';

-- api_usage_log.email (schema_gtm_only.sql)
ALTER TABLE api_usage_log ADD COLUMN email TEXT;

-- api_usage_log.logged_at (schema_gtm_only.sql; non-constant default dropped — see header)
ALTER TABLE api_usage_log ADD COLUMN logged_at TEXT;

-- crm_leads.icp_tier
ALTER TABLE crm_leads ADD COLUMN icp_tier TEXT NOT NULL DEFAULT 'D';

-- crm_leads.notes
ALTER TABLE crm_leads ADD COLUMN notes TEXT;

-- crm_leads.status
ALTER TABLE crm_leads ADD COLUMN status TEXT NOT NULL DEFAULT 'new';

-- cti_iocs.confidence
ALTER TABLE cti_iocs ADD COLUMN confidence       INTEGER DEFAULT 50;

-- cti_iocs.false_positive
ALTER TABLE cti_iocs ADD COLUMN false_positive   INTEGER DEFAULT 0;

-- email_sequences.current_step
ALTER TABLE email_sequences ADD COLUMN current_step    INTEGER DEFAULT 0;

-- email_sequences.enrolled_at (non-constant default dropped — see header)
ALTER TABLE email_sequences ADD COLUMN enrolled_at     TEXT;

-- email_sequences.last_sent_at
ALTER TABLE email_sequences ADD COLUMN last_sent_at    TEXT;

-- email_sequences.meta
ALTER TABLE email_sequences ADD COLUMN meta            TEXT DEFAULT '{}';

-- email_sequences.sequence_id (NOT NULL dropped — no safe default for a retrofit; see header)
ALTER TABLE email_sequences ADD COLUMN sequence_id     TEXT;

-- funnel_events.meta
ALTER TABLE funnel_events ADD COLUMN meta        TEXT DEFAULT '{}';

-- leads.converted_at
ALTER TABLE leads ADD COLUMN converted_at    TEXT;

-- leads.funnel_stage
ALTER TABLE leads ADD COLUMN funnel_stage    TEXT DEFAULT 'visitor';

-- leads.name
ALTER TABLE leads ADD COLUMN name            TEXT;

-- leads.scan_count
ALTER TABLE leads ADD COLUMN scan_count      INTEGER DEFAULT 0;

-- leads.source
ALTER TABLE leads ADD COLUMN source          TEXT DEFAULT 'scan';

-- mssp_clients.open_alerts
ALTER TABLE mssp_clients ADD COLUMN open_alerts INTEGER NOT NULL DEFAULT 0;

-- mssp_customers.partner_id
ALTER TABLE mssp_customers ADD COLUMN partner_id       TEXT;

-- proposals.accepted_at
ALTER TABLE proposals ADD COLUMN accepted_at INTEGER;

-- proposals.company
ALTER TABLE proposals ADD COLUMN company TEXT NOT NULL DEFAULT '';

-- proposals.contact_email
ALTER TABLE proposals ADD COLUMN contact_email TEXT;

-- proposals.deal_id (schema_v23_migrate.sql)
ALTER TABLE proposals ADD COLUMN deal_id TEXT;

-- proposals.gst_inr
ALTER TABLE proposals ADD COLUMN gst_inr REAL NOT NULL DEFAULT 0;

-- proposals.html_content
ALTER TABLE proposals ADD COLUMN html_content TEXT;

-- proposals.metadata
ALTER TABLE proposals ADD COLUMN metadata TEXT DEFAULT '{}';

-- proposals.opportunity_id
ALTER TABLE proposals ADD COLUMN opportunity_id TEXT;

-- proposals.org_size
ALTER TABLE proposals ADD COLUMN org_size TEXT;

-- proposals.package
ALTER TABLE proposals ADD COLUMN package TEXT NOT NULL DEFAULT '';

-- proposals.sector
ALTER TABLE proposals ADD COLUMN sector TEXT;

-- proposals.total_inr
ALTER TABLE proposals ADD COLUMN total_inr REAL NOT NULL DEFAULT 0;

-- proposals.type
ALTER TABLE proposals ADD COLUMN type TEXT NOT NULL DEFAULT 'enterprise';

-- proposals.viewed_at
ALTER TABLE proposals ADD COLUMN viewed_at INTEGER;

-- report_access.report_id (NOT NULL dropped — see header; schema_v39_marketplace.sql's
-- NOT NULL assumed a different, never-deployed table design)
ALTER TABLE report_access ADD COLUMN report_id TEXT;

-- revenue_snapshots.org_id (schema_phase4.sql)
ALTER TABLE revenue_snapshots ADD COLUMN org_id TEXT DEFAULT 'default';

-- revenue_snapshots.period (schema_phase2.sql; NOT NULL dropped — see header)
ALTER TABLE revenue_snapshots ADD COLUMN period TEXT;

-- revenue_snapshots.snapshot_date (schema_phase4.sql; NOT NULL dropped — see header)
ALTER TABLE revenue_snapshots ADD COLUMN snapshot_date TEXT;

-- revenue_snapshots: UNIQUE indexes required by ON CONFLICT targets in
-- revenueMetrics.js (period) and revenueIntelligence.js (org_id, snapshot_date) —
-- safe on existing rows because every pre-existing row now has NULL for these
-- new columns, and SQL never treats NULL as equal to NULL for uniqueness.
CREATE UNIQUE INDEX IF NOT EXISTS idx_snapshots_period ON revenue_snapshots(period);
CREATE UNIQUE INDEX IF NOT EXISTS idx_revenue_snapshots_org_date ON revenue_snapshots(org_id, snapshot_date);

-- sales_outreach.body
ALTER TABLE sales_outreach ADD COLUMN body            TEXT;

-- sales_outreach.outreach_type
ALTER TABLE sales_outreach ADD COLUMN outreach_type   TEXT;

-- sales_outreach.sent_at
ALTER TABLE sales_outreach ADD COLUMN sent_at         TEXT;

-- sales_outreach.subject
ALTER TABLE sales_outreach ADD COLUMN subject         TEXT;

-- scan_history.created_at (NOT NULL + non-constant default dropped — see header)
ALTER TABLE scan_history ADD COLUMN created_at  TEXT;

-- threat_intel.threat_class (schema_v40_godmode_intel_columns.sql — pre-written, never applied)
ALTER TABLE threat_intel ADD COLUMN threat_class TEXT;

-- threat_intel.solution_generated (schema_v40_godmode_intel_columns.sql — pre-written, never applied)
ALTER TABLE threat_intel ADD COLUMN solution_generated INTEGER DEFAULT 0;
