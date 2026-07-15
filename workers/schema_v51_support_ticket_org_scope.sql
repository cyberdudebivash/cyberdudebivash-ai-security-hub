-- CYBERDUDEBIVASH® AI Security Hub
-- v51 — Support Ticket System: org scoping + comment thread (CAP-PORTAL-004)
-- Apply: wrangler d1 execute cyberdudebivash-security-hub --remote --file schema_v51_support_ticket_org_scope.sql
--
-- Backs the customer-facing Support Ticket UI (Customer Lifecycle Completion
-- Program, Phase 3). Adds organization scoping to the existing support_tickets
-- table (workers/schema_master.sql) and a new comment thread table.
--
-- NOTE: D1 does not support "ALTER TABLE ... ADD COLUMN IF NOT EXISTS" — the
-- ALTER statement below is safe to run exactly once against a database that
-- already has support_tickets (schema_master.sql applies first). Re-running
-- this file against a database where it already succeeded will error on the
-- ALTER (column already exists) — same convention as schema_v31_p0_fixes.sql.
-- The CREATE TABLE / CREATE INDEX statements are idempotent (IF NOT EXISTS).

ALTER TABLE support_tickets ADD COLUMN organization_id TEXT;

CREATE INDEX IF NOT EXISTS idx_support_tickets_org ON support_tickets(organization_id);

CREATE TABLE IF NOT EXISTS support_ticket_comments (
  id              TEXT PRIMARY KEY,
  ticket_id       TEXT NOT NULL,
  author_user_id  TEXT NOT NULL,
  is_staff        INTEGER NOT NULL DEFAULT 0,
  body            TEXT NOT NULL,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_support_ticket_comments_ticket   ON support_ticket_comments(ticket_id);
CREATE INDEX IF NOT EXISTS idx_support_ticket_comments_created  ON support_ticket_comments(created_at);
