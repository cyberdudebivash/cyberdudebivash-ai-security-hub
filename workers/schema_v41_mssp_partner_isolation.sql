-- ════════════════════════════════════════════════════════════════════════════
-- schema_v41 — MSSP per-partner tenant isolation (P0 #1)
-- Additive only. Adds an owner column so every msspWorkspace query can be
-- scoped to the calling partner, closing the cross-partner data-leak path.
-- Idempotent: ADD COLUMN is wrapped with `|| true` by the migration job; the
-- index uses IF NOT EXISTS.
-- ════════════════════════════════════════════════════════════════════════════

ALTER TABLE mssp_customers ADD COLUMN partner_id TEXT;
CREATE INDEX IF NOT EXISTS idx_mssp_customers_partner ON mssp_customers(partner_id);
