-- ============================================================================
-- CYBERDUDEBIVASH AI Security Hub — RC-1 Production Schema Sync
-- Run ONCE against the live D1 database:
--   cd workers && npx wrangler d1 execute cyberdudebivash-security-hub --remote --file=../workers/schema_migration_rc1.sql
-- OR from project root:
--   npx wrangler d1 execute cyberdudebivash-security-hub --remote --file=./workers/schema_migration_rc1.sql
--
-- What this does NOT fix (already correct in live D1):
--   - users.tier CHECK  — live DB already includes STARTER, MSSP
--   - subscriptions.id  — live DB already uses TEXT PRIMARY KEY
--   - api_keys schema   — live DB already has user_id, key_hash, key_prefix
--
-- What this DOES fix:
--   - schema_master.sql SSOT alignment (for new environment provisioning)
--   - Duplicate subscription indexes (idempotent, no data risk)
--
-- Root cause of subscriptions INSERT failure (payments.js v2 fix):
--   payments.js was inserting columns (processor, external_id, activated_at,
--   expires_at) that do NOT exist in the live subscriptions table. Those
--   inserts silently failed — subscription records were never written despite
--   successful Razorpay payments. Fix: payments.js rewritten to use the correct
--   column list matching the live schema. No schema migration needed for this fix.
-- ============================================================================

-- Idempotent index deduplication (safe: IF NOT EXISTS guards each)
CREATE INDEX IF NOT EXISTS idx_sub_id        ON subscriptions(id);
CREATE INDEX IF NOT EXISTS idx_sub_user_id   ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_sub_email     ON subscriptions(email);
CREATE INDEX IF NOT EXISTS idx_sub_plan      ON subscriptions(plan);
CREATE INDEX IF NOT EXISTS idx_sub_status    ON subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_sub_expires   ON subscriptions(current_period_end);
CREATE INDEX IF NOT EXISTS idx_sub_created   ON subscriptions(created_at DESC);

-- Verification: confirm both tables have correct structure
-- Run manually to check:
-- SELECT name, sql FROM sqlite_master WHERE name IN ('users','subscriptions','api_keys','payments');
-- SELECT COUNT(*) FROM users;
-- SELECT COUNT(*) FROM subscriptions;
-- SELECT COUNT(*) FROM payments WHERE status = 'paid';
