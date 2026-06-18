-- ════════════════════════════════════════════════════════════════════════════
-- schema_v42 — Referral / affiliate attribution (real UTM+ref tracking)
-- Additive only. Links a lead's email to the affiliate ref_code that brought
-- them in, using first-touch attribution (INSERT OR IGNORE — the first ref_code
-- recorded for an email wins; later captures never overwrite it).
-- triggerPostPurchase reads this table at confirmed-payment time to credit the
-- referring affiliate via recordReferralConversion (workers/src/handlers/affiliateSystem.js).
-- Idempotent: CREATE TABLE/INDEX use IF NOT EXISTS.
-- ════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS referral_attribution (
  email          TEXT PRIMARY KEY,
  ref_code       TEXT NOT NULL,
  source         TEXT DEFAULT 'lead_capture',
  attributed_at  TEXT NOT NULL,
  converted      INTEGER DEFAULT 0,
  converted_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_referral_attribution_ref_code ON referral_attribution(ref_code);
