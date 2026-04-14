-- ============================================================
-- CYBERDUDEBIVASH AI Security Hub — Schema v10.0
-- Sentinel APEX Defense Solutions + Revenue Snapshots
-- ============================================================

-- Defense Solutions Marketplace
CREATE TABLE IF NOT EXISTS defense_solutions (
  id                TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  cve_id            TEXT NOT NULL,
  title             TEXT NOT NULL,
  description       TEXT NOT NULL,
  category          TEXT NOT NULL CHECK(category IN (
    'firewall_script','ids_signature','sigma_rule','yara_rule',
    'ir_playbook','hardening_script','threat_hunt_pack',
    'python_scanner','exec_briefing','api_module'
  )),
  price_inr         INTEGER NOT NULL DEFAULT 499,
  price_usd         INTEGER NOT NULL DEFAULT 6,
  demand_score      REAL NOT NULL DEFAULT 0.5,
  severity          TEXT NOT NULL DEFAULT 'MEDIUM' CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
  cvss_score        REAL,
  preview           TEXT NOT NULL,
  full_content_key  TEXT NOT NULL,
  difficulty        TEXT NOT NULL DEFAULT 'INTERMEDIATE' CHECK(difficulty IN ('BEGINNER','INTERMEDIATE','ADVANCED','EXPERT')),
  apt_groups        TEXT,
  mitre_techniques  TEXT,
  affected_systems  TEXT,
  purchase_count    INTEGER NOT NULL DEFAULT 0,
  view_count        INTEGER NOT NULL DEFAULT 0,
  is_featured       INTEGER NOT NULL DEFAULT 0,
  is_active         INTEGER NOT NULL DEFAULT 1,
  generated_at      TEXT NOT NULL DEFAULT (datetime('now')),
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_defense_solutions_cve ON defense_solutions(cve_id);
CREATE INDEX IF NOT EXISTS idx_defense_solutions_category ON defense_solutions(category);
CREATE INDEX IF NOT EXISTS idx_defense_solutions_severity ON defense_solutions(severity);
CREATE INDEX IF NOT EXISTS idx_defense_solutions_featured ON defense_solutions(is_featured) WHERE is_featured = 1;
CREATE INDEX IF NOT EXISTS idx_defense_solutions_demand ON defense_solutions(demand_score DESC);
CREATE INDEX IF NOT EXISTS idx_defense_solutions_created ON defense_solutions(created_at DESC);

-- Defense Solution Purchases
CREATE TABLE IF NOT EXISTS defense_purchases (
  id                TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  solution_id       TEXT NOT NULL REFERENCES defense_solutions(id),
  user_id           TEXT,
  email             TEXT,
  razorpay_order_id TEXT,
  razorpay_payment_id TEXT,
  amount_inr        INTEGER NOT NULL,
  amount_usd        INTEGER,
  currency          TEXT NOT NULL DEFAULT 'INR',
  status            TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid','failed','refunded')),
  access_key        TEXT,
  access_expires_at TEXT,
  ip_country        TEXT,
  created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_defense_purchases_solution ON defense_purchases(solution_id);
CREATE INDEX IF NOT EXISTS idx_defense_purchases_user ON defense_purchases(user_id);
CREATE INDEX IF NOT EXISTS idx_defense_purchases_status ON defense_purchases(status);
CREATE INDEX IF NOT EXISTS idx_defense_purchases_created ON defense_purchases(created_at DESC);

-- Revenue Snapshots (for trend charts)
CREATE TABLE IF NOT EXISTS revenue_snapshots (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  snapshot_date   TEXT NOT NULL UNIQUE,
  mrr_inr         REAL NOT NULL DEFAULT 0,
  arr_inr         REAL NOT NULL DEFAULT 0,
  daily_revenue   REAL NOT NULL DEFAULT 0,
  subscriptions   INTEGER NOT NULL DEFAULT 0,
  new_subs        INTEGER NOT NULL DEFAULT 0,
  churned_subs    INTEGER NOT NULL DEFAULT 0,
  defense_sales   INTEGER NOT NULL DEFAULT 0,
  defense_revenue REAL NOT NULL DEFAULT 0,
  api_revenue     REAL NOT NULL DEFAULT 0,
  affiliate_rev   REAL NOT NULL DEFAULT 0,
  adsense_rev     REAL NOT NULL DEFAULT 0,
  enterprise_rev  REAL NOT NULL DEFAULT 0,
  total_users     INTEGER NOT NULL DEFAULT 0,
  active_users    INTEGER NOT NULL DEFAULT 0,
  free_users      INTEGER NOT NULL DEFAULT 0,
  paid_users      INTEGER NOT NULL DEFAULT 0,
  total_scans     INTEGER NOT NULL DEFAULT 0,
  conversion_rate REAL NOT NULL DEFAULT 0,
  arpu            REAL NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_revenue_snapshots_date ON revenue_snapshots(snapshot_date DESC);

-- Enterprise Consultation Leads
CREATE TABLE IF NOT EXISTS enterprise_leads (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  company_name    TEXT NOT NULL,
  contact_name    TEXT,
  email           TEXT NOT NULL,
  phone           TEXT,
  domain          TEXT,
  requirements    TEXT,
  package_interest TEXT DEFAULT 'enterprise',
  team_size       TEXT,
  industry        TEXT,
  annual_budget   TEXT,
  urgency         TEXT DEFAULT 'normal' CHECK(urgency IN ('immediate','urgent','normal','exploratory')),
  source          TEXT DEFAULT 'website',
  status          TEXT DEFAULT 'new' CHECK(status IN ('new','contacted','qualified','proposal','closed_won','closed_lost')),
  notes           TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_enterprise_leads_email ON enterprise_leads(email);
CREATE INDEX IF NOT EXISTS idx_enterprise_leads_status ON enterprise_leads(status);
CREATE INDEX IF NOT EXISTS idx_enterprise_leads_created ON enterprise_leads(created_at DESC);

-- Custom Solution Requests
CREATE TABLE IF NOT EXISTS custom_solution_requests (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id         TEXT,
  email           TEXT NOT NULL,
  cve_id          TEXT,
  solution_types  TEXT,
  tech_stack      TEXT,
  description     TEXT NOT NULL,
  budget_range    TEXT,
  deadline        TEXT,
  status          TEXT DEFAULT 'pending' CHECK(status IN ('pending','reviewing','quoted','in_progress','delivered','closed')),
  quote_inr       INTEGER,
  quote_usd       INTEGER,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_custom_requests_email ON custom_solution_requests(email);
CREATE INDEX IF NOT EXISTS idx_custom_requests_status ON custom_solution_requests(status);

-- Blog Posts (for content automation pipeline)
CREATE TABLE IF NOT EXISTS blog_posts (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  cve_id          TEXT,
  slug            TEXT NOT NULL UNIQUE,
  title           TEXT NOT NULL,
  excerpt         TEXT,
  content         TEXT NOT NULL,
  html_content    TEXT,
  author          TEXT DEFAULT 'CYBERDUDEBIVASH AI',
  tags            TEXT,
  category        TEXT,
  seo_title       TEXT,
  seo_description TEXT,
  seo_keywords    TEXT,
  featured_image  TEXT,
  status          TEXT DEFAULT 'draft' CHECK(status IN ('draft','published','archived')),
  published_at    TEXT,
  linkedin_posted INTEGER DEFAULT 0,
  telegram_posted INTEGER DEFAULT 0,
  twitter_posted  INTEGER DEFAULT 0,
  views           INTEGER DEFAULT 0,
  solution_cta    TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_blog_posts_cve ON blog_posts(cve_id);
CREATE INDEX IF NOT EXISTS idx_blog_posts_slug ON blog_posts(slug);
CREATE INDEX IF NOT EXISTS idx_blog_posts_status ON blog_posts(status);
CREATE INDEX IF NOT EXISTS idx_blog_posts_published ON blog_posts(published_at DESC);

-- FOMO / Social Proof counters
CREATE TABLE IF NOT EXISTS fomo_events (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  event_type      TEXT NOT NULL CHECK(event_type IN ('purchase','scan','view','download','signup','upgrade')),
  entity_type     TEXT,
  entity_id       TEXT,
  display_name    TEXT,
  ip_country      TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_fomo_events_type ON fomo_events(event_type);
CREATE INDEX IF NOT EXISTS idx_fomo_events_created ON fomo_events(created_at DESC);

-- ============================================================
-- D1 binding: SECURITY_HUB_DB (same as existing)
-- KV binding: SECURITY_HUB_KV (same as existing)
-- R2 binding: SECURITY_HUB_R2 (for large content storage)
-- ============================================================
