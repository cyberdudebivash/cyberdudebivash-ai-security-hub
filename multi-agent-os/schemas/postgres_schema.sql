-- CYBERDUDEBIVASH® Multi-Agent Cybersecurity OS
-- PostgreSQL Schema v1.0 — Production-grade, indexed, auditable
-- Run with: psql $DATABASE_URL -f postgres_schema.sql

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── Tenants ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenants (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name          VARCHAR(255) NOT NULL,
    slug          VARCHAR(100) UNIQUE NOT NULL,
    tier          VARCHAR(50) NOT NULL DEFAULT 'FREE'
                  CHECK (tier IN ('FREE','STARTER','PRO','ENTERPRISE','GLOBAL_ENTERPRISE')),
    status        VARCHAR(20) NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active','suspended','deleted')),
    config        JSONB NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_tenants_slug ON tenants(slug);
CREATE INDEX idx_tenants_tier ON tenants(tier);

-- ─── Users ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email         VARCHAR(320) NOT NULL,
    role          VARCHAR(50) NOT NULL DEFAULT 'analyst'
                  CHECK (role IN ('admin','ciso','analyst','viewer','api_service')),
    tier          VARCHAR(50) NOT NULL DEFAULT 'FREE',
    metadata      JSONB NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    UNIQUE (tenant_id, email)
);
CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_users_email ON users(email);

-- ─── API Keys ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_hash      VARCHAR(128) UNIQUE NOT NULL,  -- SHA-256 of actual key
    tier          VARCHAR(50) NOT NULL DEFAULT 'FREE',
    name          VARCHAR(100),
    last_used_at  TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ,
    revoked       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);

-- ─── Orchestration Sessions ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS orchestration_sessions (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    user_id         UUID REFERENCES users(id),
    intent          VARCHAR(100) NOT NULL,
    agents_invoked  TEXT[] NOT NULL DEFAULT '{}',
    quality_score   DECIMAL(5,2),
    approved        BOOLEAN NOT NULL DEFAULT FALSE,
    total_time_ms   DECIMAL(10,2),
    tokens_used     INTEGER,
    tier            VARCHAR(50),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_sessions_tenant    ON orchestration_sessions(tenant_id);
CREATE INDEX idx_sessions_intent    ON orchestration_sessions(intent);
CREATE INDEX idx_sessions_created   ON orchestration_sessions(created_at DESC);

-- ─── Agent Execution Log ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_audit_log (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      UUID REFERENCES orchestration_sessions(id),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    user_id         UUID REFERENCES users(id),
    agent_name      VARCHAR(100) NOT NULL,
    intent          VARCHAR(100) NOT NULL,
    agents_invoked  TEXT,
    quality_score   DECIMAL(5,2),
    approved        BOOLEAN NOT NULL DEFAULT FALSE,
    elapsed_ms      DECIMAL(10,2),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_tenant   ON agent_audit_log(tenant_id);
CREATE INDEX idx_audit_agent    ON agent_audit_log(agent_name);
CREATE INDEX idx_audit_created  ON agent_audit_log(created_at DESC);

-- ─── Policy Audit ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS policy_audit (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     VARCHAR(255) NOT NULL,
    tenant_id   VARCHAR(255) NOT NULL,
    intent      VARCHAR(100) NOT NULL,
    tier        VARCHAR(50),
    allowed     BOOLEAN NOT NULL,
    reason      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_policy_tenant    ON policy_audit(tenant_id);
CREATE INDEX idx_policy_allowed   ON policy_audit(allowed);
CREATE INDEX idx_policy_created   ON policy_audit(created_at DESC);

-- ─── Intelligence Cache ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS intel_cache (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cache_key   VARCHAR(128) UNIQUE NOT NULL,
    data        JSONB NOT NULL,
    source      VARCHAR(50) NOT NULL,
    tenant_id   UUID REFERENCES tenants(id),
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_intel_cache_key     ON intel_cache(cache_key);
CREATE INDEX idx_intel_cache_expires ON intel_cache(expires_at);

-- ─── Subscriptions / Revenue ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS subscriptions (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      UUID NOT NULL REFERENCES tenants(id) UNIQUE,
    tier           VARCHAR(50) NOT NULL,
    price_usd_mo   DECIMAL(10,2) NOT NULL,
    status         VARCHAR(20) NOT NULL DEFAULT 'active',
    started_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    renews_at      TIMESTAMPTZ,
    cancelled_at   TIMESTAMPTZ,
    payment_provider VARCHAR(50),
    external_sub_id  VARCHAR(255)
);
CREATE INDEX idx_subscriptions_tenant ON subscriptions(tenant_id);
CREATE INDEX idx_subscriptions_status ON subscriptions(status);

-- ─── Knowledge Documents ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS knowledge_documents (
    doc_id      VARCHAR(64) PRIMARY KEY,
    source      VARCHAR(50) NOT NULL,
    title       TEXT NOT NULL,
    content     TEXT NOT NULL,
    metadata    JSONB NOT NULL DEFAULT '{}',
    trust_score DECIMAL(3,2) NOT NULL DEFAULT 0.90,
    freshness   DECIMAL(3,2) NOT NULL DEFAULT 1.00,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_knowledge_source ON knowledge_documents(source);

-- ─── Triggers: auto-update updated_at ───────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenants_updated    BEFORE UPDATE ON tenants    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_knowledge_updated  BEFORE UPDATE ON knowledge_documents FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── Seed: default internal tenant ──────────────────────────────────────────
INSERT INTO tenants (id, name, slug, tier)
VALUES ('00000000-0000-0000-0000-000000000001', 'CYBERDUDEBIVASH Internal', 'cdb-internal', 'GLOBAL_ENTERPRISE')
ON CONFLICT (slug) DO NOTHING;

COMMENT ON DATABASE cdb_macos IS 'CYBERDUDEBIVASH Multi-Agent Cybersecurity OS — v1.0';
