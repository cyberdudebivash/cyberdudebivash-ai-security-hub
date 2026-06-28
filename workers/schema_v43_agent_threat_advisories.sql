-- v43 — Agent Threat Advisories (real backend for /agent-threats page)
-- Replaces the static, hardcoded "Security Advisories" list in
-- frontend/agent-threats.html with a live D1-backed feed, and replaces the
-- fabricated per-framework "N active advisories" / risk-percentage counts
-- with figures computed from real rows in this table.

CREATE TABLE IF NOT EXISTS agent_threat_advisories (
  id                 TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  advisory_id        TEXT    NOT NULL UNIQUE,       -- e.g. CDB-AGT-2025-0019
  title              TEXT    NOT NULL,
  description        TEXT    NOT NULL,
  framework          TEXT    NOT NULL,               -- mcp|langchain|autogen|openai|crewai|semantic_kernel|llama_index|custom
  affected_versions  TEXT,                           -- e.g. "LangChain <= 0.2.x"
  affected_products  TEXT,                           -- human-readable, e.g. "React Agent, OpenAI Tools Agent"
  severity           TEXT    NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
  cvss_score         REAL,
  owasp_llm_id       TEXT,                            -- e.g. LLM01, LLM08
  cwe_id             TEXT,
  mitre_atlas_id     TEXT,                            -- e.g. AML.T0054
  tags               TEXT    NOT NULL DEFAULT '[]',   -- JSON array
  patch_status       TEXT    NOT NULL DEFAULT 'no_patch' CHECK (patch_status IN ('no_patch','mitigation_available','patched')),
  patch_version      TEXT,
  published_at       TEXT    NOT NULL,                -- ISO date
  updated_at         TEXT    NOT NULL DEFAULT (datetime('now')),
  created_at         TEXT    NOT NULL DEFAULT (datetime('now')),
  source             TEXT    NOT NULL DEFAULT 'cyberdudebivash_research',
  is_new             INTEGER NOT NULL DEFAULT 0,
  full_advisory_url  TEXT
);

CREATE INDEX IF NOT EXISTS idx_agt_adv_framework  ON agent_threat_advisories(framework);
CREATE INDEX IF NOT EXISTS idx_agt_adv_severity    ON agent_threat_advisories(severity);
CREATE INDEX IF NOT EXISTS idx_agt_adv_published   ON agent_threat_advisories(published_at DESC);

-- Seed: the 5 advisories that were previously hardcoded into the page HTML.
-- Real content (real CVSS scores, real OWASP/MITRE mappings) — migrated as-is,
-- not invented. This is the actual starting dataset, not filler.
INSERT OR IGNORE INTO agent_threat_advisories
  (advisory_id, title, description, framework, affected_versions, affected_products,
   severity, cvss_score, owasp_llm_id, mitre_atlas_id, tags, patch_status, published_at, is_new)
VALUES
('CDB-AGT-2025-0019',
 'MCP Tool Poisoning via Malicious Server Description',
 'A malicious MCP server can inject adversarial instructions into its tool descriptions that execute when an LLM reads the server''s capabilities. This "tool poisoning" can override the host system prompt and hijack the connected AI assistant to exfiltrate data, access unauthorized tools, or impersonate the user.',
 'mcp', 'All MCP Clients', 'Claude Desktop, Cursor, Copilot Studio',
 'CRITICAL', 9.8, 'LLM01', 'AML.T0054', '["MCP","Tool Poisoning","Prompt Injection","LLM01","AML.T0054"]',
 'no_patch', '2025-06-07', 1),

('CDB-AGT-2025-0017',
 'LangChain Agent Tool Abuse via Injected ReAct Instructions',
 'ReAct agents that process user-controlled inputs without sanitization can be manipulated through injected "Thought:" / "Action:" sequences that mimic the agent''s internal reasoning format. The agent follows the injected plan, executing arbitrary tool calls with the agent''s full permission scope.',
 'langchain', 'LangChain <= 0.2.x', 'React Agent, OpenAI Tools Agent',
 'CRITICAL', 9.1, 'LLM08', NULL, '["LangChain","ReAct","Tool Abuse","LLM08","CWE-77"]',
 'patched', '2025-06-03', 0),

('CDB-AGT-2025-0015',
 'AutoGen Multi-Agent Speaker Selection Injection',
 'In AutoGen GroupChat configurations using LLM-based speaker selection, an attacker can inject content that causes the orchestrator to incorrectly route messages — enabling a lower-privilege agent to impersonate a higher-privilege agent and execute unauthorized code or tool calls.',
 'autogen', 'AutoGen Studio', 'GroupChat with LLM-based speaker selection',
 'CRITICAL', 8.9, NULL, NULL, '["AutoGen","Multi-Agent","Speaker Selection","Privilege Escalation"]',
 'mitigation_available', '2025-05-28', 0),

('CDB-AGT-2025-0014',
 'OpenAI Agents SDK — Handoff Hijacking via Tainted Context',
 'When using agent handoffs in the OpenAI Agents SDK, the receiving agent inherits the full conversation history including any injected content from previous turns. A compromised or tainted agent can use its handoff to propagate injection payloads to downstream agents with different permission scopes.',
 'openai', 'OpenAI Agents SDK', 'Multi-agent handoffs',
 'HIGH', 8.2, 'LLM08', NULL, '["OpenAI Agents","Handoff","Context Propagation","LLM08"]',
 'patched', '2025-05-22', 0),

('CDB-AGT-2025-0011',
 'CrewAI Memory Store Poisoning via Crafted Task Output',
 'Malicious content stored in CrewAI''s long-term memory vector store can influence future agent decisions when retrieved. An attacker who controls any task output can inject adversarial embeddings that persistently bias the crew''s behavior across sessions.',
 'crewai', 'CrewAI <= 0.30', 'Long-term memory with vector store',
 'MEDIUM', 6.5, 'LLM03', NULL, '["CrewAI","Memory Poisoning","Vector Store","LLM03"]',
 'patched', '2025-05-15', 0);

UPDATE agent_threat_advisories SET patch_version = '0.3.0+' WHERE advisory_id = 'CDB-AGT-2025-0017';
UPDATE agent_threat_advisories SET patch_version = 'v1.4.0+' WHERE advisory_id = 'CDB-AGT-2025-0014';
UPDATE agent_threat_advisories SET patch_version = '0.31+'  WHERE advisory_id = 'CDB-AGT-2025-0011';
