# CYBERDUDEBIVASH Platform — Deploy Commands (Session 2026-06-10)

---

## ✅ COMPLETED — AI Engine v9.0 Schema Applied (2026-06-10)

All 10 AI Engine v9.0 tables have been applied to the live D1 database (149 tables total):
`ai_assets`, `ai_findings`, `ai_governance_assessments`, `ai_risk_register`,
`ai_redteam_engagements`, `ai_redteam_attempts`, `ai_agent_inventory`,
`ai_threat_feed`, `ai_service_engagements`, `ai_posture_scores`

Schemas applied: v28 ✅ · v29 ✅ · v30 ✅ · mcp_learning ✅ · revenue_autopilot ✅

---

## 🚀 PENDING — Deploy Worker (wrangler deploy)

The code is committed and pushed. Only the worker deploy remains.
The wrangler OAuth token needs a browser refresh before deploy will work.

**Run these two commands in a terminal (cmd or PowerShell):**

```cmd
cd C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub\workers
npx wrangler login
```
Complete the browser OAuth flow, then immediately run:
```cmd
npx wrangler deploy
```

---

## ~~⚠️ P0 HOTFIX~~ (Already Applied — ignore)

```bash
cd C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub\workers

# Apply AI Engine v9.0 schema (ai_assets, ai_governance_assessments, ai_redteam_*, ai_agent_inventory, ai_threat_feed, etc.)
npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_v28.sql --remote

# Apply remaining schemas (safe — all IF NOT EXISTS)
npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_v29.sql --remote
npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_v30_p0p1.sql --remote
npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_v31_p0_fixes.sql --remote
npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_mcp_learning.sql --remote
npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_revenue_autopilot.sql --remote
```

After running, verify tables exist:
```bash
npx wrangler d1 execute cyberdudebivash-security-hub --remote --command="SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'ai_%' ORDER BY name;"
```
Expected output: `ai_agent_inventory`, `ai_assets`, `ai_findings`, `ai_governance_assessments`, `ai_posture_scores`, `ai_redteam_attempts`, `ai_redteam_engagements`, `ai_risk_register`, `ai_service_engagements`, `ai_threat_feed`

---

The commit is already staged locally. Run these commands in order from your terminal.

---

## 1. Push to GitHub

```bash
cd C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub
git push origin main
```

If prompted, use your GitHub PAT as the password (username: `CYBERDUDEBIVASH`).

Or push with PAT embedded:
```bash
git remote set-url origin https://CYBERDUDEBIVASH:<YOUR_PAT>@github.com/cyberdudebivash/cyberdudebivash-ai-security-hub.git
git push origin main
```

---

## 2. Apply D1 Schema Hotfix (fixes mythos_runs trigger_source column error)

```bash
cd C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub\workers
npx wrangler d1 execute cyberdudebivash-security-hub --file=schema_v32_hotfix.sql --remote
```

---

## 3. Deploy Workers

```bash
cd C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub\workers
npx wrangler deploy
```

---

## What was deployed in this commit

| Area | Change |
|------|--------|
| **MYTHOS AI** | 12-stage pipeline + Sentinel Analytics Rule generator + STIX 2.1 bundle generator |
| **AI Brain V3** | 30+ ATT&CK technique mappings, real exploit probability scoring, flat MITRE array |
| **Frontend** | `safeJson()` envelope unwrap fix (root cause of `undefined%` exploit probability) |
| **CISO Hub V3** | Real D1 metrics, IBM Security ROI, live ROI card in Executive Dashboard |
| **Scan Engine** | Enterprise intelligence wired into domain scan, EPSS scoring |
| **Revenue Engine** | `SECURITY_HUB_KV` binding fix (was `CDB_KV` — all manual payments were broken) |
| **Pricing** | Backend aligned to frontend: STARTER ₹499 · PRO ₹1,499 · ENTERPRISE ₹4,999 |
| **API consistency** | `handleGetPlansV20` + `handleSubscribeV20` wrapped in `ok()` envelope |

---

## Rollback (if needed)

```bash
cd C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub
git revert HEAD --no-edit
git push origin main
cd workers && npx wrangler deploy
```
