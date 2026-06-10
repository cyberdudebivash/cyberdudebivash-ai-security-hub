# CYBERDUDEBIVASH Platform — Deploy Commands (Session 2026-06-10)

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
