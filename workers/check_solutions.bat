@echo off
cd /d C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub\workers
npx wrangler d1 execute cyberdudebivash-security-hub --remote --command "SELECT COUNT(*) as count FROM defense_solutions;"
echo ---
npx wrangler d1 execute cyberdudebivash-security-hub --remote --command "SELECT id, cve_id, tool_type, price_inr, created_at FROM defense_solutions ORDER BY created_at DESC LIMIT 10;"
