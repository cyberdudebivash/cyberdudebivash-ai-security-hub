@echo off
cd /d C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub\workers
npx wrangler d1 execute cyberdudebivash-security-hub --remote --command "SELECT id, cve_id, category, title, price_inr, severity, is_active, created_at FROM defense_solutions ORDER BY created_at DESC LIMIT 10;"
echo EXIT=%ERRORLEVEL%
