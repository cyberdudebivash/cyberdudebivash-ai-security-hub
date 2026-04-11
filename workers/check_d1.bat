@echo off
cd /d C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub\workers
npx wrangler d1 execute cyberdudebivash-security-hub --remote --command "SELECT cve_id, severity, solution_generated, cvss_score FROM threat_intel WHERE severity IN ('CRITICAL','HIGH') AND solution_generated = 0 LIMIT 5;"
echo ---
npx wrangler d1 execute cyberdudebivash-security-hub --remote --command "SELECT COUNT(*) as total, SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical, SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high, SUM(CASE WHEN solution_generated=1 THEN 1 ELSE 0 END) as solved FROM threat_intel;"
echo EXIT=%ERRORLEVEL%
