@echo off
cd /d C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub\workers
echo Adding product_id column...
npx wrangler d1 execute cyberdudebivash-security-hub --remote --command "ALTER TABLE threat_intel ADD COLUMN product_id TEXT;"
echo Verifying...
npx wrangler d1 execute cyberdudebivash-security-hub --remote --command "SELECT cve_id, severity, cvss, solution_generated FROM threat_intel WHERE severity IN ('CRITICAL','HIGH') ORDER BY cvss DESC LIMIT 5;"
echo EXIT=%ERRORLEVEL%
