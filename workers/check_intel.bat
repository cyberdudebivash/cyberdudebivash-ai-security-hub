@echo off
cd /d C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub\workers
npx wrangler d1 execute cyberdudebivash-security-hub --remote --command "SELECT id, cve_id, severity, cvss FROM threat_intel WHERE severity IN ('CRITICAL','HIGH') ORDER BY cvss DESC LIMIT 8;"
