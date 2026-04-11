@echo off
cd /d C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub\workers
npx wrangler d1 execute cyberdudebivash-security-hub --remote --command "PRAGMA table_info(threat_intel);"
echo ---
npx wrangler d1 execute cyberdudebivash-security-hub --remote --command "SELECT cve_id, severity, cvss_score FROM threat_intel ORDER BY cvss_score DESC LIMIT 5;"
