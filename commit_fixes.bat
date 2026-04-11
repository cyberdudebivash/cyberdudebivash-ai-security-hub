@echo off
cd /d C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub
git add workers/src/services/mythosOrchestrator.js workers/src/services/intelIngestionEngine.js
git commit -m "fix: MYTHOS pipeline — attempts variable, D1 column names (cvss/id), correct JSON field mapping"
git push origin main
echo EXIT=%ERRORLEVEL%
