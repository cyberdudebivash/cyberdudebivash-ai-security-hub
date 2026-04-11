@echo off
cd /d C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub\workers
echo Clearing mythos:status KV key...
npx wrangler kv key put "mythos:status" "{\"is_running\":false,\"current_job\":null,\"cleared_at\":\"%DATE% %TIME%\"}" --namespace-id 95faae90943f43afa26d552b8385d339 --remote
echo EXIT=%ERRORLEVEL%
