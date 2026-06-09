"""
CYBERDUDEBIVASH v30.0 -- Complete Route Fix + Deploy Script (v2)
Fixed: Python 3.14 Windows subprocess encoding crash
"""

import os, sys, shutil, subprocess

REPO    = os.path.dirname(os.path.abspath(__file__))
WORKERS = os.path.join(REPO, "workers")
SRC1    = os.path.join(WORKERS, "src")
SRC2    = os.path.join(WORKERS, "workers", "src")

FILE_MAP = [
    (os.path.join(SRC2, "services",  "metricsHydration.js"),
     os.path.join(SRC1, "services",  "metricsHydration.js")),
    (os.path.join(SRC2, "middleware","severityGovernanceGate.js"),
     os.path.join(SRC1, "middleware","severityGovernanceGate.js")),
    (os.path.join(SRC2, "lib",       "scanTokenEngine.js"),
     os.path.join(SRC1, "lib",       "scanTokenEngine.js")),
    (os.path.join(SRC2, "handlers",  "subscriptionPaywallEngine.js"),
     os.path.join(SRC1, "handlers",  "subscriptionPaywallEngine.js")),
]

SCHEMA_DST = os.path.join(WORKERS, "schema_v30_p0p1.sql")

IMPORT_ANCHOR = "import { handleVibeCodeScan, handleVibeCodePatterns } from './handlers/vibe-code/vibeCodeScanner.js';"

IMPORT_BLOCK = """
// -- v30.0 P0/P1 REMEDIATION IMPORTS -----------------------------------------
import { refreshPlatformMetrics, servePlatformMetrics }    from './services/metricsHydration.js';
import { enforceGovernanceBatch, validateIngestPayload, logP0Violation } from './middleware/severityGovernanceGate.js';
import { issueScanToken, verifyScanToken, scanTokenError } from './lib/scanTokenEngine.js';
import {
  gatewayRequestCeiling, applyFreemiumPaywall, handleSubscriptionCheckout,
  handleWebhookStripe, handleGetMyPlan, normalizeTier,
} from './handlers/subscriptionPaywallEngine.js';"""

ROUTE_BLOCK = """
  // -- v30.0: Platform Metrics ------------------------------------------------
  if (path === '/api/platform/metrics') {
    return servePlatformMetrics(request, env);
  }

  // -- v30.0: Scan Token issuance ---------------------------------------------
  if (path === '/api/scan/token') {
    return issueScanToken(request, env);
  }

  // -- v30.0: Subscription Checkout + Plan ------------------------------------
  if (path === '/api/subscription/checkout') {
    return handleSubscriptionCheckout(request, env, authCtx);
  }
  if (path === '/api/subscription/plan' && method === 'GET') {
    return handleGetMyPlan(request, env, authCtx);
  }

"""

CRON_ANCHOR = "ctx.waitUntil(\n      runIngestion(env)"
CRON_BLOCK  = """// -- v30.0: Platform Metrics background hydration ----------------------------
    ctx.waitUntil(
      refreshPlatformMetrics(env)
        .then(r => console.log('[CRON] MetricsHydration:', JSON.stringify(r)))
        .catch(e => console.error('[CRON] MetricsHydration error:', e?.message))
    );

    """

NOT_FOUND_ANCHORS = [
    "    return withSecurityHeaders(withCors(Response.json({\n      error:    'Not Found',",
    "    return withSecurityHeaders(withCors(Response.json({\n      error: 'Not Found',",
]

def run(cmd, cwd=None, label=""):
    """Run a shell command safely on Windows Python 3.14 (no capture, direct output)."""
    print(f"  > {cmd[:80]}")
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            shell=True,
            # Do NOT capture output -- let it print directly to avoid encoding crash
            # We use text=False and let the terminal handle encoding
        )
        return result.returncode
    except Exception as e:
        print(f"  [ERROR] {e}")
        return 1

def run_capture(cmd, cwd=None):
    """Run command capturing output safely with UTF-8 + error replacement."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            shell=True,
            capture_output=True,
            encoding='utf-8',
            errors='replace',
        )
        out = ((result.stdout or '') + (result.stderr or '')).strip()
        if out:
            for line in out.splitlines()[-8:]:
                print(f"    {line}")
        return result.returncode
    except Exception as e:
        print(f"  [ERROR] {e}")
        return 1

def patch_index(idx_path):
    label = os.path.relpath(idx_path, REPO)
    with open(idx_path, 'r', encoding='utf-8-sig') as f:
        c = f.read()
    orig  = c
    changed = []

    # imports
    if 'refreshPlatformMetrics' not in c:
        if IMPORT_ANCHOR in c:
            c = c.replace(IMPORT_ANCHOR, IMPORT_ANCHOR + IMPORT_BLOCK)
            changed.append("imports")
        else:
            print(f"  [WARN] import anchor not found in {label}")

    # routes
    if "'/api/platform/metrics'" not in c:
        inserted = False
        for anchor in NOT_FOUND_ANCHORS:
            if anchor in c:
                c = c.replace(anchor, ROUTE_BLOCK + anchor)
                changed.append("routes")
                inserted = True
                break
        if not inserted:
            idx = c.rfind("return withSecurityHeaders(withCors(Response.json({")
            if idx != -1:
                c = c[:idx] + ROUTE_BLOCK + c[idx:]
                changed.append("routes(rfind)")
            else:
                print(f"  [WARN] route anchor not found in {label}")

    # cron
    if '[CRON] MetricsHydration' not in c:
        if CRON_ANCHOR in c:
            c = c.replace(CRON_ANCHOR, CRON_BLOCK + CRON_ANCHOR)
            changed.append("cron")

    if c != orig:
        with open(idx_path, 'w', encoding='utf-8') as f:
            f.write(c)
        print(f"  [OK] patched {label}: {', '.join(changed)}")
    else:
        print(f"  [SKIP] already fully patched: {label}")

# ── MAIN ──────────────────────────────────────────────────────────────────────

print("=" * 60)
print("CYBERDUDEBIVASH v30.0 Fix + Deploy (v2)")
print("=" * 60)

# Step 1: Copy engine files
print("\n[1] Copying engine files into primary workers/src/ ...")
for src, dst in FILE_MAP:
    if os.path.exists(src):
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        print(f"  [OK] {os.path.basename(src)}")
    elif os.path.exists(dst):
        print(f"  [SKIP] already present: {os.path.basename(dst)}")
    else:
        print(f"  [MISSING] {src}")

# Step 2: Schema
print("\n[2] Schema migration file ...")
if os.path.exists(SCHEMA_DST):
    print(f"  [OK] schema already in workers/")
else:
    print(f"  [MISSING] {SCHEMA_DST}")
    print("  Place schema_v30_p0p1.sql next to this script and re-run")

# Step 3: Patch both index.js
print("\n[3] Patching index.js (both mirrors) ...")
for idx in [os.path.join(SRC1, "index.js"), os.path.join(SRC2, "index.js")]:
    if os.path.exists(idx):
        patch_index(idx)
    else:
        print(f"  [MISSING] {idx}")

# Step 4: D1 migration --remote (direct output, no capture)
print("\n[4] Running D1 schema migration (--remote) ...")
print("    (wrangler output will appear below)")
if os.path.exists(SCHEMA_DST):
    run(
        "npx wrangler d1 execute cyberdudebivash-security-hub "
        "--file=schema_v30_p0p1.sql --remote",
        cwd=WORKERS
    )
else:
    print("  [SKIP] schema file not found")

# Step 5: Git commit and push
print("\n[5] Committing and pushing ...")
os.chdir(WORKERS)
run_capture("git add src/ workers/src/ schema_v30_p0p1.sql -A")
rc = run_capture(
    "git commit -m "
    "\"v30.0.0 fix: engine files in primary src, route dispatch in both index.js mirrors\""
)
if rc == 0:
    run("git push")
    print("\n  [OK] pushed -- GitHub Actions deploying now (~2 min)")
else:
    print("\n  [INFO] nothing new to commit, pushing anyway...")
    run("git push")

print("""
======================================================================
DONE. Wait ~2 min for GitHub Actions, then run:

  curl https://cyberdudebivash.in/api/platform/metrics
  curl -X POST https://cyberdudebivash.in/api/scan/token

Expected:
  /api/platform/metrics  ->  {"success":true,"metrics":{...}}
  /api/scan/token        ->  {"token":"cdb30.xxxxx","expires_in":300}
======================================================================
""")
