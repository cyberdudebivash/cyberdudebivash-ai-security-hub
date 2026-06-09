"""
CYBERDUDEBIVASH AI Security Hub — v30.0 P0/P1 Auto-Deploy Script
Run from: C:\\Users\\Administrator\\Desktop\\cyberdudebivash-ai-security-hub\\

Usage:
    python deploy_v30_p0p1.py

What it does:
  1. Copies 4 new engine files to both workers/src/* and workers/workers/src/*
  2. Patches workers/src/index.js and workers/workers/src/index.js
  3. Patches workers/src/services/threatIngestion.js (governance gate)
  4. Confirms the schema migration SQL is ready at workers/schema_v30_p0p1.sql
  5. Prints the exact npx wrangler commands to run next
"""

import os
import shutil
import re
import sys

REPO = os.path.dirname(os.path.abspath(__file__))
SRC1 = os.path.join(REPO, "workers", "src")
SRC2 = os.path.join(REPO, "workers", "workers", "src")
OUTPUT_DIR = os.path.join(REPO, "output_v30")

# ── Determine output dir (where this script was called from)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Map: source file → destination relative to src root
FILE_MAP = {
    "metricsHydration.js":           ("services", "metricsHydration.js"),
    "severityGovernanceGate.js":     ("middleware", "severityGovernanceGate.js"),
    "scanTokenEngine.js":            ("lib", "scanTokenEngine.js"),
    "subscriptionPaywallEngine.js":  ("handlers", "subscriptionPaywallEngine.js"),
}

SCHEMA_SRC = os.path.join(SCRIPT_DIR, "schema_v30_p0p1.sql")
SCHEMA_DST = os.path.join(REPO, "workers", "schema_v30_p0p1.sql")

def copy_engine_files():
    print("\n[1] Copying engine files...")
    for fname, (subdir, dest_name) in FILE_MAP.items():
        src = os.path.join(SCRIPT_DIR, fname)
        if not os.path.exists(src):
            print(f"  SKIP (not found): {src}")
            continue
        for root in [SRC1, SRC2]:
            dst_dir = os.path.join(root, subdir)
            os.makedirs(dst_dir, exist_ok=True)
            dst = os.path.join(dst_dir, dest_name)
            shutil.copy2(src, dst)
            print(f"  COPY {fname} -> {dst}")

def copy_schema():
    print("\n[2] Copying schema migration...")
    src = os.path.join(SCRIPT_DIR, "schema_v30_p0p1.sql")
    if not os.path.exists(src):
        print(f"  SKIP (not found): {src}")
        return
    shutil.copy2(src, SCHEMA_DST)
    print(f"  COPY schema_v30_p0p1.sql -> {SCHEMA_DST}")

def patch_index(index_path):
    if not os.path.exists(index_path):
        print(f"  SKIP (not found): {index_path}")
        return False

    with open(index_path, "r", encoding="utf-8-sig") as f:
        content = f.read()

    modified = content

    # ── A: Import block ──────────────────────────────────────────────────────
    IMPORT_MARKER = "// ── v29 NEW SCANNER IMPORTS"
    IMPORT_BLOCK = (
        "\n// ── v30.0 P0/P1 REMEDIATION IMPORTS ────────────────────────────────────────\n"
        "import { refreshPlatformMetrics, servePlatformMetrics }    from './services/metricsHydration.js';\n"
        "import { enforceGovernanceBatch, validateIngestPayload, logP0Violation } from './middleware/severityGovernanceGate.js';\n"
        "import { issueScanToken, verifyScanToken, scanTokenError } from './lib/scanTokenEngine.js';\n"
        "import {\n"
        "  gatewayRequestCeiling, applyFreemiumPaywall, handleSubscriptionCheckout,\n"
        "  handleWebhookStripe, handleGetMyPlan, normalizeTier,\n"
        "} from './handlers/subscriptionPaywallEngine.js';\n\n"
    )

    if "refreshPlatformMetrics" not in modified:
        if IMPORT_MARKER in modified:
            modified = modified.replace(IMPORT_MARKER, IMPORT_BLOCK + IMPORT_MARKER)
            print(f"  PATCH import block: {index_path}")
        else:
            print(f"  WARN: import marker not found in {index_path} — import block NOT applied")

    # ── B: Route additions ───────────────────────────────────────────────────
    ROUTE_MARKER = "// ── Health check endpoint"
    ROUTE_BLOCK = (
        "// ── v30.0 Metrics, Scan Token, Subscription ────────────────────────────────\n"
        "    if (path === '/api/platform/metrics') return servePlatformMetrics(request, env);\n"
        "    if (path === '/api/scan/token') return issueScanToken(request, env);\n"
        "    if (path === '/api/subscription/checkout') return handleSubscriptionCheckout(request, env, authCtx);\n"
        "    if (path === '/api/subscription/plan') return handleGetMyPlan(request, env, authCtx);\n"
        "    if (path === '/api/webhooks/stripe') return handleWebhookStripe(request, env);\n\n"
    )

    if "servePlatformMetrics" not in modified:
        if ROUTE_MARKER in modified:
            modified = modified.replace(ROUTE_MARKER, ROUTE_BLOCK + ROUTE_MARKER)
            print(f"  PATCH route block: {index_path}")
        else:
            # Fallback: insert before the 404 catch-all
            FALLBACK_MARKER = "return Response.json({ error: 'Not found'"
            if FALLBACK_MARKER in modified and "servePlatformMetrics" not in modified:
                modified = modified.replace(FALLBACK_MARKER, ROUTE_BLOCK + FALLBACK_MARKER)
                print(f"  PATCH route block (fallback marker): {index_path}")
            else:
                print(f"  WARN: route marker not found in {index_path} — routes NOT applied")

    # ── E: Cron metrics refresh ──────────────────────────────────────────────
    CRON_MARKER = "ctx.waitUntil(\n      runIngestion(env)"
    CRON_BLOCK = (
        "// ── v30.0: Platform Metrics Hydration ───────────────────────────────────────\n"
        "    ctx.waitUntil(\n"
        "      refreshPlatformMetrics(env)\n"
        "        .then(r => console.log('[CRON] MetricsHydration:', JSON.stringify(r)))\n"
        "        .catch(e => console.error('[CRON] MetricsHydration error:', e?.message))\n"
        "    );\n\n"
    )

    if "refreshPlatformMetrics" not in modified or "[CRON] MetricsHydration" not in modified:
        if CRON_MARKER in modified:
            modified = modified.replace(CRON_MARKER, CRON_BLOCK + CRON_MARKER)
            print(f"  PATCH cron block: {index_path}")

    if modified != content:
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(modified)
        print(f"  SAVED {index_path}")
        return True
    else:
        print(f"  NO CHANGES needed: {index_path}")
        return False

def patch_threat_ingestion(ingestion_path):
    if not os.path.exists(ingestion_path):
        print(f"  SKIP (not found): {ingestion_path}")
        return

    with open(ingestion_path, "r", encoding="utf-8-sig") as f:
        content = f.read()

    if "enforceGovernanceBatch" in content:
        print(f"  SKIP (already patched): {ingestion_path}")
        return

    # Add import
    IMPORT_INSERT = "import { enforceGovernanceBatch } from '../middleware/severityGovernanceGate.js';\n"
    if IMPORT_INSERT not in content:
        first_import_pos = content.find("import ")
        content = content[:first_import_pos] + IMPORT_INSERT + content[first_import_pos:]

    # Wrap normalization output before D1 insert
    # Look for comment patterns near the insert loop
    patch_comment = (
        "\n  // ── v30.0 Severity Governance Gate (P0 enforcement) ─────────────────────\n"
        "  const { entries: governed, violations: govViolations } = await enforceGovernanceBatch(normalized, env);\n"
        "  if (govViolations.length) {\n"
        "    console.warn(`[GovernanceGate] ${govViolations.length} severity corrections applied during ingestion`);\n"
        "  }\n"
        "  const safeEntries = governed;\n"
    )

    # Find the pattern where normalized is used for insertion
    NORMALIZED_PATTERN = "for (const entry of normalized)"
    GOVERNED_PATTERN   = "for (const entry of safeEntries)"

    if NORMALIZED_PATTERN in content and GOVERNED_PATTERN not in content:
        content = content.replace(NORMALIZED_PATTERN,
                                  patch_comment + "  " + GOVERNED_PATTERN)
        print(f"  PATCH governance gate: {ingestion_path}")

    with open(ingestion_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  SAVED {ingestion_path}")

def print_next_steps():
    print("\n" + "="*70)
    print("DEPLOYMENT COMPLETE — NEXT STEPS")
    print("="*70)
    print("""
1. Run D1 schema migration:
   cd workers
   npx wrangler d1 execute cyberdudebivash-security-hub --file=schema_v30_p0p1.sql

2. Set required secrets (if not already set):
   npx wrangler secret put STRIPE_SECRET_KEY
   npx wrangler secret put STRIPE_WEBHOOK_SECRET

3. Deploy to Cloudflare:
   git add workers/ -A
   git commit -m "v30.0.0 P0/P1 remediation: severity governance, metrics hydration, scan tokens, paywall engine"
   git push

4. Verify after deployment:
   curl https://cyberdudebivash.in/api/platform/metrics | python -m json.tool
   curl -X POST https://cyberdudebivash.in/api/scan/token | python -m json.tool

5. Confirm metrics hydrate within 2 cron cycles (~60 min):
   total_scans, total_cves_tracked, active_customers should be non-null
""")

def main():
    print("="*70)
    print("CYBERDUDEBIVASH v30.0 P0/P1 Deployment Script")
    print("="*70)

    copy_engine_files()
    copy_schema()

    print("\n[3] Patching index.js (both mirrors)...")
    for idx_path in [
        os.path.join(SRC1, "index.js"),
        os.path.join(SRC2, "index.js"),
    ]:
        patch_index(idx_path)

    print("\n[4] Patching threatIngestion.js (governance gate)...")
    patch_threat_ingestion(os.path.join(SRC1, "services", "threatIngestion.js"))

    print_next_steps()

if __name__ == "__main__":
    main()
