#!/usr/bin/env python3
"""
CYBERDUDEBIVASH AI SECURITY HUB
STOREFRONT MONETIZATION P0 REGRESSION TEST SUITE v2.0
Validates pricing, geo-router, checkout-modal, dual-tree sync, Worker routes.
"""
import os, re, sys, glob, py_compile

REPO       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND   = os.path.join(REPO, 'frontend')
W_FRONTEND = os.path.join(REPO, 'workers', 'frontend')
W_IDX_1    = os.path.join(REPO, 'workers', 'workers', 'src', 'index.js')
W_IDX_2    = os.path.join(REPO, 'workers', 'src', 'index.js')
CFG_1      = os.path.join(REPO, 'workers', 'workers', 'src', 'config', 'pricingConfig.js')
CFG_2      = os.path.join(REPO, 'workers', 'src', 'config', 'pricingConfig.js')

P = '\033[92m✓\033[0m'; F = '\033[91m✗\033[0m'; W = '\033[93m⚠\033[0m'
failures = []; warnings = []; passed = 0

def ok(m):
    global passed; passed += 1; print(f"  {P} {m}")
def fail(m):
    failures.append(m); print(f"  {F} {m}")
def warn(m):
    warnings.append(m); print(f"  {W} {m}")
def read(p):
    if not os.path.exists(p): return ''
    return open(p, 'r', encoding='utf-8', errors='replace').read()
def files(tree, exts=('.html','.js')):
    out = []
    for r,ds,fs in os.walk(tree):
        ds[:] = [d for d in ds if d not in ('node_modules','.git','.wrangler')]
        for f in fs:
            if any(f.endswith(e) for e in exts): out.append(os.path.join(r,f))
    return out

print("\n" + "="*65)
print("CYBERDUDEBIVASH — MONETIZATION P0 REGRESSION SUITE v2.0")
print("="*65)

# ── 1. No stale ₹199 in scan-report context ─────────────────────
print("\n【1】 No stale ₹199 in scan-report context")
STALE = [r'Reports from ₹199', r'Unlock Full Report ₹199',
         r"amountLabel:\s*['\"]₹199['\"]", r"'₹199'.*domain",
         r'risk-stat-num-v14.*₹199']
EXEMPT = ['save ₹199']
hits = []
for tree in [FRONTEND, W_FRONTEND]:
    for fp in files(tree):
        c = read(fp)
        for pat in STALE:
            for m in re.finditer(pat, c):
                ctx = c[max(0,m.start()-40):m.end()+40].replace('\n','↵')
                if not any(e in ctx for e in EXEMPT):
                    hits.append(f"{os.path.relpath(fp,REPO)}: {ctx[:90]}")
if hits:
    for h in hits: fail(h)
else:
    ok("No stale ₹199 scan-report pricing in either tree")

# ── 2. revenue-engine module prices all ≥ ₹999 ──────────────────
print("\n【2】 revenue-engine-v14.js module prices ≥ ₹999")
MODULES = ('domain','ai','redteam','identity','compliance')
for tree in [FRONTEND, W_FRONTEND]:
    rev = os.path.join(tree, 'assets', 'revenue-engine-v14.js')
    c   = read(rev)
    if not c:
        fail(f"MISSING: {os.path.relpath(rev,REPO)}"); continue
    found = [(k,int(v)) for k,v in re.findall(r"([a-z]+):'₹(\d+)'", c) if k in MODULES]
    if not found:
        warn(f"Could not parse module prices in {os.path.relpath(rev,REPO)}")
    else:
        bad = [(k,v) for k,v in found if v < 999]
        if bad:
            for k,v in bad: fail(f"{os.path.relpath(rev,REPO)}: '{k}'=₹{v} < ₹999")
        else:
            ok(f"All {len(found)} module prices ≥ ₹999 — {os.path.relpath(rev,REPO)}")
    if "'₹199'" in c or '"₹199"' in c:
        fail(f"₹199 string still present: {os.path.relpath(rev,REPO)}")
    else:
        ok(f"No ₹199 fallback — {os.path.relpath(rev,REPO)}")

# ── 3. payment-modal.js prices dict ─────────────────────────────
print("\n【3】 payment-modal.js module prices ≥ ₹999")
c = read(os.path.join(FRONTEND, 'assets', 'payment-modal.js'))
found = [(k,int(v)) for k,v in re.findall(r"([a-z]+):\s*'₹(\d+)'", c) if k in MODULES]
if not found:
    warn("payment-modal.js: module prices not parsed (may be inlined)")
else:
    bad = [(k,v) for k,v in found if v < 999]
    if bad:
        for k,v in bad: fail(f"payment-modal.js: '{k}'=₹{v} < ₹999")
    else:
        ok(f"payment-modal.js: all {len(found)} module prices ≥ ₹999")

# ── 4. pricingConfig.js domain report ≥ 999 ─────────────────────
print("\n【4】 pricingConfig.js domain price_inr ≥ 999")
for cfg in [CFG_1, CFG_2]:
    c = read(cfg)
    if not c:
        warn(f"Config not found: {os.path.relpath(cfg,REPO)}"); continue
    m = re.search(r"domain\s*:.*?price_inr\s*:\s*(\d+)", c, re.DOTALL)
    if m:
        p = int(m.group(1))
        (ok if p >= 999 else fail)(f"{os.path.relpath(cfg,REPO)}: domain price_inr={p}")
    else:
        warn(f"Could not parse domain price_inr from {os.path.relpath(cfg,REPO)}")

# ── 5. New assets exist in both trees ───────────────────────────
print("\n【5】 New assets deployed in both trees")
for asset in ['assets/geo-currency-router.js', 'assets/checkout-modal.js']:
    for tree in [FRONTEND, W_FRONTEND]:
        fp = os.path.join(tree, asset)
        if os.path.exists(fp):
            ok(f"{os.path.relpath(fp,REPO)} ({os.path.getsize(fp):,} bytes)")
        else:
            fail(f"MISSING: {os.path.relpath(fp,REPO)}")

# ── 6. geo-currency-router.js content ───────────────────────────
print("\n【6】 geo-currency-router.js content validation")
c = read(os.path.join(FRONTEND, 'assets', 'geo-currency-router.js'))
checks = {
    'INR matrix':             'INR' in c,
    'USD matrix':             'USD' in c,
    'STARTER ₹499':           '499' in c,
    'STARTER $6':             'monthly: 6' in c or "'monthly':6" in c,
    '/api/geo fetch':         '/api/geo' in c,
    'window.__CDB_GEO':       '__CDB_GEO' in c,
    'format() function':      'format(' in c,
    'applyPricingToDOM':      'applyPricingToDOM' in c,
}
for k,v in checks.items():
    (ok if v else fail)(f"geo-currency-router: {k}")

# ── 7. checkout-modal.js content ────────────────────────────────
print("\n【7】 checkout-modal.js content validation")
c = read(os.path.join(FRONTEND, 'assets', 'checkout-modal.js'))
checks2 = {
    'UPI ID primary':        'iambivash.bn-5@okaxis' in c,
    'UPI ID alternate':      '6302177246@axisbank' in c,
    'IFSC UTIB0000052':      'UTIB0000052' in c,
    'PayPal link':           'paypal.me/iambivash' in c,
    'ETH address':           '0x742d' in c,
    'USDT TRC-20':           'TRC-20' in c or 'TJvEi7k3' in c,
    'buildUPILink()':        'buildUPILink' in c,
    'renderQR()':            'renderQR' in c,
    'CDB_CHECKOUT_MODAL':    'CDB_CHECKOUT_MODAL' in c,
    'switchTab()':           'switchTab' in c,
    'triggerRazorpay()':     'triggerRazorpay' in c,
    'geo-aware getGeo()':    'getGeo' in c,
    'Bank wire rail':        'NEFT' in c or 'bank' in c.lower(),
}
for k,v in checks2.items():
    (ok if v else fail)(f"checkout-modal: {k}")

# ── 8. /api/geo in Worker index ─────────────────────────────────
print("\n【8】 /api/geo route in Worker index.js")
for idx in [W_IDX_1, W_IDX_2]:
    c = read(idx)
    if not c:
        warn(f"Not found: {os.path.relpath(idx,REPO)}"); continue
    has_route = "path === '/api/geo'" in c
    has_cf    = 'CF-IPCountry' in c or 'request.cf' in c
    if has_route and has_cf:
        ok(f"/api/geo + CF detection in {os.path.relpath(idx,REPO)}")
    elif has_route:
        warn(f"/api/geo route present but no CF-IPCountry: {os.path.relpath(idx,REPO)}")
    else:
        fail(f"/api/geo route MISSING: {os.path.relpath(idx,REPO)}")

# ── 9. Script tags injected in all key HTML pages ───────────────
print("\n【9】 Script tags injected in key HTML pages")
KEY = ['index.html','intel.html','about.html','contact.html',
       'services.html','tools.html','booking.html','user-dashboard.html']
for page in KEY:
    for tree in [FRONTEND, W_FRONTEND]:
        fp = os.path.join(tree, page)
        c  = read(fp)
        if not c: continue
        rel = os.path.relpath(fp,REPO)
        miss = []
        if 'geo-currency-router.js' not in c: miss.append('geo-router')
        if 'checkout-modal.js' not in c:      miss.append('checkout-modal')
        if miss: fail(f"{rel}: missing {', '.join(miss)}")
        else: ok(f"{rel}: ✓")

# ── 10. Dual-tree sync ───────────────────────────────────────────
print("\n【10】 Dual-tree asset sync (frontend ↔ workers/frontend)")
for asset in ['assets/geo-currency-router.js','assets/checkout-modal.js',
              'assets/revenue-engine-v14.js','assets/payment-modal.js']:
    p1 = os.path.join(FRONTEND, asset)
    p2 = os.path.join(W_FRONTEND, asset)
    if not os.path.exists(p1) or not os.path.exists(p2):
        warn(f"Sync skip (missing): {asset}"); continue
    b1, b2 = open(p1,'rb').read(), open(p2,'rb').read()
    (ok if b1==b2 else fail)(f"SYNC {'OK' if b1==b2 else 'DRIFT'}: {asset}")

# ── 11. Python syntax check ──────────────────────────────────────
print("\n【11】 Python syntax validation")
py_files = [f for f in glob.glob(os.path.join(REPO,'**','*.py'),recursive=True)
            if '.git' not in f and 'node_modules' not in f]
errors = 0
for pf in py_files:
    try: py_compile.compile(pf, doraise=True)
    except py_compile.PyCompileError as e:
        fail(f"Syntax: {os.path.relpath(pf,REPO)}: {e}"); errors += 1
if not errors:
    ok(f"All {len(py_files)} .py files pass syntax check")

# ── 12. No stale price=199 in API URLs ──────────────────────────
print("\n【12】 No stale price=199 in API URL params")
price_hits = []
for tree in [FRONTEND, W_FRONTEND]:
    for fp in files(tree):
        c = read(fp)
        for m in re.finditer(r'price=199\b', c):
            ctx = c[max(0,m.start()-30):m.end()+30]
            price_hits.append(f"{os.path.relpath(fp,REPO)}: {ctx[:70]}")
if price_hits:
    for h in price_hits: fail(h)
else:
    ok("No stale price=199 API references")

# ── RESULTS ─────────────────────────────────────────────────────
print(f"\n{'='*65}")
print(f"RESULTS: {passed} passed · {len(failures)} failed · {len(warnings)} warnings")
print("="*65)
if failures:
    print(f"\n✗ FAILURES ({len(failures)}):")
    for f in failures: print(f"  • {f}")
if warnings:
    print(f"\n⚠ WARNINGS ({len(warnings)}):")
    for w in warnings: print(f"  • {w}")
if not failures:
    print("\n✓ ALL P0 CHECKS PASSED — PLATFORM CLEARED FOR DEPLOYMENT\n")
    sys.exit(0)
else:
    print(f"\n✗ {len(failures)} FAILURE(S) — RESOLVE BEFORE DEPLOY\n")
    sys.exit(1)
