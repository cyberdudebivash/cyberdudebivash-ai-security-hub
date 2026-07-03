#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# CYBERDUDEBIVASH — External-integration live verification (release runbook)
# ───────────────────────────────────────────────────────────────────────────────
# The capture→entitlement and SSO id_token code paths are already proven at the
# integration boundary by:
#     workers/test/paymentEntitlement.test.mjs   (real HMAC-signed webhook → tier grant)
#     workers/test/ssoOidcVerify.test.mjs        (real RS256 id_token verification)
#
# This script closes the ONLY remaining hop those tests can't cover from CI: the
# live network round-trip against the real Razorpay + IdP, against production.
#
# Run it from a machine that CAN reach the platform, with your own credentials.
# It uses a throwaway TEST_EMAIL so it never touches a real customer account.
#
# Prereqs: bash, curl, openssl, jq. Set these env vars first:
#     export BASE_URL="https://cyberdudebivash.in"
#     export RAZORPAY_WEBHOOK_SECRET="whsec_live_or_test_..."   # from Razorpay dashboard
#     export TEST_EMAIL="release-check+$(date +%s)@cyberdudebivash.com"
#     export TEST_PLAN="PRO"                                      # STARTER|PRO|ENTERPRISE|MSSP
# Optional (for the SSO check): export SSO_ORG_ID="your-org-id"
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

BASE_URL="${BASE_URL:?set BASE_URL}"
TEST_EMAIL="${TEST_EMAIL:?set TEST_EMAIL}"
TEST_PLAN="${TEST_PLAN:-PRO}"
pass() { printf '  \033[32m✓ %s\033[0m\n' "$1"; }
fail() { printf '  \033[31m✗ %s\033[0m\n' "$1"; FAILED=1; }
FAILED=0

echo "── 1. Razorpay capture → entitlement (live webhook round-trip) ──"
if [[ -z "${RAZORPAY_WEBHOOK_SECRET:-}" ]]; then
  echo "  (skipped — set RAZORPAY_WEBHOOK_SECRET to run this check)"
else
  ORDER_ID="order_relcheck_$(date +%s)"
  PAYMENT_ID="pay_relcheck_$(date +%s)"
  # Synthetic-but-validly-signed payment.captured for a subscription order.
  BODY=$(jq -cn --arg oid "$ORDER_ID" --arg pid "$PAYMENT_ID" --arg em "$TEST_EMAIL" \
    '{event:"payment.captured", id:("evt_"+$oid), payload:{payment:{entity:{id:$pid, order_id:$oid, email:$em, amount:149900, notes:{}}}}}')
  # Razorpay signs the raw body with HMAC-SHA256(secret) → hex.
  SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$RAZORPAY_WEBHOOK_SECRET" -hex | sed 's/^.*= //')

  # NOTE: production must have a pending `payments` row for $ORDER_ID with
  # module='subscription', plan=$TEST_PLAN, email=$TEST_EMAIL for the grant to fire.
  # In a real test-mode purchase Razorpay creates that row; here we assert the
  # webhook is accepted + signature-verified. Use a real test purchase for the
  # full grant, or seed the row first.
  CODE=$(curl -s -o /tmp/rzp_resp.json -w '%{http_code}' -X POST "$BASE_URL/api/webhooks/razorpay" \
    -H 'content-type: application/json' -H "x-razorpay-signature: $SIG" --data "$BODY")
  if [[ "$CODE" == "200" ]]; then pass "webhook accepted + signature verified (HTTP 200)"; else fail "webhook returned HTTP $CODE (expected 200)"; cat /tmp/rzp_resp.json; fi

  # Negative control: a bad signature MUST be rejected 401.
  CODE_BAD=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/api/webhooks/razorpay" \
    -H 'content-type: application/json' -H 'x-razorpay-signature: deadbeef' --data "$BODY")
  if [[ "$CODE_BAD" == "401" ]]; then pass "bad signature rejected (HTTP 401)"; else fail "bad signature returned HTTP $CODE_BAD (expected 401)"; fi
  echo "  → For the FULL grant proof, run one real Razorpay TEST-MODE purchase of $TEST_PLAN"
  echo "    as $TEST_EMAIL, then: curl -s \"$BASE_URL/api/auth/status\" with that user's token → tier=$TEST_PLAN"
fi

echo
echo "── 2. Enterprise SSO (OIDC) live round-trip ──"
if [[ -z "${SSO_ORG_ID:-}" ]]; then
  echo "  (skipped — set SSO_ORG_ID for a configured org to run this check)"
else
  LOGIN_CODE=$(curl -s -o /tmp/sso_resp -w '%{http_code}' -D /tmp/sso_hdr \
    "$BASE_URL/api/auth/sso/login?org_id=$SSO_ORG_ID" || true)
  LOC=$(grep -i '^location:' /tmp/sso_hdr | head -1 | tr -d '\r' | sed 's/^[Ll]ocation: //')
  if [[ "$LOGIN_CODE" =~ ^30[0-9]$ ]] && [[ -n "$LOC" ]]; then
    pass "sso/login returns a 302 redirect to the IdP authorize endpoint"
    echo "    → IdP URL: ${LOC:0:80}..."
    echo "    → Open it in a browser, complete login, and confirm you land on"
    echo "      $BASE_URL/auth/callback#access_token=… (tier granted from the org plan)."
  else
    fail "sso/login did not redirect (HTTP $LOGIN_CODE) — check the org's OIDC config"
  fi
fi

echo
if [[ "$FAILED" == "0" ]]; then
  printf '\033[32m── external-integration live checks passed ──\033[0m\n'
else
  printf '\033[31m── some checks failed — see above ──\033[0m\n'; exit 1
fi
