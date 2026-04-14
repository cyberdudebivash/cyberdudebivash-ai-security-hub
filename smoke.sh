#!/bin/bash
BASE="https://www.cyberdudebivash.in"
echo "=== Clean-URL Smoke Test Tue Apr 14 07:06:59 PM IST 2026 ==="
test_url() {
  local path=""
  local url=""
  local result
  result=
  local code=""
  local hops=""
  local final=""
  printf "%-30s %s  hops:%-2s  =>  %s\n" "" "" "" ""
}
test_url "/"
test_url "/about"
test_url "/services"
test_url "/tools"
test_url "/intel"
test_url "/booking"
test_url "/contact"
test_url "/academy"
test_url "/soc-dashboard"
test_url "/privacy-policy"
test_url "/terms-of-service"
test_url "/refund-policy"
test_url "/user-dashboard"
test_url "/admin-payments"
echo "=== Done ==="
