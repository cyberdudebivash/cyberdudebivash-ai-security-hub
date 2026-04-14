# CYBERDUDEBIVASH AI Security Hub — Architecture Deep-Dive

## Overview

The platform is a three-layer serverless architecture:

1. **Frontend Layer** — Cloudflare Pages (static HTML, no build step)
2. **API Layer** — Cloudflare Workers (edge JS, 100K req/day free)
3. **Intelligence Layer** — Python AI Core (optional, local or server deployment)

---

## Data Flow

```
User Browser
    │
    ├─ Static assets from Cloudflare Pages (index.html)
    │
    └─ API calls → Cloudflare Workers Edge
                        │
                        ├─ cors.js       (CORS headers)
                        ├─ validation.js (Input validation)
                        ├─ monetization.js (Rate limit + premium lock)
                        │
                        └─ engine.js (Deterministic scan, no external calls)
                                │
                                └─ JSON response with is_premium_locked: true
```

---

## Deterministic Engine

All scan scores are seeded from the input string using `strHash()`:

```javascript
function strHash(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}
```

This means: same input → same score, every time. No database required.

---

## Monetization Flow

```
Scan Request
    │
    └─ engine.js → all findings (free + premium)
                        │
                        └─ monetization.js
                                │
                                ├─ Free response: 2-3 findings + risk score
                                └─ Premium lock:
                                    is_premium_locked: true
                                    unlock_required: true
                                    payment_url: Razorpay link
```

---

## Rate Limiting (Cloudflare KV)

- Free tier: 10 scans/hour, 50 scans/day per IP per module
- KV keys: `rl:{ip}:{module}:{hour_epoch}` (TTL: 3600s)
- Day tracking: `rl:{ip}:day:{day_epoch}` (TTL: 86400s)
- If KV unavailable: fail open (allow request)

---

## Compliance Frameworks Covered

| Framework | Domains | Price |
|-----------|---------|-------|
| ISO 27001:2022 | A.5 Org, A.6 People, A.7 Physical, A.8 Tech | ₹999 |
| SOC 2 Type II | Security, Availability, Processing, Confidentiality, Privacy | ₹1,499 |
| GDPR 2016/679 | Lawful Basis, Data Subject Rights, Design, Breach | ₹799 |
| PCI-DSS v4.0 | Network, Cardholder Data, Vuln Mgmt, Access | ₹1,999 |
| DPDP Act 2023 | Fiduciary Obligations, Principal Rights, Consent, Cross-Border | ₹499 |
| HIPAA/HITECH | Admin, Physical, Technical Safeguards, Breach | ₹1,499 |

---

## MITRE ATT&CK Coverage (Red Team)

| Scenario | Tactic | Technique |
|----------|--------|-----------|
| RT-001 | Initial Access | T1566 Spear Phishing |
| RT-002 | Credential Access | T1110.003 Password Spraying |
| RT-003 | Discovery | T1046 Network Service Scanning |
| RT-004 | Lateral Movement | T1550.002 Pass the Hash |
| RT-005 | Persistence | T1053 Scheduled Task |
| RT-006 | Exfiltration | T1048 Exfil Over Alt Protocol |
| RT-007 | Defense Evasion | T1070 Indicator Removal |
| RT-008 | Impact | T1486 Data Encrypted for Impact |

---

*CyberDudeBivash Pvt. Ltd. — https://cyberdudebivash.in*
