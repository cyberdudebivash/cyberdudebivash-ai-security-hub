# CYBERDUDEBIVASH AI Security Hub — API Contract v3.0

**Base URL:** `https://cyberdudebivash-security-hub.workers.dev`
**Auth:** Optional `x-api-key` header. Without it: FREE tier (IP-based, 5 req/day).

---

## Authentication

| Header | Value | Effect |
|--------|-------|--------|
| `x-api-key` | `sk_live_...` | Uses registered tier (FREE/PRO/ENTERPRISE) |
| *(none)* | — | IP fallback, FREE tier (5 req/day) |

**Tier Limits:**

| Tier | Daily Limit | Burst/Min | Price |
|------|-------------|-----------|-------|
| FREE | 5 req/day | 2 req/min | ₹0 |
| PRO | 500 req/day | 20 req/min | ₹9,999/mo |
| ENTERPRISE | Unlimited | 60 req/min | Custom |

---

## Standard Response Headers

Every response includes:
```
X-RateLimit-Tier: FREE
X-RateLimit-Remaining: 4
X-RateLimit-Reset: tomorrow UTC midnight
X-Scan-ID: sc_lx3j2k8a9f
X-Powered-By: CYBERDUDEBIVASH AI Security Hub v3.0
```

---

## Endpoints

### GET /api/health
```json
{
  "status": "ok",
  "version": "3.0.0",
  "modules": ["domain","ai","redteam","identity","compliance"]
}
```

### GET /api
Returns full API info and endpoint directory.

---

### POST /api/scan/domain

**Request:**
```json
{ "domain": "example.com" }
```

**Free Response:**
```json
{
  "module": "domain_scanner",
  "version": "3.0.0",
  "target": "example.com",
  "risk_score": 62,
  "risk_level": "HIGH",
  "grade": "D",
  "tls_grade": "FAIR",
  "dnssec_enabled": false,
  "exposed_subdomain_count": 3,
  "findings": [
    {
      "id": "DOM-001",
      "title": "TLS/SSL Configuration",
      "severity": "MEDIUM",
      "description": "TLS grade: FAIR. Configuration meets baseline...",
      "recommendation": "Enforce TLS 1.3 minimum.",
      "cvss_base": 4.3,
      "is_premium": false
    }
  ],
  "locked_findings": [
    { "id": "DOM-004", "title": "Subdomain Enumeration", "severity": "HIGH", "preview": "3 exposed subdomains detected...", "locked": true }
  ],
  "locked_findings_count": 4,
  "is_premium_locked": true,
  "monetization": {
    "unlock_price": "₹199",
    "payment_url": "https://rzp.io/l/cyberdudebivash-domain",
    "upgrade_cta": "Unlock 4 additional findings + full Domain Vulnerability Report for ₹199"
  }
}
```

---

### POST /api/scan/ai

**Request:**
```json
{ "model_name": "GPT-4o", "use_case": "chatbot" }
```
`use_case` options: `chatbot` · `code-generation` · `rag` · `agent` · `recommendation` · `classification` · `voice` · `other`

---

### POST /api/scan/redteam

**Request:**
```json
{ "target_org": "Acme Corp", "scope": "external" }
```
`scope` options: `external` · `internal` · `full` · `web` · `cloud` · `hybrid` · `api`

---

### POST /api/scan/identity

**Request:**
```json
{ "org_name": "Acme Corp", "identity_provider": "azure-ad" }
```
`identity_provider` options: `azure-ad` · `okta` · `google-workspace` · `auth0` · `onelogin` · `jumpcloud` · `ping` · `duo` · `other`

---

### POST /api/generate/compliance

**Request:**
```json
{ "org_name": "Acme Corp", "framework": "iso27001" }
```
`framework` options: `iso27001` · `soc2` · `gdpr` · `pcidss` · `dpdp` · `hipaa`

---

### POST /api/leads/capture

**Request:**
```json
{ "email": "user@company.com", "scan_id": "sc_abc123", "module": "domain" }
```

**Response (201):**
```json
{
  "status": "ok",
  "lead_id": "ld_m2k9r5x",
  "message": "Email captured successfully."
}
```

---

### POST /api/contact/enterprise

**Request:**
```json
{
  "company_name": "Acme Corp",
  "email": "security@acme.com",
  "domain": "acme.com",
  "requirements": "We need quarterly red team simulations and ISO 27001 compliance support.",
  "package": "enterprise"
}
```

**Response (201):**
```json
{
  "status": "ok",
  "contact_id": "ent_p3x7q2",
  "message": "Enterprise inquiry received. Response within 24 hours.",
  "direct_contact": {
    "email": "bivashnayak.ai007@gmail.com",
    "phone": "+918179881447"
  }
}
```

---

### POST /api/webhooks/razorpay

Razorpay webhook endpoint. Signature verified via `x-razorpay-signature` header.
On `payment.captured` event: unlocks full report access (24h token stored in KV).

---

## Error Responses

### 400 Bad Request
```json
{ "error": "Validation failed", "message": "domain must be 4–253 characters", "field": "domain" }
```

### 401 Unauthorized
```json
{ "error": "Invalid API key", "hint": "Check your key or generate a new one", "upgrade_url": "https://cyberdudebivash.in/#pricing" }
```

### 413 Payload Too Large
```json
{ "error": "Payload too large", "max_size_bytes": 16384 }
```

### 429 Rate Limited
```json
{
  "error": "Rate limit exceeded",
  "reason": "daily_limit_reached",
  "tier": "FREE",
  "remaining": 0,
  "reset": "tomorrow UTC midnight",
  "retry_after": 86400,
  "upgrade_url": "https://cyberdudebivash.in/#pricing"
}
```

### 500 Internal Error
```json
{ "error": "Internal server error", "request_id": "abc123", "support": "bivash@cyberdudebivash.com" }
```

---

## Deployment (3 Commands)

```bash
# 1. Create KV namespace
cd workers && npx wrangler kv:namespace create SECURITY_HUB_KV
# → Copy the id output to wrangler.toml

# 2. Set secrets
npx wrangler secret put RAZORPAY_WEBHOOK_SECRET

# 3. Deploy
npx wrangler deploy

# 4. Deploy frontend
npx wrangler pages deploy ../frontend --project-name cyberdudebivash-security-hub
```

---

## Required GitHub Secrets

| Secret | Description |
|--------|-------------|
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token with Workers + Pages deploy permissions |
| `CLOUDFLARE_ACCOUNT_ID` | Your Cloudflare account ID |
| `WORKERS_KV_NAMESPACE_ID` | KV namespace ID from `wrangler kv:namespace create` |

---

*CyberDudeBivash Pvt. Ltd. · bivash@cyberdudebivash.com · https://cyberdudebivash.in*
