# ⚔️ CYBERDUDEBIVASH AI Security Hub

**Enterprise-Grade AI Cybersecurity Intelligence Platform**
*Built by [CyberDudeBivash Pvt. Ltd.](https://cyberdudebivash.in) — Fully Serverless · Free-Tier Compatible · Revenue-Ready*

> **Deployed version:** see `PLATFORM_VERSION` in [`workers/wrangler.toml`](workers/wrangler.toml) (v40.x line) or live at [`/api/version`](https://cyberdudebivash.in/api/version).
> This README describes the original v2 module core, which still underpins the platform; the deployed surface has grown far beyond it (841 routes, 155 handlers). For the authoritative doc map see [`DOCUMENTATION_INDEX.md`](DOCUMENTATION_INDEX.md).

**Operations:** [`INCIDENT_RESPONSE_RUNBOOK.md`](INCIDENT_RESPONSE_RUNBOOK.md) · [`DISASTER_RECOVERY_RUNBOOK.md`](DISASTER_RECOVERY_RUNBOOK.md) · [`docs/OPERATIONAL_RISK_REGISTER.md`](docs/OPERATIONAL_RISK_REGISTER.md) · nightly D1 backups via `.github/workflows/d1-backup.yml` · gated migrations via `.github/workflows/db-migrate.yml`

---

## 🚀 Platform Overview

CYBERDUDEBIVASH AI Security Hub is a production-ready, serverless AI cybersecurity platform with 5 intelligence modules, a Cloudflare edge API, and a fully branded single-file frontend with monetization built in.

### 5 Modules
| Module | Endpoint | Free Price | Premium Price |
|--------|----------|-----------|---------------|
| Domain Vulnerability Scanner | `POST /api/scan/domain` | Free preview | ₹999/report |
| AI Agent Security Scanner | `POST /api/scan/ai` | Free preview | ₹2,499/report |
| Automated Red Team | `POST /api/scan/redteam` | Free preview | ₹4,999/report |
| Identity Security Monitor | `POST /api/scan/identity` | Free preview | ₹799/report |
| Compliance Report Generator | `POST /api/generate/compliance` | Free preview | ₹499/report |

<!-- Prices above match workers/src/lib/razorpay.js MODULE_PRICES and
     workers/src/middleware/monetization.js MODULE_CONFIG (both reconciled
     2026-07-24, previously drifted from each other). NOT independently
     verified against what's actually configured on the live
     rzp.io/l/cyberdudebivash-* Razorpay Payment Links -- confirm those match
     directly in the Razorpay dashboard. -->

---

## 🏗️ Architecture

```
cyberdudebivash-ai-security-hub/
├── frontend/
│   ├── index.html          # Single-file branded platform UI (no build step)
│   └── _headers            # Cloudflare Pages security headers
├── workers/
│   ├── src/
│   │   ├── index.js        # Main router (5 endpoints + health)
│   │   ├── engine.js       # Embedded deterministic scan engine
│   │   ├── handlers/       # domain.js · ai.js · redteam.js · identity.js · compliance.js
│   │   └── middleware/     # cors.js · validation.js · monetization.js
│   ├── wrangler.toml       # Cloudflare Workers config
│   └── package.json
├── ai-core/
│   └── scanner/
│       ├── __init__.py
│       ├── adapter.py              # Clean entry point for all modules
│       ├── domain_scanner.py       # TLS · DNS · HTTP headers · threat intel
│       ├── ai_scanner.py           # OWASP LLM Top 10 (LLM01–LLM10)
│       ├── redteam_engine.py       # 8 MITRE ATT&CK scenarios
│       ├── identity_scanner.py     # Zero Trust IAM assessment
│       └── compliance_generator.py # ISO 27001 · SOC 2 · GDPR · PCI-DSS · DPDP · HIPAA
├── .github/workflows/
│   ├── ci.yml              # Lint + syntax check on every push
│   ├── deploy.yml          # Auto-deploy to Cloudflare on push to main
│   └── report.yml          # Manual report generation trigger
├── docs/
│   └── architecture.md     # Full architecture deep-dive
└── README.md
```

---

## ⚡ Deploy in 3 Commands

### 1. Workers API (Cloudflare Edge)
```bash
cd workers
npm install
npx wrangler deploy
```

### 2. Frontend (Cloudflare Pages)
```bash
npx wrangler pages deploy frontend --project-name cyberdudebivash-security-hub
```

### 3. Done — Live at your domain
Set `API_BASE` in `frontend/index.html` to your Workers URL, then push `main` for auto-deploy.

---

## 🔐 API Reference

### Health Check
```
GET /api/health
```

### Domain Vulnerability Scan
```
POST /api/scan/domain
Content-Type: application/json
{ "domain": "example.com" }
```

### AI Agent Security Scan (OWASP LLM Top 10)
```
POST /api/scan/ai
Content-Type: application/json
{ "model_name": "GPT-4o", "use_case": "chatbot" }
```

### Automated Red Team
```
POST /api/scan/redteam
Content-Type: application/json
{ "target_org": "Acme Corp", "scope": "external" }
```

### Identity Security Monitor
```
POST /api/scan/identity
Content-Type: application/json
{ "org_name": "Acme Corp", "identity_provider": "azure-ad" }
```

### Compliance Report Generator
```
POST /api/generate/compliance
Content-Type: application/json
{ "org_name": "Acme Corp", "framework": "iso27001" }
```
Supported frameworks: `iso27001` · `soc2` · `gdpr` · `pcidss` · `dpdp` · `hipaa`

---

## 💰 Monetization

Every API response includes:
```json
{
  "is_premium_locked": true,
  "unlock_required": true,
  "unlock_price": "₹499",
  "payment_url": "https://rzp.io/l/cyberdudebivash-ai",
  "upgrade_cta": "Unlock 8 additional findings + full report for ₹499"
}
```

Plug in your Razorpay key to start collecting payments immediately.

---

## 🛡️ GitHub Actions CI/CD

| Workflow | Trigger | Jobs |
|----------|---------|------|
| `ci.yml` | Every push | Lint Workers · Lint Python · Validate HTML · Security scan · Structure check |
| `deploy.yml` | Push to `main` | Deploy Workers → Deploy Pages → Print summary |
| `report.yml` | Manual trigger | Run scan via Python adapter · Upload JSON artifact |

### Required Secrets (Settings → Secrets → Actions)
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- `WORKERS_KV_NAMESPACE_ID`

---

## 🔧 Local Python Usage

```python
from ai-core.scanner.adapter import ScannerAdapter

adapter = ScannerAdapter()

# Domain scan
result = adapter.scan_domain("example.com")

# AI security scan
result = adapter.scan_ai("GPT-4o", "chatbot")

# Red team simulation
result = adapter.scan_redteam("Acme Corp", "external")

# Identity scan
result = adapter.scan_identity("Acme Corp", "azure-ad")

# Compliance report
result = adapter.generate_compliance("Acme Corp", "iso27001")
```

---

## 🌐 CYBERDUDEBIVASH® Ecosystem

| Platform | URL |
|----------|-----|
| 🌐 Official corporate site | https://www.cyberdudebivash.com |
| 🤖 This platform (AI Security Hub) | https://cyberdudebivash.in |
| 🛡️ Threat Intelligence (SENTINEL APEX — separate platform) | https://intel.cyberdudebivash.com |
| 📰 Research blog | https://blog.cyberdudebivash.in |
| 🛠️ Tools store | https://tools.cyberdudebivash.com |
| 🐙 GitHub | https://github.com/cyberdudebivash |
| 🛒 Products (Gumroad) | https://cyberdudebivash.gumroad.com |

<!-- Corrected 2026-07-24: this table previously listed
     cyberdudebivash.in/threat-intel (real, live 404), /apps, /dashboard,
     and /mcp as ecosystem paths -- /threat-intel was verified 404, /apps
     /dashboard /mcp were unverified so removed rather than left as
     unconfirmed claims. Threat intelligence is a real, separate product
     (SENTINEL APEX) on its own domain, not a sub-path of this platform. -->

---

## 📞 Contact

| Channel | Details |
|---------|---------|
| 📧 Business | bivash@cyberdudebivash.com |
| 📧 Enterprise | bivashnayak.ai007@gmail.com |
| 📞 Phone | +918179881447 |
| 💬 Discord | cybercoder127001 |
| 📍 Location | Hyderabad, India |

---

© 2026 CyberDudeBivash Pvt. Ltd. All rights reserved.
