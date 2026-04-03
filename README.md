# ⚔️ CYBERDUDEBIVASH AI Security Hub v2.0.0

**Enterprise-Grade AI Cybersecurity Intelligence Platform**
*Built by [CyberDudeBivash Pvt. Ltd.](https://cyberdudebivash.in) — Fully Serverless · Free-Tier Compatible · Revenue-Ready*

---

## 🚀 Platform Overview

CYBERDUDEBIVASH AI Security Hub is a production-ready, serverless AI cybersecurity platform with 5 intelligence modules, a Cloudflare edge API, and a fully branded single-file frontend with monetization built in.

### 5 Modules
| Module | Endpoint | Free Price | Premium Price |
|--------|----------|-----------|---------------|
| Domain Vulnerability Scanner | `POST /api/scan/domain` | Free preview | ₹199/report |
| AI Agent Security Scanner | `POST /api/scan/ai` | Free preview | ₹499/report |
| Automated Red Team | `POST /api/scan/redteam` | Free preview | ₹999/report |
| Identity Security Monitor | `POST /api/scan/identity` | Free preview | ₹799/report |
| Compliance Report Generator | `POST /api/generate/compliance` | Free preview | ₹499–₹1,999/report |

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
| 🌐 Main Website | https://cyberdudebivash.in |
| 🛡️ Threat Intelligence | https://cyberdudebivash.in/threat-intel |
| 📦 Production Apps | https://cyberdudebivash.in/apps |
| 🛠️ Top 10 Tools | https://cyberdudebivash.in/tools |
| 📊 Threat Dashboard | https://cyberdudebivash.in/dashboard |
| 🔌 MCP Server | https://cyberdudebivash.in/mcp |
| 🐙 GitHub | https://github.com/cyberdudebivash |
| 🛒 Products (Gumroad) | https://cyberdudebivash.gumroad.com |

---

## 📞 Contact

| Channel | Details |
|---------|---------|
| 📧 Business | cyberdudebivash@gmail.com |
| 📧 Enterprise | bivashnayak.ai007@gmail.com |
| 📞 Phone | +918179881447 |
| 💬 Discord | cybercoder127001 |
| 📍 Location | Hyderabad, India |

---

© 2026 CyberDudeBivash Pvt. Ltd. All rights reserved.
