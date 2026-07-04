# CYBERDUDEBIVASH® — Sub-Processor List
**Version:** 1.1 | **Effective:** 2026-07-04 | **Last reviewed:** 2026-07-04

This list identifies all third-party sub-processors that may process personal data on behalf of CYBERDUDEBIVASH in the course of providing the AI Security Hub platform.

---

## Sub-Processors

| Sub-Processor | Country | Role | Data Processed | Data Categories | Legal Basis for Transfer |
|---|---|---|---|---|---|
| **Cloudflare, Inc.** | United States (HQ); CDN globally | Infrastructure — compute (Workers), database (D1), object storage (R2), key-value store (KV), CDN, DDoS protection | Platform traffic, user account data, API requests, scan results, payment confirmation metadata | Email, hashed passwords, API key hashes, IP addresses, scan target hostnames | Standard Contractual Clauses (Cloudflare DPA) |
| **Razorpay Software Pvt Ltd** | India | Payment processing | Payment transactions, order amounts, payment method type | Payment amount, currency, Razorpay order ID, payment ID (no raw card/UPI credentials stored by us — tokenized by Razorpay) | Necessary for contract performance (payment processing); Razorpay is a RBI-licensed payment aggregator |
| **Telegram (Telegram Messenger Inc.)** | UAE (HQ) | Admin operational alerts only | Admin notification messages | No customer personal data — internal operational alerts (error messages, system events) to the operator's private Telegram bot | Legitimate interest (internal operations) |
| **NVD / NIST (U.S. NIST)** | United States | Threat intelligence data source — CVE data ingestion | Public CVE records only | No personal data — public vulnerability records | N/A (publicly available data) |
| **Google LLC (Google Analytics 4)** | United States | Web analytics on public marketing pages | Page views, marketing-funnel events | Pseudonymous analytics identifiers, IP-derived coarse location (ad personalization signals disabled) | Standard Contractual Clauses (Google Ads Data Processing Terms) |

## AI / LLM Inference Sub-Processors

Conversational and generative AI features (AI Security Copilot, AI verdicts, executive summaries, multi-agent SOC analysis) send the prompt content — which may include user chat messages, scan targets, and scan findings — to one of the following inference providers. The platform's provider router selects a provider at request time based on availability and task type; a request is sent to exactly one provider (with automatic fallback to the next on failure). Providers whose API key is not configured in the production environment are never contacted.

| Sub-Processor | Country | Role | Data Processed |
|---|---|---|---|
| **Groq, Inc.** | United States | Primary LLM inference | AI chat messages, scan-derived analysis context |
| **Cloudflare, Inc. (Workers AI)** | United States (HQ); edge globally | LLM inference fallback (in-infrastructure) | AI chat messages, scan-derived analysis context |
| **DeepSeek (Hangzhou DeepSeek AI Co., Ltd.)** | China | LLM inference fallback (only if configured) | AI chat messages, scan-derived analysis context |
| **OpenRouter, Inc.** | United States | LLM inference fallback / meta-provider (only if configured) | AI chat messages, scan-derived analysis context |
| **Together Computer, Inc. (Together AI)** | United States | LLM inference fallback (only if configured) | AI chat messages, scan-derived analysis context |
| **Anthropic, PBC** | United States | LLM inference fallback (only if configured) | AI chat messages, scan-derived analysis context |

Deterministic features — scan scoring, rule generation from templates, CVE feed ingestion, risk grading — do **not** call LLM providers.

---

## What is NOT shared with sub-processors

- Raw scan results beyond what is necessary to fulfill the service
- Full payment card numbers or UPI VPA (handled directly by Razorpay, never pass through our application layer)
- User passwords (hashed client-side and stored only as PBKDF2 hashes)
- API keys (stored as SHA-256 hashes — the raw key is shown once at creation and never stored)

---

## Changes to this list

CYBERDUDEBIVASH will provide at least **30 days advance notice** to enterprise customers before adding a new sub-processor that will process their personal data, via email to the registered enterprise contact. Enterprise customers who object to a new sub-processor addition may terminate their agreement per the terms of their contract.

---

## Questions

Contact **privacy@cyberdudebivash.in** for questions about this sub-processor list or our data processing practices.
