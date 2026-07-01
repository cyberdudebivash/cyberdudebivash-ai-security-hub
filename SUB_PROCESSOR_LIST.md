# CYBERDUDEBIVASH® — Sub-Processor List
**Version:** 1.0 | **Effective:** 2026-07-01 | **Last reviewed:** 2026-07-01

This list identifies all third-party sub-processors that may process personal data on behalf of CYBERDUDEBIVASH in the course of providing the AI Security Hub platform.

---

## Sub-Processors

| Sub-Processor | Country | Role | Data Processed | Data Categories | Legal Basis for Transfer |
|---|---|---|---|---|---|
| **Cloudflare, Inc.** | United States (HQ); CDN globally | Infrastructure — compute (Workers), database (D1), object storage (R2), key-value store (KV), CDN, DDoS protection | Platform traffic, user account data, API requests, scan results, payment confirmation metadata | Email, hashed passwords, API key hashes, IP addresses, scan target hostnames | Standard Contractual Clauses (Cloudflare DPA) |
| **Razorpay Software Pvt Ltd** | India | Payment processing | Payment transactions, order amounts, payment method type | Payment amount, currency, Razorpay order ID, payment ID (no raw card/UPI credentials stored by us — tokenized by Razorpay) | Necessary for contract performance (payment processing); Razorpay is a RBI-licensed payment aggregator |
| **Telegram (Telegram Messenger Inc.)** | UAE (HQ) | Admin operational alerts only | Admin notification messages | No customer personal data — internal operational alerts (error messages, system events) to the operator's private Telegram bot | Legitimate interest (internal operations) |
| **NVD / NIST (U.S. NIST)** | United States | Threat intelligence data source — CVE data ingestion | Public CVE records only | No personal data — public vulnerability records | N/A (publicly available data) |

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
