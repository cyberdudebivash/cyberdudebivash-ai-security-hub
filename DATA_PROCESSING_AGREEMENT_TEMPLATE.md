# Data Processing Agreement
## CYBERDUDEBIVASH® AI Security Hub

**This Data Processing Agreement ("DPA")** is entered into between:

- **Data Controller:** [ENTERPRISE CUSTOMER LEGAL NAME], a company incorporated under the laws of [JURISDICTION], with registered address at [ADDRESS] ("Controller"), and
- **Data Processor:** CYBERDUDEBIVASH Pvt Ltd, [registered address, India] ("Processor")

and forms part of, and is incorporated into, the Master Subscription Agreement or Order Form between the parties ("Principal Agreement").

**Effective Date:** [DATE OF EXECUTION]

---

## 1. Definitions

1.1 **"Personal Data"** means any information relating to an identified or identifiable natural person processed by the Processor on behalf of the Controller under the Principal Agreement.

1.2 **"Processing"** has the meaning given in applicable Data Protection Laws.

1.3 **"Data Protection Laws"** means all laws applicable to the processing of Personal Data under this DPA, including (as applicable): the Digital Personal Data Protection Act 2023 (India); the General Data Protection Regulation (EU) 2016/679 ("GDPR"); the UK GDPR; and any implementing legislation or successor legislation.

1.4 **"Security Incident"** means any accidental or unlawful destruction, loss, alteration, unauthorised disclosure of, or access to, Personal Data.

1.5 **"Sub-Processor"** means any third party engaged by the Processor to process Personal Data on behalf of the Controller. The current list is published at [URL to SUB_PROCESSOR_LIST.md].

---

## 2. Scope and Nature of Processing

2.1 The Processor shall process Personal Data only to the extent necessary to provide the services described in the Principal Agreement, including:

| Activity | Categories of Personal Data | Data Subjects |
|---|---|---|
| User account management | Email address, full name, company name, hashed password | Controller's employees and authorized users |
| API access management | Email address, API key hashes (key itself never stored raw) | Controller's developers and authorized API consumers |
| Security scan processing | Scan target hostnames/IP addresses (not attributed to individuals by the Processor) | N/A — technical data |
| Payment processing | Payment confirmation metadata (amount, order ID — no card/UPI data) | Controller's billing contact |
| Support ticket processing | Email address, ticket content as submitted | Controller's employees who submit tickets |

2.2 Scan targets submitted to the platform are processed in-flight for threat analysis and are not persistently associated with individual users beyond what is necessary for report delivery.

2.3 The Processor does not sell, rent, or otherwise disclose Personal Data to third parties for marketing purposes.

---

## 3. Processor Obligations

3.1 **Lawful instructions only.** The Processor shall process Personal Data only on documented instructions from the Controller, except where required to do so by applicable law.

3.2 **Confidentiality.** The Processor shall ensure that persons authorised to process Personal Data are subject to appropriate confidentiality obligations.

3.3 **Security.** The Processor shall implement appropriate technical and organisational measures to protect Personal Data, including those described in `FORTUNE500_SECURITY_TRUST_OVERVIEW.md`. These measures include:
- Encryption in transit (TLS) and at rest (AES-256, platform-managed by Cloudflare)
- Access control via JWT authentication, role-based permissions, and owner-gating
- Multi-factor authentication available for user accounts
- Brute-force protection (10 attempts / 15 min, KV-backed)
- Secrets management via Cloudflare Wrangler Secrets (never in source)

3.4 **Sub-Processors.** The Controller provides general authorisation for the Processor to engage the Sub-Processors listed in the Sub-Processor List. The Processor shall notify the Controller at least 30 days before engaging a new Sub-Processor. The Processor shall impose data protection obligations on Sub-Processors equivalent to those in this DPA.

3.5 **Data Subject Rights.** The Processor shall promptly notify the Controller of any data subject request and shall provide reasonable assistance to enable the Controller to respond. The Controller is responsible for responding to data subjects.

3.6 **Security Incidents.** The Processor shall notify the Controller without undue delay, and in any event within 72 hours, after becoming aware of a Security Incident affecting Personal Data. Notification shall be sent to the security contact email provided by the Controller.

3.7 **Deletion or return.** Upon termination of the Principal Agreement, the Processor shall, at the Controller's election, delete or return all Personal Data and delete existing copies, unless applicable law requires retention.

3.8 **Audit.** The Processor shall make available to the Controller all information reasonably necessary to demonstrate compliance with this DPA and, upon reasonable notice (not less than 30 days), permit and contribute to audits conducted by the Controller or a third-party auditor mandated by the Controller, at the Controller's cost.

---

## 4. Controller Obligations

4.1 The Controller represents and warrants that it has a lawful basis for processing Personal Data and for instructing the Processor to process Personal Data on its behalf.

4.2 The Controller is responsible for ensuring that data subjects have been informed about processing in accordance with applicable Data Protection Laws.

---

## 5. International Transfers

5.1 Personal Data processed under this DPA may be transferred to and processed in countries outside the Controller's jurisdiction, including the United States (Cloudflare infrastructure) and India (Razorpay, primary operations).

5.2 For transfers from the European Economic Area (EEA) or UK to third countries, the parties agree to rely on the Standard Contractual Clauses (SCCs) published by the European Commission (2021/914) or the UK International Data Transfer Agreement (IDTA) as applicable, which are incorporated by reference.

5.3 The Controller may request copies of applicable transfer mechanisms by contacting privacy@cyberdudebivash.in.

---

## 6. Liability and Indemnification

6.1 Each party's liability under this DPA is subject to the limitations and exclusions set out in the Principal Agreement.

6.2 If a party is held liable for a data protection breach that is the other party's fault, the first party may recover from the other party the portion of the liability attributable to the other party's fault.

---

## 7. Term and Termination

7.1 This DPA is effective from the Effective Date and continues until termination of the Principal Agreement.

7.2 Upon termination, the obligations under Clause 3.7 (deletion) apply.

---

## 8. General

8.1 **Governing law.** This DPA is governed by the laws of India, without prejudice to the mandatory provisions of any applicable Data Protection Law.

8.2 **Order of precedence.** In the event of a conflict between this DPA and the Principal Agreement regarding data protection, this DPA shall prevail.

8.3 **Entire agreement on data protection.** This DPA constitutes the entire agreement between the parties on the subject matter of data protection and supersedes all prior agreements.

---

## Signatures

**For the Controller:**

Name: ___________________________
Title: ___________________________
Date:  ___________________________
Signature: _______________________

**For CYBERDUDEBIVASH Pvt Ltd (Processor):**

Name: Bivash Kumar Nayak
Title: Founder & Data Protection Officer
Date:  ___________________________
Signature: _______________________

---

*For executed copies or questions, contact privacy@cyberdudebivash.in*

---

> **Note to reviewer:** This is a template DPA for enterprise customers. Before execution, have legal counsel review it against the specific jurisdiction and requirements of the enterprise customer. This template follows standard DPA structure for GDPR/DPDP Act compliance but is not a substitute for legal advice.
