# Customer Success Playbook

> Phase IX deliverable. Benchmarks come from measured evidence: the Phase VIII
> 100-organization simulation and the Phase IX live-production RC journeys.
> No aspirational numbers.

## Value milestones (measured baselines)

| Milestone | Definition | Measured baseline |
|-----------|-----------|-------------------|
| Time to first value | signup → first scan result | p50 406 ms / p95 778 ms (100 orgs) |
| Time to first report | signup → downloadable report | same session, seconds |
| Time to first AI insight | signup → `/api/ai/analyze` result | same session (FREE-available) |
| Time to team value | org created + members invited + org dashboard viewed | same day (all-API, no engineering intervention) |
| Time to production | integrated into customer workflow (keys, webhooks, SIEM export) | customer-dependent; see `IMPLEMENTATION_PLAYBOOK.md` |

If a customer has not scanned within day one, something is wrong —
onboarding is measured in seconds, not weeks. Investigate, don't wait.

## Adoption path by segment

- **Self-serve / FREE:** full core loop (scan → report → AI analyze) with
  honest limits. Success = habitual scanning; the 429 upgrade prompt is the
  expansion signal (reason + upgrade path verified graceful).
- **SMB / MSSP paid:** volume tiers, premium `/api/v1`, multi-user orgs.
  First payment and first SSO round-trip are pilot events — shepherd them
  personally and record the evidence (they are current GA gates).
- **Regulated enterprise:** do not oversell — attestation gaps (SOC 2,
  external SLA) are openly disclosed (`CUSTOMER_OBJECTION_REGISTER.md`
  OBJ-05). Position transparency as the trust posture; scope pilots to
  non-regulated data.

## Renewal & expansion signals

| Signal | Where to see it | Play |
|--------|-----------------|------|
| Scan cadence sustained/rising | org dashboard 30-day aggregates | QBR with the customer's own posture trend |
| Throttle hits rising | 429 rates | Right-size tier before frustration (OBJ-06) |
| Members growing / roles diversifying | org membership | Introduce RBAC best practice, admin training |
| Report downloads recurring | report activity | Executive-report habit = renewal anchor |
| API usage from CI/pipelines | key usage | Deepen integration; premium surface upsell |

## Objection handling

The living instrument is `CUSTOMER_OBJECTION_REGISTER.md` — every objection
gets persona, business impact, classification, corrective action, and
resolution evidence. Repeat objections escalate to the Product Council
(`docs/ENGINEERING_STANDARDS.md` §7–8). Never argue with an objection the
register marks OPEN — acknowledge it and show the disclosed mitigation.

## The success rule (permanent, §8)

A capability succeeds only when a representative customer can discover it,
understand it, configure it, use it effectively, and achieve measurable
business value with an acceptable operational experience. Technical
completeness is not success.
