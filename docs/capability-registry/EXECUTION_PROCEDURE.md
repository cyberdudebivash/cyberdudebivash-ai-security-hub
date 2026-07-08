# Capability Registry — Execution Procedure

**Status:** Operational SOP for pacing multi-session AI-agent work on the
Capability Registry (`docs/capability-registry/`). This is **not** a new
phase or framework under `docs/ENGINEERING_STANDARDS.md` §12/§13 — the
Standing Engineering Directive (§13, 2026-07-04, final) declared the
governance architecture complete (CEAP/CIP/CORB/CAB/Product Council, no more
phases). This document does not add a phase; it is a runbook for how an
agent session should pace itself while doing CEAP evidence-collection work
(populating the registry), so that work survives session interruption
instead of being silently lost. It answers "how do we run one of these
sessions safely," not "what does the business do next."

## 0. Why this exists

On 2026-07-08, a single session ran the registry-population effort across
Administration, Navigation, Production Readiness, and MASOC — validating,
testing, and committing each domain correctly — then began the Developer
Portal / API Keys domain: it independently re-verified two real bugs in the
prior session's findings, wrote a regression test, and started writing the
registry entries, before hitting a hard usage-limit cutoff mid-task.

The next session's recovery pass found:

- The **MASOC** commit (`977628f1`) existed on a pushed branch
  (`claude/capability-registry-recovery-elpx1n`) but was never merged — the
  branch's PR (#100) had been merged one commit *earlier*, at the Production
  Readiness commit, before MASOC was pushed. The work was real and safe
  (pushed to `origin`), just not yet on `main`, and was recovered with a
  clean `git cherry-pick 977628f1`.
- The **Developer Portal / API Keys** work — two independently-reverified
  bug findings, a regression test, and a partially-written registry
  entry — did not exist anywhere in git, on any branch, local or remote.
  It was never committed. It is not recoverable. It has to be redone from
  scratch.
- A stale local `main` ref (shallow-fetched at container start, before
  PR #100 merged) made an early diff look like *nothing* had been merged
  recently, which would have led to redoing already-shipped work if not
  caught by cross-checking against `git ls-remote origin` directly. See
  §3 — this is now a mandatory recovery step, not an optional check.

Two distinct failure modes, two distinct fixes:

1. **Uncommitted work is not real.** A session narrating "fix verified,
   test written, writing registry entries" is not evidence of anything
   surviving a session boundary — only `git log` / `git ls-remote` is.
   Fix: commit at smaller granularity (see §1) and never let verified,
   working changes sit uncommitted while starting the next unit of work.
2. **Local refs can be stale.** Recovery that trusts a locally-cached
   `main`/`origin/main` without re-fetching can misjudge what's already
   shipped. Fix: §3's recovery checklist re-fetches and checks
   `git ls-remote origin` directly before concluding anything is missing.

## 1. The bounded-wave procedure

Every session that touches the Capability Registry follows this sequence
and stops at the end of it — it does not loop back to step 2 for a second
wave in the same session, regardless of remaining quota:

```
Recover  → verify real git/PR state (§3) before touching anything
Inspect  → read PROGRAM_BOARD.md's remaining-work register + wave plan
Plan     → confirm (or adjust) which ONE wave this session executes
Execute  → discover, map, verify, register — for that wave only
Validate → node scripts/registry/validate.mjs
Test     → full suite (workers: npx vitest run)
Checkpoint → commit, push, append a session-log entry (§2) to PROGRAM_BOARD.md
Stop     → end the session. Do not start the next wave automatically.
```

A **wave** is one domain, or a small group of domains explicitly named
together in `PROGRAM_BOARD.md`'s wave plan (grouped because they're small
and closely related — not as a default). If a domain's investigation turns
up more than expected and threatens to blow past a single session, split it:
commit and checkpoint what's verified so far, record the split in the
session log, and let the next session continue the same domain rather than
also starting a new one.

**Why stop instead of continuing while quota remains:** every session that
kept going until it was cut off by a hard limit has produced exactly one
outcome — the in-flight unit of work was lost (see §0). A session that stops
one wave early loses nothing; a session that stops one wave late loses
whatever wasn't yet committed. There is no version of "keep going" that is
safe against a limit that arrives without warning.

## 2. Checkpoint template

Append this to `PROGRAM_BOARD.md`'s session log (most recent entry first)
at the end of every wave, whether or not the session was cut short:

```markdown
### YYYY-MM-DD — Wave: <name>

- Domains touched: <list>
- Commits: <hashes + one-line description each>
- Validator: <pass/fail + capability count>
- Tests: <files/tests passing, full suite or targeted>
- Findings: <real, independently-verified findings only — mark anything
  carried over from a prior session's narration as UNVERIFIED until
  re-confirmed against actual code>
- Remaining in this domain (if wave was split): <what's left>
- Risks / follow-ups surfaced: <e.g. a live security gap found but not
  fixed in this pass — flag explicitly, don't bury it in a findings list>
- Next recommended wave: <name, from the wave plan>
```

## 3. Recovery checklist (mandatory, before any new work)

Local git state in a fresh container can be shallow, stale, or simply wrong
about what's already shipped. Run all of these — not just `git log`:

1. `git fetch origin <working-branch> <default-branch> --depth 50` — refresh
   both, don't trust whatever was cloned at container start.
2. `git rev-parse HEAD` vs `git rev-parse origin/<default-branch>` — confirm
   which one is actually ahead, don't assume.
3. `git ls-remote origin` — list **every** remote branch directly. Local
   `git branch -a` only shows branches this container already knows about;
   a branch pushed by a prior session (e.g. `claude/*-resume-*`,
   `claude/*-recovery-*`) may exist on the remote without a local tracking
   ref yet.
4. For any candidate branch that looks like prior in-flight work: fetch it,
   then `git merge-base --is-ancestor <default-branch> <candidate>` — if
   true, diff `git diff origin/<default-branch> <candidate> --stat` to see
   exactly what's new (beware squash merges: a candidate branch can look
   "13 commits ahead" by `git log` while only the last commit or two is
   actually new content — verify with `git diff --stat` against the real
   tip, not commit-count).
5. Recover isolated new commits with `git cherry-pick <sha>`, not a full
   branch merge, when the candidate branch's history has diverged from
   `main` due to squash-merges upstream — a merge will try to reconcile
   already-integrated commits that no longer share ancestry and can produce
   spurious conflicts on content that's already identical.
6. Never trust a prior session's narrated summary ("committed X", "fixed Y
   and verified") as evidence by itself. Verify against `git log`,
   `git show`, and the actual file contents. If it isn't in git, it didn't
   happen, no matter how confidently it was described.
7. Only after 1–6: run `node scripts/registry/validate.mjs` and the full
   test suite to confirm a clean starting baseline, *then* proceed to
   Inspect/Plan (§1).

## 4. Where things live

- `docs/capability-registry/PROGRAM_BOARD.md` — current wave status,
  remaining-work register, wave plan, session log. Read this first.
- `docs/capability-registry/PRODUCTION_READINESS_REPORT.md` — generated
  structural numbers (backend/frontend/parity %, gap counts). Never
  hand-edited; regenerate with `node scripts/registry/generate-report.mjs`.
- `docs/capability-registry/SCHEMA.md` — the capability entry schema itself.

## 5. Next-session entry prompt

Paste this (adjusted for whichever wave is next per `PROGRAM_BOARD.md`) as
the task description for the next registry-population session:

> Recovery and continuation of the Capability Registry population effort
> (`docs/capability-registry/`). Read
> `docs/capability-registry/EXECUTION_PROCEDURE.md` and
> `docs/capability-registry/PROGRAM_BOARD.md` in full before doing anything
> else — they are the current source of truth for what's done, what's next,
> and how to pace this session.
>
> Scope for this session: **ONE wave** from the Program Board's proposed
> wave plan. Do not start a second wave in this session even if quota
> remains.
>
> Recovery is mandatory before new work — follow §3 exactly, including
> `git ls-remote origin` (a prior session's stale local `main` nearly caused
> a false "nothing to recover" conclusion; don't repeat that).
>
> When the wave's domain(s) are discovered, verified, registered, validated,
> and tested, commit, push, append a session-log entry to
> `PROGRAM_BOARD.md` (template in `EXECUTION_PROCEDURE.md` §2), update the
> remaining-work register and wave plan, and **stop**.
