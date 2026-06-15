# Artifact Retention Policy

**Owner:** CYBERDUDEBIVASH PRIVATE LIMITED
**Scope:** `cyberdudebivash-ai-security-hub` repository
**Status:** Authoritative

## Principle

Git tracks **source**, not **artifacts**. Anything that can be regenerated,
downloaded, or built must not live in version control — it bloats every clone,
drifts from the live tree, and slows CI.

## Rules

| Class | Examples | Where it belongs |
|-------|----------|------------------|
| Source archives / repo snapshots | `*.zip` of the repo, `*-main.zip` | **Never committed** (ignored via `.gitignore`). Use a git tag/release. |
| Build output | `dist/`, `build/`, `.wrangler/`, bundled JS | CI build step / artifact storage |
| Dependency trees | `node_modules/`, Python venvs, `__pycache__/` | Reinstalled from lockfiles (`.gitignore`) |
| Generated reports | scan output, `tools_output/` | CI artifacts or object storage |
| Office deliverables | `*.pptx`, `*.docx` board decks | Tracked **only** if they are an intentional, current deliverable. Stale copies must be removed. Never duplicate the same file across directories. |

## Enforcement

- `.gitignore` blocks `*.zip`, `node_modules/`, `__pycache__/`, `tools_output/`,
  `workspace/`, and named stale reports.
- Removed in the stabilization pass: an 11 MB accidental repo self-snapshot
  (`cyberdudebivash-ai-security-hub-main (4).zip`, 1011 files) and a duplicated
  `workers/CYBERDUDEBIVASH_PRODUCTION_AUDIT_v2.pptx`.
- Reviewers: reject any PR that adds a binary > 1 MB unless it is a required,
  non-regenerable, single-source asset.

## Releasing a snapshot

Do **not** commit a zip. Instead:

```bash
git tag -a vX.Y.Z -m "release"
git push origin vX.Y.Z
# GitHub auto-produces source archives for the tag.
```
