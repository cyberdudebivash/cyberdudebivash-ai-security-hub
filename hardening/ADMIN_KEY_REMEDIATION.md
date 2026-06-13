# ADMIN_KEY Remediation — P1 Secret Exposure

**Finding:** `ADMIN_KEY` was stored as a **plaintext `[vars]` value** in `workers/wrangler.toml` — committed to git history, printed in `wrangler deploy` output, and visible in the Cloudflare dashboard. It gates admin / MYTHOS functionality, so it is a privileged credential.

**Severity:** P1. Treat the old key as **compromised** (it is in git history and may be on public GitHub). Rotation — not just deletion — is the real fix.

---

## Fix in 2 parts

### Part A — Rotate + migrate to a secret (run the script)

```powershell
cd C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub
powershell -ExecutionPolicy Bypass -File hardening\rotate-admin-key.ps1
```

The script (safe ordering, no admin-auth gap):
1. Generates a **new strong key on your machine** (never transmitted) and shows it once — save it in your password manager.
2. `wrangler secret put ADMIN_KEY` — sets it as an **encrypted secret** (live immediately).
3. Removes the plaintext `ADMIN_KEY` line from `wrangler.toml` (keeps a `.bak`).
4. Commits, pushes, and `wrangler deploy`.
5. `wrangler secret list` to verify.

**No code change needed** — secrets bind as `env.ADMIN_KEY` exactly like the var did. Any of *your* admin tooling that sends the key must be updated to the new value.

### Part B — Purge the old key from git history (do this if the repo is/was public)

Deleting the line in Part A does **not** remove the old value from past commits. Rotation already invalidated it, but purge history to remove the secret artifact:

```bash
# 1. Backup the repo first (clone a mirror)
cd ..
git clone --mirror https://github.com/cyberdudebivash/cyberdudebivash-ai-security-hub.git backup-mirror.git

# 2. Install git-filter-repo (preferred over BFG)
pip install git-filter-repo --break-system-packages

# 3. From the working repo, replace the old secret everywhere in history.
#    Put the OLD (now-rotated) key value where shown — do NOT commit this file.
cd cyberdudebivash-ai-security-hub
printf '<PASTE_OLD_ADMIN_KEY_HERE>==>REDACTED_ROTATED_KEY\n' > ../replace.txt
git filter-repo --replace-text ../replace.txt --force

# 4. Re-add origin (filter-repo drops it) and force-push the rewritten history
git remote add origin https://github.com/cyberdudebivash/cyberdudebivash-ai-security-hub.git
git push --force --all
git push --force --tags

# 5. Delete ../replace.txt afterwards
```

> ⚠️ History rewrite is destructive and changes commit hashes. Coordinate with any collaborators (they must re-clone). The mirror backup in step 1 is your rollback.

---

## Validation checklist

- [ ] `wrangler secret list` (in `workers/`) shows **ADMIN_KEY** as a secret.
- [ ] `grep -i ADMIN_KEY workers/wrangler.toml` returns **nothing**.
- [ ] An admin endpoint accepts the **new** key and rejects the old one.
- [ ] (Public repo) `git log -S 'cdb-mythos' --oneline` returns **nothing** after the history purge.
- [ ] GitHub → Settings → confirm repo visibility; if it was public, also rotate anything else that shared this machine's logs.

## Rollback

- Part A: restore `workers/wrangler.toml.bak`, `git revert` the commit, redeploy. (The secret can stay — it's harmless.)
- Part B: restore from `backup-mirror.git` and force-push it back.

## Prevention (so this can't recur)

- Add a secret-scanner to CI (e.g., `gitleaks`) as a required gate — pairs with `hardening/test.yml`.
- Keep all credentials as `wrangler secret put` (never `[vars]`). Vars are for non-sensitive config only.
- Enable GitHub **Secret Scanning + Push Protection** on the repo.
