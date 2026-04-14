import re

REPO = r"C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub"

with open(REPO + r"\.github\workflows\deploy.yml", "r", encoding="utf-8") as f:
    yml = f.read()

original = yml

# BUG 2: PLATFORM_VERSION 13.0.0 -> 18.0.0
yml = yml.replace('  PLATFORM_VERSION: "13.0.0"', '  PLATFORM_VERSION: "18.0.0"')
print("FIX BUG2:", "OK" if '18.0.0' in yml else "MISS")

# BUG 1: Add --commit-message ASCII-safe to pages deploy
idx = yml.find("wrangler pages deploy frontend")
if idx >= 0:
    cs = yml.rfind("if wrangler", 0, idx)
    ce = yml.find("then", idx) + 4
    old = yml[cs:ce]
    print("OLD BLOCK:", repr(old[:200]))
    new = (
        "# ASCII-only commit msg -- Cloudflare Pages API code 8000111\n"
        "            # rejects non-ASCII unicode chars (em-dashes, special chars)\n"
        '            SAFE_MSG="Deploy v${{ env.PLATFORM_VERSION }} | ${GITHUB_SHA:0:8} | ${{ github.ref_name }}"\n'
        "            if wrangler pages deploy frontend \\\\\n"
        "                --project-name cyberdudebivash-security-hub \\\\\n"
        '                --branch "${{ github.ref_name }}" \\\\\n'
        '                --commit-hash "${{ github.sha }}" \\\\\n'
        '                --commit-message "${SAFE_MSG}" \\\\\n'
        "                --commit-dirty=true; then"
    )
    yml = yml[:cs] + new + yml[ce:]
    print("FIX BUG1: OK")
else:
    print("MISS BUG1 - not found")

with open(REPO + r"\.github\workflows\deploy.yml", "w", encoding="utf-8") as f:
    f.write(yml)

print("Size:", len(original), "->", len(yml))
print("Done.")
