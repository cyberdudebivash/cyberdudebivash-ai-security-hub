"""
CYBERDUDEBIVASH AI Security Hub — Content Automation Engine
============================================================
Automated pipeline:
  1. Pull latest CVEs / threat intel from Sentinel APEX feed
  2. Generate blog post + LinkedIn post + Telegram alert
  3. Publish to platform (via Workers API)
  4. Auto-post to LinkedIn (optional)
  5. Send Telegram broadcast

Usage:
  python automation/content_engine.py
  python automation/content_engine.py --mode cve_alert
  python automation/content_engine.py --mode blog
  python automation/content_engine.py --mode linkedin

Environment variables required:
  OPENAI_API_KEY         — for AI-generated content
  WORKERS_API_URL        — e.g. https://cyberdudebivash-security-hub.workers.dev
  WORKERS_API_KEY        — your platform API key (ENTERPRISE tier)
  TELEGRAM_BOT_TOKEN     — for Telegram broadcast
  TELEGRAM_CHANNEL_ID    — Sentinel APEX channel ID
  LINKEDIN_ACCESS_TOKEN  — LinkedIn API v2 token (optional)
  LINKEDIN_AUTHOR_URN    — LinkedIn person URN urn:li:person:XXXX (optional)
"""

import os
import json
import time
import argparse
import requests
from datetime import datetime, timezone

# ── Config ────────────────────────────────────────────────────────────────────
WORKERS_API_URL    = os.getenv("WORKERS_API_URL", "https://cyberdudebivash-security-hub.workers.dev")
WORKERS_API_KEY    = os.getenv("WORKERS_API_KEY", "")
OPENAI_API_KEY     = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL       = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHANNEL   = os.getenv("TELEGRAM_CHANNEL_ID", "")
LINKEDIN_TOKEN     = os.getenv("LINKEDIN_ACCESS_TOKEN", "")
LINKEDIN_AUTHOR    = os.getenv("LINKEDIN_AUTHOR_URN", "")

PLATFORM_NAME   = "CYBERDUDEBIVASH AI Security Hub"
PLATFORM_URL    = "https://cyberdudebivash.in"
GUMROAD_URL     = "https://cyberdudebivash.gumroad.com"
CONTACT_EMAIL   = "bivash@cyberdudebivash.com"

HEADERS_API = {
    "x-api-key":    WORKERS_API_KEY,
    "Content-Type": "application/json",
}

# ── 1. Fetch threat intel from platform API ───────────────────────────────────
def fetch_threat_intel(limit: int = 5) -> list[dict]:
    """Pull top critical/high CVEs from Sentinel APEX."""
    try:
        url = f"{WORKERS_API_URL}/api/threat-intel/cves"
        r = requests.get(url, headers=HEADERS_API, timeout=15,
                         params={"limit": limit, "severity": "CRITICAL,HIGH"})
        if r.status_code == 200:
            data = r.json()
            return data.get("cves", data.get("results", []))[:limit]
    except Exception as e:
        print(f"[fetch_threat_intel] Warning: {e}")

    # Fallback: public NVD recent CVEs
    try:
        nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        r = requests.get(nvd_url, timeout=15,
                         params={"resultsPerPage": limit, "noRejected": "", "cvssV3Severity": "CRITICAL"})
        if r.status_code == 200:
            items = r.json().get("vulnerabilities", [])
            return [
                {
                    "cve_id":      v["cve"]["id"],
                    "description": v["cve"]["descriptions"][0]["value"][:300],
                    "cvss_score":  v["cve"].get("metrics", {})
                                    .get("cvssMetricV31", [{}])[0]
                                    .get("cvssData", {}).get("baseScore", 9.0),
                    "severity":    "CRITICAL",
                    "published":   v["cve"].get("published", ""),
                }
                for v in items[:limit]
            ]
    except Exception as e:
        print(f"[fetch_threat_intel] NVD fallback failed: {e}")

    # Static fallback for demo/offline mode
    return [
        {
            "cve_id":      "CVE-2025-DEMO1",
            "description": "Critical remote code execution vulnerability in widely-deployed enterprise middleware.",
            "cvss_score":  9.8,
            "severity":    "CRITICAL",
            "published":   datetime.now(timezone.utc).isoformat(),
        }
    ]


# ── 2. AI Content Generation ──────────────────────────────────────────────────
def generate_with_ai(prompt: str, max_tokens: int = 800) -> str:
    """Call OpenAI to generate content."""
    if not OPENAI_API_KEY:
        return _template_fallback(prompt)

    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
            json={
                "model":      OPENAI_MODEL,
                "max_tokens": max_tokens,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are the chief security intelligence officer at CYBERDUDEBIVASH AI Security Hub, "
                            "a cutting-edge cybersecurity SaaS platform. Write authoritative, technical-but-accessible "
                            "content. Always include a subtle CTA to the platform. Be concise, impactful, professional."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.7,
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"[generate_with_ai] OpenAI error: {e}")
        return _template_fallback(prompt)


def _template_fallback(prompt: str) -> str:
    """Structured template when OpenAI is unavailable."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return (
        f"[{ts}] CYBERDUDEBIVASH Security Intelligence Update\n\n"
        "Our Sentinel APEX threat intelligence engine has detected critical vulnerabilities "
        "affecting enterprise environments. Immediate patching recommended.\n\n"
        f"Stay ahead of threats: {PLATFORM_URL}\n"
        f"Full reports from ₹199 — {PLATFORM_URL}/#pricing"
    )


# ── 3. Blog Post Generator ────────────────────────────────────────────────────
def generate_blog_post(cves: list[dict]) -> dict:
    """Generate a full blog post from CVE data."""
    cve_summary = "\n".join([
        f"- {c['cve_id']} (CVSS {c.get('cvss_score','N/A')}): {c['description'][:150]}..."
        for c in cves
    ])

    prompt = f"""
Write a professional cybersecurity blog post (800-1000 words) for the CYBERDUDEBIVASH AI Security Hub.

Title format: "Sentinel APEX Alert: [Month] [Year] Critical Threat Briefing"

Include these sections:
1. Executive Summary (2-3 sentences, C-suite level)
2. Critical CVEs This Week (use the data below)
3. Attack Vector Analysis (how attackers exploit these)
4. MITRE ATT&CK Mapping (relevant tactics/techniques)
5. Remediation Priority Matrix (HIGH/MEDIUM/LOW)
6. Why AI-Powered Security Matters (subtle platform CTA)

CVE Data:
{cve_summary}

End with: "Run a free scan at {PLATFORM_URL} — reports from ₹199"
Use markdown formatting with headers (##), bold for CVE IDs, and bullet points.
"""

    body = generate_with_ai(prompt, max_tokens=1200)
    ts   = datetime.now(timezone.utc)
    slug = f"sentinel-apex-{ts.strftime('%B-%Y').lower()}-threat-briefing"

    return {
        "type":           "blog",
        "title":          f"Sentinel APEX Alert: {ts.strftime('%B %Y')} Critical Threat Briefing",
        "slug":           slug,
        "body_md":        body,
        "tags":           "threat-intel,cve,sentinel-apex,cybersecurity",
        "excerpt":        body[:200].replace("\n", " ") + "...",
        "cve_count":      len(cves),
        "generated_at":   ts.isoformat(),
    }


# ── 4. LinkedIn Post Generator ────────────────────────────────────────────────
def generate_linkedin_post(cves: list[dict], blog_title: str = "") -> str:
    """Generate a LinkedIn-optimised post (max 3000 chars)."""
    top_cve     = cves[0] if cves else {}
    cve_id      = top_cve.get("cve_id", "Critical CVE")
    cvss_score  = top_cve.get("cvss_score", "9.8")
    description = top_cve.get("description", "")[:120]

    prompt = f"""
Write a LinkedIn post (max 280 words) for CYBERDUDEBIVASH AI Security Hub.

Context:
- Highlight a critical CVE: {cve_id} (CVSS {cvss_score})
- Brief: {description}
- Platform: {PLATFORM_URL}

Format:
- Start with a hook (one powerful sentence)
- 3-4 short paragraphs max
- 5 relevant hashtags at the end
- End with: "Free scan → {PLATFORM_URL}"
- Professional but energetic tone
- No fluff, maximum signal

Blog title for reference: {blog_title}
"""

    return generate_with_ai(prompt, max_tokens=400)


# ── 5. Telegram Alert Generator ───────────────────────────────────────────────
def generate_telegram_alert(cves: list[dict]) -> str:
    """Generate a Telegram-formatted alert message."""
    lines = [
        "🛡 *SENTINEL APEX THREAT ALERT*",
        f"📅 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"🔴 *{len(cves)} Critical/High CVEs Detected*",
        "",
    ]

    for cve in cves[:3]:
        cvss   = cve.get("cvss_score", "N/A")
        sev    = cve.get("severity", "HIGH")
        icon   = "🔴" if sev == "CRITICAL" else "🟠"
        desc   = cve.get("description", "")[:80]
        lines += [
            f"{icon} *{cve['cve_id']}* — CVSS {cvss}",
            f"   _{desc}_",
            "",
        ]

    lines += [
        "━━━━━━━━━━━━━━━━━━━━━",
        f"🔍 Run Free Scan → {PLATFORM_URL}",
        f"📊 Full Reports from ₹199",
        f"🛒 Tools & Reports → {GUMROAD_URL}",
        "",
        "#SentinelAPEX #ThreatIntel #CyberSecurity #CVE",
    ]

    return "\n".join(lines)


# ── 6. Publish to Platform Content API ───────────────────────────────────────
def publish_to_platform(post: dict) -> bool:
    """POST content to /api/content endpoint."""
    if not WORKERS_API_KEY:
        print("[publish] No API key — skipping platform publish")
        return False

    try:
        url = f"{WORKERS_API_URL}/api/content"
        r   = requests.post(url, headers=HEADERS_API,
                            json={"type": post["type"], "title": post["title"],
                                  "body_md": post["body_md"], "tags": post.get("tags", "")},
                            timeout=20)
        if r.status_code in (200, 201):
            print(f"[publish] Blog published: {post['slug']}")
            return True
        print(f"[publish] Failed {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"[publish] Error: {e}")
    return False


# ── 7. Send Telegram Broadcast ────────────────────────────────────────────────
def send_telegram(message: str) -> bool:
    """Send message to Telegram channel."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHANNEL:
        print("[telegram] Credentials not set — skipping")
        return False

    try:
        url  = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        resp = requests.post(url, json={
            "chat_id":    TELEGRAM_CHANNEL,
            "text":       message,
            "parse_mode": "Markdown",
        }, timeout=15)
        if resp.status_code == 200:
            print("[telegram] Alert sent successfully")
            return True
        print(f"[telegram] Failed: {resp.text[:200]}")
    except Exception as e:
        print(f"[telegram] Error: {e}")
    return False


# ── 8. Post to LinkedIn ───────────────────────────────────────────────────────
def post_to_linkedin(content: str) -> bool:
    """Post to LinkedIn via v2 API."""
    if not LINKEDIN_TOKEN or not LINKEDIN_AUTHOR:
        print("[linkedin] Credentials not set — skipping")
        return False

    try:
        payload = {
            "author":          LINKEDIN_AUTHOR,
            "lifecycleState":  "PUBLISHED",
            "specificContent": {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {"text": content},
                    "shareMediaCategory": "NONE",
                }
            },
            "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"},
        }

        resp = requests.post(
            "https://api.linkedin.com/v2/ugcPosts",
            headers={
                "Authorization":  f"Bearer {LINKEDIN_TOKEN}",
                "Content-Type":   "application/json",
                "X-Restli-Protocol-Version": "2.0.0",
            },
            json=payload,
            timeout=20,
        )

        if resp.status_code in (200, 201):
            print(f"[linkedin] Post published: {resp.json().get('id','')}")
            return True
        print(f"[linkedin] Failed {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        print(f"[linkedin] Error: {e}")
    return False


# ── 9. Save to local logs ────────────────────────────────────────────────────
def save_output(data: dict, prefix: str = "content"):
    """Save generated content to logs/."""
    os.makedirs("logs", exist_ok=True)
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = f"logs/{prefix}_{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[save] Output saved → {path}")
    return path


# ── MAIN ORCHESTRATION ────────────────────────────────────────────────────────
def run_cve_alert():
    print("\n[ENGINE] Mode: CVE Alert Pipeline")
    print("─" * 50)

    # Step 1: Fetch intel
    print("[1/5] Fetching threat intel...")
    cves = fetch_threat_intel(limit=5)
    print(f"      Found {len(cves)} CVEs")

    # Step 2: Generate blog
    print("[2/5] Generating blog post...")
    blog = generate_blog_post(cves)

    # Step 3: Generate LinkedIn post
    print("[3/5] Generating LinkedIn post...")
    linkedin_text = generate_linkedin_post(cves, blog["title"])

    # Step 4: Generate Telegram alert
    print("[4/5] Generating Telegram alert...")
    telegram_text = generate_telegram_alert(cves)

    # Step 5: Publish & broadcast
    print("[5/5] Publishing & broadcasting...")
    results = {
        "blog_published":      publish_to_platform(blog),
        "telegram_sent":       send_telegram(telegram_text),
        "linkedin_posted":     post_to_linkedin(linkedin_text),
    }

    output = {
        "mode":          "cve_alert",
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "cves_processed": len(cves),
        "blog":          blog,
        "linkedin_post": linkedin_text,
        "telegram_msg":  telegram_text,
        "results":       results,
    }

    save_output(output, prefix="cve_alert")
    print("\n[ENGINE] Pipeline complete:")
    for k, v in results.items():
        status = "✅" if v else "⚠️ (skipped/failed)"
        print(f"  {status} {k}")
    print()


def run_blog_only():
    print("\n[ENGINE] Mode: Blog Generation Only")
    cves = fetch_threat_intel(limit=8)
    blog = generate_blog_post(cves)
    save_output(blog, prefix="blog")
    print(f"[blog] Title: {blog['title']}")
    print(f"[blog] Length: {len(blog['body_md'])} chars")


def run_linkedin_only():
    print("\n[ENGINE] Mode: LinkedIn Post Only")
    cves = fetch_threat_intel(limit=3)
    text = generate_linkedin_post(cves)
    print("\n──── LINKEDIN POST ────")
    print(text)
    print("─────────────────────\n")
    result = post_to_linkedin(text)
    if result:
        print("✅ LinkedIn post published!")
    else:
        print("⚠️ LinkedIn not published (check credentials or save manually above)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CYBERDUDEBIVASH Content Automation Engine")
    parser.add_argument("--mode", choices=["cve_alert", "blog", "linkedin"],
                        default="cve_alert", help="Content mode to run")
    args = parser.parse_args()

    print("=" * 60)
    print("  CYBERDUDEBIVASH AI Security Hub — Content Engine")
    print(f"  Platform: {PLATFORM_URL}")
    print("=" * 60)

    if args.mode == "cve_alert":
        run_cve_alert()
    elif args.mode == "blog":
        run_blog_only()
    elif args.mode == "linkedin":
        run_linkedin_only()
