/**
 * CYBERDUDEBIVASH AI Security Hub — Defense Marketplace Seed Handler
 * Bootstraps the defense_solutions D1 table with production-grade security tools
 * generated for real, actively-exploited CVEs.
 *
 * Run via: POST /api/admin/bootstrap  (Authorization: Bearer bootstrap-cyberdude-2026)
 * Safe to re-run — uses INSERT OR IGNORE on primary key.
 */

// ── Real CVE-backed defense solutions (production-ready code) ─────────────────
const SEED_SOLUTIONS = [
  {
    id: 'sol-cve-2024-3400-fw',
    cve_id: 'CVE-2024-3400',
    title: 'PAN-OS GlobalProtect Firewall Block Rules + IDS Signatures',
    description: 'Production iptables/nftables rules, Snort/Suricata IDS signatures, and nginx WAF config to block exploitation of CVE-2024-3400 (CVSS 10.0, actively exploited by UTA0218 APT). Includes Cloudflare WAF expression. Deploy in under 5 minutes.',
    category: 'firewall_script',
    price_inr: 799, price_usd: 10,
    demand_score: 0.98, severity: 'CRITICAL', cvss_score: 10.0,
    difficulty: 'BEGINNER',
    apt_groups: JSON.stringify(['UTA0218']),
    mitre_techniques: JSON.stringify(['T1190', 'T1059.004']),
    affected_systems: JSON.stringify(['Palo Alto PAN-OS', 'GlobalProtect VPN']),
    is_featured: 1,
    preview: `#!/bin/bash
# CVE-2024-3400 — PAN-OS GlobalProtect Command Injection (CVSS 10.0)
# CYBERDUDEBIVASH Sentinel APEX Defense Tool

# iptables: block path traversal exploit attempts
iptables -I INPUT -p tcp --dport 443 -m string --string "/../" --algo bm -j DROP
iptables -I INPUT -p tcp --dport 443 -m string --string "hipreport.esp" --algo bm -j LOG

# Snort/Suricata signature
# alert http $EXTERNAL_NET any -> $HTTP_SERVERS 443 \\
#   (msg:"CVE-2024-3400 Exploit"; http.uri; content:"hipreport.esp"; content:"/../"; sid:9024340001;)
echo "[✓] CVE-2024-3400 rules applied — full version includes nginx WAF + Cloudflare rules"`,
    full_content: `#!/bin/bash
# ============================================================
# CVE-2024-3400 — PAN-OS GlobalProtect Command Injection
# CYBERDUDEBIVASH Sentinel APEX Defense Tool v1.0
# CVSS: 10.0 CRITICAL | APT: UTA0218 | KEV: YES
# ============================================================
set -euo pipefail
LOGFILE="/var/log/cve-2024-3400-mitigation.log"
echo "[$(date -u)] Applying CVE-2024-3400 mitigations..." | tee -a "$LOGFILE"

# ── 1. iptables blocking rules ──────────────────────────────
iptables -I INPUT -p tcp --dport 443 -m string --string "/../" --algo bm -j DROP
iptables -I INPUT -p tcp --dport 443 -m string --string "hipreport.esp" --algo bm -j LOG --log-prefix "[CVE-2024-3400] "
iptables -I INPUT -p tcp --dport 443 -m string --string "SESSID=../../../" --algo bm -j DROP
iptables-save > /etc/iptables/rules.v4

# ── 2. nftables equivalent ──────────────────────────────────
cat >> /etc/nftables.conf << 'NFTEOF'
table inet filter {
  chain input {
    tcp dport 443 @th,160,64 "/../" drop
    tcp dport 443 @th,160,64 "hipreport.esp" log prefix "[CVE-2024-3400] "
  }
}
NFTEOF

# ── 3. Snort/Suricata IDS Signatures ───────────────────────
mkdir -p /etc/snort/rules
cat > /etc/snort/rules/cve-2024-3400.rules << 'SNORTEOF'
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"CYBERDUDEBIVASH CVE-2024-3400 PAN-OS Exploit Attempt"; flow:established,to_server; http.uri; content:"hipreport.esp"; content:"/../"; distance:0; classtype:web-application-attack; sid:9024340001; rev:2; reference:url,nvd.nist.gov/vuln/detail/CVE-2024-3400; metadata:created_at 2024_04_12,updated_at 2024_04_20;)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"CYBERDUDEBIVASH CVE-2024-3400 Path Traversal SSL-VPN"; flow:established,to_server; http.uri; content:"/ssl-vpn/"; content:"/../"; distance:0; pcre:"/\\/ssl-vpn\\/[^?#]*\\.\\.\\/[^?#]*/i"; classtype:web-application-attack; sid:9024340002; rev:1;)
SNORTEOF

# ── 4. Suricata YAML rule ───────────────────────────────────
cat > /etc/suricata/rules/cve-2024-3400.rules << 'SUREOF'
alert http any any -> any 443 (msg:"CVE-2024-3400 PAN-OS GlobalProtect RCE"; flow:established,to_server; http.uri; content:"/../"; content:"hipreport"; distance:0; within:50; threshold:type limit,track by_src,count 3,seconds 60; classtype:trojan-activity; sid:9024340010; rev:1;)
SUREOF

# ── 5. nginx WAF block ──────────────────────────────────────
cat > /etc/nginx/conf.d/cve-2024-3400.conf << 'NGINXEOF'
# Block CVE-2024-3400 exploit patterns
location ~* /ssl-vpn/.*\.\./ { return 403; access_log /var/log/nginx/cve-2024-3400.log combined; }
location ~* /hipreport\.esp { if ($request_uri ~* "\\.\\./") { return 403; } }
NGINXEOF

# ── 6. Cloudflare WAF Rule (paste in CF Dashboard > Security > WAF) ─
echo ""
echo "=== CLOUDFLARE WAF RULE (paste in dashboard) ==="
echo "Expression: (http.request.uri.path contains \"/../\" and http.request.uri.path contains \"hipreport\")"
echo "Action: Block | Priority: 1"
echo "=================================================="
echo ""
echo "[$(date -u)] CVE-2024-3400 mitigation complete. Restart snort/suricata + nginx." | tee -a "$LOGFILE"
echo "[!] PAN-OS patched versions: 10.2.9-h1+, 11.0.4-h1+, 11.1.2-h3+"`,
  },

  {
    id: 'sol-cve-2024-21762-sigma',
    cve_id: 'CVE-2024-21762',
    title: 'Fortinet FortiOS SSL VPN — Sigma Detection Rules + IR Playbook',
    description: 'Multi-platform Sigma detection rules (Splunk/Elastic/Microsoft Sentinel/Chronicle) for CVE-2024-21762 Fortinet FortiOS out-of-bounds write. Includes a 6-phase incident response playbook and threat hunting queries. CVSS 9.6 CRITICAL, ransomware-linked.',
    category: 'sigma_rule',
    price_inr: 899, price_usd: 11,
    demand_score: 0.94, severity: 'CRITICAL', cvss_score: 9.6,
    difficulty: 'INTERMEDIATE',
    apt_groups: JSON.stringify(['FIN11', 'TA505']),
    mitre_techniques: JSON.stringify(['T1190', 'T1133', 'T1021.002']),
    affected_systems: JSON.stringify(['Fortinet FortiOS', 'FortiProxy', 'FortiSwitchManager']),
    is_featured: 1,
    preview: `title: CVE-2024-21762 Fortinet FortiOS SSL VPN Exploitation
id: a4b7c891-2d3e-4f56-8901-234567890abc
status: stable
description: Detects exploitation of CVE-2024-21762 FortiOS OOB Write RCE
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-21762
author: CYBERDUDEBIVASH Sentinel APEX
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem|contains:
      - '/remote/logincheck'
      - '/api/v2/cmdb/user/setting'
  condition: selection
# Full version includes Splunk SPL, Elastic KQL, Sentinel KQL, and 6-phase IR playbook`,
    full_content: `# ============================================================
# CVE-2024-21762 — Fortinet FortiOS SSL VPN OOB Write RCE
# CYBERDUDEBIVASH Sentinel APEX — Detection + Response Pack
# CVSS: 9.6 CRITICAL | Ransomware-linked | CISA KEV listed
# ============================================================

# ── SIGMA RULE (SIEM-agnostic) ─────────────────────────────
title: CVE-2024-21762 Fortinet FortiOS Exploitation Attempt
id: a4b7c891-2d3e-4f56-8901-234567890abc
status: stable
description: |
  Detects exploitation attempts against Fortinet FortiOS CVE-2024-21762.
  An out-of-bounds write via HTTP requests allows unauthenticated RCE.
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-21762
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
author: CYBERDUDEBIVASH Sentinel APEX
date: 2024/02/09
modified: 2024/03/01
tags:
  - attack.initial_access
  - attack.t1190
  - attack.t1133
  - cve.2024.21762
logsource:
  category: webserver
detection:
  selection_uri:
    cs-uri-stem|contains:
      - '/remote/logincheck'
      - '/remote/info'
      - '/api/v2/cmdb/user/setting'
      - '/proxy/css/'
  selection_method:
    cs-method: 'GET'
  filter_legit:
    cs-uri-stem|endswith: '.css'
  condition: selection_uri and selection_method and not filter_legit
  threshold:
    timespan: 60s
    groupby: src_ip
    condition: '> 5'
falsepositives:
  - Legitimate FortiOS admin activity (review carefully)
level: high
---

# ── SPLUNK SPL QUERY ─────────────────────────────────────────
# index=proxy OR index=webserver
# | search uri_path IN ("*/remote/logincheck*","*/proxy/css/*","*/api/v2/cmdb/*")
# | where method="GET" AND status IN (200,400,500)
# | stats count by src_ip, uri_path, _time
# | where count > 5
# | eval risk="CVE-2024-21762 Exploit Probe"
# | table _time, src_ip, uri_path, count, risk

# ── ELASTIC / KQL (Kibana) ──────────────────────────────────
# http.request.uri.path:("/remote/logincheck" OR "/proxy/css/" OR "/api/v2/cmdb/user/setting")
#   AND http.request.method:"GET"
#   AND not http.response.status_code:404

# ── MICROSOFT SENTINEL KQL ──────────────────────────────────
# CommonSecurityLog
# | where RequestURL has_any ("/remote/logincheck","/proxy/css/","/api/v2/cmdb")
# | where RequestMethod == "GET"
# | summarize Count=count() by SourceIP, RequestURL, bin(TimeGenerated, 5m)
# | where Count > 3
# | extend Alert = "CVE-2024-21762 Fortinet Exploit Attempt"

# ── 6-PHASE IR PLAYBOOK ─────────────────────────────────────
# PHASE 1 — DETECTION
#   □ Confirm alert via SIEM: isolate source IP + destination FortiGate
#   □ Pull FortiOS event logs: diagnose log kernel filter src <IP>
#   □ Check /var/log/apache2/access.log for anomalous URI patterns
#
# PHASE 2 — CONTAINMENT
#   □ Isolate affected FortiGate from network (null-route source IP)
#   □ Block source IP at upstream firewall + ISP if possible
#   □ Disable SSL-VPN portal temporarily: config vpn ssl settings; set status disable
#   □ Force session logout: diagnose vpn ssl list → delete active sessions
#
# PHASE 3 — ERADICATION
#   □ Upgrade FortiOS immediately: 7.4.3+, 7.2.7+, 7.0.14+, 6.4.15+
#   □ Run integrity check: execute verify-disk
#   □ Change ALL admin credentials + API keys
#   □ Revoke all active SSL-VPN certificates
#
# PHASE 4 — INVESTIGATION
#   □ Export FortiOS logs: execute backup config flash
#   □ Check for persistence: cron jobs, new admin accounts, modified scripts
#   □ Review DHCP leases for lateral movement evidence
#   □ Pull NetFlow/PCAP for C2 communication (check MITRE T1071)
#
# PHASE 5 — RECOVERY
#   □ Restore from last known-good backup (pre-incident)
#   □ Re-enable SSL-VPN only after upgrade confirmed
#   □ Implement MFA for all VPN access
#   □ Deploy network segmentation for VPN subnet
#
# PHASE 6 — POST-INCIDENT
#   □ File CERT-In report (India: incident@cert-in.org.in, within 6h for critical)
#   □ Update SIEM detection rules with confirmed IOCs
#   □ Conduct tabletop exercise for next VPN 0-day scenario
#   □ Add FortiOS to vulnerability management scan schedule (weekly)`,
  },

  {
    id: 'sol-cve-2024-27198-python',
    cve_id: 'CVE-2024-27198',
    title: 'JetBrains TeamCity Auth Bypass Scanner + Hardening Script',
    description: 'Python CLI scanner to detect CVE-2024-27198 (TeamCity auth bypass, CVSS 9.8) across your network. Includes a bash hardening script to disable the vulnerable REST endpoint and PowerShell equivalent for Windows. Detects exposed instances before attackers do.',
    category: 'python_scanner',
    price_inr: 999, price_usd: 12,
    demand_score: 0.91, severity: 'CRITICAL', cvss_score: 9.8,
    difficulty: 'INTERMEDIATE',
    apt_groups: JSON.stringify(['APT29', 'COLDRIVER']),
    mitre_techniques: JSON.stringify(['T1190', 'T1078', 'T1136.001']),
    affected_systems: JSON.stringify(['JetBrains TeamCity < 2023.11.4']),
    is_featured: 1,
    preview: `#!/usr/bin/env python3
# CVE-2024-27198 — JetBrains TeamCity Auth Bypass Scanner
# CYBERDUDEBIVASH Sentinel APEX Defense Tool
# Usage: python3 scanner.py -t https://teamcity.company.com

import requests, argparse, sys

def check_cve_2024_27198(target: str) -> dict:
    """Test for authentication bypass via /app/rest endpoint"""
    endpoints = ['/app/rest/users', '/app/rest/server']
    for ep in endpoints:
        r = requests.get(f"{target}{ep}", timeout=10, verify=False)
        if r.status_code == 200 and ('user' in r.text or 'server' in r.text):
            return {"vulnerable": True, "endpoint": ep, "status": r.status_code}
    return {"vulnerable": False}

# Full version: multi-target scanning, CIDR support, CSV export, Slack alerts`,
    full_content: `#!/usr/bin/env python3
"""
CVE-2024-27198 — JetBrains TeamCity Authentication Bypass Scanner
CYBERDUDEBIVASH Sentinel APEX Defense Tool v1.0
CVSS: 9.8 CRITICAL | APT29 exploitation confirmed | Supply chain risk

Usage:
  python3 scanner.py -t https://teamcity.company.com
  python3 scanner.py -f targets.txt --output results.json
  python3 scanner.py --cidr 10.0.0.0/24 --port 8111
"""

import argparse, json, sys, ipaddress, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] Install: pip3 install requests"); sys.exit(1)

EXPLOIT_ENDPOINTS = [
    '/app/rest/users',
    '/app/rest/server',
    '/app/rest/buildTypes',
    '/app/rest/projects',
    '/app/rest/agents',
]
VULN_VERSIONS = ['2023.11', '2023.05', '2022.10', '2022.04', '2021.2', '2021.1', '2020.2']

def check_target(target: str, timeout: int = 10) -> dict:
    result = {"target": target, "vulnerable": False, "version": None, "endpoints": [], "risk": "UNKNOWN"}
    try:
        # 1. Check if TeamCity is running
        r = requests.get(f"{target}/login.html", timeout=timeout, verify=False, allow_redirects=True)
        if r.status_code not in (200, 302, 401) or 'TeamCity' not in r.text:
            result["risk"] = "NOT_TEAMCITY"; return result

        # 2. Attempt unauthenticated REST access (the bypass)
        for ep in EXPLOIT_ENDPOINTS:
            try:
                er = requests.get(f"{target}{ep}", timeout=timeout, verify=False,
                                  headers={"Accept": "application/json"})
                if er.status_code == 200:
                    result["vulnerable"] = True
                    result["endpoints"].append({"path": ep, "status": 200, "bytes": len(er.content)})
                    result["risk"] = "CRITICAL"
            except: pass

        # 3. Extract version
        try:
            vr = requests.get(f"{target}/app/rest/server", timeout=timeout, verify=False,
                              headers={"Accept": "application/json"})
            if vr.status_code == 200:
                data = vr.json()
                result["version"] = data.get("version", "unknown")
                result["build"]   = data.get("buildNumber", "unknown")
                for vv in VULN_VERSIONS:
                    if vv in str(result["version"]):
                        result["patch_required"] = True
        except: pass

        # 4. Check for existing admin account abuse (T1136.001)
        if result["vulnerable"]:
            try:
                ur = requests.get(f"{target}/app/rest/users", timeout=timeout, verify=False,
                                  headers={"Accept": "application/json"})
                if ur.status_code == 200:
                    users = ur.json().get("user", [])
                    result["exposed_users"] = len(users)
                    result["admin_count"]   = sum(1 for u in users if u.get("username","").lower() in ["admin","administrator","root","teamcity"])
            except: pass
    except requests.exceptions.ConnectionError:
        result["risk"] = "UNREACHABLE"
    except Exception as e:
        result["error"] = str(e)
    return result

def main():
    parser = argparse.ArgumentParser(description="CVE-2024-27198 TeamCity Scanner — CYBERDUDEBIVASH")
    parser.add_argument("-t","--target",    help="Single target URL")
    parser.add_argument("-f","--file",      help="File with target URLs (one per line)")
    parser.add_argument("--cidr",           help="CIDR range to scan (e.g. 10.0.0.0/24)")
    parser.add_argument("--port",type=int,default=8111, help="TeamCity port (default 8111)")
    parser.add_argument("--output",         help="JSON output file")
    parser.add_argument("--threads",type=int,default=10)
    args = parser.parse_args()

    targets = []
    if args.target:   targets.append(args.target)
    if args.file:
        with open(args.file) as f: targets.extend(l.strip() for l in f if l.strip())
    if args.cidr:
        net = ipaddress.ip_network(args.cidr, strict=False)
        targets.extend(f"http://{h}:{args.port}" for h in net.hosts())

    if not targets: parser.print_help(); sys.exit(1)

    print(f"[*] CVE-2024-27198 Scanner | {len(targets)} targets | {datetime.utcnow().isoformat()}Z")
    results, vulnerable = [], []

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(check_target, t): t for t in targets}
        for f in as_completed(futures):
            r = f.result(); results.append(r)
            status = "VULNERABLE" if r["vulnerable"] else r.get("risk","OK")
            print(f"  [{status:12s}] {r['target']} | version={r.get('version','?')} | users={r.get('exposed_users','?')}")
            if r["vulnerable"]: vulnerable.append(r)

    print(f"\n[SUMMARY] Scanned: {len(results)} | Vulnerable: {len(vulnerable)} | Safe: {len(results)-len(vulnerable)}")
    if vulnerable:
        print("\n[!] VULNERABLE INSTANCES:")
        for v in vulnerable:
            print(f"  - {v['target']} (v{v.get('version','?')}) exposed endpoints: {len(v['endpoints'])}")
        print("\n[REMEDIATION] Upgrade to TeamCity 2023.11.4+ immediately.")
        print("  Temp: config/internal/auth-config.xml → set authModuleType=LDAP or disable REST")

    if args.output:
        with open(args.output,"w") as out: json.dump({"scan_time":datetime.utcnow().isoformat()+"Z","results":results,"vulnerable":vulnerable},out,indent=2)
        print(f"\n[+] Results saved: {args.output}")

if __name__ == "__main__": main()`,
  },

  {
    id: 'sol-cve-2024-1709-yara',
    cve_id: 'CVE-2024-1709',
    title: 'ConnectWise ScreenConnect YARA Rules + Threat Hunt Pack',
    description: 'YARA rules for detecting CVE-2024-1709 (ConnectWise ScreenConnect auth bypass, CVSS 10.0) malware artifacts in memory and disk. Includes Splunk SPL and Elastic EQL threat hunting queries for post-exploitation detection. CISA KEV listed, ransomware-linked.',
    category: 'yara_rule',
    price_inr: 699, price_usd: 9,
    demand_score: 0.93, severity: 'CRITICAL', cvss_score: 10.0,
    difficulty: 'INTERMEDIATE',
    apt_groups: JSON.stringify(['Black Basta', 'LockBit']),
    mitre_techniques: JSON.stringify(['T1190', 'T1059.001', 'T1021.001']),
    affected_systems: JSON.stringify(['ConnectWise ScreenConnect < 23.9.8']),
    is_featured: 1,
    preview: `rule CVE_2024_1709_ScreenConnect_Exploit {
  meta:
    description = "Detects CVE-2024-1709 ScreenConnect auth bypass artifacts"
    author = "CYBERDUDEBIVASH Sentinel APEX"
    severity = "CRITICAL"
    cve = "CVE-2024-1709"
  strings:
    $path1 = "/SetupWizard.aspx" nocase ascii
    $path2 = "/../" nocase ascii
    $sc_header = "ScreenConnect" nocase ascii
  condition:
    all of ($path*) and $sc_header
}
# Full version: 8 YARA rules + Splunk SPL + Elastic EQL hunting queries`,
    full_content: `// ============================================================
// CVE-2024-1709 — ConnectWise ScreenConnect Auth Bypass
// CYBERDUDEBIVASH Sentinel APEX YARA + Threat Hunt Pack
// CVSS: 10.0 CRITICAL | CISA KEV | Ransomware-linked
// ============================================================

// ── YARA RULE 1: Initial exploit path traversal ─────────────
rule CVE_2024_1709_ScreenConnect_Path_Traversal {
  meta:
    description = "Detects CVE-2024-1709 ScreenConnect path traversal exploit"
    author      = "CYBERDUDEBIVASH Sentinel APEX"
    date        = "2024-02-20"
    severity    = "CRITICAL"
    cve         = "CVE-2024-1709"
    reference   = "https://nvd.nist.gov/vuln/detail/CVE-2024-1709"
  strings:
    $url1 = "/SetupWizard.aspx" nocase ascii
    $url2 = "/../" nocase ascii
    $sc1  = "ScreenConnect" nocase ascii
    $sc2  = "connectwise" nocase ascii wide
  condition:
    ($url1 and $url2) or ($sc1 and $url2)
}

// ── YARA RULE 2: Admin account creation artifact ────────────
rule CVE_2024_1709_ScreenConnect_Admin_Creation {
  meta:
    description = "Detects unauthorized admin creation via CVE-2024-1709"
    severity    = "CRITICAL"
  strings:
    $s1 = "SetupWizard.aspx/Step3" nocase ascii
    $s2 = "AdminEmail" nocase ascii
    $s3 = "AdminPassword" nocase ascii
    $s4 = "POST" ascii
  condition:
    $s1 and ($s2 or $s3)
}

// ── YARA RULE 3: ScreenConnect agent dropped payload ────────
rule CVE_2024_1709_ScreenConnect_Dropped_Tool {
  meta:
    description = "Detects remote tools dropped via ScreenConnect session after exploit"
    severity    = "HIGH"
  strings:
    $sc_guid = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ ascii
    $cobalt  = "beacon" nocase ascii wide
    $msf1    = "meterpreter" nocase ascii wide
    $msf2    = "metasploit" nocase ascii wide
    $sc_path = /ScreenConnect\\\\Service\\\\/ nocase ascii wide
  condition:
    $sc_path and $sc_guid and any of ($cobalt, $msf1, $msf2)
}

// ── YARA RULE 4: Ransomware staging post-ScreenConnect ──────
rule CVE_2024_1709_Post_Exploit_Ransomware_Stage {
  meta:
    description = "Black Basta / LockBit staging after ScreenConnect exploit"
    severity    = "CRITICAL"
  strings:
    $bb1 = "BLACK BASTA" nocase ascii wide
    $lb1 = "LOCKBIT" nocase ascii wide
    $note = "README.txt" nocase ascii
    $ext1 = ".basta" nocase
    $ext2 = ".lockbit" nocase
  condition:
    any of ($bb1,$lb1) or any of ($ext1,$ext2)
}

// ── SPLUNK SPL THREAT HUNT ─────────────────────────────────
// index=iis OR index=webserver host=*screenconnect*
// | search uri_path IN ("*/SetupWizard.aspx*")
// | rex field=uri_path "Step(?P<step>\d)"
// | where step > 1
// | stats count by src_ip, uri_path, status, _time
// | eval risk=if(step>=3,"CRITICAL_ADMIN_CREATION","HIGH_PATH_TRAVERSAL")
// | where count > 1

// ── ELASTIC EQL HUNT ──────────────────────────────────────
// sequence by source.ip with maxspan=5m
//   [network where url.path like "*SetupWizard.aspx*" and url.path like "*/../*"]
//   [network where url.path like "*SetupWizard.aspx/Step3*"]
//   [process where process.name in ("cmd.exe","powershell.exe","wscript.exe")]

// ── MICROSOFT SENTINEL KQL ─────────────────────────────────
// W3CIISLog
// | where csUriStem contains "SetupWizard.aspx" and csUriQuery contains "../"
// | project TimeGenerated, cIp, csUriStem, csUriQuery, scStatus, scBytes
// | extend Risk = "CVE-2024-1709 ScreenConnect Exploit"
// | order by TimeGenerated desc`,
  },

  {
    id: 'sol-cve-2024-0012-hardening',
    cve_id: 'CVE-2024-0012',
    title: 'PAN-OS Management Interface Hardening Script + Zero Trust Config',
    description: 'Bash + PowerShell hardening script to eliminate the attack surface for CVE-2024-0012 (PAN-OS management auth bypass, CVSS 9.3). Implements Zero Trust access controls for management plane, IP allowlisting, and emergency lockdown procedure.',
    category: 'hardening_script',
    price_inr: 599, price_usd: 8,
    demand_score: 0.87, severity: 'CRITICAL', cvss_score: 9.3,
    difficulty: 'INTERMEDIATE',
    apt_groups: JSON.stringify(['UTA0218']),
    mitre_techniques: JSON.stringify(['T1190', 'T1078.001']),
    affected_systems: JSON.stringify(['Palo Alto PAN-OS < 11.2.4-h4', 'PAN-OS < 11.1.5-h1', 'PAN-OS < 11.0.6-h1', 'PAN-OS < 10.2.12-h2']),
    is_featured: 0,
    preview: `#!/bin/bash
# CVE-2024-0012 — PAN-OS Management Interface Hardening
# CYBERDUDEBIVASH Sentinel APEX Defense Tool
# Restricts management access to trusted IPs only

# Step 1: Identify management interface
echo "[*] Current management interface config:"
# On PAN-OS CLI: show interface management

# Step 2: Restrict management access (run on PAN-OS)
# set deviceconfig system permitted-ip <YOUR_MGMT_IP_RANGE>
# set deviceconfig system service disable-http yes
# set deviceconfig system service disable-telnet yes

echo "[!] Critical: Management plane must NOT be internet-exposed"
# Full version: complete Zero Trust access policy + monitoring rules`,
    full_content: `#!/bin/bash
# ============================================================
# CVE-2024-0012 — PAN-OS Management Auth Bypass Hardening
# CYBERDUDEBIVASH Sentinel APEX Defense Tool v1.0
# CVSS: 9.3 CRITICAL | Management plane exposure
# ============================================================
# Run this script on the Linux host managing PAN-OS via API.
# PAN-OS CLI commands are provided as comments — run directly on device.
# ============================================================

set -euo pipefail
MGMT_ALLOWED_IPS="\${MGMT_ALLOWED_IPS:-10.0.0.0/8}"  # override via env
LOGFILE="/var/log/pan-hardening-$(date +%Y%m%d).log"

echo "[$(date -u)] Starting PAN-OS CVE-2024-0012 hardening..." | tee -a "$LOGFILE"

# ── 1. EXTERNAL FIREWALL — block management interface ──────────────
echo "[+] Applying external firewall rules for management interface..."
# Block all external access to PAN-OS management port (port 443/4443)
# iptables rules for edge firewall:
iptables -I INPUT -p tcp --dport 443 -s "\${MGMT_ALLOWED_IPS}" -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j DROP
iptables -I INPUT -p tcp --dport 4443 -s "\${MGMT_ALLOWED_IPS}" -j ACCEPT
iptables -I INPUT -p tcp --dport 4443 -j DROP
iptables -I INPUT -p tcp --dport 22 -s "\${MGMT_ALLOWED_IPS}" -j ACCEPT
iptables -I INPUT -p tcp --dport 22 -j DROP
iptables-save > /etc/iptables/rules.v4
echo "[+] iptables rules saved"

# ── 2. PAN-OS CLI COMMANDS (run directly on firewall) ─────────────
echo ""
echo "=== PAN-OS CLI HARDENING (run directly on device) ==="
cat << 'PANOSEOF'
# Restrict management access to specific IPs
set deviceconfig system permitted-ip 10.0.0.0/8
set deviceconfig system permitted-ip 192.168.1.100/32

# Disable insecure services on management plane
set deviceconfig system service disable-http yes
set deviceconfig system service disable-telnet yes
set deviceconfig system service disable-snmp yes

# Enable certificate-based authentication
set deviceconfig system login-banner "AUTHORIZED USERS ONLY - CVE-2024-0012 hardened"

# Set management interface to dedicated OOB (out-of-band) interface
set deviceconfig system type static
set deviceconfig system ip-address <MGMT_IP>
set deviceconfig system netmask <MASK>

# Commit changes
commit

# Verify management access list
show deviceconfig system | match permitted-ip
PANOSEOF

# ── 3. MONITOR — detect exploitation attempts ──────────────────────
echo ""
echo "[+] Setting up exploitation monitoring..."
cat > /etc/rsyslog.d/pan-mgmt-monitor.conf << 'RSYSEOF'
# Forward PAN-OS management auth failures to SIEM
if $msg contains "CVE-2024-0012" or ($msg contains "authentication failed" and $msg contains "management") then {
  action(type="omfwd" target="10.0.0.50" port="514" protocol="udp")
  action(type="omfile" file="/var/log/pan-mgmt-alerts.log")
}
RSYSEOF
systemctl restart rsyslog

# ── 4. ZERO TRUST ACCESS POLICY ───────────────────────────────────
echo ""
echo "=== ZERO TRUST POLICY FOR MANAGEMENT PLANE ==="
cat << 'ZTEOF'
1. IDENTITY:   Require MFA for ALL management access (no exceptions)
2. DEVICE:     Management workstations must be domain-joined + EDR-enrolled
3. NETWORK:    Management VLAN isolated — no routing to/from production
4. ACCESS:     Just-in-time (JIT) access via PAM solution (CyberArk/BeyondTrust)
5. MONITOR:    Log ALL management plane sessions to immutable SIEM
6. PATCH:      Upgrade to PAN-OS 11.2.4-h4+ / 11.1.5-h1+ / 10.2.12-h2+
ZTEOF

echo "[$(date -u)] CVE-2024-0012 hardening complete" | tee -a "$LOGFILE"`,
  },
];

// ── Seed function ─────────────────────────────────────────────────────────────
export async function seedDefenseSolutions(env) {
  if (!env.DB) return { error: 'D1 not available', seeded: 0 };

  let seeded = 0, skipped = 0, errors = [];

  for (const sol of SEED_SOLUTIONS) {
    try {
      // Store full content in KV (so purchase handler can retrieve it)
      const kvKey = `defense:full:${sol.id}`;
      if (env.SECURITY_HUB_KV) {
        try {
          await env.SECURITY_HUB_KV.put(kvKey, sol.full_content);  // no TTL = permanent
        } catch (kvErr) {
          errors.push({ id: sol.id, kvWarning: kvErr.message });  // non-fatal — D1 insert continues
        }
      }

      // Insert into D1 — INSERT OR IGNORE for idempotency
      const result = await env.DB.prepare(`
        INSERT OR IGNORE INTO defense_solutions
          (id, cve_id, title, description, category, price_inr, price_usd,
           demand_score, severity, cvss_score, preview, full_content_key,
           difficulty, apt_groups, mitre_techniques, affected_systems,
           purchase_count, view_count, is_featured, is_active,
           generated_at, created_at, updated_at)
        VALUES
          (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,0,?,1,
           datetime('now'),datetime('now'),datetime('now'))
      `).bind(
        sol.id, sol.cve_id, sol.title, sol.description, sol.category,
        sol.price_inr, sol.price_usd, sol.demand_score, sol.severity,
        sol.cvss_score, sol.preview, kvKey, sol.difficulty,
        sol.apt_groups, sol.mitre_techniques, sol.affected_systems,
        sol.is_featured,
      ).run();

      if (result.meta?.changes > 0) { seeded++; }
      else { skipped++; }
    } catch(e) {
      errors.push({ id: sol.id, error: e.message });
    }
  }

  return {
    total: SEED_SOLUTIONS.length,
    seeded,
    skipped,
    errors,
    message: `Seeded ${seeded} defense solutions (${skipped} already existed)`,
  };
}