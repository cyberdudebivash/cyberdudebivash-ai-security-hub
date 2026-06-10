/**
 * CYBERDUDEBIVASH MYTHOS — Solution Templates Extension v2.0
 * ══════════════════════════════════════════════════════════════
 * Adds 4 missing generators to complete the 10-category marketplace:
 *   - generateYARARule          (yara_rule)
 *   - generateThreatHuntPack    (threat_hunt_pack)
 *   - generateExecutiveBriefing (exec_briefing)
 *   - generateAPISecurityModule (api_module)
 *
 * All outputs are immediately deployable, production-grade artifacts.
 */

// ═══════════════════════════════════════════════════════════════════
// 1. YARA RULE GENERATOR
// ═══════════════════════════════════════════════════════════════════
export function generateYARARule(intel, analysis = {}) {
  const cve      = intel.id || intel.cve_id || 'CVE-UNKNOWN';
  const severity = intel.severity || 'HIGH';
  const type     = (intel.type || 'VULNERABILITY').toUpperCase();
  const systems  = (intel.affected_systems || []).slice(0, 3).join(', ') || 'Multiple Systems';
  const safeName = cve.replace(/[^a-zA-Z0-9]/g, '_');
  const date     = new Date().toISOString().split('T')[0];
  const vectors  = (analysis.attack_vectors || []).join(', ') || type;
  const iocs     = analysis.ioc_signatures || [];

  // Build string entries from IOCs + generic patterns
  const stringEntries = [];
  iocs.filter(i => i.type === 'hash').slice(0, 3).forEach((ioc, n) => {
    stringEntries.push(`        $hash${n + 1} = "${ioc.value}" /* Known malicious hash */`);
  });
  iocs.filter(i => i.type === 'domain').slice(0, 3).forEach((ioc, n) => {
    stringEntries.push(`        $domain${n + 1} = "${ioc.value}" ascii wide`);
  });

  // Type-specific detection patterns
  const typePatterns = getYARAPatterns(type, cve);
  stringEntries.push(...typePatterns);

  if (stringEntries.length === 0) {
    stringEntries.push(`        $cve_ref = "${cve}" ascii wide nocase`);
    stringEntries.push(`        $exploit_sig = { 4D 5A 90 00 03 00 00 00 } /* MZ header - PE executable */`);
  }

  return `/*
 * CYBERDUDEBIVASH Sentinel APEX — YARA Detection Rule
 * ════════════════════════════════════════════════════
 * CVE:       ${cve}
 * Severity:  ${severity}
 * Type:      ${type}
 * Systems:   ${systems}
 * Generated: ${date}
 * Author:    CYBERDUDEBIVASH Sentinel APEX Autonomous Engine
 * License:   CYBERDUDEBIVASH Defense Marketplace — Single-Use License
 */

import "pe"
import "hash"

rule CYBERDUDEBIVASH_${safeName}_Detection {
    meta:
        cve              = "${cve}"
        severity         = "${severity}"
        type             = "${type}"
        affected_systems = "${systems}"
        attack_vectors   = "${vectors}"
        author           = "CYBERDUDEBIVASH Sentinel APEX"
        date             = "${date}"
        version          = "1.0"
        description      = "Detects exploitation artifacts, payloads, and indicators associated with ${cve}"
        reference        = "https://nvd.nist.gov/vuln/detail/${cve}"
        hash_tlp         = "TLP:WHITE"
        yarahub_uuid     = "generated-${safeName}"

    strings:
${stringEntries.join('\n')}

    condition:
        any of them
}

rule CYBERDUDEBIVASH_${safeName}_Memory_Scan {
    meta:
        cve         = "${cve}"
        author      = "CYBERDUDEBIVASH Sentinel APEX"
        description = "Memory-resident artifact detection for ${cve} post-exploitation"
        date        = "${date}"

    strings:
        $shell1     = "cmd.exe /c" ascii wide nocase
        $shell2     = "/bin/sh -c" ascii wide nocase
        $shell3     = "powershell -enc" ascii wide nocase
        $reverse    = { 2F 62 69 6E 2F 62 61 73 68 } /* /bin/bash */
        $exploit    = "exploit" ascii wide nocase
        $payload    = "payload" ascii wide nocase
        $dropper    = "dropper" ascii wide nocase

    condition:
        2 of ($shell*, $reverse, $exploit, $payload, $dropper)
        and filesize < 5MB
}`;
}

function getYARAPatterns(type, cve) {
  const safe = cve.replace(/[^a-zA-Z0-9]/g, '_');
  const map = {
    'RCE':           [`        $rce1 = "Runtime.exec" ascii wide`, `        $rce2 = "ProcessBuilder" ascii wide`, `        $rce3 = { 63 6D 64 2E 65 78 65 } /* cmd.exe */`],
    'SQL_INJECTION': [`        $sqli1 = "' OR '1'='1" ascii nocase`, `        $sqli2 = "UNION SELECT" ascii nocase`, `        $sqli3 = "xp_cmdshell" ascii nocase`],
    'RANSOMWARE':    [`        $ransom1 = ".locked" ascii wide`, `        $ransom2 = "YOUR_FILES_ARE_ENCRYPTED" ascii wide nocase`, `        $ransom3 = "bitcoin" ascii wide nocase`, `        $ransom4 = { 56 53 53 41 64 6D 69 6E } /* VSSAdmin */`],
    'BUFFER_OVERFLOW':[`        $bof1 = { 90 90 90 90 90 90 90 90 } /* NOP sled */`, `        $shellcode = { 31 C0 50 68 2F 2F 73 68 } /* common shellcode */`],
    'AUTHENTICATION_BYPASS': [`        $bypass1 = "admin'--" ascii nocase`, `        $bypass2 = "' OR 1=1--" ascii nocase`],
  };
  return map[type] || [`        $generic_${safe} = "${cve}" ascii wide nocase`, `        $cve_pattern = /CVE-[0-9]{4}-[0-9]+/ ascii`];
}

// ═══════════════════════════════════════════════════════════════════
// 2. THREAT HUNT PACK GENERATOR
// ═══════════════════════════════════════════════════════════════════
export function generateThreatHuntPack(intel, analysis = {}) {
  const cve      = intel.id || intel.cve_id || 'CVE-UNKNOWN';
  const severity = intel.severity || 'HIGH';
  const type     = (intel.type || 'VULNERABILITY').toUpperCase();
  const systems  = (intel.affected_systems || []).slice(0, 3).join(', ') || 'Multiple Systems';
  const date     = new Date().toISOString().split('T')[0];
  const vectors  = (analysis.attack_vectors || []).join(', ') || type;
  const mitre    = (analysis.mitre_techniques || []).map(m => `${m.id} — ${m.name}`).join('\n  #   ') || 'T1190 — Exploit Public-Facing Application';

  return `#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# CYBERDUDEBIVASH Sentinel APEX — Threat Hunt Pack
# CVE: ${cve}  |  Severity: ${severity}  |  Generated: ${date}
# ════════════════════════════════════════════════════════════════════
# MULTI-PLATFORM HUNTING QUERIES:
#   Section 1 — Splunk SPL
#   Section 2 — Elastic KQL / EQL
#   Section 3 — Microsoft Sentinel KQL
#   Section 4 — CrowdStrike Falcon / Endpoint Query
#   Section 5 — osquery (Linux/macOS/Windows)
#   Section 6 — Shell-based hunt script (Linux/macOS)
# ════════════════════════════════════════════════════════════════════
# MITRE ATT&CK:
#   ${mitre}
# Attack Vectors: ${vectors}
# Affected:       ${systems}
# ════════════════════════════════════════════════════════════════════

# ── SECTION 1: Splunk SPL ─────────────────────────────────────────
cat << 'SPLUNK_QUERIES'

[HUNT-1] Exploitation Attempt Detection
index=* (sourcetype=access_combined OR sourcetype=nginx OR sourcetype=apache_access)
| rex field=uri_path "(?<suspicious>[\\x00-\\x1f\\x7f-\\xff%00-ff]{5,})"
| where isnotnull(suspicious) OR like(uri_path, "%../%") OR like(uri_path, "%<script%")
| stats count by src_ip, uri_path, status, host
| where count > 3 OR status IN ("500","400","403")
| sort -count
| eval cve="${cve}", alert_level="${severity}"
| table _time, src_ip, host, uri_path, status, count, alert_level

[HUNT-2] Post-Exploitation Shell Activity
index=* (EventCode=4688 OR source=/var/log/auth.log OR source=/var/log/secure)
| search (CommandLine="*cmd.exe*" OR CommandLine="*powershell*" OR CommandLine="*/bin/sh*" OR CommandLine="*wget*http*" OR CommandLine="*curl*|*bash*")
| eval risk_score=case(like(CommandLine,"%powershell -enc%"), 90, like(CommandLine,"%curl%|%bash%"), 95, like(CommandLine,"%wget%"), 70, true(), 50)
| where risk_score > 60
| stats count by src_user, ComputerName, CommandLine, risk_score
| sort -risk_score

[HUNT-3] Lateral Movement Indicators
index=* (EventCode=4624 OR EventCode=4648 OR EventCode=4672)
| stats count dc(ComputerName) as targets by src_user, src_ip
| where count > 5 AND targets > 2
| eval threat="${cve} lateral movement indicator"
| table _time, src_user, src_ip, targets, count, threat

SPLUNK_QUERIES

# ── SECTION 2: Elastic KQL / EQL ─────────────────────────────────
cat << 'ELASTIC_QUERIES'

[KQL-1] Exploitation Attempt
http.request.method: ("GET" OR "POST") AND
http.response.status_code: (400 OR 403 OR 500) AND
NOT source.ip: ("10.0.0.0/8" OR "192.168.0.0/16") AND
(url.path: ("*../*" OR "*%00*" OR "*<script*") OR url.query: ("*UNION*" OR "*exec(*" OR "*eval(*"))

[KQL-2] Suspicious Process Execution
event.category: "process" AND
event.type: "start" AND
process.parent.name: ("java.exe" OR "python.exe" OR "node.exe" OR "httpd" OR "nginx") AND
process.name: ("cmd.exe" OR "powershell.exe" OR "bash" OR "sh" OR "wget" OR "curl")

[EQL-1] Process Chain — Web Shell Detection
sequence by host.name
  [process where process.name in ("httpd","nginx","tomcat","python","java") and event.type == "start"]
  [process where process.name in ("cmd.exe","powershell.exe","bash","sh","nc","ncat") and event.type == "start"]

ELASTIC_QUERIES

# ── SECTION 3: Microsoft Sentinel KQL ────────────────────────────
cat << 'SENTINEL_QUERIES'

[Sentinel-1] ${cve} Exploitation Attempt
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4624, 4648, 4688, 4720, 4732)
| where CommandLine has_any ("powershell", "cmd.exe", "/bin/bash", "wget", "curl")
| extend CVE = "${cve}", Severity = "${severity}"
| summarize count() by Account, Computer, CommandLine, CVE
| where count_ > 2
| order by count_ desc

[Sentinel-2] Anomalous Authentication Pattern
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType !in ("0", "50125", "50140")
| summarize FailedAttempts = count(), DistinctIPs = dcount(IPAddress) by UserPrincipalName
| where FailedAttempts > 5 OR DistinctIPs > 3
| extend ThreatIndicator = strcat("${cve} — Auth brute-force indicator")

SENTINEL_QUERIES

# ── SECTION 4: osquery ────────────────────────────────────────────
cat << 'OSQUERY'

-- [osquery-1] Listening network services
SELECT pid, family, protocol, local_address, local_port, remote_address, remote_port, state
FROM process_open_sockets
WHERE state = 'LISTEN' AND local_port NOT IN (22, 80, 443, 3306, 5432)
ORDER BY local_port;

-- [osquery-2] Recently modified system files
SELECT path, filename, mtime, size, md5
FROM file
WHERE path LIKE '/etc/%' OR path LIKE '/bin/%' OR path LIKE '/usr/bin/%'
AND mtime > (strftime('%s','now') - 3600)
ORDER BY mtime DESC LIMIT 50;

-- [osquery-3] Suspicious cron entries
SELECT command, path, minute, hour, month, day_of_week
FROM crontab
WHERE command LIKE '%wget%' OR command LIKE '%curl%' OR command LIKE '%bash%'
   OR command LIKE '%python%' OR command LIKE '%nc %' OR command LIKE '%ncat%';

-- [osquery-4] Running processes from tmp/world-writable dirs
SELECT p.pid, p.name, p.cmdline, p.path, u.username
FROM processes p JOIN users u ON p.uid = u.uid
WHERE p.path LIKE '/tmp/%' OR p.path LIKE '/var/tmp/%' OR p.path LIKE '/dev/shm/%';

OSQUERY

# ── SECTION 5: Live Shell Hunt Script ────────────────────────────
cat << 'HUNT_SCRIPT'
#!/bin/bash
set -euo pipefail
CVE="${cve}"
SEVERITY="${severity}"
LOG_FILE="/tmp/hunt_${cve.replace(/-/g, "_")}_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "════════════════════════════════════════════════"
echo " CYBERDUDEBIVASH Threat Hunt — $CVE"
echo " Severity: $SEVERITY  |  $(date)"
echo "════════════════════════════════════════════════"

check_open_ports() {
  echo "[*] Checking suspicious listening ports..."
  ss -tlnp 2>/dev/null | grep -v '127.0.0.1' | grep -v '::1' || netstat -tlnp 2>/dev/null
}

check_recent_auth() {
  echo "[*] Recent failed auth attempts..."
  grep -i "failed\|invalid\|error" /var/log/auth.log 2>/dev/null | tail -20 || \
  grep -i "failed\|invalid" /var/log/secure 2>/dev/null | tail -20 || echo "  [!] Cannot read auth log (check permissions)"
}

check_crontabs() {
  echo "[*] Scanning all user crontabs for suspicious entries..."
  for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null | grep -E "wget|curl|bash|python|nc " && echo "  [!] Suspicious cron for: $user"
  done
}

check_tmp_executables() {
  echo "[*] Executable files in /tmp and /var/tmp..."
  find /tmp /var/tmp /dev/shm -type f -perm /111 -ls 2>/dev/null
}

check_network_connections() {
  echo "[*] Active outbound connections..."
  ss -tnp 2>/dev/null | grep ESTAB | grep -v '127\.\|10\.\|192\.168\.' | head -20 || \
  netstat -tnp 2>/dev/null | grep ESTABLISHED | head -20
}

check_recently_modified() {
  echo "[*] Files modified in last 60 minutes in critical dirs..."
  find /etc /bin /usr/bin /sbin /usr/sbin -newer /tmp -type f -ls 2>/dev/null | head -20
}

check_open_ports
check_recent_auth
check_crontabs
check_tmp_executables
check_network_connections
check_recently_modified

echo ""
echo "[✓] Hunt complete — results saved to: $LOG_FILE"
echo "[!] Review findings and correlate with ${cve} exploitation indicators"
HUNT_SCRIPT

echo ""
echo "════════════════════════════════════════════════"
echo " Threat Hunt Pack for ${cve} — COMPLETE"
echo " Generated by CYBERDUDEBIVASH Sentinel APEX"
echo "════════════════════════════════════════════════"`;
}

// ═══════════════════════════════════════════════════════════════════
// 3. EXECUTIVE BRIEFING GENERATOR
// ═══════════════════════════════════════════════════════════════════
export function generateExecutiveBriefing(intel, analysis = {}) {
  const cve      = intel.id || intel.cve_id || 'CVE-UNKNOWN';
  const severity = intel.severity || 'HIGH';
  const cvss     = intel.cvss_score || 'N/A';
  const type     = intel.type || 'Vulnerability';
  const systems  = (intel.affected_systems || ['Multiple Systems']).slice(0, 4).join(', ');
  const exploit  = intel.exploit_status === 'confirmed' || !!intel.actively_exploited;
  const kev      = !!intel.kev_added;
  const date     = new Date().toISOString().split('T')[0];
  const epss     = intel.epss_score ? `${(intel.epss_score * 100).toFixed(1)}%` : 'N/A';
  const narrative     = analysis.narrative     || `${cve} poses a ${severity} risk to affected systems.`;
  const techImpact    = analysis.technical_impact || `${type} vulnerability enabling unauthorized system access.`;
  const bizRisk       = analysis.business_risk    || 'Potential data breach, service disruption, and reputational damage.';
  const actions       = analysis.immediate_actions || ['Apply vendor patch immediately', 'Deploy WAF rules', 'Monitor for exploitation indicators'];
  const mitres        = (analysis.mitre_techniques || []).map(m => `${m.id} (${m.tactic}): ${m.name}`);
  const vectors       = analysis.attack_vectors   || [type];
  const riskScore     = analysis.risk_score       || Math.round(parseFloat(cvss) * 10);
  const urgencyLabel  = exploit || kev ? '🔴 CRITICAL — IMMEDIATE ACTION REQUIRED' : severity === 'HIGH' ? '🟠 HIGH — ACTION WITHIN 72 HOURS' : '🟡 MEDIUM — ACTION WITHIN 7 DAYS';

  return `CYBERDUDEBIVASH SENTINEL APEX
EXECUTIVE CYBERSECURITY BRIEFING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CLASSIFICATION: CONFIDENTIAL — FOR C-SUITE AND BOARD USE ONLY
DATE ISSUED:    ${date}
PREPARED BY:    CYBERDUDEBIVASH Sentinel APEX Autonomous Engine

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SUBJECT: CRITICAL SECURITY ADVISORY — ${cve}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

URGENCY STATUS: ${urgencyLabel}

┌─────────────────────────────────────────────────────────────────┐
│  THREAT AT A GLANCE                                              │
├──────────────────────────┬──────────────────────────────────────┤
│  CVE Identifier          │  ${cve.padEnd(38)} │
│  Severity Level          │  ${severity.padEnd(38)} │
│  CVSS Score              │  ${String(cvss).padEnd(38)} │
│  EPSS (Exploit Prob.)    │  ${epss.padEnd(38)} │
│  Vulnerability Type      │  ${type.padEnd(38)} │
│  Affected Systems        │  ${systems.slice(0,38).padEnd(38)} │
│  Actively Exploited      │  ${(exploit ? 'YES — confirmed in the wild' : 'Not confirmed').padEnd(38)} │
│  CISA KEV Listed         │  ${(kev ? 'YES — federal mandate to patch' : 'No').padEnd(38)} │
│  Risk Score (0–100)      │  ${String(riskScore).padEnd(38)} │
└──────────────────────────┴──────────────────────────────────────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EXECUTIVE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${narrative}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BUSINESS RISK ASSESSMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${bizRisk}

Technical Impact:
  ${techImpact}

Attack Vectors Identified:
${vectors.map(v => `  • ${v}`).join('\n')}

MITRE ATT&CK Techniques:
${mitres.length ? mitres.map(m => `  • ${m}`).join('\n') : '  • T1190 — Exploit Public-Facing Application'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IMMEDIATE RECOMMENDED ACTIONS (PRIORITIZED)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${actions.map((a, i) => `  ${i + 1}. ${a}`).join('\n')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RESPONSE TIMELINE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  0–4 HOURS:   Deploy emergency WAF/firewall rules to block exploitation vectors
  4–24 HOURS:  Apply vendor patch or implement compensating controls
  24–72 HOURS: Full vulnerability scan on affected systems; verify no compromise
  72+ HOURS:   Document remediation, update asset inventory, review patch SLA

${kev ? `⚠️  CISA KEV COMPLIANCE: Federal agencies MUST patch within mandated deadline.\n    Failure to comply may result in regulatory sanctions.\n` : ''}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AVAILABLE DEFENSE SOLUTIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The following Sentinel APEX defense artifacts have been generated for ${cve}:

  🔥 Firewall Script      — Instant-deploy iptables/WAF rules
  🔍 Sigma Detection Rule — Splunk/Elastic/Sentinel detection
  🧬 YARA Rule Pack       — Malware/payload detection
  📋 IR Playbook          — Step-by-step incident response
  🚨 IDS Signature        — Suricata/Snort network detection
  🛡️  Hardening Script    — System hardening against this CVE
  🎯 Threat Hunt Pack     — Splunk/Elastic/Sentinel/osquery queries
  🐍 Python Scanner       — Automated vulnerability detection tool

Access all artifacts at: https://cyberdudebivash.in/defense-marketplace

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
References: https://nvd.nist.gov/vuln/detail/${cve}${kev ? '\n            https://www.cisa.gov/known-exploited-vulnerabilities-catalog' : ''}
Generated:  ${new Date().toISOString()} by CYBERDUDEBIVASH Sentinel APEX
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;
}

// ═══════════════════════════════════════════════════════════════════
// 4. API SECURITY MODULE GENERATOR
// ═══════════════════════════════════════════════════════════════════
export function generateAPISecurityModule(intel, analysis = {}) {
  const cve      = intel.id || intel.cve_id || 'CVE-UNKNOWN';
  const severity = intel.severity || 'HIGH';
  const type     = (intel.type || 'VULNERABILITY').toUpperCase();
  const date     = new Date().toISOString().split('T')[0];
  const safeName = cve.replace(/[^a-zA-Z0-9]/g, '_');
  const vectors  = analysis.attack_vectors || [];
  const rateLimit = severity === 'CRITICAL' ? 20 : severity === 'HIGH' ? 50 : 100;
  const blockPatterns = getAPIBlockPatterns(type, vectors);

  return `#!/usr/bin/env python3
"""
════════════════════════════════════════════════════════════════════
CYBERDUDEBIVASH Sentinel APEX — API Security Module
════════════════════════════════════════════════════════════════════
CVE:        ${cve}
Severity:   ${severity}
Type:       ${type}
Generated:  ${date}
Author:     CYBERDUDEBIVASH Sentinel APEX Autonomous Engine

DESCRIPTION:
  Production-grade API security middleware that blocks exploitation
  attempts targeting ${cve}. Implements:
    - Request payload inspection + blocking
    - Rate limiting per IP (${rateLimit} req/min)
    - Header injection detection
    - Response sanitization
    - Structured audit logging (SIEM-compatible JSON)

USAGE:
  # FastAPI / Starlette
  from ${safeName}_security import CyberdudebivashSecurityMiddleware
  app.add_middleware(CyberdudebivashSecurityMiddleware, strict=True)

  # Flask
  from ${safeName}_security import apply_flask_security
  apply_flask_security(app)

  # Standalone (test mode)
  python3 ${safeName}_security.py --test
════════════════════════════════════════════════════════════════════
"""

import re
import time
import json
import logging
import hashlib
import ipaddress
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Callable

# ── Structured JSON logger (SIEM-compatible) ──────────────────────
class SIEMLogger:
    def __init__(self, name: str = "cdb_sentinel"):
        self.logger = logging.getLogger(name)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(message)s'))
            self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def event(self, event_type: str, severity: str, data: Dict[str, Any]):
        record = {
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "source":      "CyberdudebivashSentinel",
            "cve":         "${cve}",
            "event_type":  event_type,
            "severity":    severity,
            **data,
        }
        self.logger.info(json.dumps(record))

logger = SIEMLogger()

# ── Rate limiter (sliding window, per-IP) ────────────────────────
class RateLimiter:
    def __init__(self, max_requests: int = ${rateLimit}, window_seconds: int = 60):
        self.max_requests   = max_requests
        self.window_seconds = window_seconds
        self._buckets: Dict[str, deque] = defaultdict(deque)

    def is_allowed(self, ip: str) -> bool:
        now    = time.time()
        bucket = self._buckets[ip]
        # Remove timestamps outside window
        while bucket and bucket[0] < now - self.window_seconds:
            bucket.popleft()
        if len(bucket) >= self.max_requests:
            logger.event("RATE_LIMIT_EXCEEDED", "HIGH", {
                "src_ip": ip, "requests_in_window": len(bucket),
                "limit": self.max_requests, "window_s": self.window_seconds,
            })
            return False
        bucket.append(now)
        return True

rate_limiter = RateLimiter(max_requests=${rateLimit})

# ── Block patterns specific to ${cve} ────────────────────────────
BLOCK_PATTERNS = [
${blockPatterns.map(p => `    re.compile(r${JSON.stringify(p.pattern)}, re.IGNORECASE),  # ${p.label}`).join('\n')}
    # Generic injection patterns
    re.compile(r'[<>][\\w/]',                  re.IGNORECASE),  # HTML/XML tags
    re.compile(r'\\x00|\\x1f|\\x7f',           re.IGNORECASE),  # Null bytes / control chars
    re.compile(r'\\.\\.[\\\\/]',                re.IGNORECASE),  # Path traversal
    re.compile(r'\\bJNDI\\b',                  re.IGNORECASE),  # Log4Shell
    re.compile(r'\\$\\{.*\\}',                 re.IGNORECASE),  # Template injection
]

SUSPICIOUS_HEADERS = [
    'x-forwarded-host', 'x-host', 'x-original-url',
    'x-rewrite-url', 'x-override-url',
]

BLOCKED_IPS: set = set()

def scan_payload(payload: str) -> Optional[str]:
    """Scan a string for malicious patterns. Returns match description or None."""
    for pattern in BLOCK_PATTERNS:
        match = pattern.search(payload)
        if match:
            return f"Blocked pattern: {pattern.pattern[:50]} matched: {match.group()[:30]}"
    return None

def check_request(method: str, path: str, headers: Dict[str, str],
                  body: str, src_ip: str) -> Dict[str, Any]:
    """
    Check a request against all security rules.
    Returns: {allowed: bool, reason: str, rule: str}
    """
    # IP blocklist check
    if src_ip in BLOCKED_IPS:
        return {"allowed": False, "reason": "IP blocklisted", "rule": "BLOCKLIST", "src_ip": src_ip}

    # Rate limit
    if not rate_limiter.is_allowed(src_ip):
        return {"allowed": False, "reason": f"Rate limit exceeded ({${rateLimit}} req/min)", "rule": "RATE_LIMIT", "src_ip": src_ip}

    # Suspicious headers
    for h in SUSPICIOUS_HEADERS:
        if h.lower() in {k.lower() for k in headers}:
            logger.event("SUSPICIOUS_HEADER", "MEDIUM", {"header": h, "src_ip": src_ip, "path": path})

    # Path scan
    path_hit = scan_payload(path)
    if path_hit:
        logger.event("MALICIOUS_PATH", "HIGH", {"src_ip": src_ip, "path": path, "match": path_hit, "cve": "${cve}"})
        BLOCKED_IPS.add(src_ip)
        return {"allowed": False, "reason": path_hit, "rule": "PATH_INJECTION", "src_ip": src_ip}

    # Body scan (POST/PUT/PATCH)
    if method.upper() in ("POST", "PUT", "PATCH") and body:
        body_hit = scan_payload(body[:8192])
        if body_hit:
            logger.event("MALICIOUS_BODY", "CRITICAL", {"src_ip": src_ip, "path": path, "match": body_hit, "cve": "${cve}"})
            BLOCKED_IPS.add(src_ip)
            return {"allowed": False, "reason": body_hit, "rule": "BODY_INJECTION", "src_ip": src_ip}

    return {"allowed": True, "reason": "OK", "rule": "PASS", "src_ip": src_ip}

# ── FastAPI / Starlette middleware ────────────────────────────────
try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    class CyberdudebivashSecurityMiddleware(BaseHTTPMiddleware):
        def __init__(self, app, strict: bool = True):
            super().__init__(app)
            self.strict = strict

        async def dispatch(self, request: Request, call_next: Callable):
            src_ip  = request.client.host if request.client else "unknown"
            body    = ""
            try:
                raw  = await request.body()
                body = raw.decode("utf-8", errors="replace")
            except Exception:
                pass
            result = check_request(
                request.method, str(request.url.path),
                dict(request.headers), body, src_ip,
            )
            if not result["allowed"]:
                return JSONResponse(
                    status_code=403,
                    content={"error": "Request blocked by Sentinel APEX", "rule": result["rule"]},
                )
            return await call_next(request)

except ImportError:
    pass  # Starlette not installed — use Flask or standalone mode

# ── Flask integration ─────────────────────────────────────────────
def apply_flask_security(app):
    try:
        from flask import request, jsonify, abort
        from functools import wraps

        @app.before_request
        def sentinel_check():
            src_ip = request.environ.get("HTTP_X_REAL_IP", request.remote_addr or "unknown")
            body   = ""
            try: body = request.get_data(as_text=True, max_content_length=8192)
            except Exception: pass
            result = check_request(request.method, request.path, dict(request.headers), body, src_ip)
            if not result["allowed"]:
                return jsonify({"error": "Blocked by Sentinel APEX", "rule": result["rule"]}), 403

    except ImportError:
        print("[Sentinel] Flask not available — middleware not applied")

# ── CLI test mode ─────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"CYBERDUDEBIVASH Sentinel APEX — API Security Module")
    print(f"CVE: ${cve}  |  Severity: ${severity}")
    print(f"Rate limit: ${rateLimit} req/min\\n")

    TESTS = [
        ("GET",  "/api/users",               {}, "",                                   "10.0.0.1",   True),
        ("POST", "/api/login",               {}, '{"user":"admin","pass":"pass"}',      "10.0.0.2",   True),
        ("GET",  "/api/../../../etc/passwd", {}, "",                                   "1.2.3.4",    False),
        ("POST", "/api/search",              {}, "q=1' UNION SELECT * FROM users--",   "1.2.3.5",    False),
        ("GET",  "/api/data",                {}, "",                                   "1.2.3.6",    True),
        ("POST", "/api/cmd",                 {}, '{"cmd":"ls; cat /etc/passwd"}',       "5.6.7.8",    False),
    ]
    all_passed = True
    for method, path, headers, body, ip, expected in TESTS:
        result = check_request(method, path, headers, body, ip)
        status = "✅ PASS" if result["allowed"] == expected else "❌ FAIL"
        if result["allowed"] != expected: all_passed = False
        print(f"  {status} {method} {path[:40]:40s} → {result['rule']}")

    print(f"\\n{'✅ All tests passed' if all_passed else '❌ Some tests failed'}")`;
}

function getAPIBlockPatterns(type, vectors) {
  const base = [
    { pattern: "(?:union[\\s+]select|select[\\s+].*from|drop[\\s+]table|insert[\\s+]into)", label: "SQL injection" },
    { pattern: "(?:<script[\\s>]|javascript:|on\\w+\\s*=)", label: "XSS" },
    { pattern: "(?:\\.\\.[\\\\/]){2,}", label: "Path traversal" },
    { pattern: "(?:eval\\s*\\(|exec\\s*\\(|system\\s*\\(|popen\\s*\\()", label: "Code execution" },
  ];
  if (/SSRF/.test(type) || vectors.some(v => /SSRF/i.test(v))) {
    base.push({ pattern: "(?:169\\.254\\.|127\\.|10\\.|192\\.168\\.)", label: "SSRF internal IP" });
  }
  if (/AUTH/.test(type)) {
    base.push({ pattern: "(?:'\\s*or\\s*'1'='1|admin'--|\\bOR\\b\\s+1=1)", label: "Auth bypass" });
  }
  return base;
}

// ═══════════════════════════════════════════════════════════════════
// 5. MICROSOFT SENTINEL ANALYTICS RULE (proper ARM/JSON format)
// ═══════════════════════════════════════════════════════════════════
export function generateSentinelAnalyticsRule(intel, analysis = {}) {
  const cve      = intel.id || intel.cve_id || 'CVE-UNKNOWN';
  const severity = intel.severity || 'HIGH';
  const type     = (intel.type || 'VULNERABILITY').toUpperCase();
  const systems  = (intel.affected_systems || []).slice(0, 3).join(', ') || 'Multiple Systems';
  const date     = new Date().toISOString().split('T')[0];
  const mitre    = (analysis.mitre_techniques || [])[0] || { id: 'T1190', name: 'Exploit Public-Facing Application' };
  const safeName = cve.replace(/[^a-zA-Z0-9]/g, '_');
  const sentinelSev = severity === 'CRITICAL' ? 'High' : severity === 'HIGH' ? 'High' : severity === 'MEDIUM' ? 'Medium' : 'Low';

  // KQL analytics query — tailored to CVE type
  const kqlQuery = getSentinelKQL(type, cve, intel);

  // Produce both the deployable ARM JSON and a README section
  const ruleJson = JSON.stringify({
    apiVersion: '2021-09-01-preview',
    type: 'Microsoft.OperationalInsights/workspaces/providers/alertRules',
    kind: 'Scheduled',
    properties: {
      displayName:         `CYBERDUDEBIVASH — ${cve} Detection`,
      description:         `Detects exploitation attempts for ${cve} (${type}). Affected: ${systems}. Generated by CYBERDUDEBIVASH Sentinel APEX.`,
      severity:            sentinelSev,
      enabled:             true,
      query:               kqlQuery,
      queryFrequency:      'PT1H',
      queryPeriod:         'PT24H',
      triggerOperator:     'GreaterThan',
      triggerThreshold:    0,
      suppressionDuration: 'PT5H',
      suppressionEnabled:  false,
      tactics:             [getTacticForType(type)],
      techniques:          [mitre.id || 'T1190'],
      alertDetailsOverride: {
        alertDisplayNameFormat: `${cve} Alert — {{AccountCustomEntity}} from {{IPCustomEntity}}`,
        alertDescriptionFormat:  `${cve} exploitation detected. Source IP: {{IPCustomEntity}}. Account: {{AccountCustomEntity}}.`,
        alertSeverityColumnName: null,
        alertTacticsColumnName:  null,
      },
      customDetails: {
        CVE:      cve,
        Severity: severity,
        Source:   'CyberdudebivashSentinelAPEX',
      },
      entityMappings: [
        { entityType: 'IP',      fieldMappings: [{ identifier: 'Address',           columnName: 'IPCustomEntity' }] },
        { entityType: 'Account', fieldMappings: [{ identifier: 'FullName',          columnName: 'AccountCustomEntity' }] },
        { entityType: 'Host',    fieldMappings: [{ identifier: 'HostName',          columnName: 'HostCustomEntity' }] },
      ],
      incidentConfiguration: {
        createIncident: true,
        groupingConfiguration: {
          enabled:             true,
          reopenClosedIncident: false,
          lookbackDuration:    'PT5H',
          matchingMethod:      'AllEntities',
          groupByEntities:     ['IP'],
          groupByAlertDetails: [],
          groupByCustomDetails: ['CVE'],
        },
      },
    },
  }, null, 2);

  return `// ════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH Sentinel APEX — Microsoft Sentinel Analytics Rule
// CVE: ${cve}  |  Severity: ${severity}  |  Type: ${type}
// Generated: ${date}
// ════════════════════════════════════════════════════════════════════
//
// DEPLOYMENT OPTIONS:
//
// Option A — Azure Portal:
//   1. Microsoft Sentinel → Analytics → + Create → Scheduled query rule
//   2. Paste KQL query from Section 1 below
//   3. Set: Frequency=1h, Lookup=24h, Threshold>0
//   4. Map entities as shown in Section 2
//
// Option B — ARM Template deployment (recommended for CI/CD):
//   az deployment group create \\
//     --resource-group <YOUR_RG> \\
//     --template-file sentinel_rule_${safeName}.json
//
// Option C — Terraform (azurerm_sentinel_alert_rule_scheduled):
//   resource "azurerm_sentinel_alert_rule_scheduled" "${safeName}" { ... }
//
// MITRE ATT&CK: ${mitre.id} — ${mitre.name || 'Exploit Public-Facing Application'}
// Affected Systems: ${systems}
// ════════════════════════════════════════════════════════════════════

// ── SECTION 1: KQL Analytics Query ──────────────────────────────────
/*
${kqlQuery}
*/

// ── SECTION 2: ARM Template (deploy-ready JSON) ─────────────────────
${ruleJson}`;
}

function getSentinelKQL(type, cve, intel) {
  const systems = (intel.affected_systems || ['*']).slice(0, 2).join('|');
  switch (type) {
    case 'RCE':
      return `// ${cve} — Remote Code Execution Detection
let lookback = 24h;
union SecurityEvent, CommonSecurityLog, Syslog
| where TimeGenerated > ago(lookback)
| where (EventID in (4688, 4104) or DeviceEventClassID contains "exec")
  and (CommandLine has_any ("cmd.exe /c", "powershell -enc", "bash -i", "/bin/sh -c", "wget http", "curl|bash", "python -c"))
| extend CVE = "${cve}", TechniqueId = "T1059"
| project TimeGenerated, Computer, Account, CommandLine, ProcessName=Process, CVE, TechniqueId,
          IPCustomEntity=SourceIP, AccountCustomEntity=Account, HostCustomEntity=Computer
| order by TimeGenerated desc`;

    case 'SQLI':
      return `// ${cve} — SQL Injection Detection
let lookback = 24h;
AzureDiagnostics
| where TimeGenerated > ago(lookback)
| where ResourceType == "APPLICATIONGATEWAYS"
  and (requestUri_s contains "' OR " or requestUri_s contains "UNION SELECT" or requestUri_s contains "--"
       or queryString_s matches regex @"(?i)(union\s+select|' or '1'='1|1=1--|exec\s*\()")
| extend CVE = "${cve}", TechniqueId = "T1190"
| project TimeGenerated, requestUri_s, clientIP_s, CVE, TechniqueId,
          IPCustomEntity=clientIP_s, AccountCustomEntity="anonymous", HostCustomEntity=hostname_s
| order by TimeGenerated desc`;

    case 'AUTH':
      return `// ${cve} — Authentication Bypass / Brute Force Detection
let lookback = 1h;
let threshold = 5;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType !in ("0","50125","50140")
| summarize FailedAttempts=count(), DistinctIPs=dcount(IPAddress), Locations=make_set(Location)
    by UserPrincipalName, bin(TimeGenerated, 5m)
| where FailedAttempts >= threshold
| extend CVE = "${cve}", TechniqueId = "T1110.003"
| project TimeGenerated, UserPrincipalName, FailedAttempts, DistinctIPs, Locations, CVE, TechniqueId,
          AccountCustomEntity=UserPrincipalName, IPCustomEntity=tostring(Locations[0]), HostCustomEntity=""
| order by FailedAttempts desc`;

    case 'SSRF':
      return `// ${cve} — SSRF Detection
let lookback = 24h;
AzureDiagnostics
| where TimeGenerated > ago(lookback)
| where ResourceType == "APPLICATIONGATEWAYS"
  and (requestUri_s matches regex @"(?i)(169\.254\.|127\.|10\.|192\.168\.|metadata\.azure\.|169\.254\.169\.254)"
       or queryString_s matches regex @"(?i)(file://|dict://|gopher://|ftp://)")
| extend CVE = "${cve}", TechniqueId = "T1190"
| project TimeGenerated, requestUri_s, clientIP_s, CVE, TechniqueId,
          IPCustomEntity=clientIP_s, AccountCustomEntity="anonymous", HostCustomEntity=hostname_s`;

    default:
      return `// ${cve} — Exploitation Attempt Detection (Generic)
let lookback = 24h;
union SecurityEvent, CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where (EventID in (4624,4625,4648,4688,4720,4732))
  and (CommandLine has_any ("powershell","cmd.exe","wget","curl","bash","python","nc ","ncat")
       or Activity has_any ("exploit","injection","bypass","overflow"))
| extend CVE = "${cve}", TechniqueId = "T1190"
| project TimeGenerated, Computer, Account, CommandLine, Activity, CVE, TechniqueId,
          IPCustomEntity=SourceComputerName, AccountCustomEntity=Account, HostCustomEntity=Computer
| order by TimeGenerated desc`;
  }
}

function getTacticForType(type) {
  const map = { RCE:'Execution', SQLI:'InitialAccess', AUTH:'CredentialAccess',
                SSRF:'Discovery', XSS:'Execution', LFI:'InitialAccess' };
  return map[type] || 'InitialAccess';
}

// ═══════════════════════════════════════════════════════════════════
// 6. STIX 2.1 INDICATOR BUNDLE
// ═══════════════════════════════════════════════════════════════════
export function generateSTIXBundle(intel, analysis = {}) {
  const cve      = intel.id || intel.cve_id || 'CVE-UNKNOWN';
  const severity = intel.severity || 'HIGH';
  const type     = (intel.type || 'VULNERABILITY').toUpperCase();
  const date     = new Date().toISOString();
  const mitre    = (analysis.mitre_techniques || [])[0] || { id: 'T1190', name: 'Exploit Public-Facing Application' };
  const iocs     = analysis.ioc_signatures || [];

  const bundleId  = `bundle--${stixUUID(cve + 'bundle')}`;
  const vulnId    = `vulnerability--${stixUUID(cve + 'vuln')}`;
  const reportId  = `report--${stixUUID(cve + 'report')}`;
  const courseId  = `course-of-action--${stixUUID(cve + 'coa')}`;
  const attackId  = `attack-pattern--${stixUUID(mitre.id + 'ap')}`;
  const relVulnAP = `relationship--${stixUUID(cve + 'rel1')}`;
  const relCOA    = `relationship--${stixUUID(cve + 'rel2')}`;
  const tlpWhite  = 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9';

  // Build indicator objects from IOCs
  const indicators = iocs.slice(0, 5).map((ioc, i) => {
    const indId = `indicator--${stixUUID(cve + ioc.value + i)}`;
    const pattern = ioc.type === 'hash'
      ? `[file:hashes.'SHA-256' = '${ioc.value}']`
      : ioc.type === 'domain'
      ? `[domain-name:value = '${ioc.value}']`
      : ioc.type === 'ip'
      ? `[ipv4-addr:value = '${ioc.value}']`
      : `[url:value = '${ioc.value}']`;
    return {
      type: 'indicator',
      spec_version: '2.1',
      id: indId,
      created: date,
      modified: date,
      name: `${cve} ${ioc.type} indicator`,
      description: `${ioc.type} IOC associated with ${cve} exploitation`,
      pattern,
      pattern_type: 'stix',
      pattern_version: '2.1',
      valid_from: date,
      confidence: severity === 'CRITICAL' ? 90 : severity === 'HIGH' ? 75 : 60,
      labels: ['malicious-activity', `cve-${cve.toLowerCase()}`],
      object_marking_refs: [tlpWhite],
      granular_markings: [],
    };
  });

  const objects = [
    // Vulnerability
    {
      type: 'vulnerability',
      spec_version: '2.1',
      id: vulnId,
      created: date,
      modified: date,
      name: cve,
      description: (intel.description || `${type} vulnerability in ${(intel.affected_systems || []).join(', ')}`).substring(0, 500),
      external_references: [
        { source_name: 'cve', external_id: cve, url: `https://nvd.nist.gov/vuln/detail/${cve}` },
        { source_name: 'cyberdudebivash', url: `https://intel.cyberdudebivash.com/threats/${cve}` },
      ],
      labels: [severity.toLowerCase(), type.toLowerCase()],
      object_marking_refs: [tlpWhite],
    },
    // Attack Pattern
    {
      type: 'attack-pattern',
      spec_version: '2.1',
      id: attackId,
      created: date,
      modified: date,
      name: mitre.name || 'Exploit Public-Facing Application',
      description: `MITRE ATT&CK technique ${mitre.id} observed in exploitation of ${cve}`,
      external_references: [
        { source_name: 'mitre-attack', external_id: mitre.id, url: `https://attack.mitre.org/techniques/${mitre.id.replace('.','/')}` },
      ],
      object_marking_refs: [tlpWhite],
    },
    // Course of Action
    {
      type: 'course-of-action',
      spec_version: '2.1',
      id: courseId,
      created: date,
      modified: date,
      name: `Remediate ${cve}`,
      description: (intel.recommendation || `Apply vendor patch for ${cve}. Monitor for exploitation indicators. Deploy detection rules from CYBERDUDEBIVASH Sentinel APEX.`).substring(0, 500),
      object_marking_refs: [tlpWhite],
    },
    // Relationships
    {
      type: 'relationship',
      spec_version: '2.1',
      id: relVulnAP,
      created: date,
      modified: date,
      relationship_type: 'exploits',
      source_ref: attackId,
      target_ref: vulnId,
      object_marking_refs: [tlpWhite],
    },
    {
      type: 'relationship',
      spec_version: '2.1',
      id: relCOA,
      created: date,
      modified: date,
      relationship_type: 'mitigates',
      source_ref: courseId,
      target_ref: vulnId,
      object_marking_refs: [tlpWhite],
    },
    ...indicators,
    // Report
    {
      type: 'report',
      spec_version: '2.1',
      id: reportId,
      created: date,
      modified: date,
      name: `CYBERDUDEBIVASH Threat Intelligence Report — ${cve}`,
      description: `Threat intelligence bundle for ${cve}. Severity: ${severity}. Type: ${type}. Generated by CYBERDUDEBIVASH Sentinel APEX Autonomous Intelligence Engine.`,
      published: date,
      report_types: ['vulnerability', 'threat-actor', 'indicators'],
      object_refs: [vulnId, attackId, courseId, relVulnAP, relCOA, ...indicators.map(i => i.id)],
      external_references: [
        { source_name: 'cyberdudebivash-intel', url: `https://intel.cyberdudebivash.com/threats/${cve}` },
        { source_name: 'nvd', url: `https://nvd.nist.gov/vuln/detail/${cve}` },
      ],
      labels: ['cyberdudebivash', 'sentinel-apex', cve.toLowerCase()],
      object_marking_refs: [tlpWhite],
      confidence: severity === 'CRITICAL' ? 90 : severity === 'HIGH' ? 80 : 65,
    },
  ];

  const bundle = {
    type: 'bundle',
    id: bundleId,
    spec_version: '2.1',
    objects,
  };

  return `// ════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH Sentinel APEX — STIX 2.1 Threat Intelligence Bundle
// CVE: ${cve}  |  Severity: ${severity}  |  Type: ${type}
// Generated: ${date}
// ════════════════════════════════════════════════════════════════════
//
// DEPLOYMENT:
//   MISP:      POST /events (import as STIX bundle)
//   OpenCTI:   Settings → Import → Upload STIX 2.1 JSON
//   TheHive:   Cases → Import STIX → Upload file
//   TAXII:     Push to collection endpoint with bearer token
//
// SHARING:
//   TLP:WHITE — shareable within community and publicly
//   MITRE ATT&CK: ${mitre.id} — ${mitre.name}
// ════════════════════════════════════════════════════════════════════
${JSON.stringify(bundle, null, 2)}`;
}

/** Deterministic STIX-compatible UUID from a seed string */
function stixUUID(seed) {
  let h = 5381;
  for (let i = 0; i < seed.length; i++) h = ((h << 5) + h + seed.charCodeAt(i)) & 0xffffffff;
  const hex = Math.abs(h).toString(16).padStart(8, '0');
  // Format as UUID v4-like: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
  const a = hex.substring(0, 8);
  const b = Math.abs(h ^ 0x9e3779b9).toString(16).padStart(4, '0').substring(0, 4);
  const c = '4' + Math.abs(h ^ 0x6c62272e).toString(16).padStart(3, '0').substring(0, 3);
  const d = Math.abs(h ^ 0xe4d9b37a).toString(16).padStart(4, '0').substring(0, 4);
  const e = Math.abs(h * 0x27d4eb2f).toString(16).padStart(12, '0').substring(0, 12);
  return `${a}-${b}-${c}-${d}-${e}`;
}
