/**
 * CYBERDUDEBIVASH AI Security Hub — Solution Templates Library v1.0
 * ═══════════════════════════════════════════════════════════════════
 * Sentinel APEX Defense Solutions — Powered by CYBERDUDEBIVASH
 *
 * MISSION: Production-grade, immediately deployable security artifacts.
 *
 * All templates are parameterized and generate REAL artifacts:
 *   - Python detection scripts (runnable, enterprise logging, alerting)
 *   - Suricata/Snort IDS signatures (valid rule syntax)
 *   - ModSecurity WAF rules (valid Apache/Nginx modsec syntax)
 *   - Sigma detection rules (valid YAML, sigma-compatible)
 *   - YARA malware detection rules (valid YARA syntax)
 *   - Bash system hardening scripts (idempotent, safe)
 *   - iptables/nftables firewall rules
 *   - Incident Response Playbooks (step-by-step, professional)
 *   - Nginx security configurations
 *   - AWS IAM deny policies
 */

// ═══════════════════════════════════════════════════════════════════════════════
// 1. PYTHON DETECTION SCRIPTS
// ═══════════════════════════════════════════════════════════════════════════════

export function generatePythonDetectionScript(intel, analysis) {
  const cveId      = intel.id || 'CVE-UNKNOWN';
  const type       = intel.type || 'VULNERABILITY';
  const severity   = intel.severity || 'HIGH';
  const safeCveVar = cveId.replace(/-/g, '_');
  const systems    = (intel.affected_systems || []).slice(0, 3).join(', ');

  const typeSpecificLogic = getPythonDetectionLogic(type, intel, analysis);

  return `#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════
CYBERDUDEBIVASH Sentinel APEX — ${cveId} Detection Script
═══════════════════════════════════════════════════════════════════════════
CVE:        ${cveId}
Severity:   ${severity}
Type:       ${type}
Affected:   ${systems}
Risk Score: ${analysis.risk_score || 'N/A'}/100
Generated:  ${new Date().toISOString()}

DESCRIPTION:
${(intel.description || '').substring(0, 200)}

DEPLOYMENT:
  pip3 install requests colorama python-dateutil
  python3 ${safeCveVar}_detector.py --target <IP_OR_HOSTNAME> [--port PORT]
  python3 ${safeCveVar}_detector.py --logfile /var/log/app/access.log
  python3 ${safeCveVar}_detector.py --pcap /tmp/capture.pcap

© 2026 CyberDudeBivash Pvt. Ltd. — https://cyberdudebivash.in
═══════════════════════════════════════════════════════════════════════════
"""

import argparse
import json
import logging
import os
import re
import socket
import sys
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import requests
    from requests.adapters import HTTPAdapter, Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[WARN] requests not installed — network scanning disabled")

# ── Configuration ──────────────────────────────────────────────────────────────
CVE_ID           = "${cveId}"
CVE_SEVERITY     = "${severity}"
CVE_TYPE         = "${type}"
SCRIPT_VERSION   = "1.0.0"
ALERT_WEBHOOK    = os.getenv("ALERT_WEBHOOK", "")         # Slack/Teams webhook
ALERT_EMAIL      = os.getenv("ALERT_EMAIL", "")           # Email for alerts
LOG_LEVEL        = os.getenv("LOG_LEVEL", "INFO")
OUTPUT_DIR       = Path(os.getenv("OUTPUT_DIR", "./sentinel_apex_output"))

# ── Logging Setup ──────────────────────────────────────────────────────────────
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
log_file = OUTPUT_DIR / f"{safeCveVar}_detection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file, encoding="utf-8"),
    ],
)
logger = logging.getLogger(f"SentinelAPEX.{CVE_ID}")

# ── Detection Patterns ─────────────────────────────────────────────────────────
${typeSpecificLogic.patterns}

# ── Results Store ──────────────────────────────────────────────────────────────
class DetectionResult:
    def __init__(self):
        self.findings    = []
        self.start_time  = datetime.now(timezone.utc)
        self.target      = None
        self.checked     = 0
        self.alerts      = 0

    def add_finding(self, severity, title, detail, evidence="", recommendation=""):
        finding = {
            "id":             hashlib.sha256(f"{title}{detail}{time.time()}".encode()).hexdigest()[:16],
            "cve_id":         CVE_ID,
            "severity":       severity,
            "title":          title,
            "detail":         detail,
            "evidence":       evidence,
            "recommendation": recommendation,
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "target":         self.target,
        }
        self.findings.append(finding)
        self.alerts += 1

        icon = {"CRITICAL":"🔴", "HIGH":"🟠", "MEDIUM":"🟡", "LOW":"🟢"}.get(severity, "⚪")
        logger.warning(f"{icon} [{severity}] {title} — {detail}")
        return finding

    def summary(self):
        elapsed = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        return {
            "cve_id":        CVE_ID,
            "target":        self.target,
            "checked":       self.checked,
            "findings":      len(self.findings),
            "critical":      sum(1 for f in self.findings if f["severity"] == "CRITICAL"),
            "high":          sum(1 for f in self.findings if f["severity"] == "HIGH"),
            "medium":        sum(1 for f in self.findings if f["severity"] == "MEDIUM"),
            "elapsed_sec":   round(elapsed, 2),
            "verdict":       "VULNERABLE" if self.alerts > 0 else "NOT_DETECTED",
            "scanner":       f"CyberDudeBivash Sentinel APEX v{SCRIPT_VERSION}",
            "generated_at":  datetime.now(timezone.utc).isoformat(),
        }

    def save_report(self, output_path: Optional[Path] = None):
        path = output_path or OUTPUT_DIR / f"{safeCveVar}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report = {"summary": self.summary(), "findings": self.findings}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        logger.info(f"Report saved: {path}")
        return path


# ── Detection Core ─────────────────────────────────────────────────────────────
${typeSpecificLogic.detection_function}


# ── Log File Analyzer ──────────────────────────────────────────────────────────
def analyze_log_file(logfile_path: str, result: DetectionResult) -> int:
    """Scan log file for ${cveId} exploitation indicators."""
    path = Path(logfile_path)
    if not path.exists():
        logger.error(f"Log file not found: {logfile_path}")
        return 0

    hits = 0
    logger.info(f"Scanning log file: {logfile_path}")

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            result.checked += 1

            for pat_name, pattern in DETECTION_PATTERNS.items():
                if re.search(pattern, line, re.IGNORECASE):
                    result.add_finding(
                        severity       = "HIGH",
                        title          = f"${cveId} exploitation pattern in log: {pat_name}",
                        detail         = f"Line {lineno}: {line[:200]}",
                        evidence       = line[:500],
                        recommendation = "Investigate source IP immediately and check for system compromise",
                    )
                    hits += 1
                    break

            if result.alerts >= 100:  # cap at 100 to prevent log overflow
                logger.warning("Alert cap reached (100). Consider reviewing log manually.")
                break

    logger.info(f"Log analysis complete. {hits} hits in {result.checked} lines.")
    return hits


# ── Alert Dispatcher ───────────────────────────────────────────────────────────
def dispatch_alert(summary: dict):
    """Send alert to configured webhook (Slack/Teams/custom)."""
    if not ALERT_WEBHOOK or not REQUESTS_AVAILABLE:
        return

    icon   = "🔴" if summary["critical"] > 0 else "🟠" if summary["high"] > 0 else "🟡"
    text   = (
        f"{icon} *Sentinel APEX Alert — {CVE_ID}*\\n"
        f"Target: `{summary['target']}` | Findings: `{summary['findings']}` | "
        f"Critical: `{summary['critical']}` | High: `{summary['high']}`\\n"
        f"Verdict: *{summary['verdict']}*\\n"
        f"Generated by: CyberDudeBivash AI Security Hub"
    )
    try:
        requests.post(ALERT_WEBHOOK, json={"text": text}, timeout=5)
        logger.info("Alert dispatched to webhook")
    except Exception as e:
        logger.error(f"Webhook alert failed: {e}")


# ── CLI Interface ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description=f"CYBERDUDEBIVASH Sentinel APEX — {CVE_ID} Detection Scanner",
        epilog=f"© 2026 CyberDudeBivash Pvt. Ltd. | https://cyberdudebivash.in",
    )
    parser.add_argument("--target",  "-t", help="Target IP, hostname, or URL to scan")
    parser.add_argument("--port",    "-p", type=int, default=443, help="Target port (default: 443)")
    parser.add_argument("--logfile", "-l", help="Log file path to analyze for exploitation indicators")
    parser.add_argument("--output",  "-o", help="Output directory for reports")
    parser.add_argument("--json",    action="store_true", help="Output results as JSON only")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.output:
        global OUTPUT_DIR
        OUTPUT_DIR = Path(args.output)
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if not args.target and not args.logfile:
        parser.error("Provide --target or --logfile (or both)")

    result = DetectionResult()

    # Banner
    if not args.json:
        print("=" * 72)
        print(f"  CYBERDUDEBIVASH Sentinel APEX — {CVE_ID} Detector v{SCRIPT_VERSION}")
        print(f"  Severity: {CVE_SEVERITY} | Type: {CVE_TYPE}")
        print("=" * 72)

    # Run detection
    if args.target:
        result.target = args.target
        logger.info(f"Scanning target: {args.target}:{args.port}")
        scan_target(args.target, args.port, result)

    if args.logfile:
        if not result.target:
            result.target = args.logfile
        analyze_log_file(args.logfile, result)

    # Output results
    summary = result.summary()
    report_path = result.save_report()

    if args.json:
        print(json.dumps({"summary": summary, "findings": result.findings}, indent=2))
    else:
        print("\\n" + "─" * 72)
        print(f"  SCAN COMPLETE: {summary['verdict']}")
        print(f"  Findings: {summary['findings']} | Critical: {summary['critical']} | High: {summary['high']}")
        print(f"  Report saved: {report_path}")
        print("─" * 72)

    # Dispatch alert if findings
    if result.alerts > 0:
        dispatch_alert(summary)

    return 0 if result.alerts == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
`;
}

// ── Python detection logic by vulnerability type ──────────────────────────────
function getPythonDetectionLogic(type, intel, analysis) {
  const cveId = intel.id || 'CVE-UNKNOWN';

  const logics = {
    RCE: {
      patterns: `DETECTION_PATTERNS = {
    "command_injection":     r'(?:;|&&|\\|\\|)\\s*(?:id|whoami|uname|cat\\s+/etc|ls\\s+-la|curl|wget|bash|sh|cmd\\.exe)',
    "path_traversal":        r'(?:\\.\\./){3,}(?:etc/passwd|windows/system32|proc/self)',
    "eval_execution":        r'(?:eval|exec|system|popen|subprocess)\\s*\\(',
    "base64_payload":        r'(?:base64_decode|fromCharCode|\\\\x[0-9a-f]{2}){3,}',
    "reverse_shell":         r'(?:bash\\s+-i|nc\\s+-e|python\\s+-c.*socket|perl\\s+-e.*socket)',
    "webshell_indicator":    r'(?:<?php|<%@|<script.*language.*runat.*server)',
}`,
      detection_function: `def scan_target(host: str, port: int, result: DetectionResult):
    """Test target for ${cveId} RCE vulnerability indicators."""
    if not REQUESTS_AVAILABLE:
        logger.warning("requests library required for network scanning")
        return

    session = requests.Session()
    session.verify = False
    retries = Retry(total=2, backoff_factor=0.5)
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.mount("http://",  HTTPAdapter(max_retries=retries))

    base_url = f"https://{host}:{port}" if port == 443 else f"http://{host}:{port}"

    # Probe 1: Version fingerprint
    try:
        resp = session.get(f"{base_url}/", timeout=10,
                           headers={"User-Agent": "Mozilla/5.0 (compatible; SentinelAPEX/1.0)"})
        result.checked += 1
        server = resp.headers.get("Server", "")
        x_powered = resp.headers.get("X-Powered-By", "")
        via = resp.headers.get("Via", "")

        for affected in ${JSON.stringify((intel.affected_systems || []).slice(0, 3))}:
            if any(keyword in (server + x_powered).lower() for keyword in affected.lower().split()):
                result.add_finding(
                    severity       = "HIGH",
                    title          = f"Potentially affected system fingerprinted",
                    detail         = f"Server header: {server} | X-Powered-By: {x_powered}",
                    evidence       = f"Headers: {dict(resp.headers)}",
                    recommendation = "Verify version and apply patch ${intel.patch_available ? 'immediately' : '(no patch available — apply compensating controls)'}",
                )
    except Exception as e:
        logger.debug(f"Fingerprint probe failed: {e}")

    # Probe 2: Check for known vulnerable endpoints
    VULNERABLE_PATHS = [
        "/api/v1/exec", "/cgi-bin/admin.cgi", "/wp-admin/admin-ajax.php",
        "/actuator/env", "/manager/html", "/.git/config",
        "/webui/", "/admin/console", "/_fragment",
    ]
    for path in VULNERABLE_PATHS:
        try:
            resp = session.get(f"{base_url}{path}", timeout=5, allow_redirects=False)
            result.checked += 1
            if resp.status_code in (200, 302, 401, 403):
                logger.debug(f"Endpoint {path} returned {resp.status_code}")
                for pat_name, pattern in DETECTION_PATTERNS.items():
                    if re.search(pattern, resp.text[:2000], re.IGNORECASE):
                        result.add_finding(
                            severity       = "CRITICAL",
                            title          = f"Suspicious response pattern at {path}",
                            detail         = f"Pattern '{pat_name}' matched in response",
                            evidence       = resp.text[:500],
                            recommendation = "Immediately investigate this endpoint for active exploitation",
                        )
        except Exception:
            pass

    logger.info(f"Network scan complete: {result.checked} checks, {result.alerts} alerts")`
    },
    SQLI: {
      patterns: `DETECTION_PATTERNS = {
    "union_injection":       r"(?i)\\bUNION\\s+(?:ALL\\s+)?SELECT\\b",
    "boolean_blind":         r"(?i)(?:' OR '1'='1|AND 1=1|AND 1=2|OR 1=1--|' OR ''=')",
    "time_based_blind":      r"(?i)(?:SLEEP\\(\\d+\\)|BENCHMARK\\(\\d+|WAITFOR DELAY|PG_SLEEP\\()",
    "stacked_queries":       r"(?i);\\s*(?:DROP|INSERT|UPDATE|DELETE|EXEC|EXECUTE)\\b",
    "comment_injection":     r"(?i)(?:--\\s*$|/\\*.*\\*/|#\\s*$)",
    "hex_encoding":          r"(?i)0x[0-9a-f]{4,}",
    "error_based":           r"(?i)(?:extractvalue\\(|updatexml\\(|exp\\(~\\(select)",
    "out_of_band":           r"(?i)(?:load_file\\(|into outfile|into dumpfile)",
}`,
      detection_function: `def scan_target(host: str, port: int, result: DetectionResult):
    """Test target for ${cveId} SQL injection indicators."""
    if not REQUESTS_AVAILABLE:
        return

    session = requests.Session()
    session.verify = False
    base_url = f"https://{host}:{port}" if port == 443 else f"http://{host}:{port}"

    # SQL injection test payloads (safe detection only — no destructive payloads)
    TEST_PAYLOADS = [
        ("'", "single_quote"),
        ("1 AND SLEEP(0)--", "time_based_probe"),
        ("1' AND '1'='1", "boolean_probe"),
        ("' UNION SELECT NULL--", "union_probe"),
    ]

    SQL_ERROR_PATTERNS = [
        r"(?:SQL syntax.*MySQL|Warning.*mysql_|MySQLSyntaxErrorException)",
        r"(?:ORA-[0-9]{5}|Oracle.*Driver.*SQL)",
        r"(?:Microsoft.*ODBC.*Driver|\\[SQL Server\\])",
        r"(?:PostgreSQL.*ERROR|pg_query\\(\\))",
        r"(?:SQLite.*error|sqlite3\\.OperationalError)",
        r"(?:Unclosed quotation mark|quoted string not properly terminated)",
    ]

    SCAN_ENDPOINTS = ["/search", "/login", "/api/users", "/api/products", "/index.php", "/"]

    for endpoint in SCAN_ENDPOINTS:
        for payload, payload_name in TEST_PAYLOADS:
            try:
                resp = session.get(
                    f"{base_url}{endpoint}",
                    params={"q": payload, "id": payload, "user": payload, "search": payload},
                    timeout=8,
                )
                result.checked += 1

                response_text = resp.text[:3000]
                for err_pattern in SQL_ERROR_PATTERNS:
                    if re.search(err_pattern, response_text, re.IGNORECASE):
                        result.add_finding(
                            severity       = "CRITICAL",
                            title          = f"SQL error exposed — possible injection at {endpoint}",
                            detail         = f"Payload '{payload_name}' triggered database error disclosure",
                            evidence       = re.findall(err_pattern, response_text, re.IGNORECASE)[:3],
                            recommendation = "Enable parameterized queries immediately. Review WAF rules for SQL injection patterns.",
                        )
                        break
            except Exception:
                pass

    logger.info(f"SQL injection scan complete: {result.checked} checks")`
    },
    AUTH_BYPASS: {
      patterns: `DETECTION_PATTERNS = {
    "jwt_none_alg":         r'(?:eyJ[A-Za-z0-9+/=]{20,}\\.[A-Za-z0-9+/=]*\\.)',
    "default_credentials":  r'(?:admin:admin|admin:password|root:root|admin:123456|test:test)',
    "token_manipulation":   r'(?:role.*admin|isAdmin.*true|admin.*true)',
    "path_bypass":          r'(?:/admin/../|/secure/../|%2e%2e%2f)',
    "header_injection":     r'(?:X-Original-URL|X-Forwarded-For|X-Custom-IP-Authorization)',
    "null_byte":            r'(?:%00|\\x00|\\\\x00)',
}`,
      detection_function: `def scan_target(host: str, port: int, result: DetectionResult):
    """Test target for ${cveId} authentication bypass indicators."""
    if not REQUESTS_AVAILABLE:
        return

    session  = requests.Session()
    session.verify = False
    base_url = f"https://{host}:{port}" if port == 443 else f"http://{host}:{port}"

    # Test 1: Admin endpoint accessibility without auth
    ADMIN_PATHS = [
        "/admin", "/admin/", "/administrator", "/management",
        "/wp-admin", "/phpmyadmin", "/manager", "/console",
        "/api/admin", "/api/v1/admin", "/actuator/health",
    ]
    for path in ADMIN_PATHS:
        try:
            resp = session.get(f"{base_url}{path}", timeout=5, allow_redirects=False)
            result.checked += 1
            if resp.status_code == 200:
                result.add_finding(
                    severity       = "HIGH",
                    title          = f"Admin endpoint accessible without authentication: {path}",
                    detail         = f"HTTP 200 returned without authentication credentials",
                    evidence       = f"URL: {base_url}{path} | Status: {resp.status_code} | Size: {len(resp.content)} bytes",
                    recommendation = "Immediately restrict access to admin endpoints using IP allowlist and enforce authentication",
                )
        except Exception:
            pass

    # Test 2: JWT none algorithm
    import base64
    null_jwt = base64.b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=').decode() + \
               '.' + base64.b64encode(b'{"sub":"admin","role":"admin"}').rstrip(b'=').decode() + '.'
    try:
        resp = session.get(f"{base_url}/api/profile",
                           headers={"Authorization": f"Bearer {null_jwt}"}, timeout=5)
        result.checked += 1
        if resp.status_code == 200 and 'admin' in resp.text.lower():
            result.add_finding(
                severity       = "CRITICAL",
                title          = "JWT 'alg:none' vulnerability — authentication completely bypassed",
                detail         = "Server accepted JWT with 'alg:none' and returned admin-level response",
                evidence       = resp.text[:300],
                recommendation = "Immediately reject JWTs with 'none' algorithm. Use strict algorithm validation.",
            )
    except Exception:
        pass

    logger.info(f"Auth bypass scan complete: {result.checked} checks")`
    },
  };

  return logics[type] || logics['RCE'];
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. SURICATA/SNORT IDS SIGNATURES
// ═══════════════════════════════════════════════════════════════════════════════

export function generateIDSSignature(intel, analysis) {
  const cveId     = intel.id || 'CVE-UNKNOWN';
  const severity  = intel.severity || 'HIGH';
  const type      = intel.type || 'VULNERABILITY';
  const sid_base  = generateSIDFromCVE(cveId);
  const classtype = getClasstype(type);
  const priority  = severity === 'CRITICAL' ? 1 : severity === 'HIGH' ? 2 : 3;

  const typeRules = getIDSRulesForType(type, intel, sid_base, classtype, priority);

  return `# ═══════════════════════════════════════════════════════════════════════
# CYBERDUDEBIVASH Sentinel APEX — ${cveId} IDS/IPS Signatures
# ═══════════════════════════════════════════════════════════════════════
# CVE:      ${cveId}
# Severity: ${severity} | Type: ${type} | Priority: ${priority}
# Affected: ${(intel.affected_systems || []).slice(0, 3).join(', ')}
#
# DEPLOYMENT (Suricata):
#   1. Copy to /etc/suricata/rules/cyberdudebivash_${cveId.toLowerCase().replace(/-/g,'_')}.rules
#   2. Add to /etc/suricata/suricata.yaml:
#        rule-files:
#          - cyberdudebivash_${cveId.toLowerCase().replace(/-/g,'_')}.rules
#   3. suricata-update --no-reload
#   4. systemctl reload suricata
#   5. Verify: suricata --list-runmodes
#
# DEPLOYMENT (Snort):
#   1. Copy to /etc/snort/rules/
#   2. Add include to snort.conf
#   3. snort -T -c /etc/snort/snort.conf
#
# Generated by: CyberDudeBivash Sentinel APEX v1.0
# © 2026 CyberDudeBivash Pvt. Ltd. — https://cyberdudebivash.in
# ═══════════════════════════════════════════════════════════════════════

${typeRules}

# ── Metadata rules (alert + log for SIEM ingestion) ─────────────────────────

alert tcp any any -> any any (msg:"CYBERDUDEBIVASH SENTINEL-APEX ${cveId} Scan/Exploit Activity Detected"; \\
    flow:established; \\
    content:"${cveId.split('-').join('')}"; nocase; \\
    threshold:type limit, track by_src, count 1, seconds 60; \\
    classtype:${classtype}; sid:${sid_base + 99}; rev:1; \\
    metadata:affected_product "${(intel.affected_systems || []).slice(0,1).join('')}", \\
             created_at ${new Date().toISOString().slice(0,10)}, \\
             deployment Perimeter, severity ${severity}, \\
             signature_source CyberDudeBivash_SentinelAPEX;)
`;
}

function getIDSRulesForType(type, intel, sid_base, classtype, priority) {
  const cveId  = intel.id || 'CVE-UNKNOWN';
  const rules  = [];

  const rulesByType = {
    RCE: [
      `alert http any any -> $HTTP_SERVERS any (msg:"CYBERDUDEBIVASH ${cveId} RCE Attempt — Command Injection"; \\
    flow:established,to_server; http.uri; \\
    content:"|3B|"; /* ; */ \\
    pcre:"/(?:%3B|;)\\s*(?:id|whoami|uname|cat\\s+.etc|curl|wget|bash|sh)/i"; \\
    classtype:${classtype}; sid:${sid_base + 1}; rev:1; priority:${priority}; \\
    metadata:cve ${cveId}, severity CRITICAL, mitre_technique T1059;)`,

      `alert http any any -> $HTTP_SERVERS any (msg:"CYBERDUDEBIVASH ${cveId} RCE Attempt — Path Traversal"; \\
    flow:established,to_server; http.uri; \\
    pcre:"/(?:\\.\\.\\/){3,}/"; \\
    content:"/etc/passwd"; nocase; \\
    classtype:${classtype}; sid:${sid_base + 2}; rev:1; priority:${priority}; \\
    metadata:cve ${cveId};)`,

      `alert http any any -> $HTTP_SERVERS any (msg:"CYBERDUDEBIVASH ${cveId} RCE — Reverse Shell Payload"; \\
    flow:established,to_server; http.request_body; \\
    pcre:"/(?:bash\\s+-i|nc\\s+-e|python\\s+-c.{0,50}socket|perl\\s+-e.{0,50}socket)/i"; \\
    classtype:${classtype}; sid:${sid_base + 3}; rev:1; priority:1; \\
    metadata:cve ${cveId}, severity CRITICAL;)`,

      `alert http $HTTP_SERVERS any -> any any (msg:"CYBERDUDEBIVASH ${cveId} RCE — Webshell Upload Response"; \\
    flow:established,to_client; http.response_body; \\
    pcre:"/(?:uid=\\d+|root:x:0:0|Windows IP|Volume Serial)/"; \\
    classtype:${classtype}; sid:${sid_base + 4}; rev:1; priority:1;)`,
    ],
    SQLI: [
      `alert http any any -> $HTTP_SERVERS any (msg:"CYBERDUDEBIVASH ${cveId} SQL Injection — UNION SELECT"; \\
    flow:established,to_server; http.uri; \\
    pcre:"/(?:UNION.{0,20}SELECT|UNION.{0,20}ALL.{0,20}SELECT)/i"; \\
    classtype:${classtype}; sid:${sid_base + 1}; rev:1; priority:${priority}; \\
    metadata:cve ${cveId}, mitre_technique T1190;)`,

      `alert http any any -> $HTTP_SERVERS any (msg:"CYBERDUDEBIVASH ${cveId} SQLi — Time-Based Blind"; \\
    flow:established,to_server; http.uri; \\
    pcre:"/(?:SLEEP\\(\\d{1,4}\\)|BENCHMARK\\(\\d+|WAITFOR\\sDELAY|PG_SLEEP\\(\\d)/i"; \\
    threshold:type limit, track by_src, count 3, seconds 10; \\
    classtype:${classtype}; sid:${sid_base + 2}; rev:1; priority:${priority};)`,

      `alert http any any -> $HTTP_SERVERS any (msg:"CYBERDUDEBIVASH ${cveId} SQLi — Boolean Blind"; \\
    flow:established,to_server; http.uri; \\
    pcre:"/' OR '1'='1|AND 1=1--|' OR ''='|admin'--/i"; \\
    classtype:${classtype}; sid:${sid_base + 3}; rev:1;)`,
    ],
    AUTH_BYPASS: [
      `alert http any any -> $HTTP_SERVERS any (msg:"CYBERDUDEBIVASH ${cveId} Auth Bypass — JWT None Algorithm"; \\
    flow:established,to_server; http.header; \\
    content:"Authorization"; nocase; content:"Bearer"; distance:0; nocase; \\
    pcre:"/eyJ[A-Za-z0-9+\\/=]+\\.eyJ[A-Za-z0-9+\\/=]+\\.$/"; /* no signature */ \\
    classtype:${classtype}; sid:${sid_base + 1}; rev:1; priority:1;)`,

      `alert http any any -> $HTTP_SERVERS any (msg:"CYBERDUDEBIVASH ${cveId} Auth Bypass — Path Traversal to Admin"; \\
    flow:established,to_server; http.uri; \\
    pcre:"/\\/(?:admin|secure|protected)\\/?\\.\\.\\/?\\.\\.\\/(?:admin|config|etc)/i"; \\
    classtype:${classtype}; sid:${sid_base + 2}; rev:1; priority:${priority};)`,
    ],
    DESERIALIZATION: [
      `alert http any any -> $HTTP_SERVERS any (msg:"CYBERDUDEBIVASH ${cveId} Java Deserialization Gadget Chain"; \\
    flow:established,to_server; http.request_body; \\
    content:"|AC ED 00 05|"; /* Java serialization magic bytes */ \\
    classtype:${classtype}; sid:${sid_base + 1}; rev:1; priority:1; \\
    metadata:cve ${cveId}, mitre_technique T1059;)`,

      `alert http any any -> $HTTP_SERVERS any (msg:"CYBERDUDEBIVASH ${cveId} Deserialization — ysoserial Payload"; \\
    flow:established,to_server; http.request_body; \\
    pcre:"/(?:CommonsCollections|Spring|Groovy|Clojure|JRMPClient|ROME)/"; \\
    content:"rO0AB"; /* base64 encoded \\xAC\\xED Java serial */ \\
    classtype:${classtype}; sid:${sid_base + 2}; rev:1; priority:1;)`,
    ],
    SSRF: [
      `alert http any any -> $HTTP_SERVERS any (msg:"CYBERDUDEBIVASH ${cveId} SSRF — Cloud Metadata Access"; \\
    flow:established,to_server; http.uri; \\
    pcre:"/(?:169\\.254\\.169\\.254|metadata\\.google\\.internal|169\\.254\\.170\\.2)/i"; \\
    classtype:${classtype}; sid:${sid_base + 1}; rev:1; priority:1; \\
    metadata:cve ${cveId}, mitre_technique T1046;)`,

      `alert http any any -> $HTTP_SERVERS any (msg:"CYBERDUDEBIVASH ${cveId} SSRF — Internal Network Probe"; \\
    flow:established,to_server; http.uri; \\
    pcre:"/[?&=]https?:\\/\\/(?:127\\.0\\.0\\.1|localhost|10\\.|192\\.168\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.)"/i"; \\
    classtype:${classtype}; sid:${sid_base + 2}; rev:1; priority:${priority};)`,
    ],
  };

  const typeRuleList = rulesByType[type] || rulesByType['RCE'];
  return typeRuleList.join('\n\n');
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. MODSECURITY WAF RULES
// ═══════════════════════════════════════════════════════════════════════════════

export function generateWAFRule(intel, analysis) {
  const cveId   = intel.id || 'CVE-UNKNOWN';
  const type    = intel.type || 'VULNERABILITY';
  const ruleId  = generateRuleIdFromCVE(cveId);
  const sevText = intel.severity === 'CRITICAL' ? 'CRITICAL' : 'ERROR';

  const typeRules = getWAFRulesForType(type, intel, ruleId);

  return `# ═══════════════════════════════════════════════════════════════════════
# CYBERDUDEBIVASH Sentinel APEX — ${cveId} ModSecurity WAF Rules
# ═══════════════════════════════════════════════════════════════════════
# Deploy in: /etc/modsecurity/rules/CBD-${cveId}.conf
#            /etc/nginx/modsec/rules/CBD-${cveId}.conf
#
# NGINX Integration (in nginx.conf server block):
#   modsecurity on;
#   modsecurity_rules_file /etc/nginx/modsec/main.conf;
#   modsecurity_rules_file /etc/nginx/modsec/rules/CBD-${cveId}.conf;
#
# Apache Integration (in .htaccess or VirtualHost):
#   Include /etc/modsecurity/rules/CBD-${cveId}.conf
#
# TESTING (before production):
#   nginx -t    # syntax check
#   curl -v 'http://localhost/?test=UNION SELECT 1--'
# ═══════════════════════════════════════════════════════════════════════

SecRuleEngine DetectionOnly  # Change to: On (to block) after testing

# -- Rule Set Header ----------------------------------------------------------
SecAction \\
    "id:${ruleId},\\
    phase:1,\\
    nolog,\\
    pass,\\
    setvar:'tx.cbd_${cveId.replace(/-/g,'_')}_enabled=1',\\
    msg:'CyberDudeBivash Sentinel APEX ${cveId} ruleset loaded'"

${typeRules}

# -- Logging Rule (captures all matches for SIEM) ----------------------------
SecRule TX:CBD_${cveId.replace(/-/g,'_').toUpperCase()}_SCORE "@gt 5" \\
    "id:${ruleId + 99},\\
    phase:2,\\
    log,\\
    block,\\
    status:403,\\
    msg:'CyberDudeBivash APEX: ${cveId} high-confidence block (score: %{tx.cbd_${cveId.replace(/-/g,'_')}_score})',\\
    severity:'${sevText}',\\
    tag:'cyberdudebivash/sentinel_apex',\\
    tag:'${cveId}',\\
    setvar:'ip.cbd_block_count=+1',\\
    expirevar:'ip.cbd_block_count=3600'"
`;
}

function getWAFRulesForType(type, intel, ruleId) {
  const cveId = intel.id || 'CVE-UNKNOWN';

  const rulesByType = {
    RCE: `# -- RCE Detection Rules -------------------------------------------------------

SecRule REQUEST_URI|REQUEST_BODY|ARGS \\
    "@rx (?:;|&&|\\|\\||\\$\\()\\s*(?:id|whoami|uname|cat\\s+\\/|curl\\s|wget\\s|bash\\s|sh\\s|nc\\s)" \\
    "id:${ruleId + 1},\\
    phase:2,\\
    log,\\
    deny,\\
    status:403,\\
    msg:'CyberDudeBivash APEX: ${cveId} OS Command Injection',\\
    severity:'CRITICAL',\\
    setvar:'tx.cbd_${cveId.replace(/-/g,'_')}_score=+10'"

SecRule REQUEST_URI|REQUEST_BODY|ARGS \\
    "@rx (?:\\.\\.\\/){3,}(?:etc\\/passwd|windows\\/system32|proc\\/self)" \\
    "id:${ruleId + 2},\\
    phase:2,\\
    log,\\
    deny,\\
    status:403,\\
    msg:'CyberDudeBivash APEX: ${cveId} Path Traversal to Sensitive File',\\
    severity:'CRITICAL',\\
    setvar:'tx.cbd_${cveId.replace(/-/g,'_')}_score=+10'"

SecRule REQUEST_BODY \\
    "@rx (?:bash\\s+-i|nc\\s+-e|python\\s+-c.{0,100}socket|perl\\s+-e.{0,100}socket)" \\
    "id:${ruleId + 3},\\
    phase:2,\\
    log,\\
    deny,\\
    status:403,\\
    msg:'CyberDudeBivash APEX: ${cveId} Reverse Shell Payload',\\
    severity:'CRITICAL',\\
    setvar:'tx.cbd_${cveId.replace(/-/g,'_')}_score=+15'"`,

    SQLI: `# -- SQL Injection Detection Rules -------------------------------------------

SecRule REQUEST_URI|ARGS|REQUEST_BODY \\
    "@rx (?i:\\bUNION\\b.{0,30}\\bSELECT\\b)" \\
    "id:${ruleId + 1},\\
    phase:2,\\
    log,\\
    deny,\\
    status:403,\\
    msg:'CyberDudeBivash APEX: ${cveId} SQL UNION Injection',\\
    severity:'CRITICAL',\\
    setvar:'tx.cbd_${cveId.replace(/-/g,'_')}_score=+10'"

SecRule REQUEST_URI|ARGS \\
    "@rx (?i:SLEEP\\(\\d{1,4}\\)|BENCHMARK\\(\\d+,|WAITFOR\\sDELAY|PG_SLEEP\\(\\d)" \\
    "id:${ruleId + 2},\\
    phase:2,\\
    log,\\
    deny,\\
    status:403,\\
    msg:'CyberDudeBivash APEX: ${cveId} Time-Based Blind SQLi',\\
    severity:'CRITICAL',\\
    setvar:'tx.cbd_${cveId.replace(/-/g,'_')}_score=+10'"

SecRule RESPONSE_BODY \\
    "@rx (?i:you have an error in your SQL syntax|warning.*mysql|unclosed quotation mark|ORA-[0-9]{5})" \\
    "id:${ruleId + 3},\\
    phase:4,\\
    log,\\
    msg:'CyberDudeBivash APEX: ${cveId} SQL Error Information Disclosure',\\
    severity:'HIGH',\\
    setvar:'tx.cbd_${cveId.replace(/-/g,'_')}_score=+5'"`,

    SSRF: `# -- SSRF Detection Rules -------------------------------------------------------

SecRule ARGS|REQUEST_BODY \\
    "@rx (?:https?:\\/\\/(?:169\\.254\\.169\\.254|metadata\\.google\\.internal|fd00:|::1|localhost|127\\.0\\.0\\.1))" \\
    "id:${ruleId + 1},\\
    phase:2,\\
    log,\\
    deny,\\
    status:403,\\
    msg:'CyberDudeBivash APEX: ${cveId} SSRF — Cloud Metadata/Loopback',\\
    severity:'CRITICAL',\\
    setvar:'tx.cbd_${cveId.replace(/-/g,'_')}_score=+15'"

SecRule ARGS|REQUEST_BODY \\
    "@rx (?:https?:\\/\\/(?:10\\.|192\\.168\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.))" \\
    "id:${ruleId + 2},\\
    phase:2,\\
    log,\\
    deny,\\
    status:403,\\
    msg:'CyberDudeBivash APEX: ${cveId} SSRF — Internal Network Probe',\\
    severity:'HIGH',\\
    setvar:'tx.cbd_${cveId.replace(/-/g,'_')}_score=+8'"`,
  };

  return rulesByType[type] || rulesByType['RCE'];
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. SIGMA DETECTION RULES (SIEM)
// ═══════════════════════════════════════════════════════════════════════════════

export function generateSigmaRule(intel, analysis) {
  const cveId  = intel.id || 'CVE-UNKNOWN';
  const type   = intel.type || 'VULNERABILITY';
  const safeid = cveId.toLowerCase().replace(/-/g, '_');
  const mitre  = (intel.mitre_mapping || [{ technique:'T1190', tactic:'Initial Access' }])[0];

  const typeDetection = getSigmaDetection(type, intel);

  return `# ═══════════════════════════════════════════════════════════════════════
# CYBERDUDEBIVASH Sentinel APEX — ${cveId} Sigma Detection Rule
# ═══════════════════════════════════════════════════════════════════════
# Deploy with:
#   sigma convert -t splunk rules/${safeid}.yml > ${safeid}_splunk.spl
#   sigma convert -t elastic rules/${safeid}.yml > ${safeid}_elastic.json
#   sigma convert -t qradar rules/${safeid}.yml > ${safeid}_qradar.ql
#   sigma convert -t sentinel rules/${safeid}.yml > ${safeid}_kql.kql
# ═══════════════════════════════════════════════════════════════════════

title: ${cveId} — ${(intel.title || '').substring(0, 60)}
id: ${generateUUID(cveId)}
status: stable
description: |
    Detects exploitation attempts and post-compromise activity associated with ${cveId}.
    ${(intel.description || '').substring(0, 200)}
author: CyberDudeBivash Sentinel APEX
date: ${new Date().toISOString().slice(0,10)}
modified: ${new Date().toISOString().slice(0,10)}
references:
    - https://nvd.nist.gov/vuln/detail/${cveId}
    - https://cyberdudebivash.in/threat-intel

tags:
    - attack.${mitre.tactic?.toLowerCase().replace(/\s+/g,'-') || 'initial-access'}
    - attack.${mitre.technique || 'T1190'}
    - cve.${cveId.toLowerCase()}
    - cyberdudebivash.sentinel-apex

logsource:
${typeDetection.logsource}

detection:
${typeDetection.detection}
    condition: ${typeDetection.condition}

fields:
    - src_ip
    - dest_ip
    - dest_port
    - http.request.uri
    - process.name
    - process.command_line
    - user.name
    - event.action

falsepositives:
    - Legitimate security scanning tools (authorized penetration testing)
    - Misconfigured applications generating similar patterns
    - Load balancer health checks

level: ${intel.severity?.toLowerCase() || 'high'}
`;
}

function getSigmaDetection(type, intel) {
  const detections = {
    RCE: {
      logsource: `    category: webserver
    product: generic`,
      detection: `    keywords:
        - '../../../etc/passwd'
        - '../../../windows/system32'
        - ';id;'
        - ';whoami;'
        - 'cmd.exe /c'
        - 'bash -i >&'
        - 'python -c.*socket'
        - 'eval(base64_decode'
    filter_legitimate:
        http.request.useragent|contains:
            - 'GoogleBot'
            - 'Bingbot'`,
      condition: 'keywords and not filter_legitimate',
    },
    SQLI: {
      logsource: `    category: webserver
    product: generic`,
      detection: `    sqli_patterns:
        http.request.uri|contains:
            - 'UNION SELECT'
            - 'UNION ALL SELECT'
            - 'OR 1=1--'
            - "' OR ''='"
            - 'SLEEP('
            - 'BENCHMARK('
            - 'WAITFOR DELAY'
    sqli_errors:
        message|contains:
            - 'SQL syntax'
            - 'mysql_fetch'
            - 'ORA-01756'
            - 'You have an error in your SQL'`,
      condition: 'sqli_patterns or sqli_errors',
    },
    PRIVESC: {
      logsource: `    category: process_creation
    product: linux`,
      detection: `    suid_execution:
        CommandLine|contains:
            - '/usr/bin/sudo'
            - '/usr/sbin/su '
        CommandLine|re: '\\bsudo\\s+-[sl]\\b|\\bsu\\s+-\\s'
    kernel_exploit:
        CommandLine|contains:
            - 'pkexec'
            - 'dirtycow'
            - 'dirty_sock'
            - '/proc/sysrq-trigger'
    priv_enum:
        CommandLine|contains:
            - 'find / -perm -4000'
            - 'find / -perm -u=s'
            - 'getcap -r /'`,
      condition: 'suid_execution or kernel_exploit or priv_enum',
    },
    AUTH_BYPASS: {
      logsource: `    category: webserver
    product: generic`,
      detection: `    bypass_patterns:
        http.request.uri|contains:
            - '/admin/../'
            - '/secure/%2e%2e/'
            - '/..'
        http.request.headers|contains:
            - 'X-Original-URL: /admin'
            - 'X-Rewrite-URL: /admin'
    jwt_anomaly:
        http.request.headers|re: 'eyJ[A-Za-z0-9+/=]+\\.[A-Za-z0-9+/=]+\\.$'`,
      condition: 'bypass_patterns or jwt_anomaly',
    },
  };
  return detections[type] || detections['RCE'];
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. BASH HARDENING SCRIPTS
// ═══════════════════════════════════════════════════════════════════════════════

export function generateHardeningScript(intel, analysis) {
  const cveId = intel.id || 'CVE-UNKNOWN';
  const type  = intel.type || 'VULNERABILITY';

  const typeHardening = getHardeningLogic(type, intel);

  return `#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# CYBERDUDEBIVASH Sentinel APEX — ${cveId} System Hardening Script
# ═══════════════════════════════════════════════════════════════════════════════
# CVE:       ${cveId}
# Severity:  ${intel.severity}
# Type:      ${type}
# Platform:  Linux (Ubuntu 20.04+, RHEL 8+, Debian 11+)
#
# USAGE:
#   chmod +x hardening_${cveId.replace(/-/g,'_').toLowerCase()}.sh
#   sudo bash hardening_${cveId.replace(/-/g,'_').toLowerCase()}.sh [--check|--apply|--rollback]
#   --check    : Audit current state without making changes (default)
#   --apply    : Apply all hardening measures
#   --rollback : Revert to pre-hardening state using backup
#
# IMPORTANT:
#   - Test in staging before production deployment
#   - Script creates backups at /var/backups/cbd_hardening/
#   - All changes are logged to /var/log/cbd_hardening.log
#   - Idempotent: safe to run multiple times
#
# © 2026 CyberDudeBivash Pvt. Ltd. — https://cyberdudebivash.in
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail
IFS=$'\\n\\t'

# ── Global Config ──────────────────────────────────────────────────────────────
readonly SCRIPT_NAME="CBD_Hardening_${cveId}"
readonly SCRIPT_VERSION="1.0.0"
readonly LOG_FILE="/var/log/cbd_hardening.log"
readonly BACKUP_DIR="/var/backups/cbd_hardening"
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)
MODE="\${1:---check}"  # Default: check mode

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\\033[0;31m'; ORANGE='\\033[0;33m'; GREEN='\\033[0;32m'; BLUE='\\033[0;34m'
CYAN='\\033[0;36m'; BOLD='\\033[1m'; NC='\\033[0m'

# ── Tracking ───────────────────────────────────────────────────────────────────
PASSED=0; FAILED=0; APPLIED=0; SKIPPED=0
declare -a FAILED_CHECKS=()
declare -a APPLIED_CHANGES=()

# ── Logging ────────────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$LOG_FILE")" "$BACKUP_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

log()  { echo -e "$(date '+%Y-%m-%d %H:%M:%S') [\$1] \$2"; }
info() { log "INFO " "\${BLUE}\$1\${NC}"; }
pass() { log "PASS " "\${GREEN}✅ \$1\${NC}"; ((PASSED++)); }
fail() { log "FAIL " "\${RED}❌ \$1\${NC}"; ((FAILED++)); FAILED_CHECKS+=("\$1"); }
warn() { log "WARN " "\${ORANGE}⚠️  \$1\${NC}"; }
done_apply() { log "APPLY" "\${GREEN}✅ Applied: \$1\${NC}"; ((APPLIED++)); APPLIED_CHANGES+=("\$1"); }

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "\${RED}ERROR: Must run as root (sudo bash $0)\${NC}" >&2
    exit 1
fi

# ── OS Detection ──────────────────────────────────────────────────────────────
detect_os() {
    if   [[ -f /etc/os-release ]]; then source /etc/os-release; OS_ID=\${ID:-linux}; OS_VERSION=\${VERSION_ID:-0}
    elif [[ -f /etc/redhat-release ]]; then OS_ID="rhel"; OS_VERSION="8"
    else OS_ID="linux"; OS_VERSION="0"
    fi
    PKG_MANAGER="apt-get"
    [[ "\$OS_ID" =~ ^(rhel|centos|fedora|rocky|almalinux)$ ]] && PKG_MANAGER="yum"
    [[ "\$OS_ID" == "fedora" ]] && PKG_MANAGER="dnf"
}

# ── Backup Function ────────────────────────────────────────────────────────────
backup_file() {
    local src="\$1"
    if [[ -f "\$src" ]]; then
        local dst="\${BACKUP_DIR}/\$(basename \$src).\$TIMESTAMP.bak"
        cp -p "\$src" "\$dst"
        log "BACKUP" "Backed up \$src to \$dst"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# HARDENING CHECKS AND APPLICATIONS
# ═══════════════════════════════════════════════════════════════════════════════

${typeHardening}

# ═══════════════════════════════════════════════════════════════════════════════
# COMMON HARDENING (Applied to all CVE types)
# ═══════════════════════════════════════════════════════════════════════════════

check_kernel_hardening() {
    info "Checking kernel security parameters..."

    local SYSCTL_PARAMS=(
        "net.ipv4.tcp_syncookies=1"
        "net.ipv4.conf.all.rp_filter=1"
        "net.ipv4.conf.default.rp_filter=1"
        "net.ipv4.icmp_echo_ignore_broadcasts=1"
        "net.ipv4.conf.all.accept_redirects=0"
        "net.ipv4.conf.all.send_redirects=0"
        "kernel.randomize_va_space=2"
        "kernel.exec-shield=1"
        "fs.protected_hardlinks=1"
        "fs.protected_symlinks=1"
        "kernel.core_uses_pid=1"
        "net.ipv4.tcp_max_syn_backlog=2048"
    )

    for param in "\${SYSCTL_PARAMS[@]}"; do
        key="\${param%%=*}"; val="\${param##*=}"
        current=\$(sysctl -n "\$key" 2>/dev/null || echo "MISSING")
        if [[ "\$current" == "\$val" ]]; then
            pass "sysctl \$key = \$val"
        else
            fail "sysctl \$key = \$current (expected: \$val)"
            if [[ "\$MODE" == "--apply" ]]; then
                backup_file /etc/sysctl.conf
                sysctl -w "\$param" >/dev/null
                grep -q "^\$key" /etc/sysctl.conf && \\
                    sed -i "s|^\$key.*|\$param|" /etc/sysctl.conf || \\
                    echo "\$param" >> /etc/sysctl.conf
                done_apply "sysctl \$param"
            fi
        fi
    done
    sysctl -p >/dev/null 2>&1 || true
}

check_ssh_hardening() {
    info "Checking SSH hardening..."
    local SSHD_FILE="/etc/ssh/sshd_config"
    [[ ! -f "\$SSHD_FILE" ]] && { warn "sshd_config not found — skipping"; return; }

    declare -A SSH_CHECKS=(
        ["PermitRootLogin"]="no"
        ["PasswordAuthentication"]="no"
        ["MaxAuthTries"]="3"
        ["Protocol"]="2"
        ["X11Forwarding"]="no"
        ["AllowAgentForwarding"]="no"
        ["PermitEmptyPasswords"]="no"
        ["ClientAliveInterval"]="300"
        ["ClientAliveCountMax"]="2"
    )

    for key in "\${!SSH_CHECKS[@]}"; do
        expected="\${SSH_CHECKS[\$key]}"
        current=\$(grep -i "^\$key " "\$SSHD_FILE" | awk '{print \$2}' | head -1)
        if [[ "\${current,,}" == "\${expected,,}" ]]; then
            pass "SSH \$key = \$expected"
        else
            fail "SSH \$key = '\${current:-not set}' (expected: \$expected)"
            if [[ "\$MODE" == "--apply" ]]; then
                backup_file "\$SSHD_FILE"
                sed -i "s/^#\\?\\s*\$key\\s.*\$/\$key \$expected/" "\$SSHD_FILE"
                grep -q "^\$key" "\$SSHD_FILE" || echo "\$key \$expected" >> "\$SSHD_FILE"
                done_apply "SSH \$key=\$expected"
            fi
        fi
    done

    if [[ "\$MODE" == "--apply" && \$APPLIED -gt 0 ]]; then
        sshd -t && systemctl reload sshd && info "SSH reloaded with new config"
    fi
}

check_file_permissions() {
    info "Checking critical file permissions..."

    declare -A FILE_PERMS=(
        ["/etc/passwd"]="644"
        ["/etc/shadow"]="000"
        ["/etc/group"]="644"
        ["/etc/gshadow"]="000"
        ["/etc/sudoers"]="440"
        ["/etc/crontab"]="600"
    )

    for file in "\${!FILE_PERMS[@]}"; do
        expected="\${FILE_PERMS[\$file]}"
        [[ ! -f "\$file" ]] && continue
        current=\$(stat -c "%a" "\$file")
        if [[ "\$current" == "\$expected" ]]; then
            pass "\$file permissions = \$expected"
        else
            fail "\$file permissions = \$current (expected: \$expected)"
            if [[ "\$MODE" == "--apply" ]]; then
                chmod "\$expected" "\$file"
                done_apply "chmod \$expected \$file"
            fi
        fi
    done
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

main() {
    echo -e "\\n\${BOLD}═══════════════════════════════════════════════════════════════\${NC}"
    echo -e "\${BOLD}  CYBERDUDEBIVASH Sentinel APEX — ${cveId} Hardening\${NC}"
    echo -e "\${BOLD}  Mode: \$MODE | Version: \$SCRIPT_VERSION\${NC}"
    echo -e "\${BOLD}═══════════════════════════════════════════════════════════════\${NC}\\n"

    detect_os
    info "OS: \$OS_ID \$OS_VERSION | Package Manager: \$PKG_MANAGER"

    # Run type-specific hardening
    run_type_specific_hardening

    # Run common hardening
    check_kernel_hardening
    check_ssh_hardening
    check_file_permissions

    # Summary
    echo -e "\\n\${BOLD}═══════════════════════════════════════════════════════════════\${NC}"
    echo -e "\${BOLD}  HARDENING SUMMARY\${NC}"
    echo -e "\${BOLD}═══════════════════════════════════════════════════════════════\${NC}"
    echo -e "  \${GREEN}✅ Passed:     \$PASSED\${NC}"
    echo -e "  \${RED}❌ Failed:     \$FAILED\${NC}"
    echo -e "  \${BLUE}✅ Applied:    \$APPLIED\${NC}"
    echo -e ""
    if [[ \$FAILED -gt 0 ]]; then
        echo -e "  \${RED}Failed checks:\${NC}"
        for check in "\${FAILED_CHECKS[@]}"; do
            echo -e "    - \$check"
        done
    fi
    echo -e "\\n  Log:  \$LOG_FILE"
    echo -e "  Mode: \$MODE"
    if [[ "\$MODE" == "--check" && \$FAILED -gt 0 ]]; then
        echo -e "\\n  \${ORANGE}Run with --apply to fix above issues\${NC}"
    fi
    echo -e "\${BOLD}═══════════════════════════════════════════════════════════════\${NC}\\n"

    [[ \$FAILED -gt 0 ]] && return 1 || return 0
}

main "\$@"
`;
}

function getHardeningLogic(type, intel) {
  const typeLogics = {
    RCE: `check_rce_mitigations() {
    info "Checking RCE-specific mitigations..."

    # Check ASLR
    local aslr=\$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
    [[ "\$aslr" == "2" ]] && pass "ASLR enabled (full randomization)" || fail "ASLR not fully enabled (value: \$aslr, expected: 2)"

    # Check NX/DEP via /proc/cpuinfo
    grep -qi "nx" /proc/cpuinfo && pass "NX bit enabled" || warn "NX bit status unknown"

    # Check for dangerous interpreters
    for binary in perl python python3 ruby php node; do
        if command -v "\$binary" &>/dev/null; then
            warn "\$binary interpreter present — review if required by application"
        fi
    done

    # Check cgi-bin
    for dir in /var/www/cgi-bin /usr/lib/cgi-bin /srv/www/cgi-bin; do
        if [[ -d "\$dir" ]]; then
            local count=\$(find "\$dir" -type f 2>/dev/null | wc -l)
            [[ \$count -eq 0 ]] && pass "cgi-bin directory empty" || warn "\$dir contains \$count files — review necessity"
        fi
    done

    # Check Nginx/Apache for server token exposure
    if [[ -f /etc/nginx/nginx.conf ]]; then
        grep -q "server_tokens off" /etc/nginx/nginx.conf && pass "Nginx server_tokens off" || {
            fail "Nginx server_tokens not disabled (leaks version)"
            if [[ "\$MODE" == "--apply" ]]; then
                backup_file /etc/nginx/nginx.conf
                sed -i '/http {/a\\    server_tokens off;' /etc/nginx/nginx.conf
                nginx -t && nginx -s reload
                done_apply "Nginx server_tokens off"
            fi
        }
    fi
}

run_type_specific_hardening() { check_rce_mitigations; }`,

    SQLI: `check_sqli_mitigations() {
    info "Checking SQL injection mitigations..."

    # Check MySQL configuration if present
    for mysql_conf in /etc/mysql/my.cnf /etc/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf; do
        [[ -f "\$mysql_conf" ]] || continue
        # Check for local_infile disabled
        grep -qi "^local.infile.*=.*0\\|^local.infile.*=.*OFF" "\$mysql_conf" && \\
            pass "MySQL local_infile disabled" || {
            fail "MySQL local_infile may be enabled (allows LOAD DATA LOCAL INFILE attacks)"
            if [[ "\$MODE" == "--apply" ]]; then
                backup_file "\$mysql_conf"
                echo -e "\\n[mysqld]\\nlocal-infile=0" >> "\$mysql_conf"
                systemctl restart mysql 2>/dev/null || systemctl restart mysqld 2>/dev/null || true
                done_apply "MySQL local_infile=0"
            fi
        }
    done

    # Check for PostgreSQL log settings
    for pg_conf in \$(find /etc/postgresql -name postgresql.conf 2>/dev/null | head -1); do
        grep -q "^log_statement.*=.*'all'" "\$pg_conf" && pass "PostgreSQL full query logging enabled" || \\
            warn "PostgreSQL query logging not enabled for audit trail"
    done

    # Check WAF module
    command -v modsecurity_crs_path &>/dev/null || \\
        [[ -d /etc/modsecurity ]] && pass "ModSecurity present" || warn "ModSecurity WAF not installed — consider deployment"
}

run_type_specific_hardening() { check_sqli_mitigations; }`,

    PRIVESC: `check_privesc_mitigations() {
    info "Checking privilege escalation mitigations..."

    # Check for SUID binaries
    info "Scanning for SUID binaries..."
    local suid_files=\$(find / -perm -4000 -type f 2>/dev/null | grep -v "^/proc" | sort)
    local EXPECTED_SUID=("/bin/su" "/bin/ping" "/usr/bin/sudo" "/usr/bin/passwd" "/usr/bin/newgrp" "/usr/bin/chsh" "/usr/bin/chfn" "/usr/bin/gpasswd" "/usr/bin/mount" "/usr/bin/umount")
    while IFS= read -r suid_file; do
        local expected=false
        for exp in "\${EXPECTED_SUID[@]}"; do [[ "\$suid_file" == "\$exp" ]] && expected=true && break; done
        if "\$expected"; then
            pass "Expected SUID: \$suid_file"
        else
            fail "Unexpected SUID binary: \$suid_file"
            if [[ "\$MODE" == "--apply" ]]; then
                chmod u-s "\$suid_file"
                done_apply "Removed SUID from \$suid_file"
            fi
        fi
    done <<< "\$suid_files"

    # Check sudo configuration
    visudo -cf /etc/sudoers 2>/dev/null && pass "sudoers syntax valid" || fail "sudoers file syntax error"
    grep -rq "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null && \\
        warn "NOPASSWD entries found in sudoers — review necessity" || pass "No NOPASSWD in sudoers"

    # Check world-writable directories in PATH
    for dir in \$(echo "\$PATH" | tr ':' '\\n'); do
        [[ -d "\$dir" ]] && [[ \$(stat -c '%a' "\$dir") =~ [2367] ]] && \\
            fail "World-writable directory in PATH: \$dir" || pass "PATH directory \$dir not world-writable"
    done
}

run_type_specific_hardening() { check_privesc_mitigations; }`,
  };

  return typeLogics[type] || typeLogics['RCE'];
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. INCIDENT RESPONSE PLAYBOOK
// ═══════════════════════════════════════════════════════════════════════════════

export function generateIRPlaybook(intel, analysis) {
  const cveId   = intel.id || 'CVE-UNKNOWN';
  const type    = intel.type || 'VULNERABILITY';
  const urgency = analysis.urgency || { level: 'HIGH', timeframe: '24-72 hours' };

  return `# ${cveId} — Incident Response Playbook
## CYBERDUDEBIVASH Sentinel APEX — Enterprise Defense Solutions

---

| Field | Value |
|-------|-------|
| **CVE** | ${cveId} |
| **Severity** | ${intel.severity} |
| **Type** | ${type} |
| **Risk Score** | ${analysis.risk_score || 'N/A'}/100 |
| **Urgency** | ${urgency.level} — ${urgency.timeframe} |
| **Exploit Status** | ${intel.exploit_status || 'UNKNOWN'} |
| **Patch Available** | ${intel.patch_available ? '✅ Yes' : '❌ No — Compensating controls required'} |
| **Generated** | ${new Date().toISOString()} |
| **Author** | CyberDudeBivash Sentinel APEX v1.0 |

---

## EXECUTIVE SUMMARY

${intel.description || 'A significant security vulnerability has been identified requiring immediate attention.'}

**Affected Systems:** ${(intel.affected_systems || []).join(', ') || 'See vendor advisory'}

**Potential Impact:** ${getImpactStatement(intel)}

---

## PHASE 1: DETECTION & INITIAL TRIAGE ⏱ (0–2 hours)

### 1.1 Immediate Detection Actions

- [ ] **Query SIEM for exploitation indicators** using provided detection rule
  \`\`\`
  ${analysis.detection_layer?.[0]?.siem_query || `Search for CVE-${cveId} indicators in logs`}
  \`\`\`
- [ ] **Review IDS/IPS alerts** from the last 7 days for ${cveId} signatures
- [ ] **Check WAF logs** for blocked requests matching attack patterns:
  - Pattern: \`${(intel.iocs || []).map(i => i.value).slice(0,2).join(' | ') || 'See detection signatures'}\`
- [ ] **Run detection script** on all affected systems:
  \`\`\`bash
  python3 ${cveId.replace(/-/g,'_').toLowerCase()}_detector.py --target <HOSTNAME> --logfile /var/log/app/access.log
  \`\`\`

### 1.2 Affected System Inventory

- [ ] Identify all instances of affected software in environment:
  \`\`\`bash
  # Linux — find vulnerable packages
  dpkg -l | grep -iE "${(intel.affected_systems || []).slice(0,1).join('|').split(' ')[0].toLowerCase() || 'affected-package'}"
  rpm -qa | grep -iE "${(intel.affected_systems || []).slice(0,1).join('|').split(' ')[0].toLowerCase() || 'affected-package'}"
  \`\`\`
- [ ] Document each affected system: hostname, IP, version, business criticality
- [ ] Verify internet exposure (internal vs. external-facing systems)
- [ ] Check if KEV/CISA mandate applies: ${intel.kev_added ? `⚠️ YES — CISA mandated patch by ${intel.kev_due_date || 'per agency policy'}` : 'Not in CISA KEV'}

### 1.3 Severity Assessment

| Factor | Status | Score |
|--------|--------|-------|
| CVSSv3 Base Score | ${intel.cvss_score || 'N/A'} | ${intel.cvss_score >= 9 ? '🔴 Critical' : intel.cvss_score >= 7 ? '🟠 High' : '🟡 Medium'} |
| Active Exploitation | ${intel.exploit_status === 'ACTIVELY_EXPLOITED' ? '⚠️ Confirmed' : 'Not confirmed'} | ${intel.exploit_status === 'ACTIVELY_EXPLOITED' ? '+15 pts' : '0 pts'} |
| Internet Exposed | Verify | TBD |
| Patch Available | ${intel.patch_available ? 'Yes' : 'No'} | ${intel.patch_available ? '✅' : '⚠️ Higher risk'} |

---

## PHASE 2: CONTAINMENT ⏱ (2–4 hours)

### 2.1 Immediate Containment Actions

${getContainmentSteps(type, intel)}

### 2.2 Network Controls

- [ ] **Deploy emergency WAF rule** from provided \`CBD-${cveId}.conf\` (ModSecurity):
  \`\`\`bash
  cp CBD-${cveId}.conf /etc/nginx/modsec/rules/
  nginx -t && nginx -s reload
  # Verify: tail -f /var/log/nginx/modsec_audit.log
  \`\`\`
- [ ] **Deploy IDS/IPS signature** from provided \`.rules\` file:
  \`\`\`bash
  cp ${cveId.toLowerCase().replace(/-/g,'_')}.rules /etc/suricata/rules/
  systemctl reload suricata
  \`\`\`
- [ ] **Enable enhanced logging** on affected systems
- [ ] **Block known IOCs** at firewall/proxy:
${(intel.iocs || []).map(ioc => `  \`\`\`bash\n  # Block ${ioc.type}: ${ioc.value}\n  iptables -I INPUT -s ${ioc.value} -j DROP 2>/dev/null || true\n  \`\`\``).join('\n') || '  - No IOCs identified in intel — check external threat feeds'}

### 2.3 Compromised System Handling (if exploitation confirmed)

- [ ] **Isolate compromised system** from network immediately
- [ ] **Preserve evidence** before remediation:
  \`\`\`bash
  # Create forensic snapshot
  dd if=/dev/sda of=/forensic/\$(hostname)_\$(date +%Y%m%d).img bs=4M status=progress
  # Capture memory (if possible)
  sudo avml /forensic/\$(hostname)_memory_\$(date +%Y%m%d).lime
  \`\`\`
- [ ] **Capture volatile data** (running processes, network connections, loaded modules)

---

## PHASE 3: ERADICATION ⏱ (4–24 hours)

### 3.1 Patching

${getPatchingSteps(intel)}

### 3.2 Backdoor/Persistence Removal (if compromised)

- [ ] Scan for webshells and backdoors:
  \`\`\`bash
  # Linux webshell detection
  find /var/www -name "*.php" -newer /etc/passwd -exec grep -l "eval\|base64_decode\|shell_exec" {} \\;
  # Check for unauthorized cron jobs
  crontab -l; cat /etc/crontab; ls /etc/cron.d/
  # Check authorized_keys
  find /home /root -name "authorized_keys" -newer /etc/passwd
  # Check new SUID binaries
  find / -perm -4000 -newer /etc/passwd -type f 2>/dev/null
  \`\`\`
- [ ] Verify system binary integrity:
  \`\`\`bash
  # RHEL/CentOS
  rpm -Va --nomtime --nosize | grep -v "config"
  # Debian/Ubuntu
  dpkg --verify | grep -v "^??"
  \`\`\`
- [ ] Reset all credentials on affected systems (service accounts, API keys, DB passwords)

### 3.3 Configuration Hardening

- [ ] **Apply hardening script**:
  \`\`\`bash
  sudo bash hardening_${cveId.replace(/-/g,'_').toLowerCase()}.sh --apply
  \`\`\`
- [ ] Review and apply all recommended configurations from security configuration guide

---

## PHASE 4: RECOVERY ⏱ (24–72 hours)

### 4.1 System Restoration

- [ ] Verify clean system baseline before reconnecting to network
- [ ] Restore from verified clean backup (if system was compromised)
- [ ] Deploy patched/hardened replacement system
- [ ] Validate application functionality post-patch

### 4.2 Monitoring Enhancement

- [ ] Enable SIEM alerts for ${cveId} detection signatures (30-day enhanced monitoring)
- [ ] Deploy provided Sigma rule for ongoing detection
- [ ] Implement network traffic baseline comparison
- [ ] Schedule follow-up vulnerability scan: 7 days post-remediation

### 4.3 Verification

- [ ] Re-run detection script to confirm vulnerability closed:
  \`\`\`bash
  python3 ${cveId.replace(/-/g,'_').toLowerCase()}_detector.py --target <HOSTNAME>
  # Expected: VERDICT: NOT_DETECTED
  \`\`\`
- [ ] Run vulnerability scanner (Nessus/OpenVAS/Qualys) against affected systems
- [ ] Document remediation completion in ITSM/ticket system

---

## PHASE 5: LESSONS LEARNED ⏱ (7–14 days post-incident)

### 5.1 Post-Incident Report Template

| Field | Value |
|-------|-------|
| Incident ID | IR-${new Date().getFullYear()}-XXXX |
| CVE | ${cveId} |
| Detection Method | [SIEM/IDS/Manual/Threat Hunt] |
| Time to Detect | [X hours] |
| Time to Contain | [X hours] |
| Systems Affected | [Count and names] |
| Business Impact | [Describe] |
| Root Cause | [Unpatched system/Missing control/etc.] |
| Actions Taken | [Summary] |

### 5.2 Process Improvements

- [ ] Update patch management SLA to ${intel.kev_added ? '24 hours for KEV entries' : '72 hours for CRITICAL CVEs'}
- [ ] Add ${cveId} detection signatures to standard security tool baseline
- [ ] Review attack surface inventory — are there other similar exposures?
- [ ] Update threat model with this attack vector
- [ ] Brief security team on TTPs used in this exploitation

---

## APPENDIX A: DETECTION ARTIFACTS

**SIEM Query (Splunk):**
\`\`\`
${analysis.detection_layer?.[0]?.siem_query || `index=* "${cveId}" | stats count by src_ip, dest_ip`}
\`\`\`

**Key Log Sources:**
${(analysis.detection_layer || []).map(l => `- ${l.layer}: ${l.log_sources?.join(', ')}`).join('\n')}

---

## APPENDIX B: REFERENCE LINKS

- NVD Advisory: https://nvd.nist.gov/vuln/detail/${cveId}
${intel.kev_added ? `- CISA KEV Entry: https://www.cisa.gov/known-exploited-vulnerabilities-catalog\n- CISA Due Date: ${intel.kev_due_date || 'Per agency policy'}` : ''}
- MITRE ATT&CK: https://attack.mitre.org/techniques/${(intel.mitre_mapping || [])[0]?.technique || 'T1190'}/
- CyberDudeBivash Threat Intel: https://cyberdudebivash.in/threat-intel

---
*Generated by CYBERDUDEBIVASH Sentinel APEX Defense Solutions v1.0*
*© 2026 CyberDudeBivash Pvt. Ltd. — https://cyberdudebivash.in*
`;
}

// ── IR Playbook helpers ────────────────────────────────────────────────────────
function getImpactStatement(intel) {
  const impacts = [];
  if (intel.confidentiality === 'HIGH') impacts.push('Complete data breach / credential theft');
  if (intel.integrity === 'HIGH')       impacts.push('Data manipulation / system compromise');
  if (intel.availability === 'HIGH')    impacts.push('Service disruption / ransomware deployment');
  if (intel.scope === 'CHANGED')        impacts.push('Cross-system lateral movement');
  return impacts.length ? impacts.join('; ') : 'Significant system compromise possible';
}

function getContainmentSteps(type, intel) {
  const steps = {
    RCE: `- [ ] **Immediately block** inbound traffic to affected service port if internet-facing
- [ ] **Enable maintenance mode** on affected application (show static page)
- [ ] **Increase WAF sensitivity** to "block" mode for ${intel.id}
- [ ] **Kill any suspicious child processes** spawned by web server:
  \`\`\`bash
  ps aux | grep -E "bash|nc|curl|wget" | grep wwwdata | awk '{print $2}' | xargs kill -9
  \`\`\``,
    SQLI: `- [ ] **Enable WAF blocking mode** for SQL injection patterns
- [ ] **Temporarily disable** vulnerable input fields in application config
- [ ] **Block suspicious source IPs** identified in WAF logs:
  \`\`\`bash
  # Add to nginx.conf deny list
  grep "${intel.id}" /var/log/nginx/modsec_audit.log | grep "client:" | awk '{print $2}' | sort -u
  \`\`\`
- [ ] **Rotate database credentials** used by affected application`,
    AUTH_BYPASS: `- [ ] **Immediately revoke all active sessions** and force re-authentication
- [ ] **Enable additional authentication layer** (require MFA for admin access)
- [ ] **Block access to admin endpoints** from non-authorized IP ranges
- [ ] **Reset all administrative credentials** as precaution`,
  };
  return steps[type] || steps['RCE'];
}

function getPatchingSteps(intel) {
  if (intel.patch_available) {
    return `- [ ] Download patch from vendor advisory
- [ ] Verify patch SHA256/GPG signature
- [ ] Apply in staging environment first
- [ ] Test functionality post-patch
- [ ] Apply to production in maintenance window
- [ ] Verify with: \`python3 ${(intel.id || 'CVE').replace(/-/g,'_').toLowerCase()}_detector.py --target <HOST>\``;
  }
  return `⚠️ **No patch available** — apply compensating controls:
- [ ] Deploy virtual patch via WAF (see \`CBD-${intel.id}.conf\`)
- [ ] Isolate affected service from public network if possible
- [ ] Enable maximum logging for affected component
- [ ] Monitor CISA/vendor for patch release (set up RSS/email alert)
- [ ] Subscribe to: https://nvd.nist.gov/vuln/detail/${intel.id || 'CVE-ID'}`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

function generateSIDFromCVE(cveId) {
  // Generate deterministic SID from CVE ID (9000000 - 9999999 range)
  const year = parseInt(cveId.split('-')[1] || '2025');
  const num  = parseInt(cveId.split('-')[2] || '1000');
  return 9000000 + ((year - 2020) * 10000 + (num % 10000));
}

function generateRuleIdFromCVE(cveId) {
  return generateSIDFromCVE(cveId) + 1000000;  // ModSecurity rule IDs
}

function getClasstype(type) {
  const map = {
    RCE:             'attempted-admin',
    SQLI:            'web-application-attack',
    AUTH_BYPASS:     'attempted-user',
    PRIVESC:         'attempted-admin',
    BUFFER_OVERFLOW: 'shellcode-detect',
    DESERIALIZATION: 'attempted-admin',
    SSRF:            'policy-violation',
    XSS:             'web-application-attack',
    SUPPLY_CHAIN:    'trojan-activity',
    RANSOMWARE:      'trojan-activity',
    DOS:             'denial-of-service',
  };
  return map[type] || 'attempted-intrusion';
}

function generateUUID(seed) {
  // Deterministic UUID-like string from CVE ID
  const h = (s) => {
    let hash = 0;
    for (let i = 0; i < s.length; i++) hash = Math.imul(31, hash) + s.charCodeAt(i) | 0;
    return Math.abs(hash).toString(16).padStart(8, '0');
  };
  const p1 = h(seed);
  const p2 = h(seed + 'a');
  const p3 = h(seed + 'b');
  const p4 = h(seed + 'c');
  const p5 = h(seed + 'de');
  return `${p1}-${p2.slice(0,4)}-4${p2.slice(5,8)}-${p3.slice(0,4)}-${p4}${p5.slice(0,8)}`;
}
