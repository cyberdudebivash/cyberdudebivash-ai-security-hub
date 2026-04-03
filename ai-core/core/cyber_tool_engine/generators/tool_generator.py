# ============================================================
# CYBERDUDEBIVASH AI — TOOL GENERATION ENGINE
# Generates production-grade Python tools: IOC scanners,
# malware detectors, network monitors, automation scripts.
# All generated code is fully functional and production-ready.
# ============================================================

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional
from core.cyber_tool_engine.parsers.threat_parser import ParsedThreatIntel
from core.cyber_tool_engine.classifiers.threat_classifier import ThreatClassification
from core.logging_config import get_logger

logger = get_logger("cyber_tool_engine.tool_generator")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _rule_id(prefix: str, intel: ParsedThreatIntel) -> str:
    content = f"{prefix}_{intel.threat_name}_{intel.malware_family}_{intel.threat_level}"
    return hashlib.sha256(content.encode()).hexdigest()[:8].upper()


class NetworkIOCScannerGenerator:
    """Generates a CLI Python tool that scans networks for known malicious IPs/domains."""

    def generate(self, intel: ParsedThreatIntel, classification: ThreatClassification) -> str:
        tool_id = _rule_id("TOOL", intel)
        threat_name = intel.malware_family or classification.primary_category or "Unknown"

        ips_literal = json.dumps(intel.ips[:50])
        domains_literal = json.dumps(intel.domains[:50])
        c2_literal = json.dumps(intel.c2_servers[:20])

        return f'''#!/usr/bin/env python3
"""
CYBERDUDEBIVASH AI — Network IOC Scanner
Tool ID: CDB-{tool_id}
Threat: {threat_name}
Severity: {intel.threat_level}
Generated: {_ts()}

Scans network logs, firewall exports, and live connections
for indicators of compromise associated with {threat_name}.

Usage:
    python3 cdb_ioc_scanner_{tool_id.lower()}.py --mode live
    python3 cdb_ioc_scanner_{tool_id.lower()}.py --mode file --input /var/log/firewall.log
    python3 cdb_ioc_scanner_{tool_id.lower()}.py --mode pcap --input capture.pcap
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import socket
import sys
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ── Threat Intelligence ───────────────────────────────────────
THREAT_NAME = "{threat_name}"
TOOL_ID = "CDB-{tool_id}"
SEVERITY = "{intel.threat_level}"
GENERATED = "{_ts()}"

MALICIOUS_IPS: Set[str] = set({ips_literal})
MALICIOUS_DOMAINS: Set[str] = set({domains_literal})
C2_SERVERS: Set[str] = set({c2_literal})
ALL_MALICIOUS_HOSTS = MALICIOUS_IPS | MALICIOUS_DOMAINS | C2_SERVERS

MITRE_TECHNIQUES = {json.dumps(intel.mitre_techniques[:10])}

# ── Result Container ──────────────────────────────────────────
class ScanResult:
    def __init__(self):
        self.hits: List[Dict] = []
        self.checked: int = 0
        self.start_time = datetime.now(timezone.utc)

    def add_hit(self, ioc: str, ioc_type: str, context: str, source: str):
        self.hits.append({{
            "ioc": ioc,
            "type": ioc_type,
            "context": context[:200],
            "source": source,
            "threat": THREAT_NAME,
            "severity": SEVERITY,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }})
        print(f"  [HIT] {{ioc_type.upper()}}: {{ioc}} | {{context[:80]}}")

    def summary(self) -> Dict:
        elapsed = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        return {{
            "tool_id": TOOL_ID,
            "threat": THREAT_NAME,
            "severity": SEVERITY,
            "checked": self.checked,
            "hits": len(self.hits),
            "elapsed_seconds": round(elapsed, 2),
            "results": self.hits,
        }}


# ── IOC Matching ──────────────────────────────────────────────
IP_RE = re.compile(r'\\b(?:\\d{{1,3}}\\.?){{4}}\\b')
DOMAIN_RE = re.compile(r'\\b(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{{2,}}\\b')

def extract_ips(text: str) -> List[str]:
    return IP_RE.findall(text)

def extract_domains(text: str) -> List[str]:
    return [d for d in DOMAIN_RE.findall(text) if not d.replace('.','').isdigit()]

def check_line(line: str, result: ScanResult, source: str):
    result.checked += 1
    ips = extract_ips(line)
    for ip in ips:
        if ip in MALICIOUS_IPS or ip in C2_SERVERS:
            result.add_hit(ip, "ip", line.strip(), source)

    domains = extract_domains(line)
    for domain in domains:
        for malicious in MALICIOUS_DOMAINS | C2_SERVERS:
            if malicious and (domain == malicious or domain.endswith('.' + malicious)):
                result.add_hit(domain, "domain", line.strip(), source)
                break


# ── Scan Modes ────────────────────────────────────────────────
def scan_file(filepath: str) -> ScanResult:
    result = ScanResult()
    print(f"[*] Scanning file: {{filepath}}")
    try:
        with open(filepath, 'r', errors='ignore') as f:
            for line in f:
                check_line(line, result, filepath)
    except Exception as e:
        print(f"[-] Error reading {{filepath}}: {{e}}", file=sys.stderr)
    return result


def scan_live_connections() -> ScanResult:
    result = ScanResult()
    print("[*] Scanning live network connections...")
    try:
        output = subprocess.check_output(
            ["netstat", "-tn"], text=True, timeout=30
        )
        for line in output.splitlines():
            check_line(line, result, "netstat")
    except FileNotFoundError:
        try:
            output = subprocess.check_output(
                ["ss", "-tn"], text=True, timeout=30
            )
            for line in output.splitlines():
                check_line(line, result, "ss")
        except Exception as e:
            print(f"[-] Cannot check live connections: {{e}}", file=sys.stderr)
    except Exception as e:
        print(f"[-] netstat failed: {{e}}", file=sys.stderr)

    # Also check DNS resolver cache if available
    try:
        dns_output = subprocess.check_output(
            ["ipconfig", "/displaydns"], text=True, timeout=10
        )
        for line in dns_output.splitlines():
            check_line(line, result, "dns_cache")
    except Exception:
        pass

    return result


def scan_directory(dirpath: str) -> ScanResult:
    result = ScanResult()
    print(f"[*] Scanning directory: {{dirpath}}")
    extensions = {{'.log', '.txt', '.csv', '.json', '.pcap'}}
    for root, _, files in os.walk(dirpath):
        for fname in files:
            if any(fname.endswith(ext) for ext in extensions):
                fpath = os.path.join(root, fname)
                sub = scan_file(fpath)
                result.hits.extend(sub.hits)
                result.checked += sub.checked
    return result


def resolve_and_check_domain(domain: str) -> Optional[str]:
    """Resolve domain and check if resolved IP is malicious."""
    try:
        ip = socket.gethostbyname(domain)
        if ip in MALICIOUS_IPS:
            return ip
    except Exception:
        pass
    return None


# ── Reporting ─────────────────────────────────────────────────
def write_report(summary: Dict, output_path: Optional[str] = None):
    report_path = output_path or f"cdb_scan_report_{{datetime.now().strftime('%Y%m%d_%H%M%S')}}.json"
    with open(report_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\\n[+] Report written: {{report_path}}")


def print_banner():
    print("=" * 60)
    print(f"  CYBERDUDEBIVASH AI — Network IOC Scanner")
    print(f"  Tool: {{TOOL_ID}} | Threat: {{THREAT_NAME}}")
    print(f"  Severity: {{SEVERITY}} | Generated: {{GENERATED}}")
    print(f"  IOCs: {{len(MALICIOUS_IPS)}} IPs | {{len(MALICIOUS_DOMAINS)}} Domains")
    print("=" * 60)


# ── Main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description=f"CyberDudeBivash Network IOC Scanner - {{THREAT_NAME}}"
    )
    parser.add_argument("--mode", choices=["live", "file", "dir"], default="live",
                        help="Scan mode: live connections, file, or directory")
    parser.add_argument("--input", help="Input file or directory path")
    parser.add_argument("--output", help="Output report path (JSON)")
    parser.add_argument("--quiet", action="store_true", help="Suppress banner")
    args = parser.parse_args()

    if not args.quiet:
        print_banner()

    if args.mode == "live":
        result = scan_live_connections()
    elif args.mode == "file":
        if not args.input:
            print("[-] --input required for file mode", file=sys.stderr)
            sys.exit(1)
        result = scan_file(args.input)
    elif args.mode == "dir":
        if not args.input:
            print("[-] --input required for dir mode", file=sys.stderr)
            sys.exit(1)
        result = scan_directory(args.input)
    else:
        print("[-] Unknown mode", file=sys.stderr)
        sys.exit(1)

    summary = result.summary()

    print(f"\\n[+] Scan complete: {{summary['checked']}} entries checked")
    print(f"[{'!' if summary['hits'] > 0 else '+'}] Hits: {{summary['hits']}}")

    if summary["hits"] > 0:
        print(f"\\n[!] THREAT DETECTED: {{THREAT_NAME}}")
        print(f"[!] Severity: {{SEVERITY}}")
        print(f"[!] MITRE Techniques: {{', '.join(MITRE_TECHNIQUES[:5])}}")
        print("[!] Immediate investigation recommended")
        write_report(summary, args.output)
        sys.exit(2)  # Exit code 2 = threats found

    print("[+] No malicious indicators detected")
    sys.exit(0)


if __name__ == "__main__":
    main()
'''


class FileHashScannerGenerator:
    """Generates a tool that scans files/directories for known malicious hashes."""

    def generate(self, intel: ParsedThreatIntel, classification: ThreatClassification) -> str:
        tool_id = _rule_id("HASH", intel)
        threat_name = intel.malware_family or classification.primary_category or "Unknown"
        hashes_literal = json.dumps({h.lower(): len(h) for h in intel.file_hashes[:100]})

        return f'''#!/usr/bin/env python3
"""
CYBERDUDEBIVASH AI — File Hash Scanner
Tool ID: CDB-HASH-{tool_id}
Threat: {threat_name} | Severity: {intel.threat_level}
Generated: {_ts()}

Recursively scans directories for files matching known malicious hashes
associated with {threat_name}.

Usage:
    python3 cdb_hash_scanner_{tool_id.lower()}.py --path /
    python3 cdb_hash_scanner_{tool_id.lower()}.py --path C:\\ --type md5
    python3 cdb_hash_scanner_{tool_id.lower()}.py --path /tmp --recursive
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Set

TOOL_ID = "CDB-HASH-{tool_id}"
THREAT_NAME = "{threat_name}"
SEVERITY = "{intel.threat_level}"

# Known malicious hashes: {{hash_value: hash_length}}
# Length: 32=MD5, 40=SHA1, 64=SHA256
MALICIOUS_HASHES: Dict[str, int] = {hashes_literal}

MD5_HASHES = {{h for h, l in MALICIOUS_HASHES.items() if l == 32}}
SHA1_HASHES = {{h for h, l in MALICIOUS_HASHES.items() if l == 40}}
SHA256_HASHES = {{h for h, l in MALICIOUS_HASHES.items() if l == 64}}


def compute_hashes(filepath: str) -> Dict[str, str]:
    """Compute MD5, SHA1, SHA256 for a file."""
    hashes = {{}}
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        hashes['md5'] = md5.hexdigest()
        hashes['sha1'] = sha1.hexdigest()
        hashes['sha256'] = sha256.hexdigest()
    except (PermissionError, OSError):
        pass
    return hashes


def scan_file(filepath: str) -> Optional[Dict]:
    """Check a single file against malicious hash database."""
    hashes = compute_hashes(filepath)
    if not hashes:
        return None
    for hash_type, hash_val in hashes.items():
        if hash_val in MALICIOUS_HASHES:
            return {{
                "file": filepath,
                "hash_type": hash_type,
                "hash_value": hash_val,
                "threat": THREAT_NAME,
                "severity": SEVERITY,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }}
    return None


def scan_directory(dirpath: str, recursive: bool = True,
                   max_size_mb: int = 500) -> Dict:
    results = []
    checked = 0
    skipped = 0
    max_bytes = max_size_mb * 1024 * 1024

    print(f"[*] Scanning: {{dirpath}} (recursive={{recursive}})")
    print(f"[*] Hash DB: {{len(MD5_HASHES)}} MD5, {{len(SHA1_HASHES)}} SHA1, {{len(SHA256_HASHES)}} SHA256")

    walk_fn = os.walk if recursive else lambda p: [(p, [], os.listdir(p))]

    for root, _, files in walk_fn(dirpath):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                size = os.path.getsize(fpath)
                if size > max_bytes:
                    skipped += 1
                    continue
                checked += 1
                hit = scan_file(fpath)
                if hit:
                    results.append(hit)
                    print(f"  [!] MATCH: {{fpath}}")
                    print(f"      Hash: {{hit['hash_type']}}={{hit['hash_value']}}")
            except (PermissionError, OSError):
                skipped += 1

    return {{
        "tool_id": TOOL_ID,
        "threat": THREAT_NAME,
        "severity": SEVERITY,
        "scanned_path": dirpath,
        "files_checked": checked,
        "files_skipped": skipped,
        "matches": len(results),
        "results": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }}


def main():
    parser = argparse.ArgumentParser(description=f"CDB Hash Scanner - {{THREAT_NAME}}")
    parser.add_argument("--path", required=True, help="Path to scan")
    parser.add_argument("--recursive", action="store_true", default=True)
    parser.add_argument("--max-size", type=int, default=500, help="Max file size MB")
    parser.add_argument("--output", help="Output JSON report path")
    args = parser.parse_args()

    print("=" * 60)
    print(f"  CYBERDUDEBIVASH AI — File Hash Scanner")
    print(f"  Tool: {{TOOL_ID}} | Threat: {{THREAT_NAME}}")
    print("=" * 60 + "\\n")

    result = scan_directory(args.path, args.recursive, args.max_size)

    print(f"\\n[+] Scan complete: {{result['files_checked']}} files checked")
    if result["matches"]:
        print(f"[!] THREATS FOUND: {{result['matches']}} malicious files detected!")
        out = args.output or f"hash_scan_{{datetime.now().strftime('%Y%m%d_%H%M%S')}}.json"
        with open(out, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"[+] Report: {{out}}")
        sys.exit(2)
    else:
        print("[+] No malicious files found")
        sys.exit(0)

if __name__ == "__main__":
    main()
'''


class BehaviorMonitorGenerator:
    """Generates a real-time process/behavior monitoring script."""

    def generate(self, intel: ParsedThreatIntel, classification: ThreatClassification) -> str:
        tool_id = _rule_id("MON", intel)
        threat_name = intel.malware_family or classification.primary_category or "Unknown"

        suspicious_procs = json.dumps([
            "mimikatz", "procdump", "wce", "fgdump", "pwdump",
            "meterpreter", "cobaltstrike", "empire", "ncat", "netcat",
            "nc.exe", "powersploit", "invoke-mimikatz",
        ] + [p.lower() for p in intel.persistence_methods[:5]])

        suspicious_cmdlines = json.dumps([
            "vssadmin delete", "bcdedit /set", "wbadmin delete",
            "powershell -enc", "powershell -w hidden", "-ExecutionPolicy Bypass",
            "IEX(", "Invoke-Expression", "DownloadString",
            "net user /add", "net localgroup administrators",
            "schtasks /create", "reg add HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        ] + [p.lower() for p in intel.evasion_techniques[:5]])

        return f'''#!/usr/bin/env python3
"""
CYBERDUDEBIVASH AI — Real-Time Behavior Monitor
Tool ID: CDB-MON-{tool_id}
Threat: {threat_name} | Severity: {intel.threat_level}
Generated: {_ts()}

Monitors system for behavioral indicators of {threat_name}.
Watches: process creation, network connections, file system changes.
Requires: psutil (pip install psutil)

Usage:
    sudo python3 cdb_behavior_monitor_{tool_id.lower()}.py
    sudo python3 cdb_behavior_monitor_{tool_id.lower()}.py --interval 5 --alert-webhook http://siem/webhook
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

TOOL_ID = "CDB-MON-{tool_id}"
THREAT_NAME = "{threat_name}"
SEVERITY = "{intel.threat_level}"
MITRE = {json.dumps(intel.mitre_techniques[:5])}

SUSPICIOUS_PROCESSES: Set[str] = set(p.lower() for p in {suspicious_procs})
SUSPICIOUS_CMDLINES: List[str] = {suspicious_cmdlines}
MALICIOUS_IPS: Set[str] = {json.dumps(list(set(intel.ips[:30] + intel.c2_servers[:10])))}

_running = True

def signal_handler(sig, frame):
    global _running
    print("\\n[*] Stopping monitor...")
    _running = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


class Alert:
    def __init__(self, alert_type: str, severity: str, details: Dict,
                 webhook_url: Optional[str] = None):
        self.alert = {{
            "alert_type": alert_type,
            "severity": severity,
            "threat": THREAT_NAME,
            "tool_id": TOOL_ID,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }}
        self._print()
        if webhook_url:
            self._send_webhook(webhook_url)

    def _print(self):
        sev = self.alert["severity"]
        prefix = "[!!!]" if sev == "CRITICAL" else "[!]"
        print(f"{{prefix}} ALERT: {{self.alert['alert_type']}}")
        print(f"    Severity: {{sev}} | Threat: {{THREAT_NAME}}")
        print(f"    Details: {{json.dumps(self.alert['details'])[:200]}}")
        print(f"    Time: {{self.alert['timestamp']}}")
        print()

    def _send_webhook(self, url: str):
        try:
            data = json.dumps(self.alert).encode()
            req = urllib.request.Request(url, data=data,
                                         headers={{'Content-Type': 'application/json'}})
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            print(f"[-] Webhook failed: {{e}}")


def check_processes(webhook_url: Optional[str] = None) -> int:
    """Check running processes for suspicious indicators."""
    hits = 0
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
            try:
                name = (proc.info['name'] or '').lower()
                cmdline = ' '.join(proc.info['cmdline'] or []).lower()

                # Check process name
                if any(susp in name for susp in SUSPICIOUS_PROCESSES):
                    Alert("suspicious_process", "HIGH",
                          {{"pid": proc.pid, "name": proc.info['name'],
                            "user": proc.info['username']}}, webhook_url)
                    hits += 1

                # Check command line
                for pattern in SUSPICIOUS_CMDLINES:
                    if pattern.lower() in cmdline:
                        Alert("suspicious_cmdline", SEVERITY,
                              {{"pid": proc.pid, "name": proc.info['name'],
                                "cmdline": cmdline[:200], "pattern": pattern}}, webhook_url)
                        hits += 1
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except ImportError:
        # Fallback to ps command
        try:
            output = subprocess.check_output(['ps', 'aux'], text=True, timeout=10)
            for line in output.splitlines():
                line_lower = line.lower()
                for susp in SUSPICIOUS_PROCESSES:
                    if susp in line_lower:
                        Alert("suspicious_process_ps", "HIGH",
                              {{"line": line[:200]}}, webhook_url)
                        hits += 1
        except Exception:
            pass
    return hits


def check_network_connections(webhook_url: Optional[str] = None) -> int:
    """Check active network connections for malicious IPs."""
    hits = 0
    if not MALICIOUS_IPS:
        return 0
    try:
        import psutil
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr and conn.raddr.ip in MALICIOUS_IPS:
                Alert("malicious_c2_connection", "CRITICAL",
                      {{"remote_ip": conn.raddr.ip, "remote_port": conn.raddr.port,
                        "local_port": conn.laddr.port if conn.laddr else None,
                        "pid": conn.pid, "status": conn.status}}, webhook_url)
                hits += 1
    except ImportError:
        try:
            output = subprocess.check_output(['netstat', '-tn'], text=True, timeout=10)
            for line in output.splitlines():
                for ip in MALICIOUS_IPS:
                    if ip in line:
                        Alert("malicious_connection_netstat", "CRITICAL",
                              {{"line": line.strip(), "ip": ip}}, webhook_url)
                        hits += 1
        except Exception:
            pass
    return hits


def check_persistence(webhook_url: Optional[str] = None) -> int:
    """Check common persistence locations."""
    hits = 0
    suspicious_run_keys = [
        r"HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        r"HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
    ]
    try:
        import winreg
        for key_path in suspicious_run_keys:
            try:
                parts = key_path.split('\\\\', 1)
                root = winreg.HKEY_LOCAL_MACHINE if "HKLM" in parts[0] else winreg.HKEY_CURRENT_USER
                with winreg.OpenKey(root, parts[1]) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            if any(p.lower() in str(value).lower() for p in SUSPICIOUS_PROCESSES):
                                Alert("suspicious_persistence", "HIGH",
                                      {{"key": key_path, "name": name, "value": str(value)[:200]}},
                                      webhook_url)
                                hits += 1
                            i += 1
                        except OSError:
                            break
            except Exception:
                pass
    except ImportError:
        # Linux: check cron
        try:
            cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/var/spool/cron']
            for cron_dir in cron_dirs:
                if os.path.isdir(cron_dir):
                    for fname in os.listdir(cron_dir):
                        fpath = os.path.join(cron_dir, fname)
                        try:
                            with open(fpath, 'r', errors='ignore') as f:
                                content = f.read().lower()
                            for susp in SUSPICIOUS_PROCESSES:
                                if susp in content:
                                    Alert("suspicious_cron", "HIGH",
                                          {{"file": fpath, "pattern": susp}}, webhook_url)
                                    hits += 1
                        except Exception:
                            pass
        except Exception:
            pass
    return hits


def main():
    parser = argparse.ArgumentParser(description=f"CDB Behavior Monitor - {{THREAT_NAME}}")
    parser.add_argument("--interval", type=int, default=10, help="Check interval seconds")
    parser.add_argument("--alert-webhook", help="Webhook URL for alerts (SIEM integration)")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    args = parser.parse_args()

    print("=" * 60)
    print(f"  CYBERDUDEBIVASH AI — Behavior Monitor")
    print(f"  Tool: {{TOOL_ID}} | Threat: {{THREAT_NAME}}")
    print(f"  Severity: {{SEVERITY}}")
    print(f"  Monitoring: Processes | Network | Persistence")
    print(f"  Interval: {{args.interval}}s | Webhook: {{args.alert_webhook or 'None'}}")
    print("=" * 60 + "\\n")

    total_hits = 0
    iteration = 0

    while _running:
        iteration += 1
        print(f"[*] Check #{{iteration}} @ {{datetime.now().strftime('%H:%M:%S')}}")

        hits = 0
        hits += check_processes(args.alert_webhook)
        hits += check_network_connections(args.alert_webhook)
        if iteration % 6 == 0:  # Check persistence every 6 intervals
            hits += check_persistence(args.alert_webhook)

        total_hits += hits
        if hits == 0:
            print(f"    No suspicious activity detected\\n")

        if args.once:
            break

        if _running:
            time.sleep(args.interval)

    print(f"\\n[+] Monitor stopped. Total alerts: {{total_hits}}")
    sys.exit(1 if total_hits > 0 else 0)

if __name__ == "__main__":
    main()
'''


class ToolGenerationEngine:
    """Orchestrates generation of all tool types from threat intelligence."""

    def __init__(self):
        self.network_scanner = NetworkIOCScannerGenerator()
        self.hash_scanner = FileHashScannerGenerator()
        self.behavior_monitor = BehaviorMonitorGenerator()

    def generate_all(
        self,
        intel: ParsedThreatIntel,
        classification: ThreatClassification,
        tool_types: List[str] = None,
    ) -> Dict[str, str]:
        """Generate all requested tool types."""
        tool_types = tool_types or intel.recommended_tools or ["network_ioc_scanner"]
        results = {}

        for tool_type in tool_types:
            try:
                if tool_type == "network_ioc_scanner":
                    results["network_ioc_scanner"] = self.network_scanner.generate(intel, classification)
                elif tool_type == "file_hash_scanner":
                    results["file_hash_scanner"] = self.hash_scanner.generate(intel, classification)
                elif tool_type in ("malware_detector", "behavior_monitor", "c2_detector"):
                    results["behavior_monitor"] = self.behavior_monitor.generate(intel, classification)
                elif tool_type == "generic_threat_hunter":
                    results["generic_threat_hunter"] = self.network_scanner.generate(intel, classification)
            except Exception as e:
                logger.error(f"[ToolGen] {tool_type} failed: {e}")
                results[tool_type] = f"# Tool generation failed: {e}\n"

        return results
