/**
 * CYBERDUDEBIVASH AI Security Hub — Intel Analysis Engine v1.0
 * ══════════════════════════════════════════════════════════════
 * Sentinel APEX Defense Solutions — Powered by CYBERDUDEBIVASH
 *
 * MISSION: Deep-analyze normalized threat intelligence to extract:
 *   - Attack vector taxonomy
 *   - Exploitation method with technical detail
 *   - Affected system fingerprints
 *   - Detection opportunity points
 *   - Mitigation strategy matrix
 *   - Defense tool recommendations
 *   - Risk prioritization score
 *
 * Analysis output feeds directly into the Solution Engine to generate
 * production-grade defense artifacts.
 */

import { classifyType, cvssToSeverity } from './intelIngestionEngine.js';

// ─── Attack vector taxonomy ────────────────────────────────────────────────────
const ATTACK_VECTORS = {
  NETWORK: {
    label:        'Network (Remote)',
    risk:         'HIGH',
    description:  'Exploitable over the network without physical access. Highest exposure surface.',
    detection_points: ['Network IDS/IPS', 'Firewall logs', 'NetFlow analysis', 'WAF', 'DNS monitoring'],
    mitigations:  ['Network segmentation', 'Firewall rules', 'IDS/IPS signatures', 'Rate limiting', 'Geo-blocking'],
  },
  ADJACENT: {
    label:        'Adjacent Network',
    risk:         'MEDIUM',
    description:  'Requires access to adjacent network (same subnet, Bluetooth, Wi-Fi).',
    detection_points: ['Network monitoring', 'ARP tables', 'Wireless IDS', 'Switch port logs'],
    mitigations:  ['Network segmentation', 'VLAN isolation', '802.1X authentication', 'NAC'],
  },
  LOCAL: {
    label:        'Local Access Required',
    risk:         'MEDIUM',
    description:  'Requires local authenticated access. Still dangerous for privilege escalation.',
    detection_points: ['EDR alerts', 'Sysmon logs', 'Process monitoring', 'File integrity monitoring'],
    mitigations:  ['Least privilege', 'Application whitelisting', 'EDR deployment', 'User auditing'],
  },
  PHYSICAL: {
    label:        'Physical Access Required',
    risk:         'LOW',
    description:  'Requires physical presence. Limited exposure but dangerous in insider threat scenarios.',
    detection_points: ['Physical security systems', 'CCTV', 'Access logs', 'USB monitoring'],
    mitigations:  ['Physical security controls', 'Disk encryption', 'BIOS/UEFI password', 'Boot order lock'],
  },
};

// ─── Exploitation method profiles ─────────────────────────────────────────────
const EXPLOIT_PROFILES = {
  RCE: {
    method:        'Remote Code Execution',
    execution_steps: [
      'Attacker crafts malicious payload targeting the vulnerable component',
      'Payload delivered via network, file upload, or user interaction',
      'Vulnerable parsing/processing function triggers memory corruption or logic flaw',
      'Attacker achieves code execution in the context of the vulnerable process',
      'Post-exploitation: persistence, lateral movement, or data exfiltration',
    ],
    indicators_of_compromise: [
      'Unexpected child processes spawned by application',
      'Unusual outbound network connections from server process',
      'New scheduled tasks or services created',
      'Modified system binaries or configuration files',
      'Encoded PowerShell or shell commands in logs',
    ],
    detection_signatures: [
      'Anomalous process creation (parent-child relationship)',
      'Network connections to C2 infrastructure',
      'File write to system directories',
      'Unusual encoded/obfuscated commands',
    ],
    time_to_exploit: 'Minutes (if exploit kit available) to Days (if manual development)',
    skill_required:  'LOW (with public exploit) to HIGH (novel exploit development)',
  },
  SQLI: {
    method:        'SQL Injection',
    execution_steps: [
      'Attacker identifies SQL injection point in application input',
      'Error-based, blind, or time-based SQL injection technique selected',
      'Database structure enumerated (tables, columns, users)',
      'Data extraction: credentials, PII, business data',
      'Potential for OS command execution (xp_cmdshell, LOAD FILE)',
    ],
    indicators_of_compromise: [
      'Unusual database queries with UNION, SLEEP, BENCHMARK keywords',
      'SQL error messages in application responses',
      'Large data transfers from database server',
      'Database server spawning OS processes',
      'Increased query execution times',
    ],
    detection_signatures: [
      'SQL keywords in HTTP parameters (UNION, SELECT, DROP, INSERT)',
      'Time-based anomalies in database response times',
      'Database error patterns in application logs',
      'Unusual database user activity outside business hours',
    ],
    time_to_exploit: 'Minutes to Hours',
    skill_required:  'LOW (automated tools) to MEDIUM (manual)',
  },
  AUTH_BYPASS: {
    method:        'Authentication Bypass',
    execution_steps: [
      'Attacker identifies authentication mechanism flaw',
      'Crafts request that bypasses authentication check (path traversal, param manipulation, token forgery)',
      'Gains access to privileged functionality without valid credentials',
      'Escalates to full admin/root access in targeted environment',
      'Creates backdoor for persistent access',
    ],
    indicators_of_compromise: [
      'Authentication success events without prior authentication attempts',
      'Access to admin paths from unexpected IP addresses',
      'JWT tokens with manipulated claims',
      'New admin accounts created',
      'Access patterns inconsistent with user history',
    ],
    detection_signatures: [
      'Admin endpoint access from unauthorized IP ranges',
      'Malformed authentication tokens in requests',
      'Missing or anomalous session tokens',
      'Rapid sequential authentication success from new IP',
    ],
    time_to_exploit: 'Minutes',
    skill_required:  'LOW to MEDIUM',
  },
  BUFFER_OVERFLOW: {
    method:        'Buffer Overflow / Memory Corruption',
    execution_steps: [
      'Attacker fuzzes or analyzes application to identify overflow-vulnerable input',
      'Crafts oversized or malformed input to overflow stack/heap buffer',
      'Overwrites return address or function pointer with attacker-controlled value',
      'Shellcode or ROP chain executed in process memory',
      'Arbitrary code execution achieved at process privilege level',
    ],
    indicators_of_compromise: [
      'Application crashes or unexpected restarts',
      'Core dumps or crash reports with unusual stack traces',
      'Memory corruption error logs (segfault, access violation)',
      'NX/DEP/ASLR bypass artifacts in memory',
      'Process spawning unexpected child processes post-crash',
    ],
    detection_signatures: [
      'Application crash followed by unexpected process activity',
      'Oversized inputs in network traffic or file processing',
      'DEP/ASLR bypass patterns (return-oriented programming indicators)',
      'Heap spray patterns in memory monitoring',
    ],
    time_to_exploit: 'Hours to Days',
    skill_required:  'HIGH',
  },
  DESERIALIZATION: {
    method:        'Insecure Deserialization',
    execution_steps: [
      'Attacker identifies serialized object input accepted by application',
      'Crafts malicious serialized payload (Java gadget chain, PHP object injection, Python pickle)',
      'Application deserializes attacker-controlled object without validation',
      'Magic methods/gadget chains trigger arbitrary method calls',
      'Full RCE achieved during deserialization process',
    ],
    indicators_of_compromise: [
      'Base64-encoded data containing serialization markers in requests',
      'Java: "rO0AB" pattern in base64; PHP: "O:number:" pattern',
      'Unexpected process execution from application server',
      'Outbound connections to attacker-controlled infrastructure',
      'ysoserial/marshalsec tool artifacts in logs',
    ],
    detection_signatures: [
      'Serialization markers in HTTP requests/cookies',
      'Gadget chain class names in deserialization logs',
      'Unexpected JVM/PHP process spawning commands',
      'Network connections from application server to external IPs',
    ],
    time_to_exploit: 'Minutes (with ysoserial) to Hours',
    skill_required:  'MEDIUM',
  },
  SUPPLY_CHAIN: {
    method:        'Software Supply Chain Attack',
    execution_steps: [
      'Attacker compromises upstream package repository or vendor source code',
      'Malicious code injected into legitimate package/update',
      'Victim organization installs compromised dependency',
      'Backdoor activated: establishes C2 channel, exfiltrates secrets',
      'Lateral movement through trusted software execution context',
    ],
    indicators_of_compromise: [
      'New or unexpected packages in dependency manifests',
      'Package checksum mismatches',
      'Unusual network connections from build systems',
      'Unexpected DNS queries to unknown domains from CI/CD',
      'Secrets or credentials exfiltrated via environment variables',
    ],
    detection_signatures: [
      'Package integrity verification failures',
      'New outbound DNS/HTTP connections from application servers',
      'Unexpected process spawning from package manager context',
      'CI/CD pipeline anomalies: unusual commands, data exfiltration',
    ],
    time_to_exploit: 'Immediate (on installation)',
    skill_required:  'MEDIUM to HIGH (supply chain access required)',
  },
  PRIVESC: {
    method:        'Privilege Escalation',
    execution_steps: [
      'Attacker has low-privilege access to target system',
      'Identifies vulnerable SUID binary, kernel exploit, or misconfiguration',
      'Exploits vulnerability to elevate to root/SYSTEM/admin',
      'Maintains persistence with elevated privileges',
      'Full system compromise achieved',
    ],
    indicators_of_compromise: [
      'sudo/su commands from non-admin users',
      'SUID binary execution with unusual arguments',
      'Kernel exploit artifacts in memory or /tmp',
      'New users added to privileged groups (sudo, wheel, Administrators)',
      'Unexpected changes to /etc/passwd or /etc/sudoers',
    ],
    detection_signatures: [
      'Privilege escalation system calls (setuid, setgid)',
      'Unusual sudo command patterns',
      'SUID/SGID binary execution from non-root context',
      'Group membership changes outside change windows',
    ],
    time_to_exploit: 'Minutes to Hours',
    skill_required:  'MEDIUM',
  },
};

// ─── Tool recommendation matrix ───────────────────────────────────────────────
const TOOL_RECOMMENDATIONS = {
  RCE:             { tools: ['Python detection script', 'Suricata/Snort IDS rule', 'ModSecurity WAF rule', 'Bash patch validation script', 'Sigma detection rule'], primary: 'Suricata IDS + WAF Rule' },
  SQLI:            { tools: ['WAF ModSecurity rule', 'SIEM correlation rule', 'Python scanner script', 'Nginx/Apache hardening config'], primary: 'ModSecurity WAF + SIEM Rule' },
  AUTH_BYPASS:     { tools: ['JWT validation script', 'Nginx auth config', 'Python auth audit tool', 'Sigma detection rule', 'AWS IAM policy'], primary: 'Auth Hardening Config + Sigma Rule' },
  BUFFER_OVERFLOW: { tools: ['System hardening script', 'GDB/ASLR checker', 'Suricata signature', 'Bash exploit mitigation script'], primary: 'System Hardening + IDS Signature' },
  DESERIALIZATION: { tools: ['Java agent detection', 'ModSecurity rule', 'Python YARA scanner', 'Suricata signature'], primary: 'YARA Rule + WAF Config' },
  SUPPLY_CHAIN:    { tools: ['Dependency scanner Python script', 'SBOM generator', 'CI/CD security check script', 'Package integrity validator'], primary: 'Dependency Scanner + Integrity Checker' },
  SSRF:            { tools: ['ModSecurity WAF rule', 'Nginx egress control config', 'Python SSRF detector', 'Firewall egress rules'], primary: 'WAF Rule + Egress Firewall' },
  XSS:             { tools: ['CSP configuration', 'ModSecurity XSS rule', 'Python XSS scanner', 'Nginx security headers config'], primary: 'CSP Config + WAF Rule' },
  PRIVESC:         { tools: ['Linux hardening script', 'Sysdig/Falco rules', 'Bash SUID audit script', 'Sigma detection rule'], primary: 'Falco Rules + Linux Hardening' },
  ZERO_DAY:        { tools: ['Network egress filtering', 'Process monitoring (eBPF)', 'Memory forensics guide', 'Emergency response playbook'], primary: 'Network Isolation + Process Monitor' },
  RANSOMWARE:      { tools: ['File system monitoring script', 'Backup validation tool', 'Network isolation script', 'Recovery playbook'], primary: 'File Monitor + Isolation Script' },
  PHISHING:        { tools: ['SPF/DKIM/DMARC checker', 'Email security config', 'URL reputation scanner', 'User awareness template'], primary: 'Email Hardening Config' },
};

// ═══════════════════════════════════════════════════════════════════════════════
// CORE ANALYSIS FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Deep analysis of a normalized intel item.
 * @param {object} intel - Normalized intel item from intelIngestionEngine
 * @returns {object} AnalysisReport
 */
export function analyzeIntel(intel) {
  const type           = intel.type || classifyType(intel.description || '');
  const attackProfile  = EXPLOIT_PROFILES[type] || buildGenericProfile(intel);
  const vectorInfo     = ATTACK_VECTORS[intel.attack_vector] || ATTACK_VECTORS.NETWORK;
  const toolRecs       = TOOL_RECOMMENDATIONS[type] || TOOL_RECOMMENDATIONS.RCE;
  const riskScore      = calculateRiskScore(intel);
  const urgency        = classifyUrgency(intel, riskScore);
  const detectionLayer = buildDetectionLayer(intel, type);
  const mitigations    = buildMitigationMatrix(intel, type, vectorInfo);
  const affectedScope  = analyzeAffectedScope(intel);
  const patchStrategy  = buildPatchStrategy(intel);

  return {
    intel_id:        intel.id,
    intel_title:     intel.title,
    severity:        intel.severity,
    type,
    risk_score:      riskScore,
    urgency,

    // Attack analysis
    attack_method:       attackProfile.method,
    attack_vector_info:  vectorInfo,
    execution_steps:     attackProfile.execution_steps,
    time_to_exploit:     attackProfile.time_to_exploit,
    skill_required:      attackProfile.skill_required,

    // Indicators
    ioc_signatures:           attackProfile.indicators_of_compromise || [],
    detection_signatures:     attackProfile.detection_signatures || [],
    detection_layer:          detectionLayer,

    // Mitigations
    mitigation_matrix:    mitigations,
    patch_strategy:       patchStrategy,
    recommended_tools:    toolRecs,

    // Scope
    affected_scope:  affectedScope,

    // Solution blueprint
    solution_blueprint: buildSolutionBlueprint(intel, type, mitigations, toolRecs),

    // Metadata
    analyzed_at: new Date().toISOString(),
  };
}

// ─── Risk Score Calculation ───────────────────────────────────────────────────
function calculateRiskScore(intel) {
  let score = (intel.cvss_score || 5.0) * 10;  // base 0-100

  // EPSS multiplier
  if (intel.epss_score) score *= (1 + intel.epss_score);

  // KEV/Active exploitation boost
  if (intel.kev_added)                          score = Math.min(100, score * 1.3);
  if (intel.exploit_status === 'ACTIVELY_EXPLOITED') score = Math.min(100, score + 15);
  if (intel.exploit_maturity === 'HIGH')        score = Math.min(100, score + 10);

  // Attack vector weighting
  const vectorWeights = { NETWORK:1.2, ADJACENT:1.0, LOCAL:0.8, PHYSICAL:0.6 };
  score *= (vectorWeights[intel.attack_vector] || 1.0);

  // No patch penalty
  if (!intel.patch_available)                   score = Math.min(100, score + 5);

  return Math.round(Math.min(100, Math.max(0, score)));
}

// ─── Urgency Classification ───────────────────────────────────────────────────
function classifyUrgency(intel, riskScore) {
  if (intel.kev_added || intel.exploit_status === 'ACTIVELY_EXPLOITED' || riskScore >= 90) {
    return {
      level:           'EMERGENCY',
      timeframe:       'Immediate (0-24 hours)',
      action_required: 'Emergency patch or isolation required NOW',
      color:           '#ef4444',
    };
  }
  if (riskScore >= 75 || intel.severity === 'CRITICAL') {
    return {
      level:           'CRITICAL',
      timeframe:       'Urgent (24-72 hours)',
      action_required: 'Patch within 72 hours or implement compensating control',
      color:           '#f97316',
    };
  }
  if (riskScore >= 55 || intel.severity === 'HIGH') {
    return {
      level:           'HIGH',
      timeframe:       'Priority (1-2 weeks)',
      action_required: 'Schedule patch in next maintenance window',
      color:           '#f59e0b',
    };
  }
  return {
    level:           'MODERATE',
    timeframe:       'Standard (30 days)',
    action_required: 'Include in next regular patch cycle',
    color:           '#10b981',
  };
}

// ─── Detection Layer Builder ──────────────────────────────────────────────────
function buildDetectionLayer(intel, type) {
  const layers = [];
  const vectorInfo = ATTACK_VECTORS[intel.attack_vector] || ATTACK_VECTORS.NETWORK;

  // Network-layer detection
  if (['NETWORK', 'ADJACENT'].includes(intel.attack_vector)) {
    layers.push({
      layer:       'NETWORK',
      tools:       ['IDS/IPS (Suricata, Snort)', 'WAF (ModSecurity, Cloudflare)', 'NGFW', 'NetFlow/IPFIX'],
      log_sources: ['Firewall logs', 'IDS alerts', 'WAF access logs', 'DNS query logs'],
      siem_query:  buildSIEMQuery(intel, type, 'network'),
    });
  }

  // Endpoint detection
  layers.push({
    layer:       'ENDPOINT',
    tools:       ['EDR (CrowdStrike, SentinelOne, Defender ATP)', 'Sysmon', 'Auditd (Linux)', 'osquery'],
    log_sources: ['Windows Event Log (4688, 4625, 7045)', 'Sysmon (1, 3, 7, 8, 11)', 'Auditd', '/var/log/auth.log'],
    siem_query:  buildSIEMQuery(intel, type, 'endpoint'),
  });

  // Application detection
  layers.push({
    layer:       'APPLICATION',
    tools:       ['RASP', 'Application logs', 'Web server logs', 'API gateway logs'],
    log_sources: ['Apache/Nginx access logs', 'Application error logs', 'API gateway logs'],
    siem_query:  buildSIEMQuery(intel, type, 'application'),
  });

  return layers;
}

// ─── SIEM Query Generation ─────────────────────────────────────────────────────
function buildSIEMQuery(intel, type, layer) {
  const cveId  = intel.id || 'CVE-UNKNOWN';
  const queries = {
    network: {
      RCE:         `index=network dest_port IN (80,443,8080,8443) (uri_path="*/../*" OR uri_path="*cmd=*" OR request_body="*eval(*" OR request_body="*exec(*") | eval severity="HIGH" | table _time, src_ip, dest_ip, uri_path, status`,
      SQLI:        `index=web_logs (uri_query="*UNION*SELECT*" OR uri_query="*OR 1=1*" OR uri_query="*SLEEP(*" OR uri_query="*BENCHMARK(*") | stats count by src_ip, uri_query | where count > 3`,
      AUTH_BYPASS:  `index=auth action=success | eval anomaly=if(src_ip!="192.168.0.0/16" AND user_agent="*curl*","SUSPICIOUS","NORMAL") | where anomaly="SUSPICIOUS"`,
      SSRF:         `index=web_logs uri_query IN ("*http://169.254*", "*http://127.0.0.1*", "*http://localhost*", "*file:/*") | table _time, src_ip, uri_query, status`,
    },
    endpoint: {
      RCE:          `index=sysmon EventCode=1 (CommandLine="*powershell*-enc*" OR CommandLine="*cmd.exe /c*" OR CommandLine="*bash -i*") AND ParentCommandLine="*${cveId.split('-')[0].toLowerCase()}*"`,
      PRIVESC:      `index=winevent (EventCode=4672 OR EventCode=4697) | join user [search index=winevent EventCode=4624 Logon_Type=3] | where user!="SYSTEM"`,
      SUPPLY_CHAIN: `index=sysmon EventCode=3 | where NOT dest_ip IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16") AND Image IN ("npm","pip","mvn","gradle")`,
    },
    application: {
      SQLI:         `index=app_logs (error_message="*SQL syntax*" OR error_message="*mysql_fetch*" OR error_message="*ORA-01756*") | rex field=error_message "(?<table_name>[A-Za-z_]+)" | stats count by src_ip, table_name`,
      XSS:          `index=web_logs (uri_query="*<script*" OR uri_query="*javascript:*" OR uri_query="*onerror=*" OR uri_query="*onload=*") | table _time, src_ip, uri_query`,
    },
  };

  return queries[layer]?.[type] || `index=* "${cveId}" | stats count by _time, src_ip | where count > 5`;
}

// ─── Mitigation Matrix ────────────────────────────────────────────────────────
function buildMitigationMatrix(intel, type, vectorInfo) {
  const matrix = [];

  // Immediate (0-24h) mitigations
  matrix.push({
    priority:    'IMMEDIATE',
    timeframe:   '0-24 hours',
    actions: [
      ...(intel.kev_added ? ['EMERGENCY: Isolate affected systems from network immediately'] : []),
      ...(intel.patch_available ? ['Apply vendor security patch if available and tested'] : []),
      'Deploy IDS/IPS signature for CVE detection',
      'Enable enhanced logging on affected systems',
      `Block known malicious indicators: ${(intel.iocs || []).map(i => i.value).join(', ') || 'See IOC list'}`,
    ],
  });

  // Short-term (1-7 days)
  const shortTerm = vectorInfo.mitigations?.slice(0, 3) || [];
  matrix.push({
    priority:    'SHORT_TERM',
    timeframe:   '1-7 days',
    actions: [
      'Deploy WAF/NGFW rules targeting exploit traffic patterns',
      'Implement network segmentation to limit lateral movement',
      ...shortTerm,
      'Conduct threat hunt for existing compromise indicators',
    ],
  });

  // Long-term (30+ days)
  matrix.push({
    priority:    'LONG_TERM',
    timeframe:   '30+ days',
    actions: [
      'Harden system configuration (apply hardening guide)',
      'Implement zero-trust access model',
      'Deploy continuous vulnerability scanning',
      'Establish patch cadence SLA for future vulnerabilities',
      'Conduct tabletop exercise for this attack scenario',
    ],
  });

  // Type-specific mitigations
  const typeSpecific = getTypeSpecificMitigations(type, intel);
  matrix.push({
    priority:    'TYPE_SPECIFIC',
    timeframe:   'Context-dependent',
    actions:     typeSpecific,
  });

  return matrix;
}

function getTypeSpecificMitigations(type, intel) {
  const mitigations = {
    RCE:             ['Disable unnecessary services and features', 'Enable DEP/ASLR/CFG on Windows', 'Use seccomp/AppArmor on Linux', 'Deploy RASP (Runtime Application Self-Protection)', 'Implement process allowlisting'],
    SQLI:            ['Enable parameterized queries / prepared statements', 'Deploy database activity monitoring', 'Restrict database user privileges (least privilege)', 'Enable WAF with SQL injection ruleset', 'Disable verbose database error messages in production'],
    AUTH_BYPASS:     ['Implement MFA on all administrative interfaces', 'Enforce strong session management', 'Deploy OAuth 2.0 / OpenID Connect', 'Implement API gateway with auth enforcement', 'Enable anomaly-based authentication monitoring'],
    BUFFER_OVERFLOW: ['Enable stack canaries (compile-time)', 'Enable ASLR at OS level', 'Use memory-safe languages for new development', 'Apply Control Flow Integrity (CFI)', 'Enable sandboxing for vulnerable processes'],
    DESERIALIZATION: ['Implement deserialization firewall/filter', 'Disable Java serialization entirely if not needed', 'Use serialization allowlisting', 'Run deserialization in sandboxed process', 'Monitor for gadget chain patterns'],
    SUPPLY_CHAIN:    ['Lock dependency versions (package-lock.json, Pipfile.lock)', 'Verify package checksums/signatures', 'Use private package registry with scanning', 'Implement SBOM (Software Bill of Materials)', 'Monitor CI/CD pipeline for unauthorized changes'],
    SSRF:            ['Implement server-side URL allowlisting', 'Block access to cloud metadata endpoints (169.254.169.254)', 'Use DNS rebinding protection', 'Implement egress firewall rules', 'Deploy WAF with SSRF detection'],
    XSS:             ['Implement strict Content Security Policy (CSP)', 'Enable HTTPOnly and Secure cookie flags', 'Use context-aware output encoding', 'Deploy WAF with XSS ruleset', 'Implement Subresource Integrity (SRI)'],
    PRIVESC:         ['Remove unnecessary SUID/SGID binaries', 'Implement least-privilege service accounts', 'Deploy Linux kernel hardening (seccomp, namespaces)', 'Enable Windows Credential Guard', 'Monitor for privilege escalation patterns'],
    RANSOMWARE:      ['Implement 3-2-1 backup strategy with offline copies', 'Deploy endpoint protection with rollback capability', 'Network micro-segmentation to limit propagation', 'Disable unnecessary administrative shares (SMB)', 'Enable Protected Mode for Office applications'],
  };
  return mitigations[type] || ['Apply vendor-recommended mitigations', 'Enable comprehensive logging', 'Implement network segmentation'];
}

// ─── Patch Strategy ───────────────────────────────────────────────────────────
function buildPatchStrategy(intel) {
  const urgencyDays = intel.kev_added ? 1 : intel.severity === 'CRITICAL' ? 3 : intel.severity === 'HIGH' ? 14 : 30;

  return {
    patch_available:      intel.patch_available,
    urgency_days:         urgencyDays,
    patch_procedure: [
      '1. Verify vendor advisory and patch authenticity (check SHA256/GPG signature)',
      '2. Test patch in staging environment matching production configuration',
      '3. Create rollback plan and system snapshot/backup',
      '4. Deploy to production during approved maintenance window',
      '5. Verify patch success: re-run vulnerability scanner post-patch',
      '6. Document patch application in CMDB/change management system',
    ],
    compensating_controls: intel.patch_available ? [] : [
      'Virtual patching via WAF rule',
      'Network-level blocking of exploit traffic',
      'Service isolation or temporary disable',
      'Enhanced monitoring with rapid response SLA',
    ],
    vendor_advisory: `https://nvd.nist.gov/vuln/detail/${intel.id}`,
  };
}

// ─── Affected Scope Analysis ──────────────────────────────────────────────────
function analyzeAffectedScope(intel) {
  const systems  = intel.affected_systems || [];
  const exposure = classifyExposure(intel);

  return {
    systems_count:      systems.length,
    systems,
    exposure_level:     exposure,
    internet_facing:    ['NETWORK'].includes(intel.attack_vector),
    authentication_req: intel.privileges_required !== 'NONE',
    user_interaction:   intel.user_interaction === 'REQUIRED',
    scope_change:       intel.scope === 'CHANGED',
    blast_radius:       calculateBlastRadius(intel),
  };
}

function classifyExposure(intel) {
  if (intel.attack_vector === 'NETWORK' && intel.privileges_required === 'NONE') return 'CRITICAL_EXPOSURE';
  if (intel.attack_vector === 'NETWORK') return 'HIGH_EXPOSURE';
  if (intel.attack_vector === 'ADJACENT') return 'MEDIUM_EXPOSURE';
  return 'LIMITED_EXPOSURE';
}

function calculateBlastRadius(intel) {
  const systemCount = (intel.affected_systems || []).length;
  if (intel.scope === 'CHANGED')           return 'CRITICAL — Can impact systems beyond vulnerable component';
  if (systemCount > 5)                     return 'HIGH — Multiple systems/platforms affected';
  if (intel.availability === 'HIGH')       return 'HIGH — Full service disruption possible';
  return 'MODERATE — Impact limited to vulnerable component';
}

// ─── Solution Blueprint ───────────────────────────────────────────────────────
function buildSolutionBlueprint(intel, type, mitigations, toolRecs) {
  return {
    product_type:    determinePrimProductType(type),
    recommended_tools: toolRecs,
    artifacts_to_generate: [
      { id: 'detection_script',    label: 'Detection Script',          format: 'Python (.py)',    priority: 1 },
      { id: 'ids_signature',       label: 'IDS/IPS Signature',         format: 'Suricata (.rules)', priority: 2 },
      { id: 'waf_rule',            label: 'WAF Rule',                  format: 'ModSecurity (.conf)', priority: 3 },
      { id: 'sigma_rule',          label: 'SIEM Detection Rule',       format: 'Sigma YAML',      priority: 4 },
      { id: 'ir_playbook',         label: 'Incident Response Playbook', format: 'Markdown (.md)', priority: 5 },
      { id: 'hardening_script',    label: 'System Hardening Script',   format: 'Bash (.sh)',      priority: 6 },
      { id: 'firewall_rules',      label: 'Firewall/Egress Rules',     format: 'iptables/nft',    priority: 7 },
    ],
    estimated_deployment_time: '2-4 hours',
    deployment_complexity:     type === 'SUPPLY_CHAIN' ? 'HIGH' : type === 'RCE' ? 'MEDIUM' : 'LOW',
  };
}

function determinePrimProductType(type) {
  const mapping = {
    RCE:         'Detection + Response Kit',
    SQLI:        'Web Application Defense Kit',
    AUTH_BYPASS:  'Authentication Hardening Kit',
    PRIVESC:     'Privilege Escalation Defense Kit',
    SUPPLY_CHAIN:'Supply Chain Security Kit',
    RANSOMWARE:  'Ransomware Defense + Recovery Kit',
    PHISHING:    'Email Security Defense Kit',
    SSRF:        'Server-Side Request Forgery Defense Kit',
    XSS:         'Web Application Defense Kit',
  };
  return mapping[type] || 'Comprehensive Security Defense Kit';
}

function buildGenericProfile(intel) {
  return {
    method:        intel.type || 'Vulnerability Exploitation',
    execution_steps: [
      'Attacker identifies and validates vulnerable target',
      'Exploit payload crafted targeting vulnerable component',
      'Payload delivered via applicable attack vector',
      'Vulnerability triggered, attacker gains initial foothold',
      'Post-exploitation activities commence',
    ],
    indicators_of_compromise: [
      'Unusual network connections from affected systems',
      'Unexpected process creation or file modifications',
      'Authentication anomalies in system logs',
      'Application errors coinciding with exploitation attempts',
    ],
    detection_signatures: [
      'CVE-specific payload patterns in network traffic',
      'Application behavior anomalies post-exploitation',
      'IOC matches in threat intelligence feeds',
    ],
    time_to_exploit: 'Variable',
    skill_required:  'MEDIUM',
  };
}
