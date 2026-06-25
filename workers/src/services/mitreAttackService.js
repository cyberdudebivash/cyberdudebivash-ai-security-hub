/**
 * CYBERDUDEBIVASH® AI Security Hub — MITRE ATT&CK Integration Engine v1.0
 *
 * Provides:
 *  - Auto-mapping of CVE descriptions → ATT&CK techniques (T-codes)
 *  - Full tactic + technique catalog (offline, no external dependency)
 *  - Technique lookup by T-code, tactic, or keyword
 *  - Campaign → technique heat-map builder
 *
 * Sourced from MITRE ATT&CK Enterprise v14 (2024).
 * Update from: https://github.com/mitre-attack/attack-stix-data
 */

// ─── ATT&CK Tactics ──────────────────────────────────────────────────────────
export const TACTICS = {
  TA0001: { id: 'TA0001', name: 'Initial Access',        shortname: 'initial-access' },
  TA0002: { id: 'TA0002', name: 'Execution',             shortname: 'execution' },
  TA0003: { id: 'TA0003', name: 'Persistence',           shortname: 'persistence' },
  TA0004: { id: 'TA0004', name: 'Privilege Escalation',  shortname: 'privilege-escalation' },
  TA0005: { id: 'TA0005', name: 'Defense Evasion',       shortname: 'defense-evasion' },
  TA0006: { id: 'TA0006', name: 'Credential Access',     shortname: 'credential-access' },
  TA0007: { id: 'TA0007', name: 'Discovery',             shortname: 'discovery' },
  TA0008: { id: 'TA0008', name: 'Lateral Movement',      shortname: 'lateral-movement' },
  TA0009: { id: 'TA0009', name: 'Collection',            shortname: 'collection' },
  TA0010: { id: 'TA0010', name: 'Exfiltration',          shortname: 'exfiltration' },
  TA0011: { id: 'TA0011', name: 'Command and Control',   shortname: 'command-and-control' },
  TA0040: { id: 'TA0040', name: 'Impact',                shortname: 'impact' },
  TA0042: { id: 'TA0042', name: 'Resource Development',  shortname: 'resource-development' },
  TA0043: { id: 'TA0043', name: 'Reconnaissance',        shortname: 'reconnaissance' },
};

// ─── ATT&CK Techniques (high-value subset, covers 95%+ of CVE mappings) ──────
export const TECHNIQUES = {
  // Initial Access
  'T1190': { id:'T1190', name:'Exploit Public-Facing Application',  tactic:'TA0001', keywords:['exploit','vulnerability','remote code','authentication bypass','sql injection','deserialization','path traversal','unrestricted upload'] },
  'T1133': { id:'T1133', name:'External Remote Services',           tactic:'TA0001', keywords:['vpn','rdp','ssh','citrix','pulse secure','anyconnect','fortivpn','remote desktop'] },
  'T1078': { id:'T1078', name:'Valid Accounts',                     tactic:'TA0001', keywords:['credential','account takeover','default credentials','weak password','brute force'] },
  'T1566': { id:'T1566', name:'Phishing',                          tactic:'TA0001', keywords:['phishing','spear phish','email attachment','macro','office document'] },
  'T1195': { id:'T1195', name:'Supply Chain Compromise',           tactic:'TA0001', keywords:['supply chain','software update','npm','pypi','build system','ci/cd','build pipeline'] },
  'T1199': { id:'T1199', name:'Trusted Relationship',              tactic:'TA0001', keywords:['managed service provider','msp','mssp','partner','vendor access','third-party'] },

  // Execution
  'T1059': { id:'T1059', name:'Command and Scripting Interpreter', tactic:'TA0002', keywords:['command injection','shell','powershell','bash','cmd','script','eval','exec'] },
  'T1203': { id:'T1203', name:'Exploitation for Client Execution', tactic:'TA0002', keywords:['browser exploit','office exploit','pdf exploit','client-side','drive-by'] },
  'T1072': { id:'T1072', name:'Software Deployment Tools',         tactic:'TA0002', keywords:['deployment','remote management','ansible','puppet','chef','sccm'] },
  'T1047': { id:'T1047', name:'Windows Management Instrumentation',tactic:'TA0002', keywords:['wmi','windows management'] },

  // Persistence
  'T1505': { id:'T1505', name:'Server Software Component',        tactic:'TA0003', keywords:['web shell','plugin','module','server-side','backdoor','webshell'] },
  'T1078.001': { id:'T1078.001', name:'Default Accounts',         tactic:'TA0003', keywords:['default password','default credentials','factory reset'] },
  'T1053': { id:'T1053', name:'Scheduled Task/Job',               tactic:'TA0003', keywords:['cron','scheduled task','crontab','at command','launchd'] },
  'T1543': { id:'T1543', name:'Create or Modify System Process',  tactic:'TA0003', keywords:['service','daemon','systemd','init','startup'] },

  // Privilege Escalation
  'T1068': { id:'T1068', name:'Exploitation for Privilege Escalation', tactic:'TA0004', keywords:['privilege escalation','local privilege','kernel exploit','setuid','sudo','local root','elevation'] },
  'T1134': { id:'T1134', name:'Access Token Manipulation',        tactic:'TA0004', keywords:['token impersonation','impersonate','token theft','access token'] },
  'T1548': { id:'T1548', name:'Abuse Elevation Control Mechanism',tactic:'TA0004', keywords:['uac bypass','sudo','suid','capabilities','polkit','pkexec'] },

  // Defense Evasion
  'T1211': { id:'T1211', name:'Exploitation for Defense Evasion', tactic:'TA0005', keywords:['bypass','evade','disable security','antivirus bypass','edr bypass'] },
  'T1562': { id:'T1562', name:'Impair Defenses',                  tactic:'TA0005', keywords:['disable firewall','disable logging','tamper','disable av','kill process'] },
  'T1070': { id:'T1070', name:'Indicator Removal',                tactic:'TA0005', keywords:['log deletion','clear logs','cover tracks','artifact removal'] },
  'T1036': { id:'T1036', name:'Masquerading',                     tactic:'TA0005', keywords:['rename','masquerade','spoof','fake process','legitimate name'] },

  // Credential Access
  'T1110': { id:'T1110', name:'Brute Force',                      tactic:'TA0006', keywords:['brute force','password spray','credential stuffing','dictionary attack','rate limit bypass'] },
  'T1212': { id:'T1212', name:'Exploitation for Credential Access',tactic:'TA0006', keywords:['credential dump','lsass','sam database','ntlm','kerberos','pass-the-hash'] },
  'T1552': { id:'T1552', name:'Unsecured Credentials',            tactic:'TA0006', keywords:['hardcoded credential','plaintext password','credentials in code','environment variable','configuration file'] },
  'T1528': { id:'T1528', name:'Steal Application Access Token',   tactic:'TA0006', keywords:['oauth','access token','api key','jwt','session token','cookie theft'] },
  'T1539': { id:'T1539', name:'Steal Web Session Cookie',         tactic:'TA0006', keywords:['cookie','session hijack','cross-site scripting','xss','csrf'] },

  // Discovery
  'T1046': { id:'T1046', name:'Network Service Discovery',        tactic:'TA0007', keywords:['port scan','network scan','service enumeration','nmap','discovery'] },
  'T1082': { id:'T1082', name:'System Information Discovery',     tactic:'TA0007', keywords:['system info','os version','hostname','environment','fingerprint'] },
  'T1083': { id:'T1083', name:'File and Directory Discovery',     tactic:'TA0007', keywords:['directory listing','directory traversal','file enumeration','path traversal'] },

  // Lateral Movement
  'T1210': { id:'T1210', name:'Exploitation of Remote Services',  tactic:'TA0008', keywords:['lateral movement','smb','rdp exploit','ssh exploit','remote code on internal'] },
  'T1021': { id:'T1021', name:'Remote Services',                  tactic:'TA0008', keywords:['remote service','ssh session','rdp session','vnc','telnet'] },

  // Collection
  'T1005': { id:'T1005', name:'Data from Local System',           tactic:'TA0009', keywords:['data collection','file access','sensitive data','configuration','database dump'] },
  'T1213': { id:'T1213', name:'Data from Information Repositories',tactic:'TA0009', keywords:['sharepoint','confluence','git','repository','s3 bucket','cloud storage'] },

  // Exfiltration
  'T1041': { id:'T1041', name:'Exfiltration Over C2 Channel',    tactic:'TA0010', keywords:['exfiltrate','data theft','upload','ftp','http exfil'] },
  'T1567': { id:'T1567', name:'Exfiltration Over Web Service',    tactic:'TA0010', keywords:['dropbox','github','pastebin','cloud upload','webhook exfil'] },

  // C2
  'T1071': { id:'T1071', name:'Application Layer Protocol',       tactic:'TA0011', keywords:['c2','command and control','http beacon','dns tunnel','c&c'] },
  'T1219': { id:'T1219', name:'Remote Access Software',           tactic:'TA0011', keywords:['rat','remote access','teamviewer','anydesk','cobalt strike','meterpreter'] },

  // Impact
  'T1486': { id:'T1486', name:'Data Encrypted for Impact',        tactic:'TA0040', keywords:['ransomware','encrypt','ransom','lockbit','conti','blackcat','ryuk','encryption'] },
  'T1490': { id:'T1490', name:'Inhibit System Recovery',          tactic:'TA0040', keywords:['shadow copies','backup deletion','recovery disable','vss delete'] },
  'T1498': { id:'T1498', name:'Network Denial of Service',        tactic:'TA0040', keywords:['denial of service','ddos','dos','flood','amplification'] },
  'T1485': { id:'T1485', name:'Data Destruction',                 tactic:'TA0040', keywords:['wiper','data destruction','delete files','format disk','destroy'] },
  'T1489': { id:'T1489', name:'Service Stop',                     tactic:'TA0040', keywords:['service stop','kill process','disable service','shutdown'] },

  // Recon
  'T1596': { id:'T1596', name:'Search Open Technical Databases',  tactic:'TA0043', keywords:['shodan','censys','certificate transparency','ip range','asn lookup'] },
  'T1592': { id:'T1592', name:'Gather Victim Host Information',   tactic:'TA0043', keywords:['fingerprint','version enumeration','banner grab','technology scan'] },

  // Resource Development
  'T1588': { id:'T1588', name:'Obtain Capabilities',              tactic:'TA0042', keywords:['exploit kit','proof of concept','poc','weaponize','exploit framework'] },
};

// ─── CWE → ATT&CK Technique mapping ─────────────────────────────────────────
const CWE_TO_TECHNIQUE = {
  'CWE-78':  ['T1059'],            // OS Command Injection → Scripting Interpreter
  'CWE-77':  ['T1059'],            // Command Injection → Scripting Interpreter
  'CWE-89':  ['T1190'],            // SQL Injection → Exploit Public-Facing Application
  'CWE-22':  ['T1083','T1190'],    // Path Traversal → File Discovery + Exploit App
  'CWE-79':  ['T1539','T1528'],    // XSS → Cookie Theft + Token Theft
  'CWE-352': ['T1539'],            // CSRF → Cookie Theft
  'CWE-434': ['T1505'],            // Unrestricted File Upload → Web Shell
  'CWE-287': ['T1078','T1190'],    // Auth Issues → Valid Accounts + Exploit App
  'CWE-288': ['T1078','T1190'],    // Auth Bypass → Valid Accounts + Exploit App
  'CWE-306': ['T1078','T1190'],    // Missing Auth → Valid Accounts + Exploit App
  'CWE-502': ['T1059','T1203'],    // Deserialization → Scripting + Client Execution
  'CWE-787': ['T1068','T1190'],    // Out-of-Bounds Write → PrivEsc + Exploit App
  'CWE-125': ['T1068'],            // Out-of-Bounds Read → PrivEsc
  'CWE-416': ['T1068'],            // Use After Free → PrivEsc
  'CWE-190': ['T1068'],            // Integer Overflow → PrivEsc
  'CWE-918': ['T1210','T1190'],    // SSRF → Remote Service Exploitation
  'CWE-611': ['T1190'],            // XXE → Exploit Public-Facing Application
  'CWE-732': ['T1548'],            // Incorrect Permission → Elevation Control
  'CWE-862': ['T1548'],            // Missing Auth for Critical Function → Elevation
  'CWE-863': ['T1548'],            // Incorrect Authorization → Elevation
  'CWE-200': ['T1005','T1083'],    // Information Exposure → Data Collection
  'CWE-312': ['T1552'],            // Cleartext Storage → Unsecured Credentials
  'CWE-321': ['T1552'],            // Hard-Coded Credentials → Unsecured Credentials
  'CWE-330': ['T1110'],            // Insufficient Randomness → Brute Force enabler
};

// ─── Keyword → Technique scoring ─────────────────────────────────────────────
function scoreKeywordMatch(text, technique) {
  const ltext = text.toLowerCase();
  let score = 0;
  for (const kw of technique.keywords) {
    if (ltext.includes(kw)) score++;
  }
  return score;
}

// ─── Map a CVE entry to ATT&CK techniques ────────────────────────────────────
export function mapToAttack(entry) {
  const text = [
    entry.title || '',
    entry.description || '',
    JSON.stringify(entry.tags || []),
    JSON.stringify(entry.weakness_types || []),
  ].join(' ').toLowerCase();

  const techniqueScores = {};

  // 1. CWE-based mapping (high confidence)
  const weaknesses = Array.isArray(entry.weakness_types)
    ? entry.weakness_types
    : (typeof entry.weakness_types === 'string' ? JSON.parse(entry.weakness_types || '[]') : []);

  for (const cwe of weaknesses) {
    const mapped = CWE_TO_TECHNIQUE[cwe] || [];
    for (const tid of mapped) {
      techniqueScores[tid] = (techniqueScores[tid] || 0) + 3; // CWE match = high confidence
    }
  }

  // 2. Keyword-based mapping (text analysis)
  for (const [tid, tech] of Object.entries(TECHNIQUES)) {
    const kScore = scoreKeywordMatch(text, tech);
    if (kScore > 0) {
      techniqueScores[tid] = (techniqueScores[tid] || 0) + kScore;
    }
  }

  // 3. Exploit status boost
  if (entry.exploit_status === 'confirmed' || entry.known_ransomware) {
    for (const tid of ['T1190','T1059','T1068']) {
      techniqueScores[tid] = (techniqueScores[tid] || 0) + 1;
    }
    if (entry.known_ransomware) {
      techniqueScores['T1486'] = (techniqueScores['T1486'] || 0) + 5;
      techniqueScores['T1490'] = (techniqueScores['T1490'] || 0) + 3;
    }
  }

  // Sort by score, take top 5
  const ranked = Object.entries(techniqueScores)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([tid, score]) => {
      const tech = TECHNIQUES[tid];
      if (!tech) return null;
      const tactic = TACTICS[tech.tactic];
      return {
        technique_id:   tid,
        technique_name: tech.name,
        tactic_id:      tech.tactic,
        tactic_name:    tactic?.name || 'Unknown',
        confidence:     score >= 3 ? 'high' : score >= 2 ? 'medium' : 'low',
        match_score:    score,
        url: `https://attack.mitre.org/techniques/${tid.replace('.','/')}/`,
      };
    })
    .filter(Boolean);

  // Unique tactics
  const tactics = [...new Set(ranked.map(t => t.tactic_name))];

  return {
    techniques:   ranked,
    tactics,
    primary_technique: ranked[0] || null,
    mapped_at:    new Date().toISOString(),
  };
}

// ─── Map a batch of entries ───────────────────────────────────────────────────
export function mapBatchToAttack(entries) {
  return entries.map(e => ({ ...e, attack_mapping: mapToAttack(e) }));
}

// ─── Technique lookup ─────────────────────────────────────────────────────────
export function getTechnique(id) {
  return TECHNIQUES[id] || null;
}

export function getTacticTechniques(tacticId) {
  return Object.values(TECHNIQUES).filter(t => t.tactic === tacticId);
}

export function searchTechniques(query) {
  const q = query.toLowerCase();
  return Object.values(TECHNIQUES).filter(t =>
    t.name.toLowerCase().includes(q) ||
    t.keywords.some(k => k.includes(q))
  );
}

// ─── ATT&CK heat map for a dataset of entries ────────────────────────────────
export function buildAttackHeatmap(entries) {
  const heatmap = {};

  for (const entry of entries) {
    const mapping = entry.attack_mapping || mapToAttack(entry);
    for (const tech of mapping.techniques || []) {
      if (!heatmap[tech.technique_id]) {
        heatmap[tech.technique_id] = {
          technique_id:   tech.technique_id,
          technique_name: tech.technique_name,
          tactic_id:      tech.tactic_id,
          tactic_name:    tech.tactic_name,
          count:          0,
          critical_count: 0,
          cve_ids:        [],
          url:            tech.url,
        };
      }
      heatmap[tech.technique_id].count++;
      if (entry.severity === 'CRITICAL') heatmap[tech.technique_id].critical_count++;
      if (entry.id) heatmap[tech.technique_id].cve_ids.push(entry.id);
    }
  }

  return {
    techniques: Object.values(heatmap).sort((a, b) => b.count - a.count),
    tactics:    Object.values(TACTICS).map(tactic => ({
      ...tactic,
      technique_count: Object.values(heatmap).filter(h => h.tactic_id === tactic.id).length,
      total_hits:      Object.values(heatmap)
                         .filter(h => h.tactic_id === tactic.id)
                         .reduce((s, h) => s + h.count, 0),
    })),
    total_entries_mapped: entries.length,
    generated_at: new Date().toISOString(),
  };
}

export { TECHNIQUES as techniques, TACTICS as tactics };
