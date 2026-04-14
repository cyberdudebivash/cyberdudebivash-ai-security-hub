/**
 * CYBERDUDEBIVASH MYTHOS — Intel Agent v1.0
 * ══════════════════════════════════════════
 * AI-powered threat intelligence analysis engine.
 * Uses Cloudflare Workers AI (Llama 3.1) for deep analysis.
 * Falls back to rule-based analysis if AI binding unavailable.
 */

// ── MITRE ATT&CK technique registry ──────────────────────────────────────────
const MITRE = {
  'T1190': { tactic: 'Initial Access',        name: 'Exploit Public-Facing Application' },
  'T1210': { tactic: 'Lateral Movement',      name: 'Exploitation of Remote Services' },
  'T1059': { tactic: 'Execution',             name: 'Command and Scripting Interpreter' },
  'T1078': { tactic: 'Defense Evasion',       name: 'Valid Accounts' },
  'T1068': { tactic: 'Privilege Escalation',  name: 'Exploitation for Privilege Escalation' },
  'T1486': { tactic: 'Impact',                name: 'Data Encrypted for Impact (Ransomware)' },
  'T1505': { tactic: 'Persistence',           name: 'Server Software Component' },
  'T1133': { tactic: 'Initial Access',        name: 'External Remote Services' },
  'T1203': { tactic: 'Execution',             name: 'Exploitation for Client Execution' },
  'T1055': { tactic: 'Defense Evasion',       name: 'Process Injection' },
  'T1566': { tactic: 'Initial Access',        name: 'Phishing' },
  'T1021': { tactic: 'Lateral Movement',      name: 'Remote Services' },
};

// ── Attack vector inference from description ──────────────────────────────────
function inferAttackVectors(intel) {
  const src = `${intel.description || ''} ${intel.type || ''}`.toLowerCase();
  const map = [
    [/remote.?code.?exec|rce/,         'Remote Code Execution'],
    [/sql.?inject/,                     'SQL Injection'],
    [/xss|cross.?site.?script/,         'Cross-Site Scripting'],
    [/auth.?bypass|authentication.?bypass/, 'Authentication Bypass'],
    [/privilege.?escal|privesc/,        'Privilege Escalation'],
    [/path.?travers|dir.?travers/,      'Path Traversal'],
    [/buffer.?overflow|stack.?overflow/,'Buffer Overflow'],
    [/deserializ/,                      'Insecure Deserialization'],
    [/ssrf/,                            'Server-Side Request Forgery'],
    [/command.?inject/,                 'OS Command Injection'],
    [/supply.?chain/,                   'Supply Chain Attack'],
    [/ransomware/,                      'Ransomware Deployment'],
    [/zero.?day|0.?day/,               'Zero-Day Exploit'],
  ];
  const found = map.filter(([re]) => re.test(src)).map(([, name]) => name);
  return found.length ? found : ['Network-Based Attack'];
}

// ── Recommend tools based on threat type ─────────────────────────────────────
function recommendTools(intel, riskLevel) {
  const src  = `${intel.description || ''} ${intel.type || ''}`.toLowerCase();
  const base = riskLevel === 'CRITICAL' ? ['sigma_rule','yara_rule','ir_playbook','firewall_script','exec_briefing']
             : riskLevel === 'HIGH'     ? ['sigma_rule','firewall_script','ir_playbook']
             :                           ['sigma_rule','hardening_script'];
  const extra = [];
  if (/web|http|sql|xss|api/.test(src))         extra.push('firewall_script','ids_signature');
  if (/malware|ransomware|worm/.test(src))       extra.push('yara_rule','threat_hunt_pack');
  if (/linux|bash|shell/.test(src))             extra.push('hardening_script');
  if (/python|script/.test(src))                extra.push('python_scanner');
  return [...new Set([...base, ...extra])];
}

// ── MITRE technique extraction ────────────────────────────────────────────────
function extractMITRE(intel) {
  const src   = `${intel.mitre_mapping || ''} ${intel.type || ''} ${intel.description || ''}`;
  const found = [];
  for (const [id, data] of Object.entries(MITRE)) {
    if (src.includes(id) || src.toLowerCase().includes(data.name.toLowerCase())) {
      found.push({ id, ...data });
    }
  }
  // Infer from type
  const type = (intel.type || '').toUpperCase();
  if (type === 'RCE'  && !found.find(f => f.id === 'T1190')) found.push({ id: 'T1190', ...MITRE['T1190'] });
  if (/PRIV|ESCAL/.test(type) && !found.find(f => f.id === 'T1068')) found.push({ id: 'T1068', ...MITRE['T1068'] });
  if (/RANSOM/.test(type) && !found.find(f => f.id === 'T1486')) found.push({ id: 'T1486', ...MITRE['T1486'] });
  return [...new Map(found.map(f => [f.id, f])).values()].slice(0, 5);
}

// ── Risk scoring ──────────────────────────────────────────────────────────────
function computeRisk(intel) {
  const cvss    = parseFloat(intel.cvss_score || 0);
  const epss    = parseFloat(intel.epss_score || 0);
  const exploit = intel.exploit_status === 'confirmed' || !!intel.actively_exploited;
  const kev     = !!intel.kev_added;
  let score = Math.round(cvss * 10);
  if (epss >= 0.5) score = Math.min(100, score + 15);
  if (kev)         score = Math.min(100, score + 20);
  if (exploit)     score = Math.min(100, score + 10);
  const level = cvss >= 9.0 || (cvss >= 7.0 && exploit) ? 'CRITICAL'
              : cvss >= 7.0 || (cvss >= 5.0 && exploit) ? 'HIGH'
              : cvss >= 4.0 ? 'MEDIUM' : 'LOW';
  return { level, score, exploitability: exploit ? 'CONFIRMED' : epss >= 0.3 ? 'LIKELY' : 'THEORETICAL' };
}

// ── Build analysis narrative ──────────────────────────────────────────────────
function buildNarrative(intel, risk, vectors) {
  const cve      = intel.id || intel.cve_id || 'This vulnerability';
  const systems  = (intel.affected_systems || ['affected systems']).slice(0, 2).join(' and ');
  const exploit  = intel.exploit_status === 'confirmed' || !!intel.actively_exploited;
  let n = `${cve} is a ${risk.level}-severity vulnerability (CVSS ${intel.cvss_score || 'N/A'}) affecting ${systems}. `;
  if (vectors.length) n += `Attack vectors include: ${vectors.slice(0,2).join(', ')}. `;
  if (exploit)        n += `⚠️ Active exploitation confirmed in the wild — immediate response required. `;
  else if (intel.kev_added) n += `⚠️ Added to CISA KEV catalog — federal agencies must patch per mandate. `;
  if (intel.epss_score >= 0.5) n += `EPSS: ${(intel.epss_score*100).toFixed(1)}% exploitation probability within 30 days. `;
  return n.trim();
}

// ── Detection query builder ───────────────────────────────────────────────────
function buildDetectionQuery(intel) {
  const cve = intel.id || intel.cve_id || 'CVE-UNKNOWN';
  return `// Splunk SPL — detect ${cve} exploitation\nindex=* (EventCode=4625 OR EventCode=4648 OR EventCode=4688)\n| search (CommandLine="*${cve}*" OR Description="*exploit*")\n| stats count by src_ip, dest_ip, User, EventCode\n| where count > 3\n| sort -count`;
}

// ── Patch guidance builder ────────────────────────────────────────────────────
function buildPatchGuidance(intel) {
  const hasPatch = !!intel.patch_available;
  const kev      = !!intel.kev_added;
  const steps    = hasPatch
    ? ['Apply vendor patch immediately', 'Verify patch checksum/integrity', 'Test in staging first', 'Monitor logs post-patch']
    : ['No patch available — deploy mitigations', 'Block exploitation vectors at WAF/firewall', 'Consider temporary service restriction', 'Monitor for exploitation attempts'];
  if (kev) steps.unshift('⚠️ CISA KEV — federal agencies must patch within mandated deadline');
  steps.push('Run YARA/IOC scan on all affected systems after patching');
  return { has_patch: hasPatch, steps, kev_mandated: kev };
}

// ── Workers AI enhanced analysis ─────────────────────────────────────────────
async function aiEnhancedAnalysis(intel, env) {
  if (!env?.AI) return null;
  try {
    const resp = await env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
      messages: [{
        role: 'user',
        content: `You are a senior cybersecurity analyst. Analyze this CVE and return JSON only — no markdown, no explanation.
CVE: ${intel.id || intel.cve_id}  Severity: ${intel.severity} (CVSS: ${intel.cvss_score})
Type: ${intel.type}  Exploited: ${intel.exploit_status || 'unknown'}
Description: ${(intel.description || '').slice(0, 300)}
Affected: ${(intel.affected_systems || []).join(', ')}

Return this JSON:
{"executive_summary":"2-3 sentence board-level summary","technical_impact":"1-2 sentences","threat_actor":"APT/Criminal/Opportunistic/Unknown","business_risk":"short business impact description","immediate_actions":["action1","action2","action3"],"kql_detection":"one-line KQL or SPL query"}`,
      }],
      max_tokens: 400,
    });
    const text  = resp?.response || '';
    const match = text.match(/\{[\s\S]*\}/);
    return match ? JSON.parse(match[0]) : null;
  } catch (e) {
    console.warn('[intelAgent] AI failed, using rule-based:', e.message);
    return null;
  }
}

// ── MASTER analyzeIntel function (exported) ───────────────────────────────────
export async function analyzeIntel(intel, env) {
  const risk    = computeRisk(intel);
  const vectors = inferAttackVectors(intel);
  const mitre   = extractMITRE(intel);
  const tools   = recommendTools(intel, risk.level);
  const ai      = await aiEnhancedAnalysis(intel, env);
  return {
    intel_id:            intel.id || intel.cve_id,
    risk_level:          risk.level,
    risk_score:          risk.score,
    exploitability:      risk.exploitability,
    urgency:             intel.kev_added || risk.exploitability === 'CONFIRMED' ? 'IMMEDIATE'
                       : risk.level === 'CRITICAL' ? 'URGENT' : 'SCHEDULED',
    attack_vectors:      vectors,
    mitre_techniques:    mitre,
    recommended_tools:   tools,
    narrative:           ai?.executive_summary  || buildNarrative(intel, risk, vectors),
    technical_impact:    ai?.technical_impact   || `${intel.type} vulnerability with CVSS ${intel.cvss_score}`,
    threat_actor:        ai?.threat_actor       || 'Unknown',
    business_risk:       ai?.business_risk      || `${risk.level} risk to operations and data integrity`,
    immediate_actions:   ai?.immediate_actions  || buildPatchGuidance(intel).steps.slice(0, 3),
    detection_query:     ai?.kql_detection      || buildDetectionQuery(intel),
    patch_guidance:      buildPatchGuidance(intel),
    ai_enhanced:         !!ai,
    analyzed_at:         new Date().toISOString(),
  };
}

// ── Batch analysis ────────────────────────────────────────────────────────────
export async function analyzeIntelBatch(items, env, opts = {}) {
  const results = [];
  for (const intel of items.slice(0, opts.maxItems || 10)) {
    try {
      results.push({ intel_id: intel.id, success: true, analysis: await analyzeIntel(intel, env) });
    } catch (err) {
      results.push({ intel_id: intel.id, success: false, error: err.message });
    }
  }
  return results;
}
