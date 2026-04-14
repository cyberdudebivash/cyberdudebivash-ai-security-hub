/**
 * CYBERDUDEBIVASH AI Security Hub — Attack Graph Engine v8.0
 *
 * Generates D3.js-compatible force-directed attack graphs showing:
 *   - Attacker entry points
 *   - Exploit chain paths through vulnerabilities
 *   - Lateral movement routes
 *   - Impact nodes (data, services, identities)
 *
 * Graph format is compatible with D3.js force simulation and
 * can be rendered client-side as an interactive SVG.
 *
 * Also provides:
 *   - MITRE ATT&CK technique simulation
 *   - Threat actor profiles
 *   - Exploit path scoring
 */

// ─── Node types and visual config ─────────────────────────────────────────────
const NODE_TYPES = {
  attacker:    { color: '#ef4444', icon: '👤', shape: 'triangle', group: 0 },
  internet:    { color: '#f59e0b', icon: '🌐', shape: 'circle',   group: 1 },
  entry_point: { color: '#f97316', icon: '🚪', shape: 'rect',     group: 2 },
  finding:     { color: '#a855f7', icon: '⚠️', shape: 'diamond',  group: 3 },
  pivot:       { color: '#3b82f6', icon: '↔️', shape: 'circle',   group: 4 },
  data_asset:  { color: '#10b981', icon: '💾', shape: 'rect',     group: 5 },
  impact:      { color: '#ef4444', icon: '💥', shape: 'hexagon',  group: 6 },
  defense:     { color: '#64748b', icon: '🛡️', shape: 'circle',   group: 7 },
};

// Module-specific attack graph templates
const MODULE_GRAPHS = {
  domain: {
    entry_nodes: [
      { id:'internet',       label:'Internet',         type:'internet',    risk: 0 },
      { id:'dns_lookup',     label:'DNS Lookup',       type:'entry_point', risk:10 },
      { id:'tls_handshake',  label:'TLS Handshake',    type:'entry_point', risk:20 },
      { id:'http_request',   label:'HTTP Request',     type:'entry_point', risk:15 },
      { id:'email_gateway',  label:'Email Gateway',    type:'entry_point', risk:25 },
    ],
    impact_nodes: [
      { id:'data_intercept', label:'Data Interception', type:'impact', risk:90 },
      { id:'domain_hijack',  label:'Domain Hijack',     type:'impact', risk:85 },
      { id:'phishing',       label:'Phishing Campaign', type:'impact', risk:80 },
      { id:'brand_damage',   label:'Brand Damage',      type:'impact', risk:70 },
      { id:'blacklisting',   label:'IP Blacklisting',   type:'impact', risk:60 },
    ],
    attacker_node: { id:'attacker', label:'Threat Actor', type:'attacker', risk:100 },
  },
  ai: {
    entry_nodes: [
      { id:'api_endpoint',   label:'API Endpoint',     type:'entry_point', risk:20 },
      { id:'chat_interface', label:'Chat Interface',   type:'entry_point', risk:15 },
      { id:'rag_pipeline',   label:'RAG Pipeline',     type:'entry_point', risk:30 },
      { id:'tool_call',      label:'Tool/Function Call', type:'entry_point', risk:35 },
    ],
    impact_nodes: [
      { id:'data_exfil',    label:'Data Exfiltration',   type:'impact', risk:90 },
      { id:'prompt_leak',   label:'System Prompt Leak',  type:'impact', risk:80 },
      { id:'agent_abuse',   label:'Agent Abuse',         type:'impact', risk:85 },
      { id:'pii_exposure',  label:'PII Exposure',        type:'impact', risk:75 },
    ],
    attacker_node: { id:'attacker', label:'Adversarial User', type:'attacker', risk:100 },
  },
  redteam: {
    entry_nodes: [
      { id:'phishing_email', label:'Phishing Email',   type:'entry_point', risk:40 },
      { id:'vpn_portal',     label:'VPN Portal',       type:'entry_point', risk:35 },
      { id:'web_app',        label:'Web Application',  type:'entry_point', risk:30 },
      { id:'supply_chain',   label:'Supply Chain',     type:'entry_point', risk:45 },
    ],
    impact_nodes: [
      { id:'ransomware',    label:'Ransomware Deploy',  type:'impact', risk:100 },
      { id:'data_theft',    label:'Data Theft',         type:'impact', risk:90 },
      { id:'c2_channel',    label:'C2 Established',     type:'impact', risk:80 },
      { id:'privilege_gain',label:'Domain Admin Access',type:'impact', risk:95 },
    ],
    attacker_node: { id:'attacker', label:'APT / Ransomware Group', type:'attacker', risk:100 },
  },
  identity: {
    entry_nodes: [
      { id:'login_portal',   label:'Login Portal',     type:'entry_point', risk:30 },
      { id:'mfa_push',       label:'MFA Push',         type:'entry_point', risk:35 },
      { id:'sso_provider',   label:'SSO Provider',     type:'entry_point', risk:25 },
      { id:'service_account',label:'Service Account',  type:'entry_point', risk:40 },
    ],
    impact_nodes: [
      { id:'account_takeover', label:'Account Takeover',   type:'impact', risk:95 },
      { id:'lateral_move',     label:'Lateral Movement',   type:'impact', risk:85 },
      { id:'priv_escalation',  label:'Privilege Escalation', type:'impact', risk:90 },
      { id:'data_access',      label:'Sensitive Data Access', type:'impact', risk:80 },
    ],
    attacker_node: { id:'attacker', label:'Insider / Credential Thief', type:'attacker', risk:100 },
  },
  compliance: {
    entry_nodes: [
      { id:'audit_request',  label:'Audit/Assessment',  type:'entry_point', risk:10 },
      { id:'regulator',      label:'Regulatory Body',   type:'entry_point', risk:20 },
      { id:'customer_qa',    label:'Customer Questionnaire', type:'entry_point', risk:15 },
    ],
    impact_nodes: [
      { id:'regulatory_fine', label:'Regulatory Fine',    type:'impact', risk:80 },
      { id:'contract_loss',   label:'Contract Loss',      type:'impact', risk:70 },
      { id:'reputational',    label:'Reputational Damage',type:'impact', risk:65 },
      { id:'audit_failure',   label:'Audit Failure',      type:'impact', risk:75 },
    ],
    attacker_node: { id:'attacker', label:'Auditor / Competitor', type:'attacker', risk:50 },
  },
};

// ─── Main API ─────────────────────────────────────────────────────────────────

/**
 * Build a complete D3-compatible attack graph for a scan result.
 */
export function buildAttackGraph(scanResult, module) {
  const findings = [...(scanResult.findings || []), ...(scanResult.locked_findings || [])];
  const score    = scanResult.risk_score || 0;
  const template = MODULE_GRAPHS[module] || MODULE_GRAPHS.domain;

  const nodes = [];
  const links = [];
  const nodeIds = new Set();

  // Add attacker node
  addNode(nodes, nodeIds, { ...template.attacker_node, radius: 20, fixed: true });

  // Add internet/entry nodes
  template.entry_nodes.forEach(n => {
    if (nodeIds.size < 15) {
      addNode(nodes, nodeIds, { ...n, radius: 14 });
      addLink(links, 'attacker', n.id, { type: 'recon', strength: 0.3, label: 'scan' });
    }
  });

  // Add finding nodes (vulnerabilities found)
  const topFindings = findings
    .sort((a,b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0))
    .slice(0, 8);

  topFindings.forEach((f, i) => {
    const nodeId  = `finding_${i}`;
    const sevColor = SEVERITY_COLORS[f.severity] || '#6b7280';
    const risk     = SEVERITY_RANK[f.severity] * 25;

    addNode(nodes, nodeIds, {
      id:      nodeId,
      label:   f.title?.slice(0, 30) || `Finding ${i+1}`,
      type:    'finding',
      severity: f.severity,
      color:   sevColor,
      risk,
      radius:  10 + (SEVERITY_RANK[f.severity] || 1) * 2,
    });

    // Connect finding to entry point
    const entryNode = template.entry_nodes[i % template.entry_nodes.length];
    if (nodeIds.has(entryNode.id)) {
      addLink(links, entryNode.id, nodeId, {
        type:     'exploit',
        strength: 0.6,
        label:    f.severity === 'CRITICAL' ? '⚡ exploit' : 'weakness',
        animated: f.severity === 'CRITICAL',
      });
    }
  });

  // Add pivot nodes for complex attack paths
  if (findings.length >= 3 && score >= 50) {
    const pivotId = 'pivot_core';
    addNode(nodes, nodeIds, { id: pivotId, label: 'Foothold', type: 'pivot', risk: score, radius: 13 });

    // Connect top findings to pivot
    topFindings.slice(0, 3).forEach((_, i) => {
      if (nodeIds.has(`finding_${i}`)) {
        addLink(links, `finding_${i}`, pivotId, { type: 'chain', strength: 0.5, label: 'chain' });
      }
    });

    // Connect pivot to impacts
    template.impact_nodes.slice(0, 2).forEach(n => {
      addNode(nodes, nodeIds, { ...n, radius: 16 });
      addLink(links, pivotId, n.id, { type: 'impact', strength: 0.7, label: '→ impact', animated: true });
    });
  } else {
    // Connect directly for lower-risk scans
    template.impact_nodes.slice(0, 2).forEach(n => {
      addNode(nodes, nodeIds, { ...n, radius: 14 });
      topFindings.slice(0, 2).forEach((_, i) => {
        if (nodeIds.has(`finding_${i}`)) {
          addLink(links, `finding_${i}`, n.id, { type: 'impact', strength: 0.4, label: '→ risk' });
        }
      });
    });
  }

  // Add defense nodes
  const defenseNodes = getDefenseNodes(module, findings);
  defenseNodes.forEach(d => {
    addNode(nodes, nodeIds, { ...d, radius: 10 });
    // Connect defenses to the entry points they protect
    template.entry_nodes.slice(0, 2).forEach(e => {
      if (nodeIds.has(e.id)) {
        addLink(links, d.id, e.id, { type: 'defense', strength: 0.2, label: 'protect', dashed: true });
      }
    });
  });

  return {
    nodes,
    links,
    metadata: {
      module,
      risk_score:     score,
      node_count:     nodes.length,
      link_count:     links.length,
      critical_paths: countCriticalPaths(links),
      generated_at:   new Date().toISOString(),
    },
    d3_config: {
      charge:          -300,
      link_distance:   80,
      center_strength: 0.1,
      collision_radius: 30,
    },
  };
}

/**
 * Simulate exploit paths — returns ordered chains from entry to impact.
 */
export function simulateExploitPaths(findings, module, target) {
  const template = MODULE_GRAPHS[module] || MODULE_GRAPHS.domain;
  const critFindings = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
  const paths = [];

  if (!critFindings.length) {
    return [{
      id:          'PATH-01',
      likelihood:   15,
      severity:    'LOW',
      steps: [
        { step: 1, action: `Attacker performs passive reconnaissance on ${target}`, tactic: 'Reconnaissance' },
        { step: 2, action: 'No critical entry points found — attacker moves to easier target', tactic: 'N/A' },
      ],
      impact: 'Minimal — reconnaissance only',
      mitigations: ['Continue monitoring', 'Maintain current security posture'],
    }];
  }

  // Path 1: Most direct exploit chain
  const primaryEntry   = template.entry_nodes[0];
  const topFinding     = critFindings[0];
  const primaryImpact  = template.impact_nodes[0];

  paths.push({
    id:         'PATH-01',
    likelihood:  topFinding.severity === 'CRITICAL' ? 80 : 55,
    severity:   topFinding.severity,
    attack_vector: primaryEntry.label,
    steps: [
      { step: 1, action: `Attacker identifies ${primaryEntry.label} as entry point via ${target}`, tactic: 'Reconnaissance', technique: 'T1592' },
      { step: 2, action: `Exploit: ${topFinding.title} — ${topFinding.description?.slice(0,80) || 'vulnerability leveraged'}`, tactic: 'Initial Access', technique: 'T1190' },
      { step: 3, action: 'Establish persistent access and enumerate internal assets', tactic: 'Persistence', technique: 'T1098' },
      { step: 4, action: `Achieve objective: ${primaryImpact.label}`, tactic: 'Impact', technique: 'T1486' },
    ],
    impact:      primaryImpact.label,
    time_to_exploit: topFinding.severity === 'CRITICAL' ? '< 24 hours' : '1-3 days',
    mitigations: [topFinding.recommendation || 'Remediate immediately', 'Enable monitoring and alerting'],
  });

  // Path 2: Chained exploit (if multiple findings)
  if (critFindings.length >= 2) {
    const secondFinding = critFindings[1];
    paths.push({
      id:         'PATH-02',
      likelihood:  60,
      severity:   'HIGH',
      attack_vector: 'Multi-step chain',
      steps: [
        { step: 1, action: `Initial access via ${topFinding.title}`, tactic: 'Initial Access', technique: 'T1190' },
        { step: 2, action: `Pivot using ${secondFinding.title} to gain additional access`, tactic: 'Lateral Movement', technique: 'T1021' },
        { step: 3, action: 'Escalate privileges using combined vulnerability chain', tactic: 'Privilege Escalation', technique: 'T1078' },
        { step: 4, action: `Final impact: ${template.impact_nodes[1]?.label || 'data exfiltration'}`, tactic: 'Exfiltration', technique: 'T1041' },
      ],
      impact:      template.impact_nodes[1]?.label || 'Data breach',
      time_to_exploit: '2-7 days',
      mitigations: [topFinding.recommendation || 'Patch immediately', secondFinding.recommendation || 'Harden configuration', 'Implement network segmentation'],
    });
  }

  return paths;
}

/**
 * Get threat actor profiles relevant to the module.
 */
export function getThreatActorProfiles(module) {
  const profiles = {
    domain: [
      { name: 'APT28 (Fancy Bear)', origin: 'Russia', motivation: 'Espionage', tactic: 'DNS hijacking, email spoofing', risk_to_target: 'HIGH' },
      { name: 'Lazarus Group',      origin: 'DPRK',   motivation: 'Financial', tactic: 'Watering hole, supply chain', risk_to_target: 'HIGH' },
      { name: 'FIN7',               origin: 'Unknown', motivation: 'Financial', tactic: 'Phishing, DNS abuse',         risk_to_target: 'MEDIUM' },
    ],
    ai: [
      { name: 'AI Red Teams (State)',  origin: 'Various', motivation: 'Capability testing', tactic: 'Automated prompt injection', risk_to_target: 'HIGH' },
      { name: 'Automated Exploit Kits',origin: 'Unknown', motivation: 'Data theft',          tactic: 'LLM jailbreaking toolkits',  risk_to_target: 'HIGH' },
    ],
    redteam: [
      { name: 'APT29 (Cozy Bear)',   origin: 'Russia',  motivation: 'Espionage',   tactic: 'Password spray, persistence',   risk_to_target: 'CRITICAL' },
      { name: 'REvil / Sodinokibi',  origin: 'Unknown', motivation: 'Ransomware',  tactic: 'Double extortion',              risk_to_target: 'CRITICAL' },
      { name: 'Cl0p',                origin: 'Unknown', motivation: 'Ransomware',  tactic: 'MOVEit/GoAnywhere exploitation', risk_to_target: 'HIGH' },
    ],
    identity: [
      { name: 'Lapsus$ Group',       origin: 'UK/BR',   motivation: 'Data theft', tactic: 'MFA fatigue, social engineering', risk_to_target: 'CRITICAL' },
      { name: 'Scattered Spider',    origin: 'Unknown', motivation: 'Financial',  tactic: 'SIM swapping, Okta attacks',      risk_to_target: 'HIGH' },
    ],
    compliance: [
      { name: 'Regulatory Bodies',   origin: 'India/EU', motivation: 'Compliance', tactic: 'Audit, inspection',     risk_to_target: 'MEDIUM' },
      { name: 'Opportunistic Actors',origin: 'Unknown',  motivation: 'Financial',  tactic: 'Target weak security orgs', risk_to_target: 'HIGH' },
    ],
  };

  return profiles[module] || profiles.domain;
}

// ─── Helper functions ─────────────────────────────────────────────────────────

const SEVERITY_RANK   = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
const SEVERITY_COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#3b82f6', INFO: '#6b7280' };

function addNode(nodes, nodeIds, node) {
  if (!nodeIds.has(node.id)) {
    const typeConfig = NODE_TYPES[node.type] || NODE_TYPES.finding;
    nodes.push({
      id:      node.id,
      label:   node.label,
      type:    node.type,
      color:   node.color || typeConfig.color,
      icon:    typeConfig.icon,
      risk:    node.risk || 0,
      radius:  node.radius || 10,
      group:   typeConfig.group,
      severity: node.severity,
    });
    nodeIds.add(node.id);
  }
}

function addLink(links, source, target, opts = {}) {
  links.push({
    source,
    target,
    type:     opts.type     || 'exploit',
    strength: opts.strength || 0.5,
    label:    opts.label    || '',
    animated: opts.animated || false,
    dashed:   opts.dashed   || false,
  });
}

function getDefenseNodes(module, findings) {
  const defenses = {
    domain:     [
      { id: 'def_tls',    label: 'TLS 1.3',      type: 'defense', risk: 0 },
      { id: 'def_dnssec', label: 'DNSSEC',        type: 'defense', risk: 0 },
      { id: 'def_waf',    label: 'WAF',           type: 'defense', risk: 0 },
    ],
    ai:         [
      { id: 'def_filter', label: 'Input Filter',  type: 'defense', risk: 0 },
      { id: 'def_rlhf',   label: 'Safety Layer',  type: 'defense', risk: 0 },
    ],
    redteam:    [
      { id: 'def_mfa',    label: 'MFA',           type: 'defense', risk: 0 },
      { id: 'def_edr',    label: 'EDR',           type: 'defense', risk: 0 },
    ],
    identity:   [
      { id: 'def_ca',     label: 'Cond. Access',  type: 'defense', risk: 0 },
      { id: 'def_pim',    label: 'PIM/PAM',       type: 'defense', risk: 0 },
    ],
    compliance: [
      { id: 'def_policy', label: 'Policy Docs',   type: 'defense', risk: 0 },
      { id: 'def_audit',  label: 'Audit Evidence',type: 'defense', risk: 0 },
    ],
  };

  // Only include defense nodes where findings indicate weakness
  return (defenses[module] || []).filter((_, i) => {
    const critCount = findings.filter(f => f.severity === 'CRITICAL').length;
    return i < Math.max(1, 3 - critCount); // Fewer defenses when more criticals
  });
}

function countCriticalPaths(links) {
  return links.filter(l => l.type === 'exploit' || l.type === 'impact').length;
}
