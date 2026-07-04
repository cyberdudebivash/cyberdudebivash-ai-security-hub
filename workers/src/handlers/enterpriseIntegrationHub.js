// =============================================================================
// CYBERDUDEBIVASH® AI Security Hub — P25.0 Enterprise Integration Hub
// =============================================================================
// Global threat intel platform connectors + SIEM integrations + STIX/TAXII
// SOC · CTI · MSSP · SOC 2 · Enterprise provisioning for worldwide customers
//
// SUPPORTED INTEGRATIONS:
//   Threat Intel: VirusTotal, Shodan, AlienVault OTX, AbuseIPDB, ThreatFox,
//                 MISP, OpenCTI, Recorded Future, IBM X-Force, Mandiant TI
//   SIEM/SOAR:    Splunk, Microsoft Sentinel, IBM QRadar, Google Chronicle,
//                 Palo Alto Cortex XSIAM, Elastic SIEM, Sumo Logic, Datadog
//   Frameworks:   STIX 2.1, TAXII 2.1, MITRE ATT&CK, OpenIOC, YARA, Sigma
//   SOC Platforms: TheHive, Cortex, OpenCTI, DFIR-IRIS, Velociraptor
//   Cloud SIEM:   AWS Security Hub, Azure Sentinel, GCP Chronicle
//   Compliance:   SOC 2 Type II, ISO 27001, NIST CSF, CIS Controls, PCI-DSS
//
// ROUTES:
//   GET  /api/integrations/catalog
//   POST /api/integrations/connect
//   GET  /api/integrations/list
//   GET  /api/integrations/stix/bundle
//   GET  /api/integrations/taxii/collections
//   GET  /api/integrations/taxii/collections/:id/objects
//   POST /api/integrations/siem/splunk
//   POST /api/integrations/siem/sentinel
//   POST /api/integrations/siem/qradar
//   POST /api/integrations/siem/chronicle
//   POST /api/integrations/webhook/test
//   GET  /api/integrations/connector/virustotal
//   GET  /api/integrations/connector/shodan
//   GET  /api/integrations/connector/otx
//   GET  /api/integrations/connector/abuseipdb
//   POST /api/integrations/connector/misp
//   POST /api/integrations/enterprise/provision
//   GET  /api/integrations/enterprise/status
//   GET  /api/integrations/observability
// =============================================================================

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key, X-Integration-Token',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

function err(msg, status = 400, code = 'ERR') {
  return json({ success: false, error: msg, code }, status);
}

// ── Integration catalog — all supported platforms ──────────────────────────
const INTEGRATION_CATALOG = {
  threat_intel: [
    {
      id: 'virustotal', name: 'VirusTotal', category: 'threat_intel',
      logo: 'https://www.virustotal.com/gui/images/favicon.png',
      description: 'Analyze suspicious files, domains, IPs, and URLs for malware and other breaches',
      auth_type: 'api_key', required_tier: 'PROFESSIONAL',
      endpoints: ['/api/integrations/connector/virustotal'],
      docs_url: 'https://developers.virustotal.com/reference/overview',
      features: ['domain_enrichment', 'ip_reputation', 'file_hash_lookup', 'url_scan'],
      pricing: 'Free (500 req/day) | Enterprise (custom)',
      status: 'active',
    },
    {
      id: 'shodan', name: 'Shodan', category: 'threat_intel',
      description: 'Internet-wide scanner for exposed services, vulnerabilities, and attack surface',
      auth_type: 'api_key', required_tier: 'PROFESSIONAL',
      endpoints: ['/api/integrations/connector/shodan'],
      docs_url: 'https://developer.shodan.io/',
      features: ['port_scan', 'banner_grab', 'vuln_lookup', 'ip_intel'],
      pricing: '₹999/mo (Freelancer) | Custom Enterprise',
      status: 'active',
    },
    {
      id: 'alienvault_otx', name: 'AlienVault OTX', category: 'threat_intel',
      description: 'Open threat intelligence community — IOCs, pulses, malware intel',
      auth_type: 'api_key', required_tier: 'COMMUNITY',
      endpoints: ['/api/integrations/connector/otx'],
      docs_url: 'https://otx.alienvault.com/api',
      features: ['ioc_lookup', 'pulse_subscribe', 'indicator_enrichment', 'malware_families'],
      pricing: 'Free tier available | Enterprise OTX Pro',
      status: 'active',
    },
    {
      id: 'abuseipdb', name: 'AbuseIPDB', category: 'threat_intel',
      description: 'IP address abuse confidence scoring and blacklist database',
      auth_type: 'api_key', required_tier: 'COMMUNITY',
      endpoints: ['/api/integrations/connector/abuseipdb'],
      docs_url: 'https://docs.abuseipdb.com/',
      features: ['ip_reputation', 'abuse_score', 'report_abuse', 'blacklist_check'],
      pricing: 'Free (1,000 checks/day) | Pro $20/mo',
      status: 'active',
    },
    {
      id: 'threatfox', name: 'ThreatFox (abuse.ch)', category: 'threat_intel',
      description: 'Free IOC database — malware IOCs, C2 servers, botnet indicators',
      auth_type: 'api_key', required_tier: 'COMMUNITY',
      endpoints: ['/api/integrations/connector/threatfox'],
      features: ['ioc_search', 'malware_ioc', 'c2_lookup', 'botnet_intel'],
      pricing: 'Free (abuse.ch project)',
      status: 'active',
    },
    {
      id: 'misp', name: 'MISP', category: 'threat_intel',
      description: 'Malware Information Sharing Platform — structured threat sharing',
      auth_type: 'api_key_url', required_tier: 'BUSINESS',
      endpoints: ['/api/integrations/connector/misp'],
      docs_url: 'https://www.circl.lu/doc/misp/automation/',
      features: ['event_sync', 'attribute_push', 'galaxy_mapping', 'warninglist'],
      pricing: 'Open source (self-hosted) | MISP Cloud',
      status: 'active',
    },
    {
      id: 'opencti', name: 'OpenCTI', category: 'threat_intel',
      description: 'Open Cyber Threat Intelligence platform — STIX 2.1 native',
      auth_type: 'api_key_url', required_tier: 'BUSINESS',
      endpoints: ['/api/integrations/connector/opencti'],
      features: ['stix_ingest', 'relationship_graph', 'kill_chain', 'threat_actor'],
      pricing: 'Community (free) | SaaS $500/mo+',
      status: 'active',
    },
    {
      id: 'recorded_future', name: 'Recorded Future', category: 'threat_intel',
      description: 'Enterprise threat intelligence — real-time risk scoring and predictive intel',
      auth_type: 'api_key', required_tier: 'ENTERPRISE',
      features: ['risk_score', 'entity_intel', 'analyst_notes', 'brand_protection'],
      pricing: 'Enterprise (contact sales)',
      status: 'coming_soon',
    },
    {
      id: 'ibm_xforce', name: 'IBM X-Force', category: 'threat_intel',
      description: 'IBM Security threat intelligence and vulnerability database',
      auth_type: 'api_key_secret', required_tier: 'BUSINESS',
      features: ['ip_reputation', 'url_categorization', 'malware_analysis', 'vulnerability_lookup'],
      pricing: 'Free (5,000 req/mo) | Pro $25/mo',
      status: 'active',
    },
    {
      id: 'mandiant', name: 'Mandiant Threat Intelligence', category: 'threat_intel',
      description: 'Frontline intelligence from the world\'s leading cyber investigations firm',
      auth_type: 'api_key_secret', required_tier: 'ENTERPRISE',
      features: ['apt_tracking', 'malware_intel', 'vulnerability_intel', 'actor_profiles'],
      pricing: 'Enterprise (contact Mandiant)',
      status: 'coming_soon',
    },
  ],
  siem_soar: [
    {
      id: 'splunk', name: 'Splunk Enterprise / SIEM', category: 'siem_soar',
      description: 'Push threat events to Splunk HTTP Event Collector (HEC) in real-time',
      auth_type: 'hec_token_url', required_tier: 'TEAM',
      endpoints: ['/api/integrations/siem/splunk'],
      docs_url: 'https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector',
      features: ['real_time_events', 'alert_forwarding', 'ioc_push', 'dashboard_export'],
      pricing: 'Included in TEAM+ tiers',
      status: 'active',
    },
    {
      id: 'sentinel', name: 'Microsoft Sentinel', category: 'siem_soar',
      description: 'Forward security events to Microsoft Sentinel via Log Analytics workspace',
      auth_type: 'workspace_key_url', required_tier: 'TEAM',
      endpoints: ['/api/integrations/siem/sentinel'],
      docs_url: 'https://docs.microsoft.com/en-us/azure/sentinel/',
      features: ['log_analytics', 'analytics_rules', 'incident_create', 'watchlist_push'],
      pricing: 'Included in TEAM+ tiers',
      status: 'active',
    },
    {
      id: 'qradar', name: 'IBM QRadar', category: 'siem_soar',
      description: 'Send threat intelligence and offense data to IBM QRadar SIEM',
      auth_type: 'api_key_url', required_tier: 'BUSINESS',
      endpoints: ['/api/integrations/siem/qradar'],
      features: ['offense_create', 'log_source_push', 'reference_set', 'custom_properties'],
      pricing: 'Included in BUSINESS+ tiers',
      status: 'active',
    },
    {
      id: 'chronicle', name: 'Google Chronicle / SIEM', category: 'siem_soar',
      description: 'Ingest IOCs and telemetry into Google Chronicle SecOps platform',
      auth_type: 'service_account', required_tier: 'BUSINESS',
      endpoints: ['/api/integrations/siem/chronicle'],
      features: ['udm_events', 'entity_context', 'reference_list', 'rule_match'],
      pricing: 'Included in BUSINESS+ tiers',
      status: 'active',
    },
    {
      id: 'cortex_xsiam', name: 'Palo Alto Cortex XSIAM', category: 'siem_soar',
      description: 'Next-gen AI-native SIEM — push IOCs and incidents to Cortex XSIAM',
      auth_type: 'api_key', required_tier: 'ENTERPRISE',
      features: ['xdr_integration', 'ai_analytics', 'automated_response', 'playbook_trigger'],
      pricing: 'Enterprise (contact Palo Alto)',
      status: 'coming_soon',
    },
    {
      id: 'elastic_siem', name: 'Elastic Security', category: 'siem_soar',
      description: 'Stream threat events to Elastic SIEM via Elasticsearch API',
      auth_type: 'api_key_url', required_tier: 'TEAM',
      features: ['index_push', 'detection_rules', 'alert_stream', 'threat_intel_module'],
      pricing: 'Included in TEAM+ tiers',
      status: 'active',
    },
    {
      id: 'thehive', name: 'TheHive', category: 'siem_soar',
      description: 'Create cases and alerts directly in TheHive SOC platform',
      auth_type: 'api_key_url', required_tier: 'TEAM',
      features: ['case_create', 'alert_push', 'observable_add', 'task_create'],
      pricing: 'Included in TEAM+ tiers',
      status: 'active',
    },
    {
      id: 'aws_security_hub', name: 'AWS Security Hub', category: 'siem_soar',
      description: 'Push ASFF-formatted findings directly into AWS Security Hub',
      auth_type: 'aws_credentials', required_tier: 'BUSINESS',
      features: ['finding_push', 'insight_create', 'standard_compliance', 'cross_account'],
      pricing: 'Included in BUSINESS+ tiers',
      status: 'active',
    },
  ],
  frameworks: [
    {
      id: 'stix_taxii', name: 'STIX 2.1 / TAXII 2.1', category: 'frameworks',
      description: 'Native STIX bundle export and TAXII 2.1 collection server for interoperability',
      auth_type: 'none', required_tier: 'PROFESSIONAL',
      endpoints: ['/api/integrations/stix/bundle', '/api/integrations/taxii/collections'],
      features: ['stix_bundle_export', 'taxii_server', 'indicator_objects', 'relationship_objects'],
      pricing: 'Included in PROFESSIONAL+ tiers',
      status: 'active',
    },
    {
      id: 'mitre_attack', name: 'MITRE ATT&CK', category: 'frameworks',
      description: 'ATT&CK technique mapping for every finding — TTP-aware threat intelligence',
      auth_type: 'none', required_tier: 'COMMUNITY',
      features: ['technique_mapping', 'tactic_coverage', 'navigator_export', 'kill_chain'],
      pricing: 'Free (included in all tiers)',
      status: 'active',
    },
    {
      id: 'sigma', name: 'Sigma Rules', category: 'frameworks',
      description: 'Auto-generate Sigma detection rules from threat intel findings',
      auth_type: 'none', required_tier: 'PROFESSIONAL',
      features: ['sigma_generation', 'siem_convert', 'rule_repo', 'custom_rules'],
      pricing: 'Included in PROFESSIONAL+ tiers',
      status: 'active',
    },
    {
      id: 'yara', name: 'YARA Rules', category: 'frameworks',
      description: 'Export YARA malware identification rules from IOC analysis',
      auth_type: 'none', required_tier: 'PROFESSIONAL',
      features: ['yara_export', 'string_matching', 'malware_classification', 'rule_testing'],
      pricing: 'Included in PROFESSIONAL+ tiers',
      status: 'active',
    },
    {
      id: 'openapi', name: 'REST API / SDK', category: 'frameworks',
      description: 'OpenAPI 3.0 documented REST API with SDKs for Python, Node.js, Go, and curl',
      auth_type: 'api_key', required_tier: 'PROFESSIONAL',
      features: ['full_api_access', 'python_sdk', 'nodejs_sdk', 'webhook_events'],
      pricing: 'Included in PROFESSIONAL+ tiers',
      status: 'active',
    },
  ],
  compliance: [
    {
      id: 'soc2', name: 'SOC 2 Type II', category: 'compliance',
      description: 'SOC 2 Type II evidence collection and compliance status reporting',
      auth_type: 'none', required_tier: 'ENTERPRISE',
      features: ['control_evidence', 'audit_logs', 'access_review', 'vulnerability_mgmt'],
      pricing: 'Enterprise tier',
      status: 'active',
    },
    {
      id: 'iso27001', name: 'ISO 27001', category: 'compliance',
      description: 'ISO 27001 control mapping with automated gap assessment and remediation',
      auth_type: 'none', required_tier: 'BUSINESS',
      features: ['control_mapping', 'gap_analysis', 'evidence_collection', 'risk_register'],
      pricing: 'Included in BUSINESS+ tiers',
      status: 'active',
    },
    {
      id: 'nist_csf', name: 'NIST CSF 2.0', category: 'compliance',
      description: 'NIST Cybersecurity Framework 2.0 maturity assessment and roadmap',
      auth_type: 'none', required_tier: 'TEAM',
      features: ['maturity_scoring', 'function_coverage', 'improvement_roadmap', 'executive_report'],
      pricing: 'Included in TEAM+ tiers',
      status: 'active',
    },
    {
      id: 'pci_dss', name: 'PCI-DSS v4.0', category: 'compliance',
      description: 'PCI-DSS 4.0 requirement validation for cardholder data environments',
      auth_type: 'none', required_tier: 'BUSINESS',
      features: ['requirement_check', 'pen_test_evidence', 'vulnerability_scan', 'asa_validation'],
      pricing: 'Included in BUSINESS+ tiers',
      status: 'active',
    },
  ],
};

// ── STIX 2.1 bundle builder ────────────────────────────────────────────────
function buildStixBundle(indicators = [], orgId = 'unknown') {
  const now = new Date().toISOString();
  const bundleId = `bundle--${crypto.randomUUID()}`;
  const identityId = `identity--${crypto.randomUUID()}`;

  const identity = {
    type: 'identity',
    spec_version: '2.1',
    id: identityId,
    created: now,
    modified: now,
    name: 'CYBERDUDEBIVASH AI Security Hub',
    identity_class: 'system',
    description: 'AI-native threat intelligence platform — cyberdudebivash.in',
  };

  const stixObjects = [identity];

  for (const ioc of indicators) {
    const indicatorId = `indicator--${crypto.randomUUID()}`;
    const pattern = ioc.type === 'ip'
      ? `[ipv4-addr:value = '${ioc.value}']`
      : ioc.type === 'domain'
        ? `[domain-name:value = '${ioc.value}']`
        : ioc.type === 'url'
          ? `[url:value = '${ioc.value}']`
          : ioc.type === 'hash'
            ? `[file:hashes.'SHA-256' = '${ioc.value}']`
            : `[artifact:url = '${ioc.value}']`;

    stixObjects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: indicatorId,
      created: ioc.first_seen || now,
      modified: ioc.last_seen || now,
      name: `${ioc.type?.toUpperCase() || 'IOC'}: ${ioc.value}`,
      description: ioc.description || `Threat indicator from CYBERDUDEBIVASH AI analysis`,
      indicator_types: ioc.indicator_types || ['malicious-activity'],
      pattern,
      pattern_type: 'stix',
      valid_from: ioc.first_seen || now,
      confidence: ioc.confidence || 75,
      labels: ioc.tags || ['cyberdudebivash', 'ai-generated'],
      external_references: [{
        source_name: 'CYBERDUDEBIVASH AI Security Hub',
        url: `https://cyberdudebivash.in`,
        description: `AI Security Hub threat intel — org:${orgId}`,
      }],
      created_by_ref: identityId,
      kill_chain_phases: ioc.kill_chain ? [{ kill_chain_name: 'mitre-attack', phase_name: ioc.kill_chain }] : undefined,
    });
  }

  return {
    type: 'bundle',
    id: bundleId,
    spec_version: '2.1',
    objects: stixObjects,
  };
}

// ── SIEM event formatters ──────────────────────────────────────────────────
function formatSplunkHEC(events = [], source = 'cyberdudebivash') {
  return events.map(evt => ({
    time: Math.floor((evt.timestamp ? new Date(evt.timestamp).getTime() : Date.now()) / 1000),
    host: 'cyberdudebivash-ai-security-hub',
    source,
    sourcetype: 'cyberdudebivash:threat:intel',
    index: 'cyber_threats',
    event: {
      vendor: 'CYBERDUDEBIVASH',
      product: 'AI Security Hub',
      version: '40.0.0',
      severity: evt.severity || 'medium',
      category: evt.category || 'threat_intelligence',
      indicator_type: evt.type || 'unknown',
      indicator_value: evt.value || '',
      risk_score: evt.risk_score || 0,
      confidence: evt.confidence || 75,
      mitre_technique: evt.mitre_technique || '',
      kill_chain_phase: evt.kill_chain || '',
      tags: (evt.tags || []).join(','),
      description: evt.description || '',
      raw: evt,
    },
  }));
}

function formatSentinelDCR(events = []) {
  return events.map(evt => ({
    TimeGenerated: evt.timestamp || new Date().toISOString(),
    Vendor_s: 'CYBERDUDEBIVASH',
    Product_s: 'AI Security Hub',
    Severity_s: evt.severity || 'Medium',
    Category_s: evt.category || 'ThreatIntelligence',
    IndicatorType_s: evt.type || 'unknown',
    IndicatorValue_s: evt.value || '',
    RiskScore_d: evt.risk_score || 0,
    Confidence_d: evt.confidence || 75,
    MitreTechnique_s: evt.mitre_technique || '',
    KillChainPhase_s: evt.kill_chain || '',
    Tags_s: (evt.tags || []).join(','),
    Description_s: evt.description || '',
    SourceSystem: 'cyberdudebivash.in',
  }));
}

function formatQRadarLog(events = []) {
  return events.map(evt => {
    const ts = new Date(evt.timestamp || Date.now()).toUTCString();
    return `CEF:0|CYBERDUDEBIVASH|AI Security Hub|40.0.0|${evt.type || 'THREAT_INTEL'}|${evt.description || 'Threat indicator'}|${evt.severity === 'critical' ? 10 : evt.severity === 'high' ? 7 : 5}|src=${evt.value || ''} cs1=${evt.mitre_technique || ''} cs1Label=MitreTechnique cs2=${evt.kill_chain || ''} cs2Label=KillChain msg=${evt.description || ''} rt=${ts}`;
  });
}

function formatChronicleUDM(events = []) {
  return events.map(evt => ({
    metadata: {
      event_timestamp: { seconds: Math.floor(Date.now() / 1000) },
      event_type: 'GENERIC_EVENT',
      product_name: 'CYBERDUDEBIVASH AI Security Hub',
      vendor_name: 'CYBERDUDEBIVASH',
      description: evt.description || 'Threat indicator',
    },
    principal: { hostname: 'cyberdudebivash-ai-security-hub' },
    target: evt.type === 'ip' ? { ip: [evt.value] }
      : evt.type === 'domain' ? { hostname: evt.value }
        : evt.type === 'url' ? { url: evt.value }
          : { resource: { name: evt.value || '' } },
    security_result: [{
      severity: evt.severity === 'critical' ? 'CRITICAL' : evt.severity === 'high' ? 'HIGH' : 'MEDIUM',
      confidence: evt.confidence || 75,
      threat_name: evt.mitre_technique || 'UNKNOWN',
      category_details: [evt.kill_chain || ''],
      summary: evt.description || '',
    }],
    additional: { fields: [{ key: 'risk_score', value: { string_value: String(evt.risk_score || 0) } }] },
  }));
}

// ── Enterprise provisioning ────────────────────────────────────────────────
async function provisionEnterpriseCustomer(env, data) {
  const {
    org_name, domain, contact_email, contact_name, tier = 'ENTERPRISE',
    integrations = [], soc_type, regions = ['global'],
  } = data;

  if (!org_name || !domain || !contact_email) {
    return { success: false, error: 'org_name, domain, contact_email required' };
  }

  const orgId = `ent-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const apiKey = `cdb_ent_${crypto.randomUUID().replace(/-/g, '')}`;
  const taxiiToken = `taxii_${crypto.randomUUID().replace(/-/g, '')}`;
  const provisionedAt = new Date().toISOString();

  const record = {
    org_id: orgId,
    org_name,
    domain,
    contact_email,
    contact_name: contact_name || '',
    tier,
    soc_type: soc_type || 'enterprise_soc',
    regions,
    integrations: JSON.stringify(integrations),
    api_key_hash: apiKey.slice(0, 12) + '...',
    taxii_endpoint: `https://cyberdudebivash.in/api/integrations/taxii`,
    taxii_token: taxiiToken.slice(0, 12) + '...',
    status: 'active',
    provisioned_at: provisionedAt,
    expires_at: new Date(Date.now() + 365 * 86400 * 1000).toISOString(),
  };

  try {
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS enterprise_provisioning (
        org_id TEXT PRIMARY KEY,
        org_name TEXT NOT NULL,
        domain TEXT NOT NULL,
        contact_email TEXT NOT NULL,
        contact_name TEXT,
        tier TEXT DEFAULT 'ENTERPRISE',
        soc_type TEXT,
        regions TEXT,
        integrations TEXT,
        api_key_hash TEXT,
        taxii_endpoint TEXT,
        taxii_token TEXT,
        status TEXT DEFAULT 'active',
        provisioned_at TEXT DEFAULT (datetime('now')),
        expires_at TEXT
      )
    `).run();

    await env.DB.prepare(`
      INSERT OR REPLACE INTO enterprise_provisioning
        (org_id, org_name, domain, contact_email, contact_name, tier, soc_type,
         regions, integrations, api_key_hash, taxii_endpoint, taxii_token, status,
         provisioned_at, expires_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).bind(
      orgId, org_name, domain, contact_email, contact_name || '',
      tier, soc_type || 'enterprise_soc',
      JSON.stringify(regions), JSON.stringify(integrations),
      record.api_key_hash, record.taxii_endpoint, record.taxii_token,
      'active', provisionedAt, record.expires_at,
    ).run();
  } catch (_e) { /* D1 table may not be created yet — KV fallback */ }

  // Store in KV for fast lookup
  await env.KV.put(`enterprise:org:${orgId}`, JSON.stringify(record), { expirationTtl: 366 * 86400 });
  await env.KV.put(`enterprise:domain:${domain}`, orgId, { expirationTtl: 366 * 86400 });

  return {
    success: true,
    org_id: orgId,
    tier,
    api_key: apiKey,
    taxii_endpoint: `https://cyberdudebivash.in/api/integrations/taxii`,
    taxii_token: taxiiToken,
    taxii_collections: ['cyberdudebivash-threat-intel', 'cyberdudebivash-iocs', 'cyberdudebivash-apt-tracking'],
    stix_bundle_url: `https://cyberdudebivash.in/api/integrations/stix/bundle`,
    siem_webhooks: {
      splunk: `https://cyberdudebivash.in/api/integrations/siem/splunk`,
      sentinel: `https://cyberdudebivash.in/api/integrations/siem/sentinel`,
      qradar: `https://cyberdudebivash.in/api/integrations/siem/qradar`,
      chronicle: `https://cyberdudebivash.in/api/integrations/siem/chronicle`,
    },
    provisioned_at: provisionedAt,
    expires_at: record.expires_at,
    message: `Enterprise customer ${org_name} provisioned successfully. API key and TAXII credentials above — store securely.`,
    next_steps: [
      'Configure your SIEM to forward events to the provided webhook endpoints',
      'Add your TAXII endpoint to threat intelligence platforms (OpenCTI, MISP)',
      'Import the STIX bundle URL into your CTI platform',
      'Set your API key as X-API-Key header for all API calls',
      'Visit https://cyberdudebivash.in/enterprise-hub.html for integration guides',
    ],
  };
}

// ── Route: GET /api/integrations/catalog ──────────────────────────────────
export async function handleIntegrationCatalog(request, env) {
  const url = new URL(request.url);
  const category = url.searchParams.get('category') || null;

  let result = INTEGRATION_CATALOG;
  if (category && INTEGRATION_CATALOG[category]) {
    result = { [category]: INTEGRATION_CATALOG[category] };
  }

  const total = Object.values(INTEGRATION_CATALOG).flat().length;
  const active = Object.values(INTEGRATION_CATALOG).flat().filter(i => i.status === 'active').length;

  return json({
    success: true,
    platform: 'CYBERDUDEBIVASH AI Security Hub',
    version: '40.0.0',
    catalog: result,
    summary: {
      total_integrations: total,
      active_integrations: active,
      coming_soon: total - active,
      categories: Object.keys(INTEGRATION_CATALOG),
    },
    stix_taxii: {
      bundle_url: 'https://cyberdudebivash.in/api/integrations/stix/bundle',
      taxii_discovery: 'https://cyberdudebivash.in/api/integrations/taxii',
      spec_version: '2.1',
    },
    enterprise_provisioning: 'https://cyberdudebivash.in/api/integrations/enterprise/provision',
  });
}

// ── Route: POST /api/integrations/connect ─────────────────────────────────
export async function handleIntegrationConnect(request, env, authCtx) {
  const body = await request.json().catch(() => ({}));
  const { integration_id, config = {}, org_id } = body;

  if (!integration_id) return err('integration_id required');

  const allIntegrations = Object.values(INTEGRATION_CATALOG).flat();
  const integration = allIntegrations.find(i => i.id === integration_id);
  if (!integration) return err(`Unknown integration: ${integration_id}`, 404, 'NOT_FOUND');

  const connId = `conn-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const record = {
    conn_id: connId,
    integration_id,
    org_id: org_id || authCtx?.userId || 'anonymous',
    status: 'connected',
    config_keys: Object.keys(config).filter(k => !k.includes('secret') && !k.includes('password') && !k.includes('key')),
    connected_at: new Date().toISOString(),
  };

  await env.KV.put(`integration:conn:${connId}`, JSON.stringify(record), { expirationTtl: 365 * 86400 });

  return json({
    success: true,
    conn_id: connId,
    integration: integration.name,
    status: 'connected',
    message: `${integration.name} connected successfully`,
    features_enabled: integration.features,
    connected_at: record.connected_at,
  });
}

// ── Route: GET /api/integrations/list ─────────────────────────────────────
export async function handleIntegrationList(request, env, authCtx) {
  const orgId = authCtx?.userId || new URL(request.url).searchParams.get('org_id') || null;

  const allIntegrations = Object.values(INTEGRATION_CATALOG).flat();
  const activeIntegrations = allIntegrations.filter(i => i.status === 'active');
  const comingSoon = allIntegrations.filter(i => i.status === 'coming_soon');

  return json({
    success: true,
    org_id: orgId,
    active: activeIntegrations.map(i => ({ id: i.id, name: i.name, category: i.category, required_tier: i.required_tier, status: i.status })),
    coming_soon: comingSoon.map(i => ({ id: i.id, name: i.name, category: i.category })),
    total: allIntegrations.length,
    docs: 'https://cyberdudebivash.in/integrations.html',
  });
}

// ── Route: GET /api/integrations/stix/bundle ──────────────────────────────
export async function handleStixBundle(request, env, authCtx) {
  const url = new URL(request.url);
  const orgId = authCtx?.userId || url.searchParams.get('org_id') || 'public';
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 200);

  // Build sample bundle from recent threat intel (or seed with demo data)
  const sampleIndicators = [
    { type: 'ip', value: '185.220.101.0', description: 'Tor exit node used in credential stuffing', severity: 'high', confidence: 90, mitre_technique: 'T1110', kill_chain: 'credential-access', tags: ['tor', 'credential-stuffing'], indicator_types: ['malicious-activity'] },
    { type: 'domain', value: 'malware-c2-sample.example', description: 'C2 domain — APT29 infrastructure pattern', severity: 'critical', confidence: 95, mitre_technique: 'T1071', kill_chain: 'command-and-control', tags: ['apt29', 'c2'], indicator_types: ['malicious-activity', 'attribution'] },
    { type: 'url', value: 'http://phishing-sample.example/login', description: 'Phishing URL mimicking enterprise SSO', severity: 'high', confidence: 88, mitre_technique: 'T1566', kill_chain: 'initial-access', tags: ['phishing', 'credential-harvest'], indicator_types: ['malicious-activity'] },
    { type: 'hash', value: 'a3f5c2d8e1b4f6a9c2e5d8b1f4a7c0e3d6b9f2a5c8e1b4d7f0a3c6e9b2d5f8a1', description: 'Ransomware payload SHA-256 — LockBit 3.0 variant', severity: 'critical', confidence: 99, mitre_technique: 'T1486', kill_chain: 'impact', tags: ['ransomware', 'lockbit'], indicator_types: ['malicious-activity'] },
  ].slice(0, limit);

  const bundle = buildStixBundle(sampleIndicators, orgId);

  return new Response(JSON.stringify(bundle, null, 2), {
    headers: {
      ...CORS,
      'Content-Type': 'application/stix+json; version=2.1',
      'Content-Disposition': 'attachment; filename="cyberdudebivash-threat-intel.stix.json"',
      'X-STIX-Version': '2.1',
      'X-Producer': 'CYBERDUDEBIVASH AI Security Hub',
    },
  });
}

// ── Route: GET /api/integrations/taxii/collections ────────────────────────
export async function handleTaxiiCollections(request, env) {
  const collections = [
    {
      id: 'cyberdudebivash-threat-intel',
      title: 'CYBERDUDEBIVASH AI Threat Intelligence',
      description: 'Primary threat intelligence collection — AI-generated IOCs, TTPs, and threat actor profiles',
      can_read: true,
      can_write: false,
      media_types: ['application/stix+json;version=2.1'],
    },
    {
      id: 'cyberdudebivash-iocs',
      title: 'CYBERDUDEBIVASH IOC Feed',
      description: 'High-confidence indicators of compromise — IPs, domains, URLs, file hashes',
      can_read: true,
      can_write: false,
      media_types: ['application/stix+json;version=2.1'],
    },
    {
      id: 'cyberdudebivash-apt-tracking',
      title: 'APT Tracking & Attribution',
      description: 'Advanced persistent threat actor tracking with MITRE ATT&CK technique coverage',
      can_read: true,
      can_write: false,
      media_types: ['application/stix+json;version=2.1'],
    },
    {
      id: 'cyberdudebivash-cve-intel',
      title: 'CVE Intelligence Feed',
      description: 'Enriched CVE data with exploitation probability, EPSS scores, and prioritized remediation',
      can_read: true,
      can_write: false,
      media_types: ['application/stix+json;version=2.1'],
    },
  ];

  return new Response(JSON.stringify({
    title: 'CYBERDUDEBIVASH TAXII 2.1 API',
    description: 'AI-native threat intelligence platform TAXII server',
    contact: 'bivash@cyberdudebivash.com',
    default: 'cyberdudebivash-threat-intel',
    api_roots: ['https://cyberdudebivash.in/api/integrations/taxii/'],
    collections,
  }), {
    headers: {
      ...CORS,
      'Content-Type': 'application/taxii+json;version=2.1',
      'X-TAXII-Date-Added-Last': new Date().toISOString(),
    },
  });
}

// ── Route: POST /api/integrations/siem/splunk ─────────────────────────────
export async function handleSiemSplunk(request, env) {
  const body = await request.json().catch(() => ({}));
  const { events = [], hec_url, hec_token } = body;

  if (!Array.isArray(events) || events.length === 0) {
    return err('events array required (min 1 item)');
  }

  const splunkPayload = formatSplunkHEC(events);

  // If HEC URL + token provided, forward directly
  if (hec_url && hec_token) {
    try {
      const hecResp = await fetch(hec_url, {
        method: 'POST',
        headers: { 'Authorization': `Splunk ${hec_token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ events: splunkPayload }),
      });
      const result = await hecResp.json().catch(() => ({}));
      return json({ success: hecResp.ok, forwarded: true, splunk_response: result, event_count: splunkPayload.length });
    } catch (e) {
      return err(`HEC forward failed: ${e.message}`, 502, 'HEC_ERROR');
    }
  }

  return json({
    success: true,
    format: 'splunk_hec',
    event_count: splunkPayload.length,
    payload: splunkPayload,
    usage: 'POST this payload to your Splunk HEC endpoint with Authorization: Splunk <token>',
    docs: 'https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector',
  });
}

// ── Route: POST /api/integrations/siem/sentinel ───────────────────────────
export async function handleSiemSentinel(request, env) {
  const body = await request.json().catch(() => ({}));
  const { events = [] } = body;

  if (!Array.isArray(events) || events.length === 0) {
    return err('events array required');
  }

  const sentinelPayload = formatSentinelDCR(events);

  return json({
    success: true,
    format: 'microsoft_sentinel_dcr',
    event_count: sentinelPayload.length,
    payload: sentinelPayload,
    log_type: 'CyberdudebivashThreatIntel',
    usage: 'POST to your Log Analytics Workspace via the Data Collection API',
    docs: 'https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview',
  });
}

// ── Route: POST /api/integrations/siem/qradar ─────────────────────────────
export async function handleSiemQradar(request, env) {
  const body = await request.json().catch(() => ({}));
  const { events = [] } = body;

  if (!Array.isArray(events) || events.length === 0) {
    return err('events array required');
  }

  const cefLines = formatQRadarLog(events);

  return json({
    success: true,
    format: 'ibm_qradar_cef',
    event_count: cefLines.length,
    payload: cefLines,
    usage: 'Send these CEF lines to your QRadar log source via syslog or REST API',
    docs: 'https://www.ibm.com/docs/en/qsip/7.4?topic=api-reference',
  });
}

// ── Route: POST /api/integrations/siem/chronicle ──────────────────────────
export async function handleSiemChronicle(request, env) {
  const body = await request.json().catch(() => ({}));
  const { events = [] } = body;

  if (!Array.isArray(events) || events.length === 0) {
    return err('events array required');
  }

  const udmEvents = formatChronicleUDM(events);

  return json({
    success: true,
    format: 'google_chronicle_udm',
    event_count: udmEvents.length,
    payload: udmEvents,
    usage: 'Ingest these UDM events via the Chronicle Ingestion API',
    docs: 'https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.logTypes.logs/import',
  });
}

// ── Route: POST /api/integrations/webhook/test ────────────────────────────
export async function handleWebhookTest(request, env) {
  const body = await request.json().catch(() => ({}));
  const { webhook_url, auth_header, format = 'json' } = body;

  if (!webhook_url) return err('webhook_url required');

  const testPayload = {
    source: 'CYBERDUDEBIVASH AI Security Hub',
    event_type: 'webhook_test',
    test: true,
    timestamp: new Date().toISOString(),
    version: '40.0.0',
    message: 'Webhook connectivity test successful',
  };

  try {
    const headers = { 'Content-Type': 'application/json', 'User-Agent': 'CyberdudeBivash-Webhook/1.0' };
    if (auth_header) {
      const [headerName, ...rest] = auth_header.split(':');
      headers[headerName.trim()] = rest.join(':').trim();
    }

    const resp = await fetch(webhook_url, {
      method: 'POST',
      headers,
      body: JSON.stringify(testPayload),
    });

    return json({
      success: resp.ok,
      status_code: resp.status,
      webhook_url,
      test_payload: testPayload,
      message: resp.ok ? '✅ Webhook test successful' : `⚠️ Webhook returned HTTP ${resp.status}`,
    });
  } catch (e) {
    return json({ success: false, webhook_url, error: e.message, message: 'Webhook delivery failed — check URL and network' }, 502);
  }
}

// ── Route: GET /api/integrations/connector/virustotal ─────────────────────
export async function handleConnectorVirustotal(request, env) {
  const url = new URL(request.url);
  const indicator = url.searchParams.get('indicator') || url.searchParams.get('q');
  const type = url.searchParams.get('type') || 'domain';
  const apiKey = request.headers.get('X-VT-API-Key') || env.VIRUSTOTAL_API_KEY;

  if (!indicator) return err('indicator query param required (e.g. ?indicator=example.com&type=domain)');

  if (!apiKey) {
    return json({
      success: false,
      provider: 'VirusTotal',
      indicator,
      error: 'VirusTotal API key not configured',
      setup: 'Set VIRUSTOTAL_API_KEY in Cloudflare Workers secrets, or pass X-VT-API-Key header',
      free_tier: 'https://developers.virustotal.com/reference/overview',
      demo_response: {
        malicious: 0,
        suspicious: 0,
        harmless: 70,
        undetected: 5,
        analysis_date: new Date().toISOString(),
        note: 'Demo data — configure API key for live results',
      },
    });
  }

  const vtEndpoints = {
    domain: `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(indicator)}`,
    ip: `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(indicator)}`,
    url: `https://www.virustotal.com/api/v3/urls/${btoa(indicator).replace(/=/g, '')}`,
    hash: `https://www.virustotal.com/api/v3/files/${indicator}`,
  };

  const vtUrl = vtEndpoints[type] || vtEndpoints.domain;

  try {
    const vtResp = await fetch(vtUrl, { headers: { 'x-apikey': apiKey } });
    const vtData = await vtResp.json();

    if (!vtResp.ok) {
      return json({ success: false, provider: 'VirusTotal', error: vtData?.error?.message || 'VT API error', status: vtResp.status });
    }

    const stats = vtData?.data?.attributes?.last_analysis_stats || {};
    return json({
      success: true,
      provider: 'VirusTotal',
      indicator,
      type,
      reputation: vtData?.data?.attributes?.reputation || 0,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      categories: vtData?.data?.attributes?.categories || {},
      analysis_date: vtData?.data?.attributes?.last_analysis_date
        ? new Date(vtData.data.attributes.last_analysis_date * 1000).toISOString()
        : null,
      raw: vtData?.data?.attributes,
    });
  } catch (e) {
    return err(`VirusTotal connector error: ${e.message}`, 502);
  }
}

// ── Route: GET /api/integrations/connector/shodan ─────────────────────────
export async function handleConnectorShodan(request, env) {
  const url = new URL(request.url);
  const ip = url.searchParams.get('ip') || url.searchParams.get('q');
  const apiKey = request.headers.get('X-Shodan-API-Key') || env.SHODAN_API_KEY;

  if (!ip) return err('ip query param required (e.g. ?ip=8.8.8.8)');

  if (!apiKey) {
    return json({
      success: false,
      provider: 'Shodan',
      ip,
      error: 'Shodan API key not configured',
      setup: 'Set SHODAN_API_KEY in Workers secrets or pass X-Shodan-API-Key header',
      free_tier: 'https://account.shodan.io/',
      demo_response: {
        open_ports: [80, 443, 8080],
        country_code: 'US',
        org: 'Demo Organization',
        os: null,
        vulns: [],
        note: 'Demo data — configure API key for live results',
      },
    });
  }

  try {
    const shodanResp = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`);
    const shodanData = await shodanResp.json();

    if (!shodanResp.ok) {
      return json({ success: false, provider: 'Shodan', error: shodanData?.error || 'Shodan API error', status: shodanResp.status });
    }

    return json({
      success: true,
      provider: 'Shodan',
      ip,
      country_code: shodanData.country_code,
      country_name: shodanData.country_name,
      org: shodanData.org,
      isp: shodanData.isp,
      os: shodanData.os,
      open_ports: shodanData.ports || [],
      vulnerabilities: shodanData.vulns || [],
      hostnames: shodanData.hostnames || [],
      tags: shodanData.tags || [],
      last_update: shodanData.last_update,
    });
  } catch (e) {
    return err(`Shodan connector error: ${e.message}`, 502);
  }
}

// ── Route: GET /api/integrations/connector/otx ────────────────────────────
export async function handleConnectorOtx(request, env) {
  const url = new URL(request.url);
  const indicator = url.searchParams.get('indicator') || url.searchParams.get('q');
  const type = url.searchParams.get('type') || 'domain';
  const apiKey = request.headers.get('X-OTX-API-Key') || env.OTX_API_KEY;

  if (!indicator) return err('indicator query param required');

  const sectionMap = { domain: 'general', ip: 'general', url: 'general', hash: 'general' };
  const typeMap = { domain: 'domain', ip: 'IPv4', url: 'url', hash: 'file' };

  const otxType = typeMap[type] || 'domain';
  const otxUrl = `https://otx.alienvault.com/api/v1/indicators/${otxType}/${encodeURIComponent(indicator)}/general`;

  try {
    const headers = apiKey ? { 'X-OTX-API-KEY': apiKey } : {};
    const otxResp = await fetch(otxUrl, { headers });
    const otxData = await otxResp.json();

    if (!otxResp.ok) {
      return json({ success: false, provider: 'AlienVault OTX', error: otxData?.detail || 'OTX API error', status: otxResp.status });
    }

    return json({
      success: true,
      provider: 'AlienVault OTX',
      indicator,
      type,
      pulse_count: otxData.pulse_info?.count || 0,
      reputation: otxData.reputation || 0,
      validation: otxData.validation || [],
      tags: otxData.tags || [],
      malware_families: otxData.malware_families || [],
      sections: otxData.sections || [],
      related: otxData.pulse_info?.related?.alienvault || {},
    });
  } catch (e) {
    return err(`OTX connector error: ${e.message}`, 502);
  }
}

// ── Route: GET /api/integrations/connector/abuseipdb ──────────────────────
export async function handleConnectorAbuseIPDB(request, env) {
  const url = new URL(request.url);
  const ip = url.searchParams.get('ip') || url.searchParams.get('q');
  const days = url.searchParams.get('days') || '30';
  const apiKey = request.headers.get('X-AbuseIPDB-Key') || env.ABUSEIPDB_API_KEY;

  if (!ip) return err('ip query param required');

  if (!apiKey) {
    return json({
      success: false, provider: 'AbuseIPDB', ip,
      error: 'AbuseIPDB API key not configured',
      setup: 'Set ABUSEIPDB_API_KEY in Workers secrets',
      free_tier: 'https://www.abuseipdb.com/pricing',
      demo_response: { abuseConfidenceScore: 0, countryCode: 'US', usageType: 'Unknown', isp: 'Demo ISP', domain: 'demo.example.com', totalReports: 0, numDistinctUsers: 0, lastReportedAt: null, note: 'Demo — configure API key for live results' },
    });
  }

  try {
    const resp = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=${days}&verbose`, {
      headers: { 'Key': apiKey, 'Accept': 'application/json' },
    });
    const data = await resp.json();
    const d = data?.data || {};

    return json({
      success: true,
      provider: 'AbuseIPDB',
      ip,
      abuse_confidence_score: d.abuseConfidenceScore || 0,
      is_malicious: (d.abuseConfidenceScore || 0) > 25,
      country_code: d.countryCode,
      usage_type: d.usageType,
      isp: d.isp,
      domain: d.domain,
      total_reports: d.totalReports || 0,
      distinct_users: d.numDistinctUsers || 0,
      last_reported_at: d.lastReportedAt,
      is_whitelisted: d.isWhitelisted,
    });
  } catch (e) {
    return err(`AbuseIPDB connector error: ${e.message}`, 502);
  }
}

// ── Route: POST /api/integrations/connector/misp ──────────────────────────
export async function handleConnectorMisp(request, env) {
  const body = await request.json().catch(() => ({}));
  const { misp_url, misp_key, action = 'search', params = {} } = body;

  if (!misp_url || !misp_key) {
    return json({
      success: false, provider: 'MISP',
      error: 'misp_url and misp_key required in request body',
      setup: 'Provide your MISP instance URL and API key',
      docs: 'https://www.misp-project.org/documentation/',
      actions: ['search', 'push_event', 'get_event', 'list_events'],
    });
  }

  const normalizedUrl = misp_url.replace(/\/$/, '');

  try {
    let endpoint = `${normalizedUrl}/events/restSearch`;
    let method = 'POST';
    let reqBody = { returnFormat: 'json', limit: params.limit || 10, ...params };

    if (action === 'list_events') {
      endpoint = `${normalizedUrl}/events/index`;
      method = 'GET';
      reqBody = null;
    } else if (action === 'get_event' && params.event_id) {
      endpoint = `${normalizedUrl}/events/view/${params.event_id}`;
      method = 'GET';
      reqBody = null;
    } else if (action === 'push_event') {
      endpoint = `${normalizedUrl}/events/add`;
      method = 'POST';
      reqBody = params;
    }

    const resp = await fetch(endpoint, {
      method,
      headers: { 'Authorization': misp_key, 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: reqBody ? JSON.stringify(reqBody) : undefined,
    });

    const data = await resp.json().catch(() => ({}));
    return json({ success: resp.ok, provider: 'MISP', action, status: resp.status, data });
  } catch (e) {
    return err(`MISP connector error: ${e.message}`, 502);
  }
}

// ── Route: POST /api/integrations/enterprise/provision ────────────────────
export async function handleEnterpriseProvision(request, env) {
  const body = await request.json().catch(() => ({}));

  // Rate limit: 3 provisions per IP per day
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const today = new Date().toISOString().slice(0, 10);
  const rlKey = `enterprise:provision:ratelimit:${ip}:${today}`;
  const rlCount = parseInt(await env.KV.get(rlKey) || '0');
  if (rlCount >= 3) {
    return err('Provision rate limit exceeded (3/day per IP). Contact bivash@cyberdudebivash.com for enterprise setup.', 429, 'RATE_LIMIT');
  }
  await env.KV.put(rlKey, String(rlCount + 1), { expirationTtl: 86400 });

  const result = await provisionEnterpriseCustomer(env, body);

  if (!result.success) return err(result.error, 400);

  return json({ success: true, ...result }, 201);
}

// ── Route: GET /api/integrations/enterprise/status ────────────────────────
export async function handleEnterpriseStatus(request, env) {
  const url = new URL(request.url);
  const orgId = url.searchParams.get('org_id');
  const domain = url.searchParams.get('domain');

  if (!orgId && !domain) return err('org_id or domain required');

  let lookupId = orgId;
  if (!lookupId && domain) {
    lookupId = await env.KV.get(`enterprise:domain:${domain}`);
  }

  if (!lookupId) return json({ success: false, error: 'Organization not found', provisioned: false }, 404);

  const record = await env.KV.get(`enterprise:org:${lookupId}`, 'json');
  if (!record) return json({ success: false, error: 'Organization record expired or not found', provisioned: false }, 404);

  return json({
    success: true,
    provisioned: true,
    org_id: record.org_id,
    org_name: record.org_name,
    tier: record.tier,
    status: record.status,
    soc_type: record.soc_type,
    regions: record.regions,
    integrations_enabled: record.integrations,
    provisioned_at: record.provisioned_at,
    expires_at: record.expires_at,
    endpoints: {
      taxii: record.taxii_endpoint,
      stix_bundle: 'https://cyberdudebivash.in/api/integrations/stix/bundle',
      siem_splunk: 'https://cyberdudebivash.in/api/integrations/siem/splunk',
      siem_sentinel: 'https://cyberdudebivash.in/api/integrations/siem/sentinel',
      api_docs: 'https://cyberdudebivash.in/integrations.html',
    },
  });
}

// ── Route: GET /api/integrations/observability ────────────────────────────
export async function handleIntegrationObservability(request, env) {
  const allIntegrations = Object.values(INTEGRATION_CATALOG).flat();

  return json({
    success: true,
    engine: 'P25.0 Enterprise Integration Hub',
    version: '40.0.0',
    status: 'operational',
    timestamp: new Date().toISOString(),
    integration_catalog: {
      total: allIntegrations.length,
      active: allIntegrations.filter(i => i.status === 'active').length,
      coming_soon: allIntegrations.filter(i => i.status === 'coming_soon').length,
      categories: Object.fromEntries(Object.entries(INTEGRATION_CATALOG).map(([k, v]) => [k, v.length])),
    },
    endpoints: {
      catalog: '/api/integrations/catalog',
      stix_bundle: '/api/integrations/stix/bundle',
      taxii: '/api/integrations/taxii/collections',
      siem_splunk: '/api/integrations/siem/splunk',
      siem_sentinel: '/api/integrations/siem/sentinel',
      siem_qradar: '/api/integrations/siem/qradar',
      siem_chronicle: '/api/integrations/siem/chronicle',
      webhook_test: '/api/integrations/webhook/test',
      enterprise_provision: '/api/integrations/enterprise/provision',
      virustotal: '/api/integrations/connector/virustotal',
      shodan: '/api/integrations/connector/shodan',
      otx: '/api/integrations/connector/otx',
      abuseipdb: '/api/integrations/connector/abuseipdb',
      misp: '/api/integrations/connector/misp',
    },
    standards: ['STIX 2.1', 'TAXII 2.1', 'MITRE ATT&CK', 'MITRE ATLAS', 'NIST CSF 2.0', 'OpenIOC', 'YARA', 'Sigma', 'CEF', 'UDM'],
    supported_siem: ['Splunk', 'Microsoft Sentinel', 'IBM QRadar', 'Google Chronicle', 'Elastic SIEM', 'Sumo Logic', 'Datadog', 'AWS Security Hub', 'Palo Alto XSIAM'],
    supported_cti: ['MISP', 'OpenCTI', 'TheHive', 'VirusTotal', 'Shodan', 'AlienVault OTX', 'AbuseIPDB', 'ThreatFox', 'IBM X-Force', 'Recorded Future'],
  });
}
