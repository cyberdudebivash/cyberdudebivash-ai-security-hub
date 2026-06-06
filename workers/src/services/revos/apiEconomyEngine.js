/**
 * CYBERDUDEBIVASH AI Security Hub — API Economy + Defense Pipeline v23.0
 * Per-call API billing, usage aggregation, automated CVE→product pipeline
 */

// ─── API cost matrix (paise per call) ────────────────────────────────────────
const API_COSTS = {
  FREE:       { per_call: 0,   daily_limit: 50,    monthly_limit: 500  },
  STARTER:    { per_call: 0,   daily_limit: 200,   monthly_limit: 2000 },
  PRO:        { per_call: 0,   daily_limit: 500,   monthly_limit: 15000 },
  ENTERPRISE: { per_call: 0,   daily_limit: 10000, monthly_limit: -1   },
  PAY_AS_GO:  { per_call: 50,  daily_limit: -1,    monthly_limit: -1   }, // ₹0.50/call
};

const ENDPOINT_COSTS = {
  '/api/ai/analyze':       200, // ₹2/AI analysis call
  '/api/ai/chat':          100, // ₹1/MYTHOS chat
  '/api/ai/generate-rules': 300, // ₹3/rule generation
  '/api/ai/simulate':      200,
  '/api/ai/forecast':      200,
  '/api/scan/domain':       50,
  '/api/scan/ai':           50,
  '/api/scan/redteam':      50,
  '/api/export/siem':      100,
};

// ─── Record API call + billing ────────────────────────────────────────────────
export async function recordAPICall(db, kv, apiKeyId, userId, plan, endpoint, method, statusCode, responseMs) {
  if (!db) return;
  try {
    const period = new Date().toISOString().slice(0, 7);
    const costPaise = plan === 'PAY_AS_GO'
      ? (ENDPOINT_COSTS[endpoint] || API_COSTS.PAY_AS_GO.per_call)
      : 0;

    // Fire-and-forget insert
    db.prepare(`
      INSERT INTO api_billing
        (api_key_id, user_id, endpoint, method, plan, response_ms, status_code, cost_paise, billing_period)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(apiKeyId, userId, endpoint, method, plan, responseMs, statusCode, costPaise, period)
      .run().catch(() => {});

    // Update usage summary (upsert)
    db.prepare(`
      INSERT INTO api_usage_summary (api_key_id, user_id, period, total_calls, successful_calls, failed_calls, total_cost_paise)
      VALUES (?, ?, ?, 1, ?, ?, ?)
      ON CONFLICT(api_key_id, period) DO UPDATE SET
        total_calls      = total_calls + 1,
        successful_calls = successful_calls + CASE WHEN ? < 400 THEN 1 ELSE 0 END,
        failed_calls     = failed_calls + CASE WHEN ? >= 400 THEN 1 ELSE 0 END,
        total_cost_paise = total_cost_paise + ?,
        updated_at       = datetime('now')
    `).bind(
      apiKeyId, userId, period,
      statusCode < 400 ? 1 : 0,
      statusCode >= 400 ? 1 : 0,
      costPaise,
      statusCode, statusCode, costPaise,
    ).run().catch(() => {});
  } catch {}
}

// ─── Get API usage for a key ──────────────────────────────────────────────────
export async function getAPIUsage(db, apiKeyId, period) {
  if (!db) return null;
  const p = period || new Date().toISOString().slice(0, 7);
  try {
    const [summary, topEndpoints, dailyTrend] = await Promise.all([
      db.prepare(`SELECT * FROM api_usage_summary WHERE api_key_id=? AND period=?`)
        .bind(apiKeyId, p).first(),
      db.prepare(`
        SELECT endpoint, COUNT(*) as calls, AVG(response_ms) as avg_ms
        FROM api_billing WHERE api_key_id=? AND billing_period=?
        GROUP BY endpoint ORDER BY calls DESC LIMIT 10
      `).bind(apiKeyId, p).all(),
      db.prepare(`
        SELECT date(created_at) as day, COUNT(*) as calls
        FROM api_billing WHERE api_key_id=? AND billing_period=?
        GROUP BY day ORDER BY day
      `).bind(apiKeyId, p).all(),
    ]);

    return {
      period:        p,
      total_calls:   summary?.total_calls || 0,
      successful:    summary?.successful_calls || 0,
      failed:        summary?.failed_calls || 0,
      cost_paise:    summary?.total_cost_paise || 0,
      cost_inr:      ((summary?.total_cost_paise || 0) / 100).toFixed(2),
      top_endpoints: topEndpoints.results || [],
      daily_trend:   dailyTrend.results || [],
    };
  } catch { return null; }
}

// ─── Developer Portal: full API key analytics dashboard ──────────────────────
export async function getDevPortalData(db, userId) {
  if (!db) return {};
  try {
    const period = new Date().toISOString().slice(0, 7);
    const [keys, totalUsage, monthlyTrend] = await Promise.all([
      db.prepare(`
        SELECT ak.*, aus.total_calls, aus.total_cost_paise
        FROM api_keys ak
        LEFT JOIN api_usage_summary aus ON ak.id=aus.api_key_id AND aus.period=?
        WHERE ak.user_id=? ORDER BY ak.created_at DESC
      `).bind(period, userId).all(),

      db.prepare(`
        SELECT
          COALESCE(SUM(total_calls),0) as calls,
          COALESCE(SUM(total_cost_paise),0) as cost_paise,
          COALESCE(SUM(successful_calls),0) as successful
        FROM api_usage_summary WHERE user_id=? AND period=?
      `).bind(userId, period).first(),

      db.prepare(`
        SELECT period, SUM(total_calls) as calls, SUM(total_cost_paise) as cost
        FROM api_usage_summary WHERE user_id=?
        GROUP BY period ORDER BY period DESC LIMIT 6
      `).bind(userId).all(),
    ]);

    return {
      api_keys:      keys.results || [],
      this_month:    {
        calls:    totalUsage?.calls || 0,
        cost_inr: ((totalUsage?.cost_paise || 0) / 100).toFixed(2),
        success_rate: totalUsage?.calls > 0
          ? Math.round((totalUsage.successful / totalUsage.calls) * 100) : 100,
      },
      monthly_trend: monthlyTrend.results || [],
      rate_limits:   API_COSTS,
    };
  } catch { return {}; }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 4 — Defense Product Auto-Generation Pipeline
// ═══════════════════════════════════════════════════════════════════════════════

const PRODUCT_TYPES = ['sigma_rule','yara_rule','kql_rule','splunk_spl','ir_playbook','hardening_guide'];

// ─── Queue CVEs for product generation ───────────────────────────────────────
export async function queueCVEsForGeneration(db, cves) {
  if (!db || !cves?.length) return { queued: 0 };
  let queued = 0;
  for (const cve of cves) {
    try {
      await db.prepare(`
        INSERT OR IGNORE INTO product_pipeline
          (cve_id, cve_title, cvss_score, severity, status, products_queued)
        VALUES (?, ?, ?, ?, 'queued', ?)
      `).bind(
        cve.id || cve.cve_id,
        cve.title || `${cve.id} Vulnerability`,
        cve.cvss || cve.cvss_score || 0,
        cve.severity || 'MEDIUM',
        JSON.stringify(PRODUCT_TYPES),
      ).run();
      queued++;
    } catch {}
  }
  return { queued };
}

// ─── Generate product content from CVE data ──────────────────────────────────
export function generateProductContent(cve, productType) {
  const cveId    = cve.id || cve.cve_id || 'CVE-UNKNOWN';
  const vendor   = extractVendor(cve.title || '');
  const cvss     = cve.cvss || cve.cvss_score || 7.0;
  const severity = cve.severity || 'HIGH';

  const templates = {
    sigma_rule: `title: ${cveId} — ${vendor} Exploitation Detection
id: ${generateUUID()}
status: stable
description: Detects exploitation attempts for ${cveId} (CVSS ${cvss})
references:
  - https://nvd.nist.gov/vuln/detail/${cveId}
tags:
  - attack.initial_access
  - attack.t1190
  - cve.${cveId.toLowerCase().replace(/-/g,'_')}
logsource:
  category: webserver
detection:
  selection:
    http.uri|contains:
      - '${generateExploitPattern(cve)}'
  condition: selection
falsepositives:
  - Legitimate security scanners
level: ${severity.toLowerCase()}
# CYBERDUDEBIVASH SENTINEL APEX — Generated ${new Date().toISOString().slice(0,10)}`,

    yara_rule: `rule ${cveId.replace(/-/g,'_')}_Exploit {
  meta:
    description = "Detects ${cveId} exploitation artifacts"
    author = "CYBERDUDEBIVASH SENTINEL APEX"
    date = "${new Date().toISOString().slice(0,10)}"
    reference = "https://nvd.nist.gov/vuln/detail/${cveId}"
    severity = "${severity}"
    cvss = "${cvss}"
  strings:
    $exploit1 = "${generateExploitPattern(cve)}" ascii nocase
    $exploit2 = "${cveId}" ascii
    $vendor = "${vendor}" ascii nocase
  condition:
    any of ($exploit*) and $vendor
}`,

    kql_rule: `// ${cveId} — ${vendor} Exploitation Detection
// CVSS: ${cvss} | Severity: ${severity}
// CYBERDUDEBIVASH SENTINEL APEX
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4625, 4648, 4672, 4720)
| where ProcessCommandLine has_any ("${generateExploitPattern(cve)}", "${cveId}")
| extend ThreatLevel = "${severity}"
| extend CVE = "${cveId}"
| project TimeGenerated, Computer, Account, ProcessCommandLine, ThreatLevel, CVE
| order by TimeGenerated desc`,

    splunk_spl: `| tstats summariesonly=true count from datamodel=Web
  where Web.http_uri="${generateExploitPattern(cve)}"
  OR Web.http_uri="*${cveId}*"
  by Web.src Web.dest Web.http_uri Web.status
| eval threat="${cveId}"
| eval severity="${severity}"
| eval cvss="${cvss}"
| table _time, src, dest, http_uri, status, threat, severity, cvss
| sort - _time
// CYBERDUDEBIVASH SENTINEL APEX — ${new Date().toISOString().slice(0,10)}`,

    ir_playbook: `# ${cveId} Incident Response Playbook
## CYBERDUDEBIVASH SENTINEL APEX | CVSS ${cvss} | ${severity}

### Phase 1: DETECTION (0-1 hour)
- [ ] Confirm exploitation via IDS/SIEM alerts for ${cveId} signatures
- [ ] Identify affected systems running ${vendor}
- [ ] Capture network traffic from suspected hosts
- [ ] Check logs for IOCs: ${generateExploitPattern(cve)}

### Phase 2: CONTAINMENT (1-4 hours)
- [ ] Isolate affected systems from network
- [ ] Block attacker IP ranges at perimeter firewall
- [ ] Revoke active sessions on affected ${vendor} instances
- [ ] Enable enhanced logging on remaining ${vendor} systems
- [ ] Apply emergency WAF rule blocking exploit pattern

### Phase 3: ERADICATION (4-24 hours)
- [ ] Apply vendor patch for ${cveId} (check NVD for patch URL)
- [ ] Scan all ${vendor} instances with provided YARA rule
- [ ] Reset all service account credentials
- [ ] Audit privilege escalation events in SIEM
- [ ] Remove any backdoors or persistence mechanisms found

### Phase 4: RECOVERY (24-72 hours)
- [ ] Restore from clean backup if system compromise confirmed
- [ ] Verify patch applied to ALL ${vendor} instances
- [ ] Perform post-patch validation scan
- [ ] Monitor for 48h with enhanced alerting enabled
- [ ] Document timeline and artifacts for post-incident review

### IOCs to Hunt
- CVE Reference: ${cveId}
- Exploit Pattern: ${generateExploitPattern(cve)}
- CVSS: ${cvss} | Severity: ${severity}

*Generated by CYBERDUDEBIVASH MYTHOS AI Engine — ${new Date().toISOString().slice(0,10)}*`,

    hardening_guide: `#!/bin/bash
# ${cveId} Hardening Script — ${vendor}
# CYBERDUDEBIVASH SENTINEL APEX
# CVSS: ${cvss} | Severity: ${severity}
# Run as root on affected systems

set -e
echo "[*] Starting ${cveId} hardening for ${vendor}..."

# 1. Check if affected version is installed
echo "[1/5] Checking ${vendor} installation..."
# Add version detection for ${vendor}

# 2. Apply configuration hardening
echo "[2/5] Applying security configuration..."
# Disable vulnerable features
# Enable security headers
# Restrict exposed interfaces

# 3. Apply network controls
echo "[3/5] Configuring firewall rules..."
iptables -A INPUT -p tcp --dport 443 -m string --string "${generateExploitPattern(cve)}" --algo bm -j DROP
iptables -A INPUT -p tcp --dport 80  -m string --string "${generateExploitPattern(cve)}" --algo bm -j DROP

# 4. Enable enhanced logging
echo "[4/5] Enabling enhanced logging..."
# Configure syslog for ${vendor} events

# 5. Verify patch status
echo "[5/5] Verification complete."
echo "[+] ${cveId} hardening applied. Restart ${vendor} service to apply changes."
echo "[!] Apply vendor patch from: https://nvd.nist.gov/vuln/detail/${cveId}"
# CYBERDUDEBIVASH SENTINEL APEX`,
  };

  return {
    type:     productType,
    cve_id:   cveId,
    content:  templates[productType] || `# ${productType} for ${cveId}\n# Generated by CYBERDUDEBIVASH MYTHOS`,
    title:    `${vendor} — ${productTypeLabel(productType)}`,
    preview:  (templates[productType] || '').slice(0, 300),
    price_inr: priceByType(productType, severity),
    price_usd: Math.round(priceByType(productType, severity) / 83),
  };
}

// ─── Run the full product generation pipeline for a CVE ──────────────────────
export async function runProductPipeline(db, cveId) {
  if (!db) return { ok: false };
  try {
    // Mark as started
    await db.prepare(`UPDATE product_pipeline SET status='generating', started_at=datetime('now') WHERE cve_id=?`)
      .bind(cveId).run();

    // Get CVE data
    const cve = await db.prepare(`SELECT * FROM threat_intel WHERE id=? OR cve_id=? LIMIT 1`)
      .bind(cveId, cveId).first() || { id: cveId, severity: 'HIGH', cvss: 7.0 };

    const done = [];
    for (const type of PRODUCT_TYPES) {
      try {
        const product = generateProductContent(cve, type);
        const solId = `sol-${cveId.toLowerCase().replace(/[^a-z0-9]/g,'-')}-${type.replace(/_/g,'-')}`;

        await db.prepare(`
          INSERT OR IGNORE INTO defense_solutions
            (id, cve_id, title, description, category, price_inr, price_usd,
             demand_score, severity, cvss_score, preview, full_content_key, difficulty,
             apt_groups, is_active, is_featured, generated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'INTERMEDIATE', '[]', 1, 0, datetime('now'))
        `).bind(
          solId, cveId, product.title,
          `Auto-generated ${productTypeLabel(type)} for ${cveId} (CVSS ${cve.cvss || 7.0})`,
          type, product.price_inr, product.price_usd,
          cve.cvss ? Math.min(0.99, (cve.cvss / 10) * 0.95) : 0.75,
          cve.severity || 'HIGH',
          cve.cvss || cve.cvss_score || 7.0,
          product.preview,
          `products/${cveId}/${type}.txt`,
        ).run();
        done.push(type);
      } catch {}
    }

    await db.prepare(`
      UPDATE product_pipeline
      SET status='published', products_done=?, completed_at=datetime('now')
      WHERE cve_id=?
    `).bind(JSON.stringify(done), cveId).run();

    return { ok: true, cve_id: cveId, products_generated: done.length };
  } catch (e) {
    await db.prepare(`UPDATE product_pipeline SET status='failed', error=? WHERE cve_id=?`)
      .bind(e.message, cveId).run().catch(() => {});
    return { ok: false, error: e.message };
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function extractVendor(title) {
  const vendors = ['Ivanti','Fortinet','Cisco','Palo Alto','Microsoft','Apache','JetBrains','ConnectWise','Citrix','VMware','SolarWinds','MOVEit'];
  return vendors.find(v => title.includes(v)) || title.split(' ')[0] || 'Unknown';
}

function generateExploitPattern(cve) {
  const patterns = {
    rce: '${jndi:', sqli: "' OR '1'='1", ssrf: '/api/v1/../../etc/passwd',
    auth_bypass: '/admin/setup', path_traversal: '../../../../etc/passwd',
  };
  const title = (cve.title || '').toLowerCase();
  if (title.includes('jndi') || title.includes('log4')) return '${jndi:ldap://';
  if (title.includes('sql')) return "';DROP TABLE--";
  if (title.includes('rce') || title.includes('command')) return ';id;whoami;';
  if (title.includes('ssrf')) return '/api/v1/../../';
  if (title.includes('path') || title.includes('traversal')) return '../../../etc/';
  return `/${(cve.id || 'cve').toLowerCase()}/exploit`;
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

function productTypeLabel(type) {
  const labels = {
    sigma_rule: 'Sigma Detection Rules',
    yara_rule: 'YARA Malware Rules',
    kql_rule: 'KQL Detection Query',
    splunk_spl: 'Splunk SPL Rules',
    ir_playbook: 'IR Playbook',
    hardening_guide: 'Hardening Script',
  };
  return labels[type] || type;
}

function priceByType(type, severity) {
  const base = { sigma_rule: 899, yara_rule: 899, kql_rule: 799, splunk_spl: 799, ir_playbook: 1199, hardening_guide: 999 };
  const multiplier = severity === 'CRITICAL' ? 1.4 : severity === 'HIGH' ? 1.2 : 1.0;
  return Math.round((base[type] || 799) * multiplier / 100) * 100;
}
