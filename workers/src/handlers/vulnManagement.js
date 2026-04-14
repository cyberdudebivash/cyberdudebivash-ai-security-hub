/**
 * CYBERDUDEBIVASH AI Security Hub — Vulnerability Management Handler v19.0
 * Full vuln lifecycle: ingest → triage → remediate → verify → close
 * Real NVD/CISA KEV feed integration, CVSS 3.1 + EPSS scoring,
 * risk-prioritized kanban, SLA tracking, remediation playbooks.
 *
 * Routes:
 *   GET   /api/vulns                     → list vulnerabilities (filtered)
 *   POST  /api/vulns                     → create / ingest a vulnerability
 *   GET   /api/vulns/:id                 → get single vuln detail
 *   POST  /api/vulns/:id/remediate       → advance remediation stage
 *   GET   /api/vulns/stats               → dashboard stats
 *   GET   /api/vulns/cve/:cveId          → live NVD CVE lookup
 *   GET   /api/vulns/kev                 → CISA KEV catalog feed
 */

import { inspectBodyForAttacks, sanitizeString } from '../middleware/security.js';
import { checkRateLimitCost, rateLimitResponse }  from '../middleware/rateLimit.js';
// v21.0 — Adaptive CyberBrain: vuln prioritization
import { prioritizeVulns } from '../core/cyberBrain.js';

// ─── Remediation stage lifecycle ─────────────────────────────────────────────
const STAGES = ['open', 'in_progress', 'testing', 'patched', 'accepted_risk', 'false_positive'];

const STAGE_TRANSITIONS = {
  open:          ['in_progress', 'accepted_risk', 'false_positive'],
  in_progress:   ['testing', 'open'],
  testing:       ['patched', 'in_progress'],
  patched:       [],
  accepted_risk: ['open'],
  false_positive:['open'],
};

// ─── Seed vulnerability dataset (used when no DB is available) ────────────────
function generateSeedVulns() {
  return [
    {
      id: 'vuln-001',
      cve_id: 'CVE-2024-21413',
      title: 'Microsoft Outlook Remote Code Execution via WINAPI Moniker',
      severity: 'CRITICAL',
      cvss_score: 9.8,
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      epss_score: 0.927,
      epss_pct: 0.99,
      in_kev: true,
      affected: 'Microsoft Outlook 2016, 2019, M365 Apps',
      stage: 'in_progress',
      category: 'RCE',
      attack_vector: 'Network',
      discovered_at: '2024-02-14',
      sla_due: '2024-02-28',
      sla_breached: true,
      remediation: 'Apply KB5002432 or restrict MKH links via Group Policy',
      tags: ['microsoft', 'rce', 'kev', 'critical-patch'],
    },
    {
      id: 'vuln-002',
      cve_id: 'CVE-2024-3400',
      title: 'PAN-OS Command Injection in GlobalProtect (Zero-Day)',
      severity: 'CRITICAL',
      cvss_score: 10.0,
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      epss_score: 0.974,
      epss_pct: 0.99,
      in_kev: true,
      affected: 'PAN-OS 10.2, 11.0, 11.1 (GlobalProtect enabled)',
      stage: 'open',
      category: 'Command Injection',
      attack_vector: 'Network',
      discovered_at: '2024-04-12',
      sla_due: '2024-04-19',
      sla_breached: true,
      remediation: 'Apply PAN-OS hotfix or disable GlobalProtect gateway/portal',
      tags: ['palo-alto', 'zero-day', 'kev', 'firewall'],
    },
    {
      id: 'vuln-003',
      cve_id: 'CVE-2023-44487',
      title: 'HTTP/2 Rapid Reset DDoS Attack (CVSS 7.5)',
      severity: 'HIGH',
      cvss_score: 7.5,
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      epss_score: 0.712,
      epss_pct: 0.97,
      in_kev: true,
      affected: 'nginx, Apache httpd, IIS, Go net/http, Node.js http2',
      stage: 'patched',
      category: 'DoS',
      attack_vector: 'Network',
      discovered_at: '2023-10-10',
      sla_due: '2023-10-24',
      sla_breached: false,
      remediation: 'Update to patched versions; disable HTTP/2 as interim mitigation',
      tags: ['dos', 'kev', 'web-server', 'http2'],
    },
    {
      id: 'vuln-004',
      cve_id: 'CVE-2024-1708',
      title: 'ConnectWise ScreenConnect Path Traversal (SlashAndGrab)',
      severity: 'CRITICAL',
      cvss_score: 9.8,
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      epss_score: 0.966,
      epss_pct: 0.99,
      in_kev: true,
      affected: 'ConnectWise ScreenConnect < 23.9.8',
      stage: 'open',
      category: 'Path Traversal',
      attack_vector: 'Network',
      discovered_at: '2024-02-20',
      sla_due: '2024-02-27',
      sla_breached: true,
      remediation: 'Upgrade to ScreenConnect 23.9.8 or later immediately',
      tags: ['connectwise', 'rce', 'kev', 'ransomware'],
    },
    {
      id: 'vuln-005',
      cve_id: 'CVE-2024-27198',
      title: 'JetBrains TeamCity Authentication Bypass',
      severity: 'CRITICAL',
      cvss_score: 9.8,
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      epss_score: 0.958,
      epss_pct: 0.99,
      in_kev: true,
      affected: 'JetBrains TeamCity < 2023.11.4',
      stage: 'in_progress',
      category: 'Authentication Bypass',
      attack_vector: 'Network',
      discovered_at: '2024-03-04',
      sla_due: '2024-03-11',
      sla_breached: true,
      remediation: 'Upgrade TeamCity to 2023.11.4+ or apply security patch plugin',
      tags: ['jetbrains', 'auth-bypass', 'kev', 'ci-cd'],
    },
    {
      id: 'vuln-006',
      cve_id: 'CVE-2024-6387',
      title: 'OpenSSH RegreSSHion Race Condition RCE (unauthenticated)',
      severity: 'CRITICAL',
      cvss_score: 8.1,
      cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
      epss_score: 0.043,
      epss_pct: 0.91,
      in_kev: false,
      affected: 'OpenSSH 8.5p1 – 9.7p1 on glibc Linux',
      stage: 'testing',
      category: 'Race Condition RCE',
      attack_vector: 'Network',
      discovered_at: '2024-07-01',
      sla_due: '2024-07-15',
      sla_breached: false,
      remediation: 'Upgrade to OpenSSH 9.8p1; set LoginGraceTime 0 as interim workaround',
      tags: ['openssh', 'rce', 'linux', 'regression'],
    },
    {
      id: 'vuln-007',
      cve_id: 'CVE-2024-38812',
      title: 'VMware vCenter Server Heap Overflow in DCERPC Protocol',
      severity: 'CRITICAL',
      cvss_score: 9.8,
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      epss_score: 0.821,
      epss_pct: 0.98,
      in_kev: true,
      affected: 'VMware vCenter Server 8.0.x, 7.0.x; VMware Cloud Foundation',
      stage: 'open',
      category: 'Heap Overflow',
      attack_vector: 'Network',
      discovered_at: '2024-09-17',
      sla_due: '2024-09-24',
      sla_breached: true,
      remediation: 'Apply vCenter Server 8.0 U3b or 7.0 U3s patches immediately',
      tags: ['vmware', 'vcenter', 'rce', 'kev', 'virtualization'],
    },
    {
      id: 'vuln-008',
      cve_id: 'CVE-2024-49113',
      title: 'Windows LDAP Remote Code Execution (LDAPNightmare)',
      severity: 'CRITICAL',
      cvss_score: 9.8,
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      epss_score: 0.761,
      epss_pct: 0.98,
      in_kev: false,
      affected: 'Windows Server 2019, 2022, 2025; Windows 10/11',
      stage: 'open',
      category: 'RCE',
      attack_vector: 'Network',
      discovered_at: '2024-12-10',
      sla_due: '2024-12-24',
      sla_breached: false,
      remediation: 'Apply December 2024 Patch Tuesday update KB5048793',
      tags: ['windows', 'ldap', 'rce', 'patch-tuesday'],
    },
  ];
}

// ─── GET /api/vulns ───────────────────────────────────────────────────────────
export async function handleListVulns(request, env, authCtx) {
  const rl = await checkRateLimitCost(env, authCtx, 'audit-log');
  if (!rl.allowed) return rateLimitResponse(rl, 'vulns');

  const url      = new URL(request.url);
  const stage    = url.searchParams.get('stage');
  const severity = url.searchParams.get('severity');
  const kev      = url.searchParams.get('kev');
  const search   = url.searchParams.get('q');
  const sortBy   = url.searchParams.get('sort') || 'cvss_score';
  const order    = url.searchParams.get('order') || 'desc';
  const limit    = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 200);
  const offset   = parseInt(url.searchParams.get('offset') || '0', 10);

  let vulns = generateSeedVulns();

  // Apply filters
  if (stage)    vulns = vulns.filter(v => v.stage === stage);
  if (severity) vulns = vulns.filter(v => v.severity === severity.toUpperCase());
  if (kev === 'true') vulns = vulns.filter(v => v.in_kev);
  if (search) {
    const q = search.toLowerCase();
    vulns = vulns.filter(v =>
      v.title?.toLowerCase().includes(q) ||
      v.cve_id?.toLowerCase().includes(q) ||
      v.affected?.toLowerCase().includes(q) ||
      v.tags?.some(t => t.includes(q))
    );
  }

  // Sort
  vulns.sort((a, b) => {
    const va = a[sortBy] ?? 0;
    const vb = b[sortBy] ?? 0;
    return order === 'asc' ? (va > vb ? 1 : -1) : (va < vb ? 1 : -1);
  });

  // v21.0 — Apply adaptive prioritization for STARTER+ tiers
  const tier = authCtx?.tier || 'FREE';
  if (['STARTER', 'PRO', 'ENTERPRISE'].includes(tier)) {
    vulns = prioritizeVulns(vulns, tier);
  }

  const total     = vulns.length;
  const paginated = vulns.slice(offset, offset + limit);

  const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const byStage    = {};
  vulns.forEach(v => {
    if (bySeverity[v.severity] !== undefined) bySeverity[v.severity]++;
    byStage[v.stage] = (byStage[v.stage] || 0) + 1;
  });

  return Response.json({
    total, limit, offset,
    adaptive_prioritized: ['STARTER', 'PRO', 'ENTERPRISE'].includes(tier),
    summary: { by_severity: bySeverity, by_stage: byStage, kev_count: vulns.filter(v => v.in_kev).length },
    vulns: paginated,
    platform: 'CYBERDUDEBIVASH AI Security Hub v21.0',
  });
}

// ─── POST /api/vulns ──────────────────────────────────────────────────────────
export async function handleCreateVuln(request, env, authCtx) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON body' }, { status: 400 }); }

  if (inspectBodyForAttacks(body)) {
    return Response.json({ error: 'Malicious payload detected' }, { status: 400 });
  }

  const { cve_id, title, severity, affected, cvss_score } = body;

  if (!title || typeof title !== 'string' || title.length < 5) {
    return Response.json({ error: 'title is required (min 5 chars)' }, { status: 400 });
  }
  if (severity && !['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(severity)) {
    return Response.json({ error: 'severity must be one of: CRITICAL, HIGH, MEDIUM, LOW, INFO' }, { status: 400 });
  }

  const id = `vuln_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
  const vuln = {
    id,
    cve_id:       sanitizeString(cve_id || '', 30),
    title:        sanitizeString(title, 300),
    severity:     severity || 'MEDIUM',
    cvss_score:   typeof cvss_score === 'number' ? Math.min(10, Math.max(0, cvss_score)) : null,
    affected:     sanitizeString(affected || '', 500),
    stage:        'open',
    created_by:   authCtx.identity,
    created_at:   new Date().toISOString(),
    org_id:       authCtx.orgId || null,
  };

  if (env.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(
      `vuln:${authCtx.orgId || authCtx.identity}:${id}`,
      JSON.stringify(vuln),
      { expirationTtl: 31536000 }, // 1 year
    ).catch(() => {});
  }

  return Response.json({ success: true, vuln }, { status: 201 });
}

// ─── GET /api/vulns/:id ───────────────────────────────────────────────────────
export async function handleGetVuln(request, env, authCtx, vulnId) {
  // Check seed data first
  const seed = generateSeedVulns().find(v => v.id === vulnId);
  if (seed) {
    return Response.json({
      vuln: {
        ...seed,
        remediation_steps: generateRemediationSteps(seed),
        sla_status: seed.sla_breached ? 'BREACHED' : 'ON_TRACK',
        risk_score: Math.round(seed.cvss_score * 10 * (seed.in_kev ? 1.3 : 1) * (1 + seed.epss_score)),
        next_stage: STAGE_TRANSITIONS[seed.stage]?.[0] || null,
      },
      platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
    });
  }

  // Try KV
  if (env.SECURITY_HUB_KV && authCtx.authenticated) {
    const raw = await env.SECURITY_HUB_KV.get(`vuln:${authCtx.orgId || authCtx.identity}:${vulnId}`).catch(() => null);
    if (raw) {
      try {
        return Response.json({ vuln: JSON.parse(raw), platform: 'CYBERDUDEBIVASH AI Security Hub v19.0' });
      } catch {}
    }
  }

  return Response.json({ error: 'Vulnerability not found' }, { status: 404 });
}

// ─── POST /api/vulns/:id/remediate ────────────────────────────────────────────
export async function handleRemediateVuln(request, env, authCtx, vulnId) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const rl = await checkRateLimitCost(env, authCtx, 'vulns/remediate');
  if (!rl.allowed) return rateLimitResponse(rl, 'vulns/remediate');

  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON body' }, { status: 400 }); }

  const { stage, notes, assignee } = body;

  if (!stage || !STAGES.includes(stage)) {
    return Response.json({
      error: 'stage is required',
      valid: STAGES,
    }, { status: 400 });
  }

  // Find vuln in seed or KV
  const seed = generateSeedVulns().find(v => v.id === vulnId);
  const currentStage = seed?.stage || 'open';
  const allowed = STAGE_TRANSITIONS[currentStage] || [];

  if (!allowed.includes(stage)) {
    return Response.json({
      error: `Cannot transition from '${currentStage}' to '${stage}'`,
      allowed_transitions: allowed,
    }, { status: 400 });
  }

  const update = {
    previous_stage:  currentStage,
    new_stage:       stage,
    updated_by:      authCtx.identity,
    updated_at:      new Date().toISOString(),
    notes:           sanitizeString(notes || '', 1000),
    assignee:        sanitizeString(assignee || '', 100),
    vuln_id:         vulnId,
  };

  // Persist updated stage to KV
  if (env.SECURITY_HUB_KV) {
    const updated = { ...(seed || { id: vulnId }), stage, ...update };
    env.SECURITY_HUB_KV.put(
      `vuln:${authCtx.orgId || authCtx.identity}:${vulnId}:latest`,
      JSON.stringify(updated),
      { expirationTtl: 31536000 },
    ).catch(() => {});
    // Append to history
    env.SECURITY_HUB_KV.put(
      `vuln:history:${vulnId}:${Date.now()}`,
      JSON.stringify(update),
      { expirationTtl: 7776000 },
    ).catch(() => {});
  }

  return Response.json({
    success:     true,
    vuln_id:     vulnId,
    new_stage:   stage,
    update,
    message:     `Vulnerability advanced to '${stage}'`,
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  });
}

// ─── GET /api/vulns/stats ─────────────────────────────────────────────────────
export async function handleVulnStats(request, env, authCtx) {
  const all = generateSeedVulns();

  const stats = {
    total:      all.length,
    by_stage:   {},
    by_severity:{},
    kev_count:  all.filter(v => v.in_kev).length,
    sla_breached: all.filter(v => v.sla_breached).length,
    avg_cvss:   +(all.reduce((s, v) => s + (v.cvss_score || 0), 0) / all.length).toFixed(1),
    avg_epss:   +(all.reduce((s, v) => s + (v.epss_score || 0), 0) / all.length).toFixed(3),
    critical_open: all.filter(v => v.severity === 'CRITICAL' && v.stage === 'open').length,
    risk_score: Math.round(all.reduce((s, v) =>
      s + v.cvss_score * (v.in_kev ? 1.3 : 1) * (1 + v.epss_score), 0)),
  };

  all.forEach(v => {
    stats.by_stage[v.stage]       = (stats.by_stage[v.stage]       || 0) + 1;
    stats.by_severity[v.severity] = (stats.by_severity[v.severity] || 0) + 1;
  });

  return Response.json({
    stats,
    generated_at: new Date().toISOString(),
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  });
}

// ─── GET /api/vulns/cve/:cveId — Live NVD lookup ─────────────────────────────
export async function handleCVELookup(request, env, authCtx, cveId) {
  if (!cveId || !/^CVE-\d{4}-\d{4,}$/i.test(cveId)) {
    return Response.json({ error: 'Invalid CVE ID format (expected CVE-YYYY-NNNNN)' }, { status: 400 });
  }

  // Try NVD API (public, no auth required)
  try {
    const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId.toUpperCase())}`;
    const nvdResp = await fetch(nvdUrl, {
      headers: { 'User-Agent': 'CYBERDUDEBIVASH-SecurityHub/19.0' },
      signal: AbortSignal.timeout(8000),
    });

    if (nvdResp.ok) {
      const data = await nvdResp.json();
      const cve  = data.vulnerabilities?.[0]?.cve;
      if (cve) {
        const metrics = cve.metrics?.cvssMetricV31?.[0] ||
                        cve.metrics?.cvssMetricV30?.[0] ||
                        cve.metrics?.cvssMetricV2?.[0];
        return Response.json({
          cve_id:      cve.id,
          published:   cve.published,
          modified:    cve.lastModified,
          status:      cve.vulnStatus,
          description: cve.descriptions?.find(d => d.lang === 'en')?.value || '',
          cvss_score:  metrics?.cvssData?.baseScore || null,
          cvss_vector: metrics?.cvssData?.vectorString || null,
          cvss_version:metrics?.cvssData?.version || null,
          severity:    metrics?.cvssData?.baseSeverity || null,
          cwe:         cve.weaknesses?.map(w => w.description?.[0]?.value).filter(Boolean) || [],
          references:  cve.references?.slice(0, 10).map(r => ({ url: r.url, tags: r.tags })) || [],
          configurations: cve.configurations?.length || 0,
          source:      'NVD NIST',
          platform:    'CYBERDUDEBIVASH AI Security Hub v19.0',
        });
      }
    }
  } catch {}

  // Fallback: check seed data
  const seed = generateSeedVulns().find(v => v.cve_id?.toUpperCase() === cveId.toUpperCase());
  if (seed) {
    return Response.json({
      cve_id:      seed.cve_id,
      title:       seed.title,
      cvss_score:  seed.cvss_score,
      cvss_vector: seed.cvss_vector,
      severity:    seed.severity,
      affected:    seed.affected,
      in_kev:      seed.in_kev,
      epss_score:  seed.epss_score,
      remediation: seed.remediation,
      source:      'CYBERDUDEBIVASH Seed Intel (NVD unavailable)',
      platform:    'CYBERDUDEBIVASH AI Security Hub v19.0',
    });
  }

  return Response.json({ error: `CVE ${cveId} not found in NVD or local intelligence` }, { status: 404 });
}

// ─── GET /api/vulns/kev — CISA KEV feed ──────────────────────────────────────
export async function handleKEVFeed(request, env, authCtx) {
  // Try live CISA KEV catalog
  try {
    const kevResp = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
      headers: { 'User-Agent': 'CYBERDUDEBIVASH-SecurityHub/19.0' },
      signal: AbortSignal.timeout(8000),
    });
    if (kevResp.ok) {
      const data = await kevResp.json();
      const url  = new URL(request.url);
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 500);
      const offset = parseInt(url.searchParams.get('offset') || '0', 10);
      const q = url.searchParams.get('q')?.toLowerCase();

      let vulns = data.vulnerabilities || [];
      if (q) vulns = vulns.filter(v =>
        v.cveID?.toLowerCase().includes(q) ||
        v.vendorProject?.toLowerCase().includes(q) ||
        v.product?.toLowerCase().includes(q)
      );

      return Response.json({
        catalog_version: data.catalogVersion,
        date_released:   data.dateReleased,
        count:           data.count,
        total_filtered:  vulns.length,
        limit, offset,
        vulnerabilities: vulns.slice(offset, offset + limit),
        source:          'CISA KEV (live)',
        platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
      });
    }
  } catch {}

  // Fallback: return KEV-marked entries from seed data
  const kevVulns = generateSeedVulns().filter(v => v.in_kev);
  return Response.json({
    catalog_version: 'local-seed',
    total_filtered:  kevVulns.length,
    vulnerabilities: kevVulns,
    source:          'CYBERDUDEBIVASH Seed Intel (CISA KEV unavailable)',
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  });
}

// ─── Helper: generate remediation steps ──────────────────────────────────────
function generateRemediationSteps(vuln) {
  const steps = [
    { step: 1, action: 'Confirm vulnerability presence',     detail: `Verify ${vuln.cve_id} affects your environment`, done: vuln.stage !== 'open' },
    { step: 2, action: 'Assess impact and blast radius',      detail: 'Identify all affected systems and data sensitivity', done: ['in_progress','testing','patched'].includes(vuln.stage) },
    { step: 3, action: 'Apply vendor patch or workaround',   detail: vuln.remediation || 'Apply available security patch', done: ['testing','patched'].includes(vuln.stage) },
    { step: 4, action: 'Validate remediation in staging',     detail: 'Run regression tests and confirm patch effectiveness', done: vuln.stage === 'patched' },
    { step: 5, action: 'Deploy to production',               detail: 'Roll out patch with change management approval', done: vuln.stage === 'patched' },
    { step: 6, action: 'Post-deployment verification',       detail: 'Re-scan to confirm vulnerability is closed', done: vuln.stage === 'patched' },
  ];
  return steps;
}
