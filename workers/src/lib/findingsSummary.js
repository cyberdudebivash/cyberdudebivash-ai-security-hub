/**
 * Compact findings summary persisted onto scan_history rows (see
 * schema_migration_scan_history_findings_2026_07.sql). A raw finding can
 * carry a lot of detail (mitre_techniques, epss, remediation_sla, long
 * descriptions) that the dashboard doesn't render and that would bloat
 * every scan_history row — this keeps only what the Scans page and Threat
 * Graph actually use, and caps the count so one scan can't dominate row
 * size. Preserves cve_id/ip/actor when a module's findings carry them
 * (some do), without requiring them (the domain scanner's findings don't).
 */
const MAX_FINDINGS_PERSISTED = 20;

export function distillFindingsForHistory(findings) {
  if (!Array.isArray(findings) || findings.length === 0) return null;
  const compact = findings.slice(0, MAX_FINDINGS_PERSISTED).map(f => ({
    id:       f?.id ?? null,
    title:    f?.title ?? f?.description ?? null,
    severity: String(f?.severity || 'medium').toLowerCase(),
    cvss:     f?.cvss_base ?? f?.cvss ?? null,
    ...(Array.isArray(f?.cwe_ids) ? { cwe_ids: f.cwe_ids.slice(0, 5) } : {}),
    ...(f?.cve_id ? { cve_id: f.cve_id } : {}),
    ...(f?.ip     ? { ip:     f.ip }     : {}),
    ...(f?.actor  ? { actor:  f.actor }  : {}),
  }));
  try { return JSON.stringify(compact); } catch { return null; }
}

export function parsePersistedFindings(raw) {
  if (!raw) return undefined;
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : undefined;
  } catch { return undefined; }
}
