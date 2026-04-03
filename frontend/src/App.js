import React, { useState, useEffect, useCallback } from "react";

const API = "";  // uses CRA proxy → http://localhost:8000

// ── API helpers ──────────────────────────────────────────────
const api = {
  get: (path) => fetch(`${API}${path}`).then(r => r.json()),
  post: (path, body) => fetch(`${API}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).then(r => r.json()),
};

// ── Small UI primitives ───────────────────────────────────────
const Card = ({ title, children, color = "#1a1f2e" }) => (
  <div style={{
    background: color, borderRadius: 10, padding: 20,
    marginBottom: 16, border: "1px solid #2d3748",
  }}>
    {title && <h3 style={{ color: "#63b3ed", marginTop: 0, marginBottom: 12 }}>{title}</h3>}
    {children}
  </div>
);

const Badge = ({ label, color = "#4a5568" }) => (
  <span style={{
    background: color, color: "#fff", borderRadius: 4,
    padding: "2px 8px", fontSize: 11, fontWeight: 700,
    marginRight: 4, display: "inline-block",
  }}>{label}</span>
);

const severityColor = (s) => ({
  CRITICAL: "#e53e3e", HIGH: "#dd6b20", MEDIUM: "#d69e2e",
  LOW: "#38a169", INFO: "#4299e1", PASS: "#38a169",
}[s?.toUpperCase()] || "#4a5568");

const Btn = ({ onClick, children, disabled, color = "#4299e1" }) => (
  <button onClick={onClick} disabled={disabled} style={{
    background: disabled ? "#4a5568" : color, color: "#fff",
    border: "none", borderRadius: 6, padding: "8px 18px",
    cursor: disabled ? "not-allowed" : "pointer", fontWeight: 600, fontSize: 13,
  }}>{children}</button>
);

const Input = ({ value, onChange, placeholder, multiline, rows = 4 }) => {
  const style = {
    width: "100%", background: "#2d3748", color: "#e2e8f0",
    border: "1px solid #4a5568", borderRadius: 6, padding: "8px 12px",
    fontSize: 13, boxSizing: "border-box",
  };
  return multiline
    ? <textarea value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} rows={rows} style={style} />
    : <input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} style={style} />;
};

const Spinner = () => (
  <span style={{ display: "inline-block", animation: "spin 1s linear infinite" }}>⚙️</span>
);

// ── Dashboard Tab ─────────────────────────────────────────────
function Dashboard() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    api.get("/system/status").then(d => { setStatus(d); setLoading(false); });
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [load]);

  if (loading && !status) return <p style={{ color: "#a0aec0" }}>Loading system status…</p>;

  const comp = status?.components || {};
  const compColor = (v) => (v === "CONNECTED" || v === "ONLINE" ? "#38a169" : v?.includes("AGENT") ? "#4299e1" : "#e53e3e");

  return (
    <div>
      <Card title="🖥️ System Overview">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 12 }}>
          {Object.entries(comp).map(([k, v]) => (
            <div key={k} style={{ background: "#2d3748", borderRadius: 8, padding: 14, textAlign: "center" }}>
              <div style={{ color: compColor(v), fontWeight: 700, fontSize: 13 }}>{v}</div>
              <div style={{ color: "#718096", fontSize: 11, marginTop: 4 }}>{k}</div>
            </div>
          ))}
        </div>
        <div style={{ marginTop: 12, color: "#718096", fontSize: 12 }}>
          Uptime: {Math.round((status?.uptime_seconds || 0) / 60)}m &nbsp;|&nbsp;
          Version: {status?.version} &nbsp;|&nbsp;
          <span style={{ color: "#68d391" }}>● ACTIVE</span>
        </div>
      </Card>
      <Card title="🤖 Registered Agents">
        <AgentsList />
      </Card>
      <Card title="📊 Memory">
        <MemoryStats />
      </Card>
    </div>
  );
}

function AgentsList() {
  const [agents, setAgents] = useState([]);
  useEffect(() => {
    api.get("/cyber/agents").then(d => setAgents(d.agents || []));
  }, []);
  return (
    <div>
      {agents.map(a => (
        <div key={a.name} style={{
          display: "flex", justifyContent: "space-between", alignItems: "center",
          padding: "8px 12px", background: "#2d3748", borderRadius: 6, marginBottom: 6,
        }}>
          <span style={{ color: "#e2e8f0", fontWeight: 600 }}>{a.name}</span>
          <span style={{ color: "#718096", fontSize: 12 }}>{a.description}</span>
          <Badge label={`Score: ${(a.score * 100).toFixed(0)}%`} color={a.score > 0.7 ? "#38a169" : "#d69e2e"} />
        </div>
      ))}
    </div>
  );
}

function MemoryStats() {
  const [stats, setStats] = useState(null);
  const load = () => api.get("/admin/memory").then(setStats);
  useEffect(() => { load(); }, []);
  if (!stats) return <span style={{ color: "#718096" }}>Loading…</span>;
  return (
    <div style={{ color: "#e2e8f0", fontSize: 13 }}>
      <span style={{ marginRight: 16 }}>📝 {stats.total_entries} entries</span>
      <span style={{ marginRight: 16 }}>💾 {(stats.size_bytes / 1024).toFixed(1)} KB</span>
      <Btn onClick={load} color="#4299e1">Refresh</Btn>
    </div>
  );
}

// ── Threat Intel Tab ──────────────────────────────────────────
function ThreatIntel() {
  const [target, setTarget] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const analyze = async () => {
    if (!target.trim()) return;
    setLoading(true); setResult(null);
    try {
      const r = await api.post("/cyber/threat-intel/sync", { target });
      setResult(r);
    } finally { setLoading(false); }
  };

  return (
    <div>
      <Card title="🔍 Threat Intelligence Analyzer">
        <p style={{ color: "#a0aec0", fontSize: 13, marginBottom: 12 }}>
          Analyze IPs, domains, URLs, file hashes, or CVE identifiers.
        </p>
        <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
          <div style={{ flex: 1 }}>
            <Input value={target} onChange={setTarget} placeholder="e.g. 192.168.1.1  |  evil.com  |  CVE-2024-1234  |  d41d8cd9..." />
          </div>
          <Btn onClick={analyze} disabled={loading || !target.trim()} color="#e53e3e">
            {loading ? <Spinner /> : "Analyze"}
          </Btn>
        </div>
        {result && <ThreatResult data={result} />}
      </Card>
    </div>
  );
}

function ThreatResult({ data }) {
  const output = data.output || data;
  const level = output.threat_level || "UNKNOWN";
  const color = severityColor(level);
  return (
    <Card color="#2d3748">
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
        <Badge label={level} color={color} />
        {output.is_malicious && <Badge label="⚠ MALICIOUS" color="#e53e3e" />}
        {output.threat_score !== undefined && (
          <Badge label={`Score: ${output.threat_score}/100`} color={color} />
        )}
        <span style={{ color: "#718096", fontSize: 12 }}>{output.indicator_type}</span>
      </div>
      {output.summary && <p style={{ color: "#e2e8f0", fontSize: 13, margin: "8px 0" }}>{output.summary}</p>}
      {output.recommendations?.length > 0 && (
        <div>
          <div style={{ color: "#63b3ed", fontWeight: 600, fontSize: 12, marginBottom: 4 }}>Recommendations</div>
          {output.recommendations.map((r, i) => (
            <div key={i} style={{ color: "#a0aec0", fontSize: 12, marginBottom: 2 }}>• {r}</div>
          ))}
        </div>
      )}
    </Card>
  );
}

// ── Vulnerability Tab ─────────────────────────────────────────
function VulnAnalysis() {
  const [cve, setCve] = useState("");
  const [software, setSoftware] = useState("");
  const [version, setVersion] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const analyze = async () => {
    setLoading(true); setResult(null);
    try {
      const r = await api.post("/cyber/vulnerability/sync", { cve_id: cve, software, version });
      setResult(r);
    } finally { setLoading(false); }
  };

  return (
    <div>
      <Card title="🛡️ Vulnerability Analyzer">
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 8, marginBottom: 12 }}>
          <Input value={cve} onChange={setCve} placeholder="CVE-2024-XXXXX (optional)" />
          <Input value={software} onChange={setSoftware} placeholder="Software (e.g. Apache)" />
          <Input value={version} onChange={setVersion} placeholder="Version (e.g. 2.4.51)" />
        </div>
        <Btn onClick={analyze} disabled={loading || (!cve && !software)} color="#dd6b20">
          {loading ? <Spinner /> : "Analyze Vulnerability"}
        </Btn>
      </Card>
      {result && <VulnResult data={result} />}
    </div>
  );
}

function VulnResult({ data }) {
  const out = data.output || data;
  const sev = out.severity || "UNKNOWN";
  return (
    <Card color="#2d3748">
      <div style={{ display: "flex", gap: 8, marginBottom: 10, flexWrap: "wrap" }}>
        <Badge label={sev} color={severityColor(sev)} />
        {out.cvss_score && <Badge label={`CVSS: ${out.cvss_score}`} color={severityColor(sev)} />}
        {out.exploit_available && <Badge label="Exploit Available" color="#e53e3e" />}
        {out.patch_available && <Badge label="Patch Available" color="#38a169" />}
        <Badge label={`Patch Urgency: ${out.patch_urgency || "N/A"}`} color="#4a5568" />
      </div>
      {out.description && <p style={{ color: "#e2e8f0", fontSize: 13, margin: "8px 0" }}>{out.description}</p>}
      {out.remediation_steps?.length > 0 && (
        <div>
          <div style={{ color: "#68d391", fontWeight: 600, fontSize: 12, marginBottom: 4 }}>Remediation Steps</div>
          {out.remediation_steps.map((s, i) => (
            <div key={i} style={{ color: "#a0aec0", fontSize: 12, marginBottom: 2 }}>{i + 1}. {s}</div>
          ))}
        </div>
      )}
    </Card>
  );
}

// ── Malware Analysis Tab ──────────────────────────────────────
function MalwareAnalysis() {
  const [sample, setSample] = useState("");
  const [behavior, setBehavior] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const analyze = async () => {
    setLoading(true); setResult(null);
    try {
      const r = await api.post("/cyber/malware/sync", { sample, sample_type: "hash", behavior });
      setResult(r);
    } finally { setLoading(false); }
  };

  return (
    <div>
      <Card title="🦠 Malware Analyzer">
        <div style={{ marginBottom: 8 }}>
          <Input value={sample} onChange={setSample} placeholder="MD5 / SHA1 / SHA256 hash or sample identifier" />
        </div>
        <div style={{ marginBottom: 12 }}>
          <Input value={behavior} onChange={setBehavior} placeholder="Observed behavior (optional)" multiline rows={3} />
        </div>
        <Btn onClick={analyze} disabled={loading || !sample.trim()} color="#9f7aea">
          {loading ? <Spinner /> : "Analyze Sample"}
        </Btn>
      </Card>
      {result && <MalwareResult data={result} />}
    </div>
  );
}

function MalwareResult({ data }) {
  const out = data.output || data;
  return (
    <Card color="#2d3748">
      <div style={{ display: "flex", gap: 8, marginBottom: 10, flexWrap: "wrap" }}>
        <Badge label={out.malware_type || "Unknown"} color="#9f7aea" />
        <Badge label={out.malware_family || "Unknown Family"} color="#4a5568" />
        <Badge label={out.threat_level || "UNKNOWN"} color={severityColor(out.threat_level)} />
        {out.is_malicious && <Badge label="⚠ MALICIOUS" color="#e53e3e" />}
        {out.confidence !== undefined && <Badge label={`Confidence: ${out.confidence}%`} color="#4a5568" />}
      </div>
      {out.behaviors?.length > 0 && (
        <div style={{ marginBottom: 8 }}>
          <div style={{ color: "#fc8181", fontWeight: 600, fontSize: 12, marginBottom: 4 }}>Behaviors</div>
          {out.behaviors.map((b, i) => <div key={i} style={{ color: "#a0aec0", fontSize: 12 }}>• {b}</div>)}
        </div>
      )}
      {out.mitre_techniques?.length > 0 && (
        <div>
          <div style={{ color: "#63b3ed", fontWeight: 600, fontSize: 12, marginBottom: 4 }}>MITRE ATT&CK</div>
          {out.mitre_techniques.map((t, i) => <Badge key={i} label={t} color="#2b6cb0" />)}
        </div>
      )}
    </Card>
  );
}

// ── Security Audit Tab ────────────────────────────────────────
function SecurityAudit() {
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState("python");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const audit = async () => {
    setLoading(true); setResult(null);
    try {
      const r = await api.post("/cyber/audit/sync", { code, language, audit_type: "code" });
      setResult(r);
    } finally { setLoading(false); }
  };

  const runSast = async () => {
    setLoading(true); setResult(null);
    try {
      const r = await api.post("/cyber/sast", {});
      setResult(r);
    } finally { setLoading(false); }
  };

  return (
    <div>
      <Card title="🔐 Security Audit">
        <div style={{ display: "flex", gap: 8, marginBottom: 8, alignItems: "center" }}>
          <select value={language} onChange={e => setLanguage(e.target.value)} style={{
            background: "#2d3748", color: "#e2e8f0", border: "1px solid #4a5568",
            borderRadius: 6, padding: "7px 10px", fontSize: 13,
          }}>
            {["python", "javascript", "typescript", "go", "java", "php", "ruby", "bash"].map(l => (
              <option key={l} value={l}>{l}</option>
            ))}
          </select>
          <Btn onClick={runSast} disabled={loading} color="#4a5568">
            {loading ? <Spinner /> : "Run SAST on Project"}
          </Btn>
        </div>
        <div style={{ marginBottom: 12 }}>
          <Input value={code} onChange={setCode} placeholder="Paste code here for AI-powered security audit…" multiline rows={8} />
        </div>
        <Btn onClick={audit} disabled={loading || !code.trim()} color="#38a169">
          {loading ? <Spinner /> : "Audit Code"}
        </Btn>
      </Card>
      {result && <AuditResult data={result} />}
    </div>
  );
}

function AuditResult({ data }) {
  const out = data.output || data;
  const overall = out.overall_status || out.overall_risk || "UNKNOWN";
  const findings = out.findings || [];
  return (
    <Card color="#2d3748">
      <div style={{ display: "flex", gap: 8, marginBottom: 12, alignItems: "center" }}>
        <Badge label={`Overall: ${overall}`} color={severityColor(overall)} />
        <Badge label={`${out.total_findings ?? findings.length} findings`} color="#4a5568" />
        {out.scanned_files && <Badge label={`${out.scanned_files} files scanned`} color="#4a5568" />}
        {out.secure_code_score !== undefined && <Badge label={`Score: ${out.secure_code_score}/100`} color="#38a169" />}
      </div>
      {findings.length > 0 && findings.slice(0, 10).map((f, i) => (
        <div key={i} style={{
          background: "#1a1f2e", borderRadius: 6, padding: 10, marginBottom: 6,
          borderLeft: `3px solid ${severityColor(f.severity)}`,
        }}>
          <div style={{ display: "flex", gap: 6, marginBottom: 4 }}>
            <Badge label={f.severity} color={severityColor(f.severity)} />
            <Badge label={f.category || f.cwe || "misc"} color="#4a5568" />
            {f.line && <span style={{ color: "#718096", fontSize: 11 }}>Line {f.line}</span>}
          </div>
          <div style={{ color: "#e2e8f0", fontSize: 12, marginBottom: 4 }}>{f.description}</div>
          {f.code && <code style={{ color: "#fc8181", fontSize: 11, display: "block" }}>{f.code}</code>}
          {f.remediation && <div style={{ color: "#68d391", fontSize: 11, marginTop: 4 }}>Fix: {f.remediation}</div>}
        </div>
      ))}
    </Card>
  );
}

// ── OSINT Tab ─────────────────────────────────────────────────
function OSINT() {
  const [target, setTarget] = useState("");
  const [targetType, setTargetType] = useState("organization");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const analyze = async () => {
    setLoading(true); setResult(null);
    try {
      const r = await api.post("/cyber/osint/sync", { target, target_type: targetType });
      setResult(r);
    } finally { setLoading(false); }
  };

  return (
    <div>
      <Card title="🌐 OSINT Intelligence">
        <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
          <div style={{ flex: 1 }}>
            <Input value={target} onChange={setTarget} placeholder="Organization name, domain, or person" />
          </div>
          <select value={targetType} onChange={e => setTargetType(e.target.value)} style={{
            background: "#2d3748", color: "#e2e8f0", border: "1px solid #4a5568",
            borderRadius: 6, padding: "7px 10px", fontSize: 13,
          }}>
            <option value="organization">Organization</option>
            <option value="domain">Domain</option>
            <option value="person">Person</option>
            <option value="ip_range">IP Range</option>
          </select>
          <Btn onClick={analyze} disabled={loading || !target.trim()} color="#4299e1">
            {loading ? <Spinner /> : "Gather Intel"}
          </Btn>
        </div>
        {result && <OSINTResult data={result} />}
      </Card>
    </div>
  );
}

function OSINTResult({ data }) {
  const out = data.output || data;
  const surface = out.attack_surface || {};
  return (
    <Card color="#2d3748">
      <div style={{ display: "flex", gap: 8, marginBottom: 10, flexWrap: "wrap" }}>
        {out.risk_score !== undefined && (
          <Badge label={`Risk Score: ${out.risk_score}/100`}
            color={out.risk_score > 70 ? "#e53e3e" : out.risk_score > 40 ? "#d69e2e" : "#38a169"} />
        )}
      </div>
      {out.executive_summary && <p style={{ color: "#e2e8f0", fontSize: 13 }}>{out.executive_summary}</p>}
      {surface.exposed_services?.length > 0 && (
        <div style={{ marginBottom: 8 }}>
          <div style={{ color: "#fc8181", fontWeight: 600, fontSize: 12, marginBottom: 4 }}>Exposed Services</div>
          {surface.exposed_services.map((s, i) => <Badge key={i} label={s} color="#742a2a" />)}
        </div>
      )}
      {out.recommendations?.slice(0, 5).map((r, i) => (
        <div key={i} style={{ color: "#a0aec0", fontSize: 12, marginBottom: 2 }}>• {r}</div>
      ))}
    </Card>
  );
}

// ── AI Generate Tab ───────────────────────────────────────────
function AIGenerate() {
  const [prompt, setPrompt] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const generate = async () => {
    setLoading(true); setResult(null);
    try {
      const r = await api.post("/generate/code/sync", { prompt, tenant_id: "default" });
      setResult(r);
    } finally { setLoading(false); }
  };

  return (
    <div>
      <Card title="⚡ AI Code Generator">
        <div style={{ marginBottom: 12 }}>
          <Input value={prompt} onChange={setPrompt}
            placeholder="Describe what to build… e.g. 'FastAPI endpoint for JWT authentication with SQLAlchemy'"
            multiline rows={4} />
        </div>
        <Btn onClick={generate} disabled={loading || !prompt.trim()} color="#9f7aea">
          {loading ? <Spinner /> : "Generate Code"}
        </Btn>
      </Card>
      {result?.generated_code && (
        <Card title="Generated Code" color="#2d3748">
          <pre style={{
            background: "#1a1f2e", color: "#68d391", padding: 16,
            borderRadius: 6, overflowX: "auto", fontSize: 12, lineHeight: 1.6,
            maxHeight: 500, overflow: "auto",
          }}>{result.generated_code}</pre>
        </Card>
      )}
    </div>
  );
}

// ── Admin Tab ─────────────────────────────────────────────────
function Admin() {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    api.get("/admin/stats").then(setStats);
  }, []);

  return (
    <div>
      <Card title="⚙️ System Administration">
        {stats && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12 }}>
            {[
              ["Tenants", stats.tenants, "#4299e1"],
              ["Tasks Logged", stats.tasks_logged, "#9f7aea"],
              ["Threats Analyzed", stats.threats_analyzed, "#e53e3e"],
              ["Revenue (credits)", stats.total_revenue?.toFixed(2), "#38a169"],
            ].map(([label, val, color]) => (
              <div key={label} style={{ background: "#2d3748", borderRadius: 8, padding: 16, textAlign: "center" }}>
                <div style={{ color, fontSize: 24, fontWeight: 700 }}>{val ?? "—"}</div>
                <div style={{ color: "#718096", fontSize: 12, marginTop: 4 }}>{label}</div>
              </div>
            ))}
          </div>
        )}
      </Card>
      <Card title="🔍 Project SAST Scan">
        <SastRunner />
      </Card>
    </div>
  );
}

function SastRunner() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    try { const r = await api.post("/admin/sast", {}); setResult(r); }
    finally { setLoading(false); }
  };

  return (
    <div>
      <Btn onClick={run} disabled={loading} color="#e53e3e">
        {loading ? <Spinner /> : "Run Full Project SAST"}
      </Btn>
      {result && (
        <div style={{ marginTop: 12 }}>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
            <Badge label={`Status: ${result.overall_status}`} color={severityColor(result.overall_status)} />
            <Badge label={`${result.scanned_files} files`} color="#4a5568" />
            <Badge label={`${result.total_findings} findings`} color="#4a5568" />
            {Object.entries(result.severity_summary || {}).filter(([, v]) => v > 0).map(([k, v]) => (
              <Badge key={k} label={`${k}: ${v}`} color={severityColor(k)} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── App Shell ─────────────────────────────────────────────────
const TABS = [
  { id: "dashboard", label: "🖥️ Dashboard" },
  { id: "threat", label: "🔍 Threat Intel" },
  { id: "vuln", label: "🛡️ Vulnerability" },
  { id: "malware", label: "🦠 Malware" },
  { id: "audit", label: "🔐 Audit" },
  { id: "osint", label: "🌐 OSINT" },
  { id: "generate", label: "⚡ AI Generate" },
  { id: "admin", label: "⚙️ Admin" },
];

export default function App() {
  const [tab, setTab] = useState("dashboard");

  return (
    <div style={{ minHeight: "100vh", background: "#0d1117", color: "#e2e8f0", fontFamily: "system-ui, sans-serif" }}>
      {/* Header */}
      <div style={{ background: "#161b22", borderBottom: "1px solid #2d3748", padding: "12px 24px", display: "flex", alignItems: "center", gap: 16 }}>
        <span style={{ fontSize: 20, fontWeight: 800, color: "#63b3ed", letterSpacing: 1 }}>⚔️ CYBERDUDEBIVASH AI</span>
        <span style={{ color: "#4a5568", fontSize: 13 }}>Autonomous Cybersecurity Intelligence Platform v2.0</span>
      </div>

      {/* Tabs */}
      <div style={{ background: "#161b22", borderBottom: "1px solid #2d3748", padding: "0 24px", display: "flex", gap: 2, overflowX: "auto" }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            background: tab === t.id ? "#1a1f2e" : "transparent",
            color: tab === t.id ? "#63b3ed" : "#718096",
            border: "none", borderBottom: tab === t.id ? "2px solid #63b3ed" : "2px solid transparent",
            padding: "10px 16px", cursor: "pointer", fontWeight: tab === t.id ? 700 : 400,
            fontSize: 13, whiteSpace: "nowrap", transition: "color 0.2s",
          }}>{t.label}</button>
        ))}
      </div>

      {/* Content */}
      <div style={{ maxWidth: 1100, margin: "0 auto", padding: 24 }}>
        {tab === "dashboard" && <Dashboard />}
        {tab === "threat" && <ThreatIntel />}
        {tab === "vuln" && <VulnAnalysis />}
        {tab === "malware" && <MalwareAnalysis />}
        {tab === "audit" && <SecurityAudit />}
        {tab === "osint" && <OSINT />}
        {tab === "generate" && <AIGenerate />}
        {tab === "admin" && <Admin />}
      </div>

      <style>{`
        * { box-sizing: border-box; }
        textarea, input, select { outline: none; }
        textarea:focus, input:focus { border-color: #63b3ed !important; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #1a1f2e; }
        ::-webkit-scrollbar-thumb { background: #4a5568; border-radius: 3px; }
      `}</style>
    </div>
  );
}
