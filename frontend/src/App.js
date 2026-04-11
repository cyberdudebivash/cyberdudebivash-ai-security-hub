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

// ── Payment Checkout Component ────────────────────────────────
const PAYMENT_DETAILS = {
  upi: ["iambivash.bn-5@okaxis", "iambivash.bn-5@okicici", "6302177246@axisbank"],
  bank: { name: "Bivash Kumar Nayak", account: "915010024617260", ifsc: "UTIB0000052", bank: "Axis Bank" },
  paypal: "iambivash.bn@gmail.com",
  crypto: { address: "0xa824c20158a4bfe2f3d8e80351b1906bd0ac0796", networks: ["BNB Smart Chain (BEP20)", "Ethereum (ERC20)"] },
};

const PLANS = [
  { key: "STARTER", label: "Starter", price: "₹499", priceVal: 499, emoji: "⚡", color: "#3b82f6", desc: "10 scans/month · PDF reports · 2 API keys" },
  { key: "PRO",     label: "Pro",     price: "₹1,499", priceVal: 1499, emoji: "🚀", color: "#8b5cf6", desc: "Unlimited scans · Full AI analysis · Priority support", popular: true },
  { key: "ENTERPRISE", label: "Enterprise", price: "₹4,999", priceVal: 4999, emoji: "🏢", color: "#f59e0b", desc: "White-label · Multi-user · Dedicated support" },
];

function CopyBtn({ text }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); });
  };
  return (
    <button onClick={copy} style={{
      background: copied ? "rgba(34,197,94,.15)" : "rgba(99,179,237,.1)",
      border: `1px solid ${copied ? "rgba(34,197,94,.4)" : "rgba(99,179,237,.3)"}`,
      color: copied ? "#86efac" : "#63b3ed",
      padding: "4px 10px", borderRadius: 6, fontSize: 11, fontWeight: 700,
      cursor: "pointer", whiteSpace: "nowrap", transition: "all .2s", flexShrink: 0,
    }}>{copied ? "✅ Copied!" : "Copy"}</button>
  );
}

function FieldRow({ label, value }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, background: "rgba(255,255,255,.04)", border: "1px solid rgba(255,255,255,.08)", borderRadius: 8, padding: "10px 14px", marginBottom: 8 }}>
      <div>
        <div style={{ fontSize: 10, color: "rgba(255,255,255,.4)", textTransform: "uppercase", letterSpacing: ".5px", marginBottom: 2 }}>{label}</div>
        <div style={{ fontFamily: "monospace", fontSize: 13, color: "#e2e8f0", wordBreak: "break-all" }}>{value}</div>
      </div>
      <CopyBtn text={value} />
    </div>
  );
}

function PaymentCheckout({ product, productLabel, amountLabel, onSuccess }) {
  const [activeTab, setActiveTab] = useState("upi");
  const [method, setMethod] = useState("UPI");
  const [txnId, setTxnId] = useState("");
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState(null); // null | {type, msg}
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [recordId, setRecordId] = useState(null);

  const tabStyle = (t) => ({
    flex: 1, background: activeTab === t ? "rgba(99,179,237,.12)" : "rgba(255,255,255,.04)",
    border: `1px solid ${activeTab === t ? "rgba(99,179,237,.5)" : "rgba(255,255,255,.1)"}`,
    color: activeTab === t ? "#63b3ed" : "rgba(255,255,255,.5)",
    padding: "8px 6px", borderRadius: 8, fontSize: 12, fontWeight: 700,
    cursor: "pointer", textAlign: "center", transition: "all .2s",
  });

  const submit = async () => {
    if (!txnId.trim()) { setStatus({ type: "err", msg: "⚠️ Transaction ID is required" }); return; }
    if (!email.trim() || !email.includes("@")) { setStatus({ type: "err", msg: "⚠️ Valid email required" }); return; }
    setLoading(true); setStatus(null);
    const payload = { txnId: txnId.trim(), method, product: product || "unknown", user: email.trim(), amount: amountLabel || "", currency: "INR" };
    let attempt = 0;
    while (attempt < 3) {
      attempt++;
      try {
        const r = await fetch("/api/payment/confirm", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
        const d = await r.json();
        if (r.ok || r.status === 409) {
          setSubmitted(true); setRecordId(d.record_id);
          if (onSuccess) onSuccess({ txnId: txnId.trim(), email: email.trim() });
          setLoading(false); return;
        }
        if (r.status === 422 || r.status === 400) {
          const msg = d?.detail?.[0]?.msg || d?.detail || d?.message || "Validation error";
          setStatus({ type: "err", msg: `⚠️ ${msg}` }); setLoading(false); return;
        }
        throw new Error(d?.message || `Server error ${r.status}`);
      } catch (e) {
        if (attempt >= 3) { setStatus({ type: "err", msg: `⚠️ Failed after 3 attempts. Email: support@cyberdudebivash.com with TXN: ${txnId}` }); setLoading(false); return; }
        await new Promise(res => setTimeout(res, 1200 * attempt));
      }
    }
  };

  if (submitted) return (
    <div style={{ textAlign: "center", padding: "32px 16px" }}>
      <div style={{ fontSize: 52, marginBottom: 14 }}>✅</div>
      <div style={{ fontSize: 20, fontWeight: 900, color: "#22c55e", marginBottom: 8 }}>Payment Submitted!</div>
      <div style={{ fontSize: 13, color: "rgba(255,255,255,.6)", marginBottom: 6 }}>
        TXN ID: <code style={{ background: "rgba(255,255,255,.08)", padding: "2px 8px", borderRadius: 4 }}>{txnId}</code>
      </div>
      {recordId && <div style={{ fontSize: 11, color: "rgba(255,255,255,.35)", marginBottom: 12 }}>Record: {recordId}</div>}
      <div style={{ background: "rgba(34,197,94,.06)", border: "1px solid rgba(34,197,94,.2)", borderRadius: 10, padding: 14, fontSize: 12, color: "rgba(255,255,255,.6)", lineHeight: 1.7, maxWidth: 360, margin: "0 auto 20px" }}>
        Our team will verify within <strong style={{ color: "#fff" }}>2–4 hours</strong> and activate access for <strong style={{ color: "#63b3ed" }}>{email}</strong>.<br />
        📧 Check spam if you don't get confirmation.
      </div>
      <a href="mailto:support@cyberdudebivash.com" style={{ color: "#63b3ed", fontSize: 12 }}>support@cyberdudebivash.com</a>
    </div>
  );

  return (
    <div>
      {(productLabel || amountLabel) && (
        <div style={{ background: "rgba(99,179,237,.06)", border: "1px solid rgba(99,179,237,.15)", borderRadius: 10, padding: "12px 16px", marginBottom: 16, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontWeight: 700, color: "#e2e8f0", fontSize: 14 }}>{productLabel || product}</span>
          {amountLabel && <span style={{ fontSize: 18, fontWeight: 900, color: "#63b3ed" }}>{amountLabel}</span>}
        </div>
      )}
      <div style={{ background: "rgba(245,158,11,.06)", border: "1px solid rgba(245,158,11,.2)", borderRadius: 10, padding: "11px 14px", marginBottom: 16, fontSize: 12, color: "rgba(255,255,255,.7)", lineHeight: 1.65 }}>
        <strong style={{ color: "#f59e0b" }}>How it works:</strong> Choose a payment method → Transfer funds → Click <strong style={{ color: "#22c55e" }}>I HAVE PAID</strong> → Enter Transaction ID. Access activated in 2–4 hrs.
      </div>

      {/* Method Tabs */}
      <div style={{ display: "flex", gap: 8, marginBottom: 18, flexWrap: "wrap" }}>
        {[["upi","📱 UPI"],["bank","🏦 Bank"],["paypal","🌐 PayPal"],["crypto","₿ Crypto"]].map(([t,l]) => (
          <button key={t} style={tabStyle(t)} onClick={() => setActiveTab(t)}>{l}</button>
        ))}
      </div>

      {/* UPI */}
      {activeTab === "upi" && (
        <div>
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
            <div style={{ flex: 1, minWidth: 200 }}>
              {PAYMENT_DETAILS.upi.map((id, i) => (
                <FieldRow key={i} label={i === 0 ? "Axis" : i === 1 ? "ICICI" : "Axis Bank"} value={id} />
              ))}
              <a href="upi://pay?pa=iambivash.bn-5@okaxis&pn=BivashKumarNayak"
                style={{ display: "block", textAlign: "center", background: "rgba(99,179,237,.1)", border: "1px solid rgba(99,179,237,.3)", color: "#63b3ed", padding: 9, borderRadius: 8, fontSize: 12, fontWeight: 700, textDecoration: "none", marginTop: 8 }}>
                📱 Open UPI App →
              </a>
            </div>
            <div style={{ textAlign: "center", flexShrink: 0 }}>
              <div style={{ fontSize: 10, color: "rgba(255,255,255,.4)", marginBottom: 8, textTransform: "uppercase", letterSpacing: ".5px" }}>Scan QR</div>
              <img src="/upi-qr.png" alt="UPI QR" style={{ maxWidth: 140, borderRadius: 10, border: "2px solid rgba(255,255,255,.1)", cursor: "zoom-in" }}
                onError={e => { e.target.style.display = "none"; }} />
              <div style={{ fontSize: 10, color: "rgba(255,255,255,.3)", marginTop: 6 }}>GPay · PhonePe · Paytm</div>
            </div>
          </div>
        </div>
      )}

      {/* Bank */}
      {activeTab === "bank" && (
        <div>
          <FieldRow label="Account Name" value={PAYMENT_DETAILS.bank.name} />
          <FieldRow label="Account Number" value={PAYMENT_DETAILS.bank.account} />
          <FieldRow label="IFSC Code" value={PAYMENT_DETAILS.bank.ifsc} />
          <FieldRow label="Bank" value={PAYMENT_DETAILS.bank.bank} />
          <div style={{ fontSize: 11, color: "rgba(255,255,255,.4)", marginTop: 8, lineHeight: 1.6, padding: "8px 12px", background: "rgba(0,212,255,.04)", borderRadius: 8, border: "1px solid rgba(0,212,255,.1)" }}>
            💡 IMPS = instant 24×7 · NEFT = 2–4 hrs · Add your email in remarks for faster activation.
          </div>
        </div>
      )}

      {/* PayPal */}
      {activeTab === "paypal" && (
        <div>
          <FieldRow label="PayPal Email" value={PAYMENT_DETAILS.paypal} />
          <a href="https://www.paypal.com/paypalme/iambivash" target="_blank" rel="noopener noreferrer"
            style={{ display: "block", textAlign: "center", background: "rgba(0,112,243,.12)", border: "1px solid rgba(0,112,243,.3)", color: "#60a5fa", padding: 10, borderRadius: 8, fontSize: 13, fontWeight: 700, textDecoration: "none", marginTop: 10 }}>
            🌐 Open PayPal.me →
          </a>
          <div style={{ fontSize: 11, color: "rgba(255,255,255,.4)", marginTop: 10, lineHeight: 1.6 }}>
            ⚠️ Select <strong style={{ color: "#e2e8f0" }}>"Friends &amp; Family"</strong> to avoid fees. Add product name + email in the note.
          </div>
        </div>
      )}

      {/* Crypto */}
      {activeTab === "crypto" && (
        <div>
          <FieldRow label="Wallet Address (BNB / ETH)" value={PAYMENT_DETAILS.crypto.address} />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginTop: 10 }}>
            <div style={{ background: "rgba(240,185,11,.07)", border: "1px solid rgba(240,185,11,.2)", borderRadius: 8, padding: 10, textAlign: "center", fontSize: 11, color: "rgba(255,255,255,.6)" }}>
              ✅ BNB Smart Chain<br /><strong style={{ color: "#f0b90b" }}>BEP20</strong>
            </div>
            <div style={{ background: "rgba(98,126,234,.07)", border: "1px solid rgba(98,126,234,.2)", borderRadius: 8, padding: 10, textAlign: "center", fontSize: 11, color: "rgba(255,255,255,.6)" }}>
              ✅ Ethereum<br /><strong style={{ color: "#627eea" }}>ERC20</strong>
            </div>
          </div>
          <div style={{ fontSize: 11, color: "rgba(255,255,255,.4)", marginTop: 10, lineHeight: 1.6, padding: "8px 12px", background: "rgba(239,68,68,.05)", borderRadius: 8, border: "1px solid rgba(239,68,68,.15)" }}>
            ⚠️ Wrong network = lost funds. TX Hash = your Transaction ID after sending.
          </div>
        </div>
      )}

      {/* Confirmation Form */}
      <div style={{ borderTop: "1px solid rgba(255,255,255,.07)", margin: "18px 0 14px" }} />
      <div style={{ fontSize: 12, fontWeight: 800, color: "rgba(255,255,255,.55)", textAlign: "center", letterSpacing: ".5px", marginBottom: 12 }}>↓ AFTER PAYING — SUBMIT YOUR CONFIRMATION ↓</div>
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        <select value={method} onChange={e => setMethod(e.target.value)} style={{ background: "rgba(255,255,255,.06)", border: "1px solid rgba(255,255,255,.12)", borderRadius: 8, padding: "10px 12px", color: "#e2e8f0", fontSize: 13, cursor: "pointer" }}>
          <option value="UPI">📱 UPI Transfer</option>
          <option value="BANK">🏦 Bank Transfer (NEFT/IMPS)</option>
          <option value="PAYPAL">🌐 PayPal</option>
          <option value="CRYPTO_BNB">₿ Crypto — BNB (BEP20)</option>
          <option value="CRYPTO_ETH">₿ Crypto — ETH (ERC20)</option>
        </select>
        <input value={txnId} onChange={e => setTxnId(e.target.value)} placeholder="Transaction ID / UTR / TX Hash *"
          style={{ background: "rgba(255,255,255,.06)", border: "1px solid rgba(255,255,255,.12)", borderRadius: 8, padding: "10px 12px", color: "#e2e8f0", fontSize: 13 }} />
        <input value={email} onChange={e => setEmail(e.target.value)} type="email" placeholder="Your email (for confirmation & access) *"
          style={{ background: "rgba(255,255,255,.06)", border: "1px solid rgba(255,255,255,.12)", borderRadius: 8, padding: "10px 12px", color: "#e2e8f0", fontSize: 13 }} />
      </div>
      {status && <div style={{ marginTop: 10, fontSize: 12, padding: "8px 12px", borderRadius: 6, background: status.type === "err" ? "rgba(239,68,68,.1)" : "rgba(34,197,94,.1)", color: status.type === "err" ? "#fca5a5" : "#86efac", textAlign: "center" }}>{status.msg}</div>}
      <button onClick={submit} disabled={loading} style={{ width: "100%", background: "linear-gradient(135deg,#00d4ff,#0099cc)", border: "none", color: "#000", padding: 14, borderRadius: 10, fontWeight: 900, fontSize: 15, cursor: loading ? "not-allowed" : "pointer", marginTop: 8, opacity: loading ? .7 : 1, fontFamily: "inherit" }}>
        {loading ? "⏳ Submitting..." : "✅ I HAVE PAID — Submit Confirmation"}
      </button>
      <div style={{ textAlign: "center", marginTop: 12, fontSize: 11, color: "rgba(255,255,255,.25)", lineHeight: 1.7 }}>
        🔒 Manual verification · Access in 2–4 hrs · <a href="mailto:support@cyberdudebivash.com" style={{ color: "rgba(99,179,237,.5)" }}>support@cyberdudebivash.com</a>
      </div>
    </div>
  );
}

// ── Billing / Plans Tab ───────────────────────────────────────
function Billing() {
  const [selectedPlan, setSelectedPlan] = useState(null);
  const [checkStatus, setCheckStatus] = useState({});
  const [recordId, setRecordId] = useState("");
  const [statusResult, setStatusResult] = useState(null);

  const checkPaymentStatus = async () => {
    if (!recordId.trim()) return;
    try {
      const r = await fetch(`/api/payment/status/${recordId.trim()}`);
      const d = await r.json();
      setStatusResult(d);
    } catch { setStatusResult({ status: "error", message: "Could not fetch status" }); }
  };

  const statusColor = { pending: "#f59e0b", approved: "#22c55e", rejected: "#ef4444" };

  return (
    <div>
      <Card title="💳 Upgrade Your Plan">
        <p style={{ color: "#718096", fontSize: 13, marginBottom: 20 }}>
          Choose a plan, complete payment via UPI / Bank / PayPal / Crypto, and submit your confirmation. Access activated within 2–4 hours.
        </p>
        {!selectedPlan ? (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16 }}>
            {PLANS.map(p => (
              <div key={p.key} style={{ background: p.popular ? "rgba(139,92,246,.08)" : "rgba(255,255,255,.03)", border: `1px solid ${p.popular ? "rgba(139,92,246,.4)" : "rgba(255,255,255,.1)"}`, borderRadius: 14, padding: 20, position: "relative" }}>
                {p.popular && <div style={{ position: "absolute", top: -10, left: "50%", transform: "translateX(-50%)", background: p.color, color: "#000", fontSize: 9, fontWeight: 900, padding: "3px 12px", borderRadius: 999, whiteSpace: "nowrap" }}>⭐ MOST POPULAR</div>}
                <div style={{ fontSize: 24, marginBottom: 8 }}>{p.emoji}</div>
                <div style={{ fontSize: 11, fontWeight: 800, color: p.color, textTransform: "uppercase", letterSpacing: ".08em", marginBottom: 4 }}>{p.label}</div>
                <div style={{ fontSize: 26, fontWeight: 900, color: "#fff", marginBottom: 2 }}>{p.price}</div>
                <div style={{ fontSize: 11, color: "#718096", marginBottom: 14 }}>/month</div>
                <div style={{ fontSize: 12, color: "rgba(255,255,255,.55)", marginBottom: 18, lineHeight: 1.5 }}>{p.desc}</div>
                <button onClick={() => setSelectedPlan(p)} style={{ width: "100%", background: `linear-gradient(135deg,${p.color},${p.color}cc)`, border: "none", color: "#fff", padding: "10px 0", borderRadius: 8, fontWeight: 800, cursor: "pointer", fontSize: 13 }}>
                  {p.emoji} Get {p.label}
                </button>
              </div>
            ))}
          </div>
        ) : (
          <div>
            <button onClick={() => setSelectedPlan(null)} style={{ background: "rgba(255,255,255,.06)", border: "1px solid rgba(255,255,255,.1)", color: "#718096", padding: "6px 14px", borderRadius: 6, cursor: "pointer", fontSize: 12, marginBottom: 16 }}>← Back to Plans</button>
            <PaymentCheckout product={`subscription-${selectedPlan.key}`} productLabel={`${selectedPlan.emoji} ${selectedPlan.label} Plan`} amountLabel={`${selectedPlan.price}/month`} onSuccess={() => {}} />
          </div>
        )}
      </Card>

      <Card title="📋 All Payment Methods">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12 }}>
          {[
            { icon: "📱", label: "UPI", detail: "iambivash.bn-5@okaxis", sub: "Instant · Any UPI App" },
            { icon: "🏦", label: "Bank Transfer", detail: "A/C: 915010024617260", sub: "IFSC: UTIB0000052 · Axis Bank" },
            { icon: "🌐", label: "PayPal", detail: "iambivash.bn@gmail.com", sub: "International · Friends & Family" },
            { icon: "₿", label: "Crypto", detail: "BNB / ETH", sub: "0xa824c...796 · BEP20/ERC20" },
          ].map((m, i) => (
            <div key={i} style={{ background: "rgba(255,255,255,.03)", border: "1px solid rgba(255,255,255,.07)", borderRadius: 10, padding: 14 }}>
              <div style={{ fontSize: 20, marginBottom: 6 }}>{m.icon}</div>
              <div style={{ fontWeight: 700, color: "#e2e8f0", fontSize: 13, marginBottom: 3 }}>{m.label}</div>
              <div style={{ fontFamily: "monospace", fontSize: 11, color: "#63b3ed", marginBottom: 3 }}>{m.detail}</div>
              <div style={{ fontSize: 10, color: "#718096" }}>{m.sub}</div>
            </div>
          ))}
        </div>
      </Card>

      <Card title="🔍 Check Payment Status">
        <div style={{ display: "flex", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
          <input value={recordId} onChange={e => setRecordId(e.target.value)} placeholder="Enter your Record ID"
            style={{ flex: 1, background: "#2d3748", border: "1px solid #4a5568", borderRadius: 6, padding: "8px 12px", color: "#e2e8f0", fontSize: 13 }} />
          <button onClick={checkPaymentStatus} style={{ background: "#4299e1", border: "none", color: "#fff", padding: "8px 18px", borderRadius: 6, cursor: "pointer", fontWeight: 600, fontSize: 13 }}>Check</button>
        </div>
        {statusResult && (
          <div style={{ background: "rgba(255,255,255,.03)", border: "1px solid rgba(255,255,255,.08)", borderRadius: 8, padding: 14 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
              <span style={{ fontSize: 10, fontWeight: 800, textTransform: "uppercase", background: statusColor[statusResult.status] || "#4a5568", color: "#000", padding: "2px 8px", borderRadius: 4 }}>{statusResult.status}</span>
              <span style={{ fontSize: 12, color: "#a0aec0" }}>{statusResult.product}</span>
            </div>
            <div style={{ fontSize: 12, color: "rgba(255,255,255,.6)", lineHeight: 1.6 }}>{statusResult.message}</div>
          </div>
        )}
      </Card>

      <Card title="🛡️ Enterprise & Custom Plans">
        <p style={{ color: "#718096", fontSize: 13, marginBottom: 16 }}>Need white-label, MSSP, or a custom enterprise plan? Contact us directly.</p>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <a href="mailto:enterprise@cyberdudebivash.com" style={{ background: "rgba(245,158,11,.12)", border: "1px solid rgba(245,158,11,.3)", color: "#f59e0b", padding: "10px 20px", borderRadius: 8, fontWeight: 700, fontSize: 13, textDecoration: "none" }}>📧 Enterprise Inquiry</a>
          <button onClick={() => setSelectedPlan(PLANS[2])} style={{ background: "rgba(245,158,11,.08)", border: "1px solid rgba(245,158,11,.2)", color: "#f59e0b", padding: "10px 20px", borderRadius: 8, fontWeight: 700, fontSize: 13, cursor: "pointer" }}>🏢 Enterprise Plan ₹4,999/mo</button>
        </div>
      </Card>
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
  { id: "billing", label: "💳 Billing" },
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
        {tab === "billing" && <Billing />}
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
