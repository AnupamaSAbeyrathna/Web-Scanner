import { useState, useEffect, useRef } from "react";
import "./App.css";

const API = "http://localhost:3000";

const SEVERITY_RANK = { HIGH: 0, MEDIUM: 1, LOW: 2 };

const severityColor = (s) => {
  if (s === "HIGH") return "sev-high";
  if (s === "MEDIUM") return "sev-medium";
  return "sev-low";
};

const vulnIcon = (v) => {
  if (v === "MissingHeader") return "🛡️";
  if (v === "DirectoryEnumeration") return "📂";
  if (v === "ConnectionError") return "🔌";
  return "⚠️";
};

export default function App() {
  const [target, setTarget] = useState("");
  const [scans, setScans] = useState([]);
  const [activeScan, setActiveScan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const pollRef = useRef(null);

  const startScan = async () => {
    if (!target.trim()) { setError("Please enter a target URL."); return; }
    setError("");
    setLoading(true);
    try {
      const res = await fetch(`${API}/scan/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim() }),
      });
      const data = await res.json();
      const newScan = { id: data.id, target: target.trim(), status: "Running", findings: [] };
      setScans((prev) => [newScan, ...prev]);
      setActiveScan(newScan);
      pollStatus(data.id);
    } catch (e) {
      setError("Could not reach the scanner API. Is the server running?");
    }
    setLoading(false);
  };

  const pollStatus = (id) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${API}/scan/${id}`);
        const data = await res.json();
        setScans((prev) => prev.map((s) => (s.id === id ? data : s)));
        setActiveScan((prev) => (prev?.id === id ? data : prev));
        if (data.status === "Done") clearInterval(pollRef.current);
      } catch {}
    }, 1500);
  };

  const selectScan = (scan) => {
    setActiveScan(scan);
    if (scan.status === "Running") pollStatus(scan.id);
  };

  const sortedFindings = (findings) =>
    [...findings].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9));

  const countBySev = (findings, sev) => findings.filter((f) => f.severity === sev).length;

  return (
    <div className="app">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="logo">
            <span className="logo-icon">🔍</span>
            <div>
              <div className="logo-title">WebScan</div>
              <div className="logo-sub">Vulnerability Scanner</div>
            </div>
          </div>
        </div>

        <div className="scan-form">
          <label className="form-label">Target URL</label>
          <input
            className="url-input"
            type="text"
            placeholder="https://example.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && startScan()}
          />
          {error && <div className="form-error">{error}</div>}
          <button className="scan-btn" onClick={startScan} disabled={loading}>
            {loading ? <span className="spinner" /> : "▶ Start Scan"}
          </button>
        </div>

        <div className="scan-history">
          <div className="history-title">Scan History</div>
          {scans.length === 0 && <div className="history-empty">No scans yet</div>}
          {scans.map((scan) => (
            <div
              key={scan.id}
              className={`history-item ${activeScan?.id === scan.id ? "active" : ""}`}
              onClick={() => selectScan(scan)}
            >
              <div className="history-target">{new URL(scan.target).hostname}</div>
              <div className={`history-status ${scan.status === "Done" ? "status-done" : "status-running"}`}>
                {scan.status === "Running" ? "⏳ Running" : `✅ Done · ${scan.findings.length} findings`}
              </div>
            </div>
          ))}
        </div>
      </aside>

      {/* Main Panel */}
      <main className="main">
        {!activeScan ? (
          <div className="empty-state">
            <div className="empty-icon">🛡️</div>
            <h2>Ready to Scan</h2>
            <p>Enter a target URL on the left and click <strong>Start Scan</strong> to begin discovering vulnerabilities.</p>
          </div>
        ) : (
          <>
            {/* Header */}
            <div className="scan-header">
              <div>
                <div className="scan-target">{activeScan.target}</div>
                <div className="scan-id">ID: {activeScan.id}</div>
              </div>
              <div className={`badge ${activeScan.status === "Done" ? "badge-done" : "badge-running"}`}>
                {activeScan.status === "Running" ? (
                  <><span className="pulse" />Scanning…</>
                ) : "✅ Complete"}
              </div>
            </div>

            {/* Stats */}
            {activeScan.status === "Done" && (
              <div className="stats-row">
                <div className="stat-card stat-total">
                  <div className="stat-num">{activeScan.findings.length}</div>
                  <div className="stat-label">Total Findings</div>
                </div>
                <div className="stat-card stat-high">
                  <div className="stat-num">{countBySev(activeScan.findings, "HIGH")}</div>
                  <div className="stat-label">High</div>
                </div>
                <div className="stat-card stat-medium">
                  <div className="stat-num">{countBySev(activeScan.findings, "MEDIUM")}</div>
                  <div className="stat-label">Medium</div>
                </div>
                <div className="stat-card stat-low">
                  <div className="stat-num">{countBySev(activeScan.findings, "LOW")}</div>
                  <div className="stat-label">Low</div>
                </div>
              </div>
            )}

            {/* Findings */}
            <div className="findings-section">
              <div className="findings-title">Findings</div>
              {activeScan.status === "Running" && activeScan.findings.length === 0 && (
                <div className="scan-progress">
                  <div className="progress-bar"><div className="progress-fill" /></div>
                  <div className="progress-label">Scanner is running…</div>
                </div>
              )}
              {activeScan.findings.length === 0 && activeScan.status === "Done" && (
                <div className="no-findings">🎉 No vulnerabilities found!</div>
              )}
              <div className="findings-list">
                {sortedFindings(activeScan.findings).map((f, i) => (
                  <div key={i} className={`finding-card ${severityColor(f.severity)}`}>
                    <div className="finding-top">
                      <span className="finding-icon">{vulnIcon(f.vulnerability)}</span>
                      <span className="finding-vuln">{f.vulnerability}</span>
                      <span className={`finding-badge ${severityColor(f.severity)}-badge`}>{f.severity}</span>
                    </div>
                    <div className="finding-url">{f.url}</div>
                    <div className="finding-evidence">{f.evidence}</div>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
