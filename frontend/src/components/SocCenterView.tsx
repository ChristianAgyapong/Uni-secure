import React, { useState, useEffect } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Lock,
  Unlock,
  AlertTriangle,
  Server,
  Activity,
  Terminal,
  CheckCircle2,
  RefreshCw,
  Search,
  FileCode,
  Radio,
  Eye,
} from "lucide-react";
import {
  API,
  OverviewData,
  BuildingData,
  ThreatCenterData,
  LogsData,
  LogEntry,
} from "../api/client";

export const SocCenterView: React.FC = () => {
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [threats, setThreats] = useState<ThreatCenterData | null>(null);
  const [logsData, setLogsData] = useState<LogsData | null>(null);
  const [loading, setLoading] = useState(false);
  const [lockdownActive, setLockdownActive] = useState(false);
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  const [logFilter, setLogFilter] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  useEffect(() => {
    fetchAllSocData();
  }, []);

  const fetchAllSocData = async () => {
    setLoading(true);
    try {
      const [ov, th, lg, hl] = await Promise.all([
        API.socOverview().catch(() => null),
        API.socThreats().catch(() => null),
        API.socLogs().catch(() => null),
        API.health().catch(() => ({ lockdown_active: false })),
      ]);
      if (ov) setOverview(ov);
      if (th) setThreats(th);
      if (lg) {
        setLogsData(lg);
        if (lg.logs.length > 0) setSelectedLog(lg.logs[0]);
      }
      setLockdownActive(hl.lockdown_active);
    } finally {
      setLoading(false);
    }
  };

  const handleToggleLockdown = async () => {
    try {
      const res = await API.toggleLockdown();
      setLockdownActive(res.lockdown_active);
    } catch (e) {
      console.error(e);
    }
  };

  const handleThreatAction = async (eventId: string, action: "confirm" | "dismiss" | "isolate") => {
    try {
      await API.threatAction(eventId, action);
      // Refresh threats
      const th = await API.socThreats();
      setThreats(th);
    } catch (e) {
      console.error(e);
    }
  };

  const handleIsolateNode = async (nodeId: string, currentIsolated: boolean) => {
    try {
      await API.isolateNode(nodeId, !currentIsolated);
      // Refresh overview
      const ov = await API.socOverview();
      setOverview(ov);
    } catch (e) {
      console.error(e);
    }
  };

  const filteredLogs = (logsData?.logs ?? []).filter((l) => {
    const matchesLevel = logFilter === "ALL" || l.level.toUpperCase() === logFilter;
    const matchesSearch =
      !searchQuery ||
      l.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      l.source.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (l.metadata?.host && l.metadata.host.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesLevel && matchesSearch;
  });

  return (
    <div className="soc-content">
      {/* ── TOP SOC COMMAND BAR ── */}
      <div className="panel" style={{ padding: "16px 20px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 14 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 10, fontWeight: 800, color: "var(--accent-red)", textTransform: "uppercase", letterSpacing: 0.8 }}>
                Security Operations Center (SOC)
              </span>
              <span style={{
                fontSize: 9, fontWeight: 700, padding: "2px 7px", borderRadius: 3,
                background: "rgba(239,68,68,0.15)", color: "#ef4444", border: "1px solid rgba(239,68,68,0.3)"
              }}>
                Live Campus Telemetry
              </span>
            </div>
            <h1 className="building-title" style={{ fontSize: 22, marginTop: 4 }}>
              UniSecure Threat Operations & Live Incident Response
            </h1>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {/* Lockdown Button */}
            <button
              onClick={handleToggleLockdown}
              style={{
                display: "flex", alignItems: "center", gap: 6,
                padding: "8px 16px", borderRadius: 6, cursor: "pointer",
                background: lockdownActive ? "#ef4444" : "rgba(255,255,255,0.04)",
                border: `1px solid ${lockdownActive ? "#ef4444" : "var(--border)"}`,
                color: lockdownActive ? "#fff" : "var(--text-main)",
                fontWeight: 700, fontSize: 12,
                boxShadow: lockdownActive ? "0 0 20px rgba(239,68,68,0.6)" : "none",
                transition: "all 0.2s",
              }}
            >
              {lockdownActive ? <Unlock size={14} /> : <Lock size={14} />}
              <span>{lockdownActive ? "LOCKDOWN ACTIVE (DISENGAGE)" : "ENGAGE LOCKDOWN"}</span>
            </button>

            <button onClick={fetchAllSocData} disabled={loading} className="btn-secondary-soc" style={{ padding: "8px 14px", fontSize: 12 }}>
              <RefreshCw size={13} style={{ animation: loading ? "spin 1s linear infinite" : "none" }} />
              <span>Refresh SOC</span>
            </button>
          </div>
        </div>

        {/* Lockdown Banner Warning */}
        {lockdownActive && (
          <div style={{
            marginTop: 14, background: "rgba(239,68,68,0.15)", border: "1px solid #ef4444",
            borderRadius: 6, padding: "10px 14px", display: "flex", alignItems: "center", gap: 10,
            animation: "pulse 1.5s infinite",
          }}>
            <ShieldAlert size={18} color="#ef4444" />
            <div style={{ fontSize: 12, color: "#fff", fontWeight: 700 }}>
              EMERGENCY NETWORK LOCKDOWN ENGAGED — External gateway border routes restricted to quarantine subnets.
            </div>
          </div>
        )}
      </div>

      {/* ── KPI METRIC CARDS ── */}
      {overview?.kpis && (
        <div className="kpi-row">
          <div className="kpi-card">
            <div className="kpi-header">
              <span>Active Campus Threats</span>
              <ShieldAlert size={18} color="#ef4444" />
            </div>
            <div className="kpi-value-row">
              <span className="kpi-number" style={{ color: "#ef4444" }}>{overview.kpis.total_active_threats}</span>
              <span className="kpi-status-opt" style={{ color: "#ef4444" }}>{overview.kpis.threats_delta}</span>
            </div>
            <div className="kpi-line-threat" />
          </div>

          <div className="kpi-card">
            <div className="kpi-header">
              <span>Model Confidence Avg</span>
              <Activity size={18} color="#38bdf8" />
            </div>
            <div className="kpi-value-row">
              <span className="kpi-number" style={{ color: "#38bdf8" }}>{overview.kpis.model_confidence_avg}%</span>
              <span className="kpi-status-opt">{overview.kpis.confidence_status}</span>
            </div>
            <div className="kpi-line-conf" />
          </div>

          <div className="kpi-card">
            <div className="kpi-header">
              <span>Aggregated Campus Bandwidth</span>
              <Radio size={18} color="#10b981" />
            </div>
            <div className="kpi-value-row">
              <span className="kpi-number" style={{ color: "#10b981" }}>{overview.kpis.network_throughput}</span>
              <span className="kpi-status-opt">{overview.kpis.throughput_status}</span>
            </div>
            <div className="kpi-line-thru" />
          </div>
        </div>
      )}

      {/* ── TWO-COLUMN: CAMPUS NODE TAPS & FLAGGED INCIDENTS ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 16 }}>

        {/* LEFT: Campus Network Node Taps */}
        <div className="panel" style={{ padding: 18 }}>
          <div className="panel-title" style={{ marginBottom: 12 }}>
            <Server size={15} color="var(--accent-cyan)" />
            <span>Monitored Campus Network Nodes & Sensors</span>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {(overview?.campus_nodes ?? []).map((node) => {
              return (
                <div
                  key={node.id}
                  style={{
                    background: node.is_alert ? "rgba(239,68,68,0.06)" : "rgba(255,255,255,0.02)",
                    border: `1px solid ${node.is_alert ? "rgba(239,68,68,0.3)" : "var(--border)"}`,
                    borderRadius: 6, padding: "10px 14px",
                    display: "flex", alignItems: "center", justifyContent: "space-between",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <div style={{
                      width: 10, height: 10, borderRadius: "50%",
                      background: node.is_alert ? "#ef4444" : "#10b981",
                      boxShadow: node.is_alert ? "0 0 8px #ef4444" : "none",
                    }} />
                    <div>
                      <div style={{ fontSize: 12, fontWeight: 700, color: "#fff" }}>{node.name}</div>
                      <div style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
                        IP: {node.ip} · Last Active: {node.last_active}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span style={{
                      fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 3,
                      background: node.is_alert ? "rgba(239,68,68,0.2)" : "rgba(16,185,129,0.2)",
                      color: node.is_alert ? "#ef4444" : "#10b981",
                    }}>
                      {node.status}
                    </span>

                    <button
                      onClick={() => handleIsolateNode(node.id, false)}
                      style={{
                        fontSize: 10, fontWeight: 700, padding: "4px 8px", borderRadius: 4, cursor: "pointer",
                        background: "rgba(255,255,255,0.05)", border: "1px solid var(--border)",
                        color: "var(--text-muted)",
                      }}
                    >
                      Quarantine
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* RIGHT: Flagged Threat Events & Response */}
        <div className="panel" style={{ padding: 18 }}>
          <div className="panel-title" style={{ marginBottom: 12 }}>
            <ShieldAlert size={15} color="var(--accent-red)" />
            <span>Active Incident Response Trail</span>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {(threats?.flagged_events ?? []).map((ev) => (
              <div
                key={ev.id}
                style={{
                  background: "rgba(255,255,255,0.02)", border: `1px solid ${ev.color}44`,
                  borderLeft: `3px solid ${ev.color}`, borderRadius: 6, padding: "10px 12px",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: "#fff" }}>{ev.title}</div>
                    <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 2 }}>
                      Event: {ev.id} · Timestamp: {ev.timestamp}
                    </div>
                  </div>
                  <span style={{
                    fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 3,
                    background: `${ev.color}26`, color: ev.color,
                  }}>
                    {ev.severity}
                  </span>
                </div>

                {/* Entropy */}
                <div style={{ marginTop: 8, fontSize: 10, color: "var(--text-muted)" }}>
                  Detected Entropy: <strong style={{ color: "var(--accent-purple)" }}>{ev.detected_entropy} bits</strong> (Baseline: {ev.baseline_entropy} bits)
                </div>

                {/* Actions */}
                <div style={{ display: "flex", gap: 6, marginTop: 10 }}>
                  <button
                    onClick={() => handleThreatAction(ev.id, "confirm")}
                    style={{
                      flex: 1, padding: "4px 0", borderRadius: 4, cursor: "pointer",
                      fontSize: 10, fontWeight: 700, border: "1px solid #10b98166",
                      background: "rgba(16,185,129,0.15)", color: "#10b981",
                    }}
                  >
                    Confirm Threat
                  </button>
                  <button
                    onClick={() => handleThreatAction(ev.id, "dismiss")}
                    style={{
                      flex: 1, padding: "4px 0", borderRadius: 4, cursor: "pointer",
                      fontSize: 10, fontWeight: 700, border: "1px solid var(--border)",
                      background: "rgba(255,255,255,0.03)", color: "var(--text-muted)",
                    }}
                  >
                    Dismiss False Pos
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── SECURITY AUDIT TELEMETRY LOGS & RAW PACKET PAYLOADS ── */}
      <div className="panel" style={{ padding: 18 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, flexWrap: "wrap", gap: 10 }}>
          <div className="panel-title">
            <Terminal size={15} color="var(--accent-cyan)" />
            <span>Campus Security Telemetry Logs & Raw Payloads</span>
          </div>

          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {/* Search Input */}
            <div style={{ position: "relative" }}>
              <input
                type="text"
                placeholder="Search logs, IPs, hosts…"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="logs-filter-select"
                style={{ width: 180, paddingLeft: 24, fontSize: 11 }}
              />
              <Search size={11} color="var(--text-dim)" style={{ position: "absolute", left: 8, top: "50%", transform: "translateY(-50%)" }} />
            </div>

            {/* Filter Pills */}
            <div style={{ display: "flex", gap: 4 }}>
              {["ALL", "CRITICAL", "ALERT", "DEBUG", "INFO"].map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => setLogFilter(lvl)}
                  style={{
                    fontSize: 10, fontWeight: 700, padding: "3px 8px", borderRadius: 4, cursor: "pointer",
                    border: "1px solid",
                    background: logFilter === lvl ? "var(--accent-cyan)" : "transparent",
                    color: logFilter === lvl ? "#000" : "var(--text-dim)",
                    borderColor: logFilter === lvl ? "var(--accent-cyan)" : "var(--border)",
                  }}
                >
                  {lvl}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Logs Table and Payload Inspector Split */}
        <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: 14 }}>
          {/* Logs Table */}
          <div style={{ maxHeight: 280, overflowY: "auto", border: "1px solid var(--border)", borderRadius: 6 }}>
            <table className="sensor-table" style={{ fontSize: 11 }}>
              <thead>
                <tr>
                  <th>TIME</th>
                  <th>LEVEL</th>
                  <th>SOURCE</th>
                  <th>DESCRIPTION</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.map((log) => {
                  const isSel = selectedLog?.id === log.id;
                  return (
                    <tr
                      key={log.id}
                      onClick={() => setSelectedLog(log)}
                      style={{
                        cursor: "pointer",
                        background: isSel ? "rgba(14,165,233,0.12)" : "transparent",
                        borderLeft: isSel ? "2px solid var(--accent-cyan)" : "2px solid transparent",
                      }}
                    >
                      <td style={{ fontFamily: "var(--font-mono)", color: "var(--text-dim)" }}>
                        {log.timestamp.slice(11, 19)}
                      </td>
                      <td>
                        <span style={{
                          fontSize: 9, fontWeight: 700, padding: "1px 5px", borderRadius: 3,
                          background: `${log.level_color}22`, color: log.level_color,
                        }}>
                          {log.level}
                        </span>
                      </td>
                      <td style={{ color: "#fff", fontWeight: 600 }}>{log.source}</td>
                      <td style={{ color: "var(--text-muted)", maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {log.description}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Raw Payload Inspector */}
          <div style={{ background: "#050914", border: "1px solid var(--border)", borderRadius: 6, padding: 12, display: "flex", flexDirection: "column" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, fontWeight: 700, color: "var(--accent-cyan)" }}>
                <FileCode size={13} />
                <span>Raw Log Payload ({selectedLog?.id ?? "none"})</span>
              </div>
              <span style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
                Host: {selectedLog?.metadata?.host ?? "—"}
              </span>
            </div>

            <pre style={{
              flex: 1, maxHeight: 220, overflowY: "auto", margin: 0,
              fontSize: 10, fontFamily: "var(--font-mono)", color: "#38bdf8",
              lineHeight: 1.5, background: "rgba(0,0,0,0.4)", padding: 10, borderRadius: 4,
            }}>
              {selectedLog ? JSON.stringify(selectedLog, null, 2) : "// Click any log entry to inspect payload"}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
