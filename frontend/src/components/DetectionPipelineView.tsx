import React, { useState, useEffect, useRef } from "react";
import {
  Play,
  Upload,
  Activity,
  Shield,
  ShieldAlert,
  ShieldX,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Zap,
  Target,
  Eye,
  RefreshCw,
  ChevronRight,
  BarChart3,
  Clock,
  Layers,
  FileWarning,
  Cpu,
  TrendingUp,
  Download,
  ShieldCheck,
  Lock,
} from "lucide-react";
import { API, AnalysisResult, WindowResult } from "../api/client";

/* ─── Threat Level helpers ─────────────────────────────────────────────────── */
function getThreatMeta(level: string) {
  switch (level) {
    case "CRITICAL":
      return { color: "#ef4444", glow: "rgba(239,68,68,0.25)", icon: ShieldX,   bg: "rgba(239,68,68,0.12)",   border: "rgba(239,68,68,0.4)" };
    case "HIGH":
      return { color: "#f97316", glow: "rgba(249,115,22,0.25)", icon: ShieldAlert, bg: "rgba(249,115,22,0.12)", border: "rgba(249,115,22,0.4)" };
    case "MEDIUM":
      return { color: "#f59e0b", glow: "rgba(245,158,11,0.25)", icon: AlertTriangle, bg: "rgba(245,158,11,0.12)", border: "rgba(245,158,11,0.4)" };
    default:
      return { color: "#10b981", glow: "rgba(16,185,129,0.25)", icon: Shield,    bg: "rgba(16,185,129,0.12)",  border: "rgba(16,185,129,0.4)" };
  }
}

/* ─── Animated pulsing dot ─────────────────────────────────────────────────── */
const PulseDot: React.FC<{ color: string }> = ({ color }) => (
  <span style={{ position: "relative", display: "inline-flex", width: 10, height: 10 }}>
    <span style={{
      position: "absolute", inset: 0, borderRadius: "50%",
      background: color, opacity: 0.6,
      animation: "ping 1.4s cubic-bezier(0, 0, 0.2, 1) infinite",
    }} />
    <span style={{ width: 10, height: 10, borderRadius: "50%", background: color, display: "inline-block" }} />
  </span>
);

/* ─── KPI Stat card ────────────────────────────────────────────────────────── */
const KpiCard: React.FC<{ label: string; value: string | number; sub?: string; color?: string; icon: React.ReactNode; pulse?: boolean }> =
  ({ label, value, sub, color = "#38bdf8", icon, pulse = false }) => (
    <div style={{
      flex: 1, minWidth: 140,
      background: "linear-gradient(135deg, rgba(12,23,44,0.9), rgba(8,16,32,0.95))",
      border: `1px solid ${color}33`,
      borderRadius: 10, padding: "14px 16px",
      position: "relative", overflow: "hidden",
    }}>
      <div style={{
        position: "absolute", inset: 0,
        background: `radial-gradient(circle at 100% 0%, ${color}0d 0%, transparent 60%)`,
      }} />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", position: "relative" }}>
        <div>
          <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 0.8 }}>
            {label}
          </div>
          <div style={{ fontSize: 26, fontWeight: 800, color, fontFamily: "var(--font-mono)", marginTop: 4, lineHeight: 1 }}>
            {value}
          </div>
          {sub && <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>{sub}</div>}
        </div>
        <div style={{
          width: 36, height: 36, borderRadius: 8,
          background: `${color}1a`, border: `1px solid ${color}33`,
          display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          {icon}
        </div>
      </div>
      {pulse && (
        <div style={{ position: "absolute", top: 8, right: 8 }}>
          <PulseDot color={color} />
        </div>
      )}
    </div>
  );

/* ─── Threat distribution bar ──────────────────────────────────────────────── */
const ThreatBar: React.FC<{ label: string; count: number; total: number; color: string; level: string }> =
  ({ label, count, total, color, level }) => {
    const pct = total > 0 ? (count / total) * 100 : 0;
    return (
      <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
        <div style={{ width: 6, height: 6, borderRadius: "50%", background: color, flexShrink: 0 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
            <span style={{ fontSize: 11, color: "#fff", fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {label}
            </span>
            <span style={{ fontSize: 11, fontFamily: "var(--font-mono)", color, flexShrink: 0, marginLeft: 8 }}>
              {count} ({pct.toFixed(0)}%)
            </span>
          </div>
          <div style={{ height: 3, background: "rgba(255,255,255,0.06)", borderRadius: 999 }}>
            <div style={{
              height: "100%", width: `${pct}%`, borderRadius: 999,
              background: `linear-gradient(90deg, ${color}aa, ${color})`,
              transition: "width 0.6s cubic-bezier(0.4,0,0.2,1)",
            }} />
          </div>
        </div>
        <span style={{
          fontSize: 9, fontWeight: 700, letterSpacing: 0.6,
          padding: "2px 6px", borderRadius: 3,
          background: `${color}22`, color, border: `1px solid ${color}44`,
          flexShrink: 0,
        }}>
          {level}
        </span>
      </div>
    );
  };

/* ─── Window row ───────────────────────────────────────────────────────────── */
const WindowRow: React.FC<{ w: WindowResult; isSelected: boolean; onClick: () => void; idx: number }> =
  ({ w, isSelected, onClick, idx }) => {
    const meta = getThreatMeta(w.threat_level);
    const isAttack = !w.prediction.toUpperCase().startsWith("BENIGN");
    return (
      <tr
        onClick={onClick}
        style={{
          cursor: "pointer",
          background: isSelected ? "rgba(14,165,233,0.1)" : idx % 2 === 0 ? "rgba(255,255,255,0.015)" : "transparent",
          transition: "background 0.15s",
          borderLeft: isSelected ? `2px solid var(--accent-cyan)` : "2px solid transparent",
        }}
      >
        <td style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-dim)", padding: "7px 10px" }}>
          #{w.window + 1}
        </td>
        <td style={{ padding: "7px 8px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            {isAttack
              ? <ShieldX size={12} color={meta.color} />
              : <CheckCircle2 size={12} color="#10b981" />}
            <span style={{ fontSize: 11, color: "#fff", fontWeight: isAttack ? 700 : 400 }}>
              {w.prediction}
            </span>
          </div>
        </td>
        <td style={{ padding: "7px 8px" }}>
          <span style={{
            fontSize: 9, fontWeight: 700, letterSpacing: 0.6,
            padding: "2px 7px", borderRadius: 3,
            background: meta.bg, color: meta.color, border: `1px solid ${meta.border}`,
          }}>
            {w.threat_level}
          </span>
        </td>
        <td style={{ padding: "7px 8px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 44, height: 3, background: "rgba(255,255,255,0.08)", borderRadius: 999 }}>
              <div style={{ height: "100%", width: `${w.confidence * 100}%`, background: meta.color, borderRadius: 999 }} />
            </div>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: meta.color }}>
              {(w.confidence * 100).toFixed(0)}%
            </span>
          </div>
        </td>
        <td style={{ padding: "7px 8px", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-dim)" }}>
          {w.ground_truth ? (
            <span style={{ color: w.correct ? "#10b981" : "#ef4444" }}>
              {w.correct ? "✓" : "✗"} {w.ground_truth}
            </span>
          ) : "—"}
        </td>
      </tr>
    );
  };

/* ─── Main component ───────────────────────────────────────────────────────── */
export const DetectionPipelineView: React.FC = () => {
  const [inputMode, setInputMode] = useState<"preset" | "stream" | "upload">("preset");
  const [selectedPreset, setSelectedPreset] = useState("DDoS Attack Sample");
  const [streamAttack, setStreamAttack] = useState("DDoS Attack");
  const [streamFlows, setStreamFlows] = useState(70);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [selectedWindow, setSelectedWindow] = useState<WindowResult | null>(null);
  const [filterLevel, setFilterLevel] = useState<string>("ALL");
  const [scanLine, setScanLine] = useState(0);
  const [quarantined, setQuarantined] = useState(false);

  const scanRef = useRef<ReturnType<typeof setInterval> | null>(null);

  /* Animated scan-line while loading */
  useEffect(() => {
    if (loading) {
      scanRef.current = setInterval(() => {
        setScanLine((p) => (p + 3) % 100);
      }, 40);
    } else {
      if (scanRef.current) clearInterval(scanRef.current);
    }
    return () => { if (scanRef.current) clearInterval(scanRef.current); };
  }, [loading]);

  /* Auto-run DDoS preset on mount */
  useEffect(() => { runPreset("DDoS Attack Sample"); }, []);

  /* ── Run handlers ─────────────────────────────────────────────────────────── */
  const runPreset = async (name: string) => {
    setLoading(true); setError(null); setQuarantined(false);
    try {
      const res = await API.analyzePreset(name, 40);
      setResult(res);
      setSelectedWindow(res.windows[0] ?? null);
    } catch (e: any) { setError(e.message ?? "Inference error"); }
    finally { setLoading(false); }
  };

  const runStream = async (attackType?: string) => {
    setLoading(true); setError(null); setQuarantined(false);
    const targetAttack = attackType ?? streamAttack;
    try {
      const res = await API.simulate(targetAttack, streamFlows, 30);
      setResult(res);
      setSelectedWindow(res.windows[0] ?? null);
    } catch (e: any) { setError(e.message ?? "Simulation error"); }
    finally { setLoading(false); }
  };

  const runUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!uploadedFile) return;
    setLoading(true); setError(null); setQuarantined(false);
    try {
      const res = await API.analyzeFile(uploadedFile, 40);
      setResult(res);
      setSelectedWindow(res.windows[0] ?? null);
    } catch (e: any) { setError(e.message ?? "Upload error"); }
    finally { setLoading(false); }
  };

  const exportIncidentReport = () => {
    if (!result) return;
    const report = {
      timestamp: new Date().toISOString(),
      classifier: "MEIC-ViT (Xiao et al., Computer Networks 2026)",
      summary: {
        total_windows: windows.length,
        attack_windows: attackWindows.length,
        benign_windows: benignWindows.length,
        primary_threat: topThreat,
        mean_confidence: Number((avgConf * 100).toFixed(2)),
        inference_time_ms: Number((result.elapsed_s * 1000).toFixed(0)),
        quarantine_enacted: quarantined,
      },
      class_distribution: result.class_counts,
      threat_windows: windows.map(w => ({
        window_id: w.window,
        prediction: w.prediction,
        threat_level: w.threat_level,
        confidence: Number((w.confidence * 100).toFixed(1)),
        ground_truth: w.ground_truth,
        top5_softmax: w.top5
      }))
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `threat_audit_${topThreat.replace(/\\s+/g, "_").toLowerCase()}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  /* ── Derived metrics ──────────────────────────────────────────────────────── */
  const windows = result?.windows ?? [];
  const attackWindows = windows.filter(w => !w.prediction.toUpperCase().startsWith("BENIGN"));
  const benignWindows = windows.filter(w => w.prediction.toUpperCase().startsWith("BENIGN"));
  const avgConf = windows.length > 0 ? windows.reduce((a, w) => a + w.confidence, 0) / windows.length : 0;
  const topThreat = result?.highest_threat ?? "—";
  const topThreatMeta = getThreatMeta(
    attackWindows.length > 0 ? (attackWindows[0].threat_level) : "LOW"
  );

  /* Threat class distribution (sorted by count) */
  const classDist: Array<{ label: string; count: number; level: string; color: string }> = [];
  if (result) {
    const LEVEL_COLOR: Record<string, string> = {
      CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#f59e0b", LOW: "#10b981", UNKNOWN: "#8295b5",
    };
    Object.entries(result.class_counts).forEach(([label, count]) => {
      const threatWin = windows.find(w => w.prediction === label);
      const level = threatWin?.threat_level ?? "UNKNOWN";
      classDist.push({ label, count, level, color: LEVEL_COLOR[level] ?? "#8295b5" });
    });
    classDist.sort((a, b) => b.count - a.count);
  }

  /* Filtered window list */
  const filteredWindows = filterLevel === "ALL"
    ? windows
    : windows.filter(w => filterLevel === "ATTACK" ? !w.prediction.toUpperCase().startsWith("BENIGN") : w.threat_level === filterLevel);

  /* ── Render ───────────────────────────────────────────────────────────────── */
  return (
    <div className="soc-content">

      {/* ── INPUT CONTROLS ─────────────────────────────────────────────────── */}
      <div className="panel" style={{ padding: "16px 18px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
          <div style={{ display: "flex", gap: 6 }}>
            {(["preset", "stream", "upload"] as const).map((mode) => {
              const labels = { preset: "Preset Captures", stream: "Live Stream Inject", upload: "Upload CSV" };
              const icons = { preset: <Layers size={13} />, stream: <Activity size={13} />, upload: <Upload size={13} /> };
              return (
                <button
                  key={mode}
                  className={`btn-secondary-soc ${inputMode === mode ? "btn-primary-soc" : ""}`}
                  onClick={() => setInputMode(mode)}
                  style={{ padding: "7px 14px", fontSize: 12 }}
                >
                  {icons[mode]}
                  <span>{labels[mode]}</span>
                </button>
              );
            })}
          </div>
          <div style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
            MEIC-ViT · 35×35 RGB · Algorithm 1
          </div>
        </div>

        {/* Mode: Preset */}
        {inputMode === "preset" && (
          <div style={{ display: "flex", gap: 12, alignItems: "flex-end", flexWrap: "wrap" }}>
            <div style={{ flex: 1, minWidth: 260 }}>
              <label style={{ fontSize: 10, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 0.6 }}>
                Traffic Capture Sample
              </label>
              <select
                className="logs-filter-select"
                style={{ width: "100%", marginTop: 5 }}
                value={selectedPreset}
                onChange={(e) => setSelectedPreset(e.target.value)}
              >
                <option value="DDoS Attack Sample">🔴 DDoS Volumetric Flood (CICIDS-2017)</option>
                <option value="Port Scan Probe">🟠 PortScan Reconnaissance Sweep</option>
                <option value="Benign Traffic">🟢 Benign Normal Baseline Traffic</option>
                <option value="Mixed Attack Traffic">🔴 Multi-Vector Attack Mixture</option>
              </select>
            </div>
            <button
              className="btn-primary-soc"
              style={{ height: 36, paddingInline: 20 }}
              disabled={loading}
              onClick={() => runPreset(selectedPreset)}
            >
              {loading ? <RefreshCw size={14} style={{ animation: "spin 1s linear infinite" }} /> : <Play size={14} />}
              <span>{loading ? "Analyzing…" : "Analyze Threats"}</span>
            </button>
          </div>
        )}

        {/* Mode: Stream */}
        {inputMode === "stream" && (
          <div style={{ display: "flex", gap: 14, alignItems: "flex-end", flexWrap: "wrap" }}>
            <div style={{ flex: 1, minWidth: 220 }}>
              <label style={{ fontSize: 10, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 0.6 }}>
                Attack Vector
              </label>
              <select className="logs-filter-select" style={{ width: "100%", marginTop: 5 }} value={streamAttack} onChange={(e) => setStreamAttack(e.target.value)}>
                <option value="DDoS Attack">DDoS SYN Flood</option>
                <option value="PortScan Probe">PortScan Recon Sweep</option>
                <option value="Botnet C2 Beaconing">Botnet C2 Beaconing</option>
                <option value="Heartbleed Exploit">OpenSSL Heartbleed Exploit</option>
                <option value="Web SQL Injection">SQL Injection Probe</option>
                <option value="Normal Traffic">Benign Baseline</option>
              </select>
            </div>
            <div style={{ minWidth: 160 }}>
              <label style={{ fontSize: 10, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 0.6 }}>
                Flows: {streamFlows}
              </label>
              <input type="range" min="35" max="140" step="7" value={streamFlows}
                onChange={(e) => setStreamFlows(Number(e.target.value))}
                style={{ width: "100%", marginTop: 8, accentColor: "var(--accent-cyan)" }} />
            </div>
            <button className="btn-primary-soc" style={{ height: 36, paddingInline: 20 }} disabled={loading} onClick={runStream}>
              {loading ? <RefreshCw size={14} style={{ animation: "spin 1s linear infinite" }} /> : <Zap size={14} />}
              <span>{loading ? "Injecting…" : "Inject & Detect"}</span>
            </button>
          </div>
        )}

        {/* Mode: Upload */}
        {inputMode === "upload" && (
          <form onSubmit={runUpload} style={{ display: "flex", gap: 14, alignItems: "flex-end", flexWrap: "wrap" }}>
            <div style={{ flex: 1 }}>
              <label style={{ fontSize: 10, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 0.6 }}>
                CICFlowMeter CSV (35 flow features)
              </label>
              <div style={{
                marginTop: 5, border: "2px dashed var(--border)", borderRadius: 7, padding: "12px 16px",
                background: "rgba(14,165,233,0.03)", cursor: "pointer", transition: "border-color 0.2s",
              }}>
                <input type="file" accept=".csv" onChange={(e) => setUploadedFile(e.target.files?.[0] ?? null)}
                  style={{ color: "var(--text-muted)", fontSize: 12, width: "100%" }} />
                {uploadedFile && (
                  <div style={{ marginTop: 6, fontSize: 11, color: "var(--accent-cyan)" }}>
                    <FileWarning size={11} style={{ display: "inline", marginRight: 4 }} />
                    {uploadedFile.name} ({(uploadedFile.size / 1024).toFixed(0)} KB)
                  </div>
                )}
              </div>
            </div>
            <button type="submit" className="btn-primary-soc" style={{ height: 36, paddingInline: 20 }} disabled={loading || !uploadedFile}>
              {loading ? <RefreshCw size={14} style={{ animation: "spin 1s linear infinite" }} /> : <Upload size={14} />}
              <span>{loading ? "Scanning…" : "Scan File"}</span>
            </button>
          </form>
        )}

        {/* Quick Threat Test Vector Chips */}
        <div style={{ marginTop: 14, paddingTop: 12, borderTop: "1px solid rgba(255,255,255,0.05)", display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <span style={{ fontSize: 10, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 0.6, marginRight: 4 }}>
            Quick Threat Vectors:
          </span>
          {[
            { label: "DDoS SYN Flood", icon: "🔴", attack: "DDoS Attack" },
            { label: "PortScan Recon", icon: "🟠", attack: "PortScan Probe" },
            { label: "Botnet C2 Beacon", icon: "🔴", attack: "Botnet C2 Beaconing" },
            { label: "Heartbleed Exploit", icon: "🔴", attack: "Heartbleed Exploit" },
            { label: "SQL Injection", icon: "🟠", attack: "Web SQL Injection" },
            { label: "Benign Baseline", icon: "🟢", attack: "Normal Traffic" },
          ].map((item) => (
            <button
              key={item.label}
              disabled={loading}
              onClick={() => {
                setInputMode("stream");
                setStreamAttack(item.attack);
                runStream(item.attack);
              }}
              style={{
                fontSize: 11, fontWeight: 600,
                padding: "4px 10px", borderRadius: 5,
                background: "rgba(255,255,255,0.03)",
                border: "1px solid rgba(255,255,255,0.08)",
                color: "var(--text-muted)", cursor: "pointer",
                display: "flex", alignItems: "center", gap: 5,
                transition: "all 0.15s",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = "var(--accent-cyan)";
                e.currentTarget.style.color = "#fff";
                e.currentTarget.style.background = "rgba(56,189,248,0.08)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = "rgba(255,255,255,0.08)";
                e.currentTarget.style.color = "var(--text-muted)";
                e.currentTarget.style.background = "rgba(255,255,255,0.03)";
              }}
            >
              <span>{item.icon}</span>
              <span>{item.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* ── Loading scanner ─────────────────────────────────────────────────── */}
      {loading && (
        <div style={{
          background: "linear-gradient(135deg, rgba(8,16,32,0.97), rgba(12,23,44,0.97))",
          border: "1px solid var(--border)", borderRadius: 10, padding: "28px 24px",
          textAlign: "center", position: "relative", overflow: "hidden",
        }}>
          <div style={{
            position: "absolute", left: 0, right: 0,
            top: `${scanLine}%`, height: 2,
            background: "linear-gradient(90deg, transparent, var(--accent-cyan), transparent)",
            transition: "top 0.04s linear",
          }} />
          <Cpu size={28} color="var(--accent-cyan)" style={{ marginBottom: 10 }} />
          <div style={{ fontSize: 14, fontWeight: 700, color: "#fff" }}>MEIC-ViT Inference Running</div>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
            Mapping flows → 35×35 RGB tensors → Transformer classification…
          </div>
          <div style={{ display: "flex", justifyContent: "center", gap: 20, marginTop: 16 }}>
            {["Path A: Global Stats", "Path B: Row Visual", "Path C: Sequential"].map((p, i) => (
              <div key={p} style={{
                fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-mono)",
                padding: "4px 10px", borderRadius: 4,
                background: "rgba(56,189,248,0.06)", border: "1px solid var(--border)",
                animation: `fadeIn 0.3s ease ${i * 0.15}s both`,
              }}>
                {p}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Error ───────────────────────────────────────────────────────────── */}
      {error && (
        <div style={{ background: "rgba(239,68,68,0.12)", border: "1px solid rgba(239,68,68,0.4)", borderRadius: 8, padding: "12px 16px", display: "flex", gap: 10, alignItems: "center" }}>
          <XCircle size={16} color="#ef4444" />
          <span style={{ color: "#ef4444", fontSize: 13 }}>{error}</span>
        </div>
      )}

      {/* ── RESULTS ─────────────────────────────────────────────────────────── */}
      {result && !loading && (
        <>
          {/* ── KPI Strip ──────────────────────────────────────────────────── */}
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            <KpiCard
              label="Primary Threat"
              value={topThreat.length > 14 ? topThreat.slice(0, 13) + "…" : topThreat}
              sub={attackWindows.length > 0 ? attackWindows[0].threat_level : "BENIGN"}
              color={topThreatMeta.color}
              icon={<ShieldX size={16} color={topThreatMeta.color} />}
              pulse={attackWindows.length > 0}
            />
            <KpiCard
              label="Attack Windows"
              value={attackWindows.length}
              sub={`of ${windows.length} total (${windows.length > 0 ? ((attackWindows.length / windows.length) * 100).toFixed(0) : 0}%)`}
              color={attackWindows.length > 0 ? "#ef4444" : "#10b981"}
              icon={<Target size={16} color={attackWindows.length > 0 ? "#ef4444" : "#10b981"} />}
              pulse={attackWindows.length > 0}
            />
            <KpiCard
              label="Model Confidence"
              value={`${(avgConf * 100).toFixed(1)}%`}
              sub="Mean across all windows"
              color="#38bdf8"
              icon={<TrendingUp size={16} color="#38bdf8" />}
            />
            <KpiCard
              label="Inference Time"
              value={`${(result.elapsed_s * 1000).toFixed(0)}ms`}
              sub={`${windows.length} windows processed`}
              color="#818cf8"
              icon={<Clock size={16} color="#818cf8" />}
            />
          </div>

          {/* ── Alert Banner (critical / high only) ────────────────────────── */}
          {attackWindows.length > 0 && (
            <div style={{
              background: `linear-gradient(135deg, ${topThreatMeta.bg}, rgba(8,16,32,0.9))`,
              border: `1px solid ${topThreatMeta.border}`,
              borderLeft: `4px solid ${topThreatMeta.color}`,
              borderRadius: 10, padding: "14px 18px",
              display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap",
              boxShadow: `0 0 24px ${topThreatMeta.glow}`,
            }}>
              <PulseDot color={topThreatMeta.color} />
              <div style={{ flex: 1, minWidth: 260 }}>
                <div style={{ fontSize: 13, fontWeight: 700, color: topThreatMeta.color }}>
                  🚨 INTRUSION DETECTED — {topThreat}
                </div>
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                  {attackWindows.length} malicious traffic windows detected •{" "}
                  {((attackWindows.length / windows.length) * 100).toFixed(1)}% of analyzed flows are hostile •{" "}
                  Threat Level: <strong style={{ color: topThreatMeta.color }}>{topThreatMeta.color === "#ef4444" ? "CRITICAL" : "HIGH"}</strong>
                </div>
              </div>

              {/* Action Buttons */}
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                {quarantined ? (
                  <button
                    onClick={() => setQuarantined(false)}
                    style={{
                      display: "flex", alignItems: "center", gap: 6,
                      padding: "6px 12px", borderRadius: 6,
                      background: "rgba(16,185,129,0.18)", border: "1px solid #10b981",
                      color: "#10b981", fontSize: 11, fontWeight: 700, cursor: "pointer",
                    }}
                  >
                    <ShieldCheck size={14} />
                    <span>QUARANTINED (UNDO)</span>
                  </button>
                ) : (
                  <button
                    onClick={() => setQuarantined(true)}
                    style={{
                      display: "flex", alignItems: "center", gap: 6,
                      padding: "7px 14px", borderRadius: 6,
                      background: "#ef4444", border: "1px solid rgba(239,68,68,0.6)",
                      color: "#fff", fontSize: 11, fontWeight: 700, cursor: "pointer",
                      boxShadow: "0 0 12px rgba(239,68,68,0.4)",
                    }}
                  >
                    <Lock size={13} />
                    <span>QUARANTINE VECTOR</span>
                  </button>
                )}

                <button
                  onClick={exportIncidentReport}
                  style={{
                    display: "flex", alignItems: "center", gap: 6,
                    padding: "7px 12px", borderRadius: 6,
                    background: "rgba(255,255,255,0.06)", border: "1px solid var(--border)",
                    color: "#fff", fontSize: 11, fontWeight: 600, cursor: "pointer",
                  }}
                  title="Export complete threat audit and softmax distributions as JSON"
                >
                  <Download size={13} />
                  <span>EXPORT REPORT</span>
                </button>
              </div>

              <div style={{
                fontSize: 22, fontWeight: 900, fontFamily: "var(--font-mono)",
                color: topThreatMeta.color, letterSpacing: -1,
              }}>
                {attackWindows.length > 0 ? attackWindows[0].threat_level : "LOW"}
              </div>
            </div>
          )}

          {!attackWindows.length && (
            <div style={{
              background: "rgba(16,185,129,0.08)", border: "1px solid rgba(16,185,129,0.3)",
              borderLeft: "4px solid #10b981", borderRadius: 10, padding: "12px 18px",
              display: "flex", alignItems: "center", gap: 12,
            }}>
              <CheckCircle2 size={18} color="#10b981" />
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: "#10b981" }}>Network Clear — No Intrusions Detected</div>
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                  All {windows.length} analyzed windows classified as BENIGN. Mean confidence: {(avgConf * 100).toFixed(1)}%
                </div>
              </div>
            </div>
          )}

          {/* ── Main Two-Column ─────────────────────────────────────────────── */}
          <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1fr", gap: 16, alignItems: "start" }}>

            {/* Left: Window Audit Table */}
            <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
              <div style={{ padding: "12px 14px 10px", borderBottom: "1px solid var(--border)" }}>
                <div className="panel-title">
                  <BarChart3 size={15} color="var(--accent-cyan)" />
                  <span>Per-Window Threat Audit ({windows.length} slices)</span>
                </div>
                <div style={{ display: "flex", gap: 6, marginTop: 10, flexWrap: "wrap" }}>
                  {["ALL", "ATTACK", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((f) => (
                    <button
                      key={f}
                      onClick={() => setFilterLevel(f)}
                      style={{
                        fontSize: 10, fontWeight: 700, letterSpacing: 0.5,
                        padding: "3px 9px", borderRadius: 4, cursor: "pointer", border: "1px solid",
                        background: filterLevel === f ? "var(--accent-cyan)" : "transparent",
                        color: filterLevel === f ? "#000" : "var(--text-dim)",
                        borderColor: filterLevel === f ? "var(--accent-cyan)" : "var(--border)",
                        transition: "all 0.15s",
                      }}
                    >
                      {f}
                    </button>
                  ))}
                </div>
              </div>
              <div style={{ maxHeight: 360, overflowY: "auto" }}>
                <table className="sensor-table" style={{ fontSize: 12 }}>
                  <thead>
                    <tr>
                      <th style={{ padding: "7px 10px" }}>WIN</th>
                      <th style={{ padding: "7px 8px" }}>PREDICTION</th>
                      <th style={{ padding: "7px 8px" }}>LEVEL</th>
                      <th style={{ padding: "7px 8px" }}>CONF</th>
                      <th style={{ padding: "7px 8px" }}>GROUND TRUTH</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredWindows.map((w, i) => (
                      <WindowRow
                        key={w.window}
                        w={w}
                        isSelected={selectedWindow?.window === w.window}
                        onClick={() => setSelectedWindow(w)}
                        idx={i}
                      />
                    ))}
                    {filteredWindows.length === 0 && (
                      <tr>
                        <td colSpan={5} style={{ textAlign: "center", padding: 24, color: "var(--text-dim)", fontSize: 12 }}>
                          No windows match this filter
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Right: Detail Panel + Distribution */}
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>

              {/* Attention heatmap + probabilities */}
              {selectedWindow && (
                <div className="panel" style={{ padding: 16 }}>
                  <div className="panel-header" style={{ marginBottom: 12 }}>
                    <div className="panel-title">
                      <Eye size={14} color="var(--accent-purple)" />
                      <span>Window #{selectedWindow.window + 1} — Attention Map</span>
                    </div>
                    <span style={{
                      fontSize: 10, fontWeight: 700,
                      padding: "2px 8px", borderRadius: 3,
                      background: getThreatMeta(selectedWindow.threat_level).bg,
                      color: getThreatMeta(selectedWindow.threat_level).color,
                      border: `1px solid ${getThreatMeta(selectedWindow.threat_level).border}`,
                    }}>
                      {selectedWindow.threat_level}
                    </span>
                  </div>

                  <div style={{ textAlign: "center", marginBottom: 14 }}>
                    <img
                      src={`data:image/png;base64,${selectedWindow.composite_b64}`}
                      alt="RGB + Attention heatmap"
                      style={{ width: "100%", maxWidth: 320, borderRadius: 6, border: "1px solid var(--border)", imageRendering: "pixelated" }}
                    />
                    <div style={{ display: "flex", justifyContent: "space-around", marginTop: 6, fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--text-dim)" }}>
                      <span>← 24-bit RGB Flow</span>
                      <span style={{ color: "#f97316" }}>Attention Map →</span>
                    </div>
                  </div>

                  {/* Prediction headline */}
                  <div style={{
                    background: getThreatMeta(selectedWindow.threat_level).bg,
                    border: `1px solid ${getThreatMeta(selectedWindow.threat_level).border}`,
                    borderRadius: 7, padding: "10px 14px", marginBottom: 12,
                  }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase" }}>Predicted Class</div>
                    <div style={{ fontSize: 15, fontWeight: 800, color: getThreatMeta(selectedWindow.threat_level).color, marginTop: 2 }}>
                      {selectedWindow.prediction}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                      Confidence: {(selectedWindow.confidence * 100).toFixed(1)}%
                    </div>
                  </div>

                  {/* Top-5 softmax bars */}
                  <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 0.6, marginBottom: 8 }}>
                    Top-5 Softmax Distribution
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                    {selectedWindow.top5.map((c, i) => (
                      <div key={c.label}>
                        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, marginBottom: 2 }}>
                          <span style={{ color: i === 0 ? "#fff" : "var(--text-muted)", fontWeight: i === 0 ? 700 : 400, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "68%" }}>
                            {i === 0 && <ChevronRight size={10} style={{ display: "inline", marginRight: 2 }} />}
                            {c.label}
                          </span>
                          <span style={{ fontFamily: "var(--font-mono)", color: i === 0 ? "var(--accent-cyan)" : "var(--text-dim)", flexShrink: 0 }}>
                            {(c.prob * 100).toFixed(1)}%
                          </span>
                        </div>
                        <div style={{ height: 3, background: "rgba(255,255,255,0.06)", borderRadius: 999 }}>
                          <div style={{
                            height: "100%", width: `${c.prob * 100}%`, borderRadius: 999,
                            background: i === 0 ? "var(--accent-cyan)" : "rgba(56,189,248,0.3)",
                            transition: "width 0.5s cubic-bezier(0.4,0,0.2,1)",
                          }} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Attack Class Distribution */}
              {classDist.length > 0 && (
                <div className="panel" style={{ padding: 16 }}>
                  <div className="panel-title" style={{ marginBottom: 12 }}>
                    <BarChart3 size={14} color="var(--accent-amber)" />
                    <span>Threat Class Distribution</span>
                  </div>
                  <div>
                    {classDist.map((c) => (
                      <ThreatBar
                        key={c.label}
                        label={c.label}
                        count={c.count}
                        total={windows.length}
                        color={c.color}
                        level={c.level}
                      />
                    ))}
                  </div>

                  {/* Summary row */}
                  <div style={{
                    marginTop: 12, display: "flex", gap: 12,
                    padding: "10px 0", borderTop: "1px solid rgba(255,255,255,0.05)",
                  }}>
                    <div style={{ flex: 1, textAlign: "center" }}>
                      <div style={{ fontSize: 18, fontWeight: 800, color: "#ef4444", fontFamily: "var(--font-mono)" }}>{attackWindows.length}</div>
                      <div style={{ fontSize: 9, color: "var(--text-dim)", textTransform: "uppercase" }}>Malicious</div>
                    </div>
                    <div style={{ width: 1, background: "var(--border)" }} />
                    <div style={{ flex: 1, textAlign: "center" }}>
                      <div style={{ fontSize: 18, fontWeight: 800, color: "#10b981", fontFamily: "var(--font-mono)" }}>{benignWindows.length}</div>
                      <div style={{ fontSize: 9, color: "var(--text-dim)", textTransform: "uppercase" }}>Benign</div>
                    </div>
                    <div style={{ width: 1, background: "var(--border)" }} />
                    <div style={{ flex: 1, textAlign: "center" }}>
                      <div style={{ fontSize: 18, fontWeight: 800, color: "#38bdf8", fontFamily: "var(--font-mono)" }}>{classDist.length}</div>
                      <div style={{ fontSize: 9, color: "var(--text-dim)", textTransform: "uppercase" }}>Classes</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* ── Threat Timeline (horizontal scroll of all windows) ──────────── */}
          <div className="panel" style={{ padding: "12px 14px" }}>
            <div className="panel-title" style={{ marginBottom: 10 }}>
              <Activity size={14} color="var(--accent-green)" />
              <span>Threat Timeline — Sliding Window Sequence</span>
              <span style={{ marginLeft: "auto", fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
                W=35, S=18 (48.6% overlap) · Click any cell to inspect
              </span>
            </div>
            <div style={{ display: "flex", gap: 3, overflowX: "auto", paddingBottom: 6 }}>
              {windows.map((w) => {
                const m = getThreatMeta(w.threat_level);
                const isAtk = !w.prediction.toUpperCase().startsWith("BENIGN");
                const isSel = selectedWindow?.window === w.window;
                return (
                  <div
                    key={w.window}
                    title={`#${w.window + 1}: ${w.prediction} (${(w.confidence * 100).toFixed(0)}%)`}
                    onClick={() => setSelectedWindow(w)}
                    style={{
                      width: 24, height: 36, flexShrink: 0, borderRadius: 3,
                      background: isAtk ? m.color : "#10b981",
                      opacity: isSel ? 1 : isAtk ? 0.7 + w.confidence * 0.3 : 0.3 + w.confidence * 0.3,
                      cursor: "pointer",
                      border: isSel ? "2px solid #fff" : "1px solid transparent",
                      transition: "opacity 0.2s, border 0.15s",
                      position: "relative",
                    }}
                  >
                    {isSel && (
                      <div style={{
                        position: "absolute", top: -6, left: "50%", transform: "translateX(-50%)",
                        width: 0, height: 0,
                        borderLeft: "4px solid transparent", borderRight: "4px solid transparent",
                        borderTop: "5px solid #fff",
                      }} />
                    )}
                  </div>
                );
              })}
            </div>
            <div style={{ display: "flex", gap: 16, marginTop: 8, fontSize: 10, color: "var(--text-dim)" }}>
              <span>🔴 Critical / High attack</span>
              <span>🟠 Medium threat</span>
              <span>🟢 Benign</span>
              <span>· Brightness = confidence</span>
            </div>
          </div>
        </>
      )}

      {/* Keyframe animations (injected inline) */}
      <style>{`
        @keyframes ping {
          75%, 100% { transform: scale(2); opacity: 0; }
        }
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(4px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
};
