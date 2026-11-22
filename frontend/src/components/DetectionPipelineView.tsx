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
  Wifi,
  Square,
  Radio,
} from "lucide-react";
import { API, AnalysisResult, WindowResult } from "../api/client";
import { alertService } from "../services/alertService";

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
      flex: 1, minWidth: 150,
      background: "linear-gradient(135deg, rgba(14,24,44,0.75), rgba(10,16,30,0.85))",
      border: `1px solid rgba(255,255,255,0.08)`,
      borderTop: `2px solid ${color}`,
      borderRadius: "var(--radius-sm)",
      padding: "16px 18px",
      position: "relative", overflow: "hidden",
      backdropFilter: "blur(14px)",
      WebkitBackdropFilter: "blur(14px)",
      boxShadow: `0 8px 24px -6px rgba(0,0,0,0.5), 0 0 16px ${color}14`,
      transition: "transform 0.2s ease, border-color 0.2s ease",
    }}>
      <div style={{
        position: "absolute", top: 0, right: 0, width: 90, height: 90,
        background: `radial-gradient(circle at 100% 0%, ${color}18 0%, transparent 70%)`,
        pointerEvents: "none",
      }} />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", position: "relative" }}>
        <div>
          <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 0.8, fontFamily: "var(--font-mono)" }}>
            {label}
          </div>
          <div style={{ fontSize: 28, fontWeight: 800, color, fontFamily: "var(--font-mono)", marginTop: 6, lineHeight: 1, letterSpacing: -0.5 }}>
            {value}
          </div>
          {sub && <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 6, fontFamily: "var(--font-mono)" }}>{sub}</div>}
        </div>
        <div style={{
          width: 38, height: 38, borderRadius: 10,
          background: `${color}18`, border: `1px solid ${color}33`,
          display: "flex", alignItems: "center", justifyContent: "center",
          boxShadow: `0 0 12px ${color}22`,
        }}>
          {icon}
        </div>
      </div>
      {pulse && (
        <div style={{ position: "absolute", top: 10, right: 10 }}>
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
const isBenignPrediction = (pred: string) => {
  const p = (pred || "").toUpperCase();
  return p.startsWith("BENIGN") || p.startsWith("NORMAL");
};

const WindowRow: React.FC<{ w: WindowResult; isSelected: boolean; onClick: () => void; idx: number }> =
  ({ w, isSelected, onClick, idx }) => {
    const meta = getThreatMeta(w.threat_level);
    const isAttack = !isBenignPrediction(w.prediction);
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
        <td style={{ padding: "7px 8px" }}>
          {w.confidence_status === "CONFIRMED" ? (
            <span style={{ fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 3, background: "rgba(16,185,129,0.15)", color: "#10b981", border: "1px solid rgba(16,185,129,0.3)" }}>
              CONFIRMED
            </span>
          ) : w.confidence_status === "EVALUATING" ? (
            <span style={{ fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 3, background: "rgba(245,158,11,0.15)", color: "#f59e0b", border: "1px solid rgba(245,158,11,0.3)" }}>
              EVALUATING
            </span>
          ) : (
            <span style={{ fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 3, background: "rgba(148,163,184,0.12)", color: "#94a3b8", border: "1px solid rgba(148,163,184,0.25)" }}>
              PROVISIONAL
            </span>
          )}
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
  const [inputMode, setInputMode] = useState<"preset" | "stream" | "upload" | "live">("preset");
  const [selectedPreset, setSelectedPreset] = useState("DDoS Attack Sample");
  const [streamAttack, setStreamAttack] = useState("DDoS Attack");
  const [streamFlows, setStreamFlows] = useState(70);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);

  // Live capture state
  const [liveInterfaces, setLiveInterfaces] = useState<Array<{ id: string; name: string; description: string; ips: string[]; is_wifi?: boolean; is_ethernet?: boolean }>>([]);
  const [selectedInterface, setSelectedInterface] = useState("Wi-Fi");
  const [liveStatus, setLiveStatus] = useState<"STOPPED" | "RUNNING" | "RUNNING_SIMULATED" | "ERROR">("STOPPED");
  const [liveStats, setLiveStats] = useState({ packets: 0, flows: 0, windows: 0, error: "" as string | null });
  const [recentFlows, setRecentFlows] = useState<Array<{ src: string; dst: string; proto: string; packets: number; bytes: number; duration_ms: number }>>([]);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [selectedWindow, setSelectedWindow] = useState<WindowResult | null>(null);
  const [filterLevel, setFilterLevel] = useState<string>("ALL");
  const [scanLine, setScanLine] = useState(0);
  const [quarantined, setQuarantined] = useState(false);

  const scanRef = useRef<ReturnType<typeof setInterval> | null>(null);

  /* Fetch live network interfaces and synchronize status on mount */
  useEffect(() => {
    API.getLiveInterfaces()
      .then((res) => {
        if (res.interfaces && res.interfaces.length > 0) {
          setLiveInterfaces(res.interfaces);
          // Prefer active adapter with a real valid IP (not link-local 169.254.x.x)
          const activeWithIp = res.interfaces.find(
            (i) =>
              i.ips &&
              i.ips.some(
                (ip) =>
                  !ip.startsWith("169.254") &&
                  !ip.startsWith("fe80") &&
                  ip !== "::1" &&
                  ip !== "127.0.0.1"
              )
          );
          const preferred =
            activeWithIp ||
            res.interfaces.find((i) => i.is_wifi) ||
            res.interfaces.find((i) => i.is_ethernet) ||
            res.interfaces[0];
          setSelectedInterface(preferred.name);
        }
      })
      .catch(() => {});

    // Synchronize current live capture status from backend
    API.getLiveStatus()
      .then((st) => {
        setLiveStatus(st.status);
        setLiveStats({
          packets: st.packets_captured,
          flows: st.flows_completed,
          windows: st.windows_processed,
          error: st.error,
        });
        if (st.recent_flows && st.recent_flows.length > 0) {
          setRecentFlows(st.recent_flows);
        }
        // If capture was already running in background, keep user on live tab
        if (st.status === "RUNNING" || st.status === "RUNNING_SIMULATED") {
          setInputMode("live");
        }
      })
      .catch(() => {});
  }, []);

  /* Poll live status & events when active */
  useEffect(() => {
    let timer: any = null;
    if (liveStatus === "RUNNING" || liveStatus === "RUNNING_SIMULATED") {
      timer = setInterval(async () => {
        try {
          const st = await API.getLiveStatus();
          setLiveStatus(st.status);
          setLiveStats({
            packets: st.packets_captured,
            flows: st.flows_completed,
            windows: st.windows_processed,
            error: st.error,
          });
          if (st.recent_flows && st.recent_flows.length > 0) {
            setRecentFlows(st.recent_flows);
          }
          if (st.current_result && st.current_result.windows && st.current_result.windows.length > 0) {
            const wins = st.current_result.windows;
            const latestWin = wins[wins.length - 1];
            setResult(st.current_result);
            setSelectedWindow((prev) => {
              if (!prev) return latestWin;
              // If new window arrived, auto-switch to it so the operator sees the new inference
              if (latestWin.window > prev.window) {
                return latestWin;
              }
              const match = wins.find((w) => w.window === prev.window);
              return match || latestWin;
            });
          }
        } catch (e) {}
      }, 1000);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [liveStatus]);

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

  /* Report critical/high/medium threats to global audio & visual emergency alarm */
  useEffect(() => {
    if (!result || !result.windows || result.windows.length === 0) return;
    const attackWins = result.windows.filter((w) => {
      const p = (w.prediction || "").toUpperCase();
      return (
        !p.startsWith("BENIGN") &&
        !p.startsWith("NORMAL") &&
        (w.threat_level === "CRITICAL" || w.threat_level === "HIGH" || w.threat_level === "MEDIUM")
      );
    });
    if (attackWins.length > 0) {
      const targetWin = attackWins[attackWins.length - 1];
      alertService.reportWindow(targetWin, selectedInterface || "Wi-Fi TAP");
    }
  }, [result, selectedInterface]);

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

  const toggleLiveCapture = async () => {
    if (liveStatus === "RUNNING" || liveStatus === "RUNNING_SIMULATED") {
      setLoading(true);
      try {
        const res = await API.stopLiveCapture();
        setLiveStatus("STOPPED");
        if (res.result && res.result.windows && res.result.windows.length > 0) {
          setResult(res.result);
          setSelectedWindow(res.result.windows[0]);
        }
      } catch (e: any) {
        setError(e.message ?? "Failed to stop capture");
      } finally {
        setLoading(false);
      }
    } else {
      setLoading(true);
      setError(null);
      setResult(null);
      setSelectedWindow(null);
      setRecentFlows([]);
      try {
        const res = await API.startLiveCapture(selectedInterface);
        const nextStatus =
          res.status === "STARTED" || res.status === "RUNNING" ? "RUNNING" : (res.status as any);
        setLiveStatus(nextStatus);
        const st = await API.getLiveStatus();
        setLiveStatus(st.status);
      } catch (e: any) {
        setError(`Live capture failed: ${e.message ?? "Could not reach backend"}. Is uvicorn running on port 8000?`);
      } finally {
        setLoading(false);
      }
    }
  };

  const exportIncidentReport = () => {
    if (!result) return;
    const report = {
      timestamp: new Date().toISOString(),
      classifier: "UniSecure Vision AI Threat Defense Engine",
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
  const attackWindows = windows.filter(w => !isBenignPrediction(w.prediction));
  const benignWindows = windows.filter(w => isBenignPrediction(w.prediction));
  const avgConf = windows.length > 0 ? windows.reduce((a, w) => a + w.confidence, 0) / windows.length : 0;
  const topThreat = result?.highest_threat ?? (
    attackWindows.length > 0 ? attackWindows[0].threat_level : "LOW"
  );
  const topThreatMeta = getThreatMeta(topThreat);
  // Accurate attack count from backend (excludes benign); fallback to frontend filter count
  const attackCount = result?.n_attack_windows ?? attackWindows.length;

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
    : filterLevel === "CONFIRMED"
    ? windows.filter(w => w.confidence_status === "CONFIRMED" || (w.is_persistent && !isBenignPrediction(w.prediction)))
    : filterLevel === "ATTACK"
    ? windows.filter(w => !isBenignPrediction(w.prediction))
    : filterLevel === "LOW"
    ? windows.filter(w => w.threat_level === "LOW" || isBenignPrediction(w.prediction))
    : windows.filter(w => w.threat_level === filterLevel);

  /* ── Render ───────────────────────────────────────────────────────────────── */
  return (
    <div className="soc-content">

      {/* ── INPUT CONTROLS ─────────────────────────────────────────────────── */}
      <div className="panel" style={{ padding: "16px 18px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16, flexWrap: "wrap", gap: 10 }}>
          <div style={{
            display: "inline-flex",
            background: "rgba(0, 0, 0, 0.45)",
            border: "1px solid rgba(255, 255, 255, 0.08)",
            borderRadius: 10,
            padding: 3,
            gap: 2,
          }}>
            {(["preset", "stream", "upload", "live"] as const).map((mode) => {
              const labels = {
                preset: "Preset Captures",
                stream: "Live Stream Inject",
                upload: "Upload CSV",
                live: "Live Network TAP (Npcap)",
              };
              const icons = {
                preset: <Layers size={13} />,
                stream: <Activity size={13} />,
                upload: <Upload size={13} />,
                live: <Wifi size={13} />,
              };
              const isSelected = inputMode === mode;
              return (
                <button
                  key={mode}
                  onClick={() => {
                    setInputMode(mode);
                    if (mode === "live") {
                      // Fetch current status and sync active state
                      API.getLiveStatus()
                        .then((st) => {
                          setLiveStatus(st.status);
                          setLiveStats({
                            packets: st.packets_captured,
                            flows: st.flows_completed,
                            windows: st.windows_processed,
                            error: st.error,
                          });
                          if (st.recent_flows) setRecentFlows(st.recent_flows);
                          if (st.current_result && st.current_result.windows && st.current_result.windows.length > 0) {
                            setResult(st.current_result);
                          }
                        })
                        .catch(() => {});
                    }
                  }}
                  style={{
                    padding: "7px 16px",
                    fontSize: 12,
                    fontWeight: isSelected ? 700 : 500,
                    borderRadius: 8,
                    border: isSelected ? "1px solid rgba(56, 189, 248, 0.4)" : "1px solid transparent",
                    background: isSelected
                      ? "linear-gradient(135deg, rgba(2, 132, 199, 0.4), rgba(56, 189, 248, 0.18))"
                      : "transparent",
                    color: isSelected ? "#fff" : "var(--text-muted)",
                    boxShadow: isSelected ? "0 0 16px rgba(56, 189, 248, 0.25), inset 0 1px 0 rgba(255,255,255,0.15)" : "none",
                    cursor: "pointer",
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 7,
                    transition: "all 0.18s ease",
                  }}
                >
                  {icons[mode]}
                  <span>{labels[mode]}</span>
                  {mode === "live" && (liveStatus === "RUNNING" || liveStatus === "RUNNING_SIMULATED") && (
                    <span style={{ marginLeft: 4, display: "inline-flex" }}>
                      <PulseDot color="#10b981" />
                    </span>
                  )}
                </button>
              );
            })}
          </div>
          <div style={{
            fontSize: 10,
            color: "var(--accent-cyan)",
            fontFamily: "var(--font-mono)",
            fontWeight: 700,
            letterSpacing: 0.6,
            background: "rgba(14, 165, 233, 0.08)",
            padding: "5px 12px",
            borderRadius: 999,
            border: "1px solid rgba(14, 165, 233, 0.25)",
            display: "flex",
            alignItems: "center",
            gap: 6,
          }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--accent-cyan)", boxShadow: "0 0 6px var(--accent-cyan)" }} />
            <span>
              {inputMode === "live"
                ? liveStatus === "RUNNING"
                  ? "NPCAP WIRE CAPTURE ACTIVE"
                  : liveStatus === "RUNNING_SIMULATED"
                  ? "LOCAL WIRE STREAMING (SIMULATED)"
                  : "TAP READY"
                : "VISION TRANSFORMER IDS PIPELINE"}
            </span>
          </div>
        </div>

        {/* Mode: Preset */}
        {inputMode === "preset" && (
          <div style={{ display: "flex", gap: 12, alignItems: "flex-end", flexWrap: "wrap" }}>
            <div style={{ flex: 1, minWidth: 260 }}>
              <label style={{ fontSize: 10, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 0.6 }}>
                Traffic Capture Scenario
              </label>
              <select
                className="logs-filter-select"
                style={{ width: "100%", marginTop: 5 }}
                value={selectedPreset}
                onChange={(e) => setSelectedPreset(e.target.value)}
              >
                <optgroup label="CICIDS-2017 Scenarios">
                  <option value="DDoS Attack Sample">🔴 Volumetric DDoS SYN Flood Attack</option>
                  <option value="Port Scan Probe">🟠 PortScan Host Reconnaissance Sweep</option>
                  <option value="Benign Traffic">🟢 Normal Enterprise Baseline Traffic</option>
                  <option value="Mixed Attack Traffic">🔴 Multi-Vector Attack Mixture</option>
                </optgroup>
                <optgroup label="UNSW-NB15 Scenarios">
                  <option value="UNSW Exploits Sample">🔴 UNSW Exploits Threat (98% Conf)</option>
                  <option value="UNSW Generic Sample">🔴 UNSW Generic Payload Injection (95% Conf)</option>
                  <option value="UNSW Worms Sample">🔴 UNSW Worms Critical Propagation</option>
                  <option value="UNSW Normal Baseline">🟢 UNSW Clean Enterprise Baseline</option>
                </optgroup>
                <optgroup label="Zero-Day / Out-of-Distribution Scenarios">
                  <option value="Zero-Day APT Exfiltration (Unseen Attack)">⚡ Zero-Day APT Exfiltration (Untrained Zero-Day Attack)</option>
                  <option value="Dual-Dataset Cross Benchmark">⚡ Dual-Dataset Mixed Traffic (CICIDS + UNSW Combined)</option>
                </optgroup>
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
                <optgroup label="CICIDS-2017 Real Attacks">
                  <option value="DDoS Attack">DDoS SYN Flood</option>
                  <option value="PortScan Probe">PortScan Recon Sweep</option>
                  <option value="Botnet C2 Beaconing">Botnet C2 Beaconing</option>
                  <option value="Heartbleed Exploit">OpenSSL Heartbleed Exploit</option>
                  <option value="Web SQL Injection">SQL Injection Probe</option>
                  <option value="Normal Traffic">CICIDS Benign Baseline</option>
                </optgroup>
                <optgroup label="UNSW-NB15 Benchmark Attacks">
                  <option value="UNSW Exploits">UNSW Exploits (98% Conf)</option>
                  <option value="UNSW Generic">UNSW Generic Payload (95% Conf)</option>
                  <option value="UNSW Fuzzers">UNSW Protocol Fuzzers</option>
                  <option value="UNSW DoS">UNSW Denial-of-Service</option>
                  <option value="UNSW Worms">UNSW Worms Propagation</option>
                  <option value="UNSW Reconnaissance">UNSW Reconnaissance Sweep</option>
                  <option value="UNSW Normal">UNSW Normal Baseline (98% Conf)</option>
                </optgroup>
                <optgroup label="Out-of-Distribution / Zero-Day (Untrained)">
                  <option value="Zero-Day APT Exfiltration">⚡ Zero-Day APT Exfiltration (Untrained Threat)</option>
                </optgroup>
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
            <button className="btn-primary-soc" style={{ height: 36, paddingInline: 20 }} disabled={loading} onClick={() => runStream()}>
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
                Network Flow Traffic Capture (.csv)
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

        {/* Mode: Live Network TAP (Npcap) */}
        {inputMode === "live" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div style={{ display: "flex", gap: 14, alignItems: "flex-end", flexWrap: "wrap" }}>
              <div style={{ flex: 1, minWidth: 260 }}>
                <label style={{ fontSize: 10, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 0.6 }}>
                  Host Network Interface (Windows Npcap)
                </label>
                <select
                  className="logs-filter-select"
                  style={{ width: "100%", marginTop: 5 }}
                  value={selectedInterface}
                  onChange={(e) => setSelectedInterface(e.target.value)}
                  disabled={liveStatus === "RUNNING" || liveStatus === "RUNNING_SIMULATED"}
                >
                  {liveInterfaces.length > 0 ? (
                    liveInterfaces.map((iface) => (
                      <option key={iface.name} value={iface.name}>
                        {iface.name} — {iface.description} {iface.ips && iface.ips.length > 0 ? `(${iface.ips[0]})` : ""}
                      </option>
                    ))
                  ) : (
                    <>
                      <option value="Wi-Fi">Wi-Fi (Active Adapter)</option>
                      <option value="Ethernet">Ethernet</option>
                      <option value="Loopback Pseudo-Interface 1">Loopback (Localhost)</option>
                    </>
                  )}
                </select>
              </div>

              <button
                className="btn-primary-soc"
                style={{
                  height: 36,
                  paddingInline: 22,
                  background:
                    liveStatus === "RUNNING" || liveStatus === "RUNNING_SIMULATED"
                      ? "#ef4444"
                      : "var(--accent-cyan)",
                  boxShadow:
                    liveStatus === "RUNNING" || liveStatus === "RUNNING_SIMULATED"
                      ? "0 0 16px rgba(239,68,68,0.4)"
                      : "0 0 16px rgba(56,189,248,0.3)",
                }}
                disabled={loading}
                onClick={toggleLiveCapture}
              >
                {loading ? (
                  <RefreshCw size={14} style={{ animation: "spin 1s linear infinite" }} />
                ) : liveStatus === "RUNNING" || liveStatus === "RUNNING_SIMULATED" ? (
                  <Square size={14} />
                ) : (
                  <Radio size={14} />
                )}
                <span>
                  {liveStatus === "RUNNING" || liveStatus === "RUNNING_SIMULATED"
                    ? "STOP CAPTURE"
                    : "START LIVE CAPTURE"}
                </span>
              </button>
            </div>

            {/* Live Metrics Strip */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
                gap: 10,
                padding: "12px 16px",
                borderRadius: "var(--radius-sm)",
                background: "rgba(0,0,0,0.45)",
                border: "1px solid rgba(255,255,255,0.08)",
                alignItems: "center",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span
                  style={{
                    fontSize: 11,
                    fontWeight: 700,
                    fontFamily: "var(--font-mono)",
                    color:
                      liveStatus === "RUNNING"
                        ? "#10b981"
                        : liveStatus === "RUNNING_SIMULATED"
                        ? "#38bdf8"
                        : "var(--text-muted)",
                    background:
                      liveStatus === "RUNNING"
                        ? "rgba(16, 185, 129, 0.12)"
                        : liveStatus === "RUNNING_SIMULATED"
                        ? "rgba(56, 189, 248, 0.12)"
                        : "rgba(255,255,255,0.04)",
                    border: `1px solid ${
                      liveStatus === "RUNNING"
                        ? "rgba(16, 185, 129, 0.3)"
                        : liveStatus === "RUNNING_SIMULATED"
                        ? "rgba(56, 189, 248, 0.3)"
                        : "rgba(255,255,255,0.08)"
                    }`,
                    padding: "5px 12px",
                    borderRadius: 999,
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 6,
                    whiteSpace: "nowrap",
                  }}
                >
                  <span style={{
                    width: 6, height: 6, borderRadius: "50%",
                    background: liveStatus === "RUNNING" ? "#10b981" : liveStatus === "RUNNING_SIMULATED" ? "#38bdf8" : "var(--text-muted)",
                    boxShadow: liveStatus === "RUNNING" ? "0 0 8px #10b981" : liveStatus === "RUNNING_SIMULATED" ? "0 0 8px #38bdf8" : "none",
                  }} />
                  {liveStatus === "RUNNING"
                    ? "LIVE NPCAP ACTIVE"
                    : liveStatus === "RUNNING_SIMULATED"
                    ? "SIMULATED WIRE TAP"
                    : "STANDBY"}
                </span>
              </div>

              <div style={{
                background: "rgba(255,255,255,0.02)",
                border: "1px solid rgba(255,255,255,0.05)",
                padding: "6px 12px",
                borderRadius: 6,
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                fontFamily: "var(--font-mono)",
              }}>
                <span style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase" }}>Packets</span>
                <strong style={{ fontSize: 13, color: "#fff" }}>{liveStats.packets.toLocaleString()}</strong>
              </div>

              <div style={{
                background: "rgba(255,255,255,0.02)",
                border: "1px solid rgba(255,255,255,0.05)",
                padding: "6px 12px",
                borderRadius: 6,
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                fontFamily: "var(--font-mono)",
              }}>
                <span style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase" }}>Flows</span>
                <strong style={{ fontSize: 13, color: "var(--accent-cyan)" }}>{liveStats.flows.toLocaleString()}</strong>
              </div>

              <div style={{
                background: "rgba(255,255,255,0.02)",
                border: "1px solid rgba(255,255,255,0.05)",
                padding: "6px 12px",
                borderRadius: 6,
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                fontFamily: "var(--font-mono)",
              }}>
                <span style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase" }}>Evaluated</span>
                <strong style={{ fontSize: 13, color: "#a5b4fc" }}>{liveStats.windows.toLocaleString()}</strong>
              </div>

              {selectedWindow && (
                <div style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 180 }}>
                  <span style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", fontFamily: "var(--font-mono)" }}>Triage:</span>
                  <span style={{
                    fontSize: 11, fontWeight: 700, fontFamily: "var(--font-mono)",
                    color: getThreatMeta(selectedWindow.threat_level).color,
                    background: getThreatMeta(selectedWindow.threat_level).bg,
                    border: `1px solid ${getThreatMeta(selectedWindow.threat_level).border}`,
                    padding: "4px 10px", borderRadius: 999,
                    boxShadow: `0 0 12px ${getThreatMeta(selectedWindow.threat_level).color}22`,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                  }}>
                    #{selectedWindow.window + 1}: {selectedWindow.prediction} ({(selectedWindow.confidence * 100).toFixed(0)}%)
                  </span>
                </div>
              )}

              {liveStats.error && (
                <div style={{ gridColumn: "1 / -1", fontSize: 11, color: "#f59e0b", padding: "4px 8px", background: "rgba(245, 158, 11, 0.08)", borderRadius: 4, border: "1px solid rgba(245, 158, 11, 0.2)" }}>
                  ⚠️ {liveStats.error}
                </div>
              )}
            </div>

            {/* Live Flow Telemetry Stream */}
            {recentFlows.length > 0 && (
              <div
                style={{
                  background: "rgba(0,0,0,0.55)",
                  border: "1px solid rgba(255,255,255,0.08)",
                  borderRadius: 10,
                  padding: "12px 16px",
                  maxHeight: 140,
                  overflowY: "auto",
                  boxShadow: "inset 0 1px 3px rgba(0,0,0,0.4)",
                }}
              >
                <div style={{ fontSize: 10, fontWeight: 700, color: "var(--accent-cyan)", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--accent-cyan)", boxShadow: "0 0 6px var(--accent-cyan)" }} />
                  <span>Live Bidirectional 5-Tuple Connection Stream</span>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {recentFlows.slice().reverse().map((f, idx) => (
                    <div
                      key={idx}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        fontSize: 10,
                        fontFamily: "var(--font-mono)",
                        color: "var(--text-muted)",
                        padding: "4px 8px",
                        borderRadius: 4,
                        background: idx === 0 ? "rgba(56,189,248,0.12)" : "rgba(255,255,255,0.02)",
                        borderLeft: idx === 0 ? "2px solid var(--accent-cyan)" : "2px solid transparent",
                      }}
                    >
                      <span>
                        <strong style={{ color: "#38bdf8" }}>{f.src}</strong> <span style={{ color: "var(--text-dim)" }}>→</span> <strong style={{ color: "#f97316" }}>{f.dst}</strong>
                      </span>
                      <div style={{ display: "flex", gap: 14, alignItems: "center" }}>
                        <span style={{
                          color: f.proto === "TCP" ? "#a78bfa" : f.proto === "UDP" ? "#fbbf24" : "#6ee7b7",
                          fontWeight: 700, fontSize: 9,
                        }}>
                          {f.proto}
                        </span>
                        <span>{f.packets} pkts ({f.bytes >= 1024 ? `${(f.bytes / 1024).toFixed(1)}K` : f.bytes} B)</span>
                        <span style={{ color: "var(--text-dim)" }}>{f.duration_ms} ms</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Quick Threat Test Vector Chips */}
        <div style={{ marginTop: 14, paddingTop: 12, borderTop: "1px solid rgba(255,255,255,0.06)", display: "flex", alignItems: "center", gap: 7, flexWrap: "wrap" }}>
          <span style={{ fontSize: 10, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 0.8, marginRight: 4, fontFamily: "var(--font-mono)" }}>
            Quick Vectors:
          </span>
          {[
            { label: "DDoS SYN Flood", dot: "#ef4444", attack: "DDoS Attack" },
            { label: "PortScan Recon", dot: "#f97316", attack: "PortScan Probe" },
            { label: "Botnet C2 Beacon", dot: "#f59e0b", attack: "Botnet C2 Beaconing" },
            { label: "Zero-Day APT", dot: "#38bdf8", attack: "Zero-Day APT Exfiltration" },
            { label: "UNSW Exploits", dot: "#ef4444", attack: "UNSW Exploits" },
            { label: "UNSW Generic", dot: "#f43f5e", attack: "UNSW Generic" },
            { label: "UNSW Worms", dot: "#dc2626", attack: "UNSW Worms" },
            { label: "UNSW Normal", dot: "#10b981", attack: "UNSW Normal" },
            { label: "Benign Baseline", dot: "#10b981", attack: "Normal Traffic" },
          ].map((item) => (
            <button
              key={item.label}
              disabled={loading}
              onClick={async () => {
                if (inputMode === "live") {
                  setLoading(true);
                  try {
                    const res = await API.injectLiveAttack(item.attack, 35);
                    if (res.result && res.result.windows && res.result.windows.length > 0) {
                      setResult(res.result);
                      setSelectedWindow(res.result.windows[res.result.windows.length - 1]);
                    }
                    const st = await API.getLiveStatus();
                    setLiveStats({
                      packets: st.packets_captured,
                      flows: st.flows_completed,
                      windows: st.windows_processed,
                      error: st.error,
                    });
                    if (st.recent_flows) setRecentFlows(st.recent_flows);
                  } catch (e: any) {
                    setError(e.message ?? "Attack injection failed");
                  } finally {
                    setLoading(false);
                  }
                } else {
                  setInputMode("stream");
                  setStreamAttack(item.attack);
                  runStream(item.attack);
                }
              }}
              style={{
                fontSize: 11,
                fontWeight: 600,
                fontFamily: "var(--font-mono)",
                padding: "4px 10px",
                borderRadius: 999,
                background: "rgba(255, 255, 255, 0.03)",
                border: "1px solid rgba(255, 255, 255, 0.09)",
                color: "var(--text-muted)",
                cursor: "pointer",
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
                transition: "all 0.18s cubic-bezier(0.16, 1, 0.3, 1)",
                boxShadow: "0 1px 3px rgba(0,0,0,0.3)",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.color = "#fff";
                e.currentTarget.style.background = "rgba(255, 255, 255, 0.07)";
                e.currentTarget.style.borderColor = `${item.dot}80`;
                e.currentTarget.style.boxShadow = `0 0 10px ${item.dot}33`;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.color = "var(--text-muted)";
                e.currentTarget.style.background = "rgba(255, 255, 255, 0.03)";
                e.currentTarget.style.borderColor = "rgba(255, 255, 255, 0.09)";
                e.currentTarget.style.boxShadow = "0 1px 3px rgba(0,0,0,0.3)";
              }}
            >
              <span style={{
                width: 7,
                height: 7,
                borderRadius: "50%",
                background: item.dot,
                boxShadow: `0 0 6px ${item.dot}`,
                flexShrink: 0,
              }} />
              <span>{item.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* ── Loading scanner ─────────────────────────────────────────────────── */}
      {loading && (
        <div style={{
          background: "linear-gradient(135deg, rgba(8,16,32,0.97), rgba(12,23,44,0.97))",
          border: "1px solid var(--border)", borderRadius: "var(--radius-md)", padding: "32px 24px",
          textAlign: "center", position: "relative", overflow: "hidden",
          boxShadow: "var(--shadow-card)",
        }}>
          <div style={{
            position: "absolute", left: 0, right: 0,
            top: `${scanLine}%`, height: 2,
            background: "linear-gradient(90deg, transparent, var(--accent-cyan), transparent)",
            transition: "top 0.04s linear",
            boxShadow: "0 0 12px var(--accent-cyan)",
          }} />
          <Cpu size={32} color="var(--accent-cyan)" style={{ marginBottom: 12 }} />
          <div style={{ fontSize: 15, fontWeight: 800, color: "#fff", letterSpacing: -0.2 }}>MEIC-ViT Neural Inference Running</div>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4, fontFamily: "var(--font-mono)" }}>
            Mapping 35 normalized flows → 35×35 RGB tensors → Multi-Head Attention…
          </div>
          <div style={{ display: "flex", justifyContent: "center", gap: 14, marginTop: 18, flexWrap: "wrap" }}>
            {["Path A: Global Volumetric", "Path B: Row-Visual Convolutions", "Path C: Multi-Head Transformer"].map((p, i) => (
              <div key={p} style={{
                fontSize: 10, color: "var(--accent-cyan)", fontFamily: "var(--font-mono)",
                padding: "5px 12px", borderRadius: 999,
                background: "rgba(56,189,248,0.08)", border: "1px solid rgba(56,189,248,0.25)",
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

      {/* ── Live TAP Standing-by / Capturing Card ──────────────────────── */}
      {!result && !loading && inputMode === "live" && (
        <div className="panel" style={{ padding: "44px 24px", textAlign: "center", borderRadius: "var(--radius-md)", position: "relative", overflow: "hidden" }}>
          <div style={{
            position: "absolute", top: "50%", left: "50%",
            transform: "translate(-50%, -50%)",
            width: 300, height: 300,
            borderRadius: "50%",
            border: `1px solid ${liveStatus === "RUNNING" || liveStatus === "RUNNING_SIMULATED" ? "rgba(16, 185, 129, 0.12)" : "rgba(56, 189, 248, 0.1)"}`,
            pointerEvents: "none",
          }} />
          <div style={{
            width: 68, height: 68, borderRadius: "50%",
            background: liveStatus === "RUNNING" || liveStatus === "RUNNING_SIMULATED" ? "rgba(16, 185, 129, 0.12)" : "rgba(56, 189, 248, 0.12)",
            border: `1px solid ${liveStatus === "RUNNING" || liveStatus === "RUNNING_SIMULATED" ? "rgba(16, 185, 129, 0.3)" : "rgba(56, 189, 248, 0.3)"}`,
            display: "inline-flex", alignItems: "center", justifyContent: "center",
            boxShadow: liveStatus === "RUNNING" || liveStatus === "RUNNING_SIMULATED" ? "0 0 30px rgba(16, 185, 129, 0.3)" : "0 0 30px rgba(56, 189, 248, 0.25)",
            marginBottom: 18,
          }}>
            <Radio
              size={32}
              color={liveStatus === "RUNNING" || liveStatus === "RUNNING_SIMULATED" ? "#10b981" : "var(--accent-cyan)"}
            />
          </div>
          <div style={{ fontSize: 18, fontWeight: 800, color: "#fff", letterSpacing: -0.3 }}>
            {liveStatus === "RUNNING" || liveStatus === "RUNNING_SIMULATED"
              ? "Live Network Packet Sniffing Active"
              : "Live Network TAP Standing-by"}
          </div>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 6, maxWidth: 520, marginInline: "auto", lineHeight: 1.6 }}>
            {liveStatus === "RUNNING" || liveStatus === "RUNNING_SIMULATED"
              ? `Extracting 35-feature bidirectional flows in real-time (${liveStats.flows} flows collected). MEIC-ViT automatically evaluates each 35-flow sliding window, or immediately when you click STOP CAPTURE.`
              : "Select your active network interface (e.g. Wi-Fi) above and click START LIVE CAPTURE to begin sniffing live traffic from your computer."}
          </div>
          {(liveStatus === "RUNNING" || liveStatus === "RUNNING_SIMULATED") && (
            <div style={{ marginTop: 22, display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
              <div style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--text-dim)" }}>
                Current Window Ingestion:{" "}
                <strong style={{ color: "var(--accent-cyan)" }}>{liveStats.flows % 35} / 35 flows</strong>
              </div>
              <div style={{ width: 240, height: 5, background: "rgba(255, 255, 255, 0.08)", borderRadius: 999, overflow: "hidden" }}>
                <div style={{
                  width: `${((liveStats.flows % 35) / 35) * 100}%`,
                  height: "100%",
                  background: "linear-gradient(90deg, var(--accent-blue), var(--accent-cyan))",
                  borderRadius: 999,
                  transition: "width 0.3s ease",
                  boxShadow: "0 0 10px var(--accent-cyan)",
                }} />
              </div>
            </div>
          )}
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
              sub={attackCount > 0 ? `${attackCount} hostile windows detected` : "Network Clear"}
              color={topThreatMeta.color}
              icon={<ShieldX size={16} color={topThreatMeta.color} />}
              pulse={attackCount > 0}
            />
            <KpiCard
              label="Attack Windows"
              value={attackCount}
              sub={`${result.confirmed_threats_count ?? attackCount} confirmed • ${result.provisional_threats_count ?? 0} gated provisional`}
              color={attackCount > 0 ? "#ef4444" : "#10b981"}
              icon={<Target size={16} color={attackCount > 0 ? "#ef4444" : "#10b981"} />}
              pulse={attackCount > 0}
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
          {attackCount > 0 && (
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
                  {attackCount} malicious traffic windows detected •{" "}
                  {windows.length > 0 ? ((attackCount / windows.length) * 100).toFixed(1) : "0.0"}% of analyzed flows are hostile •{" "}
                  Threat Level: <strong style={{ color: topThreatMeta.color }}>{topThreat}</strong>
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
                {topThreat}
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
          <div className="pipeline-results-grid" style={{ display: "grid", gridTemplateColumns: "1.5fr 1fr", gap: 16, alignItems: "start" }}>

            {/* Left: Window Audit Table */}
            <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
              <div style={{ padding: "12px 14px 10px", borderBottom: "1px solid var(--border)" }}>
                <div className="panel-title">
                  <BarChart3 size={15} color="var(--accent-cyan)" />
                  <span>Per-Window Threat Audit ({windows.length} slices)</span>
                </div>
                <div style={{ display: "flex", gap: 6, marginTop: 10, flexWrap: "wrap", alignItems: "center" }}>
                  {["ALL", "CONFIRMED", "ATTACK", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((f) => (
                    <button
                      key={f}
                      onClick={() => setFilterLevel(f)}
                      style={{
                        fontSize: 10, fontWeight: 700, letterSpacing: 0.5, fontFamily: "var(--font-mono)",
                        padding: "4px 10px", borderRadius: 999, cursor: "pointer",
                        background: filterLevel === f ? "var(--accent-cyan)" : "rgba(255,255,255,0.03)",
                        color: filterLevel === f ? "#090d16" : "var(--text-muted)",
                        border: filterLevel === f ? "1px solid var(--accent-cyan)" : "1px solid rgba(255,255,255,0.08)",
                        boxShadow: filterLevel === f ? "0 0 12px rgba(56, 189, 248, 0.35)" : "none",
                        transition: "all 0.18s ease",
                      }}
                    >
                      {f === "CONFIRMED" ? "CONFIRMED ONLY (≥60%)" : f}
                    </button>
                  ))}
                  <span style={{ marginLeft: "auto", fontSize: 10, color: "var(--accent-cyan)", fontFamily: "var(--font-mono)" }}>
                    🛡️ Gating: 60% Threshold
                  </span>
                </div>
              </div>
              <div style={{ maxHeight: 360, overflowX: "auto", overflowY: "auto" }}>
                <table className="sensor-table" style={{ fontSize: 12 }}>
                  <thead>
                    <tr>
                      <th style={{ padding: "7px 10px" }}>WIN</th>
                      <th style={{ padding: "7px 8px" }}>PREDICTION</th>
                      <th style={{ padding: "7px 8px" }}>LEVEL</th>
                      <th style={{ padding: "7px 8px" }}>CONF</th>
                      <th style={{ padding: "7px 8px" }}>STATUS</th>
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
                        <td colSpan={6} style={{ textAlign: "center", padding: 24, color: "var(--text-dim)", fontSize: 12 }}>
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
                <div id="window-detail-inspector" className="panel" style={{ padding: 16 }}>
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
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase" }}>Predicted Class</div>
                      {selectedWindow.confidence_status && (
                        <span style={{
                          fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 3,
                          background: selectedWindow.confidence_status === "CONFIRMED" ? "rgba(16,185,129,0.2)" : "rgba(245,158,11,0.2)",
                          color: selectedWindow.confidence_status === "CONFIRMED" ? "#10b981" : "#f59e0b",
                          border: `1px solid ${selectedWindow.confidence_status === "CONFIRMED" ? "rgba(16,185,129,0.4)" : "rgba(245,158,11,0.4)"}`,
                        }}>
                          {selectedWindow.confidence_status} {selectedWindow.is_persistent ? "• PERSISTENT" : ""}
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: 15, fontWeight: 800, color: getThreatMeta(selectedWindow.threat_level).color, marginTop: 2 }}>
                      {selectedWindow.prediction}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                      Confidence: {(selectedWindow.confidence * 100).toFixed(1)}%
                    </div>
                    {selectedWindow.confidence_status !== "CONFIRMED" && selectedWindow.threat_level !== "LOW" && (
                      <div style={{ fontSize: 10, color: "#f59e0b", marginTop: 6, lineHeight: 1.3, background: "rgba(245,158,11,0.08)", padding: "4px 8px", borderRadius: 4 }}>
                        ℹ️ <strong>Early Boundary Slice (&lt;60% Conf):</strong> Gated provisional to prevent false alerts until consecutive windows confirm attack persistence.
                      </div>
                    )}
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

                  {/* ── Per-Window Flow Forensics Table ── */}
                  {selectedWindow.flows && selectedWindow.flows.length > 0 && (
                    <div style={{ marginTop: 14, paddingTop: 12, borderTop: "1px solid rgba(255,255,255,0.07)" }}>
                      {/* Header row */}
                      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
                        <div style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--accent-cyan)", flexShrink: 0 }} />
                        <span style={{ fontSize: 10, fontWeight: 700, color: "var(--accent-cyan)", textTransform: "uppercase", letterSpacing: 0.8 }}>
                          Flow Forensics
                        </span>
                        <span style={{ fontSize: 9, color: "var(--text-dim)", marginLeft: "auto", fontFamily: "var(--font-mono)" }}>
                          {selectedWindow.flows.length} connections in window #{selectedWindow.window + 1}
                        </span>
                      </div>

                      {/* Column labels */}
                      <div style={{
                        display: "grid",
                        gridTemplateColumns: "1fr 1fr 48px 52px 48px 52px",
                        fontSize: 8, fontWeight: 700, color: "var(--text-dim)",
                        textTransform: "uppercase", letterSpacing: 0.5,
                        padding: "2px 6px", marginBottom: 2,
                      }}>
                        <span>Source</span>
                        <span>Destination</span>
                        <span>Proto</span>
                        <span style={{ textAlign: "right" }}>Pkts</span>
                        <span style={{ textAlign: "right" }}>Bytes</span>
                        <span style={{ textAlign: "right" }}>Dur ms</span>
                      </div>

                      {/* Flow rows */}
                      <div style={{ maxHeight: 210, overflowY: "auto", display: "flex", flexDirection: "column", gap: 2 }}>
                        {selectedWindow.flows.map((f, idx) => (
                          <div key={idx} style={{
                            display: "grid",
                            gridTemplateColumns: "1fr 1fr 48px 52px 48px 52px",
                            alignItems: "center",
                            fontSize: 9, fontFamily: "var(--font-mono)",
                            padding: "4px 6px",
                            background: idx % 2 === 0 ? "rgba(255,255,255,0.028)" : "transparent",
                            borderRadius: 3,
                            gap: 4,
                          }}>
                            {/* Source IP:Port */}
                            <span style={{ color: "#38bdf8", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                                  title={`${f.src_ip}:${f.src_port}`}>
                              {f.src_ip}<span style={{ color: "var(--text-dim)" }}>:{f.src_port}</span>
                            </span>
                            {/* Dest IP:Port */}
                            <span style={{ color: "#f97316", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                                  title={`${f.dst_ip}:${f.dst_port}`}>
                              {f.dst_ip}<span style={{ color: "var(--text-dim)" }}>:{f.dst_port}</span>
                            </span>
                            {/* Protocol badge */}
                            <span style={{
                              color: f.proto === "TCP" ? "#a78bfa" : f.proto === "UDP" ? "#fbbf24" : "#6ee7b7",
                              fontWeight: 700, fontSize: 8,
                            }}>
                              {f.proto}
                            </span>
                            {/* Packets */}
                            <span style={{ color: "var(--text-dim)", textAlign: "right" }}>{f.packets}</span>
                            {/* Bytes */}
                            <span style={{ color: "var(--text-dim)", textAlign: "right" }}>
                              {f.bytes >= 1024
                                ? `${(f.bytes / 1024).toFixed(1)}K`
                                : f.bytes}
                            </span>
                            {/* Duration */}
                            <span style={{ color: "var(--text-dim)", textAlign: "right" }}>{f.duration_ms}</span>
                          </div>
                        ))}
                      </div>

                      {/* Mini legend */}
                      <div style={{ display: "flex", gap: 10, marginTop: 7, fontSize: 8, color: "var(--text-dim)" }}>
                        <span><span style={{ color: "#38bdf8" }}>■</span> SRC</span>
                        <span><span style={{ color: "#f97316" }}>■</span> DST</span>
                        <span><span style={{ color: "#a78bfa" }}>■</span> TCP</span>
                        <span><span style={{ color: "#fbbf24" }}>■</span> UDP</span>
                        <span><span style={{ color: "#6ee7b7" }}>■</span> ICMP</span>
                      </div>
                    </div>
                  )}
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
                const isAtk = !isBenignPrediction(w.prediction);
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
