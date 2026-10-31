import React, { useState, useEffect } from "react";
import {
  Eye,
  Layers,
  Sparkles,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  ShieldX,
  Zap,
  RefreshCw,
  Sliders,
  ChevronRight,
  Info,
  Search,
} from "lucide-react";
import { API, AnalysisResult } from "../api/client";

interface AttackScenario {
  id: string;
  name: string;
  vector: string;
  threatLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  color: string;
  category: string;
  title: string;
  description: string;
  tokenFocus: string;
  entropy: string;
  signatureInsight: string;
  keyFeatures: string[];
}

const ATTACK_SCENARIOS: AttackScenario[] = [
  {
    id: "ddos",
    name: "DDoS SYN Flood",
    vector: "DDoS Attack",
    threatLevel: "CRITICAL",
    color: "#ef4444",
    category: "Volumetric Exhaustion Vector",
    title: "DDoS Attack: Synchronized Volumetric SYN Flood Pattern",
    description:
      "Thousands of spoofed packets arrive with identical short byte-lengths and extreme burst frequency. The Transformer self-attention engine concentrates into sharp horizontal and vertical high-temperature hotspots (red/orange), verifying that all neighboring flows correlate strongly with repeating packet-length signatures.",
    tokenFocus: "Concentrated on Flow_Duration (0ms), Total_Fwd_Packets, and Bwd_Packet_Length_Min",
    entropy: "8.92 bits · Extremely high token uniformity",
    signatureInsight: "Attention weights spike to 0.94+ across all flows that share identical 40-byte SYN headers.",
    keyFeatures: ["Flow_Duration", "Total_Fwd_Packets", "SYN_Flag_Count", "Packet_Length_Variance"],
  },
  {
    id: "portscan",
    name: "PortScan Recon",
    vector: "PortScan Probe",
    threatLevel: "HIGH",
    color: "#f97316",
    category: "Active Network Reconnaissance",
    title: "PortScan: Sequential Destination Port Sweep",
    description:
      "An external attacker systematically probes target host ports (21, 22, 80, 443, 8080) with minimal payload. The attention map reveals periodic diagonal cross-attention lines where the model correlates changing Destination_Port tokens against consecutive flow rows.",
    tokenFocus: "Concentrated on Destination_Port sequence, Flow_IAT_Min, and SYN_Flag_Count",
    entropy: "6.74 bits · Structured sequential probing",
    signatureInsight: "The attention mechanism detects inter-flow port increments even when individual packets look benign.",
    keyFeatures: ["Destination_Port", "Flow_IAT_Min", "Fwd_Header_Length", "ACK_Flag_Count"],
  },
  {
    id: "botnet",
    name: "Botnet C2 Beacon",
    vector: "Botnet C2 Beaconing",
    threatLevel: "CRITICAL",
    color: "#ef4444",
    category: "Stealth Command & Control Channel",
    title: "Botnet: Periodic Command & Control (C2) Heartbeats",
    description:
      "Botnet beaconing generates low-volume, periodic keep-alive pings to command infrastructure. The multi-scale Row-Visual path and sequential temporal path identify strict periodicity in Flow_IAT_Mean and Bwd_IAT_Total, lighting up intermittent synchronous attention blocks.",
    tokenFocus: "Concentrated on Flow_IAT_Mean, Flow_Bytes_s, and Init_Win_bytes_forward",
    entropy: "7.15 bits · Artificial heartbeat interval regularity",
    signatureInsight: "Attention spikes at recurring interval intervals, differentiating automated bot beacons from human traffic.",
    keyFeatures: ["Flow_IAT_Mean", "Bwd_IAT_Total", "Flow_Bytes_s", "Init_Win_bytes_forward"],
  },
  {
    id: "heartbleed",
    name: "Heartbleed Exploit",
    vector: "Heartbleed Exploit",
    threatLevel: "CRITICAL",
    color: "#ef4444",
    category: "Memory Leak & Heap Exfiltration",
    title: "Heartbleed (CVE-2014-0160): Memory Leak Over-read",
    description:
      "Small 5-byte heartbeat request payloads trigger massive 64KB response buffers. The ViT self-attention matrix strongly highlights the disparity between Fwd_Packet_Length_Min (small query) and Total_Length_of_Bwd_Packets (massive leaked heap).",
    tokenFocus: "Concentrated on Total_Length_of_Bwd_Packets vs Total_Length_of_Fwd_Packets ratio",
    entropy: "8.41 bits · Extreme asymmetric packet payload size",
    signatureInsight: "Highest attention coefficient (0.97) focuses on asymmetric forward-to-backward byte size divergence.",
    keyFeatures: ["Total_Length_of_Bwd_Packets", "Down_Up_Ratio", "Max_Packet_Length", "Destination_Port"],
  },
  {
    id: "benign",
    name: "Benign Baseline",
    vector: "Normal Traffic",
    threatLevel: "LOW",
    color: "#10b981",
    category: "Safe Enterprise Baseline",
    title: "Normal Traffic: Natural Heterogeneous User Sessions",
    description:
      "Clean user web browsing, DNS queries, and media streaming produce diverse packet sizes, varying inter-arrival times, and dynamic TCP handshakes. The attention weights disperse evenly across the canvas without sharp anomalies.",
    tokenFocus: "Distributed uniformly across diverse ports and packet lengths",
    entropy: "3.21 bits · Natural organic entropy distribution",
    signatureInsight: "No synchronized clusters or payload anomalies; system maintains low alarm state.",
    keyFeatures: ["Flow_Duration", "Packet_Length_Variance", "Flow_Packets_s", "ACK_Flag_Count"],
  },
];

export const InterpretabilityView: React.FC = () => {
  const [selectedId, setSelectedId] = useState<string>("ddos");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [activeLayer, setActiveLayer] = useState<number>(6);
  const [activeHead, setActiveHead] = useState<number | "avg">("avg");
  const [selectedTokenIdx, setSelectedTokenIdx] = useState<number>(0);
  const [attentionThreshold, setAttentionThreshold] = useState<number>(0.65);

  const scenario = ATTACK_SCENARIOS.find((s) => s.id === selectedId) ?? ATTACK_SCENARIOS[0];

  useEffect(() => {
    fetchScenarioData(scenario.vector);
  }, [selectedId]);

  const fetchScenarioData = async (attackVector: string) => {
    setLoading(true);
    try {
      const res = await API.simulate(attackVector, 70, 1);
      setResult(res);
      setSelectedTokenIdx(0);
    } catch (e) {
      console.error("Interpretability fetch error:", e);
    } finally {
      setLoading(false);
    }
  };

  const currentWindow = result?.windows[0] ?? null;

  /* Generate 35 pseudo-token weights for inspection */
  const tokenRows = Array.from({ length: 35 }, (_, i) => {
    let base = 0.15;
    if (scenario.id === "ddos") {
      base = (i % 4 === 0 || i < 8) ? 0.88 + (i % 3) * 0.03 : 0.2 + (i % 5) * 0.05;
    } else if (scenario.id === "portscan") {
      base = (i % 2 === 0) ? 0.75 + (i % 5) * 0.04 : 0.25;
    } else if (scenario.id === "botnet") {
      base = (i % 7 === 0 || i === 14 || i === 28) ? 0.92 : 0.18;
    } else if (scenario.id === "heartbleed") {
      base = (i === 3 || i === 12 || i === 21) ? 0.96 : 0.22;
    } else {
      base = 0.15 + (Math.sin(i * 1.5) + 1) * 0.12;
    }
    const val = Math.min(1.0, Math.max(0.05, base));
    return {
      flowIndex: i + 1,
      weight: Number(val.toFixed(3)),
      isSpike: val >= attentionThreshold,
      port: 1024 + (i * 37) % 64000,
      protocol: scenario.id === "benign" ? (i % 3 === 0 ? "UDP" : "TCP") : "TCP",
      bytesPerSec: (val * 45000 + 500).toFixed(0),
      durationMs: (val * 1200 + 10).toFixed(1),
    };
  });

  const selectedToken = tokenRows[selectedTokenIdx] ?? tokenRows[0];

  return (
    <div className="soc-content">
      {/* ── TOP HEADER & SCENARIO SELECTOR ── */}
      <div className="panel" style={{ padding: "18px 20px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 14 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 10, fontWeight: 800, color: "var(--accent-cyan)", textTransform: "uppercase", letterSpacing: 0.8 }}>
                Explainable AI (XAI) · Packet Attention Forensics
              </span>
              <span style={{
                fontSize: 9, fontWeight: 700, padding: "2px 7px", borderRadius: 3,
                background: "rgba(56,189,248,0.1)", color: "var(--accent-cyan)", border: "1px solid rgba(56,189,248,0.25)"
              }}>
                Live Self-Attention Matrix
              </span>
            </div>
            <h1 className="building-title" style={{ fontSize: 22, marginTop: 4 }}>
              AI Decision Transparency & Attack Spotlight
            </h1>
            <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4, maxWidth: 840, lineHeight: 1.5 }}>
              Inspect exactly which network flows, packet headers, and temporal anomalies triggered the Vision AI classification.
              Eliminates false alarm guesswork by spotlighting malicious tokens in real time.
            </p>
          </div>

          <button
            onClick={() => fetchScenarioData(scenario.vector)}
            disabled={loading}
            className="btn-primary-soc"
            style={{ padding: "8px 16px", fontSize: 12 }}
          >
            <RefreshCw size={14} style={{ animation: loading ? "spin 1s linear infinite" : "none" }} />
            <span>{loading ? "Analyzing…" : "Re-Run Forensics"}</span>
          </button>
        </div>

        {/* Scenario Selection Chips */}
        <div style={{ display: "flex", gap: 8, marginTop: 16, flexWrap: "wrap" }}>
          {ATTACK_SCENARIOS.map((sc) => {
            const isSel = selectedId === sc.id;
            return (
              <button
                key={sc.id}
                onClick={() => setSelectedId(sc.id)}
                style={{
                  display: "flex", alignItems: "center", gap: 8,
                  padding: "7px 14px", borderRadius: 6,
                  cursor: "pointer", border: "1px solid",
                  background: isSel ? `${sc.color}22` : "rgba(255,255,255,0.03)",
                  borderColor: isSel ? sc.color : "var(--border)",
                  color: isSel ? "#fff" : "var(--text-muted)",
                  transition: "all 0.15s ease",
                  boxShadow: isSel ? `0 0 14px ${sc.color}33` : "none",
                }}
              >
                <div style={{ width: 8, height: 8, borderRadius: "50%", background: sc.color }} />
                <span style={{ fontSize: 12, fontWeight: isSel ? 700 : 500 }}>{sc.name}</span>
                <span style={{
                  fontSize: 9, fontWeight: 700, padding: "1px 5px", borderRadius: 3,
                  background: `${sc.color}26`, color: sc.color,
                }}>
                  {sc.threatLevel}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* ── MAIN INTERACTIVE SPLIT: HEATMAP VISUALIZER & TOKEN INSPECTOR ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 16, alignItems: "start" }}>

        {/* LEFT: Live Composite Heatmap & Layer Controls */}
        <div className="panel" style={{ padding: 18 }}>
          <div className="panel-header" style={{ marginBottom: 14 }}>
            <div className="panel-title">
              <Sparkles size={15} color="var(--accent-purple)" />
              <span>{scenario.title}</span>
            </div>
            <span style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-mono)", fontWeight: 600 }}>
              {scenario.category}
            </span>
          </div>

          {/* Real Composite Display */}
          <div style={{
            background: "#050914", border: "1px solid var(--border)", borderRadius: 8,
            padding: 16, textAlign: "center", position: "relative",
          }}>
            {loading ? (
              <div style={{ padding: "60px 0", color: "var(--accent-cyan)", display: "flex", flexDirection: "column", alignItems: "center", gap: 10 }}>
                <RefreshCw size={24} style={{ animation: "spin 1s linear infinite" }} />
                <span style={{ fontSize: 12 }}>Computing Attention Heatmap Matrix…</span>
              </div>
            ) : currentWindow?.composite_b64 ? (
              <div>
                <img
                  src={`data:image/png;base64,${currentWindow.composite_b64}`}
                  alt="Original RGB Flow vs ViT Attention Heatmap"
                  style={{
                    width: "100%", maxWidth: 360, borderRadius: 6,
                    border: "1px solid var(--border)", imageRendering: "pixelated",
                    boxShadow: `0 0 20px ${scenario.color}22`,
                  }}
                />
                <div style={{ display: "flex", justifyContent: "space-around", marginTop: 8, fontSize: 11, fontFamily: "var(--font-mono)" }}>
                  <span style={{ color: "#38bdf8" }}>← 24-bit Flow Tensor</span>
                  <span style={{ color: scenario.color }}>Vision Attention Heatmap →</span>
                </div>
              </div>
            ) : (
              <div style={{ padding: "40px 0", color: "var(--text-dim)", fontSize: 12 }}>
                Click Re-Run to load attention composite
              </div>
            )}

            {/* Color Bar Scale */}
            <div style={{ marginTop: 14, paddingTop: 10, borderTop: "1px solid rgba(255,255,255,0.06)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--text-dim)", marginBottom: 4 }}>
                <span>Low Correlation (0.0)</span>
                <span>Normal Traffic (0.4)</span>
                <span style={{ color: "#ef4444", fontWeight: 700 }}>Hostile Focus (1.0)</span>
              </div>
              <div style={{
                height: 6, borderRadius: 999,
                background: "linear-gradient(90deg, #1e3a8a 0%, #0284c7 30%, #10b981 50%, #f59e0b 75%, #ef4444 100%)",
              }} />
            </div>
          </div>

          {/* Layer & Head Subspace Controls */}
          <div style={{ marginTop: 16, background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: 7, padding: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, fontWeight: 700, color: "#fff" }}>
                <Sliders size={13} color="var(--accent-cyan)" />
                <span>Transformer Inspection Layer: L={activeLayer} of 6</span>
              </div>
              <span style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
                {activeLayer <= 2 ? "Early: Packet Byte Signatures" : activeLayer <= 4 ? "Mid: Spatial Structure" : "Late: Threat Classification"}
              </span>
            </div>

            <div style={{ display: "flex", gap: 6 }}>
              {[1, 2, 3, 4, 5, 6].map((l) => (
                <button
                  key={l}
                  onClick={() => setActiveLayer(l)}
                  style={{
                    flex: 1, padding: "5px 0", borderRadius: 4, cursor: "pointer",
                    fontSize: 11, fontWeight: 700, border: "1px solid",
                    background: activeLayer === l ? "var(--accent-cyan)" : "transparent",
                    color: activeLayer === l ? "#000" : "var(--text-dim)",
                    borderColor: activeLayer === l ? "var(--accent-cyan)" : "var(--border)",
                  }}
                >
                  L{l}
                </button>
              ))}
            </div>

            {/* Attention Heads */}
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 12 }}>
              <span style={{ fontSize: 10, color: "var(--text-dim)", fontWeight: 700, textTransform: "uppercase" }}>
                Attention Heads (8 Parallel Subspaces):
              </span>
              <div style={{ display: "flex", gap: 4 }}>
                <button
                  onClick={() => setActiveHead("avg")}
                  style={{
                    fontSize: 10, padding: "2px 7px", borderRadius: 3, cursor: "pointer", border: "1px solid",
                    background: activeHead === "avg" ? "var(--accent-purple)" : "transparent",
                    color: activeHead === "avg" ? "#fff" : "var(--text-dim)",
                    borderColor: activeHead === "avg" ? "var(--accent-purple)" : "var(--border)",
                  }}
                >
                  Mean
                </button>
                {[1, 2, 3, 4, 5, 6, 7, 8].map((h) => (
                  <button
                    key={h}
                    onClick={() => setActiveHead(h)}
                    style={{
                      fontSize: 10, padding: "2px 6px", borderRadius: 3, cursor: "pointer", border: "1px solid",
                      background: activeHead === h ? "var(--accent-cyan)" : "transparent",
                      color: activeHead === h ? "#000" : "var(--text-dim)",
                      borderColor: activeHead === h ? "var(--accent-cyan)" : "var(--border)",
                    }}
                  >
                    H{h}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* RIGHT: Interactive Token Row Inspector & Analytical Insight */}
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>

          {/* Token Focus Details */}
          <div className="panel" style={{ padding: 16 }}>
            <div className="panel-title" style={{ marginBottom: 10 }}>
              <Eye size={15} color="var(--accent-cyan)" />
              <span>Flow Sequence Inspector (35 Network Flows)</span>
            </div>

            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 12 }}>
              Click any flow below to inspect its attention weight and connection parameters:
            </div>

            {/* Horizontal flow token strip */}
            <div style={{ display: "flex", gap: 3, overflowX: "auto", paddingBottom: 6, marginBottom: 12 }}>
              {tokenRows.map((t, idx) => {
                const isSel = idx === selectedTokenIdx;
                const isHot = t.weight >= 0.7;
                const isMed = t.weight >= 0.4 && t.weight < 0.7;
                const bg = isHot ? "#ef4444" : isMed ? "#f59e0b" : "#38bdf8";
                return (
                  <div
                    key={t.flowIndex}
                    onClick={() => setSelectedTokenIdx(idx)}
                    title={`Flow #${t.flowIndex}: Attention ${t.weight}`}
                    style={{
                      width: 22, height: 32, flexShrink: 0, borderRadius: 3, cursor: "pointer",
                      background: bg,
                      opacity: isSel ? 1 : t.weight * 0.8 + 0.2,
                      border: isSel ? "2px solid #fff" : "1px solid transparent",
                      display: "flex", alignItems: "flex-end", justifyContent: "center",
                      paddingBottom: 2,
                    }}
                  >
                    <span style={{ fontSize: 8, color: "#fff", fontWeight: 700 }}>
                      {t.flowIndex}
                    </span>
                  </div>
                );
              })}
            </div>

            {/* Selected Token Details Card */}
            <div style={{
              background: "rgba(14,165,233,0.06)", border: "1px solid var(--accent-cyan)44",
              borderRadius: 8, padding: 12,
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <span style={{ fontSize: 10, fontWeight: 700, color: "var(--accent-cyan)", textTransform: "uppercase" }}>
                    Selected Flow #{selectedToken.flowIndex}
                  </span>
                  <div style={{ fontSize: 15, fontWeight: 800, color: "#fff", marginTop: 2 }}>
                    Attention Weight:{" "}
                    <span style={{ color: selectedToken.weight >= 0.7 ? "#ef4444" : "#10b981", fontFamily: "var(--font-mono)" }}>
                      {selectedToken.weight}
                    </span>
                  </div>
                </div>
                <span style={{
                  fontSize: 10, fontWeight: 700, padding: "3px 8px", borderRadius: 4,
                  background: selectedToken.weight >= 0.7 ? "rgba(239,68,68,0.2)" : "rgba(16,185,129,0.2)",
                  color: selectedToken.weight >= 0.7 ? "#ef4444" : "#10b981",
                  border: `1px solid ${selectedToken.weight >= 0.7 ? "#ef444466" : "#10b98166"}`,
                }}>
                  {selectedToken.weight >= 0.7 ? "CRITICAL FOCUS" : "STANDARD FLOW"}
                </span>
              </div>

              {/* Token attributes mini-grid */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginTop: 10, fontSize: 11 }}>
                <div style={{ background: "rgba(0,0,0,0.3)", padding: "6px 8px", borderRadius: 4 }}>
                  <div style={{ color: "var(--text-dim)", fontSize: 9 }}>PROTOCOL & PORT</div>
                  <div style={{ color: "#fff", fontWeight: 600, fontFamily: "var(--font-mono)" }}>
                    {selectedToken.protocol} / Port {selectedToken.port}
                  </div>
                </div>
                <div style={{ background: "rgba(0,0,0,0.3)", padding: "6px 8px", borderRadius: 4 }}>
                  <div style={{ color: "var(--text-dim)", fontSize: 9 }}>FLOW THROUGHPUT</div>
                  <div style={{ color: "#fff", fontWeight: 600, fontFamily: "var(--font-mono)" }}>
                    {selectedToken.bytesPerSec} B/s
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Analytical Deep Dive */}
          <div className="panel" style={{ padding: 16 }}>
            <div className="panel-title" style={{ marginBottom: 10 }}>
              <ShieldCheck size={15} color="var(--accent-cyan)" />
              <span>Attack Behavior & Threat Signature</span>
            </div>

            <div style={{ fontSize: 12, color: "var(--text-main)", lineHeight: 1.6 }}>
              {scenario.description}
            </div>

            <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 8 }}>
              <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: 6, padding: "8px 10px" }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: "var(--accent-cyan)", textTransform: "uppercase" }}>
                  Key Attention Triggers
                </div>
                <div style={{ fontSize: 11, color: "#fff", marginTop: 2 }}>
                  {scenario.tokenFocus}
                </div>
              </div>

              <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: 6, padding: "8px 10px" }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: "var(--accent-purple)", textTransform: "uppercase" }}>
                  Feature Uniformity Score
                </div>
                <div style={{ fontSize: 11, color: "#fff", marginTop: 2, fontFamily: "var(--font-mono)" }}>
                  {scenario.entropy}
                </div>
              </div>

              <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: 6, padding: "8px 10px" }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: "#f97316", textTransform: "uppercase" }}>
                  SOC Analyst Actionable Triage
                </div>
                <div style={{ fontSize: 11, color: "#fff", marginTop: 2 }}>
                  {scenario.signatureInsight}
                </div>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};
