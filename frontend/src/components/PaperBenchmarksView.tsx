import React from "react";
import { BarChart2, CheckCircle2, Award, Zap, Layers } from "lucide-react";

export const PaperBenchmarksView: React.FC = () => {
  const modelComparisons = [
    { model: "1D-CNN (Convolutional)", accuracy: "94.21%", precision: "93.90%", recall: "93.80%", f1: "93.85%", latency: "11.2 ms" },
    { model: "ResNet-50 (Deep Residual)", accuracy: "96.14%", precision: "95.92%", recall: "95.68%", f1: "95.80%", latency: "18.4 ms" },
    { model: "Standard ViT (Patch-based)", accuracy: "97.35%", precision: "97.20%", recall: "97.00%", f1: "97.10%", latency: "16.8 ms" },
    { model: "Swin Transformer (Shifted Windows)", accuracy: "98.22%", precision: "98.15%", recall: "97.95%", f1: "98.05%", latency: "22.5 ms" },
    { model: "MEIC-ViT (Proposed in Paper)", accuracy: "99.42%", precision: "99.45%", recall: "99.31%", f1: "99.38%", latency: "15.4 ms", isBest: true },
  ];

  const ablationResults = [
    { variant: "Path A only (Global Statistics)", accuracy: "96.82%", f1: "96.54%", description: "Captures macro distribution but loses local sequence order" },
    { variant: "Path B only (Row Visual)", accuracy: "97.45%", f1: "97.12%", description: "Captures 2D intra-burst correlation but lacks global bounds" },
    { variant: "Path C only (Sequential Content)", accuracy: "97.80%", f1: "97.55%", description: "Captures time-series ordering but sensitive to packet jitter" },
    { variant: "Full MEIC-ViT (3-Path Parallel)", accuracy: "99.42%", f1: "99.38%", isBest: true, description: "Synergistic multi-scale representation across all dimensions" },
  ];

  return (
    <div className="soc-content">
      {/* ── Top Highlight KPI Cards ── */}
      <div className="kpi-row">
        <div className="kpi-card">
          <div className="kpi-header">
            <span>CICIDS-2017 Overall Accuracy</span>
            <Award size={18} color="#10b981" />
          </div>
          <div className="kpi-value-row">
            <span className="kpi-number" style={{ color: "#10b981" }}>99.42%</span>
            <span className="kpi-status-opt">+2.07% vs ViT</span>
          </div>
          <div className="kpi-line-conf" />
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span>Macro F1-Score (All 15 Classes)</span>
            <BarChart2 size={18} color="#38bdf8" />
          </div>
          <div className="kpi-value-row">
            <span className="kpi-number" style={{ color: "#38bdf8" }}>99.38%</span>
            <span className="kpi-status-opt">Imbalanced Robust</span>
          </div>
          <div className="kpi-line-thru" />
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span>Inference Speed per 35-Flow Window</span>
            <Zap size={18} color="#f59e0b" />
          </div>
          <div className="kpi-value-row">
            <span className="kpi-number" style={{ color: "#fff" }}>15.4 ms</span>
            <span style={{ fontSize: 12, color: "var(--accent-amber)" }}>Real-Time Line-Rate</span>
          </div>
          <div className="kpi-line-threat" style={{ background: "#f59e0b" }} />
        </div>
      </div>

      {/* ── Table 1: Model Comparison (Paper Tables 4 & 5) ── */}
      <div className="panel" style={{ padding: 20 }}>
        <div className="panel-header">
          <div className="panel-title">
            <BarChart2 size={16} color="var(--accent-cyan)" />
            <span>Paper Table 4: Benchmark Comparison on CICIDS-2017</span>
          </div>
          <span style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
            15 Traffic Classes • Stratified 5-Fold Cross Validation
          </span>
        </div>

        <table className="sensor-table">
          <thead>
            <tr>
              <th>ARCHITECTURE</th>
              <th>ACCURACY</th>
              <th>PRECISION</th>
              <th>RECALL</th>
              <th>F1-SCORE</th>
              <th>LATENCY</th>
            </tr>
          </thead>
          <tbody>
            {modelComparisons.map((row) => (
              <tr
                key={row.model}
                style={{
                  background: row.isBest ? "rgba(16, 185, 129, 0.08)" : "transparent",
                  fontWeight: row.isBest ? 700 : 400,
                }}
              >
                <td style={{ color: row.isBest ? "#10b981" : "#fff" }}>
                  {row.model} {row.isBest && "★"}
                </td>
                <td style={{ fontFamily: "var(--font-mono)", color: row.isBest ? "#10b981" : "var(--text-main)" }}>
                  {row.accuracy}
                </td>
                <td style={{ fontFamily: "var(--font-mono)" }}>{row.precision}</td>
                <td style={{ fontFamily: "var(--font-mono)" }}>{row.recall}</td>
                <td style={{ fontFamily: "var(--font-mono)", color: row.isBest ? "#38bdf8" : "var(--text-main)" }}>
                  {row.f1}
                </td>
                <td style={{ fontFamily: "var(--font-mono)", color: "var(--text-dim)" }}>
                  {row.latency}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* ── Table 2: Ablation Study (Paper Table 6) ── */}
      <div className="panel" style={{ padding: 20 }}>
        <div className="panel-header">
          <div className="panel-title">
            <Layers size={16} color="var(--accent-purple)" />
            <span>Paper Table 6: Multi-Scale Feature Ablation Study</span>
          </div>
          <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
            Validating the necessity of the parallel three-path architecture
          </span>
        </div>

        <table className="sensor-table">
          <thead>
            <tr>
              <th>FEATURE PATH CONFIGURATION</th>
              <th>ACCURACY</th>
              <th>F1-SCORE</th>
              <th>ARCHITECTURAL RATIONALE</th>
            </tr>
          </thead>
          <tbody>
            {ablationResults.map((ab) => (
              <tr
                key={ab.variant}
                style={{
                  background: ab.isBest ? "rgba(16, 185, 129, 0.08)" : "transparent",
                  fontWeight: ab.isBest ? 700 : 400,
                }}
              >
                <td style={{ color: ab.isBest ? "#10b981" : "#fff" }}>
                  {ab.variant} {ab.isBest && "★"}
                </td>
                <td style={{ fontFamily: "var(--font-mono)", color: ab.isBest ? "#10b981" : "var(--text-main)" }}>
                  {ab.accuracy}
                </td>
                <td style={{ fontFamily: "var(--font-mono)", color: ab.isBest ? "#38bdf8" : "var(--text-main)" }}>
                  {ab.f1}
                </td>
                <td style={{ color: "var(--text-muted)", fontSize: 12 }}>
                  {ab.description}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
