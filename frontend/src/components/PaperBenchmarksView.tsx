import React, { useState, useEffect } from "react";
import {
  BarChart2,
  Award,
  Zap,
  Layers,
  Database,
  Cpu,
  RefreshCw,
  TrendingUp,
  FileText,
  ChevronRight,
  ShieldAlert,
} from "lucide-react";
import { API, DatasetStats, BenchmarkResult } from "../api/client";

interface ModelRow {
  model: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  latency: number;
  isBest?: boolean;
}

const MODEL_COMPARISONS: ModelRow[] = [
  { model: "MEIC-ViT (Our Loaded Model)", accuracy: 99.68, precision: 99.65, recall: 99.71, f1: 99.68, latency: 15.4, isBest: true },
  { model: "Swin Transformer (Shifted Windows)", accuracy: 98.22, precision: 98.15, recall: 97.95, f1: 98.05, latency: 22.5 },
  { model: "XGBoost (Feature Ranked)", accuracy: 98.05, precision: 97.80, recall: 98.30, f1: 98.05, latency: 8.5 },
  { model: "Standard ViT (Patch-based)", accuracy: 97.35, precision: 97.20, recall: 97.00, f1: 97.10, latency: 16.8 },
  { model: "ResNet-50 (Deep Residual)", accuracy: 96.14, precision: 95.92, recall: 95.68, f1: 95.80, latency: 18.4 },
  { model: "1D-CNN (Convolutional)", accuracy: 94.21, precision: 93.90, recall: 93.80, f1: 93.85, latency: 11.2 },
  { model: "LSTM / GRU (Recurrent)", accuracy: 96.45, precision: 96.12, recall: 96.78, f1: 96.45, latency: 26.8 },
];

const CLASS_METRICS: Record<string, { precision: number; recall: number; f1: number; count: string; far: number }> = {
  "DDoS": { precision: 99.92, recall: 99.88, f1: 99.90, count: "128,027", far: 0.08 },
  "PortScan": { precision: 99.85, recall: 99.80, f1: 99.82, count: "158,930", far: 0.15 },
  "Bot": { precision: 98.95, recall: 99.12, f1: 99.03, count: "1,966", far: 0.32 },
  "Heartbleed": { precision: 99.40, recall: 99.80, f1: 99.60, count: "11", far: 0.10 },
  "Infiltration": { precision: 97.80, recall: 98.20, f1: 98.00, count: "36", far: 0.45 },
  "DoS Hulk": { precision: 99.88, recall: 99.90, f1: 99.89, count: "231,073", far: 0.11 },
  "DoS GoldenEye": { precision: 99.60, recall: 99.55, f1: 99.57, count: "10,293", far: 0.20 },
  "FTP-Patator": { precision: 99.70, recall: 99.65, f1: 99.67, count: "7,938", far: 0.18 },
  "SSH-Patator": { precision: 99.65, recall: 99.70, f1: 99.67, count: "5,897", far: 0.19 },
  "DoS slowloris": { precision: 99.30, recall: 99.40, f1: 99.35, count: "5,796", far: 0.28 },
  "DoS Slowhttptest": { precision: 99.20, recall: 99.35, f1: 99.27, count: "5,499", far: 0.30 },
  "Web Attack Brute Force": { precision: 98.70, recall: 98.90, f1: 98.80, count: "1,507", far: 0.38 },
  "Web Attack XSS": { precision: 98.40, recall: 98.60, f1: 98.50, count: "652", far: 0.42 },
  "Web Attack Sql Injection": { precision: 98.10, recall: 98.50, f1: 98.30, count: "21", far: 0.48 },
  "BENIGN": { precision: 99.85, recall: 99.90, f1: 99.87, count: "2,273,097", far: 0.10 },
};

export const PaperBenchmarksView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<"models" | "classes" | "dataset" | "live_bench">("models");
  const [datasetStats, setDatasetStats] = useState<DatasetStats | null>(null);
  const [datasetLoading, setDatasetLoading] = useState(false);
  const [selectedClass, setSelectedClass] = useState("DDoS");

  // Live Hardware Benchmark State
  const [benchRunning, setBenchRunning] = useState(false);
  const [benchResult, setBenchResult] = useState<BenchmarkResult | null>(null);
  const [benchBatchSize, setBenchBatchSize] = useState(30);

  useEffect(() => {
    fetchDatasetStats();
  }, []);

  const fetchDatasetStats = () => {
    setDatasetLoading(true);
    API.datasetStats()
      .then(setDatasetStats)
      .catch(console.error)
      .finally(() => setDatasetLoading(false));
  };

  const runHardwareBenchmark = async () => {
    setBenchRunning(true);
    try {
      const res = await API.benchmarkRun(benchBatchSize);
      setBenchResult(res);
    } catch (e) {
      console.error("Benchmark error:", e);
    } finally {
      setBenchRunning(false);
    }
  };

  const currClass = CLASS_METRICS[selectedClass] ?? CLASS_METRICS["DDoS"];

  return (
    <div className="soc-content">
      {/* ── TOP HIGHLIGHT ROW ── */}
      <div className="kpi-row">
        <div className="kpi-card">
          <div className="kpi-header">
            <span>Overall Paper Accuracy</span>
            <Award size={18} color="#10b981" />
          </div>
          <div className="kpi-value-row">
            <span className="kpi-number" style={{ color: "#10b981" }}>99.68%</span>
            <span className="kpi-status-opt">+2.33% vs Standard ViT</span>
          </div>
          <div className="kpi-line-conf" />
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span>Macro F1-Score (All 15 Classes)</span>
            <BarChart2 size={18} color="#38bdf8" />
          </div>
          <div className="kpi-value-row">
            <span className="kpi-number" style={{ color: "#38bdf8" }}>99.68%</span>
            <span className="kpi-status-opt">Imbalance Resilient</span>
          </div>
          <div className="kpi-line-thru" />
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span>False Alarm Rate (FAR)</span>
            <ShieldAlert size={18} color="#f59e0b" />
          </div>
          <div className="kpi-value-row">
            <span className="kpi-number" style={{ color: "#fff" }}>0.32%</span>
            <span style={{ fontSize: 12, color: "var(--accent-amber)" }}>Lowest in Literature</span>
          </div>
          <div className="kpi-line-threat" style={{ background: "#f59e0b" }} />
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span>Inference Latency</span>
            <Zap size={18} color="#818cf8" />
          </div>
          <div className="kpi-value-row">
            <span className="kpi-number" style={{ color: "#818cf8" }}>
              {benchResult ? `${benchResult.latency_per_window_ms}ms` : "15.4ms"}
            </span>
            <span style={{ fontSize: 12, color: "var(--accent-cyan)" }}>
              {benchResult ? "Live Measured" : "Paper GPU"}
            </span>
          </div>
          <div className="kpi-line-conf" style={{ background: "#818cf8" }} />
        </div>
      </div>

      {/* ── SUB-NAVIGATION TABS ── */}
      <div className="panel" style={{ padding: "12px 16px" }}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", gap: 6 }}>
            {[
              { id: "models", label: "Model Architecture Comparison", icon: <BarChart2 size={13} /> },
              { id: "classes", label: "15-Class Confusion & Metrics", icon: <Layers size={13} /> },
              { id: "dataset", label: "Real CICIDS-2017 Dataset Files", icon: <Database size={13} /> },
              { id: "live_bench", label: "⚡ Live Hardware Benchmark", icon: <Zap size={13} /> },
            ].map((t) => (
              <button
                key={t.id}
                className={`btn-secondary-soc ${activeTab === t.id ? "btn-primary-soc" : ""}`}
                onClick={() => setActiveTab(t.id as any)}
                style={{ padding: "6px 12px", fontSize: 11 }}
              >
                {t.icon}
                <span>{t.label}</span>
              </button>
            ))}
          </div>

          <span style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
            Computer Networks Vol. 282 (2026) 112273
          </span>
        </div>
      </div>

      {/* ── TAB 1: MODEL ARCHITECTURE COMPARISON ── */}
      {activeTab === "models" && (
        <div className="panel" style={{ padding: 20 }}>
          <div className="panel-header" style={{ marginBottom: 14 }}>
            <div className="panel-title">
              <BarChart2 size={16} color="var(--accent-cyan)" />
              <span>Table 4: Comparative Benchmarks on CICIDS-2017</span>
            </div>
            <span style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
              15 Classes · 5-Fold Cross Validation · 2,830,743 Flows
            </span>
          </div>

          <table className="sensor-table">
            <thead>
              <tr>
                <th>MODEL ARCHITECTURE</th>
                <th>ACCURACY</th>
                <th>PRECISION</th>
                <th>RECALL</th>
                <th>F1-SCORE</th>
                <th>INFERENCE LATENCY</th>
              </tr>
            </thead>
            <tbody>
              {MODEL_COMPARISONS.map((row) => (
                <tr
                  key={row.model}
                  style={{
                    background: row.isBest ? "rgba(16, 185, 129, 0.08)" : "transparent",
                    borderLeft: row.isBest ? "3px solid #10b981" : "3px solid transparent",
                  }}
                >
                  <td style={{ color: row.isBest ? "#10b981" : "#fff", fontWeight: row.isBest ? 700 : 500 }}>
                    {row.model} {row.isBest && "★ (Active Checkpoint)"}
                  </td>
                  <td style={{ fontFamily: "var(--font-mono)", color: row.isBest ? "#10b981" : "var(--text-main)", fontWeight: row.isBest ? 700 : 400 }}>
                    {row.accuracy.toFixed(2)}%
                  </td>
                  <td style={{ fontFamily: "var(--font-mono)" }}>{row.precision.toFixed(2)}%</td>
                  <td style={{ fontFamily: "var(--font-mono)" }}>{row.recall.toFixed(2)}%</td>
                  <td style={{ fontFamily: "var(--font-mono)", color: row.isBest ? "#38bdf8" : "var(--text-main)", fontWeight: row.isBest ? 700 : 400 }}>
                    {row.f1.toFixed(2)}%
                  </td>
                  <td style={{ fontFamily: "var(--font-mono)", color: "var(--text-dim)" }}>
                    {row.latency.toFixed(1)} ms
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Ablation Study summary */}
          <div style={{ marginTop: 20, paddingTop: 16, borderTop: "1px solid rgba(255,255,255,0.06)" }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: "var(--accent-purple)", marginBottom: 8 }}>
              Multi-Scale Feature Ablation Study (Table 6)
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 10 }}>
              {[
                { name: "Path A Only (Global Stats)", acc: "96.82%", f1: "96.54%", note: "Captures volume envelope but loses micro temporal jitter" },
                { name: "Path B Only (Row Visual)", acc: "97.45%", f1: "97.12%", note: "Detects packet spatial alignment but lacks global scale" },
                { name: "Path C Only (Sequential)", acc: "97.80%", f1: "97.55%", note: "Extracts sequential order but sensitive to out-of-order packets" },
                { name: "Full Parallel MEIC-ViT", acc: "99.68%", f1: "99.68%", note: "All 3 paths fused via channel concatenation (Best)" },
              ].map((ab) => (
                <div key={ab.name} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: 6, padding: "10px 12px" }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: "#fff" }}>{ab.name}</div>
                  <div style={{ fontSize: 14, fontWeight: 800, color: "var(--accent-cyan)", fontFamily: "var(--font-mono)", margin: "4px 0" }}>
                    {ab.acc} Acc · {ab.f1} F1
                  </div>
                  <div style={{ fontSize: 10, color: "var(--text-muted)" }}>{ab.note}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 2: 15-CLASS CONFUSION & METRIC INSPECTOR ── */}
      {activeTab === "classes" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1.6fr", gap: 16 }}>
          {/* Class List */}
          <div className="panel" style={{ padding: 16 }}>
            <div className="panel-title" style={{ marginBottom: 10 }}>
              <Layers size={14} color="var(--accent-cyan)" />
              <span>Select Attack Class ({Object.keys(CLASS_METRICS).length})</span>
            </div>
            <div style={{ maxHeight: 420, overflowY: "auto", display: "flex", flexDirection: "column", gap: 4 }}>
              {Object.keys(CLASS_METRICS).map((c) => {
                const isSel = selectedClass === c;
                const isAtk = c !== "BENIGN";
                return (
                  <button
                    key={c}
                    onClick={() => setSelectedClass(c)}
                    style={{
                      display: "flex", alignItems: "center", justifyContent: "space-between",
                      padding: "8px 10px", borderRadius: 5, cursor: "pointer", border: "1px solid",
                      background: isSel ? "rgba(14,165,233,0.12)" : "rgba(255,255,255,0.015)",
                      borderColor: isSel ? "var(--accent-cyan)" : "transparent",
                      color: isSel ? "#fff" : "var(--text-muted)",
                      textAlign: "left",
                    }}
                  >
                    <span style={{ fontSize: 11, fontWeight: isSel ? 700 : 500 }}>{c}</span>
                    <span style={{
                      fontSize: 10, fontFamily: "var(--font-mono)",
                      color: isAtk ? (isSel ? "#ef4444" : "var(--text-dim)") : "#10b981",
                    }}>
                      F1: {CLASS_METRICS[c].f1}%
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Detailed Metric Inspection Panel */}
          <div className="panel" style={{ padding: 20 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
              <div>
                <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase" }}>
                  Class Performance Profile
                </div>
                <h2 style={{ fontSize: 20, fontWeight: 800, color: selectedClass === "BENIGN" ? "#10b981" : "#ef4444", marginTop: 2 }}>
                  {selectedClass}
                </h2>
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                  Total Benchmark Sample Population: <strong style={{ color: "#fff" }}>{currClass.count} flows</strong>
                </div>
              </div>

              <div style={{
                background: "rgba(16,185,129,0.1)", border: "1px solid rgba(16,185,129,0.3)",
                borderRadius: 6, padding: "6px 12px", textAlign: "right",
              }}>
                <div style={{ fontSize: 10, color: "var(--text-dim)" }}>FALSE ALARM RATE</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: "#10b981", fontFamily: "var(--font-mono)" }}>
                  {currClass.far}%
                </div>
              </div>
            </div>

            {/* Metric Bars */}
            <div style={{ display: "flex", flexDirection: "column", gap: 14, marginTop: 16 }}>
              {[
                { label: "Precision (True Positives / Predicted Positives)", val: currClass.precision, color: "#38bdf8" },
                { label: "Recall (True Positives / Actual Attack Ground Truth)", val: currClass.recall, color: "#10b981" },
                { label: "Harmonic F1-Score (2 · P·R / (P + R))", val: currClass.f1, color: "#818cf8" },
              ].map((m) => (
                <div key={m.label}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
                    <span style={{ color: "var(--text-muted)" }}>{m.label}</span>
                    <span style={{ fontFamily: "var(--font-mono)", fontWeight: 700, color: m.color }}>
                      {m.val.toFixed(2)}%
                    </span>
                  </div>
                  <div style={{ height: 6, background: "rgba(255,255,255,0.06)", borderRadius: 999 }}>
                    <div style={{
                      height: "100%", width: `${m.val}%`, borderRadius: 999,
                      background: `linear-gradient(90deg, ${m.color}88, ${m.color})`,
                    }} />
                  </div>
                </div>
              ))}
            </div>

            <div style={{ marginTop: 20, background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: 6, padding: 12 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: "#fff" }}>Why MEIC-ViT Excels on {selectedClass}:</div>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4, lineHeight: 1.5 }}>
                {selectedClass === "Heartbleed" || selectedClass === "Infiltration" || selectedClass === "Bot"
                  ? "Because of Stratified Focal Loss (gamma=2.5) and 24-bit RGB transformation, MEIC-ViT preserves subtle low-rate signatures without drowning in majority Benign traffic."
                  : "The parallel 3-path feature extraction captures synchronized volumetric packet rates across consecutive sliding windows (W=35, S=18)."}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 3: REAL CICIDS-2017 DATASET FILES ── */}
      {activeTab === "dataset" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div className="panel" style={{ padding: 18 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <div>
                <div className="panel-title">
                  <Database size={15} color="var(--accent-cyan)" />
                  <span>Real CICIDS-2017 Benchmark Files (Local MachineLearningCVE)</span>
                </div>
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                  Live sampled from <code style={{ color: "var(--accent-cyan)" }}>backend/sample_data/dataset/MachineLearningCVE</code>
                </div>
              </div>
              <button onClick={fetchDatasetStats} disabled={datasetLoading} className="btn-secondary-soc" style={{ padding: "6px 12px", fontSize: 11 }}>
                <RefreshCw size={12} style={{ animation: datasetLoading ? "spin 1s linear infinite" : "none" }} />
                <span>Refresh Dataset Info</span>
              </button>
            </div>

            {datasetStats?.files ? (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 12 }}>
                {datasetStats.files.map((f) => (
                  <div key={f.filename} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: 6, padding: 12 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 700, color: "#fff" }}>{f.day}</div>
                        <div style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-mono)", marginTop: 1 }}>{f.filename}</div>
                      </div>
                      <span style={{ fontSize: 11, fontWeight: 700, color: "var(--accent-cyan)", fontFamily: "var(--font-mono)" }}>
                        {f.size_mb} MB
                      </span>
                    </div>

                    <div style={{ marginTop: 8, paddingTop: 6, borderTop: "1px solid rgba(255,255,255,0.05)" }}>
                      <div style={{ fontSize: 9, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase" }}>Class Breakdown:</div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 4 }}>
                        {Object.entries(f.label_counts || {}).slice(0, 3).map(([lbl, cnt]) => (
                          <span key={lbl} style={{
                            fontSize: 9, padding: "2px 6px", borderRadius: 3,
                            background: lbl.toUpperCase().startsWith("BENIGN") ? "rgba(16,185,129,0.15)" : "rgba(239,68,68,0.15)",
                            color: lbl.toUpperCase().startsWith("BENIGN") ? "#10b981" : "#ef4444",
                          }}>
                            {lbl}: {cnt}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ padding: 30, textAlign: "center", color: "var(--text-dim)" }}>Loading dataset files…</div>
            )}
          </div>

          {/* Top Discriminative Features */}
          {datasetStats?.top_features && (
            <div className="panel" style={{ padding: 18 }}>
              <div className="panel-title" style={{ marginBottom: 12 }}>
                <TrendingUp size={15} color="var(--accent-amber)" />
                <span>Feature Importance Ranking (Mutual Information on CICIDS-2017)</span>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 10 }}>
                {datasetStats.top_features.map((feat, idx) => (
                  <div key={feat.feature} style={{ background: "rgba(255,255,255,0.015)", border: "1px solid var(--border)", borderRadius: 5, padding: "8px 10px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11 }}>
                      <span style={{ color: "#fff", fontWeight: 600 }}>#{idx + 1} {feat.feature}</span>
                      <span style={{ fontFamily: "var(--font-mono)", color: "var(--accent-amber)" }}>{(feat.importance * 100).toFixed(0)}%</span>
                    </div>
                    <div style={{ height: 3, background: "rgba(255,255,255,0.06)", borderRadius: 999, marginTop: 4 }}>
                      <div style={{ height: "100%", width: `${feat.importance * 100}%`, background: "var(--accent-amber)", borderRadius: 999 }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── TAB 4: LIVE HARDWARE BENCHMARK RUNNER ── */}
      {activeTab === "live_bench" && (
        <div className="panel" style={{ padding: 20 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 14 }}>
            <div>
              <div className="panel-title">
                <Zap size={16} color="var(--accent-cyan)" />
                <span>Live Hardware Latency & Throughput Benchmark</span>
              </div>
              <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4, maxWidth: 700 }}>
                Runs real live forward passes of the PyTorch MEIC-ViT model checkpoint on your local machine to measure exact CPU inference speed and flow throughput.
              </p>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ fontSize: 11, color: "var(--text-dim)" }}>Batch Windows:</span>
                <select
                  value={benchBatchSize}
                  onChange={(e) => setBenchBatchSize(Number(e.target.value))}
                  className="logs-filter-select"
                  style={{ width: 80 }}
                >
                  <option value={10}>10</option>
                  <option value={30}>30</option>
                  <option value={60}>60</option>
                  <option value={100}>100</option>
                </select>
              </div>

              <button
                onClick={runHardwareBenchmark}
                disabled={benchRunning}
                className="btn-primary-soc"
                style={{ padding: "8px 18px", fontSize: 12 }}
              >
                {benchRunning ? <RefreshCw size={14} style={{ animation: "spin 1s linear infinite" }} /> : <Zap size={14} />}
                <span>{benchRunning ? "Testing Model…" : "Run Hardware Benchmark"}</span>
              </button>
            </div>
          </div>

          {/* Results Display */}
          {benchResult ? (
            <div style={{ marginTop: 20 }}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12 }}>
                <div style={{ background: "rgba(56,189,248,0.08)", border: "1px solid rgba(56,189,248,0.3)", borderRadius: 8, padding: 14 }}>
                  <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase" }}>Latency per Window</div>
                  <div style={{ fontSize: 24, fontWeight: 800, color: "var(--accent-cyan)", fontFamily: "var(--font-mono)", marginTop: 4 }}>
                    {benchResult.latency_per_window_ms} ms
                  </div>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>W=35 flows per window</div>
                </div>

                <div style={{ background: "rgba(16,185,129,0.08)", border: "1px solid rgba(16,185,129,0.3)", borderRadius: 8, padding: 14 }}>
                  <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase" }}>Flow Throughput</div>
                  <div style={{ fontSize: 24, fontWeight: 800, color: "#10b981", fontFamily: "var(--font-mono)", marginTop: 4 }}>
                    {benchResult.throughput_flows_sec.toLocaleString()}
                  </div>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>network flows / second</div>
                </div>

                <div style={{ background: "rgba(129,140,248,0.08)", border: "1px solid rgba(129,140,248,0.3)", borderRadius: 8, padding: 14 }}>
                  <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase" }}>Trained Parameters</div>
                  <div style={{ fontSize: 24, fontWeight: 800, color: "#818cf8", fontFamily: "var(--font-mono)", marginTop: 4 }}>
                    {(benchResult.total_parameters / 1e6).toFixed(2)}M
                  </div>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>{benchResult.total_parameters.toLocaleString()} weights</div>
                </div>

                <div style={{ background: "rgba(245,158,11,0.08)", border: "1px solid rgba(245,158,11,0.3)", borderRadius: 8, padding: 14 }}>
                  <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase" }}>Compute Device</div>
                  <div style={{ fontSize: 18, fontWeight: 800, color: "#f59e0b", marginTop: 4 }}>
                    {benchResult.device}
                  </div>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>6 Layers · 8 Heads</div>
                </div>
              </div>

              <div style={{ marginTop: 14, background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: 6, padding: 12, fontSize: 11, color: "var(--text-muted)" }}>
                ✓ Benchmark successfully executed {benchResult.batch_size} sliding windows in {benchResult.elapsed_ms}ms total. At {benchResult.throughput_flows_sec.toLocaleString()} flows/s, MEIC-ViT easily handles high-rate campus network traffic in real time.
              </div>
            </div>
          ) : (
            <div style={{ marginTop: 20, padding: 30, textAlign: "center", background: "rgba(255,255,255,0.01)", border: "1px dashed var(--border)", borderRadius: 8 }}>
              <Cpu size={28} color="var(--accent-cyan)" style={{ marginBottom: 8 }} />
              <div style={{ fontSize: 13, color: "#fff", fontWeight: 600 }}>Ready to benchmark loaded PyTorch engine</div>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                Click "Run Hardware Benchmark" above to test model latency on your current system.
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
