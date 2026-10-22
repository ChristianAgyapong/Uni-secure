import React, { useState, useEffect } from "react";
import {
  Cpu,
  Layers,
  BookOpen,
  Sliders,
  ChevronRight,
  Calculator,
  Info,
  CheckCircle2,
  Code,
  Zap,
} from "lucide-react";
import { API, ModelInfo } from "../api/client";

interface ArchBlock {
  id: string;
  name: string;
  pathType: "input" | "pathA" | "pathB" | "pathC" | "fusion" | "encoder" | "pooling" | "output";
  color: string;
  inShape: string;
  outShape: string;
  equation: string;
  description: string;
  paperRef: string;
}

const ARCH_BLOCKS: ArchBlock[] = [
  {
    id: "algo1",
    name: "Algorithm 1: 24-bit Flow-to-RGB Mapping",
    pathType: "input",
    color: "#38bdf8",
    inShape: "(B, 35, 35) Raw Normalized Features",
    outShape: "(B, 35, 35, 3) 24-bit RGB Image Tensors",
    equation: "R = (v >> 16) & 0xFF,  G = (v >> 8) & 0xFF,  B = v & 0xFF",
    description: "Linearly maps 35 normalized continuous network flow features into 24-bit color components across 35 time steps, preserving extreme decimal precision within color channels.",
    paperRef: "Section 3.2.1 · Algorithm 1 (Flow-to-RGB Conversion)",
  },
  {
    id: "pathA",
    name: "Path A: Global Statistical Representation",
    pathType: "pathA",
    color: "#0ea5e9",
    inShape: "(B, 35, 35, 3) RGB Tensor",
    outShape: "(B, 64) Global Statistical Vector",
    equation: "F_stat = Linear(Concat[Mean(X), Std(X), IQR(X)])",
    description: "Computes summary statistics (mean, variance, interquartile range) across the entire sliding burst window to capture the macro volumetric volume envelope.",
    paperRef: "Section 3.2.2 · Path A (Global Statistics)",
  },
  {
    id: "pathB",
    name: "Path B: Row-Visual Spatial Representation",
    pathType: "pathB",
    color: "#a855f7",
    inShape: "(B, 35, 35, 3) RGB Image",
    outShape: "(B, 35, 256) Spatial Token Embeddings",
    equation: "F_row = Conv2D_{1x35}(X) + Linear(X_row)",
    description: "Extracts 2D spatial correlations between adjacent flow rows, identifying byte-level burst similarities across consecutive connection attempts.",
    paperRef: "Section 3.2.2 · Path B (Row Visual Spatial)",
  },
  {
    id: "pathC",
    name: "Path C: Sequential Content Representation",
    pathType: "pathC",
    color: "#10b981",
    inShape: "(B, 35, 35, 3) Flow Sequence",
    outShape: "(B, 35, 256) Position-Aware Tokens",
    equation: "F_seq = LayerNorm(Linear(X) + E_pos)",
    description: "Embeds temporal order using 1D learnable positional encodings, ensuring early reconnaissance probes are chronologically linked to later exploitation flows.",
    paperRef: "Section 3.2.2 · Path C (Sequential Temporal)",
  },
  {
    id: "fusion",
    name: "Multi-Scale Feature Fusion Layer",
    pathType: "fusion",
    color: "#f59e0b",
    inShape: "(B, 35, 512) Fused Path B & C Tokens",
    outShape: "(B, 35, 256) Transformer Input Tokens",
    equation: "H_0 = LayerNorm(W_fuse · [F_row ∥ F_seq] + b_fuse)",
    description: "Fuses row-visual and sequential temporal embeddings via channel concatenation and linear projection, forming the input sequence for the Transformer encoder.",
    paperRef: "Section 3.2.3 · Multi-Scale Feature Fusion",
  },
  {
    id: "encoder",
    name: "Transformer Encoder (6 Blocks × 8 Heads)",
    pathType: "encoder",
    color: "#ec4899",
    inShape: "(B, 35, 256) Token Sequence",
    outShape: "(B, 35, 256) Contextualized Latent Representations",
    equation: "A = Softmax(Q·Kᵀ / √32),  H_{l} = MLP(LayerNorm(H_{l-1} + A·V))",
    description: "Computes self-attention across all 35 flow tokens simultaneously. Eight parallel attention heads (d_k=32) capture diverse correlation patterns.",
    paperRef: "Section 3.2.4 · Multi-Head Self-Attention Encoder",
  },
  {
    id: "pooling",
    name: "Top-K Confidence Logit Pooling (K=3)",
    pathType: "pooling",
    color: "#6366f1",
    inShape: "(B, 35, 15) Row-Level Attack Predictions",
    outShape: "(B, 15) Pooled Window Prediction",
    equation: "Y_window = (1/K) · ∑_{k=1}^K TopK_{k}(RowLogits, dim=rows)",
    description: "Averages the top-3 highest confidence row predictions in the window. Suppresses transient single-packet noise while reliably elevating true attack signals.",
    paperRef: "Section 3.2.5 · Top-K Logit Pooling Mechanism",
  },
  {
    id: "output",
    name: "Classification Head (15 Classes)",
    pathType: "output",
    color: "#14b8a6",
    inShape: "(B, 15) Pooled Logits",
    outShape: "Softmax Probability Distribution (15 Classes)",
    equation: "P(class = c | X) = exp(y_c) / ∑_{j} exp(y_j)",
    description: "Maps final logits to calibrated class probabilities for BENIGN + 14 distinct attack types (DDoS, PortScan, Bot, Heartbleed, Infiltration, etc.).",
    paperRef: "Table 3 & Table 5 · 15-Class Evaluation",
  },
];

export const ArchitectureView: React.FC = () => {
  const [modelInfo, setModelInfo] = useState<ModelInfo | null>(null);
  const [selectedBlockId, setSelectedBlockId] = useState("algo1");

  // Dynamic Tensor Calculator States
  const [calcW, setCalcW] = useState(35);
  const [calcS, setCalcS] = useState(18);
  const [calcD, setCalcD] = useState(256);
  const [calcLayers, setCalcLayers] = useState(6);
  const [calcHeads, setCalcHeads] = useState(8);

  useEffect(() => {
    API.modelInfo().then(setModelInfo).catch(console.error);
  }, []);

  const selectedBlock = ARCH_BLOCKS.find((b) => b.id === selectedBlockId) ?? ARCH_BLOCKS[0];

  // Dynamic calculations
  const overlapPct = (((calcW - calcS) / calcW) * 100).toFixed(1);
  const d_k = Math.floor(calcD / calcHeads);
  // Parameter formula approximation for ViT:
  // Embedding + L * (4 * D^2 + 8 * D^2 [MLP]) + Classifier
  const attnParamsPerLayer = 4 * calcD * calcD;
  const mlpParamsPerLayer = 8 * calcD * calcD;
  const estimatedParams = Math.round(
    calcW * 35 * 3 + calcLayers * (attnParamsPerLayer + mlpParamsPerLayer) + calcD * 15 + 35 * calcD
  );
  const gflopsPerWindow = ((2 * estimatedParams * calcW) / 1e9).toFixed(3);
  const memoryKbPerWindow = (((calcW * calcD * 4 * calcLayers) / 1024)).toFixed(1);

  return (
    <div className="soc-content">
      {/* ── TOP SECTION HEADER ── */}
      <div className="panel" style={{ padding: "18px 20px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 14 }}>
          <div>
            <div style={{ fontSize: 10, fontWeight: 800, color: "var(--accent-cyan)", textTransform: "uppercase", letterSpacing: 0.8 }}>
              Research Section 3 & Figure 3
            </div>
            <h1 className="building-title" style={{ fontSize: 22, marginTop: 4 }}>
              Multi-Scale Enhanced Vision Transformer (MEIC-ViT)
            </h1>
            <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4, maxWidth: 880, lineHeight: 1.5 }}>
              MEIC-ViT solves the limitation of applying standard vision transformers to network intrusion detection.
              By combining 24-bit continuous feature colorization with a parallel 3-path feature extraction scheme (Global Stats, Row Visual, and Sequential Temporal),
              it captures both macro volume bursts and micro temporal anomalies.
            </p>
          </div>

          <div style={{
            background: "rgba(16,185,129,0.1)", border: "1px solid rgba(16,185,129,0.3)",
            borderRadius: 6, padding: "8px 14px", textAlign: "right",
          }}>
            <div style={{ fontSize: 9, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase" }}>PyTorch Checkpoint</div>
            <div style={{ fontSize: 14, fontWeight: 800, color: "#10b981", fontFamily: "var(--font-mono)", marginTop: 2 }}>
              5.03M Parameters Active
            </div>
          </div>
        </div>
      </div>

      {/* ── INTERACTIVE NEURAL PIPELINE ARCHITECTURE FLOW ── */}
      <div className="panel" style={{ padding: 18 }}>
        <div className="panel-title" style={{ marginBottom: 14 }}>
          <Layers size={15} color="var(--accent-cyan)" />
          <span>Interactive Forward-Pass Pipeline Diagram (Click Any Block to Inspect)</span>
        </div>

        {/* Pipeline Stage Blocks */}
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {ARCH_BLOCKS.map((block, idx) => {
            const isSel = selectedBlockId === block.id;
            return (
              <div
                key={block.id}
                onClick={() => setSelectedBlockId(block.id)}
                style={{
                  display: "flex", alignItems: "center", justifyContent: "space-between",
                  padding: "10px 14px", borderRadius: 6, cursor: "pointer", border: "1px solid",
                  background: isSel ? `${block.color}1a` : "rgba(255,255,255,0.02)",
                  borderColor: isSel ? block.color : "var(--border)",
                  transition: "all 0.15s ease",
                  boxShadow: isSel ? `0 0 16px ${block.color}26` : "none",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <div style={{
                    width: 24, height: 24, borderRadius: 5,
                    background: `${block.color}26`, border: `1px solid ${block.color}66`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontSize: 10, fontWeight: 800, color: block.color, fontFamily: "var(--font-mono)",
                  }}>
                    {idx + 1}
                  </div>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: isSel ? 700 : 500, color: isSel ? "#fff" : "var(--text-main)" }}>
                      {block.name}
                    </div>
                    <div style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-mono)", marginTop: 2 }}>
                      {block.inShape} ➔ {block.outShape}
                    </div>
                  </div>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{
                    fontSize: 10, fontFamily: "var(--font-mono)", padding: "2px 8px", borderRadius: 3,
                    background: "rgba(0,0,0,0.3)", color: block.color, border: `1px solid ${block.color}44`,
                  }}>
                    {block.equation.length > 35 ? block.equation.slice(0, 32) + "…" : block.equation}
                  </span>
                  <ChevronRight size={14} color={isSel ? block.color : "var(--text-dim)"} />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── SELECTED STAGE DEEP DIVE PANEL ── */}
      <div className="panel" style={{ padding: 20 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: selectedBlock.color, textTransform: "uppercase" }}>
              Active Pipeline Stage
            </div>
            <h2 style={{ fontSize: 18, fontWeight: 800, color: "#fff", marginTop: 2 }}>
              {selectedBlock.name}
            </h2>
            <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 2 }}>
              {selectedBlock.paperRef}
            </div>
          </div>

          <div style={{ display: "flex", gap: 8 }}>
            <span style={{
              fontSize: 10, padding: "4px 10px", borderRadius: 4,
              background: "rgba(56,189,248,0.1)", border: "1px solid rgba(56,189,248,0.3)",
              color: "var(--accent-cyan)", fontFamily: "var(--font-mono)",
            }}>
              IN: {selectedBlock.inShape}
            </span>
            <span style={{
              fontSize: 10, padding: "4px 10px", borderRadius: 4,
              background: "rgba(16,185,129,0.1)", border: "1px solid rgba(16,185,129,0.3)",
              color: "#10b981", fontFamily: "var(--font-mono)",
            }}>
              OUT: {selectedBlock.outShape}
            </span>
          </div>
        </div>

        {/* Mathematical Equation Block */}
        <div style={{
          background: "#050914", border: `1px solid ${selectedBlock.color}44`,
          borderRadius: 6, padding: "12px 16px", marginBottom: 14,
        }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase", marginBottom: 4 }}>
            Mathematical Formulation:
          </div>
          <code style={{ fontSize: 13, color: selectedBlock.color, fontFamily: "var(--font-mono)", display: "block" }}>
            {selectedBlock.equation}
          </code>
        </div>

        <p style={{ fontSize: 12, color: "var(--text-main)", lineHeight: 1.6 }}>
          {selectedBlock.description}
        </p>
      </div>

      {/* ── DYNAMIC HYPERPARAMETER & TENSOR CALCULATOR ── */}
      <div className="panel" style={{ padding: 20 }}>
        <div className="panel-title" style={{ marginBottom: 12 }}>
          <Calculator size={15} color="var(--accent-cyan)" />
          <span>Interactive Forward-Pass Hyperparameter & Tensor Simulator</span>
        </div>
        <p style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 16 }}>
          Adjust the architectural hyperparameters below to simulate tensor dimensions, parameter counts, and theoretical latency:
        </p>

        {/* Sliders Grid */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 14, marginBottom: 18 }}>
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
              <span style={{ color: "var(--text-dim)" }}>Window Size (W):</span>
              <span style={{ color: "#fff", fontWeight: 700, fontFamily: "var(--font-mono)" }}>{calcW} flows</span>
            </div>
            <input type="range" min="15" max="50" step="5" value={calcW} onChange={(e) => setCalcW(Number(e.target.value))}
              style={{ width: "100%", accentColor: "var(--accent-cyan)" }} />
          </div>

          <div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
              <span style={{ color: "var(--text-dim)" }}>Stride (S):</span>
              <span style={{ color: "#fff", fontWeight: 700, fontFamily: "var(--font-mono)" }}>{calcS} ({overlapPct}% overlap)</span>
            </div>
            <input type="range" min="5" max="30" step="1" value={calcS} onChange={(e) => setCalcS(Number(e.target.value))}
              style={{ width: "100%", accentColor: "var(--accent-cyan)" }} />
          </div>

          <div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
              <span style={{ color: "var(--text-dim)" }}>Hidden Dim (D):</span>
              <span style={{ color: "#fff", fontWeight: 700, fontFamily: "var(--font-mono)" }}>{calcD}</span>
            </div>
            <input type="range" min="128" max="512" step="64" value={calcD} onChange={(e) => setCalcD(Number(e.target.value))}
              style={{ width: "100%", accentColor: "var(--accent-cyan)" }} />
          </div>

          <div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
              <span style={{ color: "var(--text-dim)" }}>Encoder Layers (L):</span>
              <span style={{ color: "#fff", fontWeight: 700, fontFamily: "var(--font-mono)" }}>{calcLayers}</span>
            </div>
            <input type="range" min="2" max="12" step="2" value={calcLayers} onChange={(e) => setCalcLayers(Number(e.target.value))}
              style={{ width: "100%", accentColor: "var(--accent-cyan)" }} />
          </div>

          <div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
              <span style={{ color: "var(--text-dim)" }}>Attention Heads (H):</span>
              <span style={{ color: "#fff", fontWeight: 700, fontFamily: "var(--font-mono)" }}>{calcHeads} (d_k={d_k})</span>
            </div>
            <input type="range" min="4" max="16" step="4" value={calcHeads} onChange={(e) => setCalcHeads(Number(e.target.value))}
              style={{ width: "100%", accentColor: "var(--accent-cyan)" }} />
          </div>
        </div>

        {/* Calculated Output Metrics Strip */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12 }}>
          <div style={{ background: "rgba(56,189,248,0.06)", border: "1px solid var(--border)", borderRadius: 6, padding: 12 }}>
            <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase" }}>Estimated Parameters</div>
            <div style={{ fontSize: 20, fontWeight: 800, color: "var(--accent-cyan)", fontFamily: "var(--font-mono)", marginTop: 2 }}>
              {(estimatedParams / 1e6).toFixed(2)}M
            </div>
            <div style={{ fontSize: 10, color: "var(--text-muted)" }}>~{estimatedParams.toLocaleString()} weights</div>
          </div>

          <div style={{ background: "rgba(16,185,129,0.06)", border: "1px solid var(--border)", borderRadius: 6, padding: 12 }}>
            <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase" }}>Window Overlap Ratio</div>
            <div style={{ fontSize: 20, fontWeight: 800, color: "#10b981", fontFamily: "var(--font-mono)", marginTop: 2 }}>
              {overlapPct}%
            </div>
            <div style={{ fontSize: 10, color: "var(--text-muted)" }}>Paper optimal: 48.6%</div>
          </div>

          <div style={{ background: "rgba(129,140,248,0.06)", border: "1px solid var(--border)", borderRadius: 6, padding: 12 }}>
            <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase" }}>Compute Complexity</div>
            <div style={{ fontSize: 20, fontWeight: 800, color: "#818cf8", fontFamily: "var(--font-mono)", marginTop: 2 }}>
              {gflopsPerWindow} GFLOPs
            </div>
            <div style={{ fontSize: 10, color: "var(--text-muted)" }}>Per single window pass</div>
          </div>

          <div style={{ background: "rgba(245,158,11,0.06)", border: "1px solid var(--border)", borderRadius: 6, padding: 12 }}>
            <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase" }}>Activation Footprint</div>
            <div style={{ fontSize: 20, fontWeight: 800, color: "#f59e0b", fontFamily: "var(--font-mono)", marginTop: 2 }}>
              {memoryKbPerWindow} KB
            </div>
            <div style={{ fontSize: 10, color: "var(--text-muted)" }}>Lightweight edge footprint</div>
          </div>
        </div>
      </div>

      {/* ── CITATION & REPRODUCIBILITY BLOCK ── */}
      <div className="panel" style={{ padding: 18 }}>
        <div className="panel-title" style={{ marginBottom: 10 }}>
          <BookOpen size={14} color="var(--accent-cyan)" />
          <span>Research Citation & Implementation Attribution</span>
        </div>
        <pre
          style={{
            background: "#050914", border: "1px solid var(--border)", borderRadius: 6,
            padding: 12, fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--accent-cyan)",
            lineHeight: 1.6, overflowX: "auto",
          }}
        >
{`@article{xiao2026meicvit,
  title     = {MEIC-ViT: A multi-scale enhanced vision transformer for network intrusion detection},
  author    = {Xiao, Yeqiu and Wang, Peihua and Wang, Yichuan and Ma, Yibin and Hei, Xinhong},
  journal   = {Computer Networks},
  volume    = {282},
  pages     = {112273},
  year      = {2026},
  publisher = {Elsevier}
}`}
        </pre>
      </div>
    </div>
  );
};
