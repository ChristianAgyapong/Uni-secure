import React, { useState, useEffect } from "react";
import {
  Cpu,
  Layers,
  Sliders,
  ChevronRight,
  Calculator,
  Info,
  CheckCircle2,
  Code,
  Zap,
  Activity,
  ShieldCheck,
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
  pipelineStage: string;
}

const ARCH_BLOCKS: ArchBlock[] = [
  {
    id: "algo1",
    name: "24-bit Flow-to-RGB Image Transformation",
    pathType: "input",
    color: "#38bdf8",
    inShape: "(Batch, 35, 35) Raw Flow Features",
    outShape: "(Batch, 35, 35, 3) 24-bit Color Tensors",
    equation: "Red = (val >> 16) & 0xFF,  Green = (val >> 8) & 0xFF,  Blue = val & 0xFF",
    description: "Linearly maps 35 normalized continuous network flow features into 24-bit color components across 35 time steps, preserving extreme decimal precision within color channels.",
    pipelineStage: "Stage 1 · Data Ingestion & Visual Slicing",
  },
  {
    id: "pathA",
    name: "Path A: Global Volumetric Envelope Extractor",
    pathType: "pathA",
    color: "#0ea5e9",
    inShape: "(Batch, 35, 35, 3) Color Tensor",
    outShape: "(Batch, 64) Global Statistical Vector",
    equation: "Stats = Linear(Concat[Mean(X), Max(X), Std(X), Diff, PeakRatio])",
    description: "Computes 5 spatial statistical metrics across the entire sliding burst window to capture the macro volumetric traffic envelope and detect sudden spikes.",
    pipelineStage: "Stage 2A · Macro-Level Statistical Sensor",
  },
  {
    id: "pathB",
    name: "Path B: Row-Visual Spatial Pattern Scanner",
    pathType: "pathB",
    color: "#a855f7",
    inShape: "(Batch, 35, 35, 3) Image Tensor",
    outShape: "(Batch, 35, 128) Spatial Flow Embeddings",
    equation: "Z_row = GELU(BatchNorm(Conv2D_{1x35}(X)))",
    description: "Applies 2D asymmetric convolution across horizontal flow rows, capturing spatial relationships between packet sizes, TCP flags, and connection states.",
    pipelineStage: "Stage 2B · Packet-Level Visual Embedding",
  },
  {
    id: "pathC",
    name: "Path C: Sequential Chronological Timeline Analyzer",
    pathType: "pathC",
    color: "#10b981",
    inShape: "(Batch, 35, 35, 3) Flow Sequence",
    outShape: "(Batch, 35, 128) Sequential Content Tokens",
    equation: "Z_seq = Linear(AdaptiveAvgPool(Conv1D(X)))",
    description: "Two 1D convolutions extract localized temporal transitions, ensuring early reconnaissance probes are chronologically linked to later exploitation flows.",
    pipelineStage: "Stage 2C · Temporal Order & Sequence Sensor",
  },
  {
    id: "fusion",
    name: "Multi-Scale Sensor Fusion & Token Projection",
    pathType: "fusion",
    color: "#f59e0b",
    inShape: "(Batch, 35, 256) Fused Visual + Sequential Tokens",
    outShape: "(Batch, 35, 256) Normalized Input Tokens",
    equation: "Tokens = LayerNorm(Linear(Concat[Path B, Path C]) + PosEmbed)",
    description: "Merges row-visual and sequential temporal embeddings via channel concatenation and linear projection, injecting learnable positional embeddings.",
    pipelineStage: "Stage 3 · Hierarchical Tensor Merging",
  },
  {
    id: "encoder",
    name: "Vision Transformer Core (6 Layers × 8 Heads)",
    pathType: "encoder",
    color: "#ec4899",
    inShape: "(Batch, 35, 256) Token Sequence",
    outShape: "(Batch, 35, 256) Contextualized Latents",
    equation: "Attn = Softmax(Q·Kᵀ / √32) · V,  Out = FFN(LayerNorm(H + Attn))",
    description: "Multi-Head Self-Attention dynamically weights correlations across all 35 flows simultaneously, logically isolating hostile burst signatures from background chatter.",
    pipelineStage: "Stage 4 · Global Self-Attention Engine",
  },
  {
    id: "pooling",
    name: "Top-K Salient Logit Pooling (K=3)",
    pathType: "pooling",
    color: "#6366f1",
    inShape: "(Batch, 35, 15) Row Prediction Logits",
    outShape: "(Batch, 15) Pooled Attack Probabilities",
    equation: "Final_Logits = Mean(Top-3(Row_Classifiers(H_fused)))",
    description: "Extracts the mean of the top 3 highest activation logits across the flow window, forcing the AI to focus on the sharpest attack signatures without benign dilution.",
    pipelineStage: "Stage 5 · Malicious Burst Isolation",
  },
  {
    id: "output",
    name: "Stratified Multi-Vector Decision Head",
    pathType: "output",
    color: "#10b981",
    inShape: "(Batch, 15) Decision Logits",
    outShape: "15 Threat Classes + Confidence % + Heatmap",
    equation: "P(c) = Softmax(Final_Logits), Loss = - (1/B) sum alpha_c * (1-p)^2.5 * log(p)",
    description: "Predicts probabilities across 15 attack classes. Stratified Focal Loss guarantees rare intrusions receive equal prioritization.",
    pipelineStage: "Stage 6 · Final Threat Classification",
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

  const overlapPct = (((calcW - calcS) / calcW) * 100).toFixed(1);
  const d_k = Math.floor(calcD / calcHeads);
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
              Neural Processing Pipeline Blueprint
            </div>
            <h1 className="building-title" style={{ fontSize: 22, marginTop: 4 }}>
              Multi-Scale Vision AI Threat Defense Architecture
            </h1>
            <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4, maxWidth: 880, lineHeight: 1.5 }}>
              Combines 24-bit flow colorization with three parallel perception pathways (Global Volume, Row Spatial Patterns, and Sequential Temporal Transitions) 
              feeding into a 6-layer Vision Transformer engine for real-time intrusion classification.
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
          <span>Interactive Forward-Pass Pipeline Diagram (Click Any Stage to Inspect)</span>
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
                    background: `${block.color}18`, color: block.color, border: `1px solid ${block.color}33`,
                  }}>
                    {block.pipelineStage}
                  </span>
                  <ChevronRight size={14} color={isSel ? block.color : "var(--text-dim)"} />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── STAGE DETAIL & EQUATION INSPECTOR ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 16 }}>
        {/* Left: Selected Block Details */}
        <div className="panel" style={{ padding: 18, borderLeft: `4px solid ${selectedBlock.color}` }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
            <div>
              <span style={{ fontSize: 10, fontWeight: 700, color: selectedBlock.color, textTransform: "uppercase" }}>
                {selectedBlock.pipelineStage}
              </span>
              <h2 style={{ fontSize: 18, fontWeight: 800, color: "#fff", marginTop: 2 }}>
                {selectedBlock.name}
              </h2>
            </div>
            <span style={{
              fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--text-dim)",
              background: "rgba(255,255,255,0.03)", padding: "3px 8px", borderRadius: 4,
            }}>
              Active Module
            </span>
          </div>

          <p style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.6, marginBottom: 14 }}>
            {selectedBlock.description}
          </p>

          <div style={{ background: "rgba(0,0,0,0.4)", border: "1px solid var(--border)", borderRadius: 6, padding: "12px 14px", marginBottom: 14 }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase", marginBottom: 4 }}>
              Mathematical Transformation
            </div>
            <code style={{ fontSize: 12, color: selectedBlock.color, fontFamily: "var(--font-mono)", display: "block" }}>
              {selectedBlock.equation}
            </code>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, fontSize: 11 }}>
            <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: 5, padding: "8px 10px" }}>
              <div style={{ fontSize: 9, color: "var(--text-dim)", textTransform: "uppercase" }}>Input Dimensions</div>
              <div style={{ color: "#fff", fontWeight: 700, fontFamily: "var(--font-mono)", marginTop: 2 }}>{selectedBlock.inShape}</div>
            </div>
            <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: 5, padding: "8px 10px" }}>
              <div style={{ fontSize: 9, color: "var(--text-dim)", textTransform: "uppercase" }}>Output Dimensions</div>
              <div style={{ color: selectedBlock.color, fontWeight: 700, fontFamily: "var(--font-mono)", marginTop: 2 }}>{selectedBlock.outShape}</div>
            </div>
          </div>
        </div>

        {/* Right: Dynamic Tensor Parameter Calculator */}
        <div className="panel" style={{ padding: 18 }}>
          <div className="panel-title" style={{ marginBottom: 12 }}>
            <Calculator size={15} color="var(--accent-cyan)" />
            <span>Real-Time Hyperparameter & Tensor Sizer</span>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
                <span style={{ color: "var(--text-muted)" }}>Window Size (W = {calcW} flows)</span>
                <span style={{ color: "var(--accent-cyan)", fontFamily: "var(--font-mono)" }}>35 flows</span>
              </div>
              <input type="range" min="20" max="50" value={calcW} onChange={(e) => setCalcW(Number(e.target.value))} style={{ width: "100%", accentColor: "var(--accent-cyan)" }} />
            </div>

            <div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
                <span style={{ color: "var(--text-muted)" }}>Sliding Stride (S = {calcS} flows)</span>
                <span style={{ color: "var(--accent-cyan)", fontFamily: "var(--font-mono)" }}>{overlapPct}% Overlap</span>
              </div>
              <input type="range" min="5" max="35" value={calcS} onChange={(e) => setCalcS(Number(e.target.value))} style={{ width: "100%", accentColor: "var(--accent-cyan)" }} />
            </div>

            <div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
                <span style={{ color: "var(--text-muted)" }}>Hidden Dim (D = {calcD}, Heads = {calcHeads})</span>
                <span style={{ color: "var(--accent-purple)", fontFamily: "var(--font-mono)" }}>d_k = {d_k}</span>
              </div>
              <input type="range" min="128" max="512" step="64" value={calcD} onChange={(e) => setCalcD(Number(e.target.value))} style={{ width: "100%", accentColor: "var(--accent-purple)" }} />
            </div>

            {/* Calculated Values */}
            <div style={{ marginTop: 6, paddingTop: 10, borderTop: "1px solid var(--border)", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
              <div style={{ background: "rgba(56,189,248,0.06)", borderRadius: 5, padding: "8px 10px" }}>
                <div style={{ fontSize: 9, color: "var(--text-dim)" }}>MODEL WEIGHTS</div>
                <div style={{ fontSize: 14, fontWeight: 800, color: "var(--accent-cyan)", fontFamily: "var(--font-mono)", marginTop: 2 }}>
                  {(estimatedParams / 1e6).toFixed(2)} M
                </div>
              </div>
              <div style={{ background: "rgba(16,185,129,0.06)", borderRadius: 5, padding: "8px 10px" }}>
                <div style={{ fontSize: 9, color: "var(--text-dim)" }}>FORWARD GFLOPS</div>
                <div style={{ fontSize: 14, fontWeight: 800, color: "#10b981", fontFamily: "var(--font-mono)", marginTop: 2 }}>
                  {gflopsPerWindow} G
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
