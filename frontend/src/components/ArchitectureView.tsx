import React, { useState, useEffect } from "react";
import { Cpu, Layers, BookOpen, CheckCircle, Code } from "lucide-react";
import { API, ModelInfo } from "../api/client";

export const ArchitectureView: React.FC = () => {
  const [modelInfo, setModelInfo] = useState<ModelInfo | null>(null);

  useEffect(() => {
    API.modelInfo().then(setModelInfo).catch(console.error);
  }, []);

  const hyperparams = [
    { label: "Sliding Window Size (W)", value: `${modelInfo?.window ?? 35} flows`, desc: "Number of consecutive packet flows bundled into one image" },
    { label: "Sliding Window Stride (S)", value: `${modelInfo?.stride ?? 18} flows`, desc: "48.6% temporal overlap between consecutive windows" },
    { label: "Input Image Resolution", value: "35 × 35 × 3", desc: "24-bit RGB linear bitwise mapping" },
    { label: "Feature Dimension", value: `${modelInfo?.n_features ?? 35} attributes`, desc: "Normalized statistical metrics (CICIDS-2017)" },
    { label: "Transformer Hidden Dim (D)", value: `${modelInfo?.hidden_dim ?? 256}`, desc: "Internal embedding size for attention heads" },
    { label: "Transformer Encoder Layers (L)", value: `${modelInfo?.n_layers ?? 6} layers`, desc: "Stacked Multi-Head Self-Attention blocks" },
    { label: "Attention Heads (H)", value: `${modelInfo?.n_heads ?? 8} heads`, desc: "Parallel subspace projections (d_k = 32)" },
    { label: "Top-K Pooling (K)", value: `Top-${modelInfo?.topk ?? 3} Mean Logit`, desc: "Averages top-3 window confidence to filter jitter noise" },
    { label: "Total Trained Parameters", value: "5,038,735", desc: "Trained PyTorch weights (meic_vit_best.pt)" },
    { label: "Output Attack Classes", value: `${modelInfo?.n_classes ?? 15} classes`, desc: "BENIGN + 14 distinct cyberattack categories" },
  ];

  return (
    <div className="soc-content">
      {/* ── Architecture Overview ── */}
      <div className="panel" style={{ padding: 20 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: "var(--accent-cyan)", textTransform: "uppercase", letterSpacing: 0.6 }}>
          Paper Section 3 & Figure 3
        </div>
        <h1 className="building-title" style={{ fontSize: 24, marginTop: 4, marginBottom: 8 }}>
          Multi-Scale Enhanced ViT Architecture
        </h1>
        <p style={{ fontSize: 13, color: "var(--text-muted)", lineHeight: 1.6, maxWidth: 950 }}>
          MEIC-ViT resolves the fundamental limitation of applying standard computer vision transformers to network security:
          network packets are not natural 2D photos, but rather temporal protocol flows with both global macro statistics and sharp local byte-burst patterns.
          MEIC-ViT introduces a parallel three-path feature extraction scheme before the self-attention encoder:
        </p>

        {/* 3 Paths Cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14, marginTop: 16 }}>
          <div style={{ background: "rgba(56, 189, 248, 0.05)", border: "1px solid rgba(56, 189, 248, 0.25)", borderRadius: 6, padding: 14 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: "var(--accent-cyan)", marginBottom: 4 }}>
              Path A: Global Statistical Representation
            </div>
            <div style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.5 }}>
              Computes mean, standard deviation, and interquartile range (IQR) across each flow attribute. Captures the macro volumetric envelope of the burst.
            </div>
          </div>

          <div style={{ background: "rgba(129, 140, 248, 0.05)", border: "1px solid rgba(129, 140, 248, 0.25)", borderRadius: 6, padding: 14 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: "var(--accent-purple)", marginBottom: 4 }}>
              Path B: Row Visual Representation
            </div>
            <div style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.5 }}>
              Extracts 2D spatial correlations between adjacent flow rows in the 35×35 RGB matrix, detecting spatial byte-level similarities across consecutive connections.
            </div>
          </div>

          <div style={{ background: "rgba(16, 185, 129, 0.05)", border: "1px solid rgba(16, 185, 129, 0.25)", borderRadius: 6, padding: 14 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: "var(--accent-green)", marginBottom: 4 }}>
              Path C: Sequential Content Representation
            </div>
            <div style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.5 }}>
              Embeds the exact temporal sequence order using 1D learnable position embeddings, ensuring early reconnaissance probes are temporally linked to subsequent attacks.
            </div>
          </div>
        </div>
      </div>

      {/* ── Active Hyperparameters Grid (Direct from PyTorch Checkpoint) ── */}
      <div className="panel" style={{ padding: 20 }}>
        <div className="panel-header">
          <div className="panel-title">
            <Cpu size={16} color="var(--accent-cyan)" />
            <span>Active Model Hyperparameters (Loaded PyTorch Engine)</span>
          </div>
          <span style={{ fontSize: 11, color: "var(--accent-green)", fontFamily: "var(--font-mono)", fontWeight: 700 }}>
            STATUS: ACTIVE INFERENCE
          </span>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 14 }}>
          {hyperparams.map((hp) => (
            <div
              key={hp.label}
              style={{
                background: "rgba(255,255,255,0.02)",
                border: "1px solid var(--border)",
                borderRadius: 6,
                padding: "12px 14px",
              }}
            >
              <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-dim)", textTransform: "uppercase" }}>
                {hp.label}
              </div>
              <div style={{ fontSize: 18, fontWeight: 800, color: "#fff", fontFamily: "var(--font-mono)", margin: "4px 0" }}>
                {hp.value}
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                {hp.desc}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── BibTeX Citation Block ── */}
      <div className="panel" style={{ padding: 20 }}>
        <div className="panel-header">
          <div className="panel-title">
            <BookOpen size={16} color="var(--accent-cyan)" />
            <span>Citation & Research Attribution</span>
          </div>
        </div>

        <pre
          style={{
            background: "#050914",
            border: "1px solid var(--border)",
            borderRadius: 6,
            padding: 14,
            fontSize: 11,
            fontFamily: "var(--font-mono)",
            color: "var(--accent-cyan)",
            lineHeight: 1.6,
            overflowX: "auto",
          }}
        >
{`@article{xiao2026meicvit,
  title   = {MEIC-ViT: A multi-scale enhanced vision transformer for network intrusion detection},
  author  = {Xiao, Yeqiu and Wang, Peihua and Wang, Yichuan and Ma, Yibin and Hei, Xinhong},
  journal = {Computer Networks},
  volume  = {282},
  pages   = {112273},
  year    = {2026},
  publisher = {Elsevier}
}`}
        </pre>
      </div>
    </div>
  );
};
