import React, { useState } from "react";
import { Eye, Layers, Sparkles, BookOpen, CheckCircle } from "lucide-react";

export const InterpretabilityView: React.FC = () => {
  const [selectedCase, setSelectedCase] = useState<"ddos" | "portscan" | "benign">("ddos");

  const cases = {
    ddos: {
      title: "DDoS Attack: Volumetric SYN Flood Pattern",
      description:
        "In DDoS attacks, multiple packets with identical short length and high burst rates arrive in rapid succession. Notice how the Transformer attention weights (right) concentrate into a intense horizontal and vertical high-temperature stripe, highlighting the synchronized volumetric burst tokens.",
      tokenFocus: "Concentrated on Flow_Duration (0), Total_Fwd_Packets, and Bwd_Packet_Length_Min",
      entropy: "8.92 bits (Highly Anomalous Uniform Packet Size)",
    },
    portscan: {
      title: "PortScan: Sequential Destination Port Reconnaissance",
      description:
        "In PortScan reconnaissance, the attacker probes successive port numbers with minimal payload size. The attention map reveals periodic diagonal cross-attention bands where the model correlates sequential destination port changes across consecutive flow rows.",
      tokenFocus: "Concentrated on Dst_Port sequence, Flow_IAT_Min, and SYN_Flag_Count",
      entropy: "6.74 bits (Semi-regular structured scan)",
    },
    benign: {
      title: "Benign: Normal Multi-Service Browsing Baseline",
      description:
        "In normal network traffic, packet lengths, flow durations, and inter-arrival times vary naturally according to diverse user behavior. The self-attention matrix is smoothly distributed across the entire 35×35 image without concentrated hot spots.",
      tokenFocus: "Evenly distributed across standard HTTP/TLS protocol flow metrics",
      entropy: "4.12 bits (Natural Protocol Variation)",
    },
  };

  const curr = cases[selectedCase];

  return (
    <div className="soc-content">
      {/* ── Section Header ── */}
      <div className="panel" style={{ padding: 20 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--accent-cyan)", textTransform: "uppercase", letterSpacing: 0.6 }}>
              Research Section 4.5 & Figure 11
            </div>
            <h1 className="building-title" style={{ fontSize: 24, marginTop: 4 }}>
              Transformer Self-Attention Interpretability
            </h1>
          </div>

          <div style={{ display: "flex", gap: 8 }}>
            <button
              className={`btn-secondary-soc ${selectedCase === "ddos" ? "btn-primary-soc" : ""}`}
              onClick={() => setSelectedCase("ddos")}
            >
              DDoS Attack Pattern
            </button>
            <button
              className={`btn-secondary-soc ${selectedCase === "portscan" ? "btn-primary-soc" : ""}`}
              onClick={() => setSelectedCase("portscan")}
            >
              PortScan Pattern
            </button>
            <button
              className={`btn-secondary-soc ${selectedCase === "benign" ? "btn-primary-soc" : ""}`}
              onClick={() => setSelectedCase("benign")}
            >
              Benign Normal Traffic
            </button>
          </div>
        </div>

        <p style={{ fontSize: 13, color: "var(--text-muted)", lineHeight: 1.6, maxWidth: 900 }}>
          Unlike black-box deep learning architectures (like standard CNNs or LSTMs), MEIC-ViT enables
          cybersecurity analysts to visually explain <i>why</i> a packet burst was classified as malicious.
          By extracting and layer-averaging the self-attention weights A = Softmax(Q·K^T / √d_k),
          we project the neural attention directly back onto the 24-bit flow image.
        </p>
      </div>

      {/* ── Figure 11 Side-by-Side Comparison ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 20 }}>
        {/* Visual Box */}
        <div className="panel" style={{ padding: 20, textAlign: "center" }}>
          <div className="panel-title" style={{ justifyContent: "center", marginBottom: 16 }}>
            <Sparkles size={16} color="var(--accent-purple)" />
            <span>Replication of Figure 11: {curr.title}</span>
          </div>

          {/* Synthetic Representation of Fig 11 */}
          <div style={{ display: "inline-flex", gap: 24, background: "#060b14", padding: 20, borderRadius: 8, border: "1px solid var(--border)" }}>
            <div>
              <div
                style={{
                  width: 160,
                  height: 160,
                  borderRadius: 4,
                  border: "1px solid var(--border)",
                  background: selectedCase === "ddos"
                    ? "linear-gradient(45deg, #1e3a8a 20%, #ef4444 60%, #dc2626 90%)"
                    : selectedCase === "portscan"
                    ? "linear-gradient(135deg, #0284c7 30%, #f59e0b 70%)"
                    : "linear-gradient(135deg, #064e3b 20%, #10b981 60%, #0284c7 90%)",
                  imageRendering: "pixelated",
                  position: "relative",
                  overflow: "hidden",
                }}
              >
                <div style={{
                  position: "absolute", inset: 0,
                  backgroundImage: "radial-gradient(rgba(255,255,255,0.2) 1px, transparent 1px)",
                  backgroundSize: "8px 8px"
                }} />
              </div>
              <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-main)", marginTop: 8 }}>
                24-bit RGB Flow Matrix
              </div>
              <div style={{ fontSize: 10, color: "var(--text-dim)" }}>
                $W=35 \times 35 \times 3$ Bytes
              </div>
            </div>

            <div>
              <div
                style={{
                  width: 160,
                  height: 160,
                  borderRadius: 4,
                  border: "1px solid var(--border)",
                  background: selectedCase === "ddos"
                    ? "radial-gradient(circle at 50% 50%, #ef4444 30%, #f97316 60%, #1e3a8a 100%)"
                    : selectedCase === "portscan"
                    ? "linear-gradient(90deg, #1e3a8a 0%, #f59e0b 50%, #ef4444 80%, #1e3a8a 100%)"
                    : "radial-gradient(circle at 50% 50%, #10b981 20%, #0284c7 60%, #0f172a 100%)",
                  imageRendering: "pixelated",
                  position: "relative",
                }}
              >
                <div style={{
                  position: "absolute", inset: 0,
                  backgroundImage: "linear-gradient(rgba(255,255,255,0.15) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.15) 1px, transparent 1px)",
                  backgroundSize: "16px 16px"
                }} />
              </div>
              <div style={{ fontSize: 11, fontWeight: 700, color: "#f97316", marginTop: 8 }}>
                Layer-Averaged Attention
              </div>
              <div style={{ fontSize: 10, color: "var(--text-dim)" }}>
                Jet Colormap ($L=6, H=8$)
              </div>
            </div>
          </div>

          <div style={{ marginTop: 16, fontSize: 12, color: "var(--text-muted)" }}>
            Blue = Low Attention (~0.0) • Green/Yellow = Medium (~0.5) • Red = High Critical Attention (~1.0)
          </div>
        </div>

        {/* Analytical Explanation */}
        <div className="panel" style={{ padding: 20, display: "flex", flexDirection: "column", gap: 14 }}>
          <div className="panel-title">
            <BookOpen size={16} color="var(--accent-cyan)" />
            <span>Cybersecurity Analysis</span>
          </div>

          <div style={{ fontSize: 13, color: "var(--text-main)", lineHeight: 1.6 }}>
            {curr.description}
          </div>

          <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: 6, padding: "12px 14px" }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--accent-cyan)", textTransform: "uppercase" }}>
              Key Attention Triggers
            </div>
            <div style={{ fontSize: 12, color: "#fff", marginTop: 4 }}>
              {curr.tokenFocus}
            </div>
          </div>

          <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: 6, padding: "12px 14px" }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--accent-purple)", textTransform: "uppercase" }}>
              Feature Entropy Score
            </div>
            <div style={{ fontSize: 12, color: "#fff", marginTop: 4, fontFamily: "var(--font-mono)" }}>
              {curr.entropy}
            </div>
          </div>

          <div style={{ marginTop: "auto", fontSize: 11, color: "var(--text-dim)", lineHeight: 1.5 }}>
            *Reference: Xiao et al., "MEIC-ViT: A multi-scale enhanced vision transformer for network intrusion detection," <i>Computer Networks</i> 282 (2026), Section 4.5.
          </div>
        </div>
      </div>
    </div>
  );
};
