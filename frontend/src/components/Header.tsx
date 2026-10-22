import React from "react";
import { BookOpen, ShieldCheck, Sparkles } from "lucide-react";

export const Header: React.FC = () => {
  return (
    <header className="soc-header" style={{ height: 60, padding: "0 24px" }}>
      {/* Paper Title & Journal info */}
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{
          width: 28, height: 28, borderRadius: 6,
          background: "linear-gradient(135deg, #0284c7, #818cf8)",
          display: "flex", alignItems: "center", justifyContent: "center",
          color: "#fff", fontWeight: 700, fontSize: 13
        }}>
          ViT
        </div>
        <div>
          <div style={{ fontSize: 14, fontWeight: 700, color: "#fff", letterSpacing: -0.2 }}>
            MEIC-ViT: Multi-Scale Enhanced Vision Transformer for Network Intrusion Detection
          </div>
          <div style={{ fontSize: 11, color: "var(--text-muted)", display: "flex", alignItems: "center", gap: 6 }}>
            <span>Computer Networks, Elsevier Vol. 282 (2026) 112273</span>
            <span>•</span>
            <span style={{ color: "var(--accent-cyan)" }}>Yeqiu Xiao, Peihua Wang, Yichuan Wang, et al.</span>
          </div>
        </div>
      </div>

      {/* Paper Badges */}
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span
          style={{
            background: "rgba(56, 189, 248, 0.1)",
            color: "var(--accent-cyan)",
            border: "1px solid rgba(56, 189, 248, 0.25)",
            padding: "4px 10px",
            borderRadius: 4,
            fontSize: 11,
            fontWeight: 600,
          }}
        >
          24-bit Flow-to-RGB (Algorithm 1)
        </span>
        <span
          style={{
            background: "rgba(129, 140, 248, 0.1)",
            color: "var(--accent-purple)",
            border: "1px solid rgba(129, 140, 248, 0.25)",
            padding: "4px 10px",
            borderRadius: 4,
            fontSize: 11,
            fontWeight: 600,
          }}
        >
          Parallel 3-Path ViT
        </span>
      </div>
    </header>
  );
};
