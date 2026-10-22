import React from "react";
import {
  Activity,
  Eye,
  BarChart2,
  Cpu,
  BookOpen,
  CheckCircle2,
} from "lucide-react";

export type ResearchTab = "pipeline" | "interpretability" | "benchmarks" | "architecture";

interface SidebarProps {
  currentTab: ResearchTab;
  onSelectTab: (tab: ResearchTab) => void;
  isModelReady: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  isModelReady,
}) => {
  const navItems = [
    {
      id: "pipeline" as ResearchTab,
      label: "Detection Pipeline",
      subtitle: "Algorithm 1 & Real Inference",
      icon: Activity,
    },
    {
      id: "interpretability" as ResearchTab,
      label: "Attention Heatmaps",
      subtitle: "Figure 11 Interpretability",
      icon: Eye,
    },
    {
      id: "benchmarks" as ResearchTab,
      label: "Paper Benchmarks",
      subtitle: "CICIDS-2017 & Comparisons",
      icon: BarChart2,
    },
    {
      id: "architecture" as ResearchTab,
      label: "Model Architecture",
      subtitle: "Figure 3 & Multi-Path ViT",
      icon: Cpu,
    },
  ];

  return (
    <aside className="soc-sidebar">
      <div>
        {/* Research Paper Brand Header */}
        <div className="sidebar-header" style={{ borderStyle: "solid" }}>
          <div className="sidebar-header-icon" style={{ background: "rgba(56, 189, 248, 0.15)" }}>
            <Activity size={20} color="#38bdf8" />
          </div>
          <div>
            <div className="sidebar-title" style={{ fontSize: 15 }}>MEIC-ViT</div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
              Computer Networks 2026
            </div>
          </div>
        </div>

        {/* Clean Paper-Aligned Navigation */}
        <nav className="sidebar-nav">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                className={`nav-item ${isActive ? "active" : ""}`}
                style={{ padding: "12px 14px" }}
                onClick={() => onSelectTab(item.id)}
              >
                <Icon size={18} />
                <div style={{ display: "flex", flexDirection: "column", textAlign: "left" }}>
                  <span style={{ fontSize: 13, fontWeight: isActive ? 700 : 500 }}>
                    {item.label}
                  </span>
                  <span style={{ fontSize: 10, color: isActive ? "rgba(255,255,255,0.8)" : "var(--text-dim)", marginTop: 1 }}>
                    {item.subtitle}
                  </span>
                </div>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Model & Paper Status Footer */}
      <div className="sidebar-footer" style={{ borderTop: "1px solid var(--border)" }}>
        <div
          style={{
            background: "rgba(16, 185, 129, 0.08)",
            border: "1px solid rgba(16, 185, 129, 0.25)",
            borderRadius: 6,
            padding: "10px 12px",
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <CheckCircle2 size={16} color="#10b981" />
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: "#10b981" }}>
              {isModelReady ? "5.03M Model Loaded" : "Model Initializing"}
            </div>
            <div style={{ fontSize: 10, color: "var(--text-dim)" }}>
              PyTorch Checkpoint Active
            </div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: "var(--text-dim)", marginTop: 4 }}>
          <BookOpen size={13} />
          <span>Xiao et al. · Xi'an Univ of Tech</span>
        </div>
      </div>
    </aside>
  );
};
