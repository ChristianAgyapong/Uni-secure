import React from "react";
import {
  Activity,
  Eye,
  BarChart2,
  Cpu,
  ShieldCheck,
  CheckCircle2,
  ShieldAlert,
  Radio,
  Server,
  Layers,
} from "lucide-react";

export type ResearchTab = "pipeline" | "interpretability" | "benchmarks" | "architecture" | "soc";

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
      label: "Live Threat Monitor",
      subtitle: "Real-Time Ingestion & Triage",
      icon: Activity,
      badge: "LIVE",
      badgeColor: "#10b981",
    },
    {
      id: "interpretability" as ResearchTab,
      label: "Visual AI Forensics",
      subtitle: "Packet Attention Heatmaps",
      icon: Eye,
      badge: "AI",
      badgeColor: "#38bdf8",
    },
    {
      id: "soc" as ResearchTab,
      label: "SOC Command Deck",
      subtitle: "Campus Nodes, Isolation & Logs",
      icon: ShieldAlert,
      badge: "OPS",
      badgeColor: "#f59e0b",
    },
    {
      id: "benchmarks" as ResearchTab,
      label: "Security Telemetry",
      subtitle: "Accuracy, Speed & Hardware Test",
      icon: BarChart2,
      badge: "98.3%",
      badgeColor: "#818cf8",
    },
    {
      id: "architecture" as ResearchTab,
      label: "Neural Engine Blueprint",
      subtitle: "Multi-Path Vision Pipeline",
      icon: Cpu,
      badge: null,
      badgeColor: null,
    },
  ];

  return (
    <aside className="soc-sidebar" style={{ display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
      <div>
        {/* Operations Brand Header */}
        <div className="sidebar-header" style={{ padding: "18px 16px", borderBottom: "1px solid var(--border)" }}>
          <div className="sidebar-header-icon" style={{
            background: "linear-gradient(135deg, rgba(2,132,199,0.2), rgba(99,102,241,0.2))",
            border: "1px solid rgba(56,189,248,0.3)",
          }}>
            <ShieldCheck size={20} color="var(--accent-cyan)" />
          </div>
          <div>
            <div className="sidebar-title" style={{ fontSize: 15, fontWeight: 800, color: "#fff", letterSpacing: -0.2 }}>
              UniSecure SOC
            </div>
            <div style={{ fontSize: 11, color: "var(--accent-cyan)", marginTop: 2, fontWeight: 600 }}>
              AI Defense Operations
            </div>
          </div>
        </div>

        {/* Functional Operations Navigation */}
        <nav className="sidebar-nav" style={{ padding: "12px 10px" }}>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                className={`nav-item ${isActive ? "active" : ""}`}
                style={{
                  padding: "11px 12px",
                  borderRadius: 8,
                  marginBottom: 4,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  width: "100%",
                }}
                onClick={() => onSelectTab(item.id)}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <Icon size={18} color={isActive ? "var(--accent-cyan)" : "var(--text-muted)"} />
                  <div style={{ display: "flex", flexDirection: "column", textAlign: "left" }}>
                    <span style={{ fontSize: 13, fontWeight: isActive ? 700 : 500, color: isActive ? "#fff" : "var(--text-main)" }}>
                      {item.label}
                    </span>
                    <span style={{ fontSize: 10, color: isActive ? "rgba(255,255,255,0.7)" : "var(--text-dim)", marginTop: 1 }}>
                      {item.subtitle}
                    </span>
                  </div>
                </div>
                {item.badge && (
                  <span style={{
                    fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 4,
                    background: `${item.badgeColor}18`, color: item.badgeColor, border: `1px solid ${item.badgeColor}33`,
                    fontFamily: "var(--font-mono)",
                  }}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Model Engine Status Footer */}
      <div className="sidebar-footer" style={{ padding: 14, borderTop: "1px solid var(--border)" }}>
        <div
          style={{
            background: "rgba(16, 185, 129, 0.08)",
            border: "1px solid rgba(16, 185, 129, 0.25)",
            borderRadius: 8,
            padding: "10px 12px",
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          <CheckCircle2 size={18} color="#10b981" />
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: "#10b981" }}>
              {isModelReady ? "Vision AI Engine Active" : "Engine Initializing…"}
            </div>
            <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 1 }}>
              5.03M Parameters Loaded
            </div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: 10, color: "var(--text-dim)", marginTop: 8, paddingInline: 2 }}>
          <span>Defense Mode: Zero-Day Guard</span>
          <span style={{ color: "#10b981", fontWeight: 700 }}>● RUNNING</span>
        </div>
      </div>
    </aside>
  );
};
