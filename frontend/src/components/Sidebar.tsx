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
        <div className="sidebar-header" style={{ padding: "16px 14px", marginBottom: 18 }}>
          <div className="sidebar-header-icon" style={{
            background: "linear-gradient(135deg, rgba(2,132,199,0.3), rgba(99,102,241,0.25))",
            border: "1px solid rgba(56,189,248,0.4)",
            width: 36, height: 36, borderRadius: 10,
          }}>
            <ShieldCheck size={20} color="var(--accent-cyan)" />
          </div>
          <div>
            <div className="sidebar-title" style={{ fontSize: 15, fontWeight: 800, color: "#fff", letterSpacing: -0.3 }}>
              UniSecure SOC
            </div>
            <div style={{ fontSize: 11, color: "var(--accent-cyan)", marginTop: 2, fontWeight: 600, display: "flex", alignItems: "center", gap: 5 }}>
              <span className="pulse-dot" style={{ width: 5, height: 5 }} />
              <span>AI Defense Operations</span>
            </div>
          </div>
        </div>

        {/* Functional Operations Navigation */}
        <nav className="sidebar-nav" style={{ padding: "4px 0" }}>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                className={`nav-item ${isActive ? "active" : ""}`}
                style={{
                  padding: "11px 14px",
                  borderRadius: "var(--radius-sm)",
                  marginBottom: 4,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  width: "100%",
                }}
                onClick={() => onSelectTab(item.id)}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 11 }}>
                  <Icon size={18} color={isActive ? "var(--accent-cyan)" : "var(--text-muted)"} />
                  <div style={{ display: "flex", flexDirection: "column", textAlign: "left" }}>
                    <span style={{ fontSize: 13, fontWeight: isActive ? 700 : 500, color: isActive ? "#fff" : "var(--text-main)" }}>
                      {item.label}
                    </span>
                    <span style={{ fontSize: 10, color: isActive ? "rgba(255,255,255,0.75)" : "var(--text-dim)", marginTop: 1 }}>
                      {item.subtitle}
                    </span>
                  </div>
                </div>
                {item.badge && (
                  <span style={{
                    fontSize: 9, fontWeight: 700, padding: "2px 7px", borderRadius: 999,
                    background: `${item.badgeColor}20`, color: item.badgeColor, border: `1px solid ${item.badgeColor}40`,
                    fontFamily: "var(--font-mono)", letterSpacing: 0.4,
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
            background: "linear-gradient(135deg, rgba(16, 185, 129, 0.08), rgba(6, 182, 212, 0.05))",
            border: "1px solid rgba(16, 185, 129, 0.25)",
            borderRadius: "var(--radius-sm)",
            padding: "12px 14px",
            display: "flex",
            alignItems: "center",
            gap: 10,
            boxShadow: "0 4px 12px rgba(0,0,0,0.25)",
          }}
        >
          <CheckCircle2 size={18} color="#10b981" />
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: "#10b981" }}>
              {isModelReady ? "Vision AI Engine Active" : "Engine Initializing…"}
            </div>
            <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 1, fontFamily: "var(--font-mono)" }}>
              5.03M Parameters (ViT)
            </div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: 10, color: "var(--text-dim)", marginTop: 8, paddingInline: 2, fontFamily: "var(--font-mono)" }}>
          <span>Zero-Day Guard</span>
          <span style={{ color: "#10b981", fontWeight: 700, display: "flex", alignItems: "center", gap: 4 }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#10b981" }} />
            <span>ACTIVE</span>
          </span>
        </div>
      </div>
    </aside>
  );
};
