import React, { useState, useEffect } from "react";
import { ShieldCheck, Zap, Radio, Clock, AlertTriangle, ShieldAlert } from "lucide-react";
import { API } from "../api/client";

export const Header: React.FC = () => {
  const [timeStr, setTimeStr] = useState<string>("");
  const [lockdown, setLockdown] = useState<boolean>(false);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeStr(now.toTimeString().split(" ")[0] + " UTC");
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    API.health()
      .then((res) => setLockdown(res.lockdown_active))
      .catch(() => {});
  }, []);

  return (
    <header className="soc-header" style={{ height: 64, padding: "0 24px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
      {/* Brand & Platform Identity */}
      <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
        <div style={{
          width: 34, height: 34, borderRadius: 8,
          background: "linear-gradient(135deg, #0284c7, #6366f1)",
          display: "flex", alignItems: "center", justifyContent: "center",
          color: "#fff", fontWeight: 800, fontSize: 15,
          boxShadow: "0 0 15px rgba(2, 132, 199, 0.4)",
        }}>
          <ShieldCheck size={20} />
        </div>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 15, fontWeight: 800, color: "#fff", letterSpacing: -0.2 }}>
              UniSecure XDR
            </span>
            <span style={{
              fontSize: 10, fontWeight: 700, padding: "2px 7px", borderRadius: 4,
              background: "rgba(14, 165, 233, 0.15)", color: "var(--accent-cyan)", border: "1px solid rgba(14, 165, 233, 0.3)",
              letterSpacing: 0.5,
            }}>
              ENTERPRISE SOC
            </span>
          </div>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2, display: "flex", alignItems: "center", gap: 6 }}>
            <span>Vision AI Threat Detection Platform</span>
            <span>•</span>
            <span style={{ color: "var(--accent-cyan)" }}>Real-Time Multi-Vector Protection</span>
          </div>
        </div>
      </div>

      {/* Operational Live Status & Telemetry Indicators */}
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        {/* Sensor Status */}
        <div style={{
          display: "flex", alignItems: "center", gap: 6,
          background: "rgba(16, 185, 129, 0.08)", border: "1px solid rgba(16, 185, 129, 0.25)",
          padding: "4px 10px", borderRadius: 6, fontSize: 11, color: "#10b981", fontWeight: 600,
        }}>
          <span style={{ position: "relative", display: "inline-flex", width: 7, height: 7 }}>
            <span style={{ position: "absolute", inset: 0, borderRadius: "50%", background: "#10b981", opacity: 0.6, animation: "ping 1.4s cubic-bezier(0,0,0.2,1) infinite" }} />
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: "#10b981" }} />
          </span>
          <span>SENSOR NETWORK ONLINE</span>
        </div>

        {/* Vectors Monitored */}
        <div style={{
          display: "flex", alignItems: "center", gap: 6,
          background: "rgba(56, 189, 248, 0.08)", border: "1px solid rgba(56, 189, 248, 0.25)",
          padding: "4px 10px", borderRadius: 6, fontSize: 11, color: "var(--accent-cyan)", fontWeight: 600,
        }}>
          <Zap size={13} />
          <span>15 ATTACK VECTORS ARMED</span>
        </div>

        {/* Clock */}
        <div style={{
          display: "flex", alignItems: "center", gap: 6,
          background: "rgba(255, 255, 255, 0.03)", border: "1px solid var(--border)",
          padding: "4px 10px", borderRadius: 6, fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)",
        }}>
          <Clock size={12} />
          <span>{timeStr || "SYSTEM CLOCK"}</span>
        </div>

        {/* Lockdown Status indicator */}
        {lockdown && (
          <div style={{
            display: "flex", alignItems: "center", gap: 6,
            background: "rgba(239, 68, 68, 0.15)", border: "1px solid rgba(239, 68, 68, 0.4)",
            padding: "4px 10px", borderRadius: 6, fontSize: 11, color: "#ef4444", fontWeight: 700,
            animation: "pulse 1.5s infinite",
          }}>
            <ShieldAlert size={14} />
            <span>CAMPUS LOCKDOWN ACTIVE</span>
          </div>
        )}
      </div>
    </header>
  );
};
