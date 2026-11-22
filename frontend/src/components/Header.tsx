import React, { useState, useEffect } from "react";
import { ShieldCheck, Zap, Radio, Clock, AlertTriangle, ShieldAlert, Volume2, VolumeX, Bell } from "lucide-react";
import { API } from "../api/client";
import { alertService, ThreatAlert } from "../services/alertService";

export const Header: React.FC = () => {
  const [timeStr, setTimeStr] = useState<string>("");
  const [lockdown, setLockdown] = useState<boolean>(false);
  const [isMuted, setIsMuted] = useState<boolean>(alertService.isMuted());
  const [activeAlert, setActiveAlert] = useState<ThreatAlert | null>(null);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const hours = String(now.getUTCHours()).padStart(2, "0");
      const minutes = String(now.getUTCMinutes()).padStart(2, "0");
      setTimeStr(`${hours}:${minutes} UTC`);
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    API.health()
      .then((res) => setLockdown(res.lockdown_active))
      .catch(() => {});

    const unsubAlert = alertService.subscribeAlert((alert) => setActiveAlert(alert));
    const unsubMute = alertService.subscribeMute((muted) => setIsMuted(muted));
    return () => {
      unsubAlert();
      unsubMute();
    };
  }, []);

  const toggleSound = () => {
    alertService.toggleMute();
  };

  return (
    <header className="soc-header" style={{ height: 68, padding: "0 28px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
      {/* Brand & Platform Identity */}
      <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
        <div style={{
          width: 38, height: 38, borderRadius: 10,
          background: "linear-gradient(135deg, #0284c7 0%, #6366f1 100%)",
          display: "flex", alignItems: "center", justifyContent: "center",
          color: "#fff", fontWeight: 800, fontSize: 16,
          boxShadow: "0 0 20px rgba(14, 165, 233, 0.45), inset 0 1px 0 rgba(255, 255, 255, 0.3)",
          border: "1px solid rgba(255, 255, 255, 0.15)",
        }}>
          <ShieldCheck size={22} />
        </div>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 16, fontWeight: 800, color: "#fff", letterSpacing: -0.3 }}>
              UniSecure XDR
            </span>
            <span style={{
              fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 999,
              background: "rgba(14, 165, 233, 0.12)", color: "var(--accent-cyan)", border: "1px solid rgba(56, 189, 248, 0.3)",
              letterSpacing: 0.6, fontFamily: "var(--font-mono)",
            }}>
              ENTERPRISE SOC v2.4
            </span>
          </div>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2, display: "flex", alignItems: "center", gap: 6 }}>
            <span>Vision AI Threat Detection Platform</span>
            <span style={{ color: "rgba(255,255,255,0.2)" }}>•</span>
            <span style={{ color: "var(--accent-cyan)", fontWeight: 500 }}>Real-Time Multi-Vector Defense</span>
          </div>
        </div>
      </div>

      {/* Operational Live Status & Telemetry Indicators */}
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        {/* Sensor Status */}
        <div style={{
          display: "flex", alignItems: "center", gap: 7,
          background: "rgba(16, 185, 129, 0.08)", border: "1px solid rgba(16, 185, 129, 0.25)",
          padding: "6px 12px", borderRadius: 999, fontSize: 11, color: "#10b981", fontWeight: 600,
          fontFamily: "var(--font-mono)", letterSpacing: 0.4,
          boxShadow: "0 2px 8px rgba(16, 185, 129, 0.12)",
        }}>
          <span style={{ position: "relative", display: "inline-flex", width: 7, height: 7 }}>
            <span style={{ position: "absolute", inset: 0, borderRadius: "50%", background: "#10b981", opacity: 0.7, animation: "ping 1.4s cubic-bezier(0,0,0.2,1) infinite" }} />
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: "#10b981" }} />
          </span>
          <span>SENSOR NETWORK ONLINE</span>
        </div>

        {/* ViT Model Indicator */}
        <div style={{
          display: "flex", alignItems: "center", gap: 6,
          background: "rgba(99, 102, 241, 0.08)", border: "1px solid rgba(99, 102, 241, 0.25)",
          padding: "6px 12px", borderRadius: 999, fontSize: 11, color: "#a5b4fc", fontWeight: 600,
          fontFamily: "var(--font-mono)", letterSpacing: 0.4,
        }}>
          <Zap size={12} color="#818cf8" />
          <span>15 ATTACK VECTORS ARMED</span>
        </div>

        {/* UTC Clock */}
        <div style={{
          display: "flex", alignItems: "center", gap: 6,
          background: "rgba(255, 255, 255, 0.04)", border: "1px solid var(--border)",
          padding: "6px 12px", borderRadius: 999, fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)",
        }}>
          <Clock size={12} color="var(--accent-cyan)" />
          <span>{timeStr || "UTC"}</span>
        </div>

        {/* Audio Alarm Icon Toggle */}
        <button
          onClick={toggleSound}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            height: 32,
            padding: "0 10px",
            background: isMuted ? "rgba(239, 68, 68, 0.1)" : "rgba(16, 185, 129, 0.1)",
            border: `1px solid ${isMuted ? "rgba(239, 68, 68, 0.3)" : "rgba(16, 185, 129, 0.3)"}`,
            borderRadius: 999,
            color: isMuted ? "#ef4444" : "#10b981",
            cursor: "pointer",
            transition: "all 0.2s ease",
            fontSize: 11,
            fontWeight: 700,
            fontFamily: "var(--font-mono)",
          }}
          title={isMuted ? "Audio Alarms Muted (Click to Arm Sound)" : "Audio Alarms Active (Click to Mute Sound)"}
        >
          {isMuted ? <VolumeX size={14} /> : <Volume2 size={14} />}
          <span>{isMuted ? "MUTED" : "AUDIO ARMED"}</span>
        </button>

        {/* Active Alert Threat Pill */}
        {activeAlert && (
          <div
            onClick={() => {
              const el = document.getElementById("window-detail-inspector");
              if (el) el.scrollIntoView({ behavior: "smooth", block: "center" });
            }}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              background: activeAlert.threat_level === "CRITICAL" ? "rgba(239, 68, 68, 0.2)" : "rgba(249, 115, 22, 0.2)",
              border: `1px solid ${activeAlert.threat_level === "CRITICAL" ? "#ef4444" : "#f97316"}`,
              padding: "6px 12px",
              borderRadius: 999,
              fontSize: 11,
              fontWeight: 800,
              fontFamily: "var(--font-mono)",
              color: activeAlert.threat_level === "CRITICAL" ? "#ef4444" : "#f97316",
              boxShadow: activeAlert.threat_level === "CRITICAL" ? "0 0 16px rgba(239, 68, 68, 0.5)" : "0 0 12px rgba(249, 115, 22, 0.4)",
              animation: "pulse 1.2s infinite",
              cursor: "pointer",
            }}
            title="Active threat detected. Click to inspect details."
          >
            <AlertTriangle size={13} />
            <span>ALARM: {activeAlert.threat_level}</span>
          </div>
        )}

        {/* Lockdown Status indicator */}
        {lockdown && (
          <div style={{
            display: "flex", alignItems: "center", gap: 6,
            background: "rgba(239, 68, 68, 0.2)", border: "1px solid rgba(239, 68, 68, 0.6)",
            padding: "6px 12px", borderRadius: 999, fontSize: 11, color: "#ef4444", fontWeight: 700,
            fontFamily: "var(--font-mono)",
            animation: "pulse 1.5s infinite",
            boxShadow: "0 0 16px rgba(239, 68, 68, 0.4)",
          }}>
            <ShieldAlert size={14} />
            <span>LOCKDOWN ACTIVE</span>
          </div>
        )}
      </div>
    </header>
  );
};
