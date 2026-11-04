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
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        {/* Sensor Status */}
        <div style={{
          display: "flex", alignItems: "center", gap: 6,
          background: "rgba(16, 185, 129, 0.08)", border: "1px solid rgba(16, 185, 129, 0.25)",
          padding: "5px 10px", borderRadius: 6, fontSize: 11, color: "#10b981", fontWeight: 600,
        }}>
          <span style={{ position: "relative", display: "inline-flex", width: 7, height: 7 }}>
            <span style={{ position: "absolute", inset: 0, borderRadius: "50%", background: "#10b981", opacity: 0.6, animation: "ping 1.4s cubic-bezier(0,0,0.2,1) infinite" }} />
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: "#10b981" }} />
          </span>
          <span>ONLINE</span>
        </div>

        {/* Audio Alarm Icon Toggle */}
        <button
          onClick={toggleSound}
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            width: 32,
            height: 32,
            background: isMuted ? "rgba(239, 68, 68, 0.12)" : "rgba(16, 185, 129, 0.12)",
            border: `1px solid ${isMuted ? "rgba(239, 68, 68, 0.35)" : "rgba(16, 185, 129, 0.35)"}`,
            borderRadius: 6,
            color: isMuted ? "#ef4444" : "#10b981",
            cursor: "pointer",
            transition: "all 0.15s",
          }}
          title={isMuted ? "Audio Alarms Muted (Click to Arm Sound)" : "Audio Alarms Active (Click to Mute Sound)"}
        >
          {isMuted ? <VolumeX size={15} /> : <Volume2 size={15} />}
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
              padding: "5px 10px",
              borderRadius: 6,
              fontSize: 11,
              fontWeight: 800,
              color: activeAlert.threat_level === "CRITICAL" ? "#ef4444" : "#f97316",
              boxShadow: activeAlert.threat_level === "CRITICAL" ? "0 0 12px rgba(239, 68, 68, 0.5)" : "0 0 10px rgba(249, 115, 22, 0.4)",
              animation: "pulse 1.2s infinite",
              cursor: "pointer",
            }}
            title="Active threat detected. Click to inspect details."
          >
            <AlertTriangle size={13} />
            <span>{activeAlert.threat_level} THREAT</span>
          </div>
        )}

        {/* UTC Clock */}
        <div style={{
          display: "flex", alignItems: "center", gap: 6,
          background: "rgba(255, 255, 255, 0.03)", border: "1px solid var(--border)",
          padding: "5px 10px", borderRadius: 6, fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)",
        }}>
          <Clock size={12} />
          <span>{timeStr || "UTC"}</span>
        </div>

        {/* Lockdown Status indicator */}
        {lockdown && (
          <div style={{
            display: "flex", alignItems: "center", gap: 6,
            background: "rgba(239, 68, 68, 0.15)", border: "1px solid rgba(239, 68, 68, 0.4)",
            padding: "5px 10px", borderRadius: 6, fontSize: 11, color: "#ef4444", fontWeight: 700,
            animation: "pulse 1.5s infinite",
          }}>
            <ShieldAlert size={14} />
            <span>LOCKDOWN</span>
          </div>
        )}
      </div>
    </header>
  );
};
