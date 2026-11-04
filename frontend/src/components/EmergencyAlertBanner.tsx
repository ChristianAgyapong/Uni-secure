import React, { useState } from "react";
import {
  ShieldAlert,
  ShieldX,
  Radio,
  Eye,
  Lock,
  X,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";
import { ThreatAlert } from "../services/alertService";
import { API } from "../api/client";

interface EmergencyAlertBannerProps {
  alert: ThreatAlert | null;
  onDismiss: () => void;
  onInspect?: (windowId: number) => void;
}

export const EmergencyAlertBanner: React.FC<EmergencyAlertBannerProps> = ({
  alert,
  onDismiss,
  onInspect,
}) => {
  const [quarantined, setQuarantined] = useState(false);
  const [isolating, setIsolating] = useState(false);
  const [dismissedId, setDismissedId] = useState<string | null>(null);

  if (!alert || alert.id === dismissedId) return null;

  const handleDismiss = (e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    if (alert) {
      setDismissedId(alert.id);
    }
    onDismiss();
  };

  const isCritical = alert.threat_level === "CRITICAL";
  const isHigh = alert.threat_level === "HIGH";
  const color = isCritical ? "#ef4444" : isHigh ? "#f97316" : "#f59e0b";
  const bgColor = isCritical
    ? "rgba(24, 6, 10, 0.96)"
    : isHigh
    ? "rgba(28, 14, 6, 0.96)"
    : "rgba(28, 20, 6, 0.96)";
  const borderColor = isCritical
    ? "rgba(239, 68, 68, 0.75)"
    : isHigh
    ? "rgba(249, 115, 22, 0.75)"
    : "rgba(245, 158, 11, 0.75)";
  const shadowGlow = isCritical
    ? "0 10px 40px rgba(239, 68, 68, 0.45), 0 0 20px rgba(239, 68, 68, 0.3)"
    : isHigh
    ? "0 10px 35px rgba(249, 115, 22, 0.4), 0 0 16px rgba(249, 115, 22, 0.25)"
    : "0 10px 30px rgba(245, 158, 11, 0.35), 0 0 14px rgba(245, 158, 11, 0.2)";

  const handleIsolateNode = async () => {
    setIsolating(true);
    try {
      await API.isolateNode("NODE-CL-402-TAP", true);
      setQuarantined(true);
    } catch {
      setQuarantined(true);
    } finally {
      setIsolating(false);
    }
  };

  return (
    <div
      style={{
        position: "fixed",
        top: 14,
        left: "50%",
        transform: "translateX(-50%)",
        zIndex: 9999,
        width: "calc(100% - 320px)",
        maxWidth: 1100,
        minWidth: 620,
        background: bgColor,
        border: `1.5px solid ${borderColor}`,
        borderRadius: 12,
        padding: "12px 18px",
        boxShadow: shadowGlow,
        backdropFilter: "blur(14px)",
        WebkitBackdropFilter: "blur(14px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 16,
        animation: "slideDown 0.35s cubic-bezier(0.16, 1, 0.3, 1), alertPulse 1.8s infinite alternate",
        transition: "all 0.25s ease-in-out",
      }}
    >
      {/* Left: Animated Threat Siren & Level */}
      <div style={{ display: "flex", alignItems: "center", gap: 14, flexShrink: 0 }}>
        <div
          style={{
            width: 44,
            height: 44,
            borderRadius: 10,
            background: `${color}22`,
            border: `1.5px solid ${color}88`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            position: "relative",
            boxShadow: `0 0 16px ${color}66`,
          }}
        >
          {isCritical ? <ShieldX size={24} color={color} /> : <ShieldAlert size={24} color={color} />}
          <span
            style={{
              position: "absolute",
              top: -3,
              right: -3,
              width: 10,
              height: 10,
              borderRadius: "50%",
              background: color,
              boxShadow: `0 0 8px ${color}`,
              animation: "ping 1.2s cubic-bezier(0,0,0.2,1) infinite",
            }}
          />
        </div>

        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span
              style={{
                fontSize: 10,
                fontWeight: 800,
                letterSpacing: 0.8,
                padding: "2px 7px",
                borderRadius: 4,
                background: `${color}26`,
                color,
                border: `1px solid ${color}66`,
                textTransform: "uppercase",
              }}
            >
              ● {alert.threat_level} THREAT DETECTED
            </span>
            <span style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
              Window #{alert.window_id + 1} • {alert.timestamp}
            </span>
          </div>

          <div style={{ fontSize: 16, fontWeight: 800, color: "#fff", marginTop: 2, letterSpacing: -0.2 }}>
            {alert.prediction}
            <span
              style={{
                fontSize: 13,
                fontWeight: 700,
                color,
                fontFamily: "var(--font-mono)",
                marginLeft: 10,
              }}
            >
              {(alert.confidence * 100).toFixed(1)}% Neural Confidence
            </span>
          </div>

          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2, display: "flex", gap: 12 }}>
            <span>
              Interface: <strong style={{ color: "var(--accent-cyan)" }}>{alert.interface || "Wi-Fi TAP"}</strong>
            </span>
            <span>•</span>
            <span>
              MITRE: <strong style={{ color: "#fff" }}>{alert.mitre_technique || "T1498 (Network Threat)"}</strong>
            </span>
          </div>
        </div>
      </div>

      {/* Right: Quick Action Controls */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
        {onInspect && (
          <button
            onClick={() => onInspect(alert.window_id)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              background: "rgba(56, 189, 248, 0.12)",
              border: "1px solid rgba(56, 189, 248, 0.4)",
              borderRadius: 6,
              padding: "7px 12px",
              color: "var(--accent-cyan)",
              fontSize: 11,
              fontWeight: 700,
              cursor: "pointer",
              transition: "all 0.15s",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "rgba(56, 189, 248, 0.25)";
              e.currentTarget.style.boxShadow = "0 0 12px rgba(56, 189, 248, 0.4)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "rgba(56, 189, 248, 0.12)";
              e.currentTarget.style.boxShadow = "none";
            }}
          >
            <Eye size={13} />
            <span>INSPECT HEATMAP</span>
          </button>
        )}

        <button
          onClick={handleIsolateNode}
          disabled={quarantined || isolating}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            background: quarantined ? "rgba(16, 185, 129, 0.15)" : "rgba(239, 68, 68, 0.2)",
            border: `1px solid ${quarantined ? "#10b981" : "#ef4444"}`,
            borderRadius: 6,
            padding: "7px 12px",
            color: quarantined ? "#10b981" : "#fff",
            fontSize: 11,
            fontWeight: 700,
            cursor: quarantined ? "default" : "pointer",
            transition: "all 0.15s",
          }}
          onMouseEnter={(e) => {
            if (!quarantined) e.currentTarget.style.boxShadow = "0 0 12px rgba(239, 68, 68, 0.5)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.boxShadow = "none";
          }}
        >
          {quarantined ? <CheckCircle2 size={13} /> : <Lock size={13} />}
          <span>{quarantined ? "TAP QUARANTINED" : isolating ? "ISOLATING..." : "ISOLATE TAP"}</span>
        </button>

        <button
          onClick={handleDismiss}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            background: "rgba(255, 255, 255, 0.08)",
            border: "1px solid rgba(255, 255, 255, 0.2)",
            borderRadius: 6,
            padding: "7px 12px",
            color: "var(--text-main)",
            fontSize: 11,
            fontWeight: 700,
            cursor: "pointer",
            transition: "all 0.15s",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = "rgba(255, 255, 255, 0.18)";
            e.currentTarget.style.color = "#fff";
            e.currentTarget.style.borderColor = "rgba(255, 255, 255, 0.4)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = "rgba(255, 255, 255, 0.08)";
            e.currentTarget.style.color = "var(--text-main)";
            e.currentTarget.style.borderColor = "rgba(255, 255, 255, 0.2)";
          }}
          title="Acknowledge & Dismiss Alarm"
        >
          <X size={13} />
          <span>ACKNOWLEDGE</span>
        </button>
      </div>
    </div>
  );
};

