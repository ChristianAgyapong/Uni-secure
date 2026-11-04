/**
 * Real-Time Threat Audio & Alert Notification Service
 * UniSecure SOC — MEIC-ViT Intrusion Detection System
 * 
 * Synthesizes zero-latency acoustic alarm pulses via HTML5 Web Audio API
 * and coordinates high-priority floating emergency alerts across all views.
 */

export interface ThreatAlert {
  id: string;
  threat_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  prediction: string;
  confidence: number;
  window_id: number;
  timestamp: string;
  interface?: string;
  composite_b64?: string;
  mitre_technique?: string;
}

type AlertListener = (alert: ThreatAlert | null) => void;
type MuteListener = (muted: boolean) => void;

class ThreatAudioService {
  private ctx: AudioContext | null = null;
  private muted: boolean = false;
  private alertListeners: Set<AlertListener> = new Set();
  private muteListeners: Set<MuteListener> = new Set();
  private currentAlert: ThreatAlert | null = null;
  private lastAlertFingerprint: string = "";
  private dismissedFingerprints: Set<string> = new Set();
  private lastDismissedTime: number = 0;

  constructor() {
    try {
      const saved = localStorage.getItem("unisecure_soc_audio_muted");
      this.muted = saved === "1";
    } catch {
      this.muted = false;
    }
  }

  private initAudio() {
    if (!this.ctx) {
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      if (AudioCtx) this.ctx = new AudioCtx();
    }
    if (this.ctx && this.ctx.state === "suspended") {
      this.ctx.resume().catch(() => {});
    }
  }

  public setMuted(muted: boolean) {
    this.muted = muted;
    try {
      localStorage.setItem("unisecure_soc_audio_muted", muted ? "1" : "0");
    } catch {}
    this.muteListeners.forEach((fn) => fn(muted));
  }

  public toggleMute(): boolean {
    const next = !this.muted;
    this.setMuted(next);
    return next;
  }

  public isMuted(): boolean {
    return this.muted;
  }

  public subscribeAlert(fn: AlertListener): () => void {
    this.alertListeners.add(fn);
    fn(this.currentAlert);
    return () => this.alertListeners.delete(fn);
  }

  public subscribeMute(fn: MuteListener): () => void {
    this.muteListeners.add(fn);
    fn(this.muted);
    return () => this.muteListeners.delete(fn);
  }

  public getCurrentAlert(): ThreatAlert | null {
    return this.currentAlert;
  }

  public dismissAlert() {
    if (this.currentAlert) {
      const fp = `${this.currentAlert.window_id}-${this.currentAlert.prediction}`;
      this.dismissedFingerprints.add(fp);
      this.dismissedFingerprints.add(this.currentAlert.id);
    }
    this.lastDismissedTime = Date.now();
    this.currentAlert = null;
    this.alertListeners.forEach((fn) => fn(null));
  }

  /**
   * Evaluates window output and triggers alarm + alert if severity is HIGH or CRITICAL.
   */
  public reportWindow(w: {
    window: number;
    prediction: string;
    threat_level: string;
    confidence: number;
    composite_b64?: string;
  }, iface: string = "Wi-Fi TAP") {
    const predUpper = (w.prediction || "").toUpperCase();
    if (predUpper.startsWith("BENIGN") || predUpper.startsWith("NORMAL")) {
      return;
    }

    const level = (w.threat_level || "LOW").toUpperCase() as ThreatAlert["threat_level"];
    if (level !== "CRITICAL" && level !== "HIGH" && level !== "MEDIUM") {
      return;
    }

    // De-duplicate: check if this window was already triggered or explicitly dismissed
    const fingerprint = `${w.window}-${w.prediction}`;
    if (this.dismissedFingerprints.has(fingerprint)) {
      return;
    }

    if (fingerprint === this.lastAlertFingerprint) {
      return;
    }

    // Grace cooldown: if user just dismissed an alert within 5 seconds, don't re-pop for same class
    if (this.currentAlert === null && (Date.now() - this.lastDismissedTime < 5000)) {
      return;
    }

    this.lastAlertFingerprint = fingerprint;

    const mitreMap: Record<string, string> = {
      "DDoS": "T1498 (Network Denial of Service)",
      "DoS Hulk": "T1498 (Direct Volumetric Flooding)",
      "DoS GoldenEye": "T1499 (Endpoint DoS - Resource Exhaustion)",
      "DoS slowloris": "T1499.003 (Application Exhaustion)",
      "DoS Slowhttptest": "T1499.003 (Incomplete HTTP Request Flood)",
      "PortScan": "T1046 (Network Service Discovery / Port Recon)",
      "FTP-Patator": "T1110.001 (FTP Password Guessing)",
      "SSH-Patator": "T1110.001 (SSH Password Spraying)",
      "Heartbleed": "T1190 (OpenSSL TLS Memory Disclosure CVE-2014-0160)",
      "Web Attack Sql Injection": "T1190 (SQL Injection Data Extraction)",
      "Web Attack XSS": "T1189 (Stored / Reflected Cross-Site Scripting)",
      "Web Attack Brute Force": "T1110 (HTTP Authentication Brute Force)",
      "Bot": "T1071 (Application Layer Protocol C2 Beaconing)",
      "Infiltration": "T1078 (Valid Accounts Abuse / Lateral Movement)",
      "Exploits": "T1203 (Exploitation for Client Execution)",
      "Worms": "T1080 (Same-Subnet Spreading / Worm Propagation)",
      "Generic": "T1027 (Obfuscated / Encrypted Malicious Payload)",
      "Backdoor": "T1059 (Command & Scripting Interpreter Backdoor)",
    };

    const alert: ThreatAlert = {
      id: `ALERT-${Date.now()}`,
      threat_level: level,
      prediction: w.prediction,
      confidence: w.confidence,
      window_id: w.window,
      timestamp: new Date().toLocaleTimeString(),
      interface: iface,
      composite_b64: w.composite_b64,
      mitre_technique: mitreMap[w.prediction] || "T1059 (Execution / Network Threat)",
    };

    this.currentAlert = alert;
    this.alertListeners.forEach((fn) => fn(alert));

    // Acoustic Alarm Pulse
    if (level === "CRITICAL") {
      this.playCriticalKlaxon();
    } else {
      this.playWarningSonar();
    }
  }

  /**
   * Dual-tone acoustic alarm pulse for CRITICAL threats (DDoS, SQLi, Worms).
   * Synthesized in real-time via Web Audio API oscillators.
   */
  public playCriticalKlaxon() {
    if (this.muted) return;
    try {
      this.initAudio();
      if (!this.ctx) return;
      const now = this.ctx.currentTime;

      // Primary tone
      const osc1 = this.ctx.createOscillator();
      const gain1 = this.ctx.createGain();
      osc1.type = "sawtooth";
      osc1.frequency.setValueAtTime(880, now);
      osc1.frequency.exponentialRampToValueAtTime(440, now + 0.16);
      gain1.gain.setValueAtTime(0.18, now);
      gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.22);
      osc1.connect(gain1);
      gain1.connect(this.ctx.destination);
      osc1.start(now);
      osc1.stop(now + 0.22);

      // Staggered echo pulse
      const osc2 = this.ctx.createOscillator();
      const gain2 = this.ctx.createGain();
      osc2.type = "sawtooth";
      osc2.frequency.setValueAtTime(1046, now + 0.12);
      osc2.frequency.exponentialRampToValueAtTime(523, now + 0.30);
      gain2.gain.setValueAtTime(0.15, now + 0.12);
      gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.34);
      osc2.connect(gain2);
      gain2.connect(this.ctx.destination);
      osc2.start(now + 0.12);
      osc2.stop(now + 0.34);
    } catch {
      // Browser autoplay policy graceful catch
    }
  }

  /**
   * Single-pulse sonar ping for HIGH-level alerts.
   */
  public playWarningSonar() {
    if (this.muted) return;
    try {
      this.initAudio();
      if (!this.ctx) return;
      const now = this.ctx.currentTime;
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = "sine";
      osc.frequency.setValueAtTime(740, now);
      osc.frequency.exponentialRampToValueAtTime(440, now + 0.18);
      gain.gain.setValueAtTime(0.12, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.22);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start(now);
      osc.stop(now + 0.22);
    } catch {}
  }
}

export const alertService = new ThreatAudioService();

