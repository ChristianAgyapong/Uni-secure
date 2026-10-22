/**
 * MEIC-ViT UniSecure SOC API Client
 * Connects to the FastAPI backend at http://127.0.0.1:8000
 */

const BASE = "http://127.0.0.1:8000";

export interface OverviewData {
  kpis: {
    total_active_threats: number;
    threats_delta: string;
    model_confidence_avg: number;
    confidence_status: string;
    network_throughput: string;
    throughput_status: string;
  };
  campus_nodes: Array<{
    id: string;
    name: string;
    status: string;
    is_alert: boolean;
    threat: string | null;
    ip: string;
    x: number;
    y: number;
    last_active: string;
  }>;
  live_detections: Array<{
    id: string;
    type: string;
    badge_color: string;
    time: string;
    location: string;
    description: string;
    node_id: string;
    isolated: boolean;
  }>;
}

export interface BuildingData {
  zone: string;
  name: string;
  breadcrumb: string;
  status: string;
  active_sessions: number;
  network_load: string;
  ai_service: {
    name: string;
    tagline: string;
    inference_speed: string;
    processing_queue_active: number;
    processing_queue_waiting: number;
    ai_integrity: string;
    last_verification: string;
  };
  traffic_stream: Array<{
    time: string;
    ingress: number;
    egress: number;
  }>;
  sensors: Array<{
    sensor_id: string;
    type: string;
    reading: string;
    status: string;
    status_color: string;
    last_heartbeat: string;
  }>;
  node_mapping: {
    encryption_protocol: string;
    uptime_since_boot: string;
    gateway_status: string;
    active_sensor_nodes: number;
  };
}

export interface ThreatEvent {
  id: string;
  severity: string;
  color: string;
  title: string;
  timestamp: string;
  confidence: number;
  baseline_entropy: number;
  detected_entropy: number;
  confirmed: boolean;
  dismissed: boolean;
  signature_bars: Array<{
    label: string;
    baseline: number;
    current: number;
  }>;
}

export interface ThreatCenterData {
  ai_engine: string;
  avg_confidence: number;
  flagged_events: ThreatEvent[];
  audit_trail: Array<{
    author: string;
    time: string;
    action: string;
    badge: string;
    badge_color: string;
  }>;
  threat_intelligence: {
    analysis: string;
    global_similarity: string;
    recommended_action: string;
  };
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: string;
  level_color: string;
  source: string;
  category: string;
  description: string;
  metadata: {
    trace_id: string;
    host: string;
    environment: string;
  };
  raw_payload: Record<string, any>;
}

export interface LogsData {
  counters: {
    total_logs: string;
    total_logs_delta: string;
    security_alerts: number;
    security_alerts_sub: string;
    system_notices: number;
    system_notices_sub: string;
    critical_errors: number;
    critical_errors_sub: string;
  };
  logs: LogEntry[];
}

export interface WindowResult {
  window: number;
  prediction: string;
  confidence: number;
  threat_level: string;
  threat_color: string;
  ground_truth: string | null;
  correct: boolean | null;
  top5: Array<{ label: string; prob: number }>;
  composite_b64: string;
}

export interface AnalysisResult {
  n_flows: number;
  n_windows: number;
  elapsed_s: number;
  trained_model: boolean;
  highest_threat: string;
  threat_counts: Record<string, number>;
  class_counts: Record<string, number>;
  windows: WindowResult[];
}

export interface ModelInfo {
  trained: boolean;
  model_name: string;
  paper_citation: string;
  window: number;
  stride: number;
  n_features: number;
  n_classes: number;
  hidden_dim: number;
  n_layers: number;
  n_heads: number;
  topk: number;
  classes: string[];
}

export interface DatasetFileSummary {
  filename: string;
  day: string;
  size_mb: number;
  sampled_rows: number;
  estimated_total_rows: number;
  label_counts: Record<string, number>;
  error?: string;
}

export interface DatasetStats {
  dataset: string;
  n_files: number;
  n_classes: number;
  sampled_rows_total: number;
  aggregate_label_distribution: Record<string, number>;
  files: DatasetFileSummary[];
  top_features: Array<{ feature: string; importance: number }>;
  paper_reference: string;
}

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? "API request failed");
  }
  return res.json() as Promise<T>;
}

export const API = {
  health: () => api<{ status: string; model_loaded: boolean; trained: boolean; lockdown_active: boolean }>("/api/health"),
  modelInfo: () => api<ModelInfo>("/api/model-info"),
  classes: () => api<Array<{ label: string; threat_level: string; color: string }>>("/api/classes"),
  presets: () => api<Array<{ name: string; file: string }>>("/api/presets"),
  datasetStats: () => api<DatasetStats>("/api/dataset-stats"),

  // SOC Endpoints
  socOverview: () => api<OverviewData>("/api/soc/overview"),
  socBuilding: () => api<BuildingData>("/api/soc/building/cl402"),
  socThreats: () => api<ThreatCenterData>("/api/soc/threats"),
  socLogs: () => api<LogsData>("/api/soc/logs"),

  threatAction: (event_id: string, action: "confirm" | "dismiss" | "isolate") =>
    api<{ status: string }>("/api/soc/threat-action", {
      method: "POST",
      body: JSON.stringify({ event_id, action }),
    }),

  isolateNode: (node_id: string, isolate: boolean) =>
    api<{ status: string }>("/api/soc/isolate-node", {
      method: "POST",
      body: JSON.stringify({ node_id, isolate }),
    }),

  toggleLockdown: () =>
    api<{ status: string; lockdown_active: boolean; message: string }>("/api/soc/lockdown", {
      method: "POST",
    }),

  // MEIC-ViT Inference
  analyzePreset: (preset_name: string, max_windows = 50) =>
    api<AnalysisResult>("/api/analyze-preset", {
      method: "POST",
      body: JSON.stringify({ preset_name, max_windows }),
    }),

  analyzeFile: (file: File, max_windows = 50) => {
    const form = new FormData();
    form.append("file", file);
    return fetch(`${BASE}/api/analyze?max_windows=${max_windows}`, {
      method: "POST",
      body: form,
    }).then(async (r) => {
      if (!r.ok) {
        const e = await r.json().catch(() => ({ detail: r.statusText }));
        throw new Error(e.detail ?? "Upload failed");
      }
      return r.json() as Promise<AnalysisResult>;
    });
  },

  simulate: (attack_type: string, n_flows = 70, max_windows = 20) =>
    api<AnalysisResult>("/api/simulate", {
      method: "POST",
      body: JSON.stringify({ attack_type, n_flows, max_windows }),
    }),
};

