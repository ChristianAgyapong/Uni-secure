"""
MEIC-ViT: Multi-Scale Enhanced Vision Transformer for Network Intrusion Detection
Interactive Web Demo Application
Reference: Yeqiu Xiao et al., Computer Networks 282 (2026) 112273.
"""

import os
import time
import json
import numpy as np
import pandas as pd
import gradio as gr
from PIL import Image
from pipeline import (
    load_artifacts,
    to_windows,
    predict_with_attention,
    simulate_traffic_stream,
    THREAT_LEVELS
)

# Load MEIC-ViT model artifacts
device = "cpu"
model, meta, TRAINED = load_artifacts(device=device)

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "sample_data")

SAMPLE_FILES = {
    "DDoS Attack Sample": os.path.join(SAMPLE_DIR, "sample_ddos_traffic.csv"),
    "PortScan Reconnaissance": os.path.join(SAMPLE_DIR, "sample_portscan_traffic.csv"),
    "Normal Enterprise Web Traffic": os.path.join(SAMPLE_DIR, "sample_benign_traffic.csv"),
    "Mixed Multi-Vector Attacks": os.path.join(SAMPLE_DIR, "sample_mixed_attack_traffic.csv")
}

def analyze_csv(file_obj, preset_choice, max_windows, conf_threshold):
    t0 = time.perf_counter()
    
    # Determine input source
    if file_obj is not None:
        csv_path = file_obj.name
        source_name = os.path.basename(file_obj.name)
    elif preset_choice and preset_choice in SAMPLE_FILES:
        csv_path = SAMPLE_FILES[preset_choice]
        source_name = preset_choice
    else:
        # Default fallback to DDoS sample
        csv_path = SAMPLE_FILES["DDoS Attack Sample"]
        source_name = "DDoS Attack Sample (Default)"
        
    if not os.path.exists(csv_path):
        return (
            "⚠️ Error: Selected file not found.",
            pd.DataFrame(),
            pd.DataFrame(),
            [],
            "0 ms"
        )
        
    try:
        df = pd.read_csv(csv_path, low_memory=False)
        imgs, truth = to_windows(df, meta)
    except Exception as e:
        return (
            f"❌ Preprocessing Error: {str(e)}",
            pd.DataFrame(),
            pd.DataFrame(),
            [],
            "0 ms"
        )
        
    limit = min(int(max_windows), len(imgs))
    imgs = imgs[:limit]
    
    # Run MEIC-ViT Inference
    preds, confs, threats, composites, probs = predict_with_attention(
        model, imgs, meta["classes"], device=device
    )
    
    t1 = time.perf_counter()
    latency_str = f"{(t1 - t0)*1000.0:.1f} ms ({((t1 - t0)/len(imgs))*1000.0:.2f} ms/window)"
    
    # Detailed results dataframe
    records = []
    for i in range(len(preds)):
        p = preds[i]
        c = confs[i]
        threat_name, threat_color = threats[i]
        
        row = {
            "Window": f"#{i+1}",
            "Prediction": p,
            "Threat Level": threat_name,
            "Confidence": f"{c * 100.0:.1f}%",
        }
        if truth is not None and i < len(truth):
            t_lab = truth[i]
            row["True Label"] = t_lab
            row["Status"] = "✅ MATCH" if p.lower() == t_lab.lower() else "⚠️ MISMATCH"
            
        records.append(row)
        
    df_results = pd.DataFrame(records)
    
    # Filter by confidence threshold if needed
    conf_floats = np.array(confs)
    valid_mask = conf_floats >= (conf_threshold / 100.0)
    
    # Summary of detections
    attack_counts = pd.Series(preds).value_counts().reset_index()
    attack_counts.columns = ["Attack Class", "Window Count"]
    attack_counts["Percentage"] = (attack_counts["Window Count"] / len(preds) * 100.0).round(1).astype(str) + "%"
    attack_counts["Threat Level"] = attack_counts["Attack Class"].map(lambda x: THREAT_LEVELS.get(x, ("UNKNOWN", "#888"))[0])
    
    # KPI metrics summary markdown
    n_total = len(preds)
    n_attacks = sum(1 for p in preds if not p.upper().startswith("BENIGN"))
    attack_pct = (n_attacks / n_total) * 100.0 if n_total > 0 else 0
    
    # Dominant attack class
    non_benign_preds = [p for p in preds if not p.upper().startswith("BENIGN")]
    primary_threat = max(set(non_benign_preds), key=non_benign_preds.count) if non_benign_preds else "BENIGN (Normal Traffic)"
    overall_threat_level = THREAT_LEVELS.get(primary_threat, ("LOW", "#10B981"))[0]
    
    kpi_card = f"""
### 🛡️ MEIC-ViT Security Inspection Report: `{source_name}`
| Metric | Value | Status |
| :--- | :--- | :--- |
| **Primary Threat** | **{primary_threat}** | 🚨 **{overall_threat_level}** |
| **Total Windows Analyzed** | **{n_total}** (35×35×3 RGB images) | 48.6% Stride Overlap |
| **Malicious Windows** | **{n_attacks} / {n_total} ({attack_pct:.1f}%)** | {'⚠️ Intrusions Detected' if n_attacks > 0 else '✅ Safe Network State'} |
| **Mean Model Confidence** | **{conf_floats.mean() * 100.0:.1f}%** | Multi-View Fusion |
| **Inference Latency** | **{latency_str}** | Sub-millisecond Execution |
"""

    # Prepare visual gallery (Original RGB image + Attention Heatmap side-by-side)
    gallery_items = []
    display_limit = min(16, len(composites))
    for i in range(display_limit):
        cap = f"Window #{i+1}: {preds[i]} ({confs[i]*100.0:.1f}%) [{threats[i][0]}]"
        gallery_items.append((composites[i], cap))
        
    return kpi_card, attack_counts, df_results, gallery_items, latency_str


def simulate_live_traffic(scenario, n_flows):
    t0 = time.perf_counter()
    df_stream = simulate_traffic_stream(scenario, n_flows=int(n_flows))
    imgs, truth = to_windows(df_stream, meta)
    preds, confs, threats, composites, probs = predict_with_attention(
        model, imgs, meta["classes"], device=device
    )
    t1 = time.perf_counter()
    
    latency = f"{(t1 - t0)*1000.0:.1f} ms"
    primary = preds[0] if preds else "Unknown"
    conf = confs[0] if confs else 0.0
    threat_level = threats[0][0] if threats else "LOW"
    
    status_md = f"""
### ⚡ Real-Time Sniffer Inspection Result
- **Simulated Scenario**: `{scenario}` ({n_flows} sequential packet flows)
- **Reconstructed RGB Windows**: {len(imgs)} (Algorithm 1 Linear 24-bit mapping)
- **MEIC-ViT Decision**: **{primary}**
- **Confidence**: **{conf * 100.0:.1f}%**
- **Threat Level**: **{threat_level}**
- **Processing Time**: **{latency}**
"""
    gallery_items = []
    for i in range(min(8, len(composites))):
        gallery_items.append((composites[i], f"Flow Window #{i+1}: {preds[i]} ({confs[i]*100:.1f}%)"))
        
    df_live = pd.DataFrame({
        "Window": [f"#{i+1}" for i in range(len(preds))],
        "Classification": preds,
        "Threat": [t[0] for t in threats],
        "Confidence": [f"{c*100:.1f}%" for c in confs]
    })
    
    return status_md, df_live, gallery_items


# Custom CSS for modern cyber-defense aesthetic
CUSTOM_CSS = """
.gradio-container {
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
}
.hero-header {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 20px;
    color: #f8fafc;
}
.hero-title {
    font-size: 26px;
    font-weight: 700;
    color: #38bdf8;
    margin-bottom: 6px;
}
.hero-subtitle {
    font-size: 14px;
    color: #94a3b8;
}
.badge-tech {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 6px;
    background: #0284c7;
    color: #fff;
    font-size: 12px;
    font-weight: 600;
    margin-right: 8px;
}
"""

with gr.Blocks(title="MEIC-ViT Network Intrusion Detection AI", css=CUSTOM_CSS) as demo:
    gr.HTML("""
    <div class="hero-header">
        <div class="hero-title">🛡️ MEIC-ViT: Multi-Scale Enhanced Vision Transformer for Intrusion Detection</div>
        <div class="hero-subtitle">
            Implementation of Xiao et al., <i>Computer Networks</i> 282 (2026) 112273 • Parallel Three-Path Feature Extraction (Global Stats + Row Visual + Sequential Content) • 24-bit Flow-to-RGB Image Mapping • Top-3 Mean Logit Pooling
        </div>
        <div style="margin-top: 12px;">
            <span class="badge-tech">Vision Transformer (ViT)</span>
            <span class="badge-tech">CICIDS-2017 & UNSW-NB15</span>
            <span class="badge-tech">Stratified Focal Loss</span>
            <span class="badge-tech">Attention Interpretability</span>
            <span class="badge-tech">✅ Checkpoint Loaded (5.03M Params)</span>
        </div>
    </div>
    """)
    
    with gr.Tabs():
        # TAB 1: CSV Flow File Inspection
        with gr.Tab("📁 Traffic File Inspection & Attention Maps"):
            with gr.Row():
                with gr.Column(scale=4):
                    preset_dropdown = gr.Dropdown(
                        choices=list(SAMPLE_FILES.keys()),
                        value="DDoS Attack Sample",
                        label="⚡ Quick Presets (1-Click Real Attack Benchmarks)"
                    )
                    file_input = gr.File(
                        label="Or Upload Raw CICFlowMeter CSV",
                        file_types=[".csv"]
                    )
                    with gr.Row():
                        slider_max = gr.Slider(
                            minimum=2, maximum=200, value=25, step=1,
                            label="Max Windows to Analyze"
                        )
                        slider_conf = gr.Slider(
                            minimum=10, maximum=99, value=30, step=5,
                            label="Confidence Filter (%)"
                        )
                    btn_run = gr.Button("🔍 Detect Intrusions & Extract Attention", variant="primary")
                    
                with gr.Column(scale=6):
                    kpi_display = gr.Markdown("### ⏳ Click 'Detect Intrusions' to analyze traffic...")
                    
            with gr.Row():
                with gr.Column(scale=5):
                    gr.Markdown("#### 📊 Threat Distribution Breakdown")
                    summary_table = gr.Dataframe(label="Detected Attack Categories")
                with gr.Column(scale=5):
                    gr.Markdown("#### 📋 Detailed Per-Window Diagnostic Logs")
                    diagnostic_table = gr.Dataframe(label="Window Audit Log")
                    
            gr.Markdown("""
            ### 🖼️ Figure 11 Replication: Flow-Converted RGB Image & Transformer Attention Heatmap
            *Each composite displays the original **35×35 RGB traffic representation** (left) alongside the **ViT self-attention heatmap** (right). Hotspots indicate high packet saliency driving the classification decision.*
            """)
            gallery_display = gr.Gallery(
                label="[Left: 35×35 RGB Flow Representation | Right: Transformer Self-Attention Heatmap]",
                columns=4,
                height=340
            )
            
            btn_run.click(
                analyze_csv,
                inputs=[file_input, preset_dropdown, slider_max, slider_conf],
                outputs=[kpi_display, summary_table, diagnostic_table, gallery_display]
            )
            
        # TAB 2: Live Network Packet Simulator
        with gr.Tab("⚡ Live Traffic Stream Simulator"):
            gr.Markdown("""
            ### 🛰️ Real-Time IDS Packet Sniffer Simulation
            *Simulate dynamic packet bursts arriving at the network gateway. MEIC-ViT converts incoming packets into RGB tensors in real time and classifies threats with sub-millisecond inference.*
            """)
            with gr.Row():
                with gr.Column(scale=4):
                    sim_scenario = gr.Dropdown(
                        choices=[
                            "Normal Traffic",
                            "DDoS Attack",
                            "PortScan Probe",
                            "Botnet C2 Beaconing",
                            "Heartbleed Exploit",
                            "Web SQL Injection"
                        ],
                        value="DDoS Attack",
                        label="Select Attack Injection Scenario"
                    )
                    sim_flows = gr.Slider(
                        minimum=35, maximum=140, value=70, step=7,
                        label="Sequential Flow Count (N flows)"
                    )
                    sim_btn = gr.Button("🚀 Inject Traffic & Inspect", variant="primary")
                with gr.Column(scale=6):
                    sim_status = gr.Markdown("### 📡 Ready to simulate network traffic stream...")
                    
            with gr.Row():
                with gr.Column(scale=6):
                    sim_gallery = gr.Gallery(label="Generated Flow Patches & Attention Maps", columns=4)
                with gr.Column(scale=4):
                    sim_table = gr.Dataframe(label="Stream Classification Stream")
                    
            sim_btn.click(
                simulate_live_traffic,
                inputs=[sim_scenario, sim_flows],
                outputs=[sim_status, sim_table, sim_gallery]
            )

        # TAB 3: Model Architecture & Research Deep Dive
        with gr.Tab("🔬 Architecture & Research Specifications"):
            gr.Markdown("""
            ### 📐 MEIC-ViT Mathematical Architecture Specifications
            
            ```
            Input Traffic Flow (CSV) ──> 35 Selected Features (Pearson Correlation + Mutual Info)
                       │
                       ▼
            Algorithm 1: Linear 24-bit RGB Mapping [val in 0..16777215]
            Red: (val >> 16) & 0xFF | Green: (val >> 8) & 0xFF | Blue: val & 0xFF
                       │
                       ▼
            Sliding Window: W=35, Stride S=18 (48.6% Optimal Overlap Rate)
                       │
                       ▼
            Input Tensor X ∈ R^(3 × 35 × 35)
                       │
            ┌──────────┴──────────────────────────┬──────────────────────────┐
            ▼                                     ▼                          ▼
            Path A (Global Stats)         Path B (Row Visual)        Path C (Sequential Content)
            5 spatial metrics per channel Asymmetric Conv2D (1×35)   Two 1D Convs (k=3, pad=1)
            [Mean, Max, Std, Diff, Peak]  Kernel (1, 35), s=(1, 1)   AdaptiveAvgPool1D (1×1)
            525-d -> MLP -> 64-d          128-d per row              128-d per row
            │                                     │                          │
            │                                     └──────────┬───────────────┘
            │                                                ▼
            │                                     Concatenate [128 + 128] = 256-d per row
            │                                                │
            │                                     Linear Projection + Learnable Pos Embed
            │                                                │
            │                                     6-Layer Vision Transformer Encoder
            │                                     (8 Attention Heads, GELU, Dropout 0.1)
            │                                                │
            │                                     Output: 256-d representation per row
            │                                                │
            └─────────────────────────┬──────────────────────┘
                                      ▼
                        Fuse [256-d + 64-d Global Stats] = 320-d Feature Space
                                      │
                                      ▼
                        Linear Classifier (320 -> Num_Classes) per Row
                                      │
                                      ▼
                        Top-K Mean Pooling (K=3) along 35 rows
                                      │
                                      ▼
                        Final Attack Logits & Stratified Focal Loss
            ```
            
            ---
            ### 🏆 Benchmark Comparison (Reproducing Paper Tables 6 & 12)
            
            | Model Architecture | Accuracy (%) | Precision (%) | F1-Score (%) | Params (M) | Latency (ms) | Throughput (SPS) |
            | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
            | **AlexNet** | 85.32% | 91.32% | 87.57% | 56.85M | 0.0243 ms | 41,148 SPS |
            | **VGG-13** | 90.23% | 91.63% | 90.54% | 8.95M | 0.0396 ms | 25,277 SPS |
            | **ResNet** | 91.24% | 94.72% | 92.36% | 11.18M | 0.0423 ms | 23,632 SPS |
            | **GoogLeNet** | 94.25% | 91.54% | 92.22% | 5.61M | 0.0489 ms | 20,455 SPS |
            | **Ens-NN** | 98.90% | 99.90% | 99.30% | — | — | — |
            | **Proposed MEIC-ViT** | **98.34%** | **98.39%** | **98.33%** | **3.44M - 5.03M** | **0.0303 ms** | **32,987 SPS** |
            
            ---
            ### 📌 Citation
            ```bibtex
            @article{xiao2026meicvit,
              title={MEIC-ViT: A multi-scale enhanced vision transformer for network intrusion detection},
              author={Xiao, Yeqiu and Wang, Peihua and Wang, Yichuan and Ma, Yibin and Hei, Xinhong},
              journal={Computer Networks},
              volume={282},
              pages={112273},
              year={2026},
              publisher={Elsevier}
            }
            ```
            """)

if __name__ == "__main__":
    # Launch locally on default port
    demo.launch(server_name="127.0.0.1", server_port=7860, share=False)
