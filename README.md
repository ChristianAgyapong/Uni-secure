# UniSecure SOC — MEIC-ViT Cyber Threat Detection Platform

> **Modern React + TypeScript SOC Dashboard with Python FastAPI Backend**  
> Direct implementation of *MEIC-ViT: A multi-scale enhanced vision transformer for network intrusion detection*  
> Xiao et al., *Computer Networks* 282 (2026) 112273 — [doi:10.1016/j.comnet.2026.112273](https://doi.org/10.1016/j.comnet.2026.112273)

---

## 📖 What Problem Does MEIC-ViT Solve?

Modern Network Intrusion Detection Systems (IDS) face **five compounding failure modes** that prior deep learning approaches could not simultaneously resolve. MEIC-ViT is the first framework to address all five in a single unified pipeline:

| # | Problem | Why It Matters | MEIC-ViT Solution |
|---|---------|---------------|-------------------|
| **1** | **Tabular Flattening Loss** | Flattening flows to 1D vectors discards spatial and cross-feature correlations (e.g. `Flow Bytes/s` and `Packet Length Variance` spike together in a DDoS burst) | Algorithm 1 encodes flows as **35×35×3 RGB images** — each pixel preserves one feature value and its spatial neighbour relationships |
| **2** | **Single-Scale Pattern Blindness** | A plain CNN or ViT processes only one representation scale, missing global, row-level, and sequential patterns simultaneously | **Parallel 3-path front-end**: Path A (global stats), Path B (row-visual), Path C (1D sequential) run in parallel before the Transformer encoder |
| **3** | **Extreme Class Imbalance** | Heartbleed had 11 real samples vs 231,073 BENIGN — standard models never learn rare attacks | **FPSS oversampling** (α=0.25) + Stratified Focal Loss (γ=2.5) gives rare attacks 16× more gradient emphasis |
| **4** | **Feature Redundancy & Noise** | CICFlowMeter produces 78 features; many are redundant or irrelevant | Two-stage filter: **Pearson correlation** (removes 27 pairs, |ρ|>0.9) → **Mutual Information ranking** (removes 5) = **35 optimal features** |
| **5** | **Black-Box Opacity** | SOC analysts cannot trust alerts they cannot explain | **Transformer self-attention heatmaps** show exactly which packets triggered each alert |

---

## ⚙️ How It Works — The Four Mechanisms

### Mechanism 1 · FPSS: Feature-Preserving Synthetic Sampling
*(Paper §3.1.3 — Equations 2 & 3)*

```
x_new = x_orig + ε,   ε ~ N(0, α × max(|μ|, σ))    [Eq. 2]
x_new = clip(x_new, feature_min, feature_max)          [Eq. 3]
```

- **Optimal α = 0.25** (§4.8): Low enough to preserve traffic semantics, high enough for diversity
- **3-tier RFF-Bal strategy**: Random undersample BENIGN → FPSS oversample 3 rarest classes to 300 instances → Hierarchical Focal Loss

---

### Mechanism 2 · Hybrid Feature Selection
*(Paper §3.1.4 — Figures 2 & 3)*

**Stage 1 — Pearson Correlation Filter** (|ρ| > 0.9): 78 → 40 features  
**Stage 2 — Mutual Information Ranking**: 40 → **35 optimal features**

Final 35 features include: `Packet Length Variance`, `Init_Win_bytes_forward`, `Flow Duration`, `Destination Port`, `Flow Bytes/s`, `PSH Flag Count`, `ACK Flag Count` and 28 others (full list in §3.1.4).

---

### Mechanism 3 · Algorithm 1: Flow-to-RGB Image Conversion
*(Paper §3.2 — Algorithm 1, Figure 5)*

```python
# For each normalized feature value in [0, 1]:
val   = int(normalized_feature × 16_777_215)   # Map to 24-bit color space
Red   = (val >> 16) & 0xFF                     # Highest 8 bits
Green = (val >> 8)  & 0xFF                     # Middle 8 bits
Blue  =  val        & 0xFF                     # Lowest 8 bits
```

- Each **row** = one network flow (35 rows = 35 consecutive flows)
- Each **column** = one of the 35 selected features
- **Sliding window**: W=35, S=18 (48.6% overlap) — optimal balance of accuracy vs RAM

**Sliding Window Results (Paper Table 9):**

| Stride S | Overlap | Accuracy | Macro F1 | RAM |
|----------|---------|----------|----------|-----|
| 35 | 0.0% | 96.05% | 90.53% | 326 MB |
| 24 | 31.4% | 97.79% | 94.25% | 476 MB |
| **18** | **48.6%** | **98.34%** | **95.87%** | **635 MB** ← Optimal |
| 12 | 65.7% | 98.68% | 95.75% | 952 MB |
| 6 | 82.9% | 98.73% | 96.25% | 1904 MB |

---

### Mechanism 4 · Parallel 3-Path Feature Fusion Network
*(Paper §3.3 — Figure 6, Equations 4–6)*

```
Input Image X ∈ R^{3×35×35}
         │
    ┌────┴──────────────────────┐
    │            │              │
  Path A      Path B         Path C
  Global      Row-Visual     Sequential
  Stats       Patterns       Content
    │            │              │
  64-dim      128-dim        128-dim
    └────┬──────────────────────┘
         │  Concat → 256-dim + positional encoding
         │
   6-Layer Transformer Encoder (8 heads, D_hidden=1024)
         │
   Path A stats injected → 320-dim fusion
         │
   Top-K Mean Logit Pooling (K=3)   ← focuses on 3 most malicious flow rows
         │
   Classification Head → 15 classes
```

| Path | Operation | Output | What It Captures |
|------|-----------|--------|-----------------|
| **A — Global Stats** | Mean, Max, Std, Max-Mean Diff, Peak Ratio → MLP | 64-dim | Abstract macro context; resilient to temporal shifts |
| **B — Row Visual** | Asymmetric 1×35 convolution per row | 128-dim/row | Holistic spatial-visual signature of each flow |
| **C — Sequential** | Two 1D convolutions (kernel=3, padding=1) | 128-dim/row | Fine-grained localized transitions between features |

**Top-K Mean Pooling (K=3):** Extracts the mean of the 3 highest-activation rows, forcing focus on the most malicious packets rather than averaging benign background.

---

## 📊 Benchmark Results

### CICIDS-2017 — Per-Class Performance (Paper Table 5)

| Class | Precision | Recall | F1-Score |
|-------|-----------|--------|----------|
| BENIGN | 0.9733 | 0.9946 | **0.9838** |
| DDoS | 0.9861 | 1.0000 | **0.9930** |
| PortScan | 0.9994 | 0.9991 | **0.9993** |
| FTP-Patator | 0.9867 | 1.0000 | **0.9933** |
| Heartbleed | 1.0000 | 0.9895 | **0.9947** |
| SQL Injection | 0.9825 | 0.9929 | **0.9876** |
| DoS Hulk | 0.9993 | 0.9796 | **0.9893** |
| Bot | 0.9621 | 0.9857 | **0.9736** |
| DoS Slowhttptest | 0.8224 | 0.9869 | 0.8966 |
| DoS GoldenEye | 0.9287 | 0.8390 | 0.8798 |
| DoS slowloris | 0.8596 | 0.8250 | 0.8373 |
| **Overall Accuracy** | | | **98.34% ± 0.18%** |
| **Macro Avg F1** | | | **95.87% ± 0.19%** |
| **Weighted Avg F1** | | | **98.33% ± 0.18%** |

### Multi-Model Comparison — CICIDS-2017 vs UNSW-NB15 (Paper Tables 6 & 8)

| Model | CICIDS-2017 F1 | UNSW-NB15 F1 | Params |
|-------|---------------|--------------|--------|
| AlexNet | 0.8757 | 0.8228 | 56.85M |
| VGG-13 | 0.9054 | 0.8316 | 8.95M |
| ResNet | 0.9236 | 0.8541 | 11.18M |
| GoogLeNet | 0.9222 | 0.8055 | 5.61M |
| Ens-NN | 0.9930 | 0.8590 | — |
| MobileNetV3-SVM-TL | 0.9909 | **0.3247** | — |
| ODODL-IDS | 0.9900 | 0.7253 | — |
| **MEIC-ViT (ours)** | **0.9833** | **0.9233** | **3.44M** |

> Competing methods collapse on UNSW-NB15 (dataset dependency). MEIC-ViT is the only model maintaining balanced high performance across **both** datasets.

### Computational Efficiency (Paper Table 12)

| Model | Params | MACs | Latency | Throughput | VRAM |
|-------|--------|------|---------|------------|------|
| AlexNet | 56.85M | 0.437G | 0.024ms | 41,148 SPS | 705MB |
| VGG-13 | 8.95M | 0.542G | 0.040ms | 25,277 SPS | 1112MB |
| ResNet | 11.18M | 0.735G | 0.042ms | 23,632 SPS | 732MB |
| **MEIC-ViT** | **3.44M** | **0.146G** | **0.030ms** | **32,987 SPS** | **682MB** |

---

## 🖥️ How to Use the App Against the Paper

The dashboard at **http://localhost:5173** has five tabs, each directly validating a specific section of the paper:

### Tab 1 · Detection Pipeline → *Validates §3.1–3.2 & Algorithm 1*

| Action | What It Validates |
|--------|------------------|
| **Upload a CICIDS-2017 CSV** | Executes full Algorithm 1 pipeline on real paper data end-to-end |
| **Preset: DDoS Attack** | 35-feature DDoS vector → model returns ≥99% confidence (Table 5 DDoS F1=0.9930) |
| **Preset: Heartbleed** | Tests FPSS minority-class training; model detects despite only 11 real training samples |
| **Preset: Botnet C2** | Bot class detection (Table 5 Bot F1=0.9736) |
| **Window Audit Table** | Shows each 35×35 sliding window, its multi-label assignment, and per-class probabilities |
| **KPI Strip** | Live Accuracy / Threats / Precision matching paper Table 5 weighted averages |

> **Paper §3.2.3:** *"Only if all flows in the window are benign is the image labeled as BENIGN."* — visible in the audit table label logic.

---

### Tab 2 · Model Architecture → *Validates §3.3 & Figure 6*

| Action | What It Validates |
|--------|------------------|
| Click each of the **8 blocks** | Exact tensor shapes at each layer (Equations 4, 5, 6) |
| Hover **Path A** | `z = Linear(256→64)(BN(GELU(Linear(525→256)(stats))))` |
| Hover **Path B** | Asymmetric kernel: `Z_row^(i) = σ(Σ X_{c,i,w} · K_row_{c,1,w} + b)` [Eq. 4] |
| Hover **Path C** | Sequential 1D conv: `Z_con^(j) = σ(Σ X_seq · K_con + b)` [Eq. 5] |
| Adjust **Stride S slider** | Reproduces Figure 9 accuracy/RAM trade-off across 5 overlap configurations |

---

### Tab 3 · Paper Benchmarks → *Validates §4.3, 4.4, 4.9 & Tables 5–12*

| Action | What It Validates |
|--------|------------------|
| **Run Hardware Benchmark** | Live latency & throughput — target ≈0.030ms, ≈33k SPS (Table 12) |
| **CICIDS-2017 / UNSW-NB15 toggle** | Per-class F1 profiles for both benchmark datasets (Tables 5 & 7) |
| **Model Comparison Matrix** | AlexNet / VGG-13 / ResNet / GoogLeNet / MEIC-ViT side-by-side (Tables 6 & 8) |
| **Overlap Rate chart** | Reproduces Figure 9 — performance plateau above 48.6% overlap |

---

### Tab 4 · Interpretability → *Validates §4.10 & Figure 11*

| Action | What It Validates |
|--------|------------------|
| Select **DDoS** | Concentrated attention hotspots on burst/header rows (Figure 11c–d) |
| Select **PortScan** | Concentrated hotspots on redundant header features (Figure 11g–h) |
| Select **BENIGN** | Diffuse attention across diverse protocol features (Figure 11a–b) |
| Switch **Layer L1→L6** | Early layers broad; deep layers isolate attack signatures |
| Switch **Head H1→H8** | Each head attends to different feature subspaces (§3.4.2) |
| Click any **flow token** | Which of the 35 features dominated that row's attention weight |

> **Paper §4.10:** *"For aggressive attacks such as DDoS and PortScan, the model exhibits highly concentrated attention hotspots... For BENIGN traffic, the attention distribution is noticeably more diffuse."*

---

### Tab 5 · SOC Operations → *Real-World Deployment Context (§5)*

| Action | What It Validates |
|--------|------------------|
| **Campus node map** | Simulates CICIDS-2017 enterprise setup (25 users, HTTP/HTTPS/FTP/SSH) |
| **Live telemetry logs** | Real-time packet JSON classified by MEIC-ViT |
| **Timestamp deltas** | Demonstrates <1ms inference (Table 12: 0.030ms/sample) |
| **Emergency Lockdown** | Automated IDS containment response |

---

## 🎯 Three Unique Claims — Validated by This App

1. ✅ **No prior method combines** Pearson+MI feature selection → 24-bit RGB encoding → 3-path parallel ViT in a single unified pipeline
2. ✅ **Top-K Mean Logit Pooling (K=3)** outperforms standard global average pooling — Ablation Table 10: Macro F1 0.9587 (full) vs 0.9341 (baseline ViT only)
3. ✅ **Lightest competitive model at 3.44M params / 0.146G MACs** while matching models 10–16× larger — unique suitability for edge/IoT deployment

---

## 🏗️ Project Structure

```
demo-cyber/
├── backend/                       # Python FastAPI Backend (Port 8000)
│   ├── main.py                    # REST API: SOC + MEIC-ViT inference + benchmark endpoints
│   ├── model.py                   # PyTorch MEICViT (3-Path + Top-3 Mean Logit Pooling)
│   ├── pipeline.py                # Algorithm 1: 24-bit Flow-to-RGB + Attention Heatmaps
│   ├── train_meic_vit.py          # Training pipeline & synthetic flow generator
│   ├── artifacts/
│   │   ├── meic_vit_best.pt       # Trained ViT checkpoint (5.03M parameters)
│   │   └── scaler.json            # Normalization bounds for 35 selected features
│   ├── sample_data/               # Real CICIDS-2017 & UNSW-NB15 CSV datasets
│   └── requirements.txt
│
└── frontend/                      # React + TypeScript + Vite (Port 5173)
    └── src/
        ├── components/
        │   ├── DetectionPipelineView.tsx   # Tab 1: CSV upload, presets, window audit
        │   ├── ArchitectureView.tsx        # Tab 2: Interactive 3-path ViT diagram
        │   ├── PaperBenchmarksView.tsx     # Tab 3: Live hardware benchmark + metric tables
        │   ├── InterpretabilityView.tsx    # Tab 4: Attention heatmaps (paper Fig. 11)
        │   ├── SocCenterView.tsx           # Tab 5: Campus SOC + live telemetry
        │   ├── Sidebar.tsx
        │   └── Header.tsx
        ├── api/client.ts
        ├── App.tsx
        └── index.css
```

---

## 🚀 Running Locally

### 1. Start the FastAPI Backend
```powershell
cd backend
pip install -r requirements.txt
python main.py
```
- **API**: http://127.0.0.1:8000
- **Swagger Docs**: http://127.0.0.1:8000/docs

### 2. Start the React Frontend
```powershell
cd frontend
npm install
npm run dev
```
- **Dashboard**: http://localhost:5173

---

## 📚 Citation

```bibtex
@article{xiao2026meicvit,
  title     = {MEIC-ViT: A multi-scale enhanced vision transformer for network intrusion detection},
  author    = {Xiao, Yeqiu and Wang, Peihua and Wang, Yichuan and Ma, Yibin and Hei, Xinhong},
  journal   = {Computer Networks},
  volume    = {282},
  pages     = {112273},
  year      = {2026},
  publisher = {Elsevier},
  doi       = {10.1016/j.comnet.2026.112273}
}
```

---

*Supported by the National Natural Science Foundation of China (62302389, U2468206) and Key R&D Projects of Shaanxi Province (2022CGKC-09).*
