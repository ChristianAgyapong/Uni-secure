# UniSecure SOC — MEIC-ViT Cyber Threat Detection Platform

> **Modern React + TypeScript SOC Dashboard with Python FastAPI Backend**  
> Direct implementation of *MEIC-ViT: A multi-scale enhanced vision transformer for network intrusion detection* (Xiao et al., *Computer Networks* 282 (2026) 112273).

---

## 🛡️ Architecture & Project Structure

The project has been restructured with a separated backend and frontend architecture:

```
demo-cyber/
├── backend/                       # Python FastAPI Backend (Port 8000)
│   ├── main.py                    # REST API with SOC & MEIC-ViT inference endpoints
│   ├── model.py                   # PyTorch MEICViT (Multi-Path ViT + Top-3 Mean Logit Pooling)
│   ├── pipeline.py                # 24-bit Flow-to-RGB Image Converter & Attention Heatmaps
│   ├── train_meic_vit.py          # Training pipeline & synthetic flow generator
│   ├── artifacts/
│   │   ├── meic_vit_best.pt       # Trained ViT checkpoint (5.03M parameters)
│   │   └── scaler.json            # Normalization bounds for 35 selected features
│   ├── sample_data/               # Real CICIDS-2017 & attack benchmark CSV datasets
│   └── requirements.txt           # FastAPI, Uvicorn, PyTorch, Pillow, Pandas, Scikit-learn
│
└── frontend/                      # React + TypeScript + Vite SOC Dashboard (Port 5173)
    ├── src/
    │   ├── api/
    │   │   └── client.ts          # Typed API client connecting to FastAPI backend
    │   ├── components/
    │   │   ├── Sidebar.tsx        # "Core Network / Vigilance Active" & Emergency Lockdown
    │   │   ├── Header.tsx         # UniSecure header bar, global node search & user profile
    │   │   ├── OverviewView.tsx   # Screen 1: KPIs, Campus Node Status Map & Live Detections
    │   │   ├── BuildingsView.tsx  # Screen 2: Computer Lab 402, Live Waveform, Sensor Grid & Blueprint
    │   │   ├── ThreatCenterView.tsx# Screen 3: Flagged Events, Signature Entropy & Audit Trail
    │   │   ├── LogsView.tsx       # Screen 4: Activity Logs, Stat Cards & Slide-out JSON Drawer
    │   │   ├── MeicVitLabView.tsx # Screen 5: Real ViT Inference, Datasets & Fig. 11 Heatmaps
    │   │   └── LockdownModal.tsx  # Emergency containment modal with quarantine trigger
    │   ├── App.tsx                # Main state controller & tab router
    │   ├── index.css              # Custom dark-navy SOC design system with animations
    │   └── main.tsx
    ├── package.json
    └── index.html
```

---

## 🚀 Running the Full Stack Locally

### 1. Start the FastAPI Backend
```powershell
cd backend
python -u main.py
```
- **Backend URL**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### 2. Start the React + TypeScript Frontend
```powershell
cd frontend
npm run dev
```
- **Dashboard URL**: [http://127.0.0.1:5173](http://127.0.0.1:5173)

---

## 🌟 Implemented Views & Features

| View | Screenshot Replicated | Features |
|---|---|---|
| **Overview** | **Image 1** | 3 KPI cards (Total Threats: 12, Confidence: 98.4%, Throughput: 4.2 Gb/s), University Campus Status map with beacon alerts, and Live Detections feed with `[Isolate Node]` actions. |
| **Buildings** | **Image 2** | Computer Lab 402 monitoring, real-time SVG ingress/egress waveform, MEIC-ViT AI service metrics, 24-node sensor grid table, and isometric architectural floor plan. |
| **Threat Center** | **Image 3** | Flagged events (Critical, High, Medium, Low), dual signature comparison bar charts (Baseline 4.28 vs Detected 9.14 bits entropy), Audit Trail, and `[Confirm Threat]` / `[False Positive]` actions. |
| **Logs** | **Image 4** | 4 log stat counters, time/severity/event filters, interactive activity table, and slide-out **Log Details** drawer with full raw payload JSON inspector. |
| **MEIC-ViT AI Lab** | **Paper §3 & Fig. 11** | Real Vision Transformer inference with 5.03M parameter checkpoint, 24-bit RGB flow images, Figure 11 Attention Heatmap extraction, and CSV upload inspection. |
| **Emergency Lockdown** | **Side Action** | Red containment button triggering campus-wide quarantine and SOC alert banners. |
