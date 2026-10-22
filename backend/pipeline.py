"""
MEIC-ViT Inference and Visualization Pipeline
Reference: Yeqiu Xiao et al., Computer Networks 282 (2026) 112273.

Provides:
- load_artifacts: loads trained checkpoint and scaler metadata
- clean_cols: column sanitization matching CICFlowMeter conventions
- to_windows: converts tabular flows into 35x35x3 RGB window tensors (Algorithm 1)
- predict_with_attention: classifies traffic windows, extracts Transformer attention maps,
  and synthesizes Fig. 11 attention heatmaps
- simulate_traffic_stream: generates live streaming flows for real-time IDS simulation
"""

import os
import json
import numpy as np
import pandas as pd
import torch
from PIL import Image
from model import MEICViT

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "artifacts")

# Threat classification mapping
THREAT_LEVELS = {
    "BENIGN": ("LOW", "#10B981"),                 # Green
    "PortScan": ("MEDIUM", "#F59E0B"),             # Amber
    "Bot": ("MEDIUM", "#F59E0B"),                  # Amber
    "DoS Hulk": ("HIGH", "#F97316"),               # Orange
    "DoS GoldenEye": ("HIGH", "#F97316"),
    "DoS slowloris": ("HIGH", "#F97316"),
    "DoS Slowhttptest": ("HIGH", "#F97316"),
    "FTP-Patator": ("HIGH", "#F97316"),
    "SSH-Patator": ("HIGH", "#F97316"),
    "Web Attack Brute Force": ("HIGH", "#F97316"),
    "Web Attack XSS": ("HIGH", "#F97316"),
    "DDoS": ("CRITICAL", "#EF4444"),               # Red
    "Heartbleed": ("CRITICAL", "#EF4444"),
    "Infiltration": ("CRITICAL", "#EF4444"),
    "Web Attack Sql Injection": ("CRITICAL", "#EF4444")
}

def load_artifacts(device="cpu"):
    """
    Loads model configuration, feature normalization bounds, and trained weights.
    """
    scaler_path = os.path.join(ARTIFACTS_DIR, "scaler.json")
    if not os.path.exists(scaler_path):
        raise FileNotFoundError(f"Scaler metadata not found at {scaler_path}. Run train_meic_vit.py first.")
    
    with open(scaler_path, "r") as f:
        meta = json.load(f)
        
    window = meta.get("window", 35)
    hidden_dim = meta.get("hidden_dim", 256)
    n_layers = meta.get("n_layers", 6)
    n_heads = meta.get("n_heads", 8)
    topk = meta.get("topk", 3)
    num_classes = len(meta["classes"])
    
    model = MEICViT(num_classes=num_classes, window=window, hidden_dim=hidden_dim,
                    n_layers=n_layers, n_heads=n_heads, topk=topk)
    
    ckpt_path = os.path.join(ARTIFACTS_DIR, "meic_vit_best.pt")
    trained = os.path.exists(ckpt_path)
    if trained:
        state_dict = torch.load(ckpt_path, map_location=device)
        model.load_state_dict(state_dict)
        model.eval()
    
    model.to(device)
    return model, meta, trained


def clean_cols(df):
    """
    Sanitizes CICFlowMeter column names by stripping whitespace and replacing delimiters.
    """
    df = df.copy()
    df.columns = (
        df.columns.astype(str)
        .str.strip()
        .str.replace(" ", "_", regex=False)
        .str.replace("/", "_", regex=False)
        .str.replace(".", "_", regex=False)
        .str.replace("-", "_", regex=False)
    )
    return df


def to_windows(df, meta, max_windows: int = 50):
    """
    Algorithm 1: Converts dataframe of flows into (M, 35, 35, 3) RGB images.
    - Uses 35 selected features
    - Resiliently matches column aliases and imputes dataset-specific omissions (e.g. Source_Port, Protocol in CICIDS MachineLearningCVE)
    - Min-max normalizes to [0, 1] using training set bounds
    - Maps to 24-bit RGB: Red = (val >> 16) & 0xFF, Green = (val >> 8) & 0xFF, Blue = val & 0xFF
    - Applies sliding window (W=35, S=18 -> 48.6% overlap)
    - Extracts ground truth labels if Label column is present
    """
    df_clean = clean_cols(df)
    features = meta["features"]
    W = meta["window"]
    S = meta["stride"]
    
    # 1. Alias matching (case-insensitive / common CICFlowMeter variants)
    col_map = {}
    lower_cols = {c.lower(): c for c in df_clean.columns}
    for feat in features:
        if feat not in df_clean.columns:
            feat_lower = feat.lower()
            if feat_lower in lower_cols:
                col_map[feat] = lower_cols[feat_lower]
            elif feat_lower in ("source_port", "src_port", "sport"):
                for cand in ["source_port", "src_port", "sport"]:
                    if cand in lower_cols:
                        col_map[feat] = lower_cols[cand]
                        break
            elif feat_lower in ("protocol", "proto"):
                for cand in ["protocol", "proto"]:
                    if cand in lower_cols:
                        col_map[feat] = lower_cols[cand]
                        break

    for target, source in col_map.items():
        df_clean[target] = df_clean[source]

    # 2. Impute known domain features stripped in CICIDS MachineLearningCVE benchmark CSVs
    if "Source_Port" not in df_clean.columns:
        df_clean["Source_Port"] = 49152 # Standard dynamic ephemeral port
    if "Protocol" not in df_clean.columns:
        df_clean["Protocol"] = 6 # Standard TCP protocol

    # 3. Fallback for any other missing feature from metadata bounds
    mn_arr = np.array(meta["mn"], dtype=np.float64)
    mx_arr = np.array(meta["mx"], dtype=np.float64)
    for i, feat in enumerate(features):
        if feat not in df_clean.columns:
            df_clean[feat] = (mn_arr[i] + mx_arr[i]) / 2.0

    # 4. Large CSV optimization: slice smartly so large datasets (e.g. 75MB / 286k rows) process instantaneously
    needed_rows = max_windows * S + W + 50
    if len(df_clean) > needed_rows:
        # If Label is present and contains attack traffic, anchor slice around the first attack burst
        if "Label" in df_clean.columns:
            non_benign_mask = ~df_clean["Label"].astype(str).str.upper().str.startswith("BENIGN")
            if non_benign_mask.any():
                first_atk_idx = int(non_benign_mask.idxmax())
                start_row = max(0, first_atk_idx - 15)
                end_row = min(len(df_clean), start_row + needed_rows)
                df_clean = df_clean.iloc[start_row:end_row].reset_index(drop=True)
            else:
                df_clean = df_clean.iloc[:needed_rows].reset_index(drop=True)
        else:
            df_clean = df_clean.iloc[:needed_rows].reset_index(drop=True)
        
    x_raw = df_clean[features].replace([np.inf, -np.inf], np.nan)
    x_raw = x_raw.fillna(x_raw.median()).fillna(0).values.astype(np.float64)
    
    mn = mn_arr
    mx = mx_arr
    rng = np.where(mx - mn == 0, 1.0, mx - mn)
    
    x_norm = np.clip((x_raw - mn) / rng, 0.0, 1.0)
    
    # 24-bit RGB linear bitwise mapping (Section 3.2.1)
    iv = np.clip(x_norm * 16777215.0, 0, 16777215).astype(np.uint32)
    red = (iv >> 16) & 0xFF
    green = (iv >> 8) & 0xFF
    blue = iv & 0xFF
    rgb_flows = np.stack([red, green, blue], axis=-1).astype(np.uint8) # (N, 35, 3)
    
    if len(rgb_flows) < W:
        raise ValueError(f"Requires at least {W} flows to construct a window, got {len(rgb_flows)}")
        
    starts = list(range(0, len(rgb_flows) - W + 1, S))
    imgs = np.stack([rgb_flows[i : i + W] for i in starts], axis=0) # (M, 35, 35, 3)
    
    truth = None
    if "Label" in df_clean.columns:
        labs = df_clean["Label"].astype(str).values
        truth = []
        for i in starts:
            win_labs = labs[i : i + W]
            unique_l = np.unique(win_labs)
            non_benign = [u for u in unique_l if not u.upper().startswith("BENIGN")]
            truth.append(non_benign[0] if non_benign else "BENIGN")
            
    return imgs, truth


def generate_attention_heatmap(rgb_img, attn_matrix):
    """
    Replicates Figure 11: Visualizes original flow-converted images and their
    corresponding ViT attention heatmaps.
    
    Args:
        rgb_img: (35, 35, 3) uint8 numpy array
        attn_matrix: (35, 35) float32 numpy array of layer-averaged attention weights
    Returns:
        heatmap_img: (140, 140) PIL Image with Jet colormap overlay
        side_by_side: (140, 288) PIL Image showing [Original RGB | Attention Map]
    """
    # Token importance: sum attention weights along columns (how much all flows attend to flow i)
    row_weights = attn_matrix.sum(axis=-1) # (35,)
    
    # Normalize row weights
    rw_min, rw_max = row_weights.min(), row_weights.max()
    rw_norm = (row_weights - rw_min) / (rw_max - rw_min + 1e-8)
    
    # Expand into 2D heatmap: (35, 35)
    heatmap_2d = np.repeat(rw_norm[:, np.newaxis], 35, axis=1) # (35, 35)
    
    # Jet colormap generation without matplotlib dependency
    # 0.0 -> Blue, 0.5 -> Green/Yellow, 1.0 -> Red
    r = np.clip(1.5 - np.abs(4.0 * heatmap_2d - 3.0), 0.0, 1.0)
    g = np.clip(1.5 - np.abs(4.0 * heatmap_2d - 2.0), 0.0, 1.0)
    b = np.clip(1.5 - np.abs(4.0 * heatmap_2d - 1.0), 0.0, 1.0)
    jet_rgb = (np.stack([r, g, b], axis=-1) * 255).astype(np.uint8)
    
    # Resize to 140x140 using Nearest Neighbor for crisp pixel-cell visualization
    orig_pil = Image.fromarray(rgb_img).resize((140, 140), Image.NEAREST)
    heat_pil = Image.fromarray(jet_rgb).resize((140, 140), Image.NEAREST)
    
    # Construct side-by-side composite
    composite = Image.new("RGB", (288, 140), (20, 24, 33))
    composite.paste(orig_pil, (0, 0))
    composite.paste(heat_pil, (148, 0))
    
    return heat_pil, composite


@torch.no_grad()
def predict_with_attention(model, imgs, classes, device="cpu", bs=64):
    """
    Executes batched inference with MEIC-ViT and extracts attention heatmaps.
    Returns:
        predictions: list of top predicted classes
        confidences: list of top probabilities
        threat_levels: list of (level, color_hex)
        composites: list of PIL Images (Original | Attention Map)
        all_probs: (M, C) matrix of all class probabilities
    """
    model.eval()
    all_logits = []
    all_attns = []
    
    for i in range(0, len(imgs), bs):
        batch_np = imgs[i : i + bs]
        # (B, 35, 35, 3) -> (B, 3, 35, 35) in [0, 1]
        batch_tensor = torch.from_numpy(batch_np).permute(0, 3, 1, 2).float().div(255.0).to(device)
        logits, attns = model(batch_tensor, return_attention=True)
        all_logits.append(logits.cpu())
        all_attns.append(attns.cpu())
        
    logits_cat = torch.cat(all_logits, dim=0) # (M, C)
    attns_cat = torch.cat(all_attns, dim=0).numpy() # (M, 35, 35)
    
    probs = torch.softmax(logits_cat, dim=-1).numpy()
    pred_indices = probs.argmax(axis=1)
    
    predictions = [classes[idx] for idx in pred_indices]
    confidences = [float(probs[i, idx]) for i, idx in enumerate(pred_indices)]
    threat_info = [THREAT_LEVELS.get(p, ("UNKNOWN", "#6B7280")) for p in predictions]
    
    composites = []
    for i in range(len(imgs)):
        _, comp = generate_attention_heatmap(imgs[i], attns_cat[i])
        composites.append(comp)
        
    return predictions, confidences, threat_info, composites, probs


def simulate_traffic_stream(attack_type="DDoS", n_flows=70):
    """
    Generates synthetic live streaming flows on the fly for the real-time simulation tab.
    """
    from train_meic_vit import generate_class_flow_data
    if attack_type == "Normal Traffic":
        df = generate_class_flow_data("BENIGN", n_flows)
    elif attack_type == "DDoS Attack":
        df = pd.concat([generate_class_flow_data("BENIGN", 15),
                        generate_class_flow_data("DDoS", n_flows - 15)], ignore_index=True)
    elif attack_type == "PortScan Probe":
        df = pd.concat([generate_class_flow_data("BENIGN", 15),
                        generate_class_flow_data("PortScan", n_flows - 15)], ignore_index=True)
    elif attack_type == "Botnet C2 Beaconing":
        df = pd.concat([generate_class_flow_data("BENIGN", 20),
                        generate_class_flow_data("Bot", n_flows - 20)], ignore_index=True)
    elif attack_type == "Heartbleed Exploit":
        df = pd.concat([generate_class_flow_data("BENIGN", 20),
                        generate_class_flow_data("Heartbleed", n_flows - 20)], ignore_index=True)
    elif attack_type == "Web SQL Injection":
        df = pd.concat([generate_class_flow_data("BENIGN", 20),
                        generate_class_flow_data("Web Attack Sql Injection", n_flows - 20)], ignore_index=True)
    else:
        df = generate_class_flow_data("BENIGN", n_flows)
        
    return df
