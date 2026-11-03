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

# ── UNSW-NB15 class list (10 classes, matches meic_vit_unsw.pt) ───────────────
UNSW_CLASSES = [
    "Normal", "Generic", "Exploits", "Fuzzers", "DoS",
    "Reconnaissance", "Analysis", "Backdoor", "Shellcode", "Worms"
]

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

# ── UNSW-NB15 threat level mapping ───────────────────────────────────────────
THREAT_LEVELS_UNSW = {
    "Normal":          ("LOW",      "#10B981"),
    "Reconnaissance":  ("MEDIUM",   "#F59E0B"),
    "Fuzzers":         ("MEDIUM",   "#F59E0B"),
    "Analysis":        ("MEDIUM",   "#F59E0B"),
    "DoS":             ("HIGH",     "#F97316"),
    "Backdoor":        ("HIGH",     "#F97316"),
    "Exploits":        ("HIGH",     "#F97316"),
    "Generic":         ("HIGH",     "#F97316"),
    "Shellcode":       ("CRITICAL", "#EF4444"),
    "Worms":           ("CRITICAL", "#EF4444"),
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


def load_unsw_artifacts(device="cpu"):
    """
    Loads UNSW-NB15 specific MEIC-ViT model (10 classes) and scaler metadata.
    Returns (model, meta, True) if artifacts exist, else (None, None, False).
    """
    scaler_path = os.path.join(ARTIFACTS_DIR, "scaler_unsw.json")
    ckpt_path   = os.path.join(ARTIFACTS_DIR, "meic_vit_unsw.pt")
    if not os.path.exists(scaler_path) or not os.path.exists(ckpt_path):
        return None, None, False

    with open(scaler_path, "r") as f:
        meta = json.load(f)

    window     = meta.get("window", 35)
    hidden_dim = meta.get("hidden_dim", 256)
    n_layers   = meta.get("n_layers", 6)
    n_heads    = meta.get("n_heads", 8)
    topk       = meta.get("topk", 3)
    num_classes = len(meta["classes"])

    model = MEICViT(num_classes=num_classes, window=window,
                    hidden_dim=hidden_dim, n_layers=n_layers,
                    n_heads=n_heads, topk=topk)
    state_dict = torch.load(ckpt_path, map_location=device)
    model.load_state_dict(state_dict)
    model.eval()
    model.to(device)
    return model, meta, True


def is_unsw_dataset(df):
    """Returns True if the DataFrame appears to be UNSW-NB15 format."""
    lower_cols = {c.lower() for c in df.columns}
    return (
        "attack_cat" in lower_cols
        or ("dur" in lower_cols and "spkts" in lower_cols and "sbytes" in lower_cols)
    )


def map_unsw_dataframe(df):
    """
    Transforms UNSW-NB15 columns into the 35 standard MEIC-ViT feature columns.
    Mirrors the mapping used in train_unsw.py so inference uses the same feature space.
    """
    df = df.copy()
    lower = {c.lower(): c for c in df.columns}

    # Duration → Flow_Duration (microseconds)
    dur_s = pd.to_numeric(df.get(lower.get("dur", "__missing__"), pd.Series(0.001, index=df.index)),
                          errors="coerce").fillna(0.001).clip(lower=1e-6)
    df["Flow_Duration"] = dur_s * 1e6

    def _col(key, default_val):
        col_name = lower.get(key)
        if col_name and col_name in df.columns:
            return pd.to_numeric(df[col_name], errors="coerce").fillna(default_val)
        return pd.Series(default_val, index=df.index)

    spkts  = _col("spkts",  1).clip(lower=1)
    dpkts  = _col("dpkts",  0)
    sbytes = _col("sbytes", 64)
    dbytes = _col("dbytes", 0)
    smean  = _col("smean",  64)
    dmean  = _col("dmean",  0)
    sjit   = _col("sjit",   0)
    djit   = _col("djit",   0)
    sinpkt = _col("sinpkt", 0) * 1e3   # ms → µs
    dinpkt = _col("dinpkt", 0) * 1e3

    df["Total_Length_of_Fwd_Packets"] = sbytes
    df["Total_Length_of_Bwd_Packets"] = dbytes
    df["Fwd_Packet_Length_Mean"]      = smean

    tot_pkts    = (spkts + dpkts).clip(lower=1)
    overall_mean = (sbytes + dbytes) / tot_pkts
    p_fwd = spkts / tot_pkts
    p_bwd = dpkts / tot_pkts

    df["Packet_Length_Variance"] = (
        p_fwd * (smean - overall_mean)**2
        + p_bwd * (dmean - overall_mean)**2
        + (sjit + djit) * 2.0
    )
    df["Max_Packet_Length"]      = np.maximum(smean * 1.5, dmean * 1.5).clip(64, 1514)
    df["Fwd_Packet_Length_Max"]  = (smean * 1.4).clip(40, 1514)
    df["Min_Packet_Length"]      = np.minimum(smean, np.where(dmean > 0, dmean, smean)).clip(0, 64)
    df["Fwd_Packet_Length_Min"]  = (smean * 0.6).clip(0, 64)
    df["Bwd_Packet_Length_Min"]  = (dmean * 0.6).clip(0, 64)

    rate_col = lower.get("rate")
    if rate_col and rate_col in df.columns:
        df["Flow_Packets_s"] = pd.to_numeric(df[rate_col], errors="coerce").fillna(tot_pkts / dur_s)
    else:
        df["Flow_Packets_s"] = tot_pkts / dur_s
    df["Flow_Bytes_s"]  = (sbytes + dbytes) / dur_s
    df["Bwd_Packets_s"] = dpkts / dur_s

    df["Init_Win_bytes_forward"]  = _col("swin", 255)
    df["Init_Win_bytes_backward"] = _col("dwin", 255)

    df["Fwd_IAT_Mean"]   = sinpkt
    df["Bwd_IAT_Mean"]   = dinpkt
    df["Fwd_IAT_Max"]    = sinpkt * 2.5
    df["Bwd_IAT_Max"]    = dinpkt * 2.5
    df["Fwd_IAT_Min"]    = sinpkt * 0.2
    df["Bwd_IAT_Total"]  = dinpkt * dpkts
    df["Bwd_IAT_Std"]    = djit * 1e3
    df["Flow_IAT_Min"]   = np.minimum(sinpkt, np.where(dinpkt > 0, dinpkt, sinpkt)) * 0.1

    # Protocol
    proto_map = {"tcp": 6, "udp": 17, "icmp": 1, "arp": 0, "ospf": 89}
    proto_col = lower.get("proto")
    if proto_col and proto_col in df.columns:
        df["Protocol"] = df[proto_col].astype(str).str.lower().map(proto_map).fillna(6)
    else:
        df["Protocol"] = 6

    # Destination port
    svc_port_map = {
        "http": 80, "dns": 53, "ftp": 21, "ftp-data": 20, "smtp": 25,
        "ssh": 22, "pop3": 110, "ssl": 443, "snmp": 161, "dhcp": 67,
        "radius": 1812, "irc": 6667, "-": 80
    }
    dsport_col = lower.get("dsport")
    service_col = lower.get("service")
    if dsport_col and dsport_col in df.columns:
        df["Destination_Port"] = pd.to_numeric(df[dsport_col], errors="coerce").fillna(80)
    elif service_col and service_col in df.columns:
        df["Destination_Port"] = df[service_col].astype(str).str.lower().map(svc_port_map).fillna(80)
    else:
        df["Destination_Port"] = 80

    sport_col = lower.get("sport")
    if sport_col and sport_col in df.columns:
        df["Source_Port"] = pd.to_numeric(df[sport_col], errors="coerce").fillna(49152)
    else:
        df["Source_Port"] = 49152

    df["Fwd_Header_Length"]    = spkts * 32
    df["Bwd_Header_Length"]    = dpkts * 32
    df["min_seg_size_forward"] = 32

    sloss = _col("sloss", 0)
    df["act_data_pkt_fwd"] = np.maximum(0, spkts - sloss)
    df["Down_Up_Ratio"]    = dpkts / spkts.clip(lower=1)

    tcprtt = _col("tcprtt", 0)
    synack = _col("synack", 0)
    ackdat = _col("ackdat", 0)
    ct_flw = _col("ct_flw_http_mthd", 0)

    df["PSH_Flag_Count"] = np.where(ct_flw > 0, 1, np.where(smean > 200, 1, 0))
    df["ACK_Flag_Count"] = np.where((tcprtt > 0) | (synack > 0) | (ackdat > 0), 1, 0)
    df["Active_Mean"]    = df["Flow_Duration"] * 0.8
    df["Active_Max"]     = df["Flow_Duration"]

    return df


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
    - Auto-detects UNSW-NB15 format and applies map_unsw_dataframe() before encoding
    - Uses 35 selected features
    - Resiliently matches column aliases and imputes dataset-specific omissions
    - Min-max normalizes to [0, 1] using training set bounds
    - Maps to 24-bit RGB: Red = (val >> 16) & 0xFF, Green = (val >> 8) & 0xFF, Blue = val & 0xFF
    - Applies sliding window (W=35, S=18 -> 48.6% overlap)
    - Extracts ground truth labels if Label column is present
    """
    # ── UNSW-NB15 auto-detection and feature mapping ─────────────────────────
    _is_unsw = is_unsw_dataset(df)
    if _is_unsw:
        df = map_unsw_dataframe(df)

    df_clean = clean_cols(df)
    features = meta["features"]
    W = meta["window"]
    S = meta["stride"]

    # ── Label column unification ─────────────────────────────────────────────
    # CICIDS-2017 uses 'Label'; UNSW-NB15 uses 'attack_cat' + 'label' (binary)
    lower_cols = {c.lower(): c for c in df_clean.columns}
    if "Label" not in df_clean.columns:
        if "attack_cat" in lower_cols:
            # UNSW-NB15: attack_cat contains class name (Normal, DoS, Exploits …)
            df_clean["Label"] = df_clean[lower_cols["attack_cat"]].astype(str).str.strip()
            # For UNSW model keep "Normal" as-is; only map to BENIGN for CICIDS model
            if not _is_unsw:
                df_clean["Label"] = df_clean["Label"].replace({"Normal": "BENIGN", "normal": "BENIGN"})
        elif "label" in lower_cols:
            # Binary label (0=normal, 1=attack)
            raw_lab = df_clean[lower_cols["label"]].astype(str)
            df_clean["Label"] = raw_lab.map(
                lambda v: "BENIGN" if str(v).strip() in ("0", "0.0", "Normal") else "Attack"
            )

    # ── Protocol column: encode UNSW-NB15 nominal proto as numeric ──────────
    if "proto" in lower_cols and "Protocol" not in df_clean.columns:
        proto_map = {"tcp": 6, "udp": 17, "icmp": 1, "arp": 0, "ospf": 89}
        df_clean["Protocol"] = df_clean[lower_cols["proto"]].astype(str).str.lower().map(proto_map).fillna(6)

    # ── Service column: encode UNSW-NB15 service as numeric ─────────────────
    if "service" in lower_cols and "Service" not in df_clean.columns:
        svc_map = {"http": 80, "ftp": 21, "smtp": 25, "ssh": 22, "dns": 53, "ftp-data": 20, "-": 0}
        df_clean["Service"] = df_clean[lower_cols["service"]].astype(str).str.lower().map(svc_map).fillna(0)

    # 1. Alias matching (case-insensitive / common CICFlowMeter variants)
    col_map = {}
    lower_cols = {c.lower(): c for c in df_clean.columns}  # refresh after new cols added
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
                for cand in ["protocol", "proto", "Protocol"]:
                    if cand in lower_cols:
                        col_map[feat] = lower_cols[cand]
                        break

    for target, source in col_map.items():
        df_clean[target] = df_clean[source]

    # Validate schema coverage: ensure this is actually network flow telemetry
    matched_features = sum(1 for feat in features if feat in df_clean.columns)
    if matched_features < 3 and not _is_unsw:
        raise ValueError(
            f"Incompatible CSV Schema: Found only {matched_features} of 35 expected network flow features. "
            "The uploaded file does not appear to contain valid network traffic telemetry. "
            "Please upload a CICFlowMeter or UNSW-NB15 flow capture CSV."
        )

    # 2. Impute known domain features stripped in CICIDS MachineLearningCVE benchmark CSVs
    if "Source_Port" not in df_clean.columns:
        df_clean["Source_Port"] = 49152  # Standard dynamic ephemeral port
    if "Protocol" not in df_clean.columns:
        df_clean["Protocol"] = 6  # Standard TCP protocol

    # 3. Fallback for any other missing feature from metadata bounds
    mn_arr = np.array(meta["mn"], dtype=np.float64)
    mx_arr = np.array(meta["mx"], dtype=np.float64)
    for i, feat in enumerate(features):
        if feat not in df_clean.columns:
            df_clean[feat] = (mn_arr[i] + mx_arr[i]) / 2.0

    # 4. Large CSV optimization: slice smartly so large datasets process instantaneously
    needed_rows = max_windows * S + W + 50
    if len(df_clean) > needed_rows:
        if "Label" in df_clean.columns:
            is_clean_label = (
                df_clean["Label"].astype(str).str.upper().str.startswith("BENIGN")
                | df_clean["Label"].astype(str).str.upper().str.startswith("NORMAL")
            )
            non_benign_mask = ~is_clean_label
            if non_benign_mask.any():
                first_atk_idx = int(non_benign_mask.idxmax())
                start_row = max(0, first_atk_idx - 15)
                end_row = min(len(df_clean), start_row + needed_rows)
                df_clean = df_clean.iloc[start_row:end_row].reset_index(drop=True)
            else:
                df_clean = df_clean.iloc[:needed_rows].reset_index(drop=True)
        else:
            df_clean = df_clean.iloc[:needed_rows].reset_index(drop=True)

    # 5. Extract only numeric feature columns BEFORE calling median()
    #    This prevents 'Cannot perform reduction median with string dtype'
    #    that occurs when UNSW-NB15 string cols (proto, service, state, attack_cat) remain
    x_raw = df_clean[features].copy()
    # Force any remaining string-typed feature columns to numeric (coerce → NaN)
    for col in x_raw.columns:
        if x_raw[col].dtype == object:
            x_raw[col] = pd.to_numeric(x_raw[col], errors="coerce")
    x_raw = x_raw.replace([np.inf, -np.inf], np.nan)
    # Compute median only on numeric columns, then fill NaN
    numeric_medians = x_raw.median(numeric_only=True)
    x_raw = x_raw.fillna(numeric_medians).fillna(0).values.astype(np.float64)
    
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
        clean_name = "Normal" if _is_unsw else "BENIGN"
        filled_labs = df_clean["Label"].fillna(clean_name)
        labs = [str(x).strip() for x in filled_labs]
        truth = []
        for i in starts:
            win_labs = labs[i : i + W]
            unique_l, counts = np.unique(win_labs, return_counts=True)
            non_benign_counts = {
                l: c for l, c in zip(unique_l, counts)
                if not (str(l).upper().startswith("BENIGN") or str(l).upper().startswith("NORMAL") or str(l).upper() in ("NAN", "NONE"))
            }
            total_attack_flows = sum(non_benign_counts.values())
            
            if not non_benign_counts:
                truth.append(clean_name)
            else:
                top_attack = max(non_benign_counts.keys(), key=lambda k: non_benign_counts[k])
                # If attack flows represent the majority (>= 50% of the window)
                if total_attack_flows >= (W / 2.0):
                    truth.append(top_attack)
                else:
                    # Onset boundary: mostly benign background with early attack flows
                    truth.append(f"{clean_name} ({top_attack} Onset)")
            
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
def predict_with_attention(model, imgs, classes, device="cpu", bs=64, threat_levels=None):
    """
    Executes batched inference with MEIC-ViT and extracts attention heatmaps.
    Returns:
        predictions: list of top predicted classes
        confidences: list of top probabilities
        threat_levels: list of (level, color_hex)
        composites: list of PIL Images (Original | Attention Map)
        all_probs: (M, C) matrix of all class probabilities
    """
    if threat_levels is None:
        threat_levels = THREAT_LEVELS
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
    
    benign_name = "BENIGN"
    for cand in ("BENIGN", "Normal", "normal", "Benign"):
        if cand in classes:
            benign_name = cand
            break
    benign_idx = classes.index(benign_name) if benign_name in classes else -1
    attack_indices = [k for k in range(len(classes)) if k != benign_idx]
    
    predictions = []
    confidences = []
    
    for i in range(len(imgs)):
        p_row = probs[i]
        top_raw_idx = int(p_row.argmax())
        
        if benign_idx >= 0 and attack_indices:
            p_benign = float(p_row[benign_idx])
            p_total_attack = float(1.0 - p_benign)
            
            # Find leading attack candidate
            best_atk_idx = max(attack_indices, key=lambda k: p_row[k])
            best_atk_prob = float(p_row[best_atk_idx])
            best_atk_name = classes[best_atk_idx]
            
            # 1. Clear attack classification: raw argmax is an attack
            if top_raw_idx != benign_idx:
                predictions.append(classes[top_raw_idx])
                confidences.append(float(p_row[top_raw_idx]))
            # 2. Confirmed clean Benign baseline: Benign is unambiguous winner
            elif p_benign >= 0.50 and best_atk_prob < 0.30:
                predictions.append(benign_name)
                confidences.append(p_benign)
            # 3. Threat-Sensitive Onset Boundary:
            # Benign has a thin plurality (<0.50 or close margin) BUT an attack has significant evidence:
            elif (best_atk_prob >= 0.30 and (best_atk_prob / max(p_benign, 1e-4)) >= 0.65) or (p_total_attack >= 0.60 and best_atk_prob >= 0.25):
                # Do not underrate stealth/application attacks when Benign has only a thin margin
                predictions.append(best_atk_name)
                effective_conf = max(best_atk_prob, p_total_attack * 0.75)
                confidences.append(effective_conf)
            else:
                predictions.append(benign_name)
                confidences.append(p_benign)
        else:
            predictions.append(classes[top_raw_idx])
            confidences.append(float(p_row[top_raw_idx]))
            
    threat_info = [threat_levels.get(p, ("UNKNOWN", "#6B7280")) for p in predictions]
    
    composites = []
    for i in range(len(imgs)):
        _, comp = generate_attention_heatmap(imgs[i], attns_cat[i])
        composites.append(comp)
        
    return predictions, confidences, threat_info, composites, probs


def simulate_traffic_stream(attack_type="DDoS", n_flows=70):
    """
    Generates realistic streaming flows.
    - CICIDS-2017 attack types: use CICFlowMeter sample CSVs
    - UNSW-NB15 attack types (prefixed 'UNSW ...'): use UNSW sample CSVs
    Falls back gracefully if sample CSVs are not yet present.
    """
    sample_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_data")

    # ── UNSW-NB15 simulation (any attack_type starting with 'UNSW') ──────────
    UNSW_TYPE_MAP = {
        "UNSW Normal":          "normal",
        "UNSW Generic":         "generic",
        "UNSW Exploits":        "exploits",
        "UNSW Fuzzers":         "fuzzers",
        "UNSW DoS":             "dos",
        "UNSW Reconnaissance":  "reconnaissance",
        "UNSW Analysis":        "analysis",
        "UNSW Backdoor":        "backdoor",
        "UNSW Shellcode":       "shellcode",
        "UNSW Worms":           "worms",
    }
    if attack_type in UNSW_TYPE_MAP:
        cls_key     = UNSW_TYPE_MAP[attack_type]
        csv_path    = os.path.join(sample_dir, f"sample_unsw_{cls_key}.csv")
        normal_path = os.path.join(sample_dir, "sample_unsw_normal.csv")
        try:
            if os.path.exists(csv_path):
                df_atk = pd.read_csv(csv_path)
                if cls_key == "normal":
                    return df_atk.sample(min(n_flows, len(df_atk)),
                                         replace=(n_flows > len(df_atk)),
                                         random_state=42).reset_index(drop=True)
                # Mix 20% normal + 80% attack for realistic windows
                n_atk  = max(int(n_flows * 0.80), 35)
                n_norm = n_flows - n_atk
                df_sub = df_atk.sample(min(n_atk, len(df_atk)),
                                       replace=(n_atk > len(df_atk)), random_state=42)
                if n_norm > 0 and os.path.exists(normal_path):
                    df_norm     = pd.read_csv(normal_path)
                    df_norm_sub = df_norm.sample(min(n_norm, len(df_norm)),
                                                 replace=(n_norm > len(df_norm)), random_state=42)
                    df_sub = pd.concat([df_norm_sub, df_sub], ignore_index=True)
                return df_sub.sample(frac=1, random_state=42).reset_index(drop=True)
        except Exception:
            pass
        # Last-resort UNSW fallback: any saved UNSW CSV
        try:
            for fname in sorted(os.listdir(sample_dir)):
                if fname.startswith("sample_unsw_") and fname.endswith(".csv"):
                    return pd.read_csv(os.path.join(sample_dir, fname)).head(n_flows)
        except Exception:
            pass


    benign_path = os.path.join(sample_dir, "sample_benign_traffic.csv")
    ddos_path = os.path.join(sample_dir, "sample_ddos_traffic.csv")
    portscan_path = os.path.join(sample_dir, "sample_portscan_traffic.csv")
    mixed_path = os.path.join(sample_dir, "sample_mixed_attack_traffic.csv")
    hb_path = os.path.join(sample_dir, "sample_heartbleed_traffic.csv")
    sqli_path = os.path.join(sample_dir, "sample_sqlinjection_traffic.csv")
    
    try:
        if attack_type == "Normal Traffic" and os.path.exists(benign_path):
            df_b = pd.read_csv(benign_path)
            return df_b.sample(min(n_flows, len(df_b)), replace=(n_flows > len(df_b)), random_state=42).reset_index(drop=True)
            
        elif attack_type in ("DDoS Attack", "DDoS") and os.path.exists(ddos_path):
            df_d = pd.read_csv(ddos_path)
            return df_d.sample(min(n_flows, len(df_d)), replace=(n_flows > len(df_d)), random_state=42).reset_index(drop=True)
            
        elif attack_type in ("PortScan Probe", "PortScan") and os.path.exists(portscan_path):
            df_p = pd.read_csv(portscan_path)
            return df_p.sample(min(n_flows, len(df_p)), replace=(n_flows > len(df_p)), random_state=42).reset_index(drop=True)
            
        elif attack_type in ("Mixed Attack", "Mixed Attack Traffic") and os.path.exists(mixed_path):
            df_m = pd.read_csv(mixed_path)
            return df_m.sample(min(n_flows, len(df_m)), replace=(n_flows > len(df_m)), random_state=42).reset_index(drop=True)
            
        elif attack_type == "Botnet C2 Beaconing" and os.path.exists(mixed_path):
            df_m = pd.read_csv(mixed_path)
            bots = df_m[df_m["Label"] == "Bot"]
            bng = df_m[df_m["Label"] == "BENIGN"]
            if len(bots) > 0 and len(bng) > 0:
                n_b = min(15, len(bng))
                n_atk = n_flows - n_b
                sub = pd.concat([bng.sample(n_b, replace=True, random_state=42),
                                 bots.sample(n_atk, replace=True, random_state=42)], ignore_index=True)
                return sub

        elif attack_type in ("Heartbleed Exploit", "Heartbleed") and os.path.exists(hb_path):
            df_hb = pd.read_csv(hb_path)
            return df_hb.sample(min(n_flows, len(df_hb)), replace=(n_flows > len(df_hb)), random_state=42).reset_index(drop=True)
                
        elif attack_type in ("Web SQL Injection", "Web Attack Sql Injection") and os.path.exists(sqli_path):
            df_sqli = pd.read_csv(sqli_path)
            return df_sqli.sample(min(n_flows, len(df_sqli)), replace=(n_flows > len(df_sqli)), random_state=42).reset_index(drop=True)
    except Exception:
        pass

    # Fallback to synthetic generator if sample CSVs cannot be loaded
    from train_meic_vit import generate_class_flow_data
    if attack_type == "Normal Traffic":
        return generate_class_flow_data("BENIGN", n_flows)
    elif attack_type == "DDoS Attack":
        return pd.concat([generate_class_flow_data("BENIGN", 15),
                          generate_class_flow_data("DDoS", n_flows - 15)], ignore_index=True)
    elif attack_type == "PortScan Probe":
        return pd.concat([generate_class_flow_data("BENIGN", 15),
                          generate_class_flow_data("PortScan", n_flows - 15)], ignore_index=True)
    else:
        return generate_class_flow_data("BENIGN", n_flows)

