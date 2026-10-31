"""
Create Combined Dual-Dataset Synthetic Traffic
Combines authentic flows from both CICIDS-2017 and UNSW-NB15 into a single
standardized 35-feature traffic flow dataset to test how both models differ
and respond to cross-benchmark traffic.
"""

import os
import sys
import numpy as np
import pandas as pd
import torch

CURR_DIR = os.path.dirname(os.path.abspath(__file__))
if CURR_DIR not in sys.path:
    sys.path.insert(0, CURR_DIR)

from pipeline import (
    load_artifacts,
    load_unsw_artifacts,
    map_unsw_dataframe,
    to_windows,
    predict_with_attention,
    THREAT_LEVELS,
    THREAT_LEVELS_UNSW,
    UNSW_CLASSES,
)

SAMPLE_DIR = os.path.join(CURR_DIR, "sample_data")
OUTPUT_CSV = os.path.join(SAMPLE_DIR, "sample_dual_dataset_mixed.csv")

SELECTED_35_FEATURES = [
    "Packet_Length_Variance", "Init_Win_bytes_forward", "Total_Length_of_Bwd_Packets",
    "Total_Length_of_Fwd_Packets", "Max_Packet_Length", "Fwd_Packet_Length_Max",
    "Init_Win_bytes_backward", "Destination_Port", "Flow_Bytes_s", "Flow_Duration",
    "Fwd_IAT_Max", "Fwd_Header_Length", "Fwd_Packet_Length_Mean", "Flow_Packets_s",
    "Bwd_Header_Length", "Bwd_Packets_s", "Fwd_IAT_Mean", "Bwd_IAT_Max", "Bwd_IAT_Total",
    "Source_Port", "Bwd_IAT_Mean", "Bwd_Packet_Length_Min", "min_seg_size_forward",
    "Fwd_IAT_Min", "Bwd_IAT_Std", "Min_Packet_Length", "act_data_pkt_fwd",
    "Fwd_Packet_Length_Min", "Flow_IAT_Min", "Active_Mean", "Active_Max", "Protocol",
    "Down_Up_Ratio", "PSH_Flag_Count", "ACK_Flag_Count"
]

def build_combined_dataset():
    print("=" * 80)
    print("Building Combined Dual-Dataset (CICIDS-2017 + UNSW-NB15)...")
    print("=" * 80)
    
    parts = []
    
    # ── 1. CICIDS-2017 flows ──────────────────────────────────────────────────
    cicids_sources = [
        ("sample_benign_traffic.csv",     "BENIGN",      "CICIDS-2017", 40),
        ("sample_ddos_traffic.csv",       "DDoS",        "CICIDS-2017", 40),
        ("sample_portscan_traffic.csv",   "PortScan",    "CICIDS-2017", 40),
        ("sample_heartbleed_traffic.csv", "Heartbleed",  "CICIDS-2017", 35),
    ]
    
    for fname, label, origin, n in cicids_sources:
        fpath = os.path.join(SAMPLE_DIR, fname)
        if os.path.exists(fpath):
            df = pd.read_csv(fpath)
            # Ensure selected features exist
            sub = df[SELECTED_35_FEATURES].sample(min(n, len(df)), replace=(n > len(df)), random_state=42).copy()
            sub["Label"] = label
            sub["Origin"] = origin
            parts.append(sub)
            print(f"  + Added {len(sub)} flows from {origin}: {label}")
            
    # ── 2. UNSW-NB15 flows ────────────────────────────────────────────────────
    unsw_sources = [
        ("sample_unsw_normal.csv",    "Normal",    "UNSW-NB15", 40),
        ("sample_unsw_exploits.csv",  "Exploits",  "UNSW-NB15", 40),
        ("sample_unsw_generic.csv",   "Generic",   "UNSW-NB15", 40),
        ("sample_unsw_worms.csv",     "Worms",     "UNSW-NB15", 35),
    ]
    
    for fname, label, origin, n in unsw_sources:
        fpath = os.path.join(SAMPLE_DIR, fname)
        if os.path.exists(fpath):
            df = pd.read_csv(fpath)
            # Map raw UNSW columns -> standard 35 features
            df_mapped = map_unsw_dataframe(df)
            sub = df_mapped[SELECTED_35_FEATURES].sample(min(n, len(df_mapped)), replace=(n > len(df_mapped)), random_state=42).copy()
            sub["Label"] = label
            sub["Origin"] = origin
            parts.append(sub)
            print(f"  + Added {len(sub)} flows from {origin}: {label}")
            
    df_combined = pd.concat(parts, ignore_index=True)
    df_combined.to_csv(OUTPUT_CSV, index=False)
    print(f"\nSaved combined dataset ({len(df_combined)} flows) to:")
    print(f"  {OUTPUT_CSV}\n")
    return df_combined

def run_cross_model_comparison(df_combined):
    print("=" * 80)
    print("Cross-Model Diagnostic & Generalization Analysis")
    print("=" * 80)
    
    # Load Model 1 (CICIDS Specialist)
    model_cicids, meta_cicids, trained_cicids = load_artifacts(device="cpu")
    classes_cicids = meta_cicids["classes"]
    
    # Load Model 2 (UNSW Specialist)
    model_unsw, meta_unsw, trained_unsw = load_unsw_artifacts(device="cpu")
    
    print(f"Model 1 (CICIDS): {len(classes_cicids)} classes | Checkpoint Loaded: {trained_cicids}")
    print(f"Model 2 (UNSW):   {len(UNSW_CLASSES)} classes | Checkpoint Loaded: {trained_unsw}\n")
    
    # Slice into windows using Model 1 scaler
    imgs_c, truth_c = to_windows(df_combined, meta_cicids, max_windows=16)
    preds_c, confs_c, threats_c, _, _ = predict_with_attention(
        model_cicids, imgs_c, classes_cicids, device="cpu", threat_levels=THREAT_LEVELS
    )
    
    # Slice into windows using Model 2 scaler
    imgs_u, truth_u = to_windows(df_combined, meta_unsw, max_windows=16)
    preds_u, confs_u, threats_u, _, _ = predict_with_attention(
        model_unsw, imgs_u, UNSW_CLASSES, device="cpu", threat_levels=THREAT_LEVELS_UNSW
    )
    
    print(f"{'Win':<4} | {'Ground Truth':<18} | {'Origin':<11} | {'Model 1 (CICIDS)':<22} | {'Model 2 (UNSW)':<22} | {'Agreement'}")
    print("-" * 105)
    
    # Flow window offset tracking
    S = meta_cicids["stride"]
    W = meta_cicids["window"]
    
    agree_count = 0
    total_wins = min(len(preds_c), len(preds_u))
    
    for i in range(total_wins):
        start_idx = i * S
        end_idx = start_idx + W
        origin_sample = df_combined.iloc[start_idx:end_idx]["Origin"].value_counts().index[0]
        label_sample = truth_c[i] if truth_c else df_combined.iloc[start_idx:end_idx]["Label"].value_counts().index[0]
        
        pred1 = preds_c[i]
        conf1 = confs_c[i]
        lvl1 = threats_c[i][0]
        
        pred2 = preds_u[i]
        conf2 = confs_u[i]
        lvl2 = threats_u[i][0]
        
        # Threat level agreement
        threat_match = (lvl1 == lvl2)
        if threat_match:
            agree_count += 1
            ag_str = f"YES ({lvl1})"
        else:
            ag_str = f"DIFF ({lvl1} vs {lvl2})"
            
        print(f"#{i+1:<3} | {label_sample:<18} | {origin_sample:<11} | {pred1} ({conf1:.0%}, {lvl1})".ljust(64) +
              f" | {pred2} ({conf2:.0%}, {lvl2})".ljust(30) + f" | {ag_str}")
        
    print("-" * 105)
    print(f"Threat Severity Agreement Rate across cross-traffic: {agree_count}/{total_wins} ({agree_count/total_wins:.1%})\n")

if __name__ == "__main__":
    df = build_combined_dataset()
    run_cross_model_comparison(df)

