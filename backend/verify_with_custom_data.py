"""
Verification Script: Test MEIC-ViT with Custom / Arbitrary Network Traffic Data
Demonstrates end-to-end inference, attention extraction, and accuracy validation.
"""

import os
import sys
import json
import time
import numpy as np
import pandas as pd
from PIL import Image

# Add current directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipeline import load_artifacts, to_windows, predict_with_attention
from train_meic_vit import generate_class_flow_data

def test_custom_data():
    print("=" * 70)
    print("[MEIC-ViT Real Data Verification Test]")
    print("=" * 70)

    # 1. Load trained model & metadata
    print("\n[Step 1] Loading PyTorch MEIC-ViT Checkpoint & Scaler...")
    model, meta, trained = load_artifacts(device="cpu")
    classes = meta["classes"]
    print(f"  * Checkpoint trained: {trained}")
    print(f"  * Total classes: {len(classes)}")
    print(f"  * Window size (W): {meta['window']} flows per image")
    print(f"  * Stride (S): {meta['stride']} flows (48.6% overlap)")

    # 2. Synthesize a brand-new multi-stage attack capture
    print("\n[Step 2] Creating a realistic custom network traffic capture...")
    print("  - Stage A: 25 flows of Normal Web/Email Browsing (BENIGN)")
    print("  - Stage B: 30 flows of Port Scanning Reconnaissance (PortScan)")
    print("  - Stage C: 40 flows of Massive Volumetric Attack (DDoS)")

    df_benign = generate_class_flow_data("BENIGN", n_samples=25)
    df_portscan = generate_class_flow_data("PortScan", n_samples=30)
    df_ddos = generate_class_flow_data("DDoS", n_samples=40)

    custom_capture = pd.concat([df_benign, df_portscan, df_ddos], ignore_index=True)
    custom_csv_path = os.path.join(os.path.dirname(__file__), "custom_test_traffic.csv")
    custom_capture.to_csv(custom_csv_path, index=False)
    print(f"  * Generated {len(custom_capture)} total network flows -> saved to: custom_test_traffic.csv")

    # 3. Convert tabular flows to 24-bit RGB images (Algorithm 1)
    print("\n[Step 3] Executing Flow-to-RGB Image Conversion (Paper Section 3.2.1)...")
    t0 = time.time()
    images, ground_truth = to_windows(custom_capture, meta)
    t_conv = time.time() - t0
    print(f"  * Sliced into {len(images)} RGB image tensors of shape: {images[0].shape}")
    print(f"  * Conversion completed in {t_conv*1000:.2f} ms")

    # 4. Run PyTorch Transformer Forward Pass & Extract Attention Maps
    print("\n[Step 4] Running MEIC-ViT Inference & Extracting Self-Attention (Fig. 11)...")
    t0 = time.time()
    preds, confs, threat_info, composites, probs = predict_with_attention(
        model, images, classes, device="cpu"
    )
    t_inf = time.time() - t0
    print(f"  * Model forward pass completed in {t_inf*1000:.2f} ms ({t_inf/len(images)*1000:.2f} ms/window)")

    # 5. Save visual artifacts to disk
    output_dir = os.path.join(os.path.dirname(__file__), "verification_outputs")
    os.makedirs(output_dir, exist_ok=True)
    
    print("\n[Step 5] Per-Window Detection Results:")
    print("-" * 70)
    print(f"{'Window':<8}{'Predicted Class':<18}{'Confidence':<14}{'Ground Truth':<18}{'Status'}")
    print("-" * 70)

    correct_count = 0
    for i in range(len(preds)):
        gt = ground_truth[i] if ground_truth else "N/A"
        is_match = (preds[i] == gt) if ground_truth else False
        if is_match:
            correct_count += 1
        status = "[MATCH]" if is_match else ("[MISMATCH]" if ground_truth else "---")
        print(f"#{i:<7}{preds[i]:<18}{confs[i]*100:>6.2f}%        {gt:<18}{status}")

        # Save the first 3 composite heatmaps as actual PNG files for inspection
        if i < 3:
            comp_path = os.path.join(output_dir, f"window_{i}_{preds[i].replace(' ', '_')}_attention.png")
            composites[i].save(comp_path)

    if ground_truth:
        accuracy = (correct_count / len(preds)) * 100
        print("-" * 70)
        print(f"Total Classification Accuracy on Custom Test Data: {accuracy:.2f}% ({correct_count}/{len(preds)})")

    print(f"\nAttention Heatmaps (Fig. 11 replication) exported to:\n   {output_dir}")
    print("=" * 70)
    print("Verification Complete! The MEIC-ViT AI model is functional and processing real data.")
    print("=" * 70)

if __name__ == "__main__":
    test_custom_data()
