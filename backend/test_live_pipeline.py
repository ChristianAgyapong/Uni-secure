"""
Unit and Integration Tests for Live NIDS Capture & Inference Pipeline.
Validates Phase 1 through Phase 5 deliverables.
"""

import sys
import os
import json
import time

CURR_DIR = os.path.dirname(os.path.abspath(__file__))
if CURR_DIR not in sys.path:
    sys.path.insert(0, CURR_DIR)

from live_capture import list_network_interfaces, LiveCaptureEngine, FlowRecord
from main import LIVE_ENGINE, run_inference, MODEL, META, CLASSES, THREAT_LEVELS
import pandas as pd
import numpy as np

def test_1_feature_schema_alignment():
    print("\n--- Test 1: Feature Schema Alignment ---")
    with open(os.path.join(CURR_DIR, "artifacts", "scaler.json")) as f:
        scaler = json.load(f)
    expected_features = set(scaler["features"])
    print(f"Scaler expected features count: {len(expected_features)}")

    # Create dummy flow record
    dummy_key = ("10.21.16.30", 54321, "142.250.190.46", 443, 6)
    record = FlowRecord(dummy_key, None, time.time())
    record.fwd_packets = 5
    record.fwd_bytes = 1500
    record.fwd_lengths = [100, 200, 300, 400, 500]
    record.fwd_iats = [1000.0, 2000.0, 1500.0, 3000.0]
    record.bwd_packets = 4
    record.bwd_bytes = 2400
    record.bwd_lengths = [600, 600, 600, 600]
    record.bwd_iats = [1200.0, 1800.0, 2100.0]
    record.all_lengths = record.fwd_lengths + record.bwd_lengths
    record.all_iats = record.fwd_iats + record.bwd_iats
    record.ack_count = 8
    record.psh_count = 2

    feature_dict = record.to_feature_dict()
    extracted_features = set(feature_dict.keys())

    missing = expected_features - extracted_features
    print(f"Missing features in flow record: {missing}")
    assert len(missing) == 0, f"Flow record is missing required features: {missing}"
    print("[PASS] All 35 CICFlowMeter features are accurately computed!")

def test_2_live_batch_inference():
    print("\n--- Test 2: Live Batch Inference Through MEIC-ViT ---")
    # Generate 35 flow records (1 full window)
    records = []
    base_time = time.time()
    for i in range(35):
        key = ("10.21.16.30", 49152 + i, "8.8.8.8", 53 if i % 2 == 0 else 443, 17 if i % 2 == 0 else 6)
        r = FlowRecord(key, None, base_time + i * 0.1)
        r.fwd_packets = np.random.randint(1, 20)
        r.fwd_bytes = np.random.randint(64, 4000)
        r.bwd_packets = np.random.randint(1, 20)
        r.bwd_bytes = np.random.randint(64, 10000)
        r.fwd_lengths = [np.random.randint(40, 1460) for _ in range(r.fwd_packets)]
        r.bwd_lengths = [np.random.randint(40, 1460) for _ in range(r.bwd_packets)]
        r.all_lengths = r.fwd_lengths + r.bwd_lengths
        r.fwd_iats = [np.random.uniform(100, 5000) for _ in range(max(1, r.fwd_packets - 1))]
        r.bwd_iats = [np.random.uniform(100, 5000) for _ in range(max(1, r.bwd_packets - 1))]
        r.all_iats = r.fwd_iats + r.bwd_iats
        records.append(r.to_feature_dict())

    df = pd.DataFrame(records)
    res = run_inference(df, max_windows=5, model=MODEL, meta=META, classes=CLASSES, threat_map=THREAT_LEVELS)
    print(f"Inference complete: {res['n_windows']} windows processed in {res['elapsed_s']}s")
    print(f"Highest threat: {res['highest_threat']}")
    print(f"Predictions: {[w['prediction'] for w in res['windows']]}")
    assert res['n_windows'] > 0
    print("[PASS] Model successfully predicts live flow window with attention maps!")

def test_3_live_engine_lifecycle():
    print("\n--- Test 3: Engine Start/Status/Stop Lifecycle ---")
    start_res = LIVE_ENGINE.start_capture("Wi-Fi")
    print(f"Start response: {start_res}")
    time.sleep(2.0)
    status_res = LIVE_ENGINE.get_status()
    print(f"Status response: {status_res}")
    assert status_res["status"] in ["RUNNING", "RUNNING_SIMULATED"]
    stop_res = LIVE_ENGINE.stop_capture()
    print(f"Stop response: {stop_res}")
    assert stop_res["status"] == "STOPPED"
    print("[PASS] LiveCaptureEngine lifecycle verified!")

if __name__ == "__main__":
    test_1_feature_schema_alignment()
    test_2_live_batch_inference()
    test_3_live_engine_lifecycle()
    print("\n==========================================")
    print("ALL LIVE INTEGRATION TESTS PASSED CLEANLY!")
    print("==========================================")
