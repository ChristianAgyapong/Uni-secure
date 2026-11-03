"""
Unified Prediction Service for MEIC-ViT NIDS.
Handles preprocessing, windowing, tensor conversion, and inference
for both CSV batch uploads and live-captured network flows.
"""

import time
import numpy as np
import pandas as pd
import torch
from typing import Dict, Any, List, Optional

from pipeline import (
    load_artifacts,
    load_unsw_artifacts,
    to_windows,
    predict_with_attention,
    is_unsw_dataset,
    THREAT_LEVELS,
    THREAT_LEVELS_UNSW,
    UNSW_CLASSES,
    pil_to_b64,
)

class ModelService:
    def __init__(self, device: str = "cpu"):
        self.device = device
        
        # Load CICIDS-2017 Model (Default primary model)
        print("[ModelService] Initializing primary CICIDS-2017 model...")
        self.model_cicids, self.meta_cicids, self.trained_cicids = load_artifacts(device=self.device)
        self.classes_cicids = self.meta_cicids.get("classes", [])
        
        # Load UNSW-NB15 Model
        print("[ModelService] Initializing UNSW-NB15 model...")
        self.model_unsw, self.meta_unsw, self.trained_unsw = load_unsw_artifacts(device=self.device)
        self.classes_unsw = UNSW_CLASSES if self.trained_unsw else []
        
        print(f"[ModelService] Loaded: CICIDS ({len(self.classes_cicids)} classes), UNSW ({len(self.classes_unsw)} classes)")

    @property
    def expected_cicids_features(self) -> List[str]:
        return list(self.meta_cicids.get("features", []))

    def _is_clean_prediction(self, pred: str) -> bool:
        p = (pred or "").upper().strip()
        return p.startswith("BENIGN") or p.startswith("NORMAL")

    def predict_dataframe(
        self,
        df: pd.DataFrame,
        model_type: Optional[str] = None,
        max_windows: int = 50,
    ) -> Dict[str, Any]:
        """
        Takes a pandas DataFrame of flows, preprocesses into MEIC-ViT image tensors,
        and runs inference with spatial-temporal attention maps.
        """
        t0 = time.time()
        
        # Determine model
        if model_type == "unsw" or (model_type is None and is_unsw_dataset(df)):
            active_model = self.model_unsw if self.model_unsw else self.model_cicids
            active_meta = self.meta_unsw if self.model_unsw else self.meta_cicids
            active_classes = self.classes_unsw if self.model_unsw else self.classes_cicids
            active_threat_map = THREAT_LEVELS_UNSW if self.model_unsw else THREAT_LEVELS
            is_unsw = True
        else:
            active_model = self.model_cicids
            active_meta = self.meta_cicids
            active_classes = self.classes_cicids
            active_threat_map = THREAT_LEVELS
            is_unsw = False

        # Convert flow records to 35x35x3 RGB tensor windows
        imgs, labels, composites = to_windows(df, active_meta, max_windows=max_windows)
        
        if len(imgs) == 0:
            return {
                "n_flows": len(df),
                "n_windows": 0,
                "n_attack_windows": 0,
                "elapsed_s": round(time.time() - t0, 3),
                "trained_model": self.trained_unsw if is_unsw else self.trained_cicids,
                "highest_threat": "LOW",
                "threat_counts": {},
                "class_counts": {},
                "confirmed_threats_count": 0,
                "provisional_threats_count": 0,
                "has_anomaly": False,
                "windows": [],
            }

        # Predict with attention maps
        preds, confs, probs, attn_maps, raw_threats = predict_with_attention(
            active_model, imgs, active_classes, device=self.device, threat_levels=active_threat_map
        )
        elapsed = round(time.time() - t0, 3)

        rows = []
        threat_counts = {}
        class_counts = {}

        for i in range(len(imgs)):
            pred = preds[i]
            conf = float(confs[i])
            lvl, col = raw_threats[i]
            gt = labels[i]
            
            clean_name = "Normal" if is_unsw else "BENIGN"
            if gt:
                if self._is_clean_prediction(pred) and self._is_clean_prediction(gt):
                    correct = True
                else:
                    correct = (pred.strip().upper() == gt.strip().upper())
            else:
                correct = None

            status = "CONFIRMED" if conf >= 0.60 else "PROVISIONAL"
            
            # Multi-window persistence
            is_attack = not self._is_clean_prediction(pred)
            is_persistent = False
            if is_attack:
                if conf >= 0.70:
                    is_persistent = True
                elif i > 0 and (preds[i-1] == pred or not self._is_clean_prediction(preds[i-1])) and confs[i-1] >= 0.40:
                    is_persistent = True
                elif i < len(preds) - 1 and (preds[i+1] == pred or not self._is_clean_prediction(preds[i+1])) and confs[i+1] >= 0.40:
                    is_persistent = True

            top5_idx = probs[i].argsort()[::-1][:5]
            top5 = [{"label": active_classes[j], "prob": round(float(probs[i, j]), 4)} for j in top5_idx]

            row = {
                "window": i,
                "prediction": pred,
                "confidence": round(conf, 4),
                "threat_level": lvl,
                "threat_color": col,
                "ground_truth": gt,
                "correct": correct,
                "confidence_status": status,
                "is_persistent": is_persistent,
                "top5": top5,
                "composite_b64": pil_to_b64(composites[i]),
            }
            rows.append(row)
            threat_counts[lvl] = threat_counts.get(lvl, 0) + 1
            class_counts[pred] = class_counts.get(pred, 0) + 1

        attack_rows = [r for r in rows if not self._is_clean_prediction(r["prediction"])]
        attack_threat_counts = {}
        for r in attack_rows:
            lvl = r["threat_level"]
            attack_threat_counts[lvl] = attack_threat_counts.get(lvl, 0) + 1

        highest_threat = max(
            attack_threat_counts.keys(),
            key=lambda x: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x) if x in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] else -1,
            default="LOW"
        ) if attack_threat_counts else "LOW"

        n_attack_windows = len(attack_rows)
        confirmed_threats = sum(1 for r in attack_rows if r["confidence_status"] == "CONFIRMED" or r["is_persistent"])
        provisional_threats = sum(1 for r in attack_rows if r["confidence_status"] != "CONFIRMED" and not r["is_persistent"])
        has_anomaly = any(r["threat_level"] != "LOW" or r["confidence"] < 0.70 for r in rows)

        return {
            "n_flows": len(df),
            "n_windows": len(imgs),
            "n_attack_windows": n_attack_windows,
            "elapsed_s": elapsed,
            "trained_model": self.trained_unsw if is_unsw else self.trained_cicids,
            "highest_threat": highest_threat,
            "threat_counts": threat_counts,
            "class_counts": class_counts,
            "confirmed_threats_count": confirmed_threats,
            "provisional_threats_count": provisional_threats,
            "has_anomaly": has_anomaly,
            "windows": rows,
        }

    def predict_flow_batch(self, flow_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Accepts a list of live flow feature dictionaries and evaluates them.
        """
        df = pd.DataFrame(flow_records)
        return self.predict_dataframe(df, model_type="cicids")

