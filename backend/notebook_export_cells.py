# ── ADD A (put right BEFORE Cell 3, min-max normalisation) ───────────────────
# Capture raw ranges. In the corrected pipeline compute these on TRAIN rows only.
RAW_MIN = df[feat_cols].min()
RAW_MAX = df[feat_cols].max()

# ── ADD B (put at the END of the notebook, after training) ───────────────────
import json, shutil
art = {
    "features": list(selected_features),
    "mn": [float(RAW_MIN[f]) for f in selected_features],
    "mx": [float(RAW_MAX[f]) for f in selected_features],
    "classes": [str(c) for c in le_final.classes_],
    "window": WINDOW, "stride": STRIDE,
}
json.dump(art, open(os.path.join(OUTPUT_DIR, "scaler.json"), "w"), indent=2)
print("Saved scaler.json — download it and meic_vit_best.pt into meic_demo/artifacts/")
