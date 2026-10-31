import urllib.request
import json

presets = [
    "DDoS Attack Sample",
    "Port Scan Probe",
    "Benign Traffic",
    "Mixed Attack Traffic",
    "Heartbleed Exploit",
    "Web SQL Injection"
]

url = "http://127.0.0.1:8000/api/analyze-preset"
failures = []

for s in presets:
    payload = json.dumps({"preset_name": s, "max_windows": 5}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read())
            windows = d.get("windows", [])
            if not windows:
                raise ValueError("Response contains no analysis windows")
            preds = [x["prediction"] for x in windows[:3]]
            confs = [f"{x['confidence']*100:.1f}%" for x in windows[:3]]
            highest = d.get("highest_threat")
            print(f"[{s:<22}] -> Highest Threat: {highest:<10} | Windows: {list(zip(preds, confs))}")
    except Exception as e:
        failures.append(s)
        print(f"[{s:<22}] -> Error: {e}")

if failures:
    raise SystemExit(f"Preset checks failed: {', '.join(failures)}")
