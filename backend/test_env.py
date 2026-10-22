import sys
print("STEP 1: Starting script...", flush=True)
print("Python executable:", sys.executable, flush=True)
print("Python version:", sys.version, flush=True)

for mod in ["torch", "torchvision", "numpy", "pandas", "gradio", "PIL", "sklearn"]:
    print(f"Checking {mod}...", flush=True)
    try:
        m = __import__(mod)
        ver = getattr(m, "__version__", "unknown")
        print(f"[{mod}] OK (version {ver})", flush=True)
    except ImportError as e:
        print(f"[{mod}] NOT FOUND: {e}", flush=True)
    except Exception as e:
        print(f"[{mod}] ERROR: {e}", flush=True)

print("DONE!", flush=True)
