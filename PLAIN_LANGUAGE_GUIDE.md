# 🛡️ UniSecure SOC — Plain-English Guide & Interface Manual

> **A straightforward guide to what this system does, how the AI works, and how to get the most out of every feature in the dashboard.**  
> Based on the research paper: *MEIC-ViT: A multi-scale enhanced vision transformer for network intrusion detection* (*Elsevier Computer Networks 282, 2026*).

---

## 📌 1. What Is This System in Simple Words?

Imagine a busy university campus or enterprise office. Thousands of students and staff are sending emails, watching videos, browsing websites, and logging into servers. 

Somewhere in that sea of billions of internet packets, a hacker is trying to:
- Overwhelm the web server until it crashes (**DDoS attack**)
- Silently scan open computer ports to find a weak door (**PortScan**)
- Guess administrative passwords repeatedly (**Brute Force**)
- Steal sensitive passwords directly from server memory (**Heartbleed**)

### Why Traditional Security Tools Struggle:
1. **Rule lists get outdated fast**: If a hacker modifies their attack script slightly, old signature rules miss it.
2. **Standard AI gets confused**: Most AI models treat network data as a single flat row in a giant Excel spreadsheet. They miss the "rhythm" and timeline of how an attack unfolds over several seconds.
3. **Black-box problem**: When a normal AI sounds an alarm, it can't tell the human security analyst *why* it did so. Analysts waste hours investigating false alarms.

### What MEIC-ViT Does:
**MEIC-ViT turns network traffic into pictures.** 

By taking 35 consecutive network connections and converting their metrics into a **$35 \times 35$ color image**, the system allows an advanced **Vision Transformer** (the same cutting-edge visual AI used in self-driving cars and medical imaging) to "look" at the network traffic visually. 

- Normal web browsing looks like a calm, scattered pattern.
- A DDoS attack looks like a burning, intense bright red wall.
- A stealthy port scan looks like a rhythmic, repeated stripe.

---

## ⚙️ 2. How the AI Works Under the Hood (Without Math Headaches)

You don't need a PhD in machine learning to understand the 4 steps the AI takes:

```
Raw Network Flows 
      │
      ▼
[1. Traffic Camera] ──► Converts 35 flows into a 35×35 RGB image
      │
      ▼
[2. The Three Eyes] ──► Eye A: Overall volume peaks (Global Stats)
                    ──► Eye B: Sideways flow alignment (Row Visual)
                    ──► Eye C: Timeline sequence (Content Extractor)
      │
      ▼
[3. Transformer Brain] ─► Connects the dots using Self-Attention (Focus Spotlight)
      │
      ▼
[4. Top-3 Zoom] ────────► Focuses on the 3 most suspicious moments in the window
      │
      ▼
Final Verdict ─────────► Threat Level, Attack Class (e.g., DDoS: 99.3%), and Visual Heatmap
```

1. **The Traffic Camera (Algorithm 1)**: Converts 35 flow measurements (packet length, speed, flags) into red, green, and blue pixels.
2. **The Three Eyes (Multi-Path Front-End)**: Rather than relying on one view, the AI uses three specialized "eyes" simultaneously:
   - **Eye 1 (Global Stats)**: Spots sudden spikes in overall traffic volume.
   - **Eye 2 (Row Visual)**: Scans each flow horizontally to see how packet sizes and connection flags correlate.
   - **Eye 3 (Sequential Content)**: Reads the flows chronologically from top to bottom like a filmstrip.
3. **The Transformer Brain (Self-Attention)**: Merges all three perspectives and shines a mathematical "spotlight" on suspicious connections, linking patterns across time.
4. **Top-3 Zoom (Top-K Pooling)**: Rather than averaging everything out (which would dilute a short attack among harmless traffic), the AI zooms in on the **top 3 most malicious moments** in that time window.

---

## 🖥️ 3. How to Use the Dashboard (Feature-by-Feature Tour)

The interface is built like a modern, flight-ready **Security Operations Center (SOC)**. Here is what each tab does and why it is useful to you:

```
┌────────────────────────────────────────────────────────────────────────┐
│  UniSecure SOC — MEIC-ViT Intrusion Detection Dashboard               │
├───────────────┬────────────────────────────────────────────────────────┤
│  [SIDEBAR]    │  [MAIN INTERACTIVE DISPLAY]                            │
│               │                                                        │
│  🔍 Pipeline  │  ► Mode Selector: Preset | Live Stream | CSV Upload    │
│  👁️ Attention │  ► Threat Level Badges & Confidence Meter              │
│  📊 Benchmarks│  ► Inspection Table (Window by Window Predictions)     │
│  🏗️ Architect │  ► Composite Attention Heatmap Gallery (Figure 11)     │
│  🏢 SOC Center│  ► One-Click Incident JSON Export                      │
└───────────────┴────────────────────────────────────────────────────────┘
```

---

### Tab 1: 🔍 Detection Pipeline (Your Interactive Testing Ground)

**What it's for:** This is where you see the AI in action on actual network traffic.

#### What you can do here:
* **Option A: Test Sample Captures (Presets)**
  - Click on the dropdown to select real benchmark captures:
    - `DDoS Attack Sample`: Massive volumetric flood.
    - `Port Scan Probe`: Reconnaissance sweep probing open ports.
    - `Benign Traffic`: Clean, normal web and email browsing.
    - `Mixed Attack Traffic`: Real-world mixture of multiple attack types.
  - Click **"Analyze Threats"**. In less than 100 milliseconds, the table populates with every time window analyzed, showing predicted attack class, threat severity (Low, Medium, High, Critical), and confidence percentage.
* **Option B: Live Traffic Stream (Simulation)**
  - Switch the mode toggle to **"Live Traffic Stream"**.
  - Choose an attack vector (e.g., *Botnet C2 Beaconing*, *SQL Injection*, or *SYN Flood*).
  - Adjust the flow slider (35 to 140 flows) and click **"Inject & Detect"**.
  - Watch the model classify incoming traffic streams live with sub-second turnaround.
* **Option C: Upload Your Own CSV File**
  - Switch to **"Upload Capture File"**.
  - Drag and drop any network CSV (from tools like Wireshark or CICFlowMeter). The AI automatically cleans the columns, slices sliding windows, and provides an instant verdict.
* **Option D: Export Incident Report**
  - Found an attack? Click **"Export Incident Report"** at the top right.
  - Instantly downloads a clean JSON report with timestamps, confidence scores, threat distributions, and quarantine status—ready for compliance audits or incident response tickets.

---

### Tab 2: 👁️ Interpretability & Attention (The AI Explainability Camera)

**What it's for:** Solving the "black-box" dilemma. It proves *why* the AI made its decision.

#### How to read the visualizations:
* **The RGB Traffic Picture (Left)**: Shows the raw $35 \times 35$ image created from the network flows.
* **The Self-Attention Heatmap (Right)**:
  - **Bright, glowing red/yellow pixels**: Represent the exact packets and features that triggered the alert (e.g., abnormal packet variance or repeated TCP SYN/ACK flags).
  - **Dark purple/black regions**: Represent normal background chatter that the AI ignored.
* **Why this is useful in real life**:
  - In a standard AI, if an alarm sounds, an analyst has to guess what went wrong.
  - In MEIC-ViT, the analyst looks at the heatmap and immediately sees: *"Window #3 lit up because rows 12–15 had identical Destination Ports and zero payload length—that's a confirmed port scan."*

---

### Tab 3: 📊 Academic Benchmarks (The Proof Lab)

**What it's for:** Direct evidence that this system is backed by peer-reviewed science and genuine performance data.

#### What you will find across the 5 sub-tabs:
1. **Table 6: CICIDS-2017 & Table 12 Efficiency**:
   - Compare MEIC-ViT against standard computer vision models (**AlexNet: 85.32%**, **ResNet: 91.24%**, **GoogLeNet: 94.25%**) vs. **MEIC-ViT: 98.34%**.
   - See the lightweight footprint: only **3.44 Million parameters** and **0.0303 ms latency per sample** (over 32,000 flows/sec on a single GPU).
2. **Table 8: UNSW-NB15 Generalization**:
   - Proves the model doesn't just work on one dataset. On UNSW-NB15, competing models collapsed (MobileNetV3 F1 dropped to 32.47%), while MEIC-ViT retained **92.35% Accuracy and 92.33% F1**.
3. **Table 5: 15-Class Detailed Breakdown**:
   - Interactive class explorer. Click on any class (`Heartbleed`, `PortScan`, `DDoS`, `Bot`, `FTP-Patator`) to see exact Precision, Recall, F1 scores, sample counts, and why the model excels on it.
4. **Table 9 & 10: Ablation & Overlap Studies**:
   - See what happens if you remove Path A, Path B, or Path C.
   - Shows why **Stride $S=18$ (48.6% overlap)** was selected as the optimal sweet spot between accuracy and RAM usage.
5. **⚡ Live Hardware Benchmark**:
   - Click **"Run Hardware Benchmark"** to test your own local computer's processor right now!
   - Directly executes real forward passes through the PyTorch model and prints your local latency (ms) and flow throughput (flows/second).

---

### Tab 4: 🏗️ Architecture Blueprint (The Interactive Schematic)

**What it's for:** Understanding the entire pipeline from raw data to neural network layers.

#### Highlights:
- Step-by-step visual diagram of the 4 mechanisms (FPSS oversampling, 35-feature correlation filtering, flow-to-image encoding, 6-layer Transformer).
- Interactive parameter cards showing tensor dimensions at each step ($(B, 3, 35, 35) \rightarrow (B, 35, 256) \rightarrow (B, 35, 320) \rightarrow (B, 15)$).
- Perfect for research presentations, customer demos, or technical reviews.

---

### Tab 5: 🏢 SOC Control Center (Enterprise Operations Deck)

**What it's for:** Showing how this AI integrates into a physical security operations environment.

#### Live features:
* **Interactive Campus Node Map**: Visualizes network taps and server zones (Computer Lab 402, Engineering Server, Admin Gateway, IoT Sensors).
* **Active Threat Feed**: Shows flagged security alerts with source IP, detected anomaly, and confidence.
* **One-Click Remediation**:
  - **"Isolate Node"**: Cuts off an infected device from the rest of the campus LAN to prevent malware from spreading.
  - **"Emergency Lockdown"**: Triggers campus-wide security isolation during active severe volumetric incidents.
* **Real-Time Network Telemetry**: Live ingress/egress bandwidth gauges, active session counts, and encryption health monitors.

---

## 🚀 4. How to Run It Locally in 2 Minutes

### Prerequisites:
- Python 3.11 with PyTorch (`torch`, `fastapi`, `uvicorn`, `pandas`, `numpy`, `PIL`)
- Node.js (v18+)

### Step 1: Start the AI Backend
Open a terminal in the project folder and run:
```powershell
cd backend
py -3.11 -m uvicorn main:app --host 127.0.0.1 --port 8000
```
*You will see: `Model successfully loaded. Checkpoint trained: True (Classes: 15)`.*

### Step 2: Start the Web Dashboard
Open a second terminal window:
```powershell
cd frontend
npm run dev
```
*Vite will print: `➜ Local: http://127.0.0.1:5173/`.*

### Step 3: Open in Your Browser
Open your browser to:
👉 **`http://127.0.0.1:5173/`**

---

## 📖 5. Plain-English Glossary

| Term | What It Means in Normal English |
| :--- | :--- |
| **Network Flow** | A single conversation between two computers (e.g., your laptop connecting to a web server over port 443). Contains metrics like packet counts, byte rates, and durations. |
| **Sliding Window ($W=35, S=18$)** | Instead of checking one flow at a time, the AI groups 35 consecutive flows together into a batch, then moves forward 18 flows for the next batch (creating a 48.6% overlap so nothing falls through the cracks). |
| **Vision Transformer (ViT)** | An AI originally designed for computer vision. Instead of scanning with tiny fixed filters, it uses "attention" to see how every part of the image relates to every other part simultaneously. |
| **Self-Attention Heatmap** | A visual map where bright yellow/red areas show the exact packets the AI focused on when making its decision. |
| **Top-$K$ Mean Pooling ($K=3$)** | The AI looks at all 35 flows in a window, identifies the **3 most dangerous-looking moments**, and bases its final score on them. This ensures short, quick attacks don't get hidden by harmless traffic. |
| **BENIGN** | Clean, safe, everyday network traffic (no attack present). |
| **FPSS (Feature-Preserving Synthetic Sampling)** | A technique that creates realistic extra examples of ultra-rare attacks (like Heartbleed) so the AI gets enough practice to recognize them without altering how they behave. |
| **Stratified Focal Loss** | A loss function that tells the AI: *"Don't waste time getting better at spotting easy normal traffic—focus your brainpower on the hard-to-spot, sneaky attacks."* |

---

### 💡 Summary: Why This Interface Is Valuable
Whether you are a **cybersecurity analyst**, a **student or researcher**, or a **stakeholder evaluating IDS solutions**:
- **You can test real traffic in seconds** (no command-line typing needed).
- **You get full explainability** (the heatmaps show you *why* an alarm went off).
- **You can inspect hard research evidence** (all benchmark tables, parameters, and ablation numbers are directly accessible).
- **You have real operational controls** (isolate nodes, export signed incident JSON audits, and measure live hardware throughput).
