# Setup Guide

> **This file is read by the automated evaluation pipeline. Be precise and complete.**

---

## Prerequisites

Before you begin, ensure you have the following installed:

- [ ] **Python 3.10 or higher** — check with `python --version`
- [ ] **pip** — check with `pip --version`
- [ ] **Git** — check with `git --version`
- [ ] *(Optional)* An IBM Bob account with an **Inference-scoped API key**  
  Generate at: `bob.ibm.com → Account → API Keys → New Key → Scope: Inference`  
  The platform works fully without this key — only the AI Copilot tab requires it.

No Docker, no database, no Node.js — this is a pure Python application.

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/Deep-Chauhan-04/bob-ai-hackathon-astro-hackers.git
cd bob-ai-hackathon-astro-hackers
```

---

## Step 2 — Create a Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv .venv

# Activate it
# On Windows:
.venv\Scripts\activate
# On macOS / Linux:
source .venv/bin/activate
```

---

## Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:

| Package | Version | Purpose |
|---|---|---|
| `streamlit` | ≥1.32.0 | Interactive dashboard UI |
| `pandas` | ≥2.0.0 | Data ingestion and manipulation |
| `numpy` | ≥1.24.0 | Numerical feature engineering |
| `scikit-learn` | ≥1.3.0 | RandomForest ML classifier |
| `plotly` | ≥5.18.0 | Interactive charts and heatmaps |
| `requests` | ≥2.31.0 | URLhaus + MITRE STIX downloads |

---

## Step 4 — Configure Environment Variables

Create a `.env` file inside `src/`:

```bash
# On Windows PowerShell:
New-Item -Path src\.env -ItemType File

# On macOS / Linux:
touch src/.env
```

Open `src/.env` in any text editor and add:

```env
# Required for IBM Bob AI Copilot tab (optional — rest of the app works without it)
BOB_INFERENCE_API_KEY=your_inference_scoped_key_here

# Optional overrides (leave blank to use defaults)
BOB_INFERENCE_URL=https://api.us-east.bob.ibm.com/inference/v1
BOB_MODEL=fast
```

| Variable | Description | Required |
|---|---|---|
| `BOB_INFERENCE_API_KEY` | Inference-scoped IBM Bob API key | No (AI Copilot tab only) |
| `BOB_INFERENCE_URL` | Override Bob API base URL | No |
| `BOB_MODEL` | Override model name (`fast` or `best`) | No |

> **Note:** If you skip this step, the app will still run fully. Only **Tab 5 (IBM Bob AI
> Copilot)** will show a "key not configured" message. All other features — ML scoring,
> BLUF reports, MITRE enrichment, IOC correlation — work completely offline without a key.

---

## Step 5 — Run the Application

```bash
streamlit run src/app.py
```

The app opens automatically in your browser at `http://localhost:8501`.

### What Happens on First Run

The first launch performs four automatic setup steps (~30–60 seconds total):

| Step | What Runs | Time |
|---|---|---|
| 1 | Load and deduplicate `master_events.csv` (244k rows) | ~5s |
| 2 | Download Abuse.ch URLhaus IOC feed (falls back to offline cache if no internet) | ~3s |
| 3 | Download MITRE ATT&CK STIX 2.1 bundle (falls back to built-in catalogue if no internet) | ~5s |
| 4 | Train and cache the RandomForest classifier on first run | ~30s |

**Subsequent runs are instant** — all four items are cached to `src/cache/` and reloaded
from disk without re-downloading or re-training.

---

## Step 6 — Navigate the Dashboard

The dashboard has 5 tabs:

| Tab | Name | What You See |
|---|---|---|
| 1 | **Command Centre** | KPI cards (total events, threats, noise reduction %) + executive summary + top incidents list |
| 2 | **Alert Explorer** | Full searchable/filterable event table + hourly timeline chart + source IP threat ranking |
| 3 | **MITRE ATT&CK** | Tactic × technique heatmap + technique detail cards with detections and mitigations |
| 4 | **IOC Correlation** | URLhaus feed statistics + live IP lookup tool + malicious IP feed explorer |
| 5 | **IBM Bob AI Copilot** | Select any incident → Ask Bob to explain it, generate a BLUF, or produce an action plan. Also supports free-form SOC Q&A. |

---

## Running the ML Validation Script (Optional)

A standalone validation script is included to demonstrate model performance metrics:

```bash
python validate_ml.py
```

This prints the classification report (precision, recall, F1) and AUC-ROC score to stdout.

---

## Quick Demo Checklist

After the app loads, you can demonstrate the full pipeline in under 2 minutes:

1. **Tab 1 → Command Centre:** Show the KPI cards — 244k events ingested, >73% noise
   reduction, number of correlated incidents, top 3 incidents by priority.
2. **Tab 3 → MITRE ATT&CK:** Show the tactic heatmap and click a technique to reveal
   its description, detection strategy, and mitigations.
3. **Tab 4 → IOC Correlation:** Show URLhaus feed stats. Enter `198.50.128.218` in the
   IP lookup — it will return a Mozi botnet hit from the offline cache.
4. **Tab 1 → Click any incident → View BLUF Report:** Show the 4-section structured
   brief with priority score, technique IDs, and recommended actions.
5. **Tab 5 → Bob AI Copilot** *(requires API key)*: Select an incident and click
   "Explain this incident" — Bob responds with a grounded analysis in plain English.

---

## Troubleshooting

| Issue | Solution |
|---|---|
| `ModuleNotFoundError: No module named 'streamlit'` | Run `pip install -r requirements.txt` (ensure your virtual environment is active) |
| `FileNotFoundError: master_events.csv` | Ensure you are running `streamlit run src/app.py` from the **repository root**, not from inside `src/` |
| App is slow / spinning on first load | Normal — the RandomForest is training (~30s). Wait for the spinner to complete. All subsequent runs are instant. |
| Bob AI Copilot shows "API key not configured" | Add `BOB_INFERENCE_API_KEY=your_key` to `src/.env` and restart the app |
| Bob AI Copilot shows "Network/firewall blocked" | Your network is blocking the Bob gateway. Try a VPN or mobile hotspot, then restart. All other tabs work without Bob. |
| URLhaus shows 0 IOC records | No internet + no existing cache. The offline seed (5 demo records) will be used automatically. |
| MITRE ATT&CK shows 8 techniques (not 858) | No internet + no existing cache. The built-in catalogue covers all 8 techniques observed in the dataset. |
| `sklearn` version mismatch when loading `classifier_model.pkl` | Delete `src/cache/classifier_model.pkl` and restart — the model will retrain in ~30s |
