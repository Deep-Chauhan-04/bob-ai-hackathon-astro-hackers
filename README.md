# 🛡️ Threat Intelligence Correlation & Alert Prioritisation Assistant

---

## 👥 Team

| Field | Value |
|---|---|
| **Team Name** | Astro Hackers |
| **Track** | AI |
| **Team Lead** | Kunj Desai — 24cs015@charusat.edu.in |
| **Members** | Krish Ardeshana, Deep Chauhan, Nisarg Dedakiya |

---

## 🎯 Problem Statement

> Security Operations Centres are overwhelmed by hundreds of thousands of raw SIEM alerts daily, making it nearly impossible to separate genuine threats from noise. Decision-makers lack concise, prioritised briefings to act decisively.

Security Operations Centre (SOC) analysts and commanders face an impossible signal-to-noise problem — a single day of network telemetry from even a mid-sized organisation produces hundreds of thousands of raw IDS/SIEM alerts. Without automated correlation, enrichment, and prioritisation, genuine multi-stage attack campaigns are buried under benign traffic and duplicate events. Commanders have no fast path from raw data to an actionable, evidence-based decision.

---

## 💡 Solution

> An end-to-end AI-powered SOC platform that ingests 244k+ Zeek and CIC-IDS2018 network events, correlates them into multi-stage attack campaigns, and delivers structured BLUF executive briefs backed by MITRE ATT&CK and live IOC intelligence.

We built a full-stack Defence Intelligence Assistant using Python + Streamlit that: (1) ingests and deduplicates 244,471 real network/IDS events achieving >73% noise reduction; (2) cross-correlates every threat indicator against the live Abuse.ch URLhaus IOC feed and the MITRE ATT&CK STIX 2.1 framework; (3) applies a RandomForest ML classifier (AUC-ROC ≈ 0.99) to score each event's threat confidence; and (4) automatically generates structured **BLUF (Bottom Line Up Front)** commander intelligence briefs with a composite Priority Score = Threat Confidence × Asset Criticality × Attack Severity. An IBM Bob AI Copilot tab provides on-demand threat explanations, dynamic BLUF generation, prioritised action plans, and free-form SOC Q&A — all grounded strictly in pipeline data.

---

## ✨ Key Features

- **Multi-Source SIEM Ingestion & Deduplication:** Ingests 244k+ Zeek and CIC-IDS2018 events across two datasets, removing duplicate flows and benign noise to achieve >73% alert reduction before any analysis begins.
- **Live Abuse.ch URLhaus IOC Cross-Correlation:** Downloads the URLhaus active threat feed (~12k+ IOC records, 4,600+ malicious IPs) with offline JSON cache fallback — guaranteed to work without internet connectivity during demos.
- **MITRE ATT&CK STIX 2.1 Technique Enrichment:** Parses the full 858-technique Enterprise ATT&CK bundle, mapping every observed alert to T1110, T1190, T1498, T1499, T1071, T1595, T1078, or T1048 with detection strategies and mitigations.
- **RandomForest ML False-Positive Filter:** Trained on the full dataset, outputs per-event threat confidence scores (0–1) with feature importance explanations; cached to disk for instant reload.
- **Automated Defence-Grade BLUF Reports:** Generates structured 4-section intelligence briefs (Bottom Line / Threat Actor & Technique / Impact Assessment / Command Actions) with one-click plain-text export, backed by the formula Priority Score = Confidence × Asset Criticality × Severity.
- **IBM Bob AI Copilot:** On-demand AI threat explanations, dynamic BLUF generation, prioritised action plans, incident Q&A, and general SOC Q&A — all grounded in actual pipeline data, no hallucinated facts.

---

## 🛠️ Tech Stack

| Category | Technologies |
|---|---|
| **Languages** | Python 3.10+ |
| **Frameworks** | Streamlit, scikit-learn, Plotly, pandas, NumPy |
| **IBM Technologies** | IBM Bob (AI Copilot — inference API) |
| **Databases** | Local JSON cache (URLhaus feed, MITRE STIX, ML model) |
| **Other** | Abuse.ch URLhaus API, MITRE ATT&CK STIX 2.1, RandomForest Classifier, Zeek IDS, CIC-IDS2018 Dataset |

---

## 📁 Repository Structure

```
├── src/                        # All source code
│   ├── app.py                  # Streamlit Command Centre (5-tab dashboard)
│   ├── engine/
│   │   ├── data_loader.py      # CSV ingestion, normalisation, stratified sampling
│   │   ├── correlation.py      # Alert deduplication & campaign clustering engine
│   │   ├── classifier.py       # RandomForest ML threat classifier
│   │   ├── bluf_generator.py   # Priority scoring & BLUF report generator
│   │   ├── bob_client.py       # IBM Bob inference API client
│   │   └── bob_prompts.py      # Grounded prompt templates for Bob AI
│   ├── threat_intel/
│   │   ├── urlhaus_feed.py     # Abuse.ch URLhaus IOC feed downloader & index
│   │   └── mitre_stix.py       # MITRE ATT&CK STIX 2.1 parser & lookup
│   └── cache/                  # Auto-generated: URLhaus JSON, STIX bundle, model pkl
├── docs/                       # Written documentation
│   ├── setup-guide.md
│   └── architecture.md
├── demo/                       # Demo artifacts
│   ├── screenshots/            # App screenshots
│   └── demo-video-link.txt     # Link to demo video
├── presentation/               # Slide deck
├── master_events.csv           # 244k+ Zeek + CIC-IDS2018 SIEM events
├── requirements.txt            # Python dependencies
└── submission.yaml             # Structured submission metadata
```

---

## ⚡ How to Run

```bash
# 1. Clone the repo
git clone https://github.com/Deep-Chauhan-04/bob-ai-hackathon-astro-hackers
cd bob-ai-hackathon-astro-hackers

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
# Edit src/.env — set BOB_INFERENCE_API_KEY to your Inference-scoped key
# (Generate at: bob.ibm.com > Account > API Keys > New Key > Scope: Inference)

# 4. Run the dashboard
streamlit run src/app.py
```

The app will automatically:
- Load and deduplicate `master_events.csv` (244k+ events)
- Download the Abuse.ch URLhaus IOC feed (falls back to offline cache if no internet)
- Download the MITRE ATT&CK STIX 2.1 bundle (falls back to built-in catalogue)
- Train and cache the RandomForest classifier on first run (~30s), then reload instantly

> **Bob AI Copilot:** Requires a valid `BOB_INFERENCE_API_KEY` in `src/.env`. The rest of the platform (BLUF reports, ML, IOC correlation, MITRE mapping) works fully offline without a key.

---

## 🖥️ Demo

| Artifact | Link |
|---|---|
| 📹 Demo Video | [See demo/demo-video-link.txt](demo/demo-video-link.txt) |
| 🌐 Live Demo | [See demo/live-demo-url.txt](demo/live-demo-url.txt) |
| 🖼️ Screenshots | [See demo/screenshots/](demo/screenshots/) |
| 📊 Presentation | [See presentation/](presentation/) |

---

## ⚠️ Known Limitations

- **URLhaus IP cross-correlation:** URLhaus primarily tracks malware-hosting URLs rather than DDoS/brute-force source IPs, so direct IOC hits against the Zeek/CIC dataset IPs are limited. The lookup and feed explorer still demonstrate live threat intelligence integration.
- **Incident clustering window:** The temporal correlation engine uses a fixed 5-minute window per source IP. Small dataset samples (<20k events after deduplication) may produce few or no correlated incidents — use 50k+ for best results.
- **ML generalisation:** The RandomForest classifier is trained on the same dataset distribution. It should be re-validated against out-of-distribution production traffic before operational deployment.
- **Bob AI connectivity:** The IBM Bob inference endpoint may be blocked on corporate/campus networks. The platform degrades gracefully — all template-based BLUF, ML scoring, and MITRE enrichment remain fully functional without Bob.

---

## 🏅 What We're Most Proud Of

The automated **BLUF (Bottom Line Up Front) generator** is the centrepiece of our submission. It takes the output of four independent intelligence pipelines — ML threat confidence, MITRE ATT&CK STIX enrichment, Abuse.ch URLhaus IOC cross-correlation, and multi-stage temporal campaign clustering — and synthesises them into a single, military-grade structured intelligence brief in under one second.

A commander can read the bottom line in under 10 seconds and immediately issue containment orders with cited, traceable evidence — IP addresses, MITRE technique IDs, IOC tags, confidence percentages, and prioritised actions. This closes the gap between 244,000 raw telemetry rows and a decisive command action, which is the exact problem the system was built to solve.

---
