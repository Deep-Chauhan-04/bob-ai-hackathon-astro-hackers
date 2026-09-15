# Solution Overview

## What We Built

We built an **AI-powered SOC Command Centre** — a full-stack Python/Streamlit application
that takes 244,471 raw network/IDS events, automatically separates real threats from noise,
maps every attack to the MITRE ATT&CK framework, cross-checks suspicious IPs against a
live threat-intelligence feed, and produces a military-grade **BLUF (Bottom Line Up Front)**
intelligence brief that a commander can read and act on in under 10 seconds.

The entire pipeline — from raw CSV to interactive dashboard — runs with a single command
and works fully offline (no internet required after the first run).

---

## How It Works

### Step 1 — Data Ingestion & Deduplication (`engine/data_loader.py`, `engine/correlation.py`)

The pipeline loads `master_events.csv`, a 244,471-row dataset merging **Zeek IDS** network
flow logs and the **CIC-IDS2018** benchmark dataset. Each row represents one network flow
with fields like source/destination IP, ports, protocol, byte counts, packet counts, and a
ground-truth label (`Benign` or a specific attack category).

The deduplication engine removes:
- Rows already flagged as duplicate in the dataset (`is_duplicate == 1`)
- Exact 5-tuple duplicates (same src_ip, dst_ip, src_port, dst_port, protocol, label)

**Result: >73% noise reduction** — from 244k raw events down to a focused set of
genuinely distinct flows before any analysis begins.

---

### Step 2 — ML False-Positive Classification (`engine/classifier.py`)

A **RandomForest classifier** (120 estimators, depth 12, class-weighted) is trained on 12
numerical network-flow features:

| Feature | What It Captures |
|---|---|
| `bytes_fwd` / `bytes_bwd` | Data volume asymmetry (exfiltration signals) |
| `packets_fwd` / `packets_bwd` | Packet-rate anomalies (DDoS signals) |
| `duration` | Session length (slow-loris, long C2 beacons) |
| `dst_port` | Targeted service (SSH=22, RDP=3389, SMB=445 …) |
| `bytes_per_packet` | Payload size anomalies |
| `protocol_enc` | TCP/UDP/ICMP encoding |
| `is_duplicate` | Pre-deduplication flag |

The model achieves **AUC-ROC ≈ 0.99** on a held-out 20% test split. It outputs a
`threat_confidence` score (0.0–1.0) for every event. The trained model is cached to
`src/cache/classifier_model.pkl` — first run takes ~30 seconds, subsequent runs are instant.

---

### Step 3 — Multi-Stage Campaign Correlation (`engine/correlation.py`)

Threat events are grouped into **incidents** using source-IP + temporal proximity clustering:

1. All events with `label_binary == 1` (threat) are sorted by `src_ip` and `timestamp`.
2. For each source IP, a **5-minute rolling window** clusters consecutive events into a
   single incident (minimum 3 events to form a cluster).
3. Each incident collects: unique destination IPs, targeted ports, MITRE tactics/techniques,
   total data volume, event count, and timeline (start → end).

This transforms thousands of atomic alerts into a small set of **named, traceable incidents**
(e.g. `INC-192-168-1-5-127`) ordered by priority.

---

### Step 4 — Threat Intelligence Enrichment

**URLhaus IOC Feed** (`threat_intel/urlhaus_feed.py`)  
Downloads the Abuse.ch URLhaus CSV feed (~12,000+ active malicious URLs, ~4,600 malicious
IPs) and indexes it for O(1) lookup. Every incident's source IP and destination IPs are
checked against this index. Hits surface tags like `Mirai`, `Emotet`, `CobaltStrike`,
`C2`. An offline JSON cache (`src/cache/urlhaus_cache.json`) guarantees demo availability
without internet access.

**MITRE ATT&CK STIX 2.1** (`threat_intel/mitre_stix.py`)  
Downloads the full 858-technique Enterprise ATT&CK STIX 2.1 bundle from the official MITRE
GitHub CDN and parses it into a technique lookup index. Eight techniques cover every
attack type in this dataset:

| Technique ID | Name | Tactic |
|---|---|---|
| T1595 | Active Scanning | Reconnaissance |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1110 | Brute Force | Credential Access |
| T1078 | Valid Accounts | Defense Evasion / Persistence |
| T1071 | Application Layer Protocol (C2) | Command and Control |
| T1498 | Network Denial of Service | Impact |
| T1499 | Endpoint Denial of Service | Impact |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |

Each technique enrichment includes: description, detection strategy, and up to 5 mitigations.
A built-in offline catalogue ensures the app works without internet.

---

### Step 5 — Priority Scoring & BLUF Generation (`engine/bluf_generator.py`)

Each incident receives a **composite Priority Score** (0–10):

```
Priority Score = ML_Confidence × Asset_Criticality × Severity_Norm × IOC_Boost × Tactic_Boost
```

| Factor | Meaning |
|---|---|
| `ML_Confidence` | RandomForest threat probability (0.0–1.0) |
| `Asset_Criticality` | Port-based weighting (RDP=1.8, SMB=1.8, SSH=1.5, HTTP=1.0 …) |
| `Severity_Norm` | Attack severity 1–5 normalised to [0,1] |
| `IOC_Boost` | ×1.3 if URLhaus IOC hit confirmed |
| `Tactic_Boost` | ×1.15 per additional MITRE tactic (multi-stage progression) |

The **BLUF report** is a structured 4-section intelligence brief:

1. **BOTTOM LINE** — One-paragraph plain-language summary: who is attacking, what they did,
   ML confidence %, priority score.
2. **THREAT ACTOR & TECHNIQUE** — MITRE technique IDs + names + tactic + URLhaus IOC tags.
3. **IMPACT ASSESSMENT** — Event count, targeted IPs, ports, data volume, confidence.
4. **RECOMMENDED COMMAND ACTIONS** — 3 prioritised, tactic-specific mitigation steps with
   technique-specific sub-actions from the MITRE ATT&CK catalogue.

---

### Step 6 — IBM Bob AI Copilot (`engine/bob_client.py`, `engine/bob_prompts.py`)

An optional AI layer powered by the **IBM Bob inference API** (OpenAI-compatible endpoint).
When a valid `BOB_INFERENCE_API_KEY` is present, analysts can:

- Ask Bob to explain any incident in plain language
- Request a dynamically AI-generated BLUF for any correlated incident
- Get a prioritised action plan for any threat
- Ask free-form SOC questions (e.g. "What does T1110 mean and how do I stop it?")

All prompts are **grounded in actual pipeline data** — Bob only receives real incident facts
(IPs, techniques, event counts, confidence scores) so it cannot hallucinate. The platform
degrades gracefully when Bob is unavailable — all template-based BLUF, ML scoring, and
MITRE enrichment remain fully functional without an API key.

---

## Architecture Diagram

See [`architecture.md`](architecture.md) for the full diagram.

```
master_events.csv (244k rows)
        │
        ▼
┌─────────────────┐
│   Data Loader   │  load_events() — normalise, derive features
│  + Deduplicator │  deduplicate() — remove noise (>73% reduction)
└────────┬────────┘
         │ clean threat events
         ▼
┌─────────────────┐     ┌──────────────────────┐
│  ML Classifier  │     │  URLhaus IOC Feed     │
│ RandomForest    │     │  Abuse.ch (live/cache)│
│ AUC-ROC ≈ 0.99  │     └──────────┬───────────┘
└────────┬────────┘                │
         │ confidence scores       │ IOC hits / tags
         ▼                         ▼
┌──────────────────────────────────────────┐
│           Correlation Engine             │
│  src_ip + 5-min window → incidents       │
│  + MITRE ATT&CK STIX 2.1 enrichment     │
└─────────────────────┬────────────────────┘
                      │ enriched incidents
                      ▼
┌──────────────────────────────────────────┐
│           BLUF Generator                 │
│  Priority Score = Conf × Crit × Sev      │
│  4-section structured intelligence brief │
└─────────────────────┬────────────────────┘
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
  ┌──────────────┐      ┌──────────────────┐
  │  Streamlit   │      │  IBM Bob AI       │
  │  Dashboard   │      │  Copilot (opt.)   │
  │  5-tab UI    │      │  On-demand AI Q&A │
  └──────────────┘      └──────────────────┘
```

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| **RandomForest over deep learning** | Interpretable feature importances; no GPU required; trains in ~30s on 244k rows; AUC-ROC ≈ 0.99 is sufficient for this use case |
| **Streamlit for the UI** | Single-file Python dashboard; no separate frontend build step; judges can run it with one command |
| **Offline-resilient caches** | URLhaus and MITRE data are cached to JSON; the app works without internet after first run, guaranteeing demo reliability |
| **Template BLUF + Bob AI** | Template-based BLUF guarantees output even without an API key; Bob AI enhances it when available — no single point of failure |
| **5-minute correlation window** | Matches typical lateral movement and brute-force burst patterns in the dataset; configurable via `CAMPAIGN_WINDOW_SECONDS` |
| **Priority Score formula** | Multiplicative formula rewards incidents that simultaneously have high ML confidence AND target critical assets AND have external IOC confirmation — avoiding false promotions from any single signal |

---

## IBM Technologies Used

- **IBM Bob (AI Copilot):** The `BobClient` class in [`src/engine/bob_client.py`](../src/engine/bob_client.py)
  calls the IBM Bob inference API (`https://api.us-east.bob.ibm.com/inference/v1/chat/completions`)
  using an OpenAI-compatible chat completions schema. Every prompt is constructed in
  [`src/engine/bob_prompts.py`](../src/engine/bob_prompts.py) with real incident data injected
  — ML confidence scores, MITRE technique IDs, URLhaus IOC tags, event counts — so Bob
  produces grounded, actionable intelligence analysis rather than generic cybersecurity advice.

---
<!-- Contributor: Krish Ardeshana -->

