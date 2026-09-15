# Problem Statement

## Background

Modern organisations run Security Operations Centres (SOCs) to monitor their networks 24/7.
These SOCs rely on Security Information and Event Management (SIEM) platforms and Intrusion
Detection Systems (IDS) such as **Zeek** to collect raw network telemetry — every connection,
packet burst, and anomaly detected on the wire.

A mid-sized enterprise can produce **hundreds of thousands of individual SIEM alerts every
single day**. The CIC-IDS2018 benchmark dataset used in this project contains 244,471 real
labelled network events drawn from two sources (Zeek and CIC-IDS2018), and it represents
just a fraction of what a production environment generates.

-----

## The Problem

SOC analysts and commanders face three compounding challenges:

1. **Alert overload.** The sheer volume of raw events makes manual review impossible.
   In our dataset alone, more than **73% of alerts are benign noise or duplicates** — yet
   every alert looks the same in a flat log feed. Genuine multi-stage attack campaigns
   (reconnaissance → credential access → lateral movement → exfiltration) are buried inside
   this noise.

2. **Disconnected intelligence.** Even when a threat is spotted, analysts must manually
   cross-reference it against external threat databases (e.g. Abuse.ch URLhaus for malicious
   IPs) and the MITRE ATT&CK framework to understand what the attacker is doing and why.
   This cross-referencing is slow, error-prone, and rarely happens under time pressure.

3. **No commander-ready briefing.** Decision-makers — SOC managers, incident commanders —
   cannot read thousands of log lines. They need a **concise, prioritised, evidence-backed
   summary** (a "Bottom Line Up Front") that tells them what is happening, how serious it is,
   and exactly what to do about it — in under 10 seconds.

---

## Who Is Affected

- **SOC Tier-1 Analysts** who must triage hundreds of alerts per shift and escalate only
  the real threats — currently spending the majority of their time on false positives.
- **SOC Commanders / Incident Managers** who need to issue containment orders quickly
  but have no fast path from raw telemetry to an actionable decision.
- **Security Engineers** who maintain IDS/SIEM pipelines and need visibility into which
  attack techniques are active and how the threat landscape is evolving.

---

## Why It Matters

| Cost | Impact |
|---|---|
| Alert fatigue | Analysts miss real incidents because genuine threats look identical to noise |
| Mean Time to Detect (MTTD) | Slow manual triage increases the window for attackers to operate |
| Mean Time to Respond (MTTR) | Without a prioritised brief, commanders delay containment decisions |
| Unmapped adversary tactics | Without MITRE ATT&CK context, defenders cannot predict the next attack stage |
| Compliance risk | Undetected data exfiltration events expose organisations to regulatory penalties |

A single undetected lateral movement campaign in a real network can escalate into a full
data breach within hours. The 5-minute window between reconnaissance and credential access
in this dataset illustrates exactly how fast adversaries move.

---

## Why Existing Solutions Fall Short

- **Raw SIEM dashboards** display every alert at equal priority — analysts must manually
  sort, filter, and correlate events across multiple tools and time ranges.
- **Static threat-feed lookups** require analysts to copy-paste IPs into web portals one
  at a time; there is no automated cross-correlation at scale.
- **Manual MITRE ATT&CK mapping** is done retrospectively after incidents are confirmed,
  not in real-time as new events arrive.
- **No ML false-positive filter** means that even after manual triage, many escalations
  turn out to be benign — wasting senior analyst time.
- **No structured BLUF output** means that every incident report is written from scratch,
  with inconsistent quality and no guaranteed coverage of the key decision-making fields.
