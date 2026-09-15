"""
IBM Bob Prompt Templates
------------------------
Constructs grounded prompts for each Bob AI feature using only
the actual structured data from the pipeline — no invented facts.

All functions accept the incident dict produced by correlation.py
plus supporting values from the ML classifier. Every prompt ends with
an explicit instruction for Bob to base its answer only on the
provided data.
"""

from typing import Dict, List, Optional


# ── System persona (shared across all prompts) ────────────────────────────────
SYSTEM_PERSONA = (
    "You are a senior cybersecurity intelligence analyst embedded in a "
    "Security Operations Centre (SOC). You write concise, accurate, "
    "defence-grade intelligence assessments. Base your analysis strictly "
    "on the data provided. Do not invent IP addresses, technique names, "
    "tool names, or statistics not present in the input."
)


# ── Internal helpers ─────────────────────────────────────────────────────────

def _fmt_list(items: List, limit: int = 6) -> str:
    clean = [str(i) for i in items if i and str(i) not in ("", "nan", "None")][:limit]
    return ", ".join(clean) if clean else "N/A"


def _ioc_line(incident: Dict) -> str:
    tags = _fmt_list(incident.get("ioc_tags", []))
    if incident.get("ioc_hits"):
        return f"URLhaus IOC match: YES — tags: {tags}"
    return "URLhaus IOC match: NO"


def _incident_block(incident: Dict, ml_confidence: float) -> str:
    """Compact structured summary of incident facts for prompt context."""
    return f"""
INCIDENT FACTS (structured pipeline output — ground truth only):
  Incident ID   : {incident.get("incident_id", "?")}
  Source IP     : {incident.get("src_ip", "?")}
  Destination IPs: {_fmt_list(incident.get("dst_ips", []))}
  Destination ports: {_fmt_list(incident.get("dst_ports", []))}
  Protocols     : {_fmt_list(incident.get("protocols", []))}
  Event count   : {incident.get("event_count", 0):,}
  Total bytes   : {incident.get("total_bytes", 0):,.0f}
  Start time    : {incident.get("start_time", "?")}
  End time      : {incident.get("end_time", "?")}
  Max severity  : {incident.get("max_severity", 0)} / 5
  Priority score: {incident.get("priority_score", 0):.2f} / 10
  ML threat confidence: {ml_confidence * 100:.0f}%
  MITRE tactics : {_fmt_list(incident.get("tactics", []))}
  MITRE techniques: {_fmt_list(incident.get("techniques", []))}
  Attack categories: {_fmt_list(incident.get("categories", []))}
  {_ioc_line(incident)}
""".strip()


def _technique_details(incident: Dict) -> str:
    tech_details = incident.get("tech_details", [])
    if not tech_details:
        return ""
    lines = ["MITRE TECHNIQUE DETAILS (from STIX 2.1):"]
    for td in tech_details[:3]:
        lines.append(
            f"  {td.get('id', '')} — {td.get('name', '')}: "
            f"{td.get('description', '')[:200]}"
        )
    return "\n".join(lines)


# ── Prompt builders ───────────────────────────────────────────────────────────

def build_threat_explanation_prompt(incident: Dict, ml_confidence: float) -> str:
    """
    Prompt: explain why this incident is a genuine threat.
    Output: 3–5 sentence analyst paragraph, no bullet lists.
    """
    facts = _incident_block(incident, ml_confidence)
    tech = _technique_details(incident)
    return f"""
{facts}

{tech}

TASK: Write a 3–5 sentence threat explanation for this incident.
Explain WHY this activity is malicious (not just WHAT it is), referencing
the specific IP, event count, targeted ports, MITRE tactics/techniques,
and ML confidence score from the data above. Use concise analyst prose.
Do not add any facts, IPs, or statistics not present above.
""".strip()


def build_bluf_prompt(incident: Dict, ml_confidence: float) -> str:
    """
    Prompt: generate a defence-grade BLUF commander brief.
    Output: structured BLUF with BOTTOM LINE, THREAT ACTOR, IMPACT, ACTIONS.
    """
    facts = _incident_block(incident, ml_confidence)
    tech = _technique_details(incident)
    priority = incident.get("priority_score", 0)
    threat_label = (
        "SEVERE" if priority >= 8 else
        "CRITICAL" if priority >= 6 else
        "HIGH" if priority >= 4 else
        "MEDIUM" if priority >= 2 else "LOW"
    )
    return f"""
{facts}

{tech}

TASK: Write a structured BLUF (Bottom Line Up Front) intelligence brief.
Use exactly these four labelled sections:

BOTTOM LINE:
[One sentence: who did what to whom, with what confidence and priority]

THREAT ACTOR & TECHNIQUE:
[2–3 sentences on the adversary TTPs based on MITRE data above]

IMPACT ASSESSMENT:
[2–3 sentences on operational impact using the event count, bytes, targeted ports]

RECOMMENDED ACTIONS:
[3 numbered, specific, time-bound actions a commander can order right now]

Threat level for this incident is {threat_label} (priority {priority:.1f}/10).
Base all content strictly on the incident facts above. Do not invent data.
""".strip()


def build_recommendations_prompt(incident: Dict, ml_confidence: float) -> str:
    """
    Prompt: generate prioritised analyst action plan.
    Output: numbered list of 5 concrete actions, ordered by urgency.
    """
    facts = _incident_block(incident, ml_confidence)
    tech = _technique_details(incident)
    return f"""
{facts}

{tech}

TASK: Generate a prioritised list of exactly 5 analyst/commander actions
for this specific incident. Order them from most urgent (immediate) to
least urgent (within 24–48 h). Each action must:
  - Reference a specific observable from the incident data (e.g., the
    source IP, targeted port, tactic, or technique listed above).
  - Include a concrete time-bound directive (e.g., "within 15 minutes",
    "within 2 hours").
  - Be actionable by a SOC analyst or network engineer.

Format: numbered 1–5. Do not add generic advice not supported by the data.
""".strip()


def build_qa_prompt(
    incident: Dict,
    ml_confidence: float,
    question: str,
) -> str:
    """
    Prompt: answer an analyst's free-text question about the incident.
    Output: direct, concise answer grounded in incident data.
    """
    facts = _incident_block(incident, ml_confidence)
    tech = _technique_details(incident)
    return f"""
{facts}

{tech}

ANALYST QUESTION: {question.strip()}

TASK: Answer the question above using only the incident facts provided.
If the answer cannot be determined from the available data, say so explicitly.
Keep the answer under 150 words. Do not speculate beyond the data.
""".strip()
