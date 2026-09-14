"""
BLUF Generator — Bottom Line Up Front Incident Reports
-------------------------------------------------------
Calculates composite priority scores and generates structured,
defence-grade BLUF intelligence reports for each correlated incident.

Priority Score = Threat_Confidence × Asset_Criticality × Attack_Severity
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Asset criticality by destination port (higher = more critical)
PORT_CRITICALITY: Dict[int, float] = {
    22: 1.5,    # SSH
    23: 1.5,    # Telnet
    25: 1.3,    # SMTP
    80: 1.0,    # HTTP
    443: 1.2,   # HTTPS
    445: 1.8,   # SMB
    3306: 1.6,  # MySQL
    3389: 1.8,  # RDP
    5432: 1.6,  # PostgreSQL
    8080: 1.0,  # Alt HTTP
    53: 1.1,    # DNS
    21: 1.4,    # FTP
    1433: 1.6,  # MSSQL
}

SEVERITY_LABEL = {0: "BENIGN", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL", 5: "SEVERE"}
THREAT_LEVEL_BADGE = {
    "BENIGN": "⬜ BENIGN",
    "LOW": "🟢 LOW",
    "MEDIUM": "🟡 MEDIUM",
    "HIGH": "🟠 HIGH",
    "CRITICAL": "🔴 CRITICAL",
    "SEVERE": "🔴🔴 SEVERE",
}

TACTIC_NARRATIVE = {
    "Reconnaissance": "conducted network reconnaissance scans against the target network",
    "Credential Access": "executed credential brute-force attacks targeting authentication services",
    "Initial Access": "exploited public-facing applications to gain unauthorised initial access",
    "Command and Control": "established command-and-control (C2) communications via bot implants",
    "Impact": "launched volumetric Denial-of-Service attacks targeting network availability",
    "Defense Evasion": "attempted defence evasion using compromised valid accounts",
    "Persistence": "established persistence mechanisms via valid account abuse",
    "Privilege Escalation": "escalated privileges using compromised account credentials",
    "Exfiltration": "exfiltrated data over alternative network protocols",
}

MITIGATION_PRIORITY_MAP = {
    "Reconnaissance": [
        "Block inbound port-scan traffic at perimeter firewall (immediate)",
        "Deploy honeypot sensors to detect and track scanning activity",
        "Review and tighten egress ACLs for probe-response traffic",
    ],
    "Credential Access": [
        "Enforce account lockout after 5 failed attempts (immediate)",
        "Mandate MFA on all external-facing authentication endpoints",
        "Reset credentials for all affected accounts within 2 hours",
    ],
    "Initial Access": [
        "Apply vendor security patches for exploited vulnerabilities (P1)",
        "Isolate affected systems and deploy WAF rules immediately",
        "Initiate forensic investigation for initial-access indicators",
    ],
    "Command and Control": [
        "Block C2 IP addresses and domains at DNS and firewall (immediate)",
        "Isolate and re-image confirmed bot-infected endpoints",
        "Sweep network for additional beaconing hosts via EDR/IDS",
    ],
    "Impact": [
        "Engage upstream ISP / DDoS scrubbing service immediately",
        "Activate rate-limiting ACLs on affected network segments",
        "Redirect traffic through DDoS mitigation infrastructure",
    ],
    "Defense Evasion": [
        "Revoke and rotate all compromised credentials immediately",
        "Audit privileged account usage for the past 72 hours",
        "Enable enhanced logging on affected systems",
    ],
    "Persistence": [
        "Audit startup scripts, scheduled tasks, and registry keys",
        "Revoke compromised credentials and force password reset",
        "Search for lateral movement indicators from persistence source",
    ],
    "Privilege Escalation": [
        "Revoke escalated account privileges immediately",
        "Audit sudo/admin access grants in the past 72 hours",
        "Deploy endpoint detection for privilege abuse patterns",
    ],
    "Exfiltration": [
        "Block outbound traffic on exfiltration ports immediately",
        "Enable DLP scanning on sensitive data repositories",
        "Notify data governance team of potential breach",
    ],
}

DEFAULT_MITIGATIONS = [
    "Isolate affected network segments and notify SOC leadership",
    "Preserve all forensic evidence and initiate incident response",
    "Review firewall rules and update threat intelligence feeds",
]


def compute_priority(
    incident: Dict,
    ml_confidence: float = 0.5,
) -> float:
    """
    Priority Score = Threat_Confidence × Asset_Criticality × Attack_Severity

    Parameters
    ----------
    incident : correlated incident dict from correlation.py
    ml_confidence : classifier threat confidence (0.0–1.0)

    Returns
    -------
    Normalised priority score in range 0.0–10.0
    """
    severity = incident.get("max_severity", 1)
    severity_norm = severity / 5.0  # normalise to [0,1]

    # Asset criticality: max over targeted ports
    ports = incident.get("dst_ports", [])
    crit = max((PORT_CRITICALITY.get(int(p), 0.8) for p in ports if p), default=0.8)

    # IOC boost
    ioc_boost = 1.3 if incident.get("ioc_hits") else 1.0

    # Multi-tactic progression boost
    tactic_count = len([t for t in incident.get("tactics", []) if t and t != "Benign"])
    tactic_boost = 1.0 + min(tactic_count - 1, 2) * 0.15

    raw = ml_confidence * severity_norm * crit * ioc_boost * tactic_boost * 10
    return round(min(raw, 10.0), 2)


def generate_bluf(
    incident: Dict,
    ml_confidence: float = 0.5,
    analyst_name: str = "SOC Analyst",
) -> Dict:
    """
    Generate a structured BLUF report for a single incident.

    Returns
    -------
    Dict with keys: bluf_text, threat_level, priority_score, sections,
                    generated_at, incident_id
    """
    priority = compute_priority(incident, ml_confidence)
    severity_val = incident.get("max_severity", 1)
    threat_level = SEVERITY_LABEL.get(severity_val, "MEDIUM")

    src_ip = incident.get("src_ip", "UNKNOWN")
    tactics = [t for t in incident.get("tactics", []) if t and t != "Benign"]
    techniques = incident.get("techniques", [])
    categories = incident.get("categories", [])
    ioc_tags = incident.get("ioc_tags", [])
    tech_details = incident.get("tech_details", [])
    event_count = incident.get("event_count", 0)
    total_bytes = incident.get("total_bytes", 0)
    dst_ips = incident.get("dst_ips", [])
    dst_ports = incident.get("dst_ports", [])

    # Primary tactic for narrative selection
    primary_tactic = tactics[0] if tactics else "Unknown"
    narrative = TACTIC_NARRATIVE.get(primary_tactic, "conducted multi-vector network attacks")

    # ── BOTTOM LINE ──────────────────────────────────────────────────────
    ioc_note = (
        f" Source IP confirmed in Abuse.ch URLhaus threat database "
        f"(tags: {', '.join(ioc_tags[:3])})."
        if ioc_tags else ""
    )
    confidence_pct = round(ml_confidence * 100, 0)
    bottom_line = (
        f"Threat actor originating from {src_ip} has {narrative} "
        f"({event_count:,} correlated events across {len(set(dst_ips))} targets).{ioc_note} "
        f"ML threat confidence: {confidence_pct:.0f}%. Priority: {priority:.1f}/10."
    )

    # ── THREAT ACTOR & TECHNIQUE ─────────────────────────────────────────
    tech_lines = []
    if tech_details:
        for td in tech_details[:3]:
            tech_lines.append(
                f"• **{td['id']} — {td['name']}** ({td['tactic']}): {td['description'][:200]}…"
            )
    elif techniques:
        tech_lines = [f"• Technique: {t}" for t in techniques[:5]]
    if ioc_tags:
        tech_lines.append(f"• URLhaus IOC Tags: {', '.join(ioc_tags)}")
    if categories:
        tech_lines.append(f"• Attack Categories: {', '.join(categories[:5])}")

    # ── IMPACT ASSESSMENT ────────────────────────────────────────────────
    bytes_str = f"{total_bytes / 1_000_000:.2f} MB" if total_bytes >= 1_000_000 else f"{total_bytes:,.0f} B"
    targeted_assets = ", ".join(str(p) for p in dst_ports[:8]) if dst_ports else "Various"
    impact_lines = [
        f"• **{event_count:,} alerts** correlated into this incident.",
        f"• Targeted {len(set(dst_ips))} distinct destination IPs across ports: {targeted_assets}.",
        f"• Estimated data volume: **{bytes_str}** transferred.",
        f"• Threat confidence: **{confidence_pct:.0f}%** (ML classifier + heuristic correlation).",
    ]
    if ioc_tags:
        impact_lines.append(f"• Known malware families: {', '.join(ioc_tags)}.")

    # ── RECOMMENDED COMMAND ACTIONS ───────────────────────────────────────
    mitigations = MITIGATION_PRIORITY_MAP.get(primary_tactic, DEFAULT_MITIGATIONS)
    action_lines = [f"{i+1}. {m}" for i, m in enumerate(mitigations[:3])]

    # Add technique-specific mitigations
    if tech_details:
        for td in tech_details[:2]:
            for m in td.get("mitigations", [])[:1]:
                line = f"   ↳ {m}"
                if line not in action_lines:
                    action_lines.append(line)

    sections = {
        "BOTTOM LINE": bottom_line,
        "THREAT ACTOR & TECHNIQUE": "\n".join(tech_lines) if tech_lines else "Intelligence pending enrichment.",
        "IMPACT ASSESSMENT": "\n".join(impact_lines),
        "RECOMMENDED COMMAND ACTIONS": "\n".join(action_lines),
    }

    # Compose plain-text BLUF
    bluf_text = _render_bluf(incident["incident_id"], threat_level, priority, sections)

    return {
        "incident_id": incident["incident_id"],
        "bluf_text": bluf_text,
        "threat_level": threat_level,
        "threat_badge": THREAT_LEVEL_BADGE.get(threat_level, threat_level),
        "priority_score": priority,
        "ml_confidence": ml_confidence,
        "sections": sections,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "analyst": analyst_name,
    }


def _render_bluf(incident_id: str, threat_level: str, priority: float, sections: Dict) -> str:
    divider = "=" * 72
    sep = "-" * 72
    lines = [
        divider,
        f"  INTELLIGENCE BRIEF — {incident_id}",
        f"  THREAT LEVEL: {threat_level}  |  PRIORITY: {priority:.1f}/10",
        divider,
        "",
    ]
    for title, body in sections.items():
        lines += [f"▶ {title}", sep, body, ""]
    lines.append(divider)
    return "\n".join(lines)


def generate_executive_summary(incidents: List[Dict], stats: Dict) -> str:
    """
    Generate a short command-level executive paragraph summarising
    all active incidents and the overall network threat posture.
    """
    total = stats.get("total_events", 0)
    threats = stats.get("total_threats", 0)
    fp_pct = stats.get("fp_reduction_pct", 0)
    high_sev = stats.get("high_severity", 0)
    top_tactics = stats.get("top_tactics", {})
    incident_count = len(incidents)
    critical = sum(1 for i in incidents if i.get("priority_score", 0) >= 7)

    top_tactic_str = (
        ", ".join(list(top_tactics.keys())[:3]) if top_tactics else "various tactics"
    )

    return (
        f"**NETWORK THREAT POSTURE — EXECUTIVE SUMMARY**\n\n"
        f"Analysis of **{total:,} ingested events** across {len(stats.get('datasets', {}))} data "
        f"sources identified **{threats:,} threat events** ({100*threats/max(total,1):.1f}% threat "
        f"ratio) after **{fp_pct:.1f}% false-positive / noise reduction**. "
        f"Correlation produced **{incident_count} active incidents**, of which "
        f"**{critical} are CRITICAL/SEVERE priority** (score ≥7.0/10). "
        f"Dominant adversary tactics observed: {top_tactic_str}. "
        f"**{high_sev:,} high-severity events** require immediate SOC attention. "
        f"Immediate command action is recommended to contain high-priority incidents."
    )
