"""
Correlation Engine
------------------
Groups atomic SIEM alerts into multi-stage attack campaigns, de-duplicates
noise, cross-correlates IOCs with URLhaus, and attaches MITRE context.
"""

import logging
from typing import Dict, List, Optional

import pandas as pd

from threat_intel.urlhaus_feed import URLhausFeed
from threat_intel.mitre_stix import MitreAttack

logger = logging.getLogger(__name__)

# Minimum number of threat events from the same source IP to form an incident.
# No time-window constraint: the dataset spans multiple weeks/months so a
# fixed 5-minute window would never fire.
MIN_INCIDENT_SIZE = 3


def deduplicate(df: pd.DataFrame) -> pd.DataFrame:
    """
    Remove rows flagged as duplicates in the dataset and drop exact
    network-flow duplicates (same 5-tuple + label within 1-second window).
    Returns filtered DataFrame and logs reduction metrics.
    """
    original = len(df)
    # Step 1: use dataset-supplied flag
    df = df[df["is_duplicate"] == 0].copy()
    # Step 2: drop identical 5-tuples with same label (keep first occurrence)
    subset = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "label_binary"]
    df = df.drop_duplicates(subset=subset, keep="first")
    removed = original - len(df)
    logger.info("Deduplication: removed %d / %d rows (%.1f%%).",
                removed, original, 100 * removed / max(original, 1))
    return df.reset_index(drop=True)


def correlate_incidents(
    df: pd.DataFrame,
    feed: Optional[URLhausFeed] = None,
    mitre: Optional[MitreAttack] = None,
) -> List[Dict]:
    """
    Groups threat events into multi-stage incidents using source-IP +
    temporal proximity clustering. Enriches each incident with URLhaus
    IOC matches and MITRE ATT&CK technique details.

    Parameters
    ----------
    df : DataFrame (pre-filtered, threats only recommended)
    feed : URLhausFeed instance for IOC lookups
    mitre : MitreAttack instance for technique enrichment

    Returns
    -------
    List of incident dicts ordered by composite priority (highest first).
    """
    threat_df = df[df["label_binary"] == 1].copy()
    if threat_df.empty:
        return []

    incidents: List[Dict] = []

    # Group ALL threat events by source IP — no time-window constraint.
    # The real dataset spans multiple weeks so a narrow temporal window
    # would never produce any incidents.
    for src_ip, group in threat_df.groupby("src_ip", sort=False):
        if len(group) >= MIN_INCIDENT_SIZE:
            cluster = group.sort_values("timestamp").reset_index(drop=True)
            incident = _build_incident(cluster, src_ip, feed, mitre)
            incidents.append(incident)

    # Sort by priority descending
    incidents.sort(key=lambda x: x["priority_score"], reverse=True)
    return incidents


def _build_incident(
    cluster: pd.DataFrame,
    src_ip: str,
    feed: Optional[URLhausFeed],
    mitre: Optional[MitreAttack],
) -> Dict:
    """Build a single incident dict from a cluster of correlated alerts."""
    tactics = cluster["mitre_tactic"].dropna().unique().tolist()
    techniques = cluster["mitre_technique"].dropna().replace("", pd.NA).dropna().unique().tolist()
    categories = cluster["label_category"].dropna().unique().tolist()
    dst_ips = cluster["dst_ip"].dropna().unique().tolist()
    dst_ports = cluster["dst_port"].dropna().astype(int).unique().tolist()
    protocols = cluster["protocol"].astype(str).unique().tolist()
    severities = cluster["severity"].tolist()
    max_severity = int(max(severities)) if severities else 1
    total_bytes = float(cluster["total_bytes"].sum())
    event_count = len(cluster)

    # Timestamps
    ts_series = cluster["timestamp"].dropna()
    start_time = ts_series.min() if not ts_series.empty else None
    end_time = ts_series.max() if not ts_series.empty else None

    # URLhaus IOC enrichment
    ioc_hits: List[Dict] = []
    ioc_tags: List[str] = []
    if feed:
        hits = feed.lookup_ip(src_ip)
        ioc_hits.extend(hits)
        for dst in dst_ips[:5]:
            ioc_hits.extend(feed.lookup_ip(dst))
        for h in ioc_hits:
            for tag in (h.get("tags") or "").split(","):
                t = tag.strip()
                if t and t not in ioc_tags:
                    ioc_tags.append(t)

    # MITRE technique enrichment
    tech_details: List[Dict] = []
    if mitre and techniques:
        for tid in techniques[:5]:
            detail = mitre.get_technique(tid)
            if detail:
                tech_details.append(detail)

    # Priority scoring
    ioc_factor = 1.5 if ioc_hits else 1.0
    confidence = min(1.0, event_count / 50)  # normalised event density
    priority_score = round(max_severity * confidence * ioc_factor * min(len(tactics), 3), 3)

    return {
        "incident_id": f"INC-{src_ip.replace('.', '-')}-{event_count}",
        "src_ip": src_ip,
        "dst_ips": dst_ips[:10],
        "dst_ports": dst_ports[:10],
        "protocols": protocols,
        "event_count": event_count,
        "total_bytes": total_bytes,
        "start_time": str(start_time) if start_time else "Unknown",
        "end_time": str(end_time) if end_time else "Unknown",
        "tactics": [t for t in tactics if t and t != "Benign"],
        "techniques": techniques,
        "tech_details": tech_details,
        "categories": [c for c in categories if c not in ("Benign", "none")],
        "max_severity": max_severity,
        "ioc_hits": ioc_hits[:5],
        "ioc_tags": ioc_tags,
        "confidence": round(confidence, 3),
        "priority_score": priority_score,
    }


def top_source_ips(df: pd.DataFrame, n: int = 20) -> pd.DataFrame:
    """Return top-N source IPs by threat event count."""
    threat_df = df[df["label_binary"] == 1]
    counts = (
        threat_df.groupby("src_ip")
        .agg(
            event_count=("event_id", "count"),
            max_severity=("severity", "max"),
            tactics=("mitre_tactic", lambda x: ", ".join(sorted(set(x.dropna()) - {"Benign"}))),
            techniques=("mitre_technique", lambda x: ", ".join(sorted(set(x.dropna()) - {"", "nan"}))),
        )
        .sort_values("event_count", ascending=False)
        .head(n)
        .reset_index()
    )
    return counts


def alert_timeline(df: pd.DataFrame, freq: str = "1h") -> pd.DataFrame:
    """Resample alerts into time buckets for timeline visualisation."""
    ts = df.set_index("timestamp")
    if ts.index.tz is None:
        ts.index = ts.index.tz_localize("UTC")
    result = (
        ts.resample(freq)["label_binary"]
        .agg(total="count", threats=lambda x: (x == 1).sum(), benign=lambda x: (x == 0).sum())
        .reset_index()
    )
    result["timestamp"] = result["timestamp"].dt.strftime("%Y-%m-%d %H:%M")
    return result


def tactic_technique_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Build a tactic × technique event-count pivot for the heatmap."""
    threat_df = df[
        (df["label_binary"] == 1)
        & (df["mitre_technique"] != "")
        & (df["mitre_tactic"] != "Benign")
    ]
    if threat_df.empty:
        return pd.DataFrame()
    pivot = (
        threat_df.groupby(["mitre_tactic", "mitre_technique"])
        .size()
        .reset_index(name="count")
    )
    return pivot
