"""
Data Loader — master_events.csv ingestion & normalisation
----------------------------------------------------------
Handles efficient loading of the 244 k-row dataset with optional
sampling for fast UI interactions and full-dataset processing for ML.
"""

import logging
import os
from pathlib import Path
from typing import Optional, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Resolve the CSV path relative to this file (repo root)
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CSV = _REPO_ROOT / "master_events.csv"

# Column dtypes for memory efficiency
_DTYPES = {
    "event_id": "str",
    "src_ip": "str",
    "dst_ip": "str",
    "src_port": "Int32",
    "dst_port": "Int32",
    "protocol": "category",
    "label_binary": "int8",
    "label_category": "category",
    "mitre_tactic": "category",
    "source_dataset": "category",
    "is_duplicate": "int8",
}

# Well-known noisy/benign port pairs to help heuristic FP filter
BENIGN_PORT_PAIRS = {(53, "UDP"), (80, "TCP"), (443, "TCP"), (123, "UDP"), (67, "UDP"), (68, "UDP")}

# Severity map: label_category → numeric severity 1-5
SEVERITY_MAP = {
    "Benign": 0,
    "none": 0,
    "Reconnaissance": 2,
    "Bot": 3,
    "Command and Control": 3,
    "Credential Access": 3,
    "SSH-Bruteforce": 3,
    "Brute Force -Web": 3,
    "FTP-BruteForce": 3,
    "Initial Access": 3,
    "Defense Evasion": 3,
    "Persistence": 3,
    "Privilege Escalation": 3,
    "Infilteration": 4,
    "DoS attacks-Hulk": 4,
    "DoS attacks-GoldenEye": 4,
    "DoS attacks-Slowloris": 4,
    "DoS attacks-SlowHTTPTest": 4,
    "DDoS attacks-LOIC-HTTP": 5,
    "DDOS attack-HOIC": 5,
    "DDOS attack-LOIC-UDP": 5,
    "Exfiltration": 5,
    "SQL Injection": 5,
}


def load_events(
    csv_path: Optional[Path] = None,
    sample_size: Optional[int] = None,
    random_state: int = 42,
) -> pd.DataFrame:
    """
    Load and clean master_events.csv.

    Parameters
    ----------
    csv_path : path to CSV (defaults to repo-root master_events.csv)
    sample_size : if given, stratified-sample this many rows for fast demos
    random_state : reproducibility seed

    Returns
    -------
    Cleaned DataFrame with derived columns added.
    """
    path = csv_path or DEFAULT_CSV
    logger.info("Loading events from %s …", path)

    df = pd.read_csv(path, dtype=_DTYPES, low_memory=True)

    # ---- Basic cleaning ------------------------------------------------
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df["duration"] = pd.to_numeric(df["duration"], errors="coerce").fillna(0.0)
    for col in ("bytes_fwd", "bytes_bwd", "packets_fwd", "packets_bwd"):
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    # Fill missing MITRE fields
    df["mitre_technique"] = df["mitre_technique"].astype(str).str.strip()
    df["mitre_technique"] = df["mitre_technique"].replace({"nan": "", "None": ""})
    df["mitre_tactic"] = df["mitre_tactic"].astype(str).fillna("Unknown")

    # ---- Derived columns -----------------------------------------------
    df["total_bytes"] = df["bytes_fwd"] + df["bytes_bwd"]
    df["total_packets"] = df["packets_fwd"] + df["packets_bwd"]
    df["bytes_per_packet"] = np.where(
        df["total_packets"] > 0,
        df["total_bytes"] / df["total_packets"],
        0.0,
    )
    df["severity"] = df["label_category"].astype(str).map(
        lambda c: SEVERITY_MAP.get(c, 1 if c not in ("Benign", "none") else 0)
    )

    # ---- Stratified sample (optional) ----------------------------------
    if sample_size and sample_size < len(df):
        # Stratified sample preserving label_binary distribution
        total = len(df)
        frames = []
        for label_val, group in df.groupby("label_binary"):
            n = max(1, int(sample_size * len(group) / total))
            frames.append(group.sample(min(len(group), n), random_state=random_state))
        df = pd.concat(frames).sample(frac=1, random_state=random_state).reset_index(drop=True)
        logger.info("Sampled %d rows.", len(df))

    logger.info("Dataset ready: %d rows, %d columns.", len(df), len(df.columns))
    return df


def get_feature_matrix(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Return (X, y) for ML training / scoring.
    Features are numerical network-flow statistics.
    """
    feature_cols = [
        "src_port", "dst_port",
        "duration",
        "bytes_fwd", "bytes_bwd",
        "packets_fwd", "packets_bwd",
        "total_bytes", "total_packets",
        "bytes_per_packet",
        "is_duplicate",
    ]
    # Encode protocol as integer
    proto_map = {"TCP": 0, "UDP": 1, "ICMP": 2}
    df = df.copy()
    df["protocol_enc"] = df["protocol"].astype(str).map(proto_map).fillna(3).astype(int)
    feature_cols.append("protocol_enc")

    X = df[feature_cols].fillna(0).astype(float)
    y = df["label_binary"].astype(int)
    return X, y


def summary_stats(df: pd.DataFrame) -> dict:
    """Quick KPI dictionary for the dashboard header."""
    total = len(df)
    threats = int(df["label_binary"].sum())
    benign = total - threats
    duplicates = int(df["is_duplicate"].sum())
    high_sev = int((df["severity"] >= 4).sum())
    return {
        "total_events": total,
        "total_threats": threats,
        "total_benign": benign,
        "duplicates_filtered": duplicates,
        "high_severity": high_sev,
        "fp_reduction_pct": round(100 * (benign + duplicates) / max(total, 1), 1),
        "datasets": df["source_dataset"].value_counts().to_dict(),
        "protocols": df["protocol"].value_counts().head(5).to_dict(),
        "top_tactics": (
            df[df["label_binary"] == 1]["mitre_tactic"]
            .value_counts()
            .head(8)
            .to_dict()
        ),
        "top_techniques": (
            df[df["mitre_technique"] != ""]["mitre_technique"]
            .value_counts()
            .head(8)
            .to_dict()
        ),
    }
