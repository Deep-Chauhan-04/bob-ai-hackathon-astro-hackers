"""
ML Pipeline Validation Script
==============================
Evaluates the RandomForest threat classifier on master_events.csv.
Mirrors the exact pipeline used by app.py:
  1. load_events()    - full dataset, no sampling
  2. deduplicate()    - removes flagged + exact 5-tuple duplicates
  3. train_test_split - stratified 80/20
  4. RandomForest     - same hyperparameters as classifier.py
  5. Report metrics   - accuracy, precision, recall, F1, AUC-ROC, confusion matrix

Run from repo root:
    python validate_ml.py
"""

import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Make src imports available
SRC = Path(__file__).resolve().parent / "src"
sys.path.insert(0, str(SRC))

from engine.data_loader import get_feature_matrix, load_events
from engine.correlation import deduplicate

# ---------------------------------------------------------------------------
# Configuration — must match classifier.py exactly
# ---------------------------------------------------------------------------
RF_PARAMS = dict(
    n_estimators=120,
    max_depth=12,
    min_samples_leaf=5,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)
TEST_SIZE = 0.2
RANDOM_STATE = 42

FEATURE_NAMES = [
    "src_port", "dst_port",
    "duration",
    "bytes_fwd", "bytes_bwd",
    "packets_fwd", "packets_bwd",
    "total_bytes", "total_packets",
    "bytes_per_packet",
    "is_duplicate",
    "protocol_enc",
]


def run_validation() -> dict:
    """Run full validation pipeline and return result dict."""
    print("=" * 60)
    print("  ML PIPELINE VALIDATION")
    print("=" * 60)

    # ── 1. Load ─────────────────────────────────────────────────────────
    print("\n[1/5] Loading master_events.csv …")
    t0 = time.time()
    df_raw = load_events()
    print(f"      Raw rows: {len(df_raw):,}  |  elapsed: {time.time()-t0:.1f}s")

    raw_total = len(df_raw)
    raw_benign = int((df_raw["label_binary"] == 0).sum())
    raw_malicious = int((df_raw["label_binary"] == 1).sum())
    raw_benign_pct = 100 * raw_benign / raw_total
    raw_malicious_pct = 100 * raw_malicious / raw_total

    # ── 2. Deduplicate (mirrors app.py) ──────────────────────────────────
    print("\n[2/5] Deduplicating …")
    df = deduplicate(df_raw)
    dedup_total = len(df)
    dedup_benign = int((df["label_binary"] == 0).sum())
    dedup_malicious = int((df["label_binary"] == 1).sum())
    removed = raw_total - dedup_total
    print(f"      Post-dedup rows: {dedup_total:,}  (removed {removed:,} duplicates)")

    # ── 3. Feature matrix ────────────────────────────────────────────────
    print("\n[3/5] Building feature matrix …")
    X, y = get_feature_matrix(df)
    print(f"      Features: {X.shape[1]}  |  Samples: {X.shape[0]:,}")
    print(f"      Class balance — benign: {(y==0).sum():,}  malicious: {(y==1).sum():,}")

    # ── 4. Stratified split ──────────────────────────────────────────────
    print("\n[4/5] Splitting (stratified 80/20) …")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
    )
    print(f"      Train: {len(y_train):,}  |  Test: {len(y_test):,}")
    print(f"      Train positives: {y_train.sum():,}  |  Test positives: {y_test.sum():,}")

    # ── 5. Train ─────────────────────────────────────────────────────────
    print("\n[5/5] Training RandomForest …")
    t1 = time.time()
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(**RF_PARAMS)),
    ])
    pipeline.fit(X_train, y_train)
    train_time = time.time() - t1
    print(f"      Training complete in {train_time:.1f}s")

    # ── Evaluate ─────────────────────────────────────────────────────────
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    acc       = accuracy_score(y_test, y_pred)
    prec      = precision_score(y_test, y_pred, zero_division=0)
    rec       = recall_score(y_test, y_pred, zero_division=0)
    f1        = f1_score(y_test, y_pred, zero_division=0)
    auc       = roc_auc_score(y_test, y_prob)
    cm        = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    report_str = classification_report(
        y_test, y_pred, target_names=["Benign", "Threat"], digits=4
    )

    # Feature importances
    rf = pipeline.named_steps["clf"]
    fi_pairs = sorted(
        zip(FEATURE_NAMES, rf.feature_importances_), key=lambda x: x[1], reverse=True
    )

    result = {
        # Raw dataset
        "raw_total": raw_total,
        "raw_benign": raw_benign,
        "raw_malicious": raw_malicious,
        "raw_benign_pct": raw_benign_pct,
        "raw_malicious_pct": raw_malicious_pct,
        # Post-dedup
        "dedup_total": dedup_total,
        "dedup_benign": dedup_benign,
        "dedup_malicious": dedup_malicious,
        "removed_duplicates": removed,
        # Split sizes
        "train_size": len(y_train),
        "test_size": len(y_test),
        # Metrics
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": auc,
        # Confusion matrix
        "tn": int(tn), "fp": int(fp),
        "fn": int(fn), "tp": int(tp),
        # Extra
        "report_str": report_str,
        "fi_pairs": fi_pairs,
        "train_time_s": train_time,
    }
    return result


def print_results(r: dict) -> None:
    print("\n" + "=" * 60)
    print("  RESULTS")
    print("=" * 60)
    print(f"  Accuracy  : {r['accuracy']:.4f}")
    print(f"  Precision : {r['precision']:.4f}")
    print(f"  Recall    : {r['recall']:.4f}")
    print(f"  F1-score  : {r['f1']:.4f}")
    print(f"  ROC-AUC   : {r['roc_auc']:.4f}")
    print()
    print(f"  Confusion Matrix (test set = {r['test_size']:,} rows):")
    print(f"           Pred Benign  Pred Threat")
    print(f"  Benign   {r['tn']:>10,}  {r['fp']:>11,}")
    print(f"  Threat   {r['fn']:>10,}  {r['tp']:>11,}")
    print()
    print("  Classification Report:")
    print(r["report_str"])
    print("  Top Feature Importances:")
    for feat, imp in r["fi_pairs"][:8]:
        print(f"    {feat:25s} {imp:.4f}")


if __name__ == "__main__":
    result = run_validation()
    print_results(result)
    print("\nDone. Run save_report.py to write outputs/ml_validation_report.md")
