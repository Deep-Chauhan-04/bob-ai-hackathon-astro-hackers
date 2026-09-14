"""
ML Threat Classifier
---------------------
Trains a RandomForest / scikit-learn pipeline on master_events.csv to
distinguish genuine threats from benign / false-positive traffic.
Outputs a confidence score (0.0–1.0) for each event and top risk factors.
"""

import hashlib
import logging
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

from engine.data_loader import get_feature_matrix

logger = logging.getLogger(__name__)

CACHE_DIR = Path(__file__).resolve().parent.parent.parent / "src" / "cache"
MODEL_FILE = CACHE_DIR / "classifier_model.pkl"

# Heuristic feature importance labels (aligned with get_feature_matrix cols)
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


class ThreatClassifier:
    """
    Thin wrapper around a scikit-learn RandomForest pipeline.

    Usage
    -----
    clf = ThreatClassifier()
    clf.fit(df)                         # trains and saves model
    scores = clf.predict_proba(df)      # returns confidence array
    report = clf.classification_report(df)
    """

    def __init__(self, model_path: Optional[Path] = None):
        self._model_path = model_path or MODEL_FILE
        self._pipeline: Optional[Pipeline] = None
        self._train_hash: Optional[str] = None

    # ------------------------------------------------------------------
    def load_or_train(self, df: pd.DataFrame, force_retrain: bool = False) -> "ThreatClassifier":
        """Load cached model if available and data hash matches; otherwise train."""
        data_hash = self._hash(df)
        if not force_retrain and self._model_path.exists():
            try:
                with open(self._model_path, "rb") as fh:
                    payload = pickle.load(fh)
                if payload.get("hash") == data_hash:
                    self._pipeline = payload["pipeline"]
                    logger.info("Classifier loaded from cache.")
                    return self
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not load cached model: %s. Retraining.", exc)

        self.fit(df)
        return self

    def fit(self, df: pd.DataFrame) -> "ThreatClassifier":
        """Train classifier on full dataset."""
        X, y = get_feature_matrix(df)
        logger.info("Training classifier on %d samples (%d positives) …",
                    len(y), int(y.sum()))

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, stratify=y, random_state=42
        )

        pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(
                n_estimators=120,
                max_depth=12,
                min_samples_leaf=5,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            )),
        ])
        pipeline.fit(X_train, y_train)
        self._pipeline = pipeline

        # Evaluate
        y_pred = pipeline.predict(X_test)
        y_prob = pipeline.predict_proba(X_test)[:, 1]
        auc = roc_auc_score(y_test, y_prob)
        logger.info("Classifier AUC-ROC: %.4f", auc)
        logger.info("\n%s", classification_report(y_test, y_pred, target_names=["Benign", "Threat"]))

        # Cache model
        self._model_path.parent.mkdir(parents=True, exist_ok=True)
        data_hash = self._hash(df)
        with open(self._model_path, "wb") as fh:
            pickle.dump({"pipeline": pipeline, "hash": data_hash, "auc": auc}, fh)

        self._train_hash = data_hash
        return self

    # ------------------------------------------------------------------
    def predict_proba(self, df: pd.DataFrame) -> np.ndarray:
        """Return per-row threat confidence scores (0.0–1.0)."""
        if self._pipeline is None:
            raise RuntimeError("Model not trained. Call load_or_train() first.")
        X, _ = get_feature_matrix(df)
        return self._pipeline.predict_proba(X.fillna(0))[:, 1]

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        """Return binary predictions."""
        return (self.predict_proba(df) >= 0.5).astype(int)

    def score_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add 'threat_confidence' column to a copy of df and return it."""
        df = df.copy()
        df["threat_confidence"] = self.predict_proba(df).round(4)
        return df

    def feature_importances(self) -> List[Dict]:
        """Return feature importances sorted descending."""
        if self._pipeline is None:
            return []
        rf: RandomForestClassifier = self._pipeline.named_steps["clf"]
        importances = rf.feature_importances_
        pairs = sorted(
            zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True
        )
        return [{"feature": f, "importance": round(float(v), 4)} for f, v in pairs]

    def top_risk_factors(self, row: pd.Series, n: int = 3) -> List[str]:
        """Return human-readable top contributing risk factors for a single row."""
        importance_map = {d["feature"]: d["importance"] for d in self.feature_importances()}
        candidates = []
        for feat, imp in importance_map.items():
            val = row.get(feat, 0)
            if feat == "protocol_enc":
                val = {"TCP": 0, "UDP": 1, "ICMP": 2}.get(str(row.get("protocol", "")), 3)
            if val and float(val) > 0:
                candidates.append((feat, imp, float(val)))
        candidates.sort(key=lambda x: x[1], reverse=True)
        result = []
        for feat, imp, val in candidates[:n]:
            if feat in ("bytes_fwd", "bytes_bwd", "total_bytes"):
                result.append(f"High data transfer ({val:,.0f} bytes)")
            elif feat in ("packets_fwd", "packets_bwd", "total_packets"):
                result.append(f"High packet rate ({val:,.0f} pkts)")
            elif feat == "dst_port":
                result.append(f"Targeted port {int(val)}")
            elif feat == "src_port":
                result.append(f"Unusual source port {int(val)}")
            elif feat == "duration":
                result.append(f"Long session ({val:.1f}s)")
            elif feat == "bytes_per_packet":
                result.append(f"Anomalous packet size ({val:.1f} B/pkt)")
            else:
                result.append(feat.replace("_", " ").title())
        return result if result else ["Anomalous network flow pattern"]

    @staticmethod
    def _hash(df: pd.DataFrame) -> str:
        """Lightweight hash of dataset shape + dtypes for cache invalidation."""
        sig = f"{df.shape}:{list(df.columns)}:{df.dtypes.to_dict()}"
        return hashlib.md5(sig.encode()).hexdigest()  # noqa: S324 – not security-critical


# Module-level singleton
_clf: Optional[ThreatClassifier] = None


def get_classifier(df: Optional[pd.DataFrame] = None, force_retrain: bool = False) -> ThreatClassifier:
    """Return cached/trained classifier. Pass df to train on first call."""
    global _clf
    if _clf is None or force_retrain:
        _clf = ThreatClassifier()
        if df is not None:
            _clf.load_or_train(df, force_retrain=force_retrain)
    return _clf
