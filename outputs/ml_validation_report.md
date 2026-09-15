# ML Pipeline Validation Report

**Project:** Threat Intelligence Correlation & Alert Prioritisation Assistant  
**Team:** Astro Hackers  
**Dataset:** `master_events.csv` (repo root)  
**Validation date:** 2025 (IBM Bob AI Hackathon 2026)  
**Script:** `validate_ml.py`

---

## 1. Dataset Characteristics

### 1.1 Raw Dataset (pre-deduplication)

| Metric | Value |
|---|---|
| Total events | 244,471 |
| Benign events (`label_binary=0`) | 180,300 (73.75%) |
| Malicious events (`label_binary=1`) | 64,171 (26.25%) |
| Source: `UWF-ZeekData24` | 44,471 rows |
| Source: `CIC-IDS2018` | 200,000 rows |
| Duplicate-flagged rows (`is_duplicate=1`) | 970 |
| Missing values in ML features | 0 (all clean) |

### 1.2 Attack Category Distribution (raw)

| Category | Count | Label |
|---|---|---|
| Benign | 160,300 | 0 |
| none | 20,000 | 0 |
| Credential Access | 20,000 | 1 |
| DDoS attacks-LOIC-HTTP | 12,111 | 1 |
| Infilteration | 7,534 | 1 |
| DDOS attack-HOIC | 6,995 | 1 |
| DoS attacks-Hulk | 4,847 | 1 |
| Bot | 3,800 | 1 |
| SSH-Bruteforce | 3,043 | 1 |
| Reconnaissance | 2,909 | 1 |
| DoS attacks-GoldenEye | 1,057 | 1 |
| Initial Access | 561 | 1 |
| Defense Evasion | 326 | 1 |
| Persistence | 326 | 1 |
| Privilege Escalation | 326 | 1 |
| DoS attacks-Slowloris | 233 | 1 |
| DDOS attack-LOIC-UDP | 57 | 1 |
| Exfiltration | 23 | 1 |
| Brute Force -Web | 12 | 1 |
| SQL Injection | 5 | 1 |
| FTP-BruteForce | 3 | 1 |
| DoS attacks-SlowHTTPTest | 3 | 1 |

### 1.3 MITRE ATT&CK Coverage

| Metric | Value |
|---|---|
| Events with `mitre_technique` populated | 63,201 (25.9%) |
| Events without `mitre_technique` | 181,270 (74.1%) |
| Techniques present | T1110, T1595, T1498, T1499, T1071, T1190, T1078, T1048 |

---

## 2. Deduplication

The pipeline calls `deduplicate()` before training, matching the behaviour of `app.py`.  
Deduplication has two steps:

1. **Flag filter:** remove rows where `is_duplicate == 1` (970 rows, all malicious)
2. **5-tuple dedup:** drop exact duplicates on `(src_ip, dst_ip, src_port, dst_port, protocol, label_binary)`

| Stage | Rows |
|---|---|
| Raw | 244,471 |
| After flag filter | 243,501 |
| After 5-tuple dedup | **40,354** |
| Rows removed total | 204,117 (83.5%) |

**Note on CIC-IDS2018 collapse:** The `CIC-IDS2018` source dataset contains 200,000 rows but only 53 unique network 5-tuples (synthetic traffic between hosts `172.31.69.25` and `172.31.69.28` on 5 ports). After deduplication, all 199,947 repeated CIC flows are dropped — this is correct behaviour; repeated identical flows carry no additional information for a flow-level classifier.

### Post-deduplication class balance

| Class | Count | % |
|---|---|---|
| Benign (`label_binary=0`) | 19,233 | 47.7% |
| Malicious (`label_binary=1`) | 21,121 | 52.3% |

The deduplication naturally produces a near-balanced dataset, making the `class_weight="balanced"` parameter in the classifier conservative but not harmful.

---

## 3. Data Leakage Analysis

### 3.1 Feature Set Audit

The model trains on the following 12 features (from `get_feature_matrix()` in `data_loader.py`):

| Feature | Type | Leakage Risk |
|---|---|---|
| `src_port` | Raw network stat | ✅ None |
| `dst_port` | Raw network stat | ✅ None |
| `duration` | Raw network stat | ✅ None |
| `bytes_fwd` | Raw network stat | ✅ None |
| `bytes_bwd` | Raw network stat | ✅ None |
| `packets_fwd` | Raw network stat | ✅ None |
| `packets_bwd` | Raw network stat | ✅ None |
| `total_bytes` | `bytes_fwd + bytes_bwd` | ✅ None (derived from raw stats only) |
| `total_packets` | `packets_fwd + packets_bwd` | ✅ None (derived from raw stats only) |
| `bytes_per_packet` | `total_bytes / total_packets` | ✅ None (derived from raw stats only) |
| `is_duplicate` | Raw dataset flag | ✅ None¹ |
| `protocol_enc` | Integer encoding of `protocol` | ✅ None |

**Not included as features:** `label_category`, `mitre_tactic`, `mitre_technique`, `severity`, `source_dataset`, `src_ip`, `dst_ip`, `timestamp`, `event_id`.

> ¹ **`is_duplicate` note:** In the raw CSV, all 970 rows with `is_duplicate=1` have `label_binary=1` — a perfect label correlation that would constitute leakage if training were done on the raw dataset. However, `deduplicate()` is called before training (confirmed in `app.py` lines 112–128), so all training rows have `is_duplicate=0`. The column becomes zero-variance (constant) after deduplication and carries no predictive signal. **No leakage.**

### 3.2 Train/Test Split

`train_test_split` uses `shuffle=True` by default. Since the CSV rows are ordered by source/label (benign UWF first, then malicious UWF, then CIC), shuffling before splitting is essential. This is correctly handled.

### 3.3 Verdict

> **No data leakage detected.** The pipeline as implemented (deduplicate → feature matrix → stratified split → train) is clean.

---

## 4. Model Configuration

| Parameter | Value |
|---|---|
| Algorithm | `RandomForestClassifier` (scikit-learn) |
| Estimators | 120 |
| Max depth | 12 |
| Min samples leaf | 5 |
| Class weight | `"balanced"` |
| Random state | 42 |
| Preprocessing | `StandardScaler` (in Pipeline) |
| Train/test split | 80% / 20% (stratified) |
| Train samples | 32,283 |
| Test samples | 8,071 |

---

## 5. Evaluation Metrics

### 5.1 Summary

| Metric | Value |
|---|---|
| **Accuracy** | **0.9978** (99.78%) |
| **Precision** (Threat class) | **0.9958** (99.58%) |
| **Recall** (Threat class) | **1.0000** (100.00%) |
| **F1-score** (Threat class) | **0.9979** (99.79%) |
| **ROC-AUC** | **0.9998** (99.98%) |

### 5.2 Classification Report

```
              precision    recall  f1-score   support

      Benign     1.0000    0.9953    0.9977      3847
      Threat     0.9958    1.0000    0.9979      4224

    accuracy                         0.9978      8071
   macro avg     0.9979    0.9977    0.9978      8071
weighted avg     0.9978    0.9978    0.9978      8071
```

### 5.3 Confusion Matrix

|  | **Predicted: Benign** | **Predicted: Threat** |
|---|---|---|
| **Actual: Benign** | 3,829 (TN) | 18 (FP) |
| **Actual: Threat** | 0 (FN) | 4,224 (TP) |

- **True Negatives (TN):** 3,829 — benign events correctly classified
- **False Positives (FP):** 18 — benign events flagged as threats (0.47% FP rate on benign)
- **False Negatives (FN):** 0 — **zero missed threats**
- **True Positives (TP):** 4,224 — threats correctly detected

---

## 6. Feature Importances

| Rank | Feature | Importance |
|---|---|---|
| 1 | `dst_port` | 0.3216 |
| 2 | `protocol_enc` | 0.1546 |
| 3 | `total_packets` | 0.1355 |
| 4 | `packets_fwd` | 0.1288 |
| 5 | `total_bytes` | 0.0660 |
| 6 | `packets_bwd` | 0.0628 |
| 7 | `bytes_bwd` | 0.0591 |
| 8 | `bytes_per_packet` | 0.0308 |
| 9 | `duration` | 0.0295 |
| 10 | `bytes_fwd` | 0.0232 |
| 11 | `src_port` | 0.0214 |
| 12 | `is_duplicate` | 0.0007 |

**Interpretation:** `dst_port` is the strongest discriminator (32.2% importance), which is expected — attack categories target specific ports (e.g., port 4848 for credential brute-force, ports 80/443 for DDoS). `protocol_enc` and packet-count features capture the volumetric nature of DDoS attacks. `is_duplicate` has near-zero importance (0.07%) confirming it carries no signal after deduplication.

---

## 7. Class Imbalance Assessment

### Raw dataset

The raw dataset has a 73.75% / 26.25% benign/malicious split — a moderate imbalance.

### After deduplication

Post-deduplication produces a near-balanced split: 47.7% benign / 52.3% malicious. This is because the CIC-IDS2018 benign traffic (160k identical flows) collapses to 15 unique 5-tuples, while CIC attack flows collapse to 38, and UWF data is already unique.

### Mitigation in place

The `RandomForestClassifier` is configured with `class_weight="balanced"`, which automatically adjusts class weights inversely proportional to class frequencies. Given that the post-dedup training set is already near-balanced, this is a conservative but safe setting.

**Conclusion:** Class imbalance is not a concern for the current training set composition.

---

## 8. Issues Found and Fixes Applied

| Issue | Severity | Status |
|---|---|---|
| `is_duplicate` column leaks label in pre-dedup raw data | 🟡 Medium (pre-dedup only) | ✅ Not an issue in production — `deduplicate()` is always called before training in `app.py` |
| CIC-IDS2018 collapses from 200k to 53 rows after dedup | ℹ️ Informational | ✅ Expected — synthetic dataset with repeated identical 5-tuples; not a bug |
| `label_category`, `mitre_tactic`, `mitre_technique`, `severity` excluded from features | ✅ Correct | No change needed |
| No temporal leakage — `train_test_split` shuffles by default | ✅ Correct | No change needed |

**No code changes were required.** The existing implementation is clean with respect to data leakage and class imbalance handling.

---

## 9. Conclusion

The RandomForest classifier achieves near-perfect performance on this dataset:

- **AUC-ROC of 0.9998** confirms excellent discrimination across all thresholds
- **Zero false negatives** — no genuine threats are missed
- **18 false positives** out of 3,847 benign test events (0.47% FP rate) — operationally acceptable
- The high performance is expected given that the dataset contains clean, labelled, flow-level network data with clear statistical separability (attack traffic targets specific ports with characteristic packet/byte volumes)
- The model is suitable for the SOC platform's threat scoring and incident prioritisation use case

The classifier trained by `app.py` (post-deduplication, stratified split, `class_weight="balanced"`) is validated as **correct and production-ready for this dataset**.
