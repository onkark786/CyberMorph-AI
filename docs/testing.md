# CyberMorph AI — Testing Strategy & Verification Guide

This document details the quality assurance, verification methodology, and automated test suite implemented for **CyberMorph AI**.

---

## 1. Test Suite Architecture

The test suite is structured around modular unit, edge-case, and pipeline integration tests executed via `pytest`:

```
CybermorphAI/tests/
├── test_database.py        # SQLite schema, transactions, filtering, deletion
├── test_url_features.py    # URL parsing, safe validation, 30 UCI feature extraction
├── test_preprocessing.py   # Column headers, inf/nan handling, label normalization
├── test_phishing.py        # Model artifact loading, inference schema, risk levels
├── test_network_ids.py     # Network IDS flow inference, CSV schema check, data audits
├── test_reporting.py       # UTF-8 CSV generation, ReportLab PDF compilation
└── test_phishing_schema.py # 30-feature exact schema parity verification
```

---

## 2. Test Execution

Execute the full suite from the project directory:

```powershell
# From CybermorphAI directory:
.\.venv\Scripts\pytest -v

# Or with test coverage summary:
.\.venv\Scripts\pytest --tb=short
```

---

## 3. Core Test Scenarios & Edge Cases

### A. URL Validation & Parsing Edge Cases (`test_url_features.py`)
- **Scheme Omission:** Validates that URLs without `http://` or `https://` (e.g. `example.com/login`) are normalized safely without throwing exceptions.
- **Protocol Sanitization:** Confirms that hostile schemes such as `javascript:`, `file:`, `data:`, and empty inputs are rejected defensively with clear `ValueError` messages.
- **Feature Parity:** Asserts that exactly 30 features with ternary values in `{-1, 0, 1}` are produced for every input.
- **Privacy Masking:** Asserts that sensitive user credentials (`user:pass@`) and query tokens (`token=secret`) are redacted before database persistence.

### B. Data Cleaning & Sanitization (`test_preprocessing.py`)
- **Inconsistent Headers:** Strips trailing spaces and multiple spaces in CSV columns (e.g. `' Destination Port '` -> `'Destination Port'`).
- **Infinite & Null Handling:** Tests that floating-point infinities (`+inf`, `-inf`) resulting from microsecond zero-duration packet divisions are converted to NaN and imputed using column medians.
- **Label Normalization:** Verifies conversion of varied text labels (`'BENIGN'`, `'PortScan'`, `'DDoS'`, etc.) to standard binary integers (0 = Benign, 1 = Attack).
- **Schema Validation:** Verifies that CSVs missing mandatory flow features are identified and rejected with human-readable error explanations.

### C. Persistent Storage & History Management (`test_database.py`)
- **Transaction Safety:** Tests SQLite table initialization (`analysis_history`, `model_runs`).
- **Filtering & Search:** Asserts date, risk level, and analysis type filtering return correct subsets.
- **Atomic Deletion:** Asserts individual record deletion removes the exact ID without data corruption.
- **Audit Logging:** Confirms that model evaluation runs persist metrics into `model_runs`.

### D. Model Inference & Risk Scoring (`test_phishing.py`, `test_network_ids.py`)
- **Output Formats:** Asserts that predictions include predicted label, risk level (`Low`, `Medium`, `High`), confidence score (`[0.0, 1.0]`), and explanation points.
- **Extreme Signals:** Asserts that synthetic pure-phishing vectors (`-1` across all features) trigger `High` risk classifications.

### E. Reporting Engine (`test_reporting.py`)
- **CSV Serialization:** Asserts clean UTF-8 CSV string conversion.
- **PDF Compilation:** Asserts ReportLab document compiler returns valid binary streams starting with `%PDF` header.
