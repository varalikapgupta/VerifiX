# VerifiX Static Scanner Benchmark Report

## 1. Executive Summary

- **Run Timestamp:** 2026-10-28 18:09:58 UTC
- **Dataset Version:** 1.0.0
- **Evaluated Cases:** 22
- **Overall Precision:** 1.0000
- **Overall Recall:** 1.0000
- **Overall F1-Score:** 1.0000
- **Overall Specificity:** 1.0000
- **False Positive Rate (FPR):** 0.0000

## 2. Overall Confusion Matrix & Metrics

| Metric | Count / Value | Formula / Definition |
| :--- | :--- | :--- |
| **True Positives (TP)** | 11 | Vulnerable cases correctly detected |
| **False Positives (FP)** | 0 | Safe cases incorrectly flagged |
| **True Negatives (TN)** | 11 | Safe cases correctly passed |
| **False Negatives (FN)** | 0 | Vulnerable cases missed by scanner |
| **Errors** | 0 | Snippets causing parser/runner errors (excluded from TP/FP/TN/FN) |
| **Precision** | 1.0000 | TP / (TP + FP) |
| **Recall (Sensitivity)** | 1.0000 | TP / (TP + FN) |
| **F1-Score** | 1.0000 | 2 * P * R / (P + R) |
| **Specificity** | 1.0000 | TN / (TN + FP) |
| **False Positive Rate** | 0.0000 | FP / (FP + TN) |

### Finding-Level Counts
- Total findings generated across all cases: `11`
- Findings matching target rule: `11`
- Unrelated rule findings: `0`

## 3. Per-Rule Performance Breakdown

| Rule | Description | Cases | TP | FP | TN | FN | Prec | Recall | F1 | Spec | FPR |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `PY001` | Dynamic eval() / exec() execution | 4 | 2 | 0 | 2 | 0 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 |
| `PY002` | Dynamic path component in os.path.join() | 4 | 2 | 0 | 2 | 0 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 |
| `PY003` | Dynamic SQL construction passed to cursor.execute() | 4 | 2 | 0 | 2 | 0 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 |
| `PY004` | Dynamic shell command execution | 4 | 2 | 0 | 2 | 0 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 |
| `PY005` | Potential hardcoded credentials in assignments | 3 | 2 | 0 | 1 | 0 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 |
| `AUTH001` | Missing authorization / ownership checks on document routes | 3 | 1 | 0 | 2 | 0 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 |

## 4. Missed Detections (False Negatives)

No false negatives encountered. All vulnerable cases were detected by their target rules.

## 5. False Positives

No false positives encountered. No safe lookalikes triggered target rule alerts.

## 6. Detailed Case-by-Case Results

| Case ID | Rule | Expected Label | Outcome | Pass/Fail | Title | Detected Rules |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `CASE-PY001-01` | `PY001` | `vulnerable` | **TP** | PASS | Dynamic formula evaluation using eval() with user input | `PY001` |
| `CASE-PY001-02` | `PY001` | `vulnerable` | **TP** | PASS | Dynamic code execution using exec() with unvalidated script | `PY001` |
| `CASE-PY001-03` | `PY001` | `safe` | **TN** | PASS | Static math constant evaluation using literal eval() | `None` |
| `CASE-PY001-04` | `PY001` | `safe` | **TN** | PASS | Static configuration bootstrap with literal exec() | `None` |
| `CASE-PY002-01` | `PY002` | `vulnerable` | **TP** | PASS | Path traversal via dynamic filename in os.path.join | `PY002` |
| `CASE-PY002-02` | `PY002` | `vulnerable` | **TP** | PASS | Path traversal via dynamic f-string in os.path.join | `PY002` |
| `CASE-PY002-03` | `PY002` | `safe` | **TN** | PASS | Safe static path construction with literal components | `None` |
| `CASE-PY002-04` | `PY002` | `safe` | **TN** | PASS | Safe single-argument base directory resolution | `None` |
| `CASE-PY003-01` | `PY003` | `vulnerable` | **TP** | PASS | SQL injection via f-string formatting in cursor.execute | `PY003` |
| `CASE-PY003-02` | `PY003` | `vulnerable` | **TP** | PASS | SQL injection via percent formatting in cursor.execute | `PY003` |
| `CASE-PY003-03` | `PY003` | `safe` | **TN** | PASS | Safe parameterized SQL query in cursor.execute | `None` |
| `CASE-PY003-04` | `PY003` | `safe` | **TN** | PASS | Safe static literal SQL query in cursor.execute | `None` |
| `CASE-PY004-01` | `PY004` | `vulnerable` | **TP** | PASS | Command injection via variable command in subprocess.run | `PY004` |
| `CASE-PY004-02` | `PY004` | `vulnerable` | **TP** | PASS | Command injection via dynamic string in os.system | `PY004` |
| `CASE-PY004-03` | `PY004` | `safe` | **TN** | PASS | Safe subprocess command using fixed literal argument list | `None` |
| `CASE-PY004-04` | `PY004` | `safe` | **TN** | PASS | Safe os.system call with static string literal | `None` |
| `CASE-PY005-01` | `PY005` | `vulnerable` | **TP** | PASS | Hardcoded API secret in variable assignment | `PY005` |
| `CASE-PY005-02` | `PY005` | `vulnerable` | **TP** | PASS | Hardcoded database password in annotated assignment | `PY005` |
| `CASE-PY005-03` | `PY005` | `safe` | **TN** | PASS | Safe secret retrieval via environment variable | `None` |
| `CASE-AUTH001-01` | `AUTH001` | `vulnerable` | **TP** | PASS | BOLA/IDOR route accessing DOCUMENTS without ownership check | `AUTH001` |
| `CASE-AUTH001-02` | `AUTH001` | `safe` | **TN** | PASS | Route accessing DOCUMENTS with explicit ownership verification | `None` |
| `CASE-AUTH001-03` | `AUTH001` | `safe` | **TN** | PASS | Public endpoint not accessing DOCUMENTS collection | `None` |
