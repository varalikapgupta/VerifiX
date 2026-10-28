"""
backend/evaluate_scanner.py
===========================
22-Case Security Evaluation Benchmark for VerifiX Static Scanner.

Evaluates the AST static scanner (``backend.static_scanner.scan_source``)
against a standardized dataset of vulnerable snippets and safe lookalikes.
Measures detection metrics (TP, FP, TN, FN, Precision, Recall, F1,
Specificity, False Positive Rate) per rule and overall.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Import scanner without executing arbitrary user code
try:
    from backend.static_scanner import scan_source
except ImportError:
    from static_scanner import scan_source  # type: ignore[no-redef]


SUPPORTED_RULES: tuple[str, ...] = (
    "PY001",
    "PY002",
    "PY003",
    "PY004",
    "PY005",
    "AUTH001",
)

RULE_DESCRIPTIONS: dict[str, str] = {
    "PY001": "Dynamic eval() / exec() execution",
    "PY002": "Dynamic path component in os.path.join()",
    "PY003": "Dynamic SQL construction passed to cursor.execute()",
    "PY004": "Dynamic shell command execution",
    "PY005": "Potential hardcoded credentials in assignments",
    "AUTH001": "Missing authorization / ownership checks on document routes",
}

VALID_LABELS: tuple[str, ...] = ("vulnerable", "safe")


def safe_divide(numerator: float, denominator: float) -> float:
    """Perform safe division returning 0.0 when the denominator is zero.

    This convention avoids ZeroDivisionError in sparse or zero-count slices.
    """
    if denominator == 0.0:
        return 0.0
    return numerator / denominator


def load_dataset(file_path: Path | str, expected_count: int | None = 22) -> list[dict[str, Any]]:
    """Load and validate the evaluation dataset JSON file.

    Parameters
    ----------
    file_path : Path | str
        Path to the dataset JSON file.
    expected_count : int | None
        Expected total count of cases (default 22). If None, count is not enforced.

    Returns
    -------
    list[dict[str, Any]]
        List of validated case dictionaries.

    Raises
    ------
    FileNotFoundError
        If dataset file does not exist.
    ValueError
        If JSON schema, rule IDs, labels, duplicate IDs, or case count are invalid.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    try:
        raw_content = path.read_text(encoding="utf-8")
        data = json.loads(raw_content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON syntax in dataset file: {exc}") from exc

    if isinstance(data, dict):
        if "cases" not in data or not isinstance(data["cases"], list):
            raise ValueError("Dataset dictionary must contain a 'cases' list.")
        cases = data["cases"]
    elif isinstance(data, list):
        cases = data
    else:
        raise ValueError("Dataset root must be a JSON object with 'cases' or a list of cases.")

    if expected_count is not None and len(cases) != expected_count:
        raise ValueError(f"Dataset must contain exactly {expected_count} cases, found {len(cases)}.")

    seen_ids: set[str] = set()
    validated_cases: list[dict[str, Any]] = []

    for idx, item in enumerate(cases):
        if not isinstance(item, dict):
            raise ValueError(f"Case at index {idx} must be a dictionary.")

        for required in ("id", "rule", "label", "code"):
            if required not in item or not item[required]:
                raise ValueError(f"Case at index {idx} missing or empty required field: {required}")

        case_id = str(item["id"]).strip()
        if not case_id:
            raise ValueError(f"Case at index {idx} has an empty 'id'.")
        if case_id in seen_ids:
            raise ValueError(f"Duplicate case ID encountered: '{case_id}'")
        seen_ids.add(case_id)

        rule = str(item["rule"]).strip()
        if rule not in SUPPORTED_RULES:
            raise ValueError(
                f"Unsupported rule '{rule}' in case '{case_id}'. Must be one of {SUPPORTED_RULES}."
            )

        label = str(item["label"]).strip().lower()
        if label not in VALID_LABELS:
            raise ValueError(
                f"Invalid label '{label}' in case '{case_id}'. Must be one of {VALID_LABELS}."
            )

        code = item["code"]
        if not isinstance(code, str) or not code.strip():
            raise ValueError(f"Case '{case_id}' must provide non-empty code string.")

        title = str(item.get("title") or item.get("description") or case_id).strip()

        validated_cases.append({
            "id": case_id,
            "rule": rule,
            "label": label,
            "code": code,
            "title": title,
        })

    return validated_cases


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a single test case using the static AST scanner.

    The code snippet is analyzed only through static AST parsing, never executed.

    Classification Rules
    --------------------
    - If AST parsing raises a ``SyntaxError``, the case is classified with
      outcome ``"ERROR"``, ``passed=False``, and ``detected=False``. Such cases
      are excluded from TP, FP, TN, and FN, and tracked separately as errors.
    - If label is ``"vulnerable"``: outcome is ``"TP"`` if the target rule is
      detected in the AST findings; otherwise ``"FN"``.
    - If label is ``"safe"``: outcome is ``"FP"`` if the target rule is
      detected; otherwise ``"TN"``.

    Parameters
    ----------
    case : dict[str, Any]
        Dictionary with 'id', 'rule', 'label', 'code', and 'title'.

    Returns
    -------
    dict[str, Any]
        Evaluation result containing outcome (TP, FP, TN, FN, or ERROR),
        detected rules, actual findings, and pass/fail status.
    """
    case_id = case["id"]
    expected_rule = case["rule"]
    expected_label = case["label"]
    code = case["code"]
    title = case.get("title", case_id)

    findings: list[dict[str, Any]] = []
    syntax_error: str | None = None

    try:
        findings = scan_source(code, filename=case_id)
    except SyntaxError as exc:
        syntax_error = f"SyntaxError: {exc.msg} (line {exc.lineno})"

    detected_rules = sorted(list({f["rule"] for f in findings if "rule" in f}))
    target_rule_detected = expected_rule in detected_rules
    unrelated_findings = [f for f in findings if f.get("rule") != expected_rule]

    if syntax_error is not None:
        outcome = "ERROR"
        passed = False
        detected = False
    elif expected_label == "vulnerable":
        detected = target_rule_detected
        if detected:
            outcome = "TP"
            passed = True
        else:
            outcome = "FN"
            passed = False
    else:  # safe
        detected = target_rule_detected
        if detected:
            outcome = "FP"
            passed = False
        else:
            outcome = "TN"
            passed = True

    return {
        "id": case_id,
        "rule": expected_rule,
        "label": expected_label,
        "title": title,
        "outcome": outcome,
        "passed": passed,
        "detected": detected,
        "detected_rules": detected_rules,
        "actual_findings": findings,
        "unrelated_findings": unrelated_findings,
        "syntax_error": syntax_error,
    }


def compute_binary_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute standard detection metrics from case evaluation results.

    Returns case-level metrics: total_cases, true_positives (TP),
    false_positives (FP), true_negatives (TN), false_negatives (FN),
    errors, precision, recall, f1_score, specificity, and false_positive_rate.

    Exclusion of Syntax Errors:
    Cases with outcome ``"ERROR"`` (e.g. from an AST ``SyntaxError``) are
    strictly excluded from the confusion matrix counts (TP, FP, TN, FN) so that
    code parse failures do not inflate or bias detection metrics. The count
    of such cases is reported separately in ``errors``.
    """
    tp = sum(1 for r in results if r["outcome"] == "TP")
    fp = sum(1 for r in results if r["outcome"] == "FP")
    tn = sum(1 for r in results if r["outcome"] == "TN")
    fn = sum(1 for r in results if r["outcome"] == "FN")
    errors = sum(1 for r in results if r["outcome"] == "ERROR")
    total = len(results)

    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    f1 = safe_divide(2.0 * precision * recall, precision + recall)
    specificity = safe_divide(tn, tn + fp)
    fpr = safe_divide(fp, fp + tn)

    return {
        "total_cases": total,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "errors": errors,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "specificity": round(specificity, 4),
        "false_positive_rate": round(fpr, 4),
    }


def compute_benchmark_metrics(
    case_results: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, int]]:
    """Compute overall case metrics, per-rule case metrics, and finding-level counts.

    Parameters
    ----------
    case_results : list[dict[str, Any]]
        List of evaluated case results.

    Returns
    -------
    tuple[dict, dict, dict]
        (overall_metrics, per_rule_metrics, finding_level_counts)
    """
    overall_metrics = compute_binary_metrics(case_results)

    per_rule_metrics: dict[str, dict[str, Any]] = {}
    for rule in SUPPORTED_RULES:
        rule_cases = [r for r in case_results if r["rule"] == rule]
        per_rule_metrics[rule] = compute_binary_metrics(rule_cases)

    # Clearly distinguish case-level metrics from finding-level counts
    total_findings = sum(len(r["actual_findings"]) for r in case_results)
    expected_rule_findings = sum(
        sum(1 for f in r["actual_findings"] if f.get("rule") == r["rule"])
        for r in case_results
    )
    unrelated_findings_total = sum(len(r["unrelated_findings"]) for r in case_results)

    finding_level_counts = {
        "total_findings_generated": total_findings,
        "expected_rule_findings": expected_rule_findings,
        "unrelated_rule_findings": unrelated_findings_total,
    }

    return overall_metrics, per_rule_metrics, finding_level_counts


def generate_report_markdown(
    overall: dict[str, Any],
    per_rule: dict[str, dict[str, Any]],
    finding_counts: dict[str, int],
    case_results: list[dict[str, Any]],
    dataset_version: str = "1.0.0",
) -> str:
    """Generate a GitHub-flavored Markdown evaluation benchmark report."""
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = [
        "# VerifiX Static Scanner Benchmark Report",
        "",
        "## 1. Executive Summary",
        "",
        f"- **Run Timestamp:** {now_utc}",
        f"- **Dataset Version:** {dataset_version}",
        f"- **Evaluated Cases:** {overall['total_cases']}",
        f"- **Overall Precision:** {overall['precision']:.4f}",
        f"- **Overall Recall:** {overall['recall']:.4f}",
        f"- **Overall F1-Score:** {overall['f1_score']:.4f}",
        f"- **Overall Specificity:** {overall['specificity']:.4f}",
        f"- **False Positive Rate (FPR):** {overall['false_positive_rate']:.4f}",
        "",
        "## 2. Overall Confusion Matrix & Metrics",
        "",
        "| Metric | Count / Value | Formula / Definition |",
        "| :--- | :--- | :--- |",
        f"| **True Positives (TP)** | {overall['true_positives']} | Vulnerable cases correctly detected |",
        f"| **False Positives (FP)** | {overall['false_positives']} | Safe cases incorrectly flagged |",
        f"| **True Negatives (TN)** | {overall['true_negatives']} | Safe cases correctly passed |",
        f"| **False Negatives (FN)** | {overall['false_negatives']} | Vulnerable cases missed by scanner |",
        f"| **Errors** | {overall['errors']} | Snippets causing parser/runner errors (excluded from TP/FP/TN/FN) |",
        f"| **Precision** | {overall['precision']:.4f} | TP / (TP + FP) |",
        f"| **Recall (Sensitivity)** | {overall['recall']:.4f} | TP / (TP + FN) |",
        f"| **F1-Score** | {overall['f1_score']:.4f} | 2 * P * R / (P + R) |",
        f"| **Specificity** | {overall['specificity']:.4f} | TN / (TN + FP) |",
        f"| **False Positive Rate** | {overall['false_positive_rate']:.4f} | FP / (FP + TN) |",
        "",
        "### Finding-Level Counts",
        "- Total findings generated across all cases: "
        f"`{finding_counts['total_findings_generated']}`",
        "- Findings matching target rule: "
        f"`{finding_counts['expected_rule_findings']}`",
        "- Unrelated rule findings: "
        f"`{finding_counts['unrelated_rule_findings']}`",
        "",
        "## 3. Per-Rule Performance Breakdown",
        "",
        "| Rule | Description | Cases | TP | FP | TN | FN | Prec | Recall | F1 | Spec | FPR |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for rule in SUPPORTED_RULES:
        m = per_rule[rule]
        desc = RULE_DESCRIPTIONS.get(rule, "")
        lines.append(
            f"| `{rule}` | {desc} | {m['total_cases']} | {m['true_positives']} | "
            f"{m['false_positives']} | {m['true_negatives']} | {m['false_negatives']} | "
            f"{m['precision']:.2f} | {m['recall']:.2f} | {m['f1_score']:.2f} | "
            f"{m['specificity']:.2f} | {m['false_positive_rate']:.2f} |"
        )

    lines.extend([
        "",
        "## 4. Missed Detections (False Negatives)",
        "",
    ])

    false_negatives = [r for r in case_results if r["outcome"] == "FN"]
    if false_negatives:
        for fn_case in false_negatives:
            lines.append(
                f"- **{fn_case['id']}** (`{fn_case['rule']}`): {fn_case['title']} "
                f"(Detected rules: {fn_case['detected_rules']})"
            )
    else:
        lines.append("No false negatives encountered. All vulnerable cases were detected by their target rules.")

    lines.extend([
        "",
        "## 5. False Positives",
        "",
    ])

    false_positives = [r for r in case_results if r["outcome"] == "FP"]
    if false_positives:
        for fp_case in false_positives:
            lines.append(
                f"- **{fp_case['id']}** (`{fp_case['rule']}`): {fp_case['title']} "
                f"(Findings: {fp_case['detected_rules']})"
            )
    else:
        lines.append("No false positives encountered. No safe lookalikes triggered target rule alerts.")

    lines.extend([
        "",
        "## 6. Detailed Case-by-Case Results",
        "",
        "| Case ID | Rule | Expected Label | Outcome | Pass/Fail | Title | Detected Rules |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    for r in case_results:
        status_symbol = "PASS" if r["passed"] else "FAIL"
        detected_str = ", ".join(r["detected_rules"]) if r["detected_rules"] else "None"
        lines.append(
            f"| `{r['id']}` | `{r['rule']}` | `{r['label']}` | **{r['outcome']}** | "
            f"{status_symbol} | {r['title']} | `{detected_str}` |"
        )

    lines.append("")
    return "\n".join(lines)


def run_benchmark(
    dataset_path: Path | str,
    output_json_path: Path | str | None = None,
    output_report_path: Path | str | None = None,
    expected_count: int | None = 22,
) -> dict[str, Any]:
    """Execute the benchmark suite, compute metrics, and write artifact files.

    Parameters
    ----------
    dataset_path : Path | str
        Path to the JSON evaluation dataset.
    output_json_path : Path | str | None
        Destination for structured results JSON.
    output_report_path : Path | str | None
        Destination for Markdown benchmark report.
    expected_count : int | None
        Expected total count of cases (default 22).

    Returns
    -------
    dict[str, Any]
        Structured benchmark results dictionary.
    """
    cases = load_dataset(dataset_path, expected_count=expected_count)
    case_results = [evaluate_case(case) for case in cases]

    overall, per_rule, finding_counts = compute_benchmark_metrics(case_results)

    timestamp = datetime.now(timezone.utc).isoformat()
    benchmark_payload: dict[str, Any] = {
        "metadata": {
            "dataset_file": str(Path(dataset_path).name),
            "dataset_version": "1.0.0",
            "timestamp": timestamp,
            "total_cases": len(cases),
            "expected_rules": list(SUPPORTED_RULES),
        },
        "overall_metrics": overall,
        "per_rule_metrics": per_rule,
        "finding_level_counts": finding_counts,
        "cases": case_results,
    }

    if output_json_path is not None:
        out_json = Path(output_json_path)
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(benchmark_payload, indent=2), encoding="utf-8")

    if output_report_path is not None:
        out_report = Path(output_report_path)
        out_report.parent.mkdir(parents=True, exist_ok=True)
        report_md = generate_report_markdown(overall, per_rule, finding_counts, case_results)
        out_report.write_text(report_md, encoding="utf-8")

    return benchmark_payload


def print_terminal_summary(payload: dict[str, Any]) -> None:
    """Print a clean, concise terminal summary with totals and metrics."""
    overall = payload["overall_metrics"]
    per_rule = payload["per_rule_metrics"]
    findings = payload["finding_level_counts"]

    print("\n" + "=" * 68)
    print(" VerifiX Static Scanner 22-Case Benchmark Summary")
    print("=" * 68)
    print(f" Total Cases Evaluated : {overall['total_cases']}")
    print(f" True Positives (TP)   : {overall['true_positives']} (Vulnerable detected)")
    print(f" False Positives (FP)  : {overall['false_positives']} (Safe incorrectly flagged)")
    print(f" True Negatives (TN)   : {overall['true_negatives']} (Safe correctly passed)")
    print(f" False Negatives (FN)  : {overall['false_negatives']} (Vulnerable missed)")
    print(f" Parser / Run Errors   : {overall['errors']}")
    print("-" * 68)
    print(f" Precision             : {overall['precision']:.4f}")
    print(f" Recall (Sensitivity)  : {overall['recall']:.4f}")
    print(f" F1-Score              : {overall['f1_score']:.4f}")
    print(f" Specificity           : {overall['specificity']:.4f}")
    print(f" False Positive Rate   : {overall['false_positive_rate']:.4f}")
    print("-" * 68)
    print(f" Total AST Findings    : {findings['total_findings_generated']}")
    print(f" Expected Rule Findings: {findings['expected_rule_findings']}")
    print(f" Unrelated Findings    : {findings['unrelated_rule_findings']}")
    print("-" * 68)
    print(" Per-Rule Breakdown:")
    for rule, m in per_rule.items():
        print(
            f"   {rule:<8}: {m['total_cases']} cases | "
            f"TP={m['true_positives']} FP={m['false_positives']} "
            f"TN={m['true_negatives']} FN={m['false_negatives']} | "
            f"P={m['precision']:.2f} R={m['recall']:.2f} F1={m['f1_score']:.2f}"
        )
    print("=" * 68 + "\n")


def main() -> None:
    """CLI entry point for running the evaluation benchmark."""
    base_dir = Path(__file__).resolve().parent
    default_dataset = base_dir / "evaluation_dataset.json"
    default_results = base_dir / "evaluation_results.json"
    default_report = base_dir / "evaluation_report.md"

    parser = argparse.ArgumentParser(
        description="Run VerifiX 22-case static scanner evaluation benchmark."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=default_dataset,
        help="Path to evaluation_dataset.json",
    )
    parser.add_argument(
        "--results",
        type=Path,
        default=default_results,
        help="Path to output evaluation_results.json",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=default_report,
        help="Path to output evaluation_report.md",
    )

    args = parser.parse_args()
    results_payload = run_benchmark(
        dataset_path=args.dataset,
        output_json_path=args.results,
        output_report_path=args.report,
        expected_count=22,
    )
    print_terminal_summary(results_payload)


if __name__ == "__main__":
    main()
