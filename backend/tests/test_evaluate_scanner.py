"""
backend/tests/test_evaluate_scanner.py
======================================
Automated pytest tests for the VerifiX 22-case evaluation benchmark runner.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from backend.evaluate_scanner import (
    SUPPORTED_RULES,
    compute_benchmark_metrics,
    compute_binary_metrics,
    evaluate_case,
    load_dataset,
    run_benchmark,
    safe_divide,
)

BASE_DATASET_PATH = Path(__file__).resolve().parent.parent / "evaluation_dataset.json"


# ---------------------------------------------------------------------------
# 1. Dataset Integrity & Schema Tests
# ---------------------------------------------------------------------------

def test_dataset_contains_exactly_22_unique_cases() -> None:
    cases = load_dataset(BASE_DATASET_PATH, expected_count=22)
    assert len(cases) == 22, f"Expected 22 cases, got {len(cases)}"

    case_ids = [c["id"] for c in cases]
    assert len(case_ids) == len(set(case_ids)), "All case IDs must be unique"

    rules_in_dataset = {c["rule"] for c in cases}
    assert rules_in_dataset == set(SUPPORTED_RULES), "All 6 rules must be covered"

    labels = {c["label"] for c in cases}
    assert labels == {"vulnerable", "safe"}, "Both vulnerable and safe labels must be present"

    vulnerable_count = sum(1 for c in cases if c["label"] == "vulnerable")
    safe_count = sum(1 for c in cases if c["label"] == "safe")
    assert vulnerable_count == 11
    assert safe_count == 11


def test_invalid_dataset_schema_rejected(tmp_path: Path) -> None:
    # 1. Non-existent file
    with pytest.raises(FileNotFoundError):
        load_dataset(tmp_path / "non_existent.json")

    # 2. Malformed JSON
    bad_json_path = tmp_path / "bad.json"
    bad_json_path.write_text("{ broken json", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON"):
        load_dataset(bad_json_path)

    # 3. Wrong case count
    short_dataset = tmp_path / "short.json"
    short_dataset.write_text(
        json.dumps([{"id": "C1", "rule": "PY001", "label": "safe", "code": "pass"}]),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Dataset must contain exactly 22 cases"):
        load_dataset(short_dataset, expected_count=22)

    # 4. Duplicate case IDs
    dup_dataset = tmp_path / "dup.json"
    dup_cases = [
        {"id": "DUP-01", "rule": "PY001", "label": "safe", "code": "pass"},
        {"id": "DUP-01", "rule": "PY002", "label": "safe", "code": "pass"},
    ]
    dup_dataset.write_text(json.dumps(dup_cases), encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate case ID"):
        load_dataset(dup_dataset, expected_count=None)

    # 5. Unsupported rule ID
    bad_rule_dataset = tmp_path / "bad_rule.json"
    bad_rule_dataset.write_text(
        json.dumps([{"id": "C1", "rule": "PY999_UNKNOWN", "label": "safe", "code": "pass"}]),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Unsupported rule"):
        load_dataset(bad_rule_dataset, expected_count=None)

    # 6. Invalid label
    bad_label_dataset = tmp_path / "bad_label.json"
    bad_label_dataset.write_text(
        json.dumps([{"id": "C1", "rule": "PY001", "label": "maybe_vulnerable", "code": "pass"}]),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Invalid label"):
        load_dataset(bad_label_dataset, expected_count=None)

    # 7. Missing required field
    missing_field_dataset = tmp_path / "missing.json"
    missing_field_dataset.write_text(
        json.dumps([{"id": "C1", "rule": "PY001", "code": "pass"}]),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="missing or empty required field"):
        load_dataset(missing_field_dataset, expected_count=None)


# ---------------------------------------------------------------------------
# 2. Evaluation Logic & Independence Tests
# ---------------------------------------------------------------------------

def test_each_case_evaluated_independently() -> None:
    case_a = {
        "id": "CASE-INDEP-1",
        "rule": "PY001",
        "label": "vulnerable",
        "code": "eval(user_arg)",
        "title": "Eval test",
    }
    case_b = {
        "id": "CASE-INDEP-2",
        "rule": "PY001",
        "label": "safe",
        "code": "eval('1 + 1')",
        "title": "Literal eval test",
    }

    res_a = evaluate_case(case_a)
    res_b = evaluate_case(case_b)

    assert res_a["outcome"] == "TP"
    assert res_a["passed"] is True
    assert res_a["detected_rules"] == ["PY001"]

    assert res_b["outcome"] == "TN"
    assert res_b["passed"] is True
    assert res_b["detected_rules"] == []


def test_vulnerable_case_requires_expected_rule_to_detect() -> None:
    # 1. Matching rule detected -> True Positive
    case_match = {
        "id": "CASE-VULN-MATCH",
        "rule": "PY001",
        "label": "vulnerable",
        "code": "eval(user_code)",
        "title": "Matching rule",
    }
    res_match = evaluate_case(case_match)
    assert res_match["outcome"] == "TP"
    assert res_match["passed"] is True
    assert res_match["detected"] is True

    # 2. Finding under an unrelated rule must NOT count as detection -> False Negative
    # Target rule is PY001, but the code only triggers PY005 (hardcoded secret)
    case_unrelated = {
        "id": "CASE-VULN-MISMATCH",
        "rule": "PY001",
        "label": "vulnerable",
        "code": "api_key = 'super_secret_value'",
        "title": "Unrelated finding",
    }
    res_unrelated = evaluate_case(case_unrelated)
    assert res_unrelated["outcome"] == "FN"
    assert res_unrelated["passed"] is False
    assert res_unrelated["detected"] is False
    assert "PY005" in res_unrelated["detected_rules"]
    assert len(res_unrelated["unrelated_findings"]) == 1


def test_safe_case_with_target_finding_counts_as_false_positive() -> None:
    # Safe case wrongly triggering target rule -> False Positive
    case_fp = {
        "id": "CASE-SAFE-FP",
        "rule": "PY001",
        "label": "safe",
        "code": "eval(unintended_dynamic_var)",
        "title": "Safe lookalike falsely firing",
    }
    res_fp = evaluate_case(case_fp)
    assert res_fp["outcome"] == "FP"
    assert res_fp["passed"] is False
    assert res_fp["detected"] is True

    # Safe case with clean code -> True Negative
    case_tn = {
        "id": "CASE-SAFE-TN",
        "rule": "PY001",
        "label": "safe",
        "code": "eval('2 + 2')",
        "title": "Clean safe case",
    }
    res_tn = evaluate_case(case_tn)
    assert res_tn["outcome"] == "TN"
    assert res_tn["passed"] is True
    assert res_tn["detected"] is False

    # Safe case targeting PY001, but an unrelated finding (PY005) is present
    case_unrelated_safe = {
        "id": "CASE-SAFE-UNRELATED",
        "rule": "PY001",
        "label": "safe",
        "code": "api_key = 'token123'",
        "title": "Unrelated finding on safe case",
    }
    res_unrelated_safe = evaluate_case(case_unrelated_safe)
    # Target rule PY001 was NOT triggered -> so target rule is not a false positive
    assert res_unrelated_safe["outcome"] == "TN"
    assert res_unrelated_safe["passed"] is True
    assert len(res_unrelated_safe["unrelated_findings"]) == 1


# ---------------------------------------------------------------------------
# 3. Metrics & Confusion Matrix Tests
# ---------------------------------------------------------------------------

def test_confusion_matrix_counts_for_controlled_examples() -> None:
    controlled_results: list[dict[str, Any]] = [
        {"outcome": "TP", "actual_findings": [{"rule": "PY001"}], "rule": "PY001", "unrelated_findings": []},
        {"outcome": "TP", "actual_findings": [{"rule": "PY001"}], "rule": "PY001", "unrelated_findings": []},
        {"outcome": "FP", "actual_findings": [{"rule": "PY001"}], "rule": "PY001", "unrelated_findings": []},
        {"outcome": "TN", "actual_findings": [], "rule": "PY001", "unrelated_findings": []},
        {"outcome": "TN", "actual_findings": [], "rule": "PY001", "unrelated_findings": []},
        {"outcome": "TN", "actual_findings": [], "rule": "PY001", "unrelated_findings": []},
        {"outcome": "FN", "actual_findings": [], "rule": "PY001", "unrelated_findings": []},
    ]

    metrics = compute_binary_metrics(controlled_results)
    assert metrics["total_cases"] == 7
    assert metrics["true_positives"] == 2
    assert metrics["false_positives"] == 1
    assert metrics["true_negatives"] == 3
    assert metrics["false_negatives"] == 1
    assert metrics["errors"] == 0


def test_metrics_calculation_formulas() -> None:
    # 4 TP, 1 FP, 4 TN, 1 FN
    controlled_results: list[dict[str, Any]] = (
        [{"outcome": "TP"}] * 4
        + [{"outcome": "FP"}] * 1
        + [{"outcome": "TN"}] * 4
        + [{"outcome": "FN"}] * 1
    )

    metrics = compute_binary_metrics(controlled_results)
    # Precision = 4 / (4 + 1) = 0.8
    # Recall = 4 / (4 + 1) = 0.8
    # F1 = 2 * 0.8 * 0.8 / 1.6 = 0.8
    # Specificity = 4 / (4 + 1) = 0.8
    # FPR = 1 / (1 + 4) = 0.2
    assert metrics["precision"] == 0.8000
    assert metrics["recall"] == 0.8000
    assert metrics["f1_score"] == 0.8000
    assert metrics["specificity"] == 0.8000
    assert metrics["false_positive_rate"] == 0.2000


def test_zero_denominator_metrics_do_not_crash() -> None:
    assert safe_divide(0.0, 0.0) == 0.0
    assert safe_divide(10.0, 0.0) == 0.0

    # All TN slice (TP=0, FP=0, FN=0, TN=5)
    all_tn = [{"outcome": "TN"}] * 5
    m = compute_binary_metrics(all_tn)
    assert m["precision"] == 0.0
    assert m["recall"] == 0.0
    assert m["f1_score"] == 0.0
    assert m["specificity"] == 1.0
    assert m["false_positive_rate"] == 0.0

    # Empty list
    empty_m = compute_binary_metrics([])
    assert empty_m["total_cases"] == 0
    assert empty_m["precision"] == 0.0
    assert empty_m["recall"] == 0.0
    assert empty_m["f1_score"] == 0.0
    assert empty_m["specificity"] == 0.0
    assert empty_m["false_positive_rate"] == 0.0


def test_syntax_errors_reported_clearly_without_crashing() -> None:
    case_broken = {
        "id": "CASE-SYNTAX-ERR",
        "rule": "PY001",
        "label": "vulnerable",
        "code": "def broken_syntax(:\n   eval(x)",
        "title": "Syntax error case",
    }
    res = evaluate_case(case_broken)
    assert res["outcome"] == "ERROR"
    assert res["passed"] is False
    assert res["detected"] is False
    assert res["syntax_error"] is not None
    assert "SyntaxError" in res["syntax_error"]


def test_syntax_errors_do_not_inflate_confusion_matrix_counts() -> None:
    # Mixture of valid outcomes and syntax errors
    mixed_results: list[dict[str, Any]] = [
        {"outcome": "TP"},
        {"outcome": "TP"},
        {"outcome": "FP"},
        {"outcome": "TN"},
        {"outcome": "TN"},
        {"outcome": "FN"},
        {"outcome": "ERROR"},
        {"outcome": "ERROR"},
    ]

    metrics = compute_binary_metrics(mixed_results)
    assert metrics["total_cases"] == 8
    assert metrics["errors"] == 2
    assert metrics["true_positives"] == 2
    assert metrics["false_positives"] == 1
    assert metrics["true_negatives"] == 2
    assert metrics["false_negatives"] == 1

    # Verify confusion matrix sum excludes errors
    valid_count = (
        metrics["true_positives"]
        + metrics["false_positives"]
        + metrics["true_negatives"]
        + metrics["false_negatives"]
    )
    assert valid_count == 6
    assert valid_count + metrics["errors"] == metrics["total_cases"]

    # Precision = 2 / (2 + 1) = 0.6667
    # Recall = 2 / (2 + 1) = 0.6667
    # Specificity = 2 / (2 + 1) = 0.6667
    # FPR = 1 / (1 + 2) = 0.3333
    assert metrics["precision"] == 0.6667
    assert metrics["recall"] == 0.6667
    assert metrics["specificity"] == 0.6667
    assert metrics["false_positive_rate"] == 0.3333

    # All-error slice: all denominators for rates are zero
    all_errors = [{"outcome": "ERROR"}] * 4
    error_metrics = compute_binary_metrics(all_errors)
    assert error_metrics["total_cases"] == 4
    assert error_metrics["errors"] == 4
    assert error_metrics["true_positives"] == 0
    assert error_metrics["false_positives"] == 0
    assert error_metrics["true_negatives"] == 0
    assert error_metrics["false_negatives"] == 0
    assert error_metrics["precision"] == 0.0
    assert error_metrics["recall"] == 0.0
    assert error_metrics["f1_score"] == 0.0
    assert error_metrics["specificity"] == 0.0
    assert error_metrics["false_positive_rate"] == 0.0


# ---------------------------------------------------------------------------
# 4. Benchmark Runner & Output Artifact Tests
# ---------------------------------------------------------------------------

def test_benchmark_results_contain_all_expected_case_ids(tmp_path: Path) -> None:
    out_json = tmp_path / "results.json"
    out_report = tmp_path / "report.md"

    results = run_benchmark(
        dataset_path=BASE_DATASET_PATH,
        output_json_path=out_json,
        output_report_path=out_report,
        expected_count=22,
    )

    assert out_json.is_file()
    assert out_report.is_file()

    saved_data = json.loads(out_json.read_text(encoding="utf-8"))
    assert saved_data["metadata"]["total_cases"] == 22
    assert len(saved_data["cases"]) == 22

    evaluated_ids = {c["id"] for c in saved_data["cases"]}
    dataset_cases = load_dataset(BASE_DATASET_PATH)
    expected_ids = {c["id"] for c in dataset_cases}
    assert evaluated_ids == expected_ids

    # Verify per-rule metrics exist for all 6 rules
    for rule in SUPPORTED_RULES:
        assert rule in saved_data["per_rule_metrics"]

    report_text = out_report.read_text(encoding="utf-8")
    assert "# VerifiX Static Scanner Benchmark Report" in report_text
    assert "Executive Summary" in report_text
    assert "Per-Rule Performance Breakdown" in report_text


def test_repeated_runs_yield_identical_metrics_and_case_outcomes(tmp_path: Path) -> None:
    run1 = run_benchmark(BASE_DATASET_PATH, expected_count=22)
    run2 = run_benchmark(BASE_DATASET_PATH, expected_count=22)

    assert run1["overall_metrics"] == run2["overall_metrics"]
    assert run1["per_rule_metrics"] == run2["per_rule_metrics"]
    assert run1["finding_level_counts"] == run2["finding_level_counts"]

    outcomes1 = [c["outcome"] for c in run1["cases"]]
    outcomes2 = [c["outcome"] for c in run2["cases"]]
    assert outcomes1 == outcomes2
