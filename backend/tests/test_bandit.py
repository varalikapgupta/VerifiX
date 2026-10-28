"""
tests/test_bandit.py
====================
Bandit baseline comparison tests for the VerifiX security engine.

All tests in this module are automatically SKIPPED when bandit is not
installed in the venv.

To install bandit and run these tests:
    backend/.venv/Scripts/python.exe -m pip install bandit
    backend/.venv/Scripts/python.exe -m pytest backend/tests/test_bandit.py -v
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from bandit_baseline import (  # noqa: E402
    bandit_available,
    compare_findings,
    load_baseline,
    run_bandit,
    save_baseline,
    DEFAULT_TARGET,
    DEFAULT_BASELINE,
)
from static_scanner import scan_file  # noqa: E402

# ---------------------------------------------------------------------------
# Module-level skip: every test requires bandit to be installed.
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.skipif(
    not bandit_available(),
    reason="bandit not installed — run: "
           "backend\\.venv\\Scripts\\python.exe -m pip install bandit",
)


# ---------------------------------------------------------------------------
# Bandit runner
# ---------------------------------------------------------------------------

class TestBanditRunner:

    def test_runs_cleanly_returns_list(self):
        results = run_bandit(DEFAULT_TARGET)
        assert isinstance(results, list), "run_bandit() must return a list"

    def test_finds_at_least_one_issue(self):
        results = run_bandit(DEFAULT_TARGET)
        assert len(results) >= 1, (
            "Bandit should find at least one issue in vulnerable_app.py"
        )

    def test_every_finding_has_required_fields(self):
        results = run_bandit(DEFAULT_TARGET)
        required = {"rule", "type", "line", "evidence", "severity", "source"}
        for f in results:
            missing = required - f.keys()
            assert not missing, (
                f"Finding missing fields {missing}: {f}"
            )

    def test_source_field_is_bandit(self):
        for f in run_bandit(DEFAULT_TARGET):
            assert f["source"] == "bandit"

    def test_severity_is_lowercase_known_value(self):
        valid = {"low", "medium", "high"}
        for f in run_bandit(DEFAULT_TARGET):
            assert f["severity"] in valid, (
                f"Unexpected severity {f['severity']!r} in {f}"
            )

    def test_line_numbers_are_positive_integers(self):
        for f in run_bandit(DEFAULT_TARGET):
            assert isinstance(f["line"], int) and f["line"] > 0, (
                f"line must be a positive int; got {f['line']!r}"
            )

    def test_rule_ids_are_nonempty_strings(self):
        for f in run_bandit(DEFAULT_TARGET):
            assert isinstance(f["rule"], str) and f["rule"], (
                f"rule must be a non-empty string; got {f['rule']!r}"
            )


# ---------------------------------------------------------------------------
# Custom-rule scanner on the same target
# ---------------------------------------------------------------------------

class TestCustomRulesOnTarget:

    def test_scan_file_returns_list(self):
        results = scan_file(DEFAULT_TARGET)
        assert isinstance(results, list)

    def test_auth001_detected_by_custom_rules(self):
        results = scan_file(DEFAULT_TARGET)
        rule_ids = [f["rule"] for f in results]
        assert "AUTH001" in rule_ids, (
            "Custom scanner must detect AUTH001 in vulnerable_app.py"
        )

    def test_every_custom_finding_has_required_fields(self):
        required = {"rule", "type", "line", "evidence", "severity"}
        for f in scan_file(DEFAULT_TARGET):
            missing = required - f.keys()
            assert not missing, f"Custom finding missing fields {missing}: {f}"


# ---------------------------------------------------------------------------
# Comparison logic
# ---------------------------------------------------------------------------

class TestCompareFindings:

    def test_returns_required_keys(self):
        report = compare_findings(
            run_bandit(DEFAULT_TARGET),
            scan_file(DEFAULT_TARGET),
        )
        assert "bandit_only" in report
        assert "custom_only" in report
        assert "overlap" in report

    def test_custom_only_contains_auth001(self):
        """AUTH001 (BOLA) is a VerifiX-specific rule — Bandit does not flag it."""
        report = compare_findings(
            run_bandit(DEFAULT_TARGET),
            scan_file(DEFAULT_TARGET),
        )
        custom_only_rules = {f["rule"] for f in report["custom_only"]}
        assert "AUTH001" in custom_only_rules, (
            "AUTH001 should appear in custom_only since Bandit cannot detect BOLA"
        )

    def test_all_findings_accounted_for(self):
        bandit = run_bandit(DEFAULT_TARGET)
        custom = scan_file(DEFAULT_TARGET)
        report = compare_findings(bandit, custom)
        accounted_bandit = (
            len(report["bandit_only"])
            + len(report["overlap"]["bandit_findings"])
        )
        accounted_custom = (
            len(report["custom_only"])
            + len(report["overlap"]["custom_findings"])
        )
        assert accounted_bandit == len(bandit), (
            "Every Bandit finding must be in either bandit_only or overlap"
        )
        assert accounted_custom == len(custom), (
            "Every custom finding must be in either custom_only or overlap"
        )

    def test_overlap_is_dict_with_both_keys(self):
        report = compare_findings([], [])
        assert "bandit_findings" in report["overlap"]
        assert "custom_findings" in report["overlap"]

    def test_empty_inputs_produce_empty_output(self):
        report = compare_findings([], [])
        assert report["bandit_only"] == []
        assert report["custom_only"] == []
        assert report["overlap"]["bandit_findings"] == []
        assert report["overlap"]["custom_findings"] == []


# ---------------------------------------------------------------------------
# Baseline persistence
# ---------------------------------------------------------------------------

class TestBaselinePersistence:

    def test_save_and_load_roundtrip(self, tmp_path):
        findings = run_bandit(DEFAULT_TARGET)
        baseline_path = tmp_path / "test_baseline.json"
        save_baseline(findings, baseline_path)
        loaded = load_baseline(baseline_path)
        assert len(loaded) == len(findings)
        assert loaded[0]["rule"] == findings[0]["rule"]

    def test_load_missing_raises_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_baseline(tmp_path / "nonexistent_baseline.json")

    def test_save_creates_valid_json(self, tmp_path):
        import json
        findings = run_bandit(DEFAULT_TARGET)
        path = tmp_path / "baseline.json"
        save_baseline(findings, path)
        loaded = json.loads(path.read_text())
        assert isinstance(loaded, list)
