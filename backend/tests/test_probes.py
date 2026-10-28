"""
tests/test_probes.py
====================
Runtime validation probe tests for the VerifiX security engine.

All tests in this module are automatically SKIPPED when the Flask demo
server is not running on 127.0.0.1:5001.  The scanner unit tests in
test_scanner.py remain fully independent and server-free.

To run these tests:
    # Terminal 1
    python backend/vulnerable_app.py

    # Terminal 2
    backend/.venv/Scripts/python.exe -m pytest backend/tests/test_probes.py -v
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from probes import (  # noqa: E402
    ProbeResult,
    flask_is_running,
    probe_bola_001,
    probe_pt_001,
    probe_pt_002,
    probe_sql_001,
    probe_sql_002,
    run_all_probes,
    run_probe,
)

# ---------------------------------------------------------------------------
# Module-level skip: every test in this file requires the Flask server.
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.skipif(
    not flask_is_running(),
    reason="Flask demo server not running on 127.0.0.1:5001 — "
           "start with: python backend/vulnerable_app.py",
)


# ---------------------------------------------------------------------------
# PROBE-PT-001 — Path traversal (escape above SAFE_ROOT)
# ---------------------------------------------------------------------------

class TestProbePT001:

    def test_verdict_is_vulnerable(self):
        result = probe_pt_001()
        assert result.verdict == "VULNERABLE", (
            f"Expected VULNERABLE; got {result.verdict}. "
            f"Evidence: {result.evidence or result.error}"
        )

    def test_http_status_200(self):
        result = probe_pt_001()
        assert result.http_status == 200, (
            f"Expected HTTP 200; got {result.http_status}"
        )

    def test_evidence_nonempty(self):
        result = probe_pt_001()
        assert result.evidence, "Evidence field must not be empty"

    def test_probe_id(self):
        result = probe_pt_001()
        assert result.probe_id == "PROBE-PT-001"

    def test_scanner_rule_is_py002(self):
        result = probe_pt_001()
        assert result.scanner_rule == "PY002"


# ---------------------------------------------------------------------------
# PROBE-PT-002 — Path traversal baseline (in-bounds read)
# ---------------------------------------------------------------------------

class TestProbePT002:

    def test_verdict_is_safe(self):
        result = probe_pt_002()
        assert result.verdict == "SAFE", (
            f"Expected SAFE; got {result.verdict}. "
            f"Evidence: {result.evidence or result.error}"
        )

    def test_http_status_200(self):
        result = probe_pt_002()
        assert result.http_status == 200

    def test_content_contains_sample_content(self):
        result = probe_pt_002()
        assert "Public" in result.evidence or "sample" in result.evidence, (
            "In-bounds read should return public sample file content"
        )

    def test_probe_id(self):
        assert probe_pt_002().probe_id == "PROBE-PT-002"


# ---------------------------------------------------------------------------
# PROBE-SQL-001 — SQL injection baseline (valid user lookup)
# ---------------------------------------------------------------------------

class TestProbeSQL001:

    def test_verdict_is_safe(self):
        result = probe_sql_001()
        assert result.verdict == "SAFE", (
            f"Expected SAFE; got {result.verdict}. "
            f"Evidence: {result.evidence or result.error}"
        )

    def test_http_status_200(self):
        result = probe_sql_001()
        assert result.http_status == 200

    def test_email_in_evidence(self):
        result = probe_sql_001()
        assert "@" in result.evidence, "Evidence should contain alice's email"

    def test_probe_id(self):
        assert probe_sql_001().probe_id == "PROBE-SQL-001"

    def test_scanner_rule_is_py003(self):
        assert probe_sql_001().scanner_rule == "PY003"


# ---------------------------------------------------------------------------
# PROBE-SQL-002 — SQL injection: payload echoed in simulated query
# ---------------------------------------------------------------------------

class TestProbeSQL002:

    def test_verdict_is_vulnerable(self):
        result = probe_sql_002()
        assert result.verdict == "VULNERABLE", (
            f"Expected VULNERABLE; got {result.verdict}. "
            f"Evidence: {result.evidence or result.error}"
        )

    def test_payload_echoed_in_evidence(self):
        result = probe_sql_002()
        assert "OR" in result.evidence, (
            "The injection payload should be echoed in query_simulated"
        )

    def test_probe_id(self):
        assert probe_sql_002().probe_id == "PROBE-SQL-002"


# ---------------------------------------------------------------------------
# PROBE-BOLA-001 — BOLA: cross-user document access
# ---------------------------------------------------------------------------

class TestProbeBOLA001:

    def test_verdict_is_vulnerable(self):
        result = probe_bola_001()
        assert result.verdict == "VULNERABLE", (
            f"Expected VULNERABLE; got {result.verdict}. "
            f"Evidence: {result.evidence or result.error}"
        )

    def test_http_status_200(self):
        result = probe_bola_001()
        assert result.http_status == 200

    def test_owner_is_bob_in_evidence(self):
        result = probe_bola_001()
        assert "bob" in result.evidence, "Evidence should confirm owner=bob"

    def test_probe_id(self):
        assert probe_bola_001().probe_id == "PROBE-BOLA-001"

    def test_scanner_rule_is_auth001(self):
        assert probe_bola_001().scanner_rule == "AUTH001"


# ---------------------------------------------------------------------------
# run_all_probes() and run_probe() API
# ---------------------------------------------------------------------------

class TestProbeAPI:

    def test_run_all_probes_returns_five_results(self):
        results = run_all_probes()
        assert len(results) == 5

    def test_run_all_probes_all_have_probe_id(self):
        for r in run_all_probes():
            assert r.probe_id.startswith("PROBE-"), (
                f"Missing or malformed probe_id: {r.probe_id!r}"
            )

    def test_run_all_probes_no_errors(self):
        for r in run_all_probes():
            assert r.verdict != "ERROR", (
                f"{r.probe_id} returned ERROR: {r.error}"
            )

    def test_run_probe_by_id_pt001(self):
        result = run_probe("PROBE-PT-001")
        assert isinstance(result, ProbeResult)
        assert result.probe_id == "PROBE-PT-001"

    def test_run_probe_unknown_id_raises(self):
        with pytest.raises(KeyError):
            run_probe("PROBE-UNKNOWN-999")

    def test_probe_result_fields_present(self):
        """Every ProbeResult must carry the full required schema."""
        for r in run_all_probes():
            assert r.probe_id
            assert r.description
            assert r.method in {"GET", "POST"}
            assert r.url.startswith("http://127.0.0.1:5001")
            assert r.expected_verdict in {"VULNERABLE", "SAFE"}
            assert r.verdict in {"VULNERABLE", "SAFE", "ERROR"}
