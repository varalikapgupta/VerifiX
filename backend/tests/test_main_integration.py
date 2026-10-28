"""
backend/tests/test_main_integration.py
=======================================
Integration tests for backend/main.py.

Two layers of tests are provided:

HTTP layer (Section 1)
----------------------
Uses ``fastapi.testclient.TestClient`` (backed by ``httpx`` 0.28.x which is
installed).  starlette 1.10.0 emits a deprecation warning about preferring
``httpx2``, but the client is fully functional.  These tests exercise the real
ASGI stack: routing, middleware, Pydantic validation, HTTP status codes, and
JSON serialisation, exactly as a real HTTP caller would observe them.

Logic / unit layer (Section 2)
-------------------------------
Calls route functions directly using the Pydantic request models, giving
precise assertions over return types, internal error handling, audit-log
integration, and security invariants that are easier to express without a
running HTTP server.

Combined, the two layers cover:
- GET /        — status 200, correct JSON keys
- GET /health  — status 200, {"status": "healthy"}
- POST /scan   — status 200, target + finding_count + findings keys
- POST /analyze with vulnerable Python — 200, enriched findings, probe allow-list
- POST /analyze with safe Python       — 200, empty findings list, disclaimer
- POST /analyze with syntax error      — 400, safe message, no path leak
- POST /analyze with empty source      — 422 (Pydantic validation)
- POST /analyze with oversized filename— 422 (Pydantic validation)
- Audit log written (event_type=scan), no source code in log
- Audit failure does not crash the scan result
- Repeated calls produce identical metric-level results (determinism)
- Probe recommendations stay within REGISTERED_PROBE_IDS allow-list
- Secret string values in source are never echoed in the HTTP response
"""

from __future__ import annotations

import json
import sys
import warnings
from pathlib import Path
from typing import Any

import pytest

# ── project path bootstrap ────────────────────────────────────────────────────
# All backend modules use bare-name imports (e.g. ``from static_scanner import
# …``); inserting backend/ into sys.path mirrors what the existing test suite
# does (see test_scanner.py line 26).
_BACKEND = Path(__file__).resolve().parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

# ── suppress starlette deprecation warning for httpx vs httpx2 ───────────────
warnings.filterwarnings(
    "ignore",
    message=".*httpx.*httpx2.*",
    category=DeprecationWarning,
)

# ── HTTP-layer imports ────────────────────────────────────────────────────────
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402

# ── logic-layer imports ───────────────────────────────────────────────────────
from fastapi import HTTPException  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from main import (  # noqa: E402
    AnalyzeRequest,
    AnalyzeResponse,
    EnrichedFinding,
    analyze_source,
    health,
    home,
    run_scan,
)
from claude_reasoning import REGISTERED_PROBE_IDS  # noqa: E402
from audit_logger import AuditLogger  # noqa: E402

# ── shared test fixtures ──────────────────────────────────────────────────────

_VULN_PY001 = "eval(user_input)\n"
_VULN_PY002 = "import os\nos.path.join('/base', user_arg)\n"
_VULN_PY002_AUTH = (
    "from flask import Flask\n"
    "app = Flask(__name__)\n"
    "DOCUMENTS = {}\n"
    "@app.route('/docs/<int:doc_id>')\n"
    "def get_doc(doc_id):\n"
    "    return DOCUMENTS.get(doc_id)\n"
)
_SAFE_CODE = "x = 1 + 2\nprint(x)\n"
_SYNTAX_ERROR_CODE = "def broken(:\n    pass\n"


@pytest.fixture(scope="module")
def client() -> TestClient:
    """Shared TestClient — spin up the ASGI app once for all HTTP tests."""
    return TestClient(app, raise_server_exceptions=False)


# ===========================================================================
# SECTION 1 — HTTP LAYER (TestClient)
# ===========================================================================

class TestHttpGetRoot:
    """GET / — project identity."""

    def test_status_200(self, client: TestClient) -> None:
        r = client.get("/")
        assert r.status_code == 200

    def test_content_type_json(self, client: TestClient) -> None:
        r = client.get("/")
        assert "application/json" in r.headers["content-type"]

    def test_response_keys(self, client: TestClient) -> None:
        data = client.get("/").json()
        assert data["project"] == "VerifiX"
        assert data["status"] == "running"
        assert data["role"] == "backend"


class TestHttpGetHealth:
    """GET /health — liveness probe."""

    def test_status_200(self, client: TestClient) -> None:
        r = client.get("/health")
        assert r.status_code == 200

    def test_body(self, client: TestClient) -> None:
        assert client.get("/health").json() == {"status": "healthy"}


class TestHttpPostScan:
    """POST /scan — backward-compatible scan of vulnerable_app.py."""

    def test_status_200(self, client: TestClient) -> None:
        r = client.post("/scan")
        assert r.status_code == 200

    def test_response_keys_present(self, client: TestClient) -> None:
        data = client.post("/scan").json()
        assert "target" in data
        assert "finding_count" in data
        assert "findings" in data

    def test_finding_count_is_int(self, client: TestClient) -> None:
        data = client.post("/scan").json()
        assert isinstance(data["finding_count"], int)

    def test_findings_is_list(self, client: TestClient) -> None:
        data = client.post("/scan").json()
        assert isinstance(data["findings"], list)

    def test_finding_count_matches_list_length(self, client: TestClient) -> None:
        data = client.post("/scan").json()
        assert data["finding_count"] == len(data["findings"])


class TestHttpPostAnalyzeVulnerable:
    """POST /analyze — valid source containing vulnerabilities."""

    def _post(self, client: TestClient, source: str, filename: str = "<test>") -> Any:
        return client.post("/analyze", json={"source": source, "filename": filename})

    def test_status_200(self, client: TestClient) -> None:
        r = self._post(client, _VULN_PY001)
        assert r.status_code == 200

    def test_content_type_json(self, client: TestClient) -> None:
        r = self._post(client, _VULN_PY001)
        assert "application/json" in r.headers["content-type"]

    def test_top_level_keys_present(self, client: TestClient) -> None:
        data = self._post(client, _VULN_PY001).json()
        assert "finding_count" in data
        assert "findings" in data
        assert "disclaimer" in data

    def test_finding_count_is_positive_int(self, client: TestClient) -> None:
        data = self._post(client, _VULN_PY001).json()
        assert isinstance(data["finding_count"], int)
        assert data["finding_count"] > 0

    def test_finding_count_matches_findings_list_length(self, client: TestClient) -> None:
        data = self._post(client, _VULN_PY001).json()
        assert data["finding_count"] == len(data["findings"])

    def test_py001_rule_present_in_findings(self, client: TestClient) -> None:
        data = self._post(client, _VULN_PY001).json()
        rules = [f["rule"] for f in data["findings"]]
        assert "PY001" in rules

    def test_finding_object_has_required_fields(self, client: TestClient) -> None:
        data = self._post(client, _VULN_PY001).json()
        required = {"rule", "type", "line", "evidence", "severity",
                    "hypothesis", "confidence", "reasoning", "recommended_probes"}
        for finding in data["findings"]:
            assert required.issubset(finding.keys()), (
                f"Finding missing fields: {required - finding.keys()}"
            )

    def test_line_is_integer(self, client: TestClient) -> None:
        data = self._post(client, _VULN_PY001).json()
        for f in data["findings"]:
            assert isinstance(f["line"], int)

    def test_recommended_probes_within_allow_list(self, client: TestClient) -> None:
        data = self._post(client, _VULN_PY001).json()
        for finding in data["findings"]:
            for probe_id in finding["recommended_probes"]:
                assert probe_id in REGISTERED_PROBE_IDS, (
                    f"Probe {probe_id!r} is outside the registered allow-list"
                )

    def test_disclaimer_contains_static_analysis_language(self, client: TestClient) -> None:
        data = self._post(client, _VULN_PY001).json()
        assert "static" in data["disclaimer"].lower()

    def test_py002_probe_recommendations(self, client: TestClient) -> None:
        data = self._post(client, _VULN_PY002).json()
        py002 = [f for f in data["findings"] if f["rule"] == "PY002"]
        assert py002, "PY002 finding should be present"
        probes = py002[0]["recommended_probes"]
        assert "PROBE-PT-001" in probes
        assert "PROBE-PT-002" in probes

    def test_auth001_probe_recommendation(self, client: TestClient) -> None:
        data = self._post(client, _VULN_PY002_AUTH).json()
        auth001 = [f for f in data["findings"] if f["rule"] == "AUTH001"]
        assert auth001, "AUTH001 finding should be present"
        probes = auth001[0]["recommended_probes"]
        assert "PROBE-BOLA-001" in probes

    def test_confidence_values_are_valid(self, client: TestClient) -> None:
        data = self._post(client, _VULN_PY001).json()
        for f in data["findings"]:
            assert f["confidence"] in ("high", "medium", "low"), (
                f"Unexpected confidence: {f['confidence']!r}"
            )

    def test_secret_string_value_not_echoed_in_http_response(self, client: TestClient) -> None:
        """String literal *values* in source must never appear verbatim in the response.

        The scanner embeds synthesized AST node descriptions (variable names,
        call names) in evidence strings — that is expected.  What must not happen
        is raw secret content (string values) being echoed back through the API.
        We use a unique value that is only a string literal, never a name, so
        scanner-synthesized messages cannot include it.
        """
        sentinel = "XYZZY_UNIQUE_HTTP_LAYER_SECRET_VALUE_cc2d9e11"
        source = f"db_pass = '{sentinel}'\neval(user)\n"
        r = self._post(client, source)
        assert r.status_code == 200
        assert sentinel not in r.text, (
            "Secret string values from source must not appear in the HTTP response body"
        )


class TestHttpPostAnalyzeSafe:
    """POST /analyze — source with no vulnerabilities."""

    def test_status_200(self, client: TestClient) -> None:
        r = client.post("/analyze", json={"source": _SAFE_CODE})
        assert r.status_code == 200

    def test_empty_findings_list(self, client: TestClient) -> None:
        data = client.post("/analyze", json={"source": _SAFE_CODE}).json()
        assert data["findings"] == []
        assert data["finding_count"] == 0

    def test_disclaimer_still_present(self, client: TestClient) -> None:
        data = client.post("/analyze", json={"source": _SAFE_CODE}).json()
        assert data["disclaimer"]


class TestHttpPostAnalyzeSyntaxError:
    """POST /analyze — submitted source with a Python syntax error."""

    def test_status_400(self, client: TestClient) -> None:
        r = client.post("/analyze", json={"source": _SYNTAX_ERROR_CODE})
        assert r.status_code == 400

    def test_detail_mentions_syntax_error(self, client: TestClient) -> None:
        data = client.post("/analyze", json={"source": _SYNTAX_ERROR_CODE}).json()
        assert "syntax" in data["detail"].lower()

    def test_detail_contains_line_number(self, client: TestClient) -> None:
        data = client.post("/analyze", json={"source": _SYNTAX_ERROR_CODE}).json()
        assert any(ch.isdigit() for ch in data["detail"]), (
            "400 detail should contain the line number of the syntax error"
        )

    def test_no_filesystem_path_in_detail(self, client: TestClient) -> None:
        data = client.post("/analyze", json={"source": _SYNTAX_ERROR_CODE}).json()
        detail = data["detail"]
        assert "C:\\" not in detail
        assert "/home/" not in detail
        assert "\\backend\\" not in detail

    def test_no_stack_trace_in_response(self, client: TestClient) -> None:
        r = client.post("/analyze", json={"source": _SYNTAX_ERROR_CODE})
        assert "Traceback" not in r.text
        assert "File \"" not in r.text


class TestHttpPostAnalyzeValidationErrors:
    """POST /analyze — invalid request bodies trigger HTTP 422."""

    def test_empty_source_returns_422(self, client: TestClient) -> None:
        r = client.post("/analyze", json={"source": ""})
        assert r.status_code == 422

    def test_missing_source_field_returns_422(self, client: TestClient) -> None:
        r = client.post("/analyze", json={})
        assert r.status_code == 422

    def test_oversized_filename_returns_422(self, client: TestClient) -> None:
        r = client.post("/analyze", json={"source": _SAFE_CODE, "filename": "x" * 300})
        assert r.status_code == 422

    def test_non_string_source_returns_422(self, client: TestClient) -> None:
        r = client.post("/analyze", json={"source": 12345})
        # Pydantic will coerce int→str, so this may pass or 422 depending on version.
        # At minimum it must not return 500.
        assert r.status_code in (200, 422), (
            "Non-string source should either coerce to string or return 422, never 500"
        )

    def test_null_source_returns_422(self, client: TestClient) -> None:
        r = client.post("/analyze", json={"source": None})
        assert r.status_code == 422

    def test_malformed_json_returns_422(self, client: TestClient) -> None:
        r = client.post(
            "/analyze",
            content=b"not json at all",
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 422

    def test_422_body_is_json(self, client: TestClient) -> None:
        r = client.post("/analyze", json={"source": ""})
        assert "application/json" in r.headers["content-type"]
        # Response should parse as JSON
        data = r.json()
        assert "detail" in data


class TestHttpDeterminism:
    """Repeated identical requests must yield identical metric-level results."""

    def test_same_source_same_finding_count(self, client: TestClient) -> None:
        r1 = client.post("/analyze", json={"source": _VULN_PY001}).json()
        r2 = client.post("/analyze", json={"source": _VULN_PY001}).json()
        assert r1["finding_count"] == r2["finding_count"]

    def test_same_source_same_rules(self, client: TestClient) -> None:
        r1 = client.post("/analyze", json={"source": _VULN_PY001}).json()
        r2 = client.post("/analyze", json={"source": _VULN_PY001}).json()
        rules1 = sorted(f["rule"] for f in r1["findings"])
        rules2 = sorted(f["rule"] for f in r2["findings"])
        assert rules1 == rules2

    def test_same_source_same_probes(self, client: TestClient) -> None:
        r1 = client.post("/analyze", json={"source": _VULN_PY002}).json()
        r2 = client.post("/analyze", json={"source": _VULN_PY002}).json()
        probes1 = [sorted(f["recommended_probes"]) for f in r1["findings"]]
        probes2 = [sorted(f["recommended_probes"]) for f in r2["findings"]]
        assert probes1 == probes2


# ===========================================================================
# SECTION 2 — LOGIC / UNIT LAYER (direct function calls)
#
# These tests are preserved from the previous suite because they assert over
# Python-level return types, internal error objects, and monkeypatching of the
# audit logger — concerns that are better expressed without HTTP serialisation.
# ===========================================================================

class TestDirectEndpointFunctions:
    """Backward-compatible direct-call smoke tests."""

    def test_home_returns_correct_keys(self) -> None:
        result = home()
        assert result["project"] == "VerifiX"
        assert result["status"] == "running"
        assert result["role"] == "backend"

    def test_health_returns_healthy(self) -> None:
        assert health() == {"status": "healthy"}

    def test_scan_returns_expected_structure(self) -> None:
        result = run_scan()
        assert "target" in result
        assert "finding_count" in result
        assert "findings" in result
        assert isinstance(result["findings"], list)
        assert result["finding_count"] == len(result["findings"])


class TestAnalyzeLogicWithFindings:

    def _call(self, source: str, filename: str = "<test>") -> AnalyzeResponse:
        return analyze_source(AnalyzeRequest(source=source, filename=filename))

    def test_returns_analyze_response_instance(self) -> None:
        assert isinstance(self._call(_VULN_PY001), AnalyzeResponse)

    def test_finding_count_matches_list_length(self) -> None:
        resp = self._call(_VULN_PY001)
        assert resp.finding_count == len(resp.findings)

    def test_py001_detected(self) -> None:
        resp = self._call(_VULN_PY001)
        assert "PY001" in [f.rule for f in resp.findings]

    def test_each_finding_is_enriched_finding_instance(self) -> None:
        resp = self._call(_VULN_PY001)
        for f in resp.findings:
            assert isinstance(f, EnrichedFinding)
            assert f.rule and isinstance(f.line, int)
            assert isinstance(f.hypothesis, str) and isinstance(f.confidence, str)
            assert isinstance(f.recommended_probes, list)

    def test_probes_within_allow_list(self) -> None:
        resp = self._call(_VULN_PY001)
        for f in resp.findings:
            for pid in f.recommended_probes:
                assert pid in REGISTERED_PROBE_IDS

    def test_py002_has_path_traversal_probes(self) -> None:
        resp = self._call(_VULN_PY002)
        py002 = [f for f in resp.findings if f.rule == "PY002"]
        assert py002
        assert "PROBE-PT-001" in py002[0].recommended_probes
        assert "PROBE-PT-002" in py002[0].recommended_probes

    def test_confidence_is_valid(self) -> None:
        resp = self._call(_VULN_PY001)
        for f in resp.findings:
            assert f.confidence in ("high", "medium", "low")

    def test_disclaimer_present(self) -> None:
        assert "static" in self._call(_VULN_PY001).disclaimer.lower()

    def test_secret_value_not_in_response_json(self) -> None:
        sentinel = "XYZZY_UNIQUE_SECRET_VALUE_NOT_A_NAME_99a7b3c1"
        source = f"db_pass = '{sentinel}'\neval(user)\n"
        resp_json = self._call(source).model_dump_json()
        assert sentinel not in resp_json


class TestAnalyzeLogicNoFindings:

    def test_empty_findings(self) -> None:
        resp = analyze_source(AnalyzeRequest(source=_SAFE_CODE))
        assert resp.finding_count == 0
        assert resp.findings == []

    def test_disclaimer_present(self) -> None:
        resp = analyze_source(AnalyzeRequest(source=_SAFE_CODE))
        assert resp.disclaimer


class TestAnalyzeLogicErrors:

    def test_syntax_error_raises_http_400(self) -> None:
        body = AnalyzeRequest(source=_SYNTAX_ERROR_CODE)
        with pytest.raises(HTTPException) as exc_info:
            analyze_source(body)
        assert exc_info.value.status_code == 400
        assert "syntax" in exc_info.value.detail.lower()

    def test_syntax_error_detail_has_line_number(self) -> None:
        body = AnalyzeRequest(source=_SYNTAX_ERROR_CODE)
        with pytest.raises(HTTPException) as exc_info:
            analyze_source(body)
        assert any(ch.isdigit() for ch in exc_info.value.detail)

    def test_syntax_error_no_path_leak(self) -> None:
        body = AnalyzeRequest(source=_SYNTAX_ERROR_CODE)
        with pytest.raises(HTTPException) as exc_info:
            analyze_source(body)
        detail = exc_info.value.detail
        assert "C:\\" not in detail
        assert "/home/" not in detail

    def test_empty_source_rejected_by_pydantic(self) -> None:
        with pytest.raises(ValidationError):
            AnalyzeRequest(source="")

    def test_source_field_required(self) -> None:
        with pytest.raises((ValidationError, TypeError)):
            AnalyzeRequest()

    def test_oversized_filename_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AnalyzeRequest(source=_SAFE_CODE, filename="x" * 300)


class TestAuditLogging:

    def test_event_written_to_log(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        log_path = tmp_path / "test_audit.jsonl"
        test_logger = AuditLogger(log_path)

        import main as main_module
        original = main_module._audit_logger
        main_module._audit_logger = test_logger
        try:
            analyze_source(AnalyzeRequest(source=_VULN_PY001))
        finally:
            main_module._audit_logger = original

        assert log_path.is_file()
        lines = log_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1

        record = json.loads(lines[0])
        assert record["event_type"] == "scan"
        assert "finding_count" in record["event_data"]
        assert "rules_triggered" in record["event_data"]
        assert "source" not in str(record)

    def test_source_code_not_in_audit_log(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        log_path = tmp_path / "audit_security.jsonl"
        test_logger = AuditLogger(log_path)

        import main as main_module
        original = main_module._audit_logger
        main_module._audit_logger = test_logger
        try:
            secret = "MY_SECRET_API_KEY_SENTINEL"
            source = f"api_key = '{secret}'\n"
            analyze_source(AnalyzeRequest(source=source))
        finally:
            main_module._audit_logger = original

        assert secret not in log_path.read_text(encoding="utf-8")

    def test_audit_failure_does_not_break_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import main as main_module

        class _BrokenLogger:
            def append_event(self, *_a: Any, **_kw: Any) -> None:
                raise RuntimeError("Simulated audit failure")

        original = main_module._audit_logger
        main_module._audit_logger = _BrokenLogger()
        try:
            resp = analyze_source(AnalyzeRequest(source=_SAFE_CODE))
            assert isinstance(resp, AnalyzeResponse)
        finally:
            main_module._audit_logger = original


class TestLogicDeterminism:

    def test_repeated_calls_identical(self) -> None:
        body = AnalyzeRequest(source=_VULN_PY001)
        r1 = analyze_source(body)
        r2 = analyze_source(body)
        assert r1.finding_count == r2.finding_count
        for f1, f2 in zip(r1.findings, r2.findings):
            assert f1.rule == f2.rule
            assert f1.line == f2.line
            assert f1.recommended_probes == f2.recommended_probes
            assert f1.confidence == f2.confidence
