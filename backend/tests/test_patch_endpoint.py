"""
backend/tests/test_patch_endpoint.py
====================================
Comprehensive tests for the /patch endpoint in backend/main.py.

Covers:
- Successful sandbox patch application and structured response fields
- Original target file immutability (never modified)
- Unsupported patch rule rejection (400)
- Patch pattern mismatch handling (400)
- Syntax-validation failure handling (400)
- Audit-log recording and audit failure resilience
- Generic 500 internal error handling (no stack/internal details leaked)
- Request payload validation (422)
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

# Ensure backend/ is in sys.path
_BACKEND = Path(__file__).resolve().parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from main import TARGET_FILE, app, apply_patch_endpoint, PatchRequest  # noqa: E402
from sandbox_patcher import PatchResult, cleanup_sandbox, compute_sha256  # noqa: E402
from audit_logger import AuditLogger  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


class TestPatchEndpointSuccess:
    """Tests for successful application of approved sandbox patches."""

    def test_apply_patch_py002_success_fields(self, client: TestClient) -> None:
        """Applying PY002 patch returns HTTP 200 with all required fields."""
        resp = client.post("/patch", json={"rule": "PY002"})
        assert resp.status_code == 200
        data = resp.json()

        assert data["status"] == "APPLIED"
        assert data["rule"] == "PY002"
        assert data["syntax_valid"] is True
        assert data["original_modified"] is False
        assert "Pending runtime probe" in data["verification"]
        assert isinstance(data["message"], str) and len(data["message"]) > 0

        # Hashes
        target_hash = compute_sha256(TARGET_FILE)
        assert data["original_hash"] == target_hash
        assert data["patched_hash"] is not None
        assert data["patched_hash"] != target_hash

        # Sandbox copy
        sandbox_path = Path(data["sandbox_path"])
        assert sandbox_path.exists()
        assert sandbox_path.is_file()
        assert sandbox_path.resolve() != TARGET_FILE.resolve()

        # Content verification in sandbox copy
        content = sandbox_path.read_text(encoding="utf-8")
        assert "os.path.basename" in content
        assert "DEMO_PUBLIC_DIR" in content

        # Cleanup
        cleanup_sandbox(sandbox_path.parent)

    def test_default_rule_is_py002(self, client: TestClient) -> None:
        """Calling /patch with empty body {} defaults to PY002 and succeeds."""
        resp = client.post("/patch", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "APPLIED"
        assert data["rule"] == "PY002"
        cleanup_sandbox(Path(data["sandbox_path"]).parent)


class TestPatchEndpointImmutability:
    """Tests ensuring the original demo application file is never modified."""

    def test_original_file_strictly_unmodified(self, client: TestClient) -> None:
        """Original vulnerable_app.py must remain byte-identical before and after /patch."""
        initial_bytes = TARGET_FILE.read_bytes()
        initial_hash = compute_sha256(TARGET_FILE)

        resp = client.post("/patch", json={"rule": "PY002"})
        assert resp.status_code == 200

        data = resp.json()
        assert data["original_modified"] is False

        post_bytes = TARGET_FILE.read_bytes()
        post_hash = compute_sha256(TARGET_FILE)

        assert post_bytes == initial_bytes
        assert post_hash == initial_hash

        cleanup_sandbox(Path(data["sandbox_path"]).parent)


class TestPatchEndpointUnsupportedRules:
    """Tests rejecting unsupported patch rules safely."""

    @pytest.mark.parametrize("bad_rule", ["PY001", "PY003", "PY004", "AUTH001", "UNKNOWN_RULE"])
    def test_unsupported_rules_rejected_with_400(self, client: TestClient, bad_rule: str) -> None:
        resp = client.post("/patch", json={"rule": bad_rule})
        assert resp.status_code == 400
        data = resp.json()
        assert "Unsupported patch rule" in data["detail"]
        assert "PY002" in data["detail"]

    def test_oversized_rule_rejected_by_pydantic(self, client: TestClient) -> None:
        resp = client.post("/patch", json={"rule": "X" * 64})
        assert resp.status_code == 422


class TestPatchEndpointFailureHandling:
    """Tests handling of pattern mismatch, syntax validation errors, and exceptions."""

    def test_pattern_mismatch_returns_400(self, client: TestClient) -> None:
        """When apply_sandbox_patch returns PATTERN_MISMATCH, endpoint returns 400."""
        mismatch_result = PatchResult(
            status="PATTERN_MISMATCH",
            rule="PY002",
            message="Source does not contain recognized vulnerable pattern.",
            original_path=str(TARGET_FILE),
            original_hash="dummy_hash",
            syntax_valid=True,
        )

        with patch("sandbox_patcher.apply_sandbox_patch", return_value=mismatch_result):
            resp = client.post("/patch", json={"rule": "PY002"})
            assert resp.status_code == 400
            assert "Source does not contain recognized vulnerable pattern" in resp.json()["detail"]

    def test_syntax_validation_failure_returns_400(self, client: TestClient) -> None:
        """When apply_sandbox_patch returns syntax_valid=False, endpoint returns 400."""
        syntax_err_result = PatchResult(
            status="SYNTAX_ERROR",
            rule="PY002",
            message="Patched code failed syntax validation: SyntaxError at line 10",
            original_path=str(TARGET_FILE),
            original_hash="dummy_hash",
            syntax_valid=False,
        )

        with patch("sandbox_patcher.apply_sandbox_patch", return_value=syntax_err_result):
            resp = client.post("/patch", json={"rule": "PY002"})
            assert resp.status_code == 400
            assert "syntax" in resp.json()["detail"].lower()

    def test_unexpected_exception_returns_sanitized_500(self, client: TestClient) -> None:
        """Unexpected internal exceptions must return 500 without leaking stack or internal detail."""
        with patch("sandbox_patcher.apply_sandbox_patch", side_effect=RuntimeError("internal_leak_secret_value")):
            resp = client.post("/patch", json={"rule": "PY002"})
            assert resp.status_code == 500
            detail = resp.json()["detail"]
            assert "internal_leak_secret_value" not in detail
            assert "Sandbox patch operation failed due to an internal error." in detail


class TestPatchEndpointAuditLogging:
    """Tests for audit-log recording and error resilience."""

    def test_audit_event_recorded_on_patch(self, client: TestClient, tmp_path: Path) -> None:
        log_path = tmp_path / "test_patch_audit.jsonl"
        test_logger = AuditLogger(log_path)

        import main as main_module
        orig_logger = main_module._audit_logger
        main_module._audit_logger = test_logger
        try:
            resp = client.post("/patch", json={"rule": "PY002"})
            assert resp.status_code == 200
            cleanup_sandbox(Path(resp.json()["sandbox_path"]).parent)
        finally:
            main_module._audit_logger = orig_logger

        assert log_path.exists()
        lines = log_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) >= 1

        record = json.loads(lines[-1])
        assert record["event_type"] == "sandbox_patch"
        assert record["event_data"]["rule"] == "PY002"
        assert record["event_data"]["status"] == "APPLIED"
        assert "original_hash" in record["event_data"]
        assert "patched_hash" in record["event_data"]

    def test_audit_failure_does_not_break_patch_response(self, client: TestClient) -> None:
        """If audit logging fails, the patch endpoint still succeeds."""
        class _FailingLogger:
            def append_event(self, *_a: Any, **_kw: Any) -> None:
                raise RuntimeError("Disk write failed")

        import main as main_module
        orig_logger = main_module._audit_logger
        main_module._audit_logger = _FailingLogger()
        try:
            resp = client.post("/patch", json={"rule": "PY002"})
            assert resp.status_code == 200
            assert resp.json()["status"] == "APPLIED"
            cleanup_sandbox(Path(resp.json()["sandbox_path"]).parent)
        finally:
            main_module._audit_logger = orig_logger


class TestVerificationAndAuditEndpoints:
    """Tests for GET /audit and POST /verify endpoints."""

    def test_get_audit_trail_success(self, client: TestClient) -> None:
        resp = client.get("/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert "valid" in data
        assert "records_checked" in data
        assert "records" in data
        assert isinstance(data["records"], list)

    def test_post_verify_workflow_success(self, client: TestClient) -> None:
        resp = client.post("/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] in ("VERIFIED", "FAILED")
        assert "stages" in data
        assert "static_scan" in data["stages"]
        assert "runtime_security_probes" in data["stages"]
        assert "regression_tests" in data["stages"]
        assert "audit_verification" in data["stages"]
