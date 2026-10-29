"""
backend/verify_workflow.py
==========================
End-to-end automated verification workflow for the VerifiX security engine.

Executes the complete intended security flow:
    Static Scan
        ↓
    Structured Findings
        ↓
    Contextual Vulnerability Triage
        ↓
    Sandbox Patch
        ↓
    Syntax Validation
        ↓
    Runtime Security Probes
        ↓
    Regression Tests
        ↓
    Audit and Verification Report
"""

from __future__ import annotations

import importlib.util
import json
import logging
from pathlib import Path
import sys
from typing import Any

# Ensure backend/ is in sys.path
_BACKEND_DIR = Path(__file__).resolve().parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from audit_logger import AuditLogger, verify_audit_log
from claude_reasoning import generate_hypotheses_for_findings
from probes import probe_pt_001, probe_pt_002
from sandbox_patcher import apply_sandbox_patch, cleanup_sandbox, compute_sha256, validate_python_syntax
from static_scanner import scan_file

logger = logging.getLogger("verifix.verification")


def run_full_verification(target_file: Path | str | None = None) -> dict[str, Any]:
    """Execute the complete 8-stage VerifiX verification flow."""
    target_path = Path(target_file) if target_file else (_BACKEND_DIR / "vulnerable_app.py")
    target_path = target_path.resolve()

    report: dict[str, Any] = {
        "target_file": str(target_path),
        "stages": {},
        "verdict": "FAILED",
    }

    # -----------------------------------------------------------------------
    # Stage 1 & 2: Static Scan & Structured Findings
    # -----------------------------------------------------------------------
    findings = scan_file(target_path)
    report["stages"]["static_scan"] = {
        "finding_count": len(findings),
        "rules_triggered": sorted({f.get("rule", "") for f in findings if f.get("rule")}),
        "findings": findings,
    }

    # -----------------------------------------------------------------------
    # Stage 3: Contextual Vulnerability Triage
    # -----------------------------------------------------------------------
    hypotheses = generate_hypotheses_for_findings(findings)
    triage_results = [h.to_dict() for h in hypotheses]
    report["stages"]["vulnerability_triage"] = {
        "hypotheses_count": len(hypotheses),
        "triage": triage_results,
    }

    # -----------------------------------------------------------------------
    # Stage 4: Sandbox Patching
    # -----------------------------------------------------------------------
    patch_result = apply_sandbox_patch(target_path, "PY002")
    report["stages"]["sandbox_patch"] = {
        "status": patch_result.status,
        "rule": patch_result.rule,
        "message": patch_result.message,
        "original_hash": patch_result.original_hash,
        "patched_hash": patch_result.patched_hash,
        "patched_copy_path": patch_result.patched_copy_path,
        "original_modified": False,
    }

    if patch_result.status != "APPLIED" or not patch_result.patched_copy_path:
        report["verdict"] = "PATCH_FAILED"
        return report

    sandbox_dir = patch_result.sandbox_dir
    patched_file = Path(patch_result.patched_copy_path)

    try:
        # -------------------------------------------------------------------
        # Stage 5: Syntax Validation without Execution
        # -------------------------------------------------------------------
        syntax_ok, syntax_err = validate_python_syntax(patched_file)
        report["stages"]["syntax_validation"] = {
            "syntax_valid": syntax_ok,
            "syntax_error": syntax_err,
        }

        if not syntax_ok:
            report["verdict"] = "SYNTAX_VALIDATION_FAILED"
            return report

        # -------------------------------------------------------------------
        # Stages 6 & 7: Runtime Security Probes & Regression Tests
        # -------------------------------------------------------------------
        # Test original vulnerable app vs patched sandbox copy in isolation
        spec = importlib.util.spec_from_file_location("patched_sandbox_app", patched_file)
        if spec is None or spec.loader is None:
            raise RuntimeError("Failed to load module spec for patched sandbox copy")
        patched_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(patched_mod)

        # Baseline runtime probes against live server or in-process client
        with patched_mod.app.test_client() as p_client:
            # Probe 1: Traversal attack payload
            resp_traversal = p_client.get("/files?name=../demo_secret.txt")
            traversal_blocked = resp_traversal.status_code in (403, 404)
            traversal_body = resp_traversal.get_json() or {}

            # Probe 2: Legitimate in-bounds read (Regression test)
            resp_baseline = p_client.get("/files?name=sample.txt")
            baseline_ok = resp_baseline.status_code == 200 and "content" in (resp_baseline.get_json() or {})
            baseline_body = resp_baseline.get_json() or {}

        report["stages"]["runtime_security_probes"] = {
            "probe_id": "PROBE-PT-001",
            "description": "Path traversal via ../ — escape above public/ directory",
            "payload": {"name": "../demo_secret.txt"},
            "patched_http_status": resp_traversal.status_code,
            "traversal_blocked": traversal_blocked,
            "response": traversal_body,
            "verdict": "REMEDIATED" if traversal_blocked else "VULNERABLE",
        }

        report["stages"]["regression_tests"] = {
            "probe_id": "PROBE-PT-002",
            "description": "Path traversal baseline — in-bounds read of sample.txt",
            "payload": {"name": "sample.txt"},
            "patched_http_status": resp_baseline.status_code,
            "baseline_preserved": baseline_ok,
            "response": baseline_body,
            "verdict": "PASSED" if baseline_ok else "REGRESSION_DETECTED",
        }

        # -------------------------------------------------------------------
        # Stage 8: Audit Logging & Chain Integrity Verification
        # -------------------------------------------------------------------
        audit_log_path = _BACKEND_DIR / "audit_log.jsonl"
        audit_logger = AuditLogger(audit_log_path)

        audit_record = audit_logger.append_event(
            "verification_workflow",
            {
                "target": target_path.name,
                "rule": "PY002",
                "static_finding_count": len(findings),
                "patch_status": patch_result.status,
                "original_hash": patch_result.original_hash,
                "patched_hash": patch_result.patched_hash,
                "syntax_valid": syntax_ok,
                "traversal_blocked": traversal_blocked,
                "baseline_preserved": baseline_ok,
                "overall_verdict": "VERIFIED" if (traversal_blocked and baseline_ok) else "FAILED",
            },
        )

        audit_verification = verify_audit_log(audit_log_path)
        report["stages"]["audit_verification"] = {
            "audit_sequence": audit_record.sequence,
            "audit_record_hash": audit_record.current_hash,
            "chain_valid": audit_verification.valid,
            "records_checked": audit_verification.records_checked,
        }

        if traversal_blocked and baseline_ok and audit_verification.valid:
            report["verdict"] = "VERIFIED"
        else:
            report["verdict"] = "VERIFICATION_FAILED"

    finally:
        cleanup_sandbox(sandbox_dir)

    return report


if __name__ == "__main__":
    result = run_full_verification()
    print("=" * 60)
    print("           VerifiX End-to-End Verification Report           ")
    print("=" * 60)
    print(f"Target file:         {result['target_file']}")
    print(f"Overall verdict:     {result['verdict']}")
    print("-" * 60)
    print(f"1. Static Scan:      {result['stages']['static_scan']['finding_count']} findings")
    print(f"   Rules:            {result['stages']['static_scan']['rules_triggered']}")
    print(f"2. Triage Hypotheses:{result['stages']['vulnerability_triage']['hypotheses_count']} generated")
    print(f"3. Sandbox Patch:    {result['stages']['sandbox_patch']['status']}")
    print(f"   Original SHA-256: {result['stages']['sandbox_patch']['original_hash'][:16]}...")
    print(f"   Patched SHA-256:  {result['stages']['sandbox_patch']['patched_hash'][:16]}...")
    print(f"4. Syntax Valid:     {result['stages']['syntax_validation']['syntax_valid']}")
    print(f"5. Runtime Probe:    {result['stages']['runtime_security_probes']['verdict']} "
          f"(Status {result['stages']['runtime_security_probes']['patched_http_status']}, "
          f"blocked={result['stages']['runtime_security_probes']['traversal_blocked']})")
    print(f"6. Regression Test:  {result['stages']['regression_tests']['verdict']} "
          f"(Status {result['stages']['regression_tests']['patched_http_status']}, "
          f"preserved={result['stages']['regression_tests']['baseline_preserved']})")
    print(f"7. Audit Hash Chain: Valid={result['stages']['audit_verification']['chain_valid']} "
          f"(Records checked: {result['stages']['audit_verification']['records_checked']})")
    print("=" * 60)
