"""
VerifiX FastAPI backend.

Endpoints
---------
GET  /       Project identity
GET  /health Liveness probe
POST /scan   Scan vulnerable_app.py
POST /analyze Analyze submitted Python source without executing it
POST /patch  Apply an approved patch to a temporary sandbox copy
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Preserve the existing backend import convention.
_BACKEND_DIR = Path(__file__).resolve().parent

if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from static_scanner import scan_file, scan_source  # noqa: E402
from claude_reasoning import generate_hypotheses_for_findings  # noqa: E402
from audit_logger import AuditLogger  # noqa: E402

logger = logging.getLogger(__name__)

app = FastAPI(
    title="VerifiX Security Scanner",
    description="AI-assisted application security analysis",
    version="0.3.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = _BACKEND_DIR
TARGET_FILE = BASE_DIR / "vulnerable_app.py"

_AUDIT_LOG_PATH = BASE_DIR / "audit_log.jsonl"
_audit_logger = AuditLogger(_AUDIT_LOG_PATH)

_MAX_SOURCE_BYTES = 512 * 1024


# ---------------------------------------------------------------------------
# Request and response models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    """Source submitted for static analysis."""

    source: str = Field(
        ...,
        description="Python source code to analyze; it is never executed.",
        min_length=1,
        max_length=_MAX_SOURCE_BYTES,
    )
    filename: str = Field(
        default="<submitted>",
        description="Display name for the submitted source.",
        max_length=256,
    )


class EnrichedFinding(BaseModel):
    """A scanner finding enriched with reasoning and probe recommendations."""

    rule: str
    type: str
    line: int
    evidence: str
    severity: str
    hypothesis: str
    confidence: str
    reasoning: str
    recommended_probes: list[str]


class AnalyzeResponse(BaseModel):
    """Structured response from /analyze."""

    finding_count: int
    findings: list[EnrichedFinding]
    disclaimer: str


class PatchRequest(BaseModel):
    """Request for an approved sandbox patch."""

    rule: str = Field(default="PY002", min_length=1, max_length=32)


# ---------------------------------------------------------------------------
# Existing endpoints
# ---------------------------------------------------------------------------

@app.get("/")
def home() -> dict[str, str]:
    return {
        "project": "VerifiX",
        "status": "running",
        "role": "backend",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy"}


@app.post("/scan")
def run_scan() -> dict[str, Any]:
    """Scan the predefined backend target file."""
    try:
        findings = scan_file(TARGET_FILE)
        return {
            "target": TARGET_FILE.name,
            "finding_count": len(findings),
            "findings": findings,
        }
    except (OSError, SyntaxError) as exc:
        logger.exception("Target file scan failed")
        raise HTTPException(
            status_code=500,
            detail="Scan failed due to a file or syntax error.",
        ) from exc


# ---------------------------------------------------------------------------
# Structured static analysis
# ---------------------------------------------------------------------------

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_source(body: AnalyzeRequest) -> AnalyzeResponse:
    """
    Parse untrusted source with the AST scanner, enrich findings using offline
    reasoning, and record a minimal audit event. Submitted code is never run.
    """
    try:
        raw_findings: list[dict[str, Any]] = scan_source(
            body.source,
            filename=body.filename,
        )
    except SyntaxError as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                "Submitted source contains a Python syntax error "
                f"at line {exc.lineno}."
            ),
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected error during static analysis")
        raise HTTPException(
            status_code=500,
            detail="Static analysis failed due to an internal error.",
        ) from exc

    try:
        hypotheses = generate_hypotheses_for_findings(raw_findings)
    except Exception as exc:
        logger.exception("Offline vulnerability reasoning failed")
        raise HTTPException(
            status_code=500,
            detail="Vulnerability reasoning failed due to an internal error.",
        ) from exc

    enriched: list[EnrichedFinding] = []

    for finding, hypothesis in zip(raw_findings, hypotheses):
        enriched.append(
            EnrichedFinding(
                rule=finding.get("rule", ""),
                type=finding.get("type", ""),
                line=finding.get("line", 0),
                evidence=finding.get("evidence", ""),
                severity=finding.get("severity", ""),
                hypothesis=hypothesis.hypothesis,
                confidence=hypothesis.confidence,
                reasoning=hypothesis.reasoning,
                recommended_probes=list(
                    hypothesis.selected_probe_ids
                ),
            )
        )

    rule_ids = sorted(
        {
            finding.get("rule", "")
            for finding in raw_findings
            if finding.get("rule")
        }
    )

    try:
        _audit_logger.append_event(
            "scan",
            {
                "finding_count": len(raw_findings),
                "rules_triggered": rule_ids,
            },
        )
    except Exception:
        logger.warning(
            "Audit logging failed; scan result will still be returned."
        )

    return AnalyzeResponse(
        finding_count=len(enriched),
        findings=enriched,
        disclaimer=(
            "Findings are based on static AST analysis only. "
            "A rule match does not confirm an exploitable vulnerability. "
            "Probe recommendations require separate authorised runtime testing."
        ),
    )


# ---------------------------------------------------------------------------
# Approved sandbox patch endpoint
# ---------------------------------------------------------------------------

@app.post("/patch")
def apply_patch_endpoint(body: PatchRequest) -> dict[str, Any]:
    """Apply an approved patch to a temporary sandbox copy."""

    if body.rule != "PY002":
        raise HTTPException(
            status_code=400,
            detail="Unsupported patch rule. Only PY002 is supported.",
        )

    try:
        from sandbox_patcher import apply_sandbox_patch

        result = apply_sandbox_patch(str(TARGET_FILE), body.rule)

        if result.status != "APPLIED":
            raise HTTPException(
                status_code=400,
                detail=(
                    result.message
                    or "Patch could not be applied. Check the target pattern and patch result."
                ),
            )

        if not result.syntax_valid:
            raise HTTPException(
                status_code=400,
                detail="The patched sandbox copy did not pass syntax validation.",
            )

        try:
            _audit_logger.append_event(
                "sandbox_patch",
                {
                    "rule": body.rule,
                    "status": result.status,
                    "original_hash": result.original_hash,
                    "patched_hash": result.patched_hash,
                },
            )
        except Exception:
            logger.warning("Audit logging failed for sandbox patch.")

        return {
            "status": result.status,
            "message": result.message,
            "rule": body.rule,
            "original_hash": result.original_hash,
            "patched_hash": result.patched_hash,
            "syntax_valid": result.syntax_valid,
            "sandbox_path": result.patched_copy_path,
            "original_modified": False,
            "verification": "Pending runtime probe and regression tests",
        }

    except HTTPException:
        raise
    except Exception:
        logger.exception("Sandbox patch operation failed")
        raise HTTPException(
            status_code=500,
            detail="Sandbox patch operation failed due to an internal error.",
        )


# ---------------------------------------------------------------------------
# Verification & Audit Ledger endpoints
# ---------------------------------------------------------------------------

@app.post("/verify")
def run_verification_endpoint() -> dict[str, Any]:
    """Execute end-to-end verification workflow against target application."""
    try:
        from verify_workflow import run_full_verification
        report = run_full_verification(TARGET_FILE)
        return report
    except Exception:
        logger.exception("Verification flow failed")
        raise HTTPException(
            status_code=500,
            detail="Verification workflow failed due to an internal error.",
        )


@app.get("/audit")
def get_audit_trail() -> dict[str, Any]:
    """Return verifiable audit log records and chain integrity status."""
    import json
    from audit_logger import verify_audit_log

    records = []
    if _AUDIT_LOG_PATH.is_file():
        try:
            with _AUDIT_LOG_PATH.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
        except Exception:
            logger.warning("Failed to parse audit log lines")

    integrity = verify_audit_log(_AUDIT_LOG_PATH)
    return {
        "valid": integrity.valid,
        "records_checked": integrity.records_checked,
        "error_message": integrity.error_message,
        "failing_index": integrity.failing_index,
        "total_records": len(records),
        "records": records[-30:],
    }