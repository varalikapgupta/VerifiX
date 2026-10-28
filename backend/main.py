"""
backend/main.py
===============
VerifiX FastAPI backend.

Endpoints
---------
GET  /            — project identity
GET  /health      — liveness probe
POST /scan        — scan vulnerable_app.py (preserved, unchanged behavior)
POST /analyze     — structured scan workflow: accepts source code, runs static
                    analysis, enriches findings with offline reasoning, logs
                    the scan event via the audit logger, and returns evidence-
                    backed results with approved probe recommendations.

Security notes
--------------
- Source code submitted to /analyze is treated as untrusted input.
- It is parsed by the AST scanner only; it is NEVER executed.
- Filesystem paths, stack traces, and internal exception details are never
  returned to the caller.
- Probe recommendations are restricted to the existing allow-list in
  claude_reasoning.REGISTERED_PROBE_IDS.  No probe is executed automatically.
- Audit events log finding counts and rule IDs only; source code and secrets
  are never stored in the audit log.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Bare-name imports mirror the existing convention used across the project's
# test suite (e.g. test_scanner.py inserts backend/ into sys.path and then
# does `from static_scanner import ...`).  When FastAPI/uvicorn is launched
# from the repository root via `uvicorn backend.main:app` the path insertion
# below keeps imports working in both cases.
# ---------------------------------------------------------------------------
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

BASE_DIR = _BACKEND_DIR
TARGET_FILE = BASE_DIR / "vulnerable_app.py"

# One audit-logger instance, shared across requests (thread-safe per-path lock).
_AUDIT_LOG_PATH = BASE_DIR / "audit_log.jsonl"
_audit_logger = AuditLogger(_AUDIT_LOG_PATH)

# Maximum accepted source length (bytes) to prevent trivially large payloads.
_MAX_SOURCE_BYTES = 512 * 1024  # 512 KB


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    """Source code submitted for analysis."""

    source: str = Field(
        ...,
        description="Python source code to analyze (untrusted, never executed).",
        min_length=1,
        max_length=_MAX_SOURCE_BYTES,
    )
    filename: str = Field(
        default="<submitted>",
        description="Optional display name for the source (used in error messages only).",
        max_length=256,
    )


class EnrichedFinding(BaseModel):
    """A single scanner finding enriched with reasoning and probe recommendations."""

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
    """Structured response from the /analyze endpoint."""

    finding_count: int
    findings: list[EnrichedFinding]
    disclaimer: str


# ---------------------------------------------------------------------------
# Existing endpoints — unchanged behavior
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
    try:
        findings = scan_file(TARGET_FILE)
        return {
            "target": TARGET_FILE.name,
            "finding_count": len(findings),
            "findings": findings,
        }
    except (OSError, SyntaxError) as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
# New /analyze endpoint
# ---------------------------------------------------------------------------

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_source(body: AnalyzeRequest) -> AnalyzeResponse:
    """Structured scan workflow.

    1. Parse the submitted source with the AST scanner (never executed).
    2. Enrich each finding with offline vulnerability reasoning.
    3. Return evidence-backed results with allow-listed probe recommendations.
    4. Log the scan event (finding count + rule IDs only, no source contents).

    Returns HTTP 422 for validation errors (empty source, oversized payload).
    Returns HTTP 400 for Python syntax errors in the submitted source.
    Returns HTTP 500 only for unexpected internal errors, with a generic message.
    """
    # 1. Static analysis — treat source as untrusted; never execute it.
    try:
        raw_findings: list[dict[str, Any]] = scan_source(
            body.source,
            filename=body.filename,
        )
    except SyntaxError as exc:
        # Surface a safe, non-path-revealing message.
        raise HTTPException(
            status_code=400,
            detail=f"Submitted source contains a Python syntax error at line {exc.lineno}.",
        ) from exc
    except Exception:
        # Log internally but never leak stack trace to caller.
        logger.exception("Unexpected error during static analysis")
        raise HTTPException(
            status_code=500,
            detail="Static analysis failed due to an internal error.",
        )

    # 2. Offline reasoning — enrich each finding with hypothesis + probes.
    hypotheses = generate_hypotheses_for_findings(raw_findings)

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
                recommended_probes=list(hypothesis.selected_probe_ids),
            )
        )

    # 3. Audit logging — record only finding counts and rule IDs; never source.
    rule_ids = sorted({f.get("rule", "") for f in raw_findings if f.get("rule")})
    try:
        _audit_logger.append_event(
            "scan",
            {
                "finding_count": len(raw_findings),
                "rules_triggered": rule_ids,
            },
        )
    except Exception:
        # Audit failures must not fail the scan response.
        logger.warning("Audit logging failed; scan result will still be returned.")

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
# Generic safety net — catch unhandled exceptions and return 500 without
# leaking any internal detail.
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected internal error occurred."},
    )
