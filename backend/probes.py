"""
backend/probes.py
=================
Controlled runtime validation probes for the VerifiX security engine.

Each probe has a fixed ID, targets only 127.0.0.1:5001, sends a single
HTTP request, and returns a structured ProbeResult.  No real credentials,
no shell commands, no external network access.

Probe registry
--------------
PROBE-PT-001   Path traversal — escape above SAFE_ROOT via ../
PROBE-PT-002   Path traversal — in-bounds read (baseline, should succeed)
PROBE-SQL-001  SQL injection  — valid lookup (baseline, should succeed)
PROBE-SQL-002  SQL injection  — injection-style payload (reveals echo)
PROBE-BOLA-001 BOLA           — cross-user document access
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Any

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_URL: str = "http://127.0.0.1:5001"
_TIMEOUT: int = 5  # seconds


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    probe_id: str
    description: str
    method: str
    url: str
    payload: dict[str, Any]
    expected_verdict: str          # "VULNERABLE" | "SAFE"
    verdict: str = "ERROR"         # "VULNERABLE" | "SAFE" | "ERROR"
    evidence: str = ""
    http_status: int = 0
    error: str = ""
    scanner_rule: str = ""         # corresponding AST rule, if any


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get(path: str, params: dict | None = None,
         headers: dict | None = None) -> requests.Response:
    """Issue a GET to the loopback Flask server."""
    return requests.get(
        f"{BASE_URL}{path}",
        params=params,
        headers=headers,
        timeout=_TIMEOUT,
    )


def _excerpt(text: str, max_len: int = 200) -> str:
    """Return a safe, truncated evidence string."""
    text = text.replace("\r", "").strip()
    return text[:max_len] + ("…" if len(text) > max_len else "")


# ---------------------------------------------------------------------------
# Probe functions
# ---------------------------------------------------------------------------

def probe_pt_001() -> ProbeResult:
    """PROBE-PT-001 — Path traversal: escape above public/ via ../

    Sends: GET /files?name=../demo_secret.txt
    Vulnerable if: HTTP 200 and response body contains file content from
                   outside the public/ directory.
    """
    result = ProbeResult(
        probe_id="PROBE-PT-001",
        description="Path traversal via ../ — escape above public/ directory",
        method="GET",
        url=f"{BASE_URL}/files",
        payload={"name": "../demo_secret.txt"},
        expected_verdict="VULNERABLE",
        scanner_rule="PY002",
    )
    try:
        resp = _get("/files", params={"name": "../demo_secret.txt"})
        result.http_status = resp.status_code
        body = resp.json()
        if resp.status_code == 200 and "content" in body:
            result.verdict = "VULNERABLE"
            result.evidence = (
                "Server returned content from outside public/ directory: "
                + _excerpt(body["content"])
            )
        else:
            result.verdict = "SAFE"
            result.evidence = _excerpt(str(body))
    except requests.RequestException as exc:
        result.verdict = "ERROR"
        result.error = str(exc)
    return result


def probe_pt_002() -> ProbeResult:
    """PROBE-PT-002 — Path traversal baseline: in-bounds read of known file.

    Sends: GET /files?name=sample.txt
    Safe if: HTTP 200 and response contains public sample content (expected).
    This baseline confirms the /files endpoint is functional before
    the traversal probe is interpreted.
    """
    result = ProbeResult(
        probe_id="PROBE-PT-002",
        description="Path traversal baseline — in-bounds read of sample.txt",
        method="GET",
        url=f"{BASE_URL}/files",
        payload={"name": "sample.txt"},
        expected_verdict="SAFE",
        scanner_rule="PY002",
    )
    try:
        resp = _get("/files", params={"name": "sample.txt"})
        result.http_status = resp.status_code
        body = resp.json()
        if resp.status_code == 200 and "content" in body:
            result.verdict = "SAFE"
            result.evidence = "In-bounds read succeeded: " + _excerpt(body["content"])
        else:
            result.verdict = "ERROR"
            result.evidence = _excerpt(str(body))
    except requests.RequestException as exc:
        result.verdict = "ERROR"
        result.error = str(exc)
    return result


def probe_sql_001() -> ProbeResult:
    """PROBE-SQL-001 — SQL injection baseline: valid user lookup.

    Sends: GET /users?name=alice
    Safe if: HTTP 200 and email is returned (expected behaviour).
    Confirms /users endpoint is functional before injection probe.
    """
    result = ProbeResult(
        probe_id="PROBE-SQL-001",
        description="SQL injection baseline — valid user lookup",
        method="GET",
        url=f"{BASE_URL}/users",
        payload={"name": "alice"},
        expected_verdict="SAFE",
        scanner_rule="PY003",
    )
    try:
        resp = _get("/users", params={"name": "alice"})
        result.http_status = resp.status_code
        body = resp.json()
        if resp.status_code == 200 and "email" in body:
            result.verdict = "SAFE"
            result.evidence = (
                "Valid lookup succeeded. email="
                + str(body.get("email", ""))
                + " | query_simulated="
                + str(body.get("query_simulated", ""))
            )
        else:
            result.verdict = "ERROR"
            result.evidence = _excerpt(str(body))
    except requests.RequestException as exc:
        result.verdict = "ERROR"
        result.error = str(exc)
    return result


def probe_sql_002() -> ProbeResult:
    """PROBE-SQL-002 — SQL injection: injection-style payload.

    Sends: GET /users?name=' OR '1'='1
    Demonstrates the code path is live and the server echoes the raw
    input back in query_simulated, confirming that in a real SQL context
    this would be injectable.  The static scanner (PY003) catches the
    vulnerability in source; this probe validates the endpoint is reached.
    """
    injection_payload = "' OR '1'='1"
    result = ProbeResult(
        probe_id="PROBE-SQL-002",
        description="SQL injection payload — echoed in simulated query",
        method="GET",
        url=f"{BASE_URL}/users",
        payload={"name": injection_payload},
        expected_verdict="VULNERABLE",
        scanner_rule="PY003",
    )
    try:
        resp = _get("/users", params={"name": injection_payload})
        result.http_status = resp.status_code
        body = resp.json()
        simulated = body.get("query_simulated", "")
        # Vulnerable indicator: server echoes the raw payload in the query
        if injection_payload in simulated:
            result.verdict = "VULNERABLE"
            result.evidence = (
                "Server echoed raw payload in query_simulated: "
                + _excerpt(simulated)
            )
        else:
            result.verdict = "SAFE"
            result.evidence = _excerpt(str(body))
    except requests.RequestException as exc:
        result.verdict = "ERROR"
        result.error = str(exc)
    return result


def probe_bola_001() -> ProbeResult:
    """PROBE-BOLA-001 — BOLA: cross-user document access.

    Sends: GET /documents/2 with X-Test-User: alice
    Vulnerable if: HTTP 200 and document owner is 'bob' (alice accessed
                   bob's document without an ownership check).
    """
    result = ProbeResult(
        probe_id="PROBE-BOLA-001",
        description="BOLA — Alice reads Bob's document without ownership check",
        method="GET",
        url=f"{BASE_URL}/documents/2",
        payload={},
        expected_verdict="VULNERABLE",
        scanner_rule="AUTH001",
    )
    try:
        resp = _get("/documents/2", headers={"X-Test-User": "alice"})
        result.http_status = resp.status_code
        body = resp.json()
        doc = body.get("document", {})
        if resp.status_code == 200 and doc.get("owner") == "bob":
            result.verdict = "VULNERABLE"
            result.evidence = (
                "Alice received Bob's document. "
                "owner=" + doc.get("owner", "") + " | "
                "content=" + _excerpt(doc.get("content", ""))
            )
        else:
            result.verdict = "SAFE"
            result.evidence = _excerpt(str(body))
    except requests.RequestException as exc:
        result.verdict = "ERROR"
        result.error = str(exc)
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_PROBE_FUNCTIONS = [
    probe_pt_001,
    probe_pt_002,
    probe_sql_001,
    probe_sql_002,
    probe_bola_001,
]


def flask_is_running(host: str = "127.0.0.1", port: int = 5001) -> bool:
    """Return True if the Flask demo server is accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def run_all_probes() -> list[ProbeResult]:
    """Run every registered probe and return the results."""
    return [fn() for fn in _PROBE_FUNCTIONS]


def run_probe(probe_id: str) -> ProbeResult:
    """Run a single probe by ID. Raises KeyError for unknown IDs."""
    registry = {fn().probe_id: fn for fn in _PROBE_FUNCTIONS}
    if probe_id not in registry:
        raise KeyError(f"Unknown probe ID: {probe_id!r}")
    return registry[probe_id]()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not flask_is_running():
        print("ERROR: Flask demo server is not running on 127.0.0.1:5001")
        print("Start it with: python vulnerable_app.py")
        raise SystemExit(1)

    results = run_all_probes()
    print(f"\nVerifiX Probe Runner — {len(results)} probes\n" + "=" * 50)
    for r in results:
        icon = "🔴" if r.verdict == "VULNERABLE" else ("🟢" if r.verdict == "SAFE" else "⚠️")
        print(f"\n{icon} [{r.probe_id}] {r.description}")
        print(f"   Verdict : {r.verdict}  (expected: {r.expected_verdict})")
        print(f"   HTTP    : {r.http_status}")
        print(f"   Rule    : {r.scanner_rule}")
        print(f"   Evidence: {r.evidence or r.error}")
