"""
backend/bandit_baseline.py
==========================
Bandit integration for the VerifiX security engine.

Responsibilities
----------------
1. Run Bandit programmatically against a target file (no shell=True).
2. Parse its JSON output into a normalised list of finding dicts.
3. Compare Bandit findings against custom-rule findings from static_scanner.
4. Save / load a baseline JSON file for future diffing.

Usage (CLI)
-----------
    python bandit_baseline.py                  # scan vulnerable_app.py
    python bandit_baseline.py --save           # scan + save baseline.json
    python bandit_baseline.py --compare        # scan + compare to baseline.json
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_TARGET = BASE_DIR / "vulnerable_app.py"
DEFAULT_BASELINE = BASE_DIR / "bandit_baseline.json"


# ---------------------------------------------------------------------------
# Bandit runner
# ---------------------------------------------------------------------------

def bandit_available() -> bool:
    """Return True if bandit is importable or on PATH."""
    if shutil.which("bandit"):
        return True
    try:
        import importlib.util
        return importlib.util.find_spec("bandit") is not None
    except Exception:
        return False


def run_bandit(target_path: Path = DEFAULT_TARGET) -> list[dict[str, Any]]:
    """Run ``bandit -f json`` against *target_path* and return findings.

    Uses ``subprocess.run`` with a fixed argument list — no ``shell=True``.
    Returns an empty list if Bandit finds nothing (exit code 0).
    Raises ``RuntimeError`` if Bandit is not installed.
    Raises ``subprocess.TimeoutExpired`` if the scan exceeds 60 s.
    """
    if not bandit_available():
        raise RuntimeError(
            "bandit is not installed. Run: "
            "backend\\.venv\\Scripts\\python.exe -m pip install bandit"
        )

    cmd = [
        sys.executable,
        "-m", "bandit",
        "-f", "json",
        "-q",            # suppress progress output
        str(target_path.resolve()),
    ]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=60,
        # NO shell=True — command list is fully controlled
    )

    # Bandit exits with code 1 when it finds issues; that is expected.
    # Exit code > 1 indicates a real error.
    if proc.returncode > 1:
        raise RuntimeError(
            f"bandit exited with code {proc.returncode}:\n{proc.stderr}"
        )

    if not proc.stdout.strip():
        return []

    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Could not parse bandit JSON output: {exc}\n"
            f"stdout was: {proc.stdout[:500]}"
        ) from exc

    return _normalise_bandit(raw)


def _normalise_bandit(raw: dict) -> list[dict[str, Any]]:
    """Convert Bandit JSON output to the VerifiX finding schema."""
    findings = []
    for issue in raw.get("results", []):
        findings.append({
            "rule": issue.get("test_id", ""),          # e.g. "B101"
            "type": issue.get("test_name", ""),
            "line": issue.get("line_number", 0),
            "evidence": issue.get("issue_text", ""),
            "severity": issue.get("issue_severity", "").lower(),
            "source": "bandit",
            "confidence": issue.get("issue_confidence", "").lower(),
            "filename": issue.get("filename", ""),
        })
    return findings


# ---------------------------------------------------------------------------
# Baseline persistence
# ---------------------------------------------------------------------------

def save_baseline(
    findings: list[dict],
    path: Path = DEFAULT_BASELINE,
) -> None:
    """Write *findings* to *path* as pretty-printed JSON."""
    path.write_text(
        json.dumps(findings, indent=2),
        encoding="utf-8",
    )


def load_baseline(path: Path = DEFAULT_BASELINE) -> list[dict]:
    """Load a previously saved baseline from *path*."""
    if not path.exists():
        raise FileNotFoundError(f"No baseline found at {path}")
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def compare_findings(
    bandit_findings: list[dict],
    custom_findings: list[dict],
) -> dict[str, list[dict]]:
    """Compare Bandit findings against custom-rule findings.

    Returns a dict with three keys:
    - ``bandit_only``  — issues Bandit found that custom rules missed
    - ``custom_only``  — issues custom rules found that Bandit missed
    - ``overlap``      — issues caught by both (matched by line number ± 1)

    Matching is intentionally loose (line ± 1) because Bandit and the
    custom AST walker may point to slightly different lines for the same
    construct.
    """
    def _line(f: dict) -> int:
        return int(f.get("line", 0))

    bandit_lines = {_line(f) for f in bandit_findings}
    custom_lines = {_line(f) for f in custom_findings}

    def _near(line: int, line_set: set[int]) -> bool:
        return any(abs(line - l) <= 1 for l in line_set)

    overlap_bandit = [f for f in bandit_findings if _near(_line(f), custom_lines)]
    overlap_custom = [f for f in custom_findings if _near(_line(f), bandit_lines)]
    bandit_only = [f for f in bandit_findings if not _near(_line(f), custom_lines)]
    custom_only = [f for f in custom_findings if not _near(_line(f), bandit_lines)]

    return {
        "bandit_only": bandit_only,
        "custom_only": custom_only,
        "overlap": {
            "bandit_findings": overlap_bandit,
            "custom_findings": overlap_custom,
        },
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    # Import here to avoid circular dependency at module level
    from static_scanner import scan_file  # noqa: E402 (local import)

    parser = argparse.ArgumentParser(
        description="VerifiX Bandit baseline runner",
    )
    parser.add_argument(
        "--target",
        type=Path,
        default=DEFAULT_TARGET,
        help="File to scan (default: vulnerable_app.py)",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Save Bandit findings as the baseline JSON",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Compare current scan to saved baseline",
    )
    args = parser.parse_args()

    if not bandit_available():
        print("ERROR: bandit is not installed.")
        print("Run: backend\\.venv\\Scripts\\python.exe -m pip install bandit")
        sys.exit(1)

    print(f"Scanning: {args.target}")
    bandit_results = run_bandit(args.target)
    custom_results = scan_file(args.target)

    print(f"\nBandit findings : {len(bandit_results)}")
    for f in bandit_results:
        print(f"  [{f['rule']}] L{f['line']} {f['type']} — {f['evidence'][:60]}")

    print(f"\nCustom findings : {len(custom_results)}")
    for f in custom_results:
        print(f"  [{f['rule']}] L{f['line']} {f['type']} — {f['evidence'][:60]}")

    comparison = compare_findings(bandit_results, custom_results)
    print(f"\nBandit-only     : {len(comparison['bandit_only'])}")
    print(f"Custom-only     : {len(comparison['custom_only'])}")
    print(f"Overlap         : {len(comparison['overlap']['bandit_findings'])}")

    if args.save:
        save_baseline(bandit_results)
        print(f"\nBaseline saved to: {DEFAULT_BASELINE}")

    if args.compare:
        try:
            baseline = load_baseline()
            baseline_rules = {f["rule"] for f in baseline}
            current_rules = {f["rule"] for f in bandit_results}
            new_rules = current_rules - baseline_rules
            fixed_rules = baseline_rules - current_rules
            print(f"\nNew since baseline : {new_rules or 'none'}")
            print(f"Fixed since baseline: {fixed_rules or 'none'}")
        except FileNotFoundError:
            print("\nNo baseline file found. Run with --save first.")
