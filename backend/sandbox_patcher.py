"""
backend/sandbox_patcher.py
==========================
Modular sandbox patching framework for the VerifiX security engine.

Security Architecture & Guarantees:
1. IMMUTABILITY: The original source file is NEVER modified, overwritten,
   or deleted. All patch operations occur on a temporary copy inside an
   isolated sandbox directory.
2. INPUT VALIDATION: Targets are strictly restricted to existing `.py` files.
   Non-existent paths, non-regular files, and non-Python files are rejected.
3. SYNTAX VALIDATION WITHOUT EXECUTION: Python syntax is validated using
   `ast.parse()`. `eval()`, `exec()`, and shell commands are strictly forbidden.
4. EXPLICIT PATCH REGISTRY: Only explicitly registered, specifically recognized
   vulnerability rules and patterns are patched (initially PY002 path traversal).
   All other rules (PY001, PY003, PY004, PY005, AUTH001, unknown) are rejected
   as unsupported.
5. INTEGRITY TRACKING: Computes and records SHA-256 digests for both the original
   source file and the patched sandbox copy.
6. VERIFICATION SEPARATION: Syntax validation confirms grammatical correctness
   only; it never claims a vulnerability is resolved. Runtime probe re-testing
   and regression tests must be executed separately.
7. SAFE CLEANUP: Sandbox directories are created using `tempfile.mkdtemp` and
   can be cleaned up safely via `cleanup_sandbox()`.
"""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
import shutil
import tempfile
from typing import Any, Mapping


# ---------------------------------------------------------------------------
# Supported Patch Registry & Rules
# ---------------------------------------------------------------------------

SUPPORTED_PATCH_RULES: frozenset[str] = frozenset({
    "PY002",  # Unsafe path concatenation in os.path.join (path traversal)
})

UNSUPPORTED_RULES: frozenset[str] = frozenset({
    "PY001",    # Dynamic eval/exec
    "PY003",    # SQL query dynamic formatting
    "PY004",    # Shell command from variable
    "PY005",    # Hardcoded secrets
    "AUTH001",  # Missing authorization check (BOLA)
})


# ---------------------------------------------------------------------------
# Recognized Patch Patterns for PY002
# ---------------------------------------------------------------------------
# Specific, recognized pattern in vulnerable_app.py for path traversal.
# The patch sanitizes input using os.path.basename and strictly confines
# the resolved path to DEMO_PUBLIC_DIR.

_PY002_VULNERABLE_SUBSTRING = (
    "candidate_path = os.path.join(str(DEMO_PUBLIC_DIR), name)"
)

_PY002_VULNERABLE_BLOCK = """    candidate_path = os.path.join(str(DEMO_PUBLIC_DIR), name)
    resolved_path = Path(candidate_path).resolve()

    # SAFETY BOUNDARY: strictly confine within the isolated demo storage directory.
    # Never allow reading arbitrary OS files or repository secrets.
    if not resolved_path.is_relative_to(DEMO_STORAGE_DIR):
        return jsonify({
            "error": "Access denied: demonstration is strictly confined to isolated demo directory",
        }), 403"""

_PY002_PATCHED_BLOCK = """    # PATCHED (PY002): sanitize filename with os.path.basename and confine to DEMO_PUBLIC_DIR
    safe_name = os.path.basename(name)
    candidate_path = os.path.join(str(DEMO_PUBLIC_DIR), safe_name)
    resolved_path = Path(candidate_path).resolve()

    # SAFETY BOUNDARY: strictly confine within the public directory.
    if not resolved_path.is_relative_to(DEMO_PUBLIC_DIR):
        return jsonify({
            "error": "Access denied: path traversal not permitted outside public directory",
        }), 403"""


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PatchResult:
    """Structured result of a sandbox patch operation."""

    status: str
    rule: str
    message: str
    original_path: str
    original_hash: str
    patched_copy_path: str | None = None
    patched_hash: str | None = None
    sandbox_dir: str | None = None
    syntax_valid: bool = False

    @property
    def original_sha256(self) -> str:
        return self.original_hash

    @property
    def patched_sha256(self) -> str | None:
        return self.patched_hash

    @property
    def sandbox_path(self) -> str | None:
        return self.patched_copy_path

    def to_dict(self) -> dict[str, Any]:
        """Convert PatchResult to a plain serializable dictionary."""
        return {
            "status": self.status,
            "rule": self.rule,
            "message": self.message,
            "original_path": self.original_path,
            "original_hash": self.original_hash,
            "patched_copy_path": self.patched_copy_path,
            "patched_hash": self.patched_hash,
            "sandbox_dir": self.sandbox_dir,
            "syntax_valid": self.syntax_valid,
        }

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)


# ---------------------------------------------------------------------------
# Target & Syntax Validation Functions
# ---------------------------------------------------------------------------

def validate_target_path(target_path: str | Path) -> Path:
    """Validate that *target_path* is an existing, regular Python (.py) file.

    Raises:
        TypeError: If target_path is not a str or Path.
        FileNotFoundError: If the target file does not exist.
        ValueError: If target_path is not a regular file or does not end in .py.
    """
    if not isinstance(target_path, (str, Path)):
        raise TypeError(f"Target path must be a string or Path, got {type(target_path).__name__}")

    path = Path(target_path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"Target file does not exist: {path}")

    if not path.is_file():
        raise ValueError(f"Target path is not a regular file: {path}")

    if path.suffix.lower() != ".py":
        raise ValueError(f"Target file must have a .py extension, got: {path.name}")

    return path


def compute_sha256(data_or_path: str | bytes | Path) -> str:
    """Compute the SHA-256 hex digest of a file path, string, or bytes."""
    hasher = hashlib.sha256()

    if isinstance(data_or_path, Path):
        hasher.update(data_or_path.read_bytes())
    elif isinstance(data_or_path, str):
        try:
            path_candidate = Path(data_or_path)
            if path_candidate.is_file():
                hasher.update(path_candidate.read_bytes())
            else:
                hasher.update(data_or_path.encode("utf-8"))
        except (OSError, ValueError):
            hasher.update(data_or_path.encode("utf-8"))
    elif isinstance(data_or_path, bytes):
        hasher.update(data_or_path)
    else:
        raise TypeError(f"Cannot compute SHA-256 for type {type(data_or_path).__name__}")

    return hasher.hexdigest()


def validate_python_syntax(source_or_path: str | Path) -> tuple[bool, str | None]:
    """Validate Python syntax using `ast.parse()` without executing the code.

    Parameters:
        source_or_path: Python source code string or Path to a .py file.

    Returns:
        (True, None) if syntax is valid.
        (False, error_details) if syntax parsing fails.
    """
    try:
        if isinstance(source_or_path, Path):
            source = source_or_path.read_text(encoding="utf-8", errors="replace")
        elif isinstance(source_or_path, str):
            try:
                path_candidate = Path(source_or_path)
                if path_candidate.is_file():
                    source = path_candidate.read_text(encoding="utf-8", errors="replace")
                else:
                    source = source_or_path
            except (OSError, ValueError):
                source = source_or_path
        else:
            return False, f"Expected str or Path, got {type(source_or_path).__name__}"

        ast.parse(source)
        return True, None
    except SyntaxError as exc:
        return False, f"SyntaxError at line {exc.lineno}: {exc.msg}"
    except Exception as exc:
        return False, f"Parsing error: {exc}"


# ---------------------------------------------------------------------------
# Sandbox Management & Active Registry
# ---------------------------------------------------------------------------

# Tracks sandbox directories explicitly created and owned by this patcher session
_ACTIVE_SANDBOX_DIRS: set[Path] = set()


def create_sandbox_copy(target_path: str | Path) -> tuple[Path, Path, str]:
    """Create a temporary working copy of *target_path* in a fresh sandbox directory.

    Guarantees:
    - Target path is validated (.py, exists, regular file).
    - Original file is read strictly in read-only mode.
    - Computes original SHA-256 digest.
    - The original file is NEVER altered.
    - Registers sandbox_dir in _ACTIVE_SANDBOX_DIRS for authorized cleanup.

    Returns:
        (sandbox_dir, working_copy_path, original_sha256)
    """
    validated_path = validate_target_path(target_path)
    original_sha256 = compute_sha256(validated_path)

    sandbox_dir = Path(tempfile.mkdtemp(prefix="verifix_sandbox_")).resolve()
    _ACTIVE_SANDBOX_DIRS.add(sandbox_dir)
    copy_path = sandbox_dir / validated_path.name

    shutil.copy2(validated_path, copy_path)

    # Verify original file integrity after copy operation
    post_copy_sha256 = compute_sha256(validated_path)
    if original_sha256 != post_copy_sha256:
        shutil.rmtree(sandbox_dir, ignore_errors=True)
        _ACTIVE_SANDBOX_DIRS.discard(sandbox_dir)
        raise RuntimeError("Original file was modified during copy operation! Aborting.")

    return sandbox_dir, copy_path, original_sha256


def cleanup_sandbox(sandbox_dir: str | Path | None) -> bool:
    """Safely remove a sandbox temporary directory and all its contents.

    Security Guarantees:
    - Ensures cleanup can remove ONLY a temporary directory created and owned
      by this patcher, never an arbitrary caller-supplied directory.
    - Requires registration in _ACTIVE_SANDBOX_DIRS.
    - Enforces confinement within the system temporary directory.
    - Enforces prefix validation ('verifix_sandbox_').
    """
    if not sandbox_dir:
        return False

    try:
        path = Path(sandbox_dir).resolve()
    except (TypeError, ValueError):
        return False

    # Check 1: Must be explicitly created and tracked by this patcher
    if path not in _ACTIVE_SANDBOX_DIRS:
        return False

    # Check 2: Defense-in-depth confinement to system temporary root
    temp_root = Path(tempfile.gettempdir()).resolve()
    if not path.is_relative_to(temp_root) or not path.name.startswith("verifix_sandbox_"):
        _ACTIVE_SANDBOX_DIRS.discard(path)
        return False

    if path.exists() and path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
        _ACTIVE_SANDBOX_DIRS.discard(path)
        return True

    _ACTIVE_SANDBOX_DIRS.discard(path)
    return False


# ---------------------------------------------------------------------------
# Patch Application Engine
# ---------------------------------------------------------------------------

def get_supported_patch_rules() -> list[str]:
    """Return a sorted list of rules with automated patch support."""
    return sorted(SUPPORTED_PATCH_RULES)


def apply_sandbox_patch(target_path: str | Path, rule: str) -> PatchResult:
    """Apply a registered patch for *rule* to a temporary sandbox copy of *target_path*.

    Guarantees:
    - Original file is NEVER modified; only the sandbox copy is touched.
    - Input target must be an existing `.py` file.
    - If *rule* is not in `SUPPORTED_PATCH_RULES`, returns an unsupported result.
    - If the source code pattern does not match, returns a pattern mismatch result.
    - Validates syntax with `ast.parse()` on the patched copy.
    - Records original and patched SHA-256 hashes.
    - Never executes arbitrary code, shell commands, or network requests.
    - Does NOT claim vulnerability resolution; only syntax validity of the patch.
    """
    rule_clean = str(rule).strip()

    # 1. Target validation
    try:
        validated_target = validate_target_path(target_path)
    except (TypeError, ValueError, FileNotFoundError) as exc:
        return PatchResult(
            status="ERROR",
            rule=rule_clean,
            message=f"Invalid target path: {exc}",
            original_path=str(target_path),
            original_hash="",
        )

    # 2. Rule support check
    if rule_clean not in SUPPORTED_PATCH_RULES:
        orig_hash = compute_sha256(validated_target)
        if rule_clean in UNSUPPORTED_RULES:
            msg = (
                f"Rule '{rule_clean}' is recognized but automated patching is currently unsupported. "
                f"Only rules in {sorted(SUPPORTED_PATCH_RULES)} are registered for automated patching."
            )
        else:
            msg = (
                f"Rule '{rule_clean}' is unknown or unregistered. "
                f"Supported rules: {sorted(SUPPORTED_PATCH_RULES)}."
            )
        return PatchResult(
            status="UNSUPPORTED_RULE",
            rule=rule_clean,
            message=msg,
            original_path=str(validated_target),
            original_hash=orig_hash,
        )

    # 3. Create sandbox working copy
    sandbox_dir, working_copy, original_hash = create_sandbox_copy(validated_target)

    try:
        source = working_copy.read_text(encoding="utf-8", errors="replace")

        # 4. Pattern recognition for PY002
        if rule_clean == "PY002":
            # Normalize line endings for reliable matching
            norm_source = source.replace("\r\n", "\n")
            norm_vuln_block = _PY002_VULNERABLE_BLOCK.replace("\r\n", "\n")

            if norm_vuln_block in norm_source:
                patched_source = norm_source.replace(norm_vuln_block, _PY002_PATCHED_BLOCK)
            elif _PY002_VULNERABLE_SUBSTRING in norm_source:
                # Targeted replacement of candidate_path construction
                target_line = "candidate_path = os.path.join(str(DEMO_PUBLIC_DIR), name)"
                safe_lines = (
                    "safe_name = os.path.basename(name)\n"
                    "    candidate_path = os.path.join(str(DEMO_PUBLIC_DIR), safe_name)"
                )
                patched_source = norm_source.replace(target_line, safe_lines)
            else:
                return PatchResult(
                    status="PATTERN_MISMATCH",
                    rule=rule_clean,
                    message=(
                        "Source does not contain the specifically recognized vulnerable pattern for PY002. "
                        "No modifications applied."
                    ),
                    original_path=str(validated_target),
                    original_hash=original_hash,
                    patched_copy_path=str(working_copy),
                    patched_hash=original_hash,
                    sandbox_dir=str(sandbox_dir),
                    syntax_valid=True,
                )

        # 5. Syntax validation without execution
        syntax_ok, syntax_err = validate_python_syntax(patched_source)
        if not syntax_ok:
            return PatchResult(
                status="SYNTAX_ERROR",
                rule=rule_clean,
                message=f"Patched code failed syntax validation: {syntax_err}",
                original_path=str(validated_target),
                original_hash=original_hash,
                patched_copy_path=str(working_copy),
                patched_hash=None,
                sandbox_dir=str(sandbox_dir),
                syntax_valid=False,
            )

        # 6. Write patched code to sandbox working copy ONLY
        working_copy.write_text(patched_source, encoding="utf-8")
        patched_hash = compute_sha256(working_copy)

        # 7. Verification that original file was completely untouched
        post_original_hash = compute_sha256(validated_target)
        if post_original_hash != original_hash:
            raise RuntimeError("CRITICAL ERROR: Original file was modified during patch application!")

        return PatchResult(
            status="APPLIED",
            rule=rule_clean,
            message=(
                "Patch successfully applied to sandbox working copy and syntax verified. "
                "Verification probe and regression retesting must be run to confirm vulnerability resolution."
            ),
            original_path=str(validated_target),
            original_hash=original_hash,
            patched_copy_path=str(working_copy),
            patched_hash=patched_hash,
            sandbox_dir=str(sandbox_dir),
            syntax_valid=True,
        )

    except Exception as exc:
        cleanup_sandbox(sandbox_dir)
        return PatchResult(
            status="ERROR",
            rule=rule_clean,
            message=f"Patch application failed with unexpected error: {exc}",
            original_path=str(validated_target),
            original_hash=original_hash,
        )
