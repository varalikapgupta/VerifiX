"""
tests/test_sandbox_patcher.py
=============================
Automated unit tests for backend/sandbox_patcher.py.

Verifies:
1. compute_sha256 produces exact expected digests for known inputs.
2. validate_python_syntax validates syntax without executing code.
3. create_sandbox_copy creates an isolated copy and preserves the original file.
4. validate_target_path safely rejects invalid paths, directories, and non-.py files.
5. cleanup_sandbox removes temporary directories safely.
6. get_supported_patch_rules returns only explicitly supported rules (PY002).
7. Unsupported rules return clear UNSUPPORTED_RULE status without altering the original.
8. apply_sandbox_patch guarantees the original source is never modified.
9. Unmatched source patterns return PATTERN_MISMATCH without corrupting files.
10. PatchResult fields, hashes, and dict conversion integrity.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import pytest

# Ensure backend/ is in sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sandbox_patcher import (
    SUPPORTED_PATCH_RULES,
    UNSUPPORTED_RULES,
    PatchResult,
    apply_sandbox_patch,
    cleanup_sandbox,
    compute_sha256,
    create_sandbox_copy,
    get_supported_patch_rules,
    validate_python_syntax,
    validate_target_path,
)


# ===========================================================================
# 1. SHA-256 Digest Tests
# ===========================================================================

class TestComputeSha256:

    def test_sha256_known_bytes(self):
        """Validates against standard known SHA-256 test vector."""
        data = b"hello world"
        expected = hashlib.sha256(data).hexdigest()
        assert compute_sha256(data) == expected
        assert expected == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    def test_sha256_empty_bytes(self):
        empty_expected = hashlib.sha256(b"").hexdigest()
        assert compute_sha256(b"") == empty_expected
        assert compute_sha256("") == empty_expected

    def test_sha256_file_path(self, tmp_path):
        f = tmp_path / "sample.py"
        content = b"print('VerifiX SHA test')\n"
        f.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        assert compute_sha256(f) == expected

    def test_sha256_invalid_type_raises(self):
        with pytest.raises(TypeError, match="Cannot compute SHA-256"):
            compute_sha256(12345)  # type: ignore


# ===========================================================================
# 2. Syntax Validation Without Execution
# ===========================================================================

class TestValidatePythonSyntax:

    def test_valid_syntax_accepted(self):
        valid_code = "def add(a, b):\n    return a + b\n"
        ok, err = validate_python_syntax(valid_code)
        assert ok is True
        assert err is None

    def test_invalid_syntax_rejected(self):
        invalid_code = "def broken(:"
        ok, err = validate_python_syntax(invalid_code)
        assert ok is False
        assert err is not None
        assert "SyntaxError" in err

    def test_side_effects_not_executed(self):
        """Code containing sys.exit() or exceptions must NOT execute during validation."""
        code_with_exit = "import sys\nsys.exit(42)\n"
        # If ast.parse were executing code, this test would terminate the runner
        ok, err = validate_python_syntax(code_with_exit)
        assert ok is True
        assert err is None

    def test_validate_syntax_from_file_path(self, tmp_path):
        f = tmp_path / "good.py"
        f.write_text("x: int = 10\n", encoding="utf-8")
        ok, err = validate_python_syntax(f)
        assert ok is True
        assert err is None


# ===========================================================================
# 3. Target Path Validation
# ===========================================================================

class TestValidateTargetPath:

    def test_valid_py_file_accepted(self, tmp_path):
        f = tmp_path / "target.py"
        f.write_text("print(1)\n", encoding="utf-8")
        resolved = validate_target_path(f)
        assert resolved == f.resolve()

    def test_nonexistent_file_raises_file_not_found(self, tmp_path):
        missing = tmp_path / "nonexistent.py"
        with pytest.raises(FileNotFoundError, match="Target file does not exist"):
            validate_target_path(missing)

    def test_directory_target_raises_value_error(self, tmp_path):
        with pytest.raises(ValueError, match="not a regular file"):
            validate_target_path(tmp_path)

    def test_non_python_extension_rejected(self, tmp_path):
        txt_file = tmp_path / "notes.txt"
        txt_file.write_text("plain text", encoding="utf-8")
        with pytest.raises(ValueError, match="must have a .py extension"):
            validate_target_path(txt_file)

    def test_invalid_path_type_raises_type_error(self):
        with pytest.raises(TypeError, match="Target path must be a string or Path"):
            validate_target_path(None)  # type: ignore


# ===========================================================================
# 4. Sandbox Working Copy Creation & Immutability
# ===========================================================================

class TestCreateSandboxCopy:

    def test_creates_isolated_copy_and_preserves_original(self, tmp_path):
        orig_file = tmp_path / "original_script.py"
        orig_content = "def calculate():\n    return 42\n"
        orig_file.write_text(orig_content, encoding="utf-8")
        orig_hash_before = compute_sha256(orig_file)

        sandbox_dir, copy_path, returned_hash = create_sandbox_copy(orig_file)

        try:
            assert returned_hash == orig_hash_before
            assert sandbox_dir.exists() and sandbox_dir.is_dir()
            assert copy_path.exists() and copy_path.is_file()
            assert copy_path.parent == sandbox_dir
            assert copy_path.name == "original_script.py"
            assert compute_sha256(copy_path) == orig_hash_before

            # Modify the sandbox copy
            copy_path.write_text("MUTATED COPY", encoding="utf-8")
            assert compute_sha256(copy_path) != orig_hash_before

            # Verify the original file was strictly untouched
            assert orig_file.read_text(encoding="utf-8") == orig_content
            assert compute_sha256(orig_file) == orig_hash_before

        finally:
            cleanup_sandbox(sandbox_dir)


# ===========================================================================
# 5. Sandbox Cleanup
# ===========================================================================

class TestCleanupSandbox:

    def test_cleanup_removes_sandbox_dir(self, tmp_path):
        dummy_file = tmp_path / "dummy.py"
        dummy_file.write_text("x = 1\n", encoding="utf-8")
        sandbox_dir, _, _ = create_sandbox_copy(dummy_file)

        assert sandbox_dir.exists()
        cleaned = cleanup_sandbox(sandbox_dir)
        assert cleaned is True
        assert not sandbox_dir.exists()

    def test_cleanup_none_or_empty_returns_false(self):
        assert cleanup_sandbox(None) is False
        assert cleanup_sandbox("") is False


# ===========================================================================
# 6. Supported & Unsupported Patch Rules
# ===========================================================================

class TestPatchRuleRegistry:

    def test_get_supported_patch_rules_returns_py002(self):
        rules = get_supported_patch_rules()
        assert isinstance(rules, list)
        assert rules == ["PY002"]
        assert SUPPORTED_PATCH_RULES == frozenset({"PY002"})

    def test_unsupported_rules_defined(self):
        expected_unsupported = {"PY001", "PY003", "PY004", "PY005", "AUTH001"}
        assert expected_unsupported.issubset(UNSUPPORTED_RULES)

    def test_apply_patch_unsupported_rule_does_not_modify_file(self, tmp_path):
        target = tmp_path / "app.py"
        content = "x = 100\n"
        target.write_text(content, encoding="utf-8")
        orig_hash = compute_sha256(target)

        for rule in ["PY001", "PY003", "PY004", "PY005", "AUTH001", "UNKNOWN_RULE"]:
            res = apply_sandbox_patch(target, rule)
            assert isinstance(res, PatchResult)
            assert res.status == "UNSUPPORTED_RULE"
            assert res.rule == rule
            assert res.original_hash == orig_hash
            assert res.patched_copy_path is None
            assert "unsupported" in res.message.lower() or "unknown" in res.message.lower()

            # Ensure original is strictly untouched
            assert target.read_text(encoding="utf-8") == content
            assert compute_sha256(target) == orig_hash


# ===========================================================================
# 7. Unmatched Pattern Handling
# ===========================================================================

class TestPatternMismatch:

    def test_source_without_recognized_pattern_returns_mismatch(self, tmp_path):
        target = tmp_path / "clean_app.py"
        content = "import os\n\ndef safe_function():\n    return 'no vulnerable pattern here'\n"
        target.write_text(content, encoding="utf-8")
        orig_hash = compute_sha256(target)

        res = apply_sandbox_patch(target, "PY002")

        try:
            assert res.status == "PATTERN_MISMATCH"
            assert res.rule == "PY002"
            assert res.original_hash == orig_hash
            assert res.patched_hash == orig_hash
            assert "pattern" in res.message.lower()
            # Original file strictly untouched
            assert target.read_text(encoding="utf-8") == content
            assert compute_sha256(target) == orig_hash
        finally:
            cleanup_sandbox(res.sandbox_dir)


# ===========================================================================
# 8. Successful Sandbox Patch Application & Immutability
# ===========================================================================

class TestApplySandboxPatchSuccess:

    def test_py002_patch_applied_to_sandbox_copy_only(self, tmp_path):
        """Creates a target with the PY002 vulnerable pattern and applies the patch."""
        vulnerable_code = (
            "import os\n"
            "from pathlib import Path\n\n"
            "def read_file(name):\n"
            "    candidate_path = os.path.join(str(DEMO_PUBLIC_DIR), name)\n"
            "    resolved_path = Path(candidate_path).resolve()\n\n"
            "    # SAFETY BOUNDARY: strictly confine within the isolated demo storage directory.\n"
            "    # Never allow reading arbitrary OS files or repository secrets.\n"
            "    if not resolved_path.is_relative_to(DEMO_STORAGE_DIR):\n"
            "        return jsonify({\n"
            '            "error": "Access denied: demonstration is strictly confined to isolated demo directory",\n'
            "        }), 403\n"
        )
        target = tmp_path / "vulnerable_target.py"
        target.write_text(vulnerable_code, encoding="utf-8")
        orig_hash = compute_sha256(target)

        res = apply_sandbox_patch(target, "PY002")

        try:
            # 1. Result status and fields
            assert res.status == "APPLIED"
            assert res.rule == "PY002"
            assert res.syntax_valid is True
            assert res.original_hash == orig_hash
            assert res.patched_hash is not None
            assert res.patched_hash != orig_hash

            # 2. Verify original file was strictly untouched
            assert target.read_text(encoding="utf-8") == vulnerable_code
            assert compute_sha256(target) == orig_hash

            # 3. Verify sandbox copy contains the patch and is syntactically valid
            copy_path = Path(res.patched_copy_path)
            assert copy_path.exists()
            assert copy_path != target
            patched_content = copy_path.read_text(encoding="utf-8")
            assert "safe_name = os.path.basename(name)" in patched_content
            assert "DEMO_PUBLIC_DIR" in patched_content

            ok, err = validate_python_syntax(copy_path)
            assert ok is True and err is None

            # 4. Verify to_dict and subscripting compatibility
            res_dict = res.to_dict()
            assert res_dict["status"] == "APPLIED"
            assert res["status"] == "APPLIED"
            assert res["original_hash"] == orig_hash
            assert res.original_sha256 == orig_hash
            assert res.patched_sha256 == res.patched_hash

        finally:
            cleanup_sandbox(res.sandbox_dir)

    def test_apply_patch_invalid_path_returns_error_result(self):
        res = apply_sandbox_patch("nonexistent_file_xyz.py", "PY002")
        assert res.status == "ERROR"
        assert "Invalid target path" in res.message
        assert res.patched_copy_path is None
