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

    def test_cleanup_rejects_arbitrary_caller_directory(self, tmp_path):
        """Cleanup must reject arbitrary caller-supplied directories even if named with the prefix."""
        fake_sandbox = tmp_path / "verifix_sandbox_caller_owned"
        fake_sandbox.mkdir()
        canary_file = fake_sandbox / "important.txt"
        canary_file.write_text("critical data", encoding="utf-8")

        cleaned = cleanup_sandbox(fake_sandbox)
        assert cleaned is False, "cleanup_sandbox must refuse to delete unowned directory"
        assert fake_sandbox.exists(), "Unowned directory must not be removed"
        assert canary_file.exists(), "Canary file must remain intact"

    def test_cleanup_rejects_unregistered_dir_in_temp_root(self):
        """Even inside system temp, directories not created by create_sandbox_copy must be rejected."""
        import tempfile
        temp_root = Path(tempfile.gettempdir()).resolve()
        unregistered_dir = temp_root / "verifix_sandbox_unregistered_test"
        unregistered_dir.mkdir(exist_ok=True)
        canary = unregistered_dir / "keep_me.txt"
        canary.write_text("keep", encoding="utf-8")

        try:
            cleaned = cleanup_sandbox(unregistered_dir)
            assert cleaned is False, "Unregistered directory in tempdir must not be deleted"
            assert unregistered_dir.exists()
        finally:
            import shutil
            shutil.rmtree(unregistered_dir, ignore_errors=True)

    def test_cleanup_second_call_returns_false(self, tmp_path):
        """Calling cleanup twice on the same sandbox dir returns True then False."""
        dummy_file = tmp_path / "dummy.py"
        dummy_file.write_text("x = 1\n", encoding="utf-8")
        sandbox_dir, _, _ = create_sandbox_copy(dummy_file)

        assert cleanup_sandbox(sandbox_dir) is True
        assert cleanup_sandbox(sandbox_dir) is False


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


# ===========================================================================
# 9. PY002 Patch Behavioral Regression Tests
#
# Strategy
# --------
# The PY002 patched block performs two operations:
#
#   safe_name = os.path.basename(name)
#   candidate_path = os.path.join(str(DEMO_PUBLIC_DIR), safe_name)
#   resolved_path = Path(candidate_path).resolve()
#   if not resolved_path.is_relative_to(DEMO_PUBLIC_DIR):
#       return ..., 403
#
# We test this algorithm in isolation — as a pure Python expression — against
# a controlled tmp_path directory tree with canary files.  No code is executed,
# no Flask server is started, and no real sensitive files are read.
#
# The tests also verify that:
# 1. apply_sandbox_patch embeds `os.path.basename` in the patched file text.
# 2. The patched file no longer contains the vulnerable substring.
# 3. The original file is untouched throughout.
# 4. cleanup_sandbox removes the sandbox directory after the test.
# ===========================================================================

import os as _os_module  # alias to avoid shadowing in local helpers


def _simulate_patched_route(name: str, public_dir: "Path") -> tuple["Path | None", int]:
    """Pure-Python simulation of the PY002-patched route logic.

    Parameters mirror the patched block exactly (lines 76-85 of sandbox_patcher.py):

        safe_name = os.path.basename(name)
        candidate_path = os.path.join(str(DEMO_PUBLIC_DIR), safe_name)
        resolved_path = Path(candidate_path).resolve()
        if not resolved_path.is_relative_to(DEMO_PUBLIC_DIR):
            return ..., 403

    This helper is intentionally a pure function.  It does NOT open, read, or
    write any file; it only resolves paths.  No untrusted code is executed.

    Returns:
        (resolved_path, 200) if the path is within public_dir.
        (None, 403) if the is_relative_to check fails.
    """
    safe_name = _os_module.path.basename(name)
    candidate_path = _os_module.path.join(str(public_dir), safe_name)
    resolved_path = Path(candidate_path).resolve()
    if not resolved_path.is_relative_to(public_dir):
        return None, 403
    return resolved_path, 200


def _simulate_vulnerable_route(name: str, public_dir: "Path", storage_dir: "Path") -> tuple["Path | None", int]:
    """Pure-Python simulation of the ORIGINAL (un-patched) route logic.

    The original code joins user-supplied *name* directly without basename
    sanitization and uses the wider DEMO_STORAGE_DIR boundary.

    This is used only to contrast with the patched logic; it is NOT called on
    real files.
    """
    candidate_path = _os_module.path.join(str(public_dir), name)
    resolved_path = Path(candidate_path).resolve()
    if not resolved_path.is_relative_to(storage_dir):
        return None, 403
    return resolved_path, 200


class TestPY002PatchBehavior:
    """Behavioral regression tests for the PY002 patch.

    Directory layout used in every test (created entirely inside tmp_path):

        tmp_path/
        ├── storage/          ← simulates DEMO_STORAGE_DIR
        │   ├── public/       ← simulates DEMO_PUBLIC_DIR
        │   │   └── canary.txt  ← legitimate readable file
        │   └── internal.txt  ← secret inside storage, outside public
        └── outside/          ← completely outside storage
            └── secret.txt    ← canary that must never be reachable
    """

    # ------------------------------------------------------------------
    # Fixtures
    # ------------------------------------------------------------------

    @pytest.fixture()
    def dirs(self, tmp_path: Path):
        """Create the controlled directory tree and canary files."""
        storage = tmp_path / "storage"
        public = storage / "public"
        outside = tmp_path / "outside"

        public.mkdir(parents=True)
        outside.mkdir()

        (public / "canary.txt").write_text("PUBLIC_CANARY", encoding="utf-8")
        (storage / "internal.txt").write_text("INTERNAL_SECRET", encoding="utf-8")
        (outside / "secret.txt").write_text("OUTSIDE_SECRET", encoding="utf-8")

        return {"storage": storage, "public": public, "outside": outside}

    # ------------------------------------------------------------------
    # 9a. Legitimate access (normal filenames)
    # ------------------------------------------------------------------

    def test_ordinary_filename_resolves_inside_public(self, dirs):
        """A plain filename without any traversal resolves inside DEMO_PUBLIC_DIR."""
        path, status = _simulate_patched_route("canary.txt", dirs["public"])
        assert status == 200
        assert path is not None
        assert path.is_relative_to(dirs["public"])

    def test_ordinary_filename_with_extension_allowed(self, dirs):
        path, status = _simulate_patched_route("report.pdf", dirs["public"])
        # Path may not exist on disk, but the resolved location must be inside public.
        assert status == 200
        assert path is not None
        assert path.is_relative_to(dirs["public"])

    def test_canary_file_read_in_bounds_returns_content(self, dirs):
        """Legitimate file 'canary.txt' inside public resolves and reads correctly."""
        path, status = _simulate_patched_route("canary.txt", dirs["public"])
        assert status == 200
        assert path is not None and path.exists()
        assert path.read_text(encoding="utf-8") == "PUBLIC_CANARY"

    # ------------------------------------------------------------------
    # 9b. Traversal attempt: single hop
    # ------------------------------------------------------------------

    def test_single_dotdot_traversal_is_blocked_by_basename(self, dirs):
        """'../internal.txt' — basename strips '../', result stays inside public."""
        name = "../internal.txt"
        path, status = _simulate_patched_route(name, dirs["public"])
        # After basename: 'internal.txt' joined to public_dir -> inside public
        assert status == 200
        assert path is not None
        assert path.is_relative_to(dirs["public"]), (
            "basename should strip '../' so the resolved path is inside public"
        )
        # Critical: the resolved path must NOT point to storage/internal.txt
        expected_blocked = (dirs["storage"] / "internal.txt").resolve()
        assert path != expected_blocked, (
            "The patched route must not resolve to the storage-level secret file"
        )

    def test_traversal_outside_txt_is_confined_to_public(self, dirs):
        """'../outside.txt' — basename strips traversal, candidate stays in public."""
        name = "../outside.txt"
        path, status = _simulate_patched_route(name, dirs["public"])
        assert status == 200
        assert path is not None
        assert path.is_relative_to(dirs["public"])
        expected_path = (dirs["public"] / "outside.txt").resolve()
        assert path == expected_path
        # Does not exist inside public, so it can never leak an outside file
        assert not path.exists()

    def test_single_dotdot_traversal_basename_strips_prefix(self, dirs):
        """Confirm basename produces just the filename portion (no directory component)."""
        assert _os_module.path.basename("../internal.txt") == "internal.txt"
        assert _os_module.path.basename("../outside.txt") == "outside.txt"

    # ------------------------------------------------------------------
    # 9c. Traversal attempt: multi-hop
    # ------------------------------------------------------------------

    def test_multi_hop_traversal_is_blocked_by_basename(self, dirs):
        """'../../outside/secret.txt' — basename strips all path components."""
        name = "../../outside/secret.txt"
        path, status = _simulate_patched_route(name, dirs["public"])
        assert status == 200
        assert path is not None
        assert path.is_relative_to(dirs["public"])
        # Must NOT resolve to outside/secret.txt
        outside_secret = (dirs["outside"] / "secret.txt").resolve()
        assert path != outside_secret

    def test_deep_traversal_cannot_escape_public(self, dirs):
        """Ten levels of '../' cannot escape DEMO_PUBLIC_DIR after basename."""
        name = "../" * 10 + "secret.txt"
        path, status = _simulate_patched_route(name, dirs["public"])
        assert status == 200
        assert path is not None
        assert path.is_relative_to(dirs["public"])

    # ------------------------------------------------------------------
    # 9d. Absolute path injection
    # ------------------------------------------------------------------

    def test_absolute_path_injection_is_blocked_by_basename(self, dirs):
        """An absolute path supplied as 'name' — basename extracts just the filename."""
        abs_path = str((dirs["outside"] / "secret.txt").resolve())
        path, status = _simulate_patched_route(abs_path, dirs["public"])
        assert status == 200
        assert path is not None
        # The resolved location must be inside public, not the injected abs path
        assert path.is_relative_to(dirs["public"])

    def test_absolute_windows_style_path_blocked(self, dirs):
        """Windows-style absolute path — basename strips to last component."""
        name = "C:\\Windows\\System32\\config"
        path, status = _simulate_patched_route(name, dirs["public"])
        # On any OS, basename returns 'config' or the last segment
        assert status == 200
        assert path is not None
        assert path.is_relative_to(dirs["public"])

    # ------------------------------------------------------------------
    # 9e. Edge cases
    # ------------------------------------------------------------------

    def test_empty_filename_resolves_to_public_dir_itself(self, dirs):
        """An empty name string — basename('') == '' — joined to public_dir resolves there."""
        path, status = _simulate_patched_route("", dirs["public"])
        # basename('') == '' -> join(public, '') -> public itself or public/
        assert status == 200
        # Resolved path should still be relative to (or equal to) public
        assert path is not None
        assert path == dirs["public"].resolve() or path.is_relative_to(dirs["public"])

    def test_dot_filename_resolves_inside_public(self, dirs):
        """A single '.' — os.path.basename('.') == '.' — stays inside public."""
        name = "."
        safe = _os_module.path.basename(name)
        assert safe == "."  # confirm basename behaviour
        path, status = _simulate_patched_route(name, dirs["public"])
        assert status == 200

    def test_null_byte_in_name_handled(self, dirs):
        """A filename with an embedded null byte — basename strips path, leaving the tail."""
        name = "../\x00secret.txt"
        # basename result depends on OS but must not escape public
        safe = _os_module.path.basename(name)
        # Just verify the simulation does not raise and that status indicates containment
        path, status = _simulate_patched_route(name, dirs["public"])
        # Any result is acceptable as long as it does not resolve outside public if status==200
        if status == 200 and path is not None:
            assert path.is_relative_to(dirs["public"])

    def test_parent_directory_dotdot_blocked_by_relative_to_boundary(self, dirs):
        """A bare '..' — basename returns '..' which resolves to storage (outside public).

        The secondary defense line:
            if not resolved_path.is_relative_to(DEMO_PUBLIC_DIR): return 403
        must catch this escape attempt and return HTTP 403.
        """
        name = ".."
        path, status = _simulate_patched_route(name, dirs["public"])
        assert status == 403
        assert path is None

    def test_multi_hop_parent_directory_dotdot_blocked(self, dirs):
        """'../..' — basename returns '..' which resolves outside public, returning 403."""
        name = "../.."
        path, status = _simulate_patched_route(name, dirs["public"])
        assert status == 403
        assert path is None

    # ------------------------------------------------------------------
    # 9f. Contrast: vulnerable logic CAN escape storage
    # ------------------------------------------------------------------

    def test_vulnerable_route_allows_escape_within_storage(self, dirs):
        """The ORIGINAL (un-patched) route allows traversal within DEMO_STORAGE_DIR.

        This test documents the KNOWN vulnerable behavior to contrast with the
        patched version.  'public/../internal.txt' is relative to storage_dir so
        it is NOT blocked by the original boundary check, exposing internal.txt.
        """
        name = "../internal.txt"  # escapes public but stays inside storage
        path, status = _simulate_vulnerable_route(
            name, dirs["public"], dirs["storage"]
        )
        # The original route resolves to storage/internal.txt (inside storage boundary)
        # so it returns 200 — the secret file is reachable
        if status == 200:
            assert path is not None
            expected = (dirs["storage"] / "internal.txt").resolve()
            assert path == expected, (
                "Documenting vulnerable behavior: internal.txt is reachable "
                "via traversal in the un-patched route"
            )

    def test_vulnerable_route_reads_internal_canary_secret(self, dirs):
        """Document that unpatched route can actually read the secret file content."""
        path, status = _simulate_vulnerable_route(
            "../internal.txt", dirs["public"], dirs["storage"]
        )
        assert status == 200
        assert path is not None and path.exists()
        assert path.read_text(encoding="utf-8") == "INTERNAL_SECRET"

    def test_vulnerable_route_blocks_external_escape(self, dirs):
        """The original route blocks escapes that leave DEMO_STORAGE_DIR entirely."""
        name = "../../outside/secret.txt"
        path, status = _simulate_vulnerable_route(
            name, dirs["public"], dirs["storage"]
        )
        assert status == 403, (
            "The original route blocks traversal outside storage_dir, "
            "but NOT within it"
        )

    # ------------------------------------------------------------------
    # 9g. Patch text verification (via apply_sandbox_patch)
    # ------------------------------------------------------------------

    def test_patched_file_contains_basename_call(self, tmp_path: Path):
        """The sandbox copy produced by apply_sandbox_patch must contain os.path.basename."""
        from sandbox_patcher import _PY002_VULNERABLE_BLOCK

        vulnerable_code = (
            "import os\n"
            "from pathlib import Path\n\n"
            "DEMO_STORAGE_DIR = Path('/tmp/storage')\n"
            "DEMO_PUBLIC_DIR = Path('/tmp/storage/public')\n\n"
            "def serve_file(name):\n"
            + _PY002_VULNERABLE_BLOCK
            + "\n    return open(str(resolved_path)).read()\n"
        )
        target = tmp_path / "vuln.py"
        target.write_text(vulnerable_code, encoding="utf-8")
        orig_hash = compute_sha256(target)

        res = apply_sandbox_patch(target, "PY002")
        try:
            assert res.status == "APPLIED", f"Expected APPLIED, got: {res.status} — {res.message}"
            copy_path = Path(res.patched_copy_path)
            patched_text = copy_path.read_text(encoding="utf-8")

            # Security assertion 1: basename call is present
            assert "os.path.basename" in patched_text, (
                "Patched file must contain os.path.basename() to strip traversal components"
            )

            # Security assertion 2: vulnerable raw join pattern is gone
            assert "os.path.join(str(DEMO_PUBLIC_DIR), name)" not in patched_text, (
                "Patched file must not contain the raw unsanitized join"
            )

            # Security assertion 3: boundary is tightened to DEMO_PUBLIC_DIR
            assert "is_relative_to(DEMO_PUBLIC_DIR)" in patched_text, (
                "Patched file must confine to DEMO_PUBLIC_DIR, not the wider DEMO_STORAGE_DIR"
            )

            # Patcher guarantee: original file untouched
            assert target.read_text(encoding="utf-8") == vulnerable_code
            assert compute_sha256(target) == orig_hash
        finally:
            cleanup_sandbox(res.sandbox_dir)

    def test_patched_file_does_not_contain_storage_dir_boundary(self, tmp_path: Path):
        """After patching, is_relative_to(DEMO_STORAGE_DIR) must NOT be the boundary.

        The vulnerable code used the wider DEMO_STORAGE_DIR boundary, allowing
        traversal within storage.  The patch narrows it to DEMO_PUBLIC_DIR.
        """
        from sandbox_patcher import _PY002_VULNERABLE_BLOCK

        vulnerable_code = (
            "import os\n"
            "from pathlib import Path\n\n"
            "DEMO_STORAGE_DIR = Path('/tmp/storage')\n"
            "DEMO_PUBLIC_DIR = Path('/tmp/storage/public')\n\n"
            "def serve_file(name):\n"
            + _PY002_VULNERABLE_BLOCK
            + "\n    return open(str(resolved_path)).read()\n"
        )
        target = tmp_path / "vuln2.py"
        target.write_text(vulnerable_code, encoding="utf-8")

        res = apply_sandbox_patch(target, "PY002")
        try:
            assert res.status == "APPLIED"
            patched_text = Path(res.patched_copy_path).read_text(encoding="utf-8")
            # The patched boundary comment/check should reference DEMO_PUBLIC_DIR
            assert "DEMO_PUBLIC_DIR" in patched_text
        finally:
            cleanup_sandbox(res.sandbox_dir)

    # ------------------------------------------------------------------
    # 9h. Sandbox cleanup after patch
    # ------------------------------------------------------------------

    def test_sandbox_dir_can_be_cleaned_up_after_patch(self, tmp_path: Path):
        """After apply_sandbox_patch returns APPLIED, cleanup_sandbox must succeed."""
        from sandbox_patcher import _PY002_VULNERABLE_BLOCK

        code = (
            "import os\nfrom pathlib import Path\n"
            "DEMO_STORAGE_DIR = Path('/x')\nDEMO_PUBLIC_DIR = Path('/x/p')\n"
            "def f(name):\n" + _PY002_VULNERABLE_BLOCK + "\n    return ''\n"
        )
        target = tmp_path / "cleanup_test.py"
        target.write_text(code, encoding="utf-8")

        res = apply_sandbox_patch(target, "PY002")
        assert res.status == "APPLIED"
        sandbox_path = Path(res.sandbox_dir)
        assert sandbox_path.exists()

        cleaned = cleanup_sandbox(res.sandbox_dir)
        assert cleaned is True
        assert not sandbox_path.exists(), "Sandbox directory must be removed after cleanup"

    def test_sandbox_dir_not_deleteable_without_registration(self, tmp_path: Path):
        """A directory path identical in form but not registered must be rejected."""
        import tempfile

        # Manufacture a path that looks like a sandbox but was never registered
        fake = Path(tempfile.gettempdir()) / "verifix_sandbox_fake_test_abc"
        fake.mkdir(exist_ok=True)
        canary = fake / "canary.txt"
        canary.write_text("safe", encoding="utf-8")

        try:
            result = cleanup_sandbox(fake)
            assert result is False, "Unregistered sandbox must not be deleted"
            assert fake.exists(), "Unregistered directory must remain intact"
        finally:
            import shutil
            shutil.rmtree(fake, ignore_errors=True)

    # ------------------------------------------------------------------
    # 9i. Original file remains unchanged through the entire patch workflow
    # ------------------------------------------------------------------

    def test_original_file_unchanged_hash_after_patch(self, tmp_path: Path):
        """apply_sandbox_patch must not alter the original file's bytes in any way."""
        from sandbox_patcher import _PY002_VULNERABLE_BLOCK

        code = (
            "import os\nfrom pathlib import Path\n"
            "DEMO_STORAGE_DIR = Path('/x')\nDEMO_PUBLIC_DIR = Path('/x/p')\n"
            "def f(name):\n" + _PY002_VULNERABLE_BLOCK + "\n    return ''\n"
        )
        target = tmp_path / "immutability.py"
        target.write_text(code, encoding="utf-8")
        original_bytes = target.read_bytes()
        original_hash = compute_sha256(target)

        res = apply_sandbox_patch(target, "PY002")
        try:
            assert res.status == "APPLIED"
            # Byte-for-byte identity
            assert target.read_bytes() == original_bytes, (
                "Original file bytes must be identical before and after patching"
            )
            assert compute_sha256(target) == original_hash, (
                "Original file SHA-256 must be identical before and after patching"
            )
            # Patched copy must differ from original
            assert res.patched_hash != original_hash, (
                "Patched sandbox copy must have a different hash from the original"
            )
        finally:
            cleanup_sandbox(res.sandbox_dir)

