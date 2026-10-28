"""
tests/test_scanner.py
=====================
Unit tests for backend/static_scanner.py.

Coverage
--------
For every rule (PY001–PY005 and AUTH001):
  - vulnerable snippet  → rule must fire
  - safe lookalike      → rule must NOT fire

Cross-cutting:
  - empty source  → no findings, no crash
  - malformed Python → SyntaxError propagated cleanly
  - scan_file() basic smoke test

No real credentials, no network access, no subprocess calls.
"""

import os
import sys
import textwrap
import pytest

# Make the backend package importable regardless of where pytest is invoked.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from static_scanner import scan_source, scan_file  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rules(source: str) -> list[str]:
    """Return just the rule IDs found in *source*."""
    return [f["rule"] for f in scan_source(textwrap.dedent(source))]


def _has(source: str, rule: str) -> bool:
    return rule in _rules(source)


def _missing(source: str, rule: str) -> bool:
    return rule not in _rules(source)


# ===========================================================================
# PY001 — eval / exec with a dynamic argument
# ===========================================================================

class TestPY001:

    def test_vulnerable_eval_variable(self):
        src = "eval(user_input)"
        assert _has(src, "PY001"), "Should fire when eval() receives a variable"

    def test_vulnerable_exec_variable(self):
        src = "exec(payload)"
        assert _has(src, "PY001"), "Should fire when exec() receives a variable"

    def test_safe_eval_literal(self):
        src = 'eval("2 + 2")'
        assert _missing(src, "PY001"), "Should NOT fire for a plain string literal"

    def test_safe_exec_literal(self):
        src = 'exec("print(1)")'
        assert _missing(src, "PY001"), "Should NOT fire for a plain string literal"

    def test_finding_fields(self):
        findings = scan_source("eval(x)")
        match = [f for f in findings if f["rule"] == "PY001"]
        assert len(match) == 1
        f = match[0]
        assert f["severity"] == "high"
        assert f["line"] == 1
        assert "PY001" == f["rule"]
        assert f["evidence"]  # non-empty


# ===========================================================================
# PY002 — unsafe dynamic path component in os.path.join
# ===========================================================================

class TestPY002:

    def test_vulnerable_variable_component(self):
        src = "import os\nos.path.join('/srv', user_path)"
        assert _has(src, "PY002"), "Should fire when a variable is used as path component"

    def test_vulnerable_fstring_component(self):
        src = "import os\nos.path.join(base, f'{name}')"
        assert _has(src, "PY002")

    def test_safe_all_literals(self):
        src = "import os\nos.path.join('/srv', 'files', 'doc.txt')"
        assert _missing(src, "PY002"), "All-literal join should NOT fire"

    def test_safe_single_arg(self):
        src = "import os\nos.path.join('/srv')"
        assert _missing(src, "PY002"), "Single-arg join should NOT fire"

    def test_finding_fields(self):
        src = "import os\nos.path.join('/base', path_var)"
        findings = scan_source(src)
        match = [f for f in findings if f["rule"] == "PY002"]
        assert len(match) == 1
        f = match[0]
        assert f["severity"] == "high"
        assert f["line"] == 2


# ===========================================================================
# PY003 — SQL dynamic formatting passed to cursor.execute
# ===========================================================================

class TestPY003:

    def test_vulnerable_percent_format(self):
        src = 'cursor.execute("SELECT * FROM users WHERE name=\'%s\'" % name)'
        assert _has(src, "PY003"), "% formatting into execute() should fire"

    def test_vulnerable_str_format(self):
        src = 'cursor.execute("SELECT * FROM t WHERE id={}".format(uid))'
        assert _has(src, "PY003"), ".format() into execute() should fire"

    def test_vulnerable_fstring(self):
        src = 'cursor.execute(f"SELECT * FROM orders WHERE id={order_id}")'
        assert _has(src, "PY003"), "f-string into execute() should fire"

    def test_safe_parameterised_query(self):
        src = 'cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))'
        assert _missing(src, "PY003"), "Parameterised query should NOT fire"

    def test_safe_literal_sql(self):
        src = 'cursor.execute("SELECT 1")'
        assert _missing(src, "PY003"), "Plain literal should NOT fire"

    def test_finding_fields(self):
        src = 'cursor.execute("DELETE FROM t WHERE k=\'%s\'" % val)'
        findings = scan_source(src)
        match = [f for f in findings if f["rule"] == "PY003"]
        assert len(match) == 1
        assert match[0]["severity"] == "high"


# ===========================================================================
# PY004 — dynamic command in subprocess / os.system
# ===========================================================================

class TestPY004:

    def test_vulnerable_subprocess_run_variable(self):
        src = "import subprocess\nsubprocess.run(cmd)"
        assert _has(src, "PY004"), "subprocess.run(variable) should fire"

    def test_vulnerable_subprocess_popen_variable(self):
        src = "import subprocess\nsubprocess.Popen(cmd_args)"
        assert _has(src, "PY004")

    def test_vulnerable_os_system_variable(self):
        src = "import os\nos.system(user_cmd)"
        assert _has(src, "PY004"), "os.system(variable) should fire"

    def test_safe_subprocess_run_literal_list(self):
        src = 'import subprocess\nsubprocess.run(["ls", "-l"])'
        assert _missing(src, "PY004"), "All-literal list command should NOT fire"

    def test_vulnerable_subprocess_run_mixed_list(self):
        src = 'import subprocess\nsubprocess.run(["ls", user_dir])'
        assert _has(src, "PY004"), "List with a variable element should fire"

    def test_safe_os_system_literal(self):
        src = 'import os\nos.system("ls")'
        assert _missing(src, "PY004"), "Literal string command should NOT fire"

    def test_finding_fields(self):
        src = "import subprocess\nsubprocess.run(user_input)"
        findings = scan_source(src)
        match = [f for f in findings if f["rule"] == "PY004"]
        assert len(match) == 1
        f = match[0]
        assert f["severity"] == "high"
        assert f["line"] == 2
        assert "subprocess.run" in f["evidence"]


# ===========================================================================
# PY005 — hardcoded secret in assignment
# ===========================================================================

class TestPY005:

    def test_vulnerable_password(self):
        src = 'password = "hunter2"'
        assert _has(src, "PY005")

    def test_vulnerable_api_key(self):
        src = 'API_KEY = "sk-abc123secret"'
        assert _has(src, "PY005")

    def test_vulnerable_token(self):
        src = 'auth_token = "eyJhbGciOiJIUzI1NiJ9.payload"'
        assert _has(src, "PY005")

    def test_vulnerable_secret(self):
        src = 'db_secret = "s3cr3tP@ss"'
        assert _has(src, "PY005")

    def test_safe_empty_string(self):
        src = 'password = ""'
        assert _missing(src, "PY005"), "Empty string is a placeholder, not a secret"

    def test_safe_whitespace_string(self):
        src = 'secret = "   "'
        assert _missing(src, "PY005"), "Whitespace-only string should NOT fire"

    def test_safe_non_secret_name(self):
        src = 'username = "admin"'
        assert _missing(src, "PY005"), "Non-secret variable name should NOT fire"

    def test_safe_non_literal_value(self):
        src = 'password = os.environ.get("PASSWORD")'
        assert _missing(src, "PY005"), "Value from env var should NOT fire"

    def test_annotated_assignment(self):
        src = 'api_key: str = "abc123"'
        assert _has(src, "PY005"), "Annotated assignment should also fire"

    def test_finding_fields(self):
        src = 'token = "secret-value"'
        findings = scan_source(src)
        match = [f for f in findings if f["rule"] == "PY005"]
        assert len(match) == 1
        f = match[0]
        assert f["severity"] == "high"
        assert "token" in f["evidence"]


# ===========================================================================
# AUTH001 — missing ownership check on a document route (preserved)
# ===========================================================================

class TestAUTH001:

    def test_vulnerable_route_no_ownership(self):
        src = textwrap.dedent("""\
            from flask import Flask
            app = Flask(__name__)
            DOCUMENTS = {}

            @app.get("/docs/<int:doc_id>")
            def get_doc(doc_id):
                return DOCUMENTS.get(doc_id)
        """)
        assert _has(src, "AUTH001")

    def test_safe_route_with_owner_check(self):
        src = textwrap.dedent("""\
            from flask import Flask
            app = Flask(__name__)
            DOCUMENTS = {}

            @app.get("/docs/<int:doc_id>")
            def get_doc(doc_id):
                owner = DOCUMENTS.get(doc_id, {}).get("owner")
                current_user = "alice"
                if owner != current_user:
                    return {}, 403
                return DOCUMENTS.get(doc_id)
        """)
        assert _missing(src, "AUTH001")


# ===========================================================================
# Cross-cutting: empty and malformed input
# ===========================================================================

class TestEdgeCases:

    def test_empty_source_no_crash(self):
        findings = scan_source("")
        assert findings == [], "Empty source must produce zero findings"

    def test_blank_lines_no_crash(self):
        findings = scan_source("\n\n\n")
        assert findings == [], "Blank source must produce zero findings"

    def test_malformed_syntax_error(self):
        with pytest.raises(SyntaxError):
            scan_source("def broken(")

    def test_malformed_incomplete_string(self):
        with pytest.raises(SyntaxError):
            scan_source('x = "unterminated')

    def test_binary_garbage_syntax_error(self):
        with pytest.raises(SyntaxError):
            scan_source("\x00\xff\xfe not python")

    def test_valid_code_no_findings(self):
        src = textwrap.dedent("""\
            def add(a, b):
                return a + b

            result = add(1, 2)
            print(result)
        """)
        findings = scan_source(src)
        assert findings == [], "Clean code must produce zero findings"


# ===========================================================================
# scan_file() smoke test
# ===========================================================================

class TestScanFile:

    def test_scan_file_returns_list(self, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text('eval(user_input)\n', encoding="utf-8")
        findings = scan_file(f)
        assert isinstance(findings, list)
        assert any(x["rule"] == "PY001" for x in findings)

    def test_scan_file_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            scan_file(tmp_path / "nonexistent.py")

    def test_scan_file_clean_returns_empty(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("x = 1 + 1\n", encoding="utf-8")
        assert scan_file(f) == []
