
import ast
import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SECRET_NAME_RE = re.compile(
    r"(password|passwd|secret|api_key|apikey|token|auth_key|private_key)",
    re.IGNORECASE,
)

_SQL_KEYWORDS_RE = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|REPLACE)\b",
    re.IGNORECASE,
)

_SHELL_FUNCS = {
    # module  → set of attribute names
    "subprocess": {"run", "Popen", "call", "check_call", "check_output"},
    "os": {"system", "popen"},
}


def _is_dynamic(node: ast.expr) -> bool:
    """Return True when *node* is not a plain string/bytes/numeric literal."""
    return not isinstance(node, ast.Constant)


def _is_dynamic_shell_arg(node: ast.expr) -> bool:
    """Return True when *node* is a dynamic shell command argument.

    Safe lookalikes that must NOT fire:
      - A plain string constant: ``"ls"``
      - A list/tuple of all-Constant elements: ``["ls", "-l"]``
    """
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, (ast.List, ast.Tuple)):
        return any(not isinstance(elt, ast.Constant) for elt in node.elts)
    return True


def _constant_value(node: ast.expr) -> str | None:
    """Return the string value of a Constant node, or None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


# ---------------------------------------------------------------------------
# Rule PY001 — eval / exec with a dynamic argument
# ---------------------------------------------------------------------------

def _check_eval_exec(node: ast.AST) -> dict | None:
    """PY001: eval() or exec() whose first argument is not a plain literal."""
    if not isinstance(node, ast.Call):
        return None
    if not isinstance(node.func, ast.Name):
        return None
    if node.func.id not in {"eval", "exec"}:
        return None
    args = node.args
    if not args:
        return None
    if not _is_dynamic(args[0]):
        return None  # eval("literal") — safe lookalike, skip
    return {
        "rule": "PY001",
        "type": "Dynamic code execution",
        "line": node.lineno,
        "evidence": f"{node.func.id}() called with a non-literal argument",
        "severity": "high",
    }


# ---------------------------------------------------------------------------
# Rule PY002 — unsafe dynamic component in os.path.join
# ---------------------------------------------------------------------------

def _check_path_join(node: ast.AST) -> dict | None:
    """PY002: os.path.join() where any argument after the first is dynamic."""
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    # Match os.path.join(...)
    if not (
        isinstance(func, ast.Attribute)
        and func.attr == "join"
        and isinstance(func.value, ast.Attribute)
        and func.value.attr == "path"
        and isinstance(func.value.value, ast.Name)
        and func.value.value.id == "os"
    ):
        return None
    # Warn if any argument beyond the base (index 0) is dynamic
    dynamic_args = [a for a in node.args[1:] if _is_dynamic(a)]
    if not dynamic_args:
        return None
    return {
        "rule": "PY002",
        "type": "Unsafe dynamic path component",
        "line": node.lineno,
        "evidence": "os.path.join() receives a non-literal path component",
        "severity": "high",
    }


# ---------------------------------------------------------------------------
# Rule PY003 — dynamic SQL formatting passed to cursor.execute
# ---------------------------------------------------------------------------

def _is_sql_format(node: ast.expr) -> bool:
    """Return True when *node* looks like a dynamically-formatted SQL string."""
    # f-string: JoinedStr
    if isinstance(node, ast.JoinedStr):
        return True
    # "SELECT ..." % var  or  "SELECT ..." + var
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        left_val = _constant_value(node.left)
        if left_val and _SQL_KEYWORDS_RE.search(left_val):
            return True
    # "SELECT ...".format(var)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        template = _constant_value(node.func.value)
        if template and _SQL_KEYWORDS_RE.search(template):
            return True
    return False


def _check_sql_format(node: ast.AST) -> dict | None:
    """PY003: dynamic SQL formatting passed to cursor.execute()."""
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if not (isinstance(func, ast.Attribute) and func.attr == "execute"):
        return None
    if not node.args:
        return None
    first_arg = node.args[0]
    if not _is_sql_format(first_arg):
        return None
    return {
        "rule": "PY003",
        "type": "SQL injection via dynamic formatting",
        "line": node.lineno,
        "evidence": "cursor.execute() receives a dynamically-formatted SQL string",
        "severity": "high",
    }


# ---------------------------------------------------------------------------
# Rule PY004 — dynamic command in subprocess / os.system
# ---------------------------------------------------------------------------

def _check_shell_cmd(node: ast.AST) -> dict | None:
    """PY004: subprocess.run/Popen/… or os.system called with a dynamic first arg."""
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if not isinstance(func, ast.Attribute):
        return None
    module_node = func.value
    if not isinstance(module_node, ast.Name):
        return None
    module_name = module_node.id
    attr_name = func.attr
    if module_name not in _SHELL_FUNCS:
        return None
    if attr_name not in _SHELL_FUNCS[module_name]:
        return None
    if not node.args:
        return None
    if not _is_dynamic_shell_arg(node.args[0]):
        return None  # literal command string or list — safe lookalike
    return {
        "rule": "PY004",
        "type": "Dynamic shell command",
        "line": node.lineno,
        "evidence": (
            f"{module_name}.{attr_name}() receives a non-literal "
            "first argument (potential command injection)"
        ),
        "severity": "high",
    }


# ---------------------------------------------------------------------------
# Rule PY005 — hardcoded secret in assignment
# ---------------------------------------------------------------------------

def _check_hardcoded_secret(node: ast.AST) -> dict | None:
    """PY005: assignment to a secret-like name with a non-empty string literal."""
    targets = []
    value = None

    if isinstance(node, ast.Assign):
        targets = node.targets
        value = node.value
    elif isinstance(node, ast.AnnAssign) and node.value is not None:
        targets = [node.target]
        value = node.value
    else:
        return None

    if not isinstance(value, ast.Constant):
        return None
    if not isinstance(value.value, str) or not value.value.strip():
        return None

    for target in targets:
        if isinstance(target, ast.Name) and _SECRET_NAME_RE.search(target.id):
            return {
                "rule": "PY005",
                "type": "Hardcoded secret",
                "line": node.lineno,
                "evidence": (
                    f"'{target.id}' assigned a non-empty string literal "
                    "(possible hardcoded credential)"
                ),
                "severity": "high",
            }
    return None


# ---------------------------------------------------------------------------
# Rule AUTH001 — missing ownership check on a document route (unchanged)
# ---------------------------------------------------------------------------

def _check_auth(node: ast.AST) -> dict | None:
    """AUTH001: Flask route accesses DOCUMENTS without an ownership check."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    is_route = any(
        isinstance(d, ast.Call)
        and isinstance(d.func, ast.Attribute)
        and d.func.attr in {"route", "get", "post"}
        for d in node.decorator_list
    )
    names = {
        child.id
        for child in ast.walk(node)
        if isinstance(child, ast.Name)
    }
    if is_route and "DOCUMENTS" in names and not (
        {"owner", "current_user", "user_id"} & names
    ):
        return {
            "rule": "AUTH001",
            "type": "Possible missing authorization check",
            "line": node.lineno,
            "evidence": "Route accesses DOCUMENTS without an obvious ownership check",
            "severity": "medium",
        }
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_CHECKERS = [
    _check_eval_exec,
    _check_path_join,
    _check_sql_format,
    _check_shell_cmd,
    _check_hardcoded_secret,
    _check_auth,
]


def scan_source(source: str, filename: str = "<string>") -> list[dict]:
    """Parse *source* and return a list of finding dicts.

    Raises ``SyntaxError`` if *source* is not valid Python.
    """
    tree = ast.parse(source, filename=filename)
    findings: list[dict] = []
    for node in ast.walk(tree):
        for checker in _CHECKERS:
            result = checker(node)
            if result is not None:
                findings.append(result)
    return findings


def scan_file(file_path) -> list[dict]:
    """Read *file_path* and delegate to ``scan_source``."""
    source = Path(file_path).read_text(encoding="utf-8")
    return scan_source(source, filename=str(file_path))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    target = Path("vulnerable_app.py")
    findings = scan_file(target)

    print(f"Scanned: {target}")
    print(f"Findings: {len(findings)}")

    for finding in findings:
        print(f"\n[{finding['severity'].upper()}] {finding['type']}")
        print(f"Rule: {finding['rule']}")
        print(f"Line: {finding['line']}")
        print(f"Evidence: {finding['evidence']}")
