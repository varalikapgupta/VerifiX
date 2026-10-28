
import ast
from pathlib import Path


def scan_file(file_path):
    source = Path(file_path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    findings = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in {"eval", "exec"}:
                    findings.append({
                        "rule": "PY001",
                        "type": "Dynamic code execution",
                        "line": node.lineno,
                        "evidence": f"{node.func.id}() call detected",
                        "severity": "high",
                    })

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
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
                findings.append({
                    "rule": "AUTH001",
                    "type": "Possible missing authorization check",
                    "line": node.lineno,
                    "evidence": "Route accesses DOCUMENTS without an obvious ownership check",
                    "severity": "medium",
                })

    return findings


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

