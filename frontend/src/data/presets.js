/**
 * Pre-packaged Python snippets illustrating VerifiX AST scanner rules,
 * reasoning hypotheses, and clean baseline comparisons.
 */

export const PRESET_SNIPPETS = [
  {
    id: 'py002-path-traversal',
    title: 'Path Traversal (PY002)',
    rule: 'PY002',
    severity: 'high',
    filename: 'file_viewer.py',
    description: 'Dynamic user input directly passed to os.path.join without boundary sanitization.',
    code: `import os
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)
PUBLIC_DIR = Path("/var/data/public")

@app.route("/download")
def download_file():
    filename = request.args.get("name", "")
    # Vulnerable: dynamic path concatenation without path canonicalization
    filepath = os.path.join(str(PUBLIC_DIR), filename)
    
    with open(filepath, "r", encoding="utf-8") as f:
        return jsonify({"content": f.read()})
`,
  },
  {
    id: 'py003-sqli',
    title: 'SQL Injection (PY003)',
    rule: 'PY003',
    severity: 'high',
    filename: 'user_search.py',
    description: 'Dynamic SQL query built via f-string formatting instead of parameterized query.',
    code: `import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/search")
def search_user():
    username = request.args.get("user", "")
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # Vulnerable: string formatting in SQL statement creates SQLi
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    return jsonify({"users": rows})
`,
  },
  {
    id: 'auth001-bola',
    title: 'BOLA Authorization (AUTH001)',
    rule: 'AUTH001',
    severity: 'medium',
    filename: 'document_service.py',
    description: 'Route accesses DOCUMENTS dictionary by ID without validating document ownership.',
    code: `from flask import Flask, request, jsonify

app = Flask(__name__)

DOCUMENTS = {
    101: {"owner": "alice", "data": "Alice Confidential Report"},
    102: {"owner": "bob", "data": "Bob Financial Statement"},
}

@app.route("/documents/<int:doc_id>")
def get_document(doc_id):
    # Vulnerable: identifies requester but does not verify doc owner
    requester = request.headers.get("X-User-Id")
    doc = DOCUMENTS.get(doc_id)
    if not doc:
        return jsonify({"error": "Not found"}), 404
        
    return jsonify({"doc": doc})
`,
  },
  {
    id: 'py001-eval',
    title: 'Dynamic Eval (PY001)',
    rule: 'PY001',
    severity: 'critical',
    filename: 'calc_handler.py',
    description: 'eval() called on dynamic variable input allowing arbitrary code execution.',
    code: `def calculate_expression(formula_str):
    # Vulnerable: eval on dynamic variable permits arbitrary code execution
    result = eval(formula_str)
    return {"result": result}
`,
  },
  {
    id: 'py004-shell',
    title: 'Shell Command (PY004)',
    rule: 'PY004',
    severity: 'critical',
    filename: 'system_tool.py',
    description: 'subprocess.run executing dynamic variable with shell=True.',
    code: `import subprocess

def run_backup(backup_target):
    # Vulnerable: dynamic shell command allows shell injection
    cmd = f"tar -czf backup.tar.gz {backup_target}"
    subprocess.run(cmd, shell=True)
`,
  },
  {
    id: 'py005-secret',
    title: 'Hardcoded Secret (PY005)',
    rule: 'PY005',
    severity: 'medium',
    filename: 'config.py',
    description: 'Hardcoded API secret token stored in plaintext source code.',
    code: `API_KEY = "sk_live_9948274928172938471928"
DATABASE_PASSWORD = "SuperSecretDatabasePassword123!"

def connect():
    pass
`,
  },
  {
    id: 'clean-safe-baseline',
    title: 'Safe Baseline (Negative)',
    rule: 'NONE',
    severity: 'safe',
    filename: 'secure_service.py',
    description: 'Hardened code with parameterized queries, basename sanitization, and auth checks.',
    code: `import os
import sqlite3
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)
STORAGE_DIR = Path("/var/data/storage").resolve()
DOCUMENTS = {
    1: {"owner": "alice", "title": "Public Guide"},
}

@app.route("/file")
def safe_file_read():
    name = request.args.get("name", "")
    safe_name = os.path.basename(name)
    resolved = (STORAGE_DIR / safe_name).resolve()
    if not resolved.is_relative_to(STORAGE_DIR):
        return jsonify({"error": "Forbidden"}), 403
    return jsonify({"path": str(resolved)})

@app.route("/user")
def safe_user_query():
    user = request.args.get("user", "")
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # Safe: parameterized placeholder
    cursor.execute("SELECT id, username FROM users WHERE username = ?", (user,))
    return jsonify({"users": cursor.fetchall()})
`,
  },
  {
    id: 'syntax-error-demo',
    title: 'Syntax Error (400 Demo)',
    rule: 'SYNTAX',
    severity: 'error',
    filename: 'broken.py',
    description: 'Demonstrates HTTP 400 Bad Request error handling for invalid Python syntax.',
    code: `def broken_function(:
    invalid_python = 123
    return invalid_python
`,
  },
];
