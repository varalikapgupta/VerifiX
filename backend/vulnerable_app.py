import os
from pathlib import Path
import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# BOLA fixture (original — unchanged)
# ---------------------------------------------------------------------------

# Demo-only users and documents.
# This is a local test fixture, not real authentication.
DOCUMENTS = {
    1: {"owner": "alice", "content": "Alice's private document"},
    2: {"owner": "bob", "content": "Bob's private document"},
}


@app.get("/documents/<int:document_id>")
def get_document(document_id):
    document = DOCUMENTS.get(document_id)

    if document is None:
        return jsonify({"error": "Document not found"}), 404

    # DEMO ONLY: identity supplied by request header.
    # This is NOT secure authentication.
    user = request.headers.get("X-Test-User")

    if not user:
        return jsonify({"error": "Missing test identity"}), 401

    # Deliberately vulnerable:
    # We identify the requester but fail to check document ownership.
    return jsonify({
        "requested_by": user,
        "document": document,
    }), 200


# ---------------------------------------------------------------------------
# Path-traversal fixture (GET /files)
# DEMO ONLY: confined strictly to an isolated directory beneath the project.
# ---------------------------------------------------------------------------

DEMO_STORAGE_DIR = Path(__file__).resolve().parent / "demo_storage"
DEMO_PUBLIC_DIR = DEMO_STORAGE_DIR / "public"


def _init_demo_filesystem() -> None:
    """Initialize isolated local demo storage beneath the project."""
    DEMO_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    DEMO_PUBLIC_DIR.mkdir(parents=True, exist_ok=True)

    # Safe public document inside public directory
    public_file = DEMO_PUBLIC_DIR / "sample.txt"
    if not public_file.exists():
        public_file.write_text("Public document: Welcome to VerifiX Demo.", encoding="utf-8")

    # Internal demo secret located in DEMO_STORAGE_DIR (one level above public/)
    secret_file = DEMO_STORAGE_DIR / "demo_secret.txt"
    if not secret_file.exists():
        secret_file.write_text(
            "DEMO_SECRET: safe_local_traversal_confirmed (demo fixture only)",
            encoding="utf-8",
        )


_init_demo_filesystem()


@app.get("/files")
def read_file():
    """DEMO ONLY — demonstrates path traversal confined to demo_storage.

    Vulnerable behavior:
    Uses uncanonicalized path join without validating against directory escape,
    allowing relative traversal ('../demo_secret.txt') out of public/.

    Safety confinement:
    Restricted strictly to DEMO_STORAGE_DIR. Never reads arbitrary OS files or
    repository secrets (returns 403 Forbidden if path escapes demo root).
    """
    name = request.args.get("name", "")
    if not name:
        return jsonify({"error": "Missing 'name' query parameter"}), 400

    # DELIBERATELY VULNERABLE: dynamic path component in os.path.join
    # (Triggers AST rule PY002 during static scans)
    candidate_path = os.path.join(str(DEMO_PUBLIC_DIR), name)
    resolved_path = Path(candidate_path).resolve()

    # SAFETY BOUNDARY: strictly confine within the isolated demo storage directory.
    # Never allow reading arbitrary OS files or repository secrets.
    if not resolved_path.is_relative_to(DEMO_STORAGE_DIR):
        return jsonify({
            "error": "Access denied: demonstration is strictly confined to isolated demo directory",
        }), 403

    try:
        content = resolved_path.read_text(encoding="utf-8", errors="replace")
        is_traversal = not resolved_path.is_relative_to(DEMO_PUBLIC_DIR)
        return jsonify({
            "filename": name,
            "content": content,
            "traversal_demonstrated": is_traversal,
        }), 200
    except IsADirectoryError:
        return jsonify({"error": "Path is a directory"}), 400
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403


# ---------------------------------------------------------------------------
# SQL-injection fixture (GET /users)
# DEMO ONLY: in-memory dataset, no external/real database connection.
# ---------------------------------------------------------------------------

_USERS_DATASET = [
    {"id": 1, "username": "alice", "role": "user", "email": "alice@example.com"},
    {"id": 2, "username": "bob", "role": "user", "email": "bob@example.com"},
    {"id": 3, "username": "admin", "role": "admin", "email": "admin@example.com"},
]


def _get_in_memory_db() -> sqlite3.Connection:
    """Creates an isolated in-memory SQLite connection seeded with _USERS_DATASET.

    No database files are created on disk and no real database is connected.
    """
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, email TEXT)"
    )
    for u in _USERS_DATASET:
        cursor.execute(
            "INSERT INTO users (id, username, role, email) VALUES (?, ?, ?, ?)",
            (u["id"], u["username"], u["role"], u["email"]),
        )
    conn.commit()
    return conn


@app.get("/users")
def get_user():
    """DEMO ONLY — demonstrates SQL injection against an in-memory dataset.

    Vulnerable behavior:
    Builds SQL query via string formatting (f-string) and executes it directly,
    allowing query manipulation (e.g., "' OR '1'='1") to bypass filtering.

    Safety confinement:
    Operates strictly on an isolated in-memory SQLite table (:memory:) initialized
    from a fixed dictionary dataset. No connection to any real database.
    """
    name = request.args.get("name", "")
    if not name:
        return jsonify({"error": "Missing 'name' query parameter"}), 400

    conn = _get_in_memory_db()
    cursor = conn.cursor()

    # DELIBERATELY VULNERABLE: dynamic SQL query formatting
    # (Triggers AST rule PY003 during static scans)
    query = f"SELECT id, username, role, email FROM users WHERE username = '{name}'"

    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()

        results = [
            {"id": row[0], "username": row[1], "role": row[2], "email": row[3]}
            for row in rows
        ]

        if not results:
            return jsonify({
                "error": "User not found",
                "query": query,
                "query_simulated": query,
            }), 404

        response_data = {
            "query": query,
            "query_simulated": query,
            "count": len(results),
            "results": results,
            # Provide top-level email for single user lookups
            "email": results[0]["email"] if len(results) == 1 else None,
            "sql_injection_demonstrated": len(results) > 1 or (
                len(results) == 1 and name.strip() != results[0]["username"]
            ),
        }
        return jsonify(response_data), 200

    except sqlite3.Error as exc:
        conn.close()
        return jsonify({
            "error": f"SQL execution error: {exc}",
            "query": query,
            "query_simulated": query,
        }), 400


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
