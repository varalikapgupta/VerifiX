"""
tests/test_demo_endpoints.py
============================
Focused tests for the demo endpoints in backend/vulnerable_app.py:
- Preserved BOLA endpoint: GET /documents/<int:document_id>
- Path-traversal demo:     GET /files
- SQL-injection demo:      GET /users

All tests run in-process using Flask's test client, requiring no open ports
or external database services.
"""

import sys
from pathlib import Path
import pytest

# Ensure backend/ is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vulnerable_app import app, DEMO_STORAGE_DIR, DEMO_PUBLIC_DIR, _USERS_DATASET


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# ===========================================================================
# 1. Preserved BOLA endpoint: GET /documents/<document_id>
# ===========================================================================

class TestDocumentsEndpoint:

    def test_authorized_owner_access(self, client):
        """Alice requests her own document (document 1)."""
        resp = client.get("/documents/1", headers={"X-Test-User": "alice"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["requested_by"] == "alice"
        assert data["document"]["owner"] == "alice"

    def test_bola_cross_user_access_preserved(self, client):
        """Alice requests Bob's document (document 2) — demonstrates BOLA."""
        resp = client.get("/documents/2", headers={"X-Test-User": "alice"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["requested_by"] == "alice"
        assert data["document"]["owner"] == "bob"

    def test_missing_identity_header(self, client):
        """Request without X-Test-User header should return 401."""
        resp = client.get("/documents/1")
        assert resp.status_code == 401
        assert "error" in resp.get_json()

    def test_document_not_found(self, client):
        """Request for nonexistent document ID should return 404."""
        resp = client.get("/documents/999", headers={"X-Test-User": "alice"})
        assert resp.status_code == 404


# ===========================================================================
# 2. Path-traversal endpoint: GET /files
# ===========================================================================

class TestFilesEndpoint:

    def test_missing_name_parameter(self, client):
        resp = client.get("/files")
        assert resp.status_code == 400
        assert "Missing 'name' query parameter" in resp.get_json()["error"]

    def test_safe_in_bounds_read(self, client):
        """Reading sample.txt within demo_storage/public succeeds normally."""
        resp = client.get("/files", query_string={"name": "sample.txt"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "Public document" in data["content"]
        assert data["traversal_demonstrated"] is False

    def test_controlled_path_traversal(self, client):
        """Reading ../demo_secret.txt traverses out of public/ into demo_storage."""
        resp = client.get("/files", query_string={"name": "../demo_secret.txt"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "DEMO_SECRET" in data["content"]
        assert data["traversal_demonstrated"] is True

    def test_out_of_bounds_traversal_blocked(self, client):
        """Attempting to escape demo_storage to read repo/system files is blocked with 403."""
        # Escape attempts toward repo root or system files
        payloads = [
            "../../vulnerable_app.py",
            "../../../main.py",
            "../../../../Windows/win.ini",
            "../../../../etc/passwd",
        ]
        for payload in payloads:
            resp = client.get("/files", query_string={"name": payload})
            assert resp.status_code == 403, f"Payload {payload} should have been forbidden"
            assert "Access denied" in resp.get_json()["error"]

    def test_file_not_found_within_sandbox(self, client):
        resp = client.get("/files", query_string={"name": "nonexistent_file.txt"})
        assert resp.status_code == 404


# ===========================================================================
# 3. SQL-injection endpoint: GET /users
# ===========================================================================

class TestUsersEndpoint:

    def test_missing_name_parameter(self, client):
        resp = client.get("/users")
        assert resp.status_code == 400
        assert "Missing 'name' query parameter" in resp.get_json()["error"]

    def test_valid_user_lookup(self, client):
        """Looking up alice returns Alice's record with email."""
        resp = client.get("/users", query_string={"name": "alice"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 1
        assert data["email"] == "alice@example.com"
        assert data["results"][0]["username"] == "alice"
        assert data["sql_injection_demonstrated"] is False

    def test_user_not_found(self, client):
        resp = client.get("/users", query_string={"name": "nonexistent_user"})
        assert resp.status_code == 404
        assert "User not found" in resp.get_json()["error"]

    def test_sql_injection_tautology_returns_all_users(self, client):
        """Injecting ' OR '1'='1 returns all records in the in-memory dataset."""
        resp = client.get("/users", query_string={"name": "' OR '1'='1"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == len(_USERS_DATASET)
        assert data["count"] >= 3
        assert data["sql_injection_demonstrated"] is True
        usernames = [u["username"] for u in data["results"]]
        assert "alice" in usernames
        assert "bob" in usernames
        assert "admin" in usernames

    def test_sql_injection_comment_bypass(self, client):
        """Injecting admin' -- returns admin record directly."""
        resp = client.get("/users", query_string={"name": "admin' --"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 1
        assert data["results"][0]["username"] == "admin"
        assert data["results"][0]["role"] == "admin"

    def test_malformed_sql_syntax_error(self, client):
        """Unclosed quote returns 400 with SQL execution error, not unhandled crash."""
        resp = client.get("/users", query_string={"name": "' OR"})
        assert resp.status_code == 400
        assert "SQL execution error" in resp.get_json()["error"]
