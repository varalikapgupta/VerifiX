
from flask import Flask, jsonify, request

app = Flask(__name__)

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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
