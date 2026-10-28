from flask import Flask, jsonify

app = Flask(__name__)

# Demo-only data for local security testing
DOCUMENTS = {
    1: {"owner": "alice", "content": "Alice's private document"},
    2: {"owner": "bob", "content": "Bob's private document"},
}

# Deliberately vulnerable: checks whether a document exists,
# but does not check whether the requester owns it.
@app.get("/documents/<int:document_id>")
def get_document(document_id):
    document = DOCUMENTS.get(document_id)

    if document is None:
        return jsonify({"error": "Document not found"}), 404

    return jsonify(document)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
