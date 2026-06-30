from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, request


app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
SAFE_DIR = BASE_DIR / "safe_files"
USERS = {
    "1": {"id": 1, "name": "Alice", "role": "student"},
    "2": {"id": 2, "name": "Bob", "role": "reviewer"},
}


@app.get("/")
def index():
    return jsonify({"name": "Heimdall local vulnerable test app", "local_only": True})


@app.get("/xss")
def xss():
    # Intentionally vulnerable local-only reflection for validation testing.
    return f"<h1>{request.args.get('q', '')}</h1>"


@app.post("/login")
def login():
    username = request.json.get("username", "") if request.is_json else request.form.get("username", "")
    query = "SELECT * FROM users WHERE name = '%s'" % username
    if "' OR '1'='1" in username:
        return jsonify({"authenticated": True, "query": query, "marker": "HEIMDALL_SQL_PROBE"})
    return jsonify({"authenticated": username in {"alice", "bob"}, "query": query})


@app.get("/file")
def file_lookup():
    requested = request.args.get("name", "readme.txt")
    target = SAFE_DIR / requested
    if ".." in requested:
        return jsonify({"blocked": False, "marker": "HEIMDALL_TRAVERSAL_PROBE", "requested": requested})
    return target.read_text(encoding="utf-8") if target.exists() else ("missing", 404)


@app.get("/user/<user_id>")
def user_profile(user_id: str):
    return jsonify(USERS.get(user_id, {}))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
