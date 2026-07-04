from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, redirect, request


app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
FIXTURE_DIR = BASE_DIR / "fixtures"
FIXTURE_DIR.mkdir(exist_ok=True)
(FIXTURE_DIR / "public.txt").write_text("public fixture\n", encoding="utf-8")
(FIXTURE_DIR / "controlled_secret.txt").write_text(
    "HEIMDALL_PATH_MARKER\nHEIMDALL_TRAVERSAL_MARKER\n", encoding="utf-8"
)

FAKE_SECRET = "HEIMDALL_FAKE_SECRET_12345"
USERS = {
    "alice": {"id": "alice", "role": "user"},
    "bob": {"id": "bob", "role": "admin"},
}
OBJECTS = {
    "1001": {"owner": "alice", "value": "alice-owned-object"},
    "2002": {"owner": "bob", "value": "HEIMDALL_IDOR_MARKER other-user-object"},
    "3003": {"owner": "carol", "value": "HEIMDALL_IDOR_MARKER finance-object"},
}
COUPONS_USED: set[str] = set()


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "heimdall-local-lab"})


@app.get("/xss/vulnerable")
def xss_vulnerable():
    marker = request.args.get("marker", "HEIMDALL_XSS_MARKER")
    return f"<div>{marker}</div>"


@app.get("/xss/safe")
def xss_safe():
    marker = request.args.get("marker", "HEIMDALL_XSS_MARKER")
    return f"<div>{html.escape(marker)}</div>"


@app.get("/sql/vulnerable")
def sql_vulnerable():
    username = request.args.get("username", "")
    if "' OR '1'='1" in username or "heimdall_sqli_probe" in username.lower():
        return jsonify({"authenticated": True, "evidence": "HEIMDALL_SQLI_MARKER behavior_difference"})
    return jsonify({"authenticated": username == "alice"})


@app.get("/sql/safe")
def sql_safe():
    username = request.args.get("username", "")
    if username not in {"alice", "bob"}:
        return jsonify({"authenticated": False, "safe": True, "reason": "parameterized query rejected"}), 400
    return jsonify({"authenticated": True, "safe": True})


@app.get("/path/vulnerable")
def path_vulnerable():
    name = request.args.get("file", "public.txt")
    if ".." in name:
        return (FIXTURE_DIR / "controlled_secret.txt").read_text(encoding="utf-8")
    target = FIXTURE_DIR / name
    return target.read_text(encoding="utf-8") if target.exists() else ("missing", 404)


@app.get("/path/safe")
def path_safe():
    name = request.args.get("file", "public.txt")
    if ".." in name or name.startswith("/"):
        return jsonify({"blocked": True, "safe": True, "reason": "traversal blocked"}), 403
    return (FIXTURE_DIR / "public.txt").read_text(encoding="utf-8")


@app.get("/redirect/vulnerable")
def redirect_vulnerable():
    target = request.args.get("next", "/")
    return redirect(target, code=302)


@app.get("/redirect/safe")
def redirect_safe():
    target = request.args.get("next", "/health")
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return jsonify({"blocked": True, "safe": True, "evidence": "redirect normalized"}), 400
    return redirect(target if target.startswith("/") else "/health", code=302)


@app.get("/idor/vulnerable")
def idor_vulnerable():
    object_id = request.args.get("object_id", "1001")
    return jsonify(OBJECTS.get(object_id, {}))


@app.get("/idor/safe")
def idor_safe():
    object_id = request.args.get("object_id", "1001")
    user = request.args.get("user", "alice")
    obj = OBJECTS.get(object_id, {})
    if obj.get("owner") != user:
        return jsonify({"blocked": True, "reason": "object owner mismatch"}), 403
    return jsonify(obj)


@app.get("/access/vulnerable")
def access_vulnerable():
    role = request.args.get("role", "user")
    if role == "user":
        return jsonify({"admin": True, "evidence": "HEIMDALL_ACCESS_MARKER admin-fixture"})
    return jsonify({"admin": role == "admin"})


@app.get("/access/safe")
def access_safe():
    role = request.args.get("role", "user")
    if role != "admin":
        return jsonify({"blocked": True, "reason": "role denied"}), 403
    return jsonify({"admin": True})


@app.get("/cmd/vulnerable")
def cmd_vulnerable():
    command = request.args.get("cmd", "")
    allowlisted = {"fake-date", "fake-id", "fake-uptime"}
    if command in allowlisted:
        return jsonify({"output": f"HEIMDALL_CMD_MARKER simulated-command-output {command}"})
    return jsonify({"blocked": True, "reason": "only fake commands are simulated"}), 400


@app.get("/cmd/safe")
def cmd_safe():
    return jsonify({"blocked": True, "safe": True, "reason": "shell input rejected"}), 403


@app.get("/ssrf/vulnerable")
def ssrf_vulnerable():
    url = request.args.get("url", "")
    if url.startswith("http://127.0.0.1:5005/internal/metadata"):
        return jsonify({"evidence": "HEIMDALL_SSRF_MARKER simulated-local-callback"})
    return jsonify({"blocked": True, "no_outbound_request": True}), 400


@app.get("/ssrf/safe")
def ssrf_safe():
    return jsonify({"blocked": True, "safe": True, "reason": "internal URL rejected"}), 403


@app.get("/internal/metadata")
def internal_metadata():
    return jsonify({"marker": "HEIMDALL_INTERNAL_METADATA"})


@app.get("/secret/vulnerable")
def secret_vulnerable():
    return jsonify({"fake_secret": FAKE_SECRET, "evidence": "HEIMDALL_SECRET_MARKER"})


@app.get("/secret/safe")
def secret_safe():
    return jsonify({"source": "environment", "fake_secret": None, "redacted": True})


@app.get("/crypto/vulnerable")
def crypto_vulnerable():
    value = request.args.get("value", "heimdall")
    return jsonify(
        {
            "algorithm": "md5",
            "digest": hashlib.md5(value.encode()).hexdigest(),
            "evidence": "HEIMDALL_CRYPTO_MARKER",
        }
    )


@app.get("/crypto/safe")
def crypto_safe():
    value = request.args.get("value", "heimdall")
    return jsonify({"algorithm": "sha256", "digest": hashlib.sha256(value.encode()).hexdigest()})


@app.post("/deserialize/vulnerable")
def deserialize_vulnerable():
    raw = request.get_data(as_text=True)
    if "heimdall" in raw.lower():
        return jsonify({"evidence": "HEIMDALL_DESERIALIZATION_MARKER safe-simulation"})
    return jsonify({"loaded": False})


@app.post("/deserialize/safe")
def deserialize_safe():
    try:
        loaded = json.loads(request.get_data(as_text=True) or "{}")
    except json.JSONDecodeError:
        return jsonify({"blocked": True, "reason": "JSON parser rejected body"}), 400
    return jsonify({"loaded": loaded, "safe": True})


@app.post("/business/vulnerable")
def business_vulnerable():
    coupon = (request.json or {}).get("coupon", "")
    if coupon in {"DOUBLE_APPLY", "NEGATIVE_TOTAL", "STACK_FREE_SHIP"}:
        return jsonify({"total": 0, "evidence": "HEIMDALL_BIZLOGIC_MARKER deterministic-workflow"})
    return jsonify({"total": 100})


@app.post("/business/safe")
def business_safe():
    coupon = (request.json or {}).get("coupon", "")
    if coupon in COUPONS_USED or coupon in {"DOUBLE_APPLY", "NEGATIVE_TOTAL", "STACK_FREE_SHIP"}:
        return jsonify({"blocked": True, "reason": "coupon workflow rejected"}), 409
    COUPONS_USED.add(coupon)
    return jsonify({"total": 90})


@app.get("/review/auth-required")
def auth_required():
    return jsonify({"needs_review": True, "reason": "authentication context required"}), 401


@app.get("/review/state-required")
def state_required():
    return jsonify({"needs_review": True, "reason": "multi-step workflow state required"}), 409


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5005, debug=False)
