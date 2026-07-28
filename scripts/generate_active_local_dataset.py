from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from pathlib import Path
from typing import Any


SEED = 42
TARGET_BASE_URL = "http://127.0.0.1:5005"
TOTAL_ACTIVE_ALERTS = 180
LEGACY_ACTIVE_ALERTS = 60

CATEGORIES = [
    "SQL Injection",
    "Reflected XSS",
    "Path Traversal",
    "SSRF",
    "Command Injection",
    "IDOR",
    "Broken Access Control",
    "Business Logic",
    "Insecure Deserialization",
    "Open Redirect",
    "Weak Crypto",
    "Hardcoded Secret",
]

RULE_IDS = {
    "SQL Injection": "python.sql-injection.string-built-query",
    "Reflected XSS": "python.flask.security.reflected-xss",
    "Path Traversal": "python.path-traversal.user-controlled-path",
    "SSRF": "python.requests.security.ssrf",
    "Command Injection": "python.command-injection.subprocess-shell",
    "IDOR": "python.access-control.idor",
    "Broken Access Control": "python.access-control.missing-role-check",
    "Business Logic": "python.business-logic.discount-abuse",
    "Insecure Deserialization": "python.deserialization.pickle-loads",
    "Open Redirect": "python.open-redirect.untrusted-next",
    "Weak Crypto": "python.crypto.weak-hash",
    "Hardcoded Secret": "generic.secrets.hardcoded-api-key",
}

COUNTS = {
    "SQL Injection": {"tp": 9, "tn": 4, "review": 2},
    "Reflected XSS": {"tp": 9, "tn": 4, "review": 2},
    "Path Traversal": {"tp": 9, "tn": 4, "review": 2},
    "Open Redirect": {"tp": 9, "tn": 4, "review": 2},
    "Command Injection": {"tp": 9, "tn": 4, "review": 2},
    "Hardcoded Secret": {"tp": 9, "tn": 4, "review": 2},
    "Weak Crypto": {"tp": 9, "tn": 4, "review": 2},
    "SSRF": {"tp": 7, "tn": 4, "review": 4},
    "IDOR": {"tp": 6, "tn": 3, "review": 6},
    "Broken Access Control": {"tp": 6, "tn": 3, "review": 6},
    "Business Logic": {"tp": 5, "tn": 3, "review": 7},
    "Insecure Deserialization": {"tp": 5, "tn": 3, "review": 7},
}
LEGACY_COUNTS = {category: {"tp": 3, "tn": 1, "review": 1} for category in CATEGORIES}

FIXTURES: dict[str, dict[str, Any]] = {
    "SQL Injection": {
        "true_endpoint": "/sql/vulnerable",
        "false_endpoint": "/sql/safe",
        "method": "GET",
        "parameters": {"username": "alice' OR '1'='1"},
        "expected_evidence_marker": "HEIMDALL_SQLI_MARKER",
        "expected_negative_evidence_marker": "parameterized query rejected",
        "expected_status_code": 200,
        "payload_hint": "controlled SQLi behavior marker",
        "snippet_true": "sql = \"SELECT * FROM users WHERE name='\" + username + \"'\"",
        "snippet_false": "cursor.execute('SELECT * FROM users WHERE name=?', (username,))",
    },
    "Reflected XSS": {
        "true_endpoint": "/xss/vulnerable",
        "false_endpoint": "/xss/safe",
        "method": "GET",
        "parameters": {"marker": "<script>HEIMDALL_XSS_MARKER</script>"},
        "expected_evidence_marker": "<script>HEIMDALL_XSS_MARKER</script>",
        "expected_negative_evidence_marker": "&lt;script&gt;HEIMDALL_XSS_MARKER&lt;/script&gt;",
        "expected_status_code": 200,
        "payload_hint": "controlled marker reflection only",
        "snippet_true": "return f\"<div>{request.args['marker']}</div>\"",
        "snippet_false": "return html.escape(request.args.get('marker', ''))",
    },
    "Path Traversal": {
        "true_endpoint": "/path/vulnerable",
        "false_endpoint": "/path/safe",
        "method": "GET",
        "parameters": {"file": "../controlled_secret.txt"},
        "expected_evidence_marker": "HEIMDALL_PATH_MARKER",
        "expected_negative_evidence_marker": "traversal blocked",
        "expected_status_code": 200,
        "payload_hint": "controlled fixture traversal marker",
        "snippet_true": "return open(base_dir + '/' + request.args['file']).read()",
        "snippet_false": "if '..' in filename: abort(403)",
    },
    "SSRF": {
        "true_endpoint": "/ssrf/vulnerable",
        "false_endpoint": "/ssrf/safe",
        "method": "GET",
        "parameters": {"url": "http://127.0.0.1:5005/internal/metadata"},
        "expected_evidence_marker": "HEIMDALL_SSRF_MARKER",
        "expected_negative_evidence_marker": "internal URL rejected",
        "expected_status_code": 200,
        "payload_hint": "simulated localhost metadata marker",
        "snippet_true": "return simulate_local_metadata_fetch(request.args['url'])",
        "snippet_false": "if parsed.hostname in INTERNAL_HOSTS: abort(403)",
    },
    "Command Injection": {
        "true_endpoint": "/cmd/vulnerable",
        "false_endpoint": "/cmd/safe",
        "method": "GET",
        "parameters": {"cmd": "fake-date"},
        "expected_evidence_marker": "HEIMDALL_CMD_MARKER",
        "expected_negative_evidence_marker": "shell input rejected",
        "expected_status_code": 200,
        "payload_hint": "allowlisted fake command marker",
        "snippet_true": "return simulate_command(request.args['cmd'])",
        "snippet_false": "abort(403)",
    },
    "IDOR": {
        "true_endpoint": "/idor/vulnerable",
        "false_endpoint": "/idor/safe",
        "method": "GET",
        "parameters": {"object_id": "2002", "user": "alice"},
        "expected_evidence_marker": "HEIMDALL_IDOR_MARKER",
        "expected_negative_evidence_marker": "object owner mismatch",
        "expected_status_code": 200,
        "payload_hint": "fake user requests another fake user's object",
        "snippet_true": "return jsonify(objects[request.args['object_id']])",
        "snippet_false": "if obj.owner != current_user.id: abort(403)",
    },
    "Broken Access Control": {
        "true_endpoint": "/access/vulnerable",
        "false_endpoint": "/access/safe",
        "method": "GET",
        "parameters": {"role": "user"},
        "expected_evidence_marker": "HEIMDALL_ACCESS_MARKER",
        "expected_negative_evidence_marker": "role denied",
        "expected_status_code": 200,
        "payload_hint": "fake low-privilege role reaches fake admin fixture",
        "snippet_true": "return jsonify(admin_panel_data)",
        "snippet_false": "if current_user.role != 'admin': abort(403)",
    },
    "Business Logic": {
        "true_endpoint": "/business/vulnerable",
        "false_endpoint": "/business/safe",
        "method": "POST",
        "parameters": {"json": {"coupon": "DOUBLE_APPLY"}},
        "expected_evidence_marker": "HEIMDALL_BIZLOGIC_MARKER",
        "expected_negative_evidence_marker": "coupon workflow rejected",
        "expected_status_code": 200,
        "payload_hint": "deterministic coupon workflow marker",
        "snippet_true": "if coupon: total = total - discount - discount",
        "snippet_false": "if coupon in used_coupons: abort(409)",
    },
    "Insecure Deserialization": {
        "true_endpoint": "/deserialize/vulnerable",
        "false_endpoint": "/deserialize/safe",
        "method": "POST",
        "parameters": {"body": "heimdall serialized payload fixture"},
        "expected_evidence_marker": "HEIMDALL_DESERIALIZATION_MARKER",
        "expected_negative_evidence_marker": "JSON parser rejected body",
        "expected_status_code": 200,
        "payload_hint": "safe deserialization simulation marker",
        "snippet_true": "obj = simulated_pickle_loader(request.data)",
        "snippet_false": "obj = json.loads(request.data)",
    },
    "Open Redirect": {
        "true_endpoint": "/redirect/vulnerable",
        "false_endpoint": "/redirect/safe",
        "method": "GET",
        "parameters": {"next": "http://example.invalid/HEIMDALL_REDIRECT_MARKER"},
        "expected_evidence_marker": "http://example.invalid/HEIMDALL_REDIRECT_MARKER",
        "expected_negative_evidence_marker": "redirect normalized",
        "expected_status_code": 302,
        "payload_hint": "do not follow redirect; inspect Location header only",
        "snippet_true": "return redirect(request.args['next'])",
        "snippet_false": "return redirect(validate_relative_url(request.args.get('next', '/')))",
    },
    "Weak Crypto": {
        "true_endpoint": "/crypto/vulnerable",
        "false_endpoint": "/crypto/safe",
        "method": "GET",
        "parameters": {"value": "heimdall"},
        "expected_evidence_marker": "HEIMDALL_CRYPTO_MARKER",
        "expected_negative_evidence_marker": '"algorithm":"sha256"',
        "expected_status_code": 200,
        "payload_hint": "controlled weak algorithm marker",
        "snippet_true": "hashlib.md5(value.encode()).hexdigest()",
        "snippet_false": "hashlib.sha256(value.encode()).hexdigest()",
    },
    "Hardcoded Secret": {
        "true_endpoint": "/secret/vulnerable",
        "false_endpoint": "/secret/safe",
        "method": "GET",
        "parameters": {},
        "expected_evidence_marker": "HEIMDALL_SECRET_MARKER",
        "expected_negative_evidence_marker": '"redacted":true',
        "expected_status_code": 200,
        "payload_hint": "fake hardcoded secret marker only",
        "snippet_true": "API_KEY = 'HEIMDALL_FAKE_SECRET_12345'",
        "snippet_false": "API_KEY = os.environ['PAYMENTS_API_KEY']",
    },
}


def generate_dataset(seed: int = SEED, profile: str = "final") -> list[dict[str, Any]]:
    rng = random.Random(seed)
    alerts: list[dict[str, Any]] = []
    selected_counts = LEGACY_COUNTS if profile == "legacy60" else COUNTS
    for category in CATEGORIES:
        counts = selected_counts[category]
        for status in ("tp", "tn", "review"):
            for local_index in range(counts[status]):
                alerts.append(_build_alert(category, status, local_index, rng))
    expected_total = LEGACY_ACTIVE_ALERTS if profile == "legacy60" else TOTAL_ACTIVE_ALERTS
    if len(alerts) != expected_total:
        raise RuntimeError(f"Expected {expected_total} active-local alerts, generated {len(alerts)}")
    rng.shuffle(alerts)
    return alerts


def _build_alert(category: str, status: str, index: int, rng: random.Random) -> dict[str, Any]:
    fixture = FIXTURES[category]
    slug = category.lower().replace(" ", "_").replace("/", "_")
    marker = fixture["expected_evidence_marker"]
    if status == "review":
        endpoint = "/review/auth-required" if category in {"IDOR", "Broken Access Control"} else "/review/state-required"
        label = "true_positive"
        behavior = "needs_review"
        snippet = fixture["snippet_true"]
        message_suffix = "requires authentication, role, object ownership, or workflow state."
        requires_auth = category in {"IDOR", "Broken Access Control"} or index % 2 == 0
        requires_state = category in {"Business Logic", "Insecure Deserialization"} or index % 2 == 1
    elif status == "tp":
        endpoint = fixture["true_endpoint"]
        label = "true_positive"
        behavior = "confirmable_active_local"
        snippet = fixture["snippet_true"]
        message_suffix = "has deterministic localhost evidence."
        requires_auth = False
        requires_state = False
    else:
        endpoint = fixture["false_endpoint"]
        label = "false_positive"
        behavior = "dismissible_false_positive"
        snippet = fixture["snippet_false"]
        message_suffix = "has a defensive control in the safe endpoint."
        requires_auth = False
        requires_state = False

    alert_id = f"ACTIVE-{slug.upper()}-{status.upper()}-{index + 1:02d}"
    message = f"{RULE_IDS[category]} reported possible {category}; {message_suffix}"
    parameters = _variant_parameters(category, fixture["parameters"], index, status)
    return {
        "alert_id": alert_id,
        "rule_id": RULE_IDS[category],
        "vulnerability_type": category,
        "severity": rng.choice(["critical", "high", "medium", "low"]),
        "file_path": "local_lab/vulnerable_app/app.py",
        "line_number": rng.randint(20, 240),
        "code_snippet": snippet,
        "endpoint": endpoint,
        "endpoint_hint": endpoint,
        "method": fixture["method"],
        "parameters": parameters,
        "payload_hint": fixture["payload_hint"],
        "sast_message": message,
        "message": message,
        "ground_truth_label": label,
        "notes": (
            "Controlled active-local fixture; validates only deterministic localhost evidence markers."
            if status != "review"
            else "Expected Needs Review; controlled local endpoint intentionally lacks full auth/workflow context."
        ),
        "target_base_url": TARGET_BASE_URL,
        "expected_evidence": marker,
        "expected_evidence_marker": marker,
        "expected_negative_evidence_marker": (
            fixture["expected_negative_evidence_marker"] if status == "tn" else ""
        ),
        "expected_status_code": fixture["expected_status_code"] if status == "tp" else None,
        "expected_validation_behavior": behavior,
        "active_local_fixture": True,
        "requires_authentication": requires_auth,
        "requires_multistep_workflow": requires_state,
        "requires_multi_step_state": requires_state,
        "source": "active_local_fixture",
        "safety_scope": "localhost-only",
    }


def _variant_parameters(category: str, parameters: dict[str, Any], index: int, status: str) -> dict[str, Any]:
    copied = json.loads(json.dumps(parameters))
    if status != "tp":
        return copied
    if category == "Command Injection":
        copied["cmd"] = ["fake-date", "fake-id", "fake-uptime"][index % 3]
    if category == "Business Logic":
        copied["json"]["coupon"] = ["DOUBLE_APPLY", "NEGATIVE_TOTAL", "STACK_FREE_SHIP"][index % 3]
    if category == "IDOR":
        copied["object_id"] = ["2002", "3003"][index % 2]
    if category == "SQL Injection" and index % 2:
        copied["username"] = "heimdall_sqli_probe"
    return copied


def write_distribution(path: Path, alerts: list[dict[str, Any]], seed: int) -> None:
    summary = {
        "seed": seed,
        "total_alerts": len(alerts),
        "categories": dict(sorted(Counter(row["vulnerability_type"] for row in alerts).items())),
        "ground_truth_labels": dict(sorted(Counter(row["ground_truth_label"] for row in alerts).items())),
        "severity": dict(sorted(Counter(row["severity"] for row in alerts).items())),
        "expected_validation_behavior": dict(
            sorted(Counter(row["expected_validation_behavior"] for row in alerts).items())
        ),
        "source": dict(sorted(Counter(row["source"] for row in alerts).items())),
        "safety_scope": "All active validation targets are localhost / 127.0.0.1 lab fixtures.",
    }
    path.write_text(json.dumps(summary, indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the expanded localhost active-validation dataset.")
    parser.add_argument("--output", default="test_data/heimdall_active_local_alerts.jsonl")
    parser.add_argument("--distribution", default="test_data/heimdall_active_local_alerts_distribution.json")
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--profile", choices=["final", "legacy60"], default="final")
    args = parser.parse_args()
    alerts = generate_dataset(args.seed, args.profile)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        for alert in alerts:
            handle.write(json.dumps(alert, ensure_ascii=False, sort_keys=True) + "\n")
    write_distribution(Path(args.distribution), alerts, args.seed)
    print(f"Wrote {len(alerts)} active-local alerts to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
