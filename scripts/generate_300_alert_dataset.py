from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from pathlib import Path


SEED = 42
TOTAL_ALERTS = 300

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

SEVERITIES = ["critical", "high", "medium", "low"]

TRUE_SNIPPETS = {
    "SQL Injection": "query = \"SELECT * FROM users WHERE name = '\" + request.args['name'] + \"'\"",
    "Reflected XSS": "return f\"<h1>{request.args.get('q', '')}</h1>\"",
    "Path Traversal": "return send_file(os.path.join(BASE_DIR, request.args['file']))",
    "SSRF": "response = requests.get(request.json['url'], timeout=3)",
    "Command Injection": "subprocess.run('ping -c 1 ' + request.args['host'], shell=True)",
    "IDOR": "return jsonify(db.get_order(request.args['order_id']))",
    "Broken Access Control": "return jsonify(admin_panel_data)  # missing role check",
    "Business Logic": "if coupon_code: total = total - cart.total * discount",
    "Insecure Deserialization": "profile = pickle.loads(request.get_data())",
    "Open Redirect": "return redirect(request.args.get('next'))",
    "Weak Crypto": "digest = hashlib.md5(password.encode()).hexdigest()",
    "Hardcoded Secret": "API_KEY = 'sk-test-hardcoded-demo-key-1234567890'",
}

FALSE_SNIPPETS = {
    "SQL Injection": "cursor.execute('SELECT * FROM users WHERE name = ?', (request.args['name'],))",
    "Reflected XSS": "return render_template('search.html', q=html.escape(request.args.get('q', '')))",
    "Path Traversal": "safe = Path(BASE_DIR, filename).resolve(); assert safe.is_relative_to(BASE_DIR)",
    "SSRF": "if parsed.hostname not in ALLOWED_HOSTS: abort(400)",
    "Command Injection": "subprocess.run(['ping', '-c', '1', allowlisted_host], check=True)",
    "IDOR": "if order.owner_id != current_user.id: abort(403)",
    "Broken Access Control": "if not current_user.has_role('admin'): abort(403)",
    "Business Logic": "if coupon.used_by_user(current_user.id): abort(409)",
    "Insecure Deserialization": "profile = json.loads(request.get_data())",
    "Open Redirect": "return redirect(validate_relative_url(request.args.get('next', '/')))",
    "Weak Crypto": "digest = hashlib.sha256(password.encode()).hexdigest()",
    "Hardcoded Secret": "API_KEY = os.environ['PAYMENTS_API_KEY']",
}

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

REQUEST_CONTEXT = {
    "SQL Injection": ("/search", "GET", {"name": "alice' OR '1'='1"}),
    "Reflected XSS": ("/search", "GET", {"q": "<img src=x onerror=alert(1)>"}),
    "Path Traversal": ("/download", "GET", {"file": "../README.md"}),
    "SSRF": ("/fetch", "POST", {"url": "http://127.0.0.1:9/metadata"}),
    "Command Injection": ("/diagnostics/ping", "POST", {"host": "127.0.0.1; echo HEIMDALL_CMD_PROBE"}),
    "IDOR": ("/orders", "GET", {"order_id": "1002"}),
    "Broken Access Control": ("/admin", "GET", {}),
    "Business Logic": ("/checkout", "POST", {"coupon": "ONCE_ONLY"}),
    "Insecure Deserialization": ("/profile/import", "POST", {"payload": "pickle-bytes-placeholder"}),
    "Open Redirect": ("/login", "GET", {"next": "https://example.invalid/callback"}),
    "Weak Crypto": ("/register", "POST", {"password": "correct-horse-battery-staple"}),
    "Hardcoded Secret": ("/config", "GET", {}),
}

REVIEW_CATEGORIES = {"IDOR", "Broken Access Control", "Business Logic", "Insecure Deserialization"}


def build_alert(category: str, index: int, rng: random.Random) -> dict:
    per_category_index = index % 25
    is_true_positive = per_category_index < 13
    severity = rng.choice(SEVERITIES)
    endpoint, method, parameters = REQUEST_CONTEXT[category]
    rule_id = RULE_IDS[category]
    category_slug = category.lower().replace(" ", "_").replace("/", "_")
    label = "true_positive" if is_true_positive else "false_positive"
    needs_review = category in REVIEW_CATEGORIES and per_category_index % 3 == 0
    if category in {"Open Redirect", "Weak Crypto", "Hardcoded Secret"} and per_category_index % 5 == 0:
        needs_review = True

    snippet = TRUE_SNIPPETS[category] if is_true_positive else FALSE_SNIPPETS[category]
    defensive_note = "Defensive control present: parameterized, escaped, allowlist, authorization check, or environment-backed secret." if not is_true_positive else ""
    review_note = "Requires authentication context, multi-step workflow, or missing runtime context; expected Needs Review." if needs_review else ""

    message = f"{rule_id}: potential {category} data flow detected."
    return {
        "alert_id": f"H300-{category_slug.upper()}-{per_category_index + 1:03d}",
        "rule_id": rule_id,
        "vulnerability_type": category,
        "severity": severity,
        "file_path": f"synthetic_app/{category_slug}/case_{per_category_index + 1:03d}.py",
        "line_number": rng.randint(12, 240),
        "code_snippet": snippet,
        "endpoint": endpoint,
        "endpoint_hint": endpoint,
        "method": method,
        "parameters": parameters,
        "payload_hint": "synthetic dry-run payload hypothesis only",
        "sast_message": message,
        "message": message,
        "ground_truth_label": label,
        "notes": " ".join(part for part in [defensive_note, review_note, "Synthetic 300-alert evaluation fixture."] if part),
        "expected_evidence_marker": "",
        "expected_status_code": None,
        "expected_validation_behavior": "needs_review" if needs_review else ("confirmable_in_live_local_test" if is_true_positive else "dismissible_false_positive"),
        "requires_authentication": category in {"IDOR", "Broken Access Control"} or needs_review,
        "requires_multistep_workflow": category == "Business Logic" or needs_review,
        "requires_multi_step_state": category == "Business Logic" or needs_review,
        "source": "synthetic_300",
    }


def generate_dataset(seed: int = SEED) -> list[dict]:
    rng = random.Random(seed)
    alerts = []
    for category in CATEGORIES:
        for index in range(25):
            alerts.append(build_alert(category, index, rng))
    rng.shuffle(alerts)
    return alerts


def write_distribution(path: Path, alerts: list[dict], seed: int) -> None:
    by_category = Counter(alert["vulnerability_type"] for alert in alerts)
    by_label = Counter(alert["ground_truth_label"] for alert in alerts)
    by_severity = Counter(alert["severity"] for alert in alerts)
    expected_behavior = Counter(alert["expected_validation_behavior"] for alert in alerts)
    summary = {
        "seed": seed,
        "total_alerts": len(alerts),
        "categories": dict(sorted(by_category.items())),
        "ground_truth_labels": dict(sorted(by_label.items())),
        "severity": dict(sorted(by_severity.items())),
        "expected_validation_behavior": dict(sorted(expected_behavior.items())),
        "notes": "Synthetic local-only dataset. No production targets, real secrets, or destructive payloads are included.",
    }
    path.write_text(json.dumps(summary, indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the Heimdall 300-alert synthetic evaluation dataset.")
    parser.add_argument("--output", default="test_data/heimdall_300_alerts.jsonl")
    parser.add_argument("--distribution", default="test_data/heimdall_300_alerts_distribution.json")
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    alerts = generate_dataset(args.seed)
    if len(alerts) != TOTAL_ALERTS:
        raise RuntimeError(f"Expected {TOTAL_ALERTS} alerts, generated {len(alerts)}")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        for alert in alerts:
            handle.write(json.dumps(alert, ensure_ascii=False, sort_keys=True) + "\n")

    write_distribution(Path(args.distribution), alerts, args.seed)
    print(f"Wrote {len(alerts)} alerts to {output_path}")
    print(f"Wrote distribution summary to {args.distribution}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
