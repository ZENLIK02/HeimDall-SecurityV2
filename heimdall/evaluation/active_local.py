from __future__ import annotations

import json
from typing import Any
from urllib import error, parse, request

from heimdall.config import HeimdallConfig, load_config

from .metrics import classify
from .models import Alert, EvaluationResult


LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
REDIRECT_CODES = {301, 302, 303, 307, 308}
BLOCKING_CODES = {400, 401, 403, 404, 409, 422}
UNSAFE_PAYLOAD_FRAGMENTS = (
    "rm -rf",
    "del /",
    "format ",
    "shutdown",
    "curl http",
    "wget http",
    "/etc/passwd",
    "169.254.169.254",
    "powershell",
    "cmd.exe",
)


class NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def is_local_url_allowed(url: str, allowed_targets: tuple[str, ...] | list[str]) -> bool:
    parsed = parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    host = parsed.hostname or ""
    if host not in LOCAL_HOSTS:
        return False
    normalized = f"{parsed.scheme}://{parsed.netloc}"
    return any(normalized == _origin(target) for target in allowed_targets)


def run_active_local_validation(alerts: list[Alert], config_path: str = "heimdall.yml") -> list[EvaluationResult]:
    config = load_config(config_path)
    return [validate_alert(alert, config) for alert in alerts]


def validate_alert(alert: Alert, config: HeimdallConfig) -> EvaluationResult:
    mode = "heimdall_active_local_validation"
    behavior = str(alert.metadata.get("expected_validation_behavior", "")).lower()
    if config.security.kill_switch:
        return _result(
            alert,
            mode,
            "needs_review",
            0.20,
            "Active validation blocked because the safety kill switch is enabled.",
            "safety_policy_abstention",
            {"active_validation": {"status": "blocked", "reason": "kill_switch"}},
        )
    if alert.metadata.get("active_local_fixture") is not True:
        return _result(
            alert,
            mode,
            "needs_review",
            0.40,
            "Active validation abstained because the alert is synthetic-only and has no localhost fixture mapping.",
            "synthetic_only_alert",
            {"active_validation": {"status": "abstained", "behavior": behavior}},
        )
    if behavior == "needs_review" or alert.metadata.get("requires_authentication") is True:
        category = "missing_authentication_context" if alert.metadata.get("requires_authentication") else "multi_step_workflow_required"
        return _result(
            alert,
            mode,
            "needs_review",
            0.54,
            "Active localhost validation abstained because authentication, role state, object ownership, or workflow context is required.",
            category,
            {"active_validation": {"status": "abstained", "behavior": behavior}},
        )
    if alert.metadata.get("requires_multi_step_state") is True or alert.metadata.get("requires_multistep_workflow") is True:
        return _result(
            alert,
            mode,
            "needs_review",
            0.54,
            "Active localhost validation abstained because a multi-step workflow fixture is required.",
            "multi_step_workflow_required",
            {"active_validation": {"status": "abstained", "behavior": behavior}},
        )
    if not _payload_is_safe(alert.parameters):
        return _result(
            alert,
            mode,
            "needs_review",
            0.20,
            "Active validation blocked an unsafe payload fragment before sending any request.",
            "safety_policy_abstention",
            {"active_validation": {"status": "blocked", "reason": "unsafe_payload_fragment"}},
        )

    target_base = _choose_target(config, alert)
    url = _build_url(target_base, alert.endpoint, alert.parameters)
    allowed_targets = tuple(config.active_validation.allowed_targets)
    if not is_local_url_allowed(url, allowed_targets):
        return _result(
            alert,
            mode,
            "needs_review",
            0.25,
            f"Blocked active validation for non-local or non-allowlisted URL: {url}",
            "safety_policy_abstention",
            {"active_validation": {"status": "blocked", "url": url}},
        )

    response = _send_request(
        url=url,
        method=alert.method,
        parameters=alert.parameters,
        timeout=float(config.active_validation.request_timeout_seconds),
    )
    prediction, confidence, reason, error_category = analyze_active_response(alert, response)
    marker = _expected_marker(alert)
    metadata = {
        "active_validation": {
            "status": "completed",
            "url": url,
            "method": alert.method,
            "status_code": response["status_code"],
            "expected_status_code": alert.metadata.get("expected_status_code"),
            "expected_evidence": marker,
            "evidence_found": _marker_observed(alert, response, marker),
            "redirect_location": response.get("location", ""),
            "body_excerpt": response["body"][:300],
            "request_log": [
                {
                    "method": alert.method,
                    "url": url,
                    "status_code": response["status_code"],
                    "local_only": True,
                    "redirect_followed": False,
                }
            ],
        },
        "dry_run": False,
    }
    return _result(alert, mode, prediction, confidence, reason, error_category, metadata)


def analyze_active_response(alert: Alert, response: dict[str, Any]) -> tuple[str, float, str, str]:
    marker = _expected_marker(alert)
    category = alert.vulnerability_type.lower()
    status_code = int(response.get("status_code") or 0)
    evidence_found = _marker_observed(alert, response, marker)
    safe_blocked = status_code in BLOCKING_CODES and not evidence_found

    if evidence_found:
        return (
            "confirmed",
            0.94,
            f"Category-specific analyzer observed controlled evidence for {alert.vulnerability_type}.",
            "active_validation_confirmed",
        )
    if "open redirect" in category and status_code in REDIRECT_CODES:
        return (
            "needs_review",
            0.45,
            "Redirect occurred but did not contain the controlled Location marker.",
            "evidence_marker_absent",
        )
    if safe_blocked:
        return (
            "dismissed",
            0.88,
            f"Safe endpoint blocked or normalized the {alert.vulnerability_type} probe.",
            "active_validation_dismissed",
        )
    if status_code == 0:
        return (
            "needs_review",
            0.30,
            "Local validation could not reach the fixture endpoint.",
            "missing_runtime_fixture",
        )
    if marker:
        return (
            "dismissed",
            0.80,
            "Expected controlled evidence marker was absent from the local response.",
            "evidence_marker_absent",
        )
    return (
        "needs_review",
        0.35,
        "Analyzer could not map the response to a category-specific decision.",
        "analyzer_inconclusive",
    )


def _result(
    alert: Alert,
    mode: str,
    prediction: str,
    confidence: float,
    rationale: str,
    error_category: str,
    metadata: dict[str, Any],
) -> EvaluationResult:
    final_decision = {
        "confirmed": "True Positive",
        "dismissed": "False Positive",
        "needs_review": "Needs Review",
    }[prediction]
    if prediction == "confirmed":
        recommended = "Fix the vulnerable code path and add regression tests for the local validation fixture."
    elif prediction == "dismissed":
        recommended = "Document the defensive control and consider suppressing or tuning the noisy SAST rule."
    else:
        recommended = "Route to manual review with authentication, state, and runtime context."
    return EvaluationResult(
        alert_id=alert.alert_id,
        mode=mode,
        vulnerability_type=alert.vulnerability_type,
        severity=alert.severity,
        ground_truth_label=alert.ground_truth_label,
        prediction=prediction,  # type: ignore[arg-type]
        classification=classify(alert.is_real_vulnerability, prediction),
        confidence=confidence,
        error_category=error_category,
        rationale=rationale,
        final_decision=final_decision,
        evidence=rationale,
        explanation=rationale,
        safety_notes=[
            "Active validation is restricted to localhost / 127.0.0.1 allowlisted targets.",
            "Payloads are deterministic, non-destructive, and fixture-backed.",
            "External redirects are inspected by Location header only and never followed.",
        ],
        recommended_action=recommended,
        metadata=metadata,
    )


def _choose_target(config: HeimdallConfig, alert: Alert) -> str:
    preferred = str(alert.metadata.get("target_base_url", "")).strip()
    allowed_targets = tuple(config.active_validation.allowed_targets)
    if preferred and is_local_url_allowed(preferred, allowed_targets):
        return preferred.rstrip("/")
    return str(allowed_targets[0]).rstrip("/")


def _build_url(base: str, endpoint: str, parameters: dict[str, Any]) -> str:
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        parsed = parse.urlparse(endpoint)
        path = parsed.path or "/"
        base = f"{parsed.scheme}://{parsed.netloc}"
    else:
        path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    query = parse.urlencode(_query_params(parameters), doseq=True)
    return f"{base}{path}{'?' + query if query else ''}"


def _query_params(parameters: dict[str, Any]) -> dict[str, Any]:
    if "query" in parameters and isinstance(parameters["query"], dict):
        return parameters["query"]
    if "json" in parameters or "body" in parameters:
        return {}
    return parameters


def _send_request(url: str, method: str, parameters: dict[str, Any], timeout: float) -> dict[str, Any]:
    headers = {"User-Agent": "Heimdall-Active-Local-Validation/2.0"}
    data = None
    if method.upper() == "POST":
        body = parameters.get("json", parameters.get("body", parameters))
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        else:
            data = str(body).encode("utf-8")
            headers["Content-Type"] = "text/plain"
    opener = request.build_opener(NoRedirectHandler)
    req = request.Request(url, data=data, method=method.upper(), headers=headers)
    try:
        with opener.open(req, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            return {"status_code": int(response.status), "body": body, "location": response.headers.get("Location", "")}
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {"status_code": int(exc.code), "body": body, "location": exc.headers.get("Location", "")}
    except OSError as exc:
        return {"status_code": 0, "body": str(exc), "location": ""}


def _expected_marker(alert: Alert) -> str:
    return (
        str(alert.metadata.get("expected_evidence_marker", "") or "")
        or str(alert.metadata.get("expected_evidence", "") or "")
        or _default_marker(alert.vulnerability_type)
    )


def _marker_observed(alert: Alert, response: dict[str, Any], marker: str) -> bool:
    if not marker:
        return False
    category = alert.vulnerability_type.lower()
    if "open redirect" in category:
        return int(response.get("status_code") or 0) in REDIRECT_CODES and marker in str(response.get("location", ""))
    return marker in str(response.get("body", ""))


def _payload_is_safe(parameters: dict[str, Any]) -> bool:
    text = json.dumps(parameters, sort_keys=True).lower()
    return not any(fragment in text for fragment in UNSAFE_PAYLOAD_FRAGMENTS)


def _default_marker(vulnerability_type: str) -> str:
    markers = {
        "reflected xss": "HEIMDALL_XSS_MARKER",
        "sql injection": "HEIMDALL_SQLI_MARKER",
        "path traversal": "HEIMDALL_PATH_MARKER",
        "ssrf": "HEIMDALL_SSRF_MARKER",
        "command injection": "HEIMDALL_CMD_MARKER",
        "idor": "HEIMDALL_IDOR_MARKER",
        "broken access control": "HEIMDALL_ACCESS_MARKER",
        "business logic": "HEIMDALL_BIZLOGIC_MARKER",
        "insecure deserialization": "HEIMDALL_DESERIALIZATION_MARKER",
        "open redirect": "http://example.invalid/HEIMDALL_REDIRECT_MARKER",
        "weak crypto": "HEIMDALL_CRYPTO_MARKER",
        "hardcoded secret": "HEIMDALL_SECRET_MARKER",
    }
    return markers.get(vulnerability_type.lower(), "")


def _origin(url: str) -> str:
    parsed = parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"
