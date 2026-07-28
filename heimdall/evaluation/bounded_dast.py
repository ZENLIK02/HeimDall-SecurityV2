from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
from typing import Any
from urllib import error, parse, request

from heimdall.config import HeimdallConfig, load_config

from .metrics import classify
from .models import Alert, EvaluationResult


PROTOCOL_VERSION = "heimdall-bounded-dast/1.0"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
REDIRECT_CODES = {301, 302, 303, 307, 308}
SUPPORTED_METHODS = {"GET", "POST"}
MAX_PAYLOAD_BYTES = 8192
MAX_EVIDENCE_MARKER_LENGTH = 1024
UNSAFE_PAYLOAD_FRAGMENTS = (
    "rm -rf",
    "del /",
    "format ",
    "shutdown",
    "reboot",
    "curl http",
    "wget http",
    "/etc/passwd",
    "169.254.169.254",
    "powershell",
    "cmd.exe",
    "drop table",
    "delete from",
    "truncate table",
    "reverse shell",
)
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


class NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def is_local_url_allowed(url: str, allowed_targets: tuple[str, ...] | list[str]) -> bool:
    try:
        parsed = parse.urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        if parsed.username or parsed.password or parsed.fragment:
            return False
        host = (parsed.hostname or "").lower()
        if host not in LOCAL_HOSTS or parsed.port is None:
            return False
        if not _host_resolves_only_to_loopback(host, parsed.port):
            return False
        normalized = _origin(url)
        return any(normalized == _origin(target) for target in allowed_targets)
    except (OSError, ValueError):
        return False


def run_bounded_dast_validation(
    alerts: list[Alert],
    config_path: str = "heimdall.yml",
) -> list[EvaluationResult]:
    config = load_config(config_path)
    return [validate_alert(alert, config) for alert in alerts]


def validate_alert(alert: Alert, config: HeimdallConfig) -> EvaluationResult:
    mode = "heimdall_active_local_validation"
    behavior = str(alert.metadata.get("expected_validation_behavior", "")).lower()

    if config.security.kill_switch:
        return _review_result(
            alert,
            mode,
            "Active validation blocked because the safety kill switch is enabled.",
            "safety_policy_abstention",
            "blocked",
            "kill_switch",
        )
    if not config.active_validation.enabled:
        return _review_result(
            alert,
            mode,
            "Bounded DAST is disabled in the active-validation configuration.",
            "validation_disabled",
            "abstained",
            "active_validation_disabled",
        )
    if not _is_explicitly_authorized(alert):
        return _review_result(
            alert,
            mode,
            "Bounded DAST abstained because the alert has no explicitly authorized runtime mapping.",
            "missing_runtime_mapping",
            "abstained",
            "runtime_mapping_not_authorized",
        )
    if behavior == "needs_review" or alert.metadata.get("requires_authentication") is True:
        category = (
            "missing_authentication_context"
            if alert.metadata.get("requires_authentication")
            else "multi_step_workflow_required"
        )
        return _review_result(
            alert,
            mode,
            "Bounded DAST abstained because authentication, role state, object ownership, or workflow context is required.",
            category,
            "abstained",
            category,
        )
    if (
        alert.metadata.get("requires_multi_step_state") is True
        or alert.metadata.get("requires_multistep_workflow") is True
    ):
        return _review_result(
            alert,
            mode,
            "Bounded DAST abstained because a multi-step workflow fixture is required.",
            "multi_step_workflow_required",
            "abstained",
            "multi_step_workflow_required",
        )

    marker = _expected_marker(alert)
    if not marker or len(marker) > MAX_EVIDENCE_MARKER_LENGTH:
        return _review_result(
            alert,
            mode,
            "Bounded DAST did not execute because no bounded positive evidence predicate was available.",
            "missing_evidence_predicate",
            "abstained",
            "missing_or_oversized_positive_marker",
        )

    method = alert.method.upper()
    if method not in SUPPORTED_METHODS:
        return _review_result(
            alert,
            mode,
            f"HTTP method {method or '<empty>'} is outside the bounded DAST protocol.",
            "safety_policy_abstention",
            "blocked",
            "unsupported_http_method",
        )
    endpoint_ok, endpoint_reason = _endpoint_is_safe(alert.endpoint)
    if not endpoint_ok:
        return _review_result(
            alert,
            mode,
            f"Bounded DAST blocked the endpoint before sending a request: {endpoint_reason}",
            "safety_policy_abstention",
            "blocked",
            endpoint_reason,
        )
    payload_ok, payload_reason = _payload_is_safe(alert)
    if not payload_ok:
        return _review_result(
            alert,
            mode,
            f"Bounded DAST blocked the payload before sending a request: {payload_reason}",
            "safety_policy_abstention",
            "blocked",
            payload_reason,
        )

    target_base = _target_for_alert(config, alert)
    url = _build_url(target_base, alert.endpoint, alert.parameters)
    allowed_targets = tuple(config.active_validation.allowed_targets)
    if not is_local_url_allowed(url, allowed_targets):
        return _review_result(
            alert,
            mode,
            f"Bounded DAST blocked a non-loopback or non-allowlisted target: {_redacted_url(url)}",
            "safety_policy_abstention",
            "blocked",
            "target_not_in_loopback_allowlist",
            {"url": _redacted_url(url)},
        )

    response = _send_request(
        url=url,
        method=method,
        parameters=alert.parameters,
        timeout=float(config.active_validation.request_timeout_seconds),
        body_limit=int(config.active_validation.response_body_limit_bytes),
    )
    prediction, confidence, reason, error_category = analyze_bounded_response(alert, response)
    positive_found = _positive_marker_observed(alert, response, marker)
    negative_marker = _negative_marker(alert)
    negative_found = _negative_marker_observed(response, negative_marker)
    response_body = str(response.get("body", ""))
    validation_metadata = {
        "status": "completed",
        "protocol_version": PROTOCOL_VERSION,
        "url": _redacted_url(url),
        "method": method,
        "request_count": 1,
        "max_requests_per_alert": 1,
        "status_code": response["status_code"],
        "expected_status_code": alert.metadata.get("expected_status_code"),
        "expected_evidence": marker,
        "positive_evidence_found": positive_found,
        "negative_evidence": negative_marker,
        "negative_evidence_found": negative_found,
        "redirect_location": response.get("location", ""),
        "redirect_followed": False,
        "response_bytes_captured": len(response_body.encode("utf-8")),
        "response_truncated": bool(response.get("truncated", False)),
        "response_sha256": hashlib.sha256(response_body.encode("utf-8")).hexdigest(),
        "request_log": [
            {
                "method": method,
                "url": _redacted_url(url),
                "status_code": response["status_code"],
                "local_only": True,
                "redirect_followed": False,
                "non_destructive": True,
            }
        ],
    }
    metadata = {
        "active_validation": validation_metadata,
        "bounded_dast": validation_metadata,
        "dry_run": False,
    }
    return _result(alert, mode, prediction, confidence, reason, error_category, metadata)


def analyze_bounded_response(
    alert: Alert,
    response: dict[str, Any],
) -> tuple[str, float, str, str]:
    marker = _expected_marker(alert)
    status_code = int(response.get("status_code") or 0)
    evidence_found = _positive_marker_observed(alert, response, marker)
    expected_status = _optional_int(alert.metadata.get("expected_status_code"))

    if evidence_found and (expected_status is None or status_code == expected_status):
        return (
            "confirmed",
            0.94,
            f"Bounded DAST observed the declared runtime evidence for {alert.vulnerability_type}.",
            "bounded_dast_confirmed",
        )
    if evidence_found:
        return (
            "needs_review",
            0.45,
            "The evidence marker was present, but the response status did not match the declared predicate.",
            "evidence_status_mismatch",
        )

    negative_marker = _negative_marker(alert)
    if _negative_marker_observed(response, negative_marker):
        return (
            "dismissed",
            0.88,
            f"Bounded DAST observed the declared negative evidence for {alert.vulnerability_type}; the alert was not reproduced under this test.",
            "bounded_dast_not_reproduced",
        )

    negative_statuses = _expected_negative_status_codes(alert)
    if status_code in negative_statuses:
        return (
            "dismissed",
            0.82,
            f"Bounded DAST observed a declared negative status ({status_code}); the alert was not reproduced under this test.",
            "bounded_dast_not_reproduced",
        )
    if status_code == 0:
        return (
            "needs_review",
            0.30,
            "Bounded DAST could not reach the allowlisted runtime target.",
            "missing_runtime_fixture",
        )
    return (
        "needs_review",
        0.40,
        "The response did not satisfy either the positive or negative evidence predicate.",
        "insufficient_runtime_evidence",
    )


# Backward-compatible name used by the existing research harness.
analyze_active_response = analyze_bounded_response


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
        "dismissed": "Not Reproduced Under Test",
        "needs_review": "Needs Review",
    }[prediction]
    if prediction == "confirmed":
        recommended = "Prioritize remediation and rerun the same bounded probe after the fix."
    elif prediction == "dismissed":
        recommended = (
            "Retain the SAST alert as not reproduced under this test; suppress or close it only after independent review."
        )
    else:
        recommended = "Route to manual review or collect a stronger authorized runtime evidence predicate."
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
            "Exactly one GET or POST request is permitted for each executable alert.",
            "The request origin must match an allowlisted loopback target.",
            "Payloads are bounded and screened for destructive or external-network content.",
            "Redirect responses are inspected but never followed.",
            "A response without a satisfied evidence predicate is routed to Needs Review.",
        ],
        recommended_action=recommended,
        metadata=metadata,
    )


def _review_result(
    alert: Alert,
    mode: str,
    rationale: str,
    error_category: str,
    status: str,
    reason: str,
    extra: dict[str, Any] | None = None,
) -> EvaluationResult:
    validation_metadata = {
        "status": status,
        "protocol_version": PROTOCOL_VERSION,
        "reason": reason,
        "request_count": 0,
        "max_requests_per_alert": 1,
        "request_log": [],
    }
    if extra:
        validation_metadata.update(extra)
    return _result(
        alert,
        mode,
        "needs_review",
        0.25,
        rationale,
        error_category,
        {
            "active_validation": validation_metadata,
            "bounded_dast": validation_metadata,
            "dry_run": False,
        },
    )


def _is_explicitly_authorized(alert: Alert) -> bool:
    return (
        alert.metadata.get("active_local_fixture") is True
        or alert.metadata.get("dast_authorized") is True
    )


def _target_for_alert(config: HeimdallConfig, alert: Alert) -> str:
    preferred = str(alert.metadata.get("target_base_url", "")).strip()
    if preferred:
        return preferred.rstrip("/")
    return str(config.active_validation.allowed_targets[0]).rstrip("/")


def _endpoint_is_safe(endpoint: str) -> tuple[bool, str]:
    if not endpoint or len(endpoint) > 2048:
        return False, "invalid_endpoint_length"
    if "\\" in endpoint or any(ord(character) < 32 for character in endpoint):
        return False, "invalid_endpoint_characters"
    parsed = parse.urlsplit(endpoint)
    if parsed.scheme or parsed.netloc:
        return False, "absolute_endpoint_not_allowed"
    if parsed.fragment:
        return False, "endpoint_fragment_not_allowed"
    path = parsed.path or "/"
    if any(segment == ".." for segment in path.split("/")):
        return False, "endpoint_path_traversal_not_allowed"
    return True, ""


def _build_url(base: str, endpoint: str, parameters: dict[str, Any]) -> str:
    parsed_endpoint = parse.urlsplit(endpoint)
    path = parsed_endpoint.path or "/"
    base_url = f"{base.rstrip('/')}/{path.lstrip('/')}"
    query_items = parse.parse_qsl(parsed_endpoint.query, keep_blank_values=True)
    query_items.extend(_query_pairs(parameters))
    query = parse.urlencode(query_items, doseq=True)
    return f"{base_url}{'?' + query if query else ''}"


def _query_pairs(parameters: dict[str, Any]) -> list[tuple[str, Any]]:
    if "query" in parameters and isinstance(parameters["query"], dict):
        return list(parameters["query"].items())
    if "json" in parameters or "body" in parameters:
        return []
    return list(parameters.items())


def _send_request(
    url: str,
    method: str,
    parameters: dict[str, Any],
    timeout: float,
    body_limit: int,
) -> dict[str, Any]:
    headers = {
        "User-Agent": f"Heimdall-Bounded-DAST/{PROTOCOL_VERSION.rsplit('/', 1)[-1]}",
        "Accept": "text/plain, application/json, text/html",
        "Connection": "close",
    }
    data = None
    if method == "POST":
        body = parameters.get("json", parameters.get("body", parameters))
        if isinstance(body, (dict, list)):
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        else:
            data = str(body).encode("utf-8")
            headers["Content-Type"] = "text/plain; charset=utf-8"

    opener = request.build_opener(NoRedirectHandler)
    req = request.Request(url, data=data, method=method, headers=headers)
    try:
        with opener.open(req, timeout=timeout) as response:
            body, truncated = _bounded_read(response, body_limit)
            return {
                "status_code": int(response.status),
                "body": body,
                "location": response.headers.get("Location", ""),
                "truncated": truncated,
            }
    except error.HTTPError as exc:
        body, truncated = _bounded_read(exc, body_limit)
        return {
            "status_code": int(exc.code),
            "body": body,
            "location": exc.headers.get("Location", ""),
            "truncated": truncated,
        }
    except OSError as exc:
        return {
            "status_code": 0,
            "body": str(exc)[:body_limit],
            "location": "",
            "truncated": False,
        }


def _bounded_read(response: Any, body_limit: int) -> tuple[str, bool]:
    raw = response.read(body_limit + 1)
    truncated = len(raw) > body_limit
    return raw[:body_limit].decode("utf-8", errors="replace"), truncated


def _expected_marker(alert: Alert) -> str:
    return (
        str(alert.metadata.get("expected_evidence_marker", "") or "")
        or str(alert.metadata.get("expected_evidence", "") or "")
        or _default_marker(alert.vulnerability_type)
    )


def _negative_marker(alert: Alert) -> str:
    return str(
        alert.metadata.get("expected_negative_evidence_marker", "")
        or alert.metadata.get("negative_evidence_marker", "")
        or ""
    )


def _positive_marker_observed(alert: Alert, response: dict[str, Any], marker: str) -> bool:
    if not marker:
        return False
    category = alert.vulnerability_type.lower()
    if "open redirect" in category:
        return (
            int(response.get("status_code") or 0) in REDIRECT_CODES
            and marker in str(response.get("location", ""))
        )
    return marker in str(response.get("body", ""))


def _negative_marker_observed(response: dict[str, Any], marker: str) -> bool:
    if not marker:
        return False
    return marker in str(response.get("body", "")) or marker in str(response.get("location", ""))


def _expected_negative_status_codes(alert: Alert) -> set[int]:
    raw = alert.metadata.get("expected_negative_status_codes", ())
    if not isinstance(raw, (list, tuple, set)):
        return set()
    output: set[int] = set()
    for value in raw:
        converted = _optional_int(value)
        if converted is not None:
            output.add(converted)
    return output


def _payload_is_safe(alert: Alert) -> tuple[bool, str]:
    try:
        serialized = json.dumps(alert.parameters, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        return False, "payload_not_json_serializable"
    if len(serialized.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        return False, "payload_too_large"
    lowered = serialized.lower()
    for fragment in UNSAFE_PAYLOAD_FRAGMENTS:
        if fragment in lowered:
            return False, f"unsafe_payload_fragment:{fragment}"
    for candidate in URL_PATTERN.findall(serialized):
        candidate = candidate.rstrip(".,;:)]}")
        if not _embedded_url_is_safe(candidate, alert.vulnerability_type):
            return False, "external_url_in_payload"
    return True, ""


def _embedded_url_is_safe(url: str, vulnerability_type: str) -> bool:
    try:
        parsed = parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        if host in LOCAL_HOSTS:
            return _host_resolves_only_to_loopback(host, parsed.port or 80)
        return host.endswith(".invalid") and "open redirect" in vulnerability_type.lower()
    except (OSError, ValueError):
        return False


def _host_resolves_only_to_loopback(host: str, port: int) -> bool:
    if host != "localhost":
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return bool(addresses) and all(
        ipaddress.ip_address(address[4][0].split("%", 1)[0]).is_loopback
        for address in addresses
    )


def _default_marker(vulnerability_type: str) -> str:
    markers = {
        "reflected xss": "HEIMDALL_XSS_MARKER",
        "xss": "HEIMDALL_XSS_MARKER",
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
    normalized = vulnerability_type.lower()
    if normalized in markers:
        return markers[normalized]
    for category, marker in markers.items():
        if category in normalized:
            return marker
    return ""


def _origin(url: str) -> str:
    parsed = parse.urlparse(url)
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _redacted_url(url: str) -> str:
    parsed = parse.urlsplit(url)
    return parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
