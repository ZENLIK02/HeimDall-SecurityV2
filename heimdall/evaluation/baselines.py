from __future__ import annotations

from .metrics import classify
from .models import Alert, EvaluationResult
from heimdall.pipeline.runner import run_validation_pipeline


SUPPORTED_MODES = (
    "sast_only",
    "rule_based_filtering",
    "llm_only_stub",
    "heimdall_full_pipeline_stub",
)

ERROR_CATEGORIES = {
    "business_logic": "business logic requires multi-step state",
    "auth": "missing authentication context",
    "payload": "insufficient payload",
    "ambiguous": "ambiguous response",
    "prompt_injection": "prompt injection risk",
    "unsupported": "unsupported vulnerability type",
    "safety": "DAST blocked by safety policy",
}


def _result(alert: Alert, mode: str, prediction: str, confidence: float, rationale: str, error_category: str = "") -> EvaluationResult:
    final_decision = {
        "confirmed": "True Positive",
        "dismissed": "False Positive",
        "needs_review": "Needs Review",
    }.get(prediction, "Needs Review")
    return EvaluationResult(
        alert_id=alert.alert_id,
        mode=mode,
        vulnerability_type=alert.vulnerability_type,
        severity=alert.severity,
        ground_truth_label=alert.ground_truth_label,
        prediction=prediction,
        classification=classify(alert.is_real_vulnerability, prediction),
        confidence=confidence,
        error_category=error_category,
        rationale=rationale,
        final_decision=final_decision,
        evidence=rationale,
        explanation=rationale,
        safety_notes=["Baseline mode does not execute DAST payloads."],
        recommended_action="Review baseline output against Heimdall full pipeline.",
    )


def _looks_sanitized(alert: Alert) -> bool:
    text = f"{alert.code_snippet}\n{alert.notes}\n{alert.sast_message}".lower()
    safe_markers = (
        "parameterized",
        "allowlist",
        "allow-list",
        "safe_load",
        "escape",
        "sanitize",
        "permission check",
        "authorization check",
        "localhost only",
        "stubbed",
    )
    return any(marker in text for marker in safe_markers)


def _requires_review(alert: Alert) -> str:
    text = f"{alert.vulnerability_type} {alert.notes} {alert.sast_message}".lower()
    if "business logic" in text or "workflow" in text or "multi-step" in text:
        return ERROR_CATEGORIES["business_logic"]
    if "auth" in text or "idor" in text or "access control" in text:
        return ERROR_CATEGORIES["auth"]
    if "prompt injection" in text:
        return ERROR_CATEGORIES["prompt_injection"]
    if alert.vulnerability_type.lower() not in {
        "xss",
        "sql injection",
        "command injection",
        "path traversal",
        "ssrf",
        "broken access control / idor",
        "business logic flaw",
    }:
        return ERROR_CATEGORIES["unsupported"]
    return ""


def run_sast_only(alerts: list[Alert]) -> list[EvaluationResult]:
    return [
        _result(alert, "sast_only", "confirmed", 0.50, "SAST-only baseline treats every alert as real.")
        for alert in alerts
    ]


def run_rule_based_filtering(alerts: list[Alert]) -> list[EvaluationResult]:
    results: list[EvaluationResult] = []
    for alert in alerts:
        review_reason = _requires_review(alert)
        if review_reason:
            results.append(_result(alert, "rule_based_filtering", "needs_review", 0.45, review_reason, review_reason))
        elif _looks_sanitized(alert):
            results.append(_result(alert, "rule_based_filtering", "dismissed", 0.72, "Safety marker suggests SAST false positive."))
        else:
            results.append(_result(alert, "rule_based_filtering", "confirmed", 0.62, "No obvious sanitization marker found."))
    return results


def run_llm_only_stub(alerts: list[Alert]) -> list[EvaluationResult]:
    results: list[EvaluationResult] = []
    for alert in alerts:
        review_reason = _requires_review(alert)
        if review_reason in {ERROR_CATEGORIES["business_logic"], ERROR_CATEGORIES["auth"]}:
            results.append(_result(alert, "llm_only_stub", "needs_review", 0.58, review_reason, review_reason))
        elif _looks_sanitized(alert):
            results.append(_result(alert, "llm_only_stub", "dismissed", 0.78, "LLM stub recognizes defensive context."))
        else:
            results.append(_result(alert, "llm_only_stub", "confirmed", 0.76, "LLM stub sees exploitable data flow pattern."))
    return results


def run_heimdall_full_pipeline_stub(alerts: list[Alert]) -> list[EvaluationResult]:
    return [run_validation_pipeline(alert) for alert in alerts]


def run_mode(alerts: list[Alert], mode: str) -> list[EvaluationResult]:
    if mode == "sast_only":
        return run_sast_only(alerts)
    if mode == "rule_based_filtering":
        return run_rule_based_filtering(alerts)
    if mode == "llm_only_stub":
        return run_llm_only_stub(alerts)
    if mode == "heimdall_full_pipeline_stub":
        return run_heimdall_full_pipeline_stub(alerts)
    raise ValueError(f"Unsupported evaluation mode: {mode}")
