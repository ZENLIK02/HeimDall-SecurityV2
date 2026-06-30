from __future__ import annotations

from heimdall.evaluation.metrics import classify
from heimdall.evaluation.models import Alert, EvaluationResult

from .context_extraction import extract_context
from .dast_executor import SafeDastExecutor
from .decision_engine import decide
from .llm_reasoning import DeterministicMockLLMProvider
from .models import DastConfig
from .prompt_guard import build_guarded_prompt
from .response_analyzer import analyze_response


def run_validation_pipeline(alert: Alert, config: DastConfig | None = None) -> EvaluationResult:
    context = extract_context(alert)
    prompt = build_guarded_prompt(context)
    llm_output = DeterministicMockLLMProvider().analyze(prompt)

    if not llm_output.payloads or llm_output.recommended_action == "needs_review":
        decision_label = "Needs Review"
        confidence = llm_output.confidence
        reason = llm_output.reasoning_summary
        error_category = "prompt injection risk" if prompt.rejected else _review_category(alert)
        evidence = "DAST validation was not executed because the LLM output required manual review."
        safety_notes = list(prompt.safety_notes) + list(llm_output.safety_notes)
        recommended_action = "Manual review before dynamic validation."
        dast_metadata = {"status": "not_executed", "request_log": []}
    else:
        executor = SafeDastExecutor(config or DastConfig())
        dast_result = executor.execute(llm_output.payloads[0])
        analysis = analyze_response(llm_output.payloads[0], dast_result)
        decision = decide(llm_output, dast_result, analysis)
        decision_label = decision.decision
        confidence = decision.confidence
        reason = decision.reason
        error_category = decision.error_category
        evidence = analysis.evidence
        safety_notes = list(prompt.safety_notes) + list(llm_output.safety_notes) + list(llm_output.payloads[0].safety_notes)
        recommended_action = _recommended_action(decision_label)
        dast_metadata = {
            "status": dast_result.status,
            "status_code": dast_result.status_code,
            "blocked_reason": dast_result.blocked_reason,
            "request_log": dast_result.request_log,
        }

    prediction = _decision_to_prediction(decision_label)
    explanation = _build_explanation(decision_label, reason, error_category)
    return EvaluationResult(
        alert_id=alert.alert_id,
        mode="heimdall_full_pipeline_stub",
        vulnerability_type=alert.vulnerability_type,
        severity=alert.severity,
        ground_truth_label=alert.ground_truth_label,
        prediction=prediction,
        classification=classify(alert.is_real_vulnerability, prediction),
        confidence=confidence,
        error_category=error_category,
        rationale=reason,
        final_decision=decision_label,
        evidence=evidence,
        explanation=explanation,
        safety_notes=safety_notes,
        recommended_action=recommended_action,
        metadata={
            "decision": decision_label,
            "dry_run": True,
            "llm_recommended_action": llm_output.recommended_action,
            "validation_strategy": llm_output.validation_strategy,
            "dast": dast_metadata,
        },
    )


def _decision_to_prediction(decision: str) -> str:
    if decision == "True Positive":
        return "confirmed"
    if decision == "False Positive":
        return "dismissed"
    return "needs_review"


def _review_category(alert: Alert) -> str:
    text = f"{alert.vulnerability_type} {alert.notes}".lower()
    if "business logic" in text or "multi-step" in text:
        return "business logic requires multi-step state"
    if "idor" in text or "access control" in text or "auth" in text:
        return "missing authentication context"
    return "ambiguous response"


def _recommended_action(decision: str) -> str:
    if decision == "True Positive":
        return "Prioritize remediation and rerun validation after the fix."
    if decision == "False Positive":
        return "Document the defensive control and suppress or tune the SAST rule if appropriate."
    return "Collect missing context and repeat validation in an authorized test environment."


def _build_explanation(decision: str, reason: str, error_category: str) -> str:
    if decision == "Needs Review" and error_category:
        return f"The alert was classified as Needs Review because {reason} Category: {error_category}."
    return f"The alert was classified as {decision} because {reason}"
