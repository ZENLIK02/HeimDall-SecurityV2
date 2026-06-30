from __future__ import annotations

from typing import Any

from .models import LLMReasoningOutput, PromptBundle, ValidationPayload
from .payload_generation import generate_safe_payloads


EXPLOITABILITY = {"likely_exploitable", "unlikely_exploitable", "uncertain"}
RECOMMENDED_ACTIONS = {"validate_with_dast", "mark_false_positive", "needs_review"}


def validate_llm_output(raw: dict[str, Any]) -> LLMReasoningOutput:
    required = {
        "vulnerability_type",
        "exploitability",
        "confidence",
        "reasoning_summary",
        "validation_strategy",
        "payloads",
        "safety_notes",
        "recommended_action",
    }
    missing = required - set(raw)
    if missing:
        raise ValueError(f"LLM output missing fields: {', '.join(sorted(missing))}")
    if raw["exploitability"] not in EXPLOITABILITY:
        raise ValueError("Invalid exploitability value")
    if raw["recommended_action"] not in RECOMMENDED_ACTIONS:
        raise ValueError("Invalid recommended_action value")
    confidence = float(raw["confidence"])
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0.0 and 1.0")
    if not isinstance(raw["payloads"], list):
        raise ValueError("payloads must be a list")

    payloads = [
        payload if isinstance(payload, ValidationPayload) else ValidationPayload(
            vulnerability_type=str(payload.get("vulnerability_type", raw["vulnerability_type"])),
            method=str(payload.get("method", "GET")).upper(),
            endpoint=str(payload.get("endpoint", "/")),
            parameters=dict(payload.get("parameters", {})),
            body=dict(payload.get("body", {})),
            expected_evidence=str(payload.get("expected_evidence", "")),
            safety_notes=list(payload.get("safety_notes", [])),
        )
        for payload in raw["payloads"]
    ]

    return LLMReasoningOutput(
        vulnerability_type=str(raw["vulnerability_type"]),
        exploitability=raw["exploitability"],
        confidence=confidence,
        reasoning_summary=str(raw["reasoning_summary"]),
        validation_strategy=str(raw["validation_strategy"]),
        payloads=payloads,
        safety_notes=[str(note) for note in raw["safety_notes"]],
        recommended_action=raw["recommended_action"],
    )


class DeterministicMockLLMProvider:
    def analyze(self, prompt: PromptBundle) -> LLMReasoningOutput:
        context = prompt.alert_context
        if prompt.rejected:
            return LLMReasoningOutput(
                vulnerability_type=str(context.get("vulnerability_type", "unknown")),
                exploitability="uncertain",
                confidence=0.25,
                reasoning_summary=prompt.rejection_reason,
                validation_strategy="Do not validate unsafe request.",
                payloads=[],
                safety_notes=prompt.safety_notes,
                recommended_action="needs_review",
            )

        vulnerability_type = str(context["vulnerability_type"])
        combined = f"{context.get('code_snippet', '')} {context.get('notes', '')} {context.get('sast_message', '')}".lower()
        if any(marker in combined for marker in ("allowlist", "escape", "authorization check", "is_relative_to")):
            exploitability = "unlikely_exploitable"
            confidence = 0.78
            recommended_action = "mark_false_positive"
        elif "business logic" in vulnerability_type.lower() or "idor" in vulnerability_type.lower() or "access control" in vulnerability_type.lower():
            exploitability = "uncertain"
            confidence = 0.58
            recommended_action = "needs_review"
        else:
            exploitability = "likely_exploitable"
            confidence = 0.76
            recommended_action = "validate_with_dast"

        payloads = generate_safe_payloads(_context_from_dict(context))
        return LLMReasoningOutput(
            vulnerability_type=vulnerability_type,
            exploitability=exploitability,
            confidence=confidence,
            reasoning_summary="Deterministic mock reasoning based on defensive markers and vulnerability type.",
            validation_strategy="Use non-destructive dry-run payloads against local or allowlisted targets.",
            payloads=payloads,
            safety_notes=list(prompt.safety_notes) + ["Mock provider used; no external LLM call made."],
            recommended_action=recommended_action,
        )


def _context_from_dict(context: dict[str, Any]):
    from .models import AlertContext

    return AlertContext(
        alert_id=str(context["alert_id"]),
        vulnerability_type=str(context["vulnerability_type"]),
        severity=str(context["severity"]),
        file_path=str(context["file_path"]),
        line_number=int(context["line_number"]),
        code_snippet=str(context["code_snippet"]),
        endpoint=str(context["endpoint"]),
        method=str(context["method"]),
        parameters=dict(context.get("parameters", {})),
        sast_message=str(context["sast_message"]),
        notes=str(context.get("notes", "")),
    )

