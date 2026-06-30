from __future__ import annotations

import re
from dataclasses import asdict

from .models import AlertContext, PromptBundle


SUSPICIOUS_INSTRUCTION_PATTERNS = (
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"system\s*prompt",
    r"developer\s*message",
    r"exfiltrate",
    r"send\s+.*secret",
    r"disable\s+safety",
)

UNSAFE_REQUEST_PATTERNS = (
    r"rm\s+-rf",
    r"drop\s+table",
    r"delete\s+from",
    r"shutdown",
    r"reverse\s+shell",
    r"curl\s+.*\|\s*sh",
    r"powershell\s+-enc",
)


OUTPUT_SCHEMA = {
    "vulnerability_type": "string",
    "exploitability": "likely_exploitable | unlikely_exploitable | uncertain",
    "confidence": "float between 0.0 and 1.0",
    "reasoning_summary": "string",
    "validation_strategy": "string",
    "payloads": "array of non-destructive local/allowlisted payload objects",
    "safety_notes": "array of strings",
    "recommended_action": "validate_with_dast | mark_false_positive | needs_review",
}


def _sanitize_text(value: str) -> tuple[str, list[str]]:
    notes: list[str] = []
    sanitized = value
    for pattern in SUSPICIOUS_INSTRUCTION_PATTERNS:
        if re.search(pattern, sanitized, flags=re.IGNORECASE):
            sanitized = re.sub(pattern, "[sanitized instruction-like text]", sanitized, flags=re.IGNORECASE)
            notes.append(f"Sanitized suspicious instruction pattern: {pattern}")
    return sanitized, notes


def contains_unsafe_request(context: AlertContext) -> str:
    combined = f"{context.code_snippet}\n{context.sast_message}\n{context.notes}"
    for pattern in UNSAFE_REQUEST_PATTERNS:
        if re.search(pattern, combined, flags=re.IGNORECASE):
            return pattern
    return ""


def build_guarded_prompt(context: AlertContext) -> PromptBundle:
    safety_notes: list[str] = []
    unsafe_pattern = contains_unsafe_request(context)
    if unsafe_pattern:
        return PromptBundle(
            system_instruction="You are Heimdall V2. Refuse destructive validation and return Needs Review.",
            alert_context=asdict(context),
            output_schema=OUTPUT_SCHEMA,
            rejected=True,
            rejection_reason=f"Unsafe or destructive request pattern detected: {unsafe_pattern}",
            safety_notes=[f"Rejected unsafe pattern: {unsafe_pattern}"],
        )

    snippet, snippet_notes = _sanitize_text(context.code_snippet)
    message, message_notes = _sanitize_text(context.sast_message)
    notes, notes_notes = _sanitize_text(context.notes)
    safety_notes.extend(snippet_notes + message_notes + notes_notes)

    alert_context = asdict(context)
    alert_context["code_snippet"] = snippet
    alert_context["sast_message"] = message
    alert_context["notes"] = notes

    return PromptBundle(
        system_instruction=(
            "You are Heimdall V2. Analyze only the alert context. "
            "Generate non-destructive validation strategy for local or explicitly allowlisted targets. "
            "Return Needs Review for uncertainty, missing auth context, or unsafe validation."
        ),
        alert_context=alert_context,
        output_schema=OUTPUT_SCHEMA,
        safety_notes=safety_notes,
    )

