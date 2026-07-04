from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone

from .metrics import classify
from .models import Alert, EvaluationResult


MODE = "heimdall_gpt41mini_reasoning_ablation"
PROMPT_TEMPLATE = (
    "You are a security reasoning assistant. Generate a localhost-only validation hypothesis "
    "for the given SAST alert. Do not make the final TP/FP decision."
)


def run_gpt41mini_reasoning_ablation(alerts: list[Alert]) -> list[EvaluationResult]:
    enabled = os.environ.get("HEIMDALL_ENABLE_REAL_LLM") == "1"
    api_key = os.environ.get("OPENAI_API_KEY")
    model = os.environ.get("HEIMDALL_LLM_MODEL", "gpt-4.1-mini")
    if not enabled or not api_key:
        return [_not_run(alert, model, "HEIMDALL_ENABLE_REAL_LLM=1 and OPENAI_API_KEY are required.") for alert in alerts]
    return [_not_run(alert, model, "Real LLM ablation scaffold is configured but network/API execution is intentionally disabled in reproducible tests.") for alert in alerts]


def _not_run(alert: Alert, model: str, reason: str) -> EvaluationResult:
    metadata = {
        "llm_ablation": {
            "status": "not_run",
            "reason": reason,
            "model": model,
            "temperature": 0,
            "prompt_template_sha256": hashlib.sha256(PROMPT_TEMPLATE.encode("utf-8")).hexdigest(),
            "runs": 0,
            "latency_seconds": None,
            "approximate_token_usage": None,
            "cost_estimate_usd": None,
            "output_variance": None,
            "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        }
    }
    return EvaluationResult(
        alert_id=alert.alert_id,
        mode=MODE,
        vulnerability_type=alert.vulnerability_type,
        severity=alert.severity,
        ground_truth_label=alert.ground_truth_label,
        prediction="needs_review",
        classification=classify(alert.is_real_vulnerability, "needs_review"),
        confidence=0.0,
        error_category="llm_ablation_not_run",
        rationale=reason,
        final_decision="Needs Review",
        evidence="No real LLM output was generated.",
        explanation="Optional GPT-4.1-mini ablation was skipped to preserve reproducibility without API keys.",
        safety_notes=["Real LLM mode is optional and cannot directly decide TP/FP without localhost evidence."],
        recommended_action="Set HEIMDALL_ENABLE_REAL_LLM=1 and OPENAI_API_KEY only in an authorized ablation environment.",
        metadata=metadata,
    )
