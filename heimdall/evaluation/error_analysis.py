from __future__ import annotations

from collections import Counter

from .baselines import ERROR_CATEGORIES
from .models import EvaluationResult


DEFAULT_ERROR_BUCKET = "ambiguous response"
STANDARD_ERROR_BUCKETS = {
    "no_endpoint_mapping",
    "synthetic_only_alert",
    "missing_runtime_fixture",
    "missing_authentication_context",
    "multi_step_workflow_required",
    "unsupported_category",
    "safety_policy_abstention",
    "unexpected_status_code",
    "evidence_marker_absent",
    "analyzer_inconclusive",
    "active_validation_confirmed",
    "active_validation_dismissed",
    "llm_ablation_not_run",
}


def group_error_cases(results: list[EvaluationResult]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    allowed = set(ERROR_CATEGORIES.values()) | STANDARD_ERROR_BUCKETS
    for result in results:
        if result.classification not in {"FP", "FN", "REVIEW"}:
            continue
        category = result.error_category or DEFAULT_ERROR_BUCKET
        if category not in allowed:
            allowed.add(category)
        counter[category] += 1

    for category in allowed:
        counter.setdefault(category, 0)
    counter.setdefault(DEFAULT_ERROR_BUCKET, 0)
    return dict(sorted(counter.items()))

