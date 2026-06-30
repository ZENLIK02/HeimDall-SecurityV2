from __future__ import annotations

from collections import Counter

from .baselines import ERROR_CATEGORIES
from .models import EvaluationResult


DEFAULT_ERROR_BUCKET = "ambiguous response"


def group_error_cases(results: list[EvaluationResult]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    allowed = set(ERROR_CATEGORIES.values())
    for result in results:
        if result.classification not in {"FP", "FN", "REVIEW"}:
            continue
        category = result.error_category if result.error_category in allowed else DEFAULT_ERROR_BUCKET
        counter[category] += 1

    for category in allowed:
        counter.setdefault(category, 0)
    counter.setdefault(DEFAULT_ERROR_BUCKET, 0)
    return dict(sorted(counter.items()))

