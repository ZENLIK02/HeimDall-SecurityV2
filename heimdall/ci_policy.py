from __future__ import annotations

from heimdall.config import HeimdallConfig
from heimdall.evaluation.models import EvaluationResult


def determine_exit_code(results: list[EvaluationResult], config: HeimdallConfig) -> int:
    for result in results:
        severity = result.severity.lower()
        confirmed = result.final_decision == "True Positive" or result.classification == "TP"
        if confirmed and severity == "critical" and config.security.fail_on_confirmed_critical:
            return 1
        if confirmed and severity == "high" and config.security.fail_on_confirmed_high:
            return 1
    return 0


def policy_summary(results: list[EvaluationResult], config: HeimdallConfig) -> dict:
    high_critical = [
        result
        for result in results
        if (result.final_decision == "True Positive" or result.classification == "TP")
        and result.severity.lower() in {"high", "critical"}
    ]
    exit_code = determine_exit_code(results, config)
    return {
        "passed": exit_code == 0,
        "exit_code": exit_code,
        "high_critical_confirmed": len(high_critical),
        "needs_review_does_not_fail": config.security.needs_review_does_not_fail,
    }
