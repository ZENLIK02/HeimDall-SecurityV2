from __future__ import annotations

from collections.abc import Iterable

from .models import EvaluationResult


def classify(is_real: bool, prediction: str) -> str:
    if prediction == "needs_review":
        return "REVIEW"
    if is_real and prediction == "confirmed":
        return "TP"
    if not is_real and prediction == "confirmed":
        return "FP"
    if not is_real and prediction == "dismissed":
        return "TN"
    if is_real and prediction == "dismissed":
        return "FN"
    return "REVIEW"


def safe_divide(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def calculate_metrics(results: Iterable[EvaluationResult]) -> dict[str, float | int]:
    rows = list(results)
    total = len(rows)
    tp = sum(1 for row in rows if row.classification == "TP")
    fp = sum(1 for row in rows if row.classification == "FP")
    tn = sum(1 for row in rows if row.classification == "TN")
    fn = sum(1 for row in rows if row.classification == "FN")
    review = sum(1 for row in rows if row.classification == "REVIEW")
    review_real = sum(
        1 for row in rows if row.classification == "REVIEW" and row.ground_truth_label == "true_positive"
    )
    review_false = sum(
        1 for row in rows if row.classification == "REVIEW" and row.ground_truth_label == "false_positive"
    )

    accuracy = safe_divide(tp + tn, total)
    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    f1 = safe_divide(2 * precision * recall, precision + recall)

    total_false_positives = fp + tn
    false_positive_reduction_rate = safe_divide(tn, total_false_positives)
    manual_review_rate = safe_divide(review, total)

    return {
        "total": total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "manual_review": review,
        "manual_review_real": review_real,
        "manual_review_false": review_false,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_reduction_rate": false_positive_reduction_rate,
        "manual_review_rate": manual_review_rate,
    }
