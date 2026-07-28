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

    decided = tp + fp + tn + fn
    total_real = tp + fn + review_real
    total_false = fp + tn + review_false
    total_false_positives = fp + tn
    false_positive_reduction_rate = safe_divide(tn, total_false_positives)
    manual_review_rate = safe_divide(review, total)
    coverage = safe_divide(decided, total)
    decided_accuracy = safe_divide(tp + tn, decided)
    abstention_rate = safe_divide(review, total)
    selective_precision = safe_divide(tp, tp + fp)
    selective_recall = safe_divide(tp, total_real)
    false_negative_risk = safe_divide(fn, total_real)
    false_positive_pass_through_rate = safe_divide(fp, total_false)
    review_burden_reduction = 1.0 - manual_review_rate
    confirmed_true_positive_rate = safe_divide(tp, total_real)
    utility_score = safe_divide(tp + tn - (2 * fp) - fn - (0.25 * review), total)

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
        "coverage": coverage,
        "decided_accuracy": decided_accuracy,
        "decision_rate": coverage,
        "abstention_rate": abstention_rate,
        "selective_precision": selective_precision,
        "selective_recall": selective_recall,
        "false_negative_risk": false_negative_risk,
        "false_positive_pass_through_rate": false_positive_pass_through_rate,
        "review_burden_reduction": review_burden_reduction,
        "confirmed_true_positive_rate": confirmed_true_positive_rate,
        "utility_score": utility_score,
    }
