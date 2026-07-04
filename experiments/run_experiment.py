from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from heimdall.evaluation.baselines import SUPPORTED_MODES, run_mode
from heimdall.evaluation.dataset_loader import load_alerts_jsonl
from heimdall.evaluation.error_analysis import group_error_cases
from heimdall.evaluation.metrics import calculate_metrics


def selected_modes(mode: str) -> list[str]:
    if mode == "all":
        return list(SUPPORTED_MODES)
    if mode not in SUPPORTED_MODES:
        raise ValueError(f"Unsupported mode {mode!r}. Use one of: all, {', '.join(SUPPORTED_MODES)}")
    return [mode]


def write_results_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "alert_id",
        "mode",
        "vulnerability_type",
        "severity",
        "ground_truth_label",
        "prediction",
        "classification",
        "confidence",
        "error_category",
        "rationale",
        "final_decision",
        "evidence",
        "explanation",
        "safety_notes",
        "recommended_action",
        "metadata",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: _csv_value(row.get(field, "")) for field in fieldnames})


def _csv_value(value: object) -> object:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return value


def write_summary_markdown(path: Path, summary: dict) -> None:
    lines = [
        "# Heimdall V2 Experiment Summary",
        "",
        f"Dataset: `{summary['dataset']}`",
        f"Total alerts loaded: {summary['alert_count']}",
        "",
    ]
    if summary["warnings"]:
        lines.extend(["## Dataset Warnings", ""])
        lines.extend(f"- {warning}" for warning in summary["warnings"])
        lines.append("")

    lines.extend(["## Metrics By Mode", ""])
    for mode, metrics in summary["modes"].items():
        lines.extend(
            [
                f"### {mode}",
                "",
                "| Metric | Value |",
                "|---|---:|",
                f"| TP | {metrics['tp']} |",
                f"| FP | {metrics['fp']} |",
                f"| TN | {metrics['tn']} |",
                f"| FN | {metrics['fn']} |",
                f"| Manual Review | {metrics['manual_review']} |",
                f"| Accuracy | {metrics['accuracy']:.4f} |",
                f"| Precision | {metrics['precision']:.4f} |",
                f"| Recall | {metrics['recall']:.4f} |",
                f"| F1-score | {metrics['f1_score']:.4f} |",
                f"| False-positive reduction rate | {metrics['false_positive_reduction_rate']:.4f} |",
                f"| Manual review rate | {metrics['manual_review_rate']:.4f} |",
                "",
                "Confusion matrix:",
                "",
                "| Actual \\ Predicted | Confirmed | Dismissed | Needs Review |",
                "|---|---:|---:|---:|",
                f"| Real vulnerability | {metrics['tp']} | {metrics['fn']} | {metrics['manual_review_real']} |",
                f"| False positive | {metrics['fp']} | {metrics['tn']} | {metrics['manual_review_false']} |",
                "",
            ]
        )

    lines.extend(["## Baseline Comparison", "", "| Mode | Accuracy delta | Precision delta | FP reduction delta |", "|---|---:|---:|---:|"])
    for mode, comparison in summary["baseline_comparison"].items():
        lines.append(
            f"| {mode} | {comparison['accuracy_delta_vs_sast_only']:.4f} | "
            f"{comparison['precision_delta_vs_sast_only']:.4f} | "
            f"{comparison['false_positive_reduction_delta_vs_sast_only']:.4f} |"
        )
    lines.append("")

    full_rows = summary["result_groups"].get("heimdall_full_pipeline_stub", {})
    lines.extend(_decision_section("Confirmed Vulnerabilities", full_rows.get("confirmed_vulnerabilities", [])))
    lines.extend(_decision_section("Discarded False Positives", full_rows.get("discarded_false_positives", [])))
    lines.extend(_decision_section("Needs Review Cases", full_rows.get("needs_review_cases", [])))

    lines.extend(["## Safety Log Summary", ""])
    safety = summary["safety_log_summary"]
    lines.extend(
        [
            f"- Dry-run requests logged: {safety['dry_run_requests']}",
            f"- Blocked requests: {safety['blocked_requests']}",
            f"- Live requests observed: {safety['live_requests']}",
            "",
        ]
    )

    lines.extend(["## Error Analysis", ""])
    for mode, buckets in summary["error_analysis"].items():
        lines.extend([f"### {mode}", "", "| Bucket | Count |", "|---|---:|"])
        for bucket, count in buckets.items():
            lines.append(f"| {bucket} | {count} |")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def _decision_section(title: str, rows: list[dict]) -> list[str]:
    lines = [f"## {title}", ""]
    if not rows:
        lines.extend(["No cases in this category for this run.", ""])
        return lines
    for row in rows:
        lines.extend(
            [
                f"### {row['alert_id']} - {row['vulnerability_type']}",
                "",
                f"- Severity: {row['severity']}",
                f"- Final decision: {row['final_decision']}",
                f"- Evidence: {row['evidence']}",
                f"- Explanation: {row['explanation']}",
                f"- Recommended action: {row['recommended_action']}",
                f"- Safety notes: {'; '.join(row['safety_notes']) if row['safety_notes'] else 'None recorded.'}",
                "",
            ]
        )
    return lines


def write_error_analysis_markdown(path: Path, summary: dict) -> None:
    lines = ["# Heimdall V2 Error Analysis", ""]
    for mode, buckets in summary["error_analysis"].items():
        lines.extend([f"## {mode}", "", "| Bucket | Count |", "|---|---:|"])
        for bucket, count in buckets.items():
            lines.append(f"| {bucket} | {count} |")
        lines.append("")

    review_cases = summary["result_groups"].get("heimdall_full_pipeline_stub", {}).get("needs_review_cases", [])
    lines.extend(["## Needs Review Explanations", ""])
    if not review_cases:
        lines.extend(["No Needs Review cases were produced by the full pipeline.", ""])
    for row in review_cases:
        lines.extend(
            [
                f"### {row['alert_id']}",
                "",
                f"- Error category: {row['error_category'] or 'uncategorized'}",
                f"- Explanation: {row['explanation']}",
                f"- Evidence: {row['evidence']}",
                "",
            ]
        )

    lines.extend(
        [
            "## Interpretation",
            "",
            "False positives are reduced when the pipeline can identify defensive controls or fails to reproduce exploit evidence in a safe dry-run validation path.",
            "Needs Review cases represent alerts where automated validation would require authentication, multi-step state, stronger runtime context, or a safety-policy exception.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def run_experiment(dataset: Path, output: Path, mode: str) -> dict:
    alerts, warnings = load_alerts_jsonl(dataset)
    modes = selected_modes(mode)

    all_rows: list[dict] = []
    metrics_by_mode: dict[str, dict] = {}
    errors_by_mode: dict[str, dict[str, int]] = {}
    result_groups: dict[str, dict[str, list[dict]]] = {}

    for selected_mode in modes:
        results = run_mode(alerts, selected_mode)
        metrics_by_mode[selected_mode] = calculate_metrics(results)
        errors_by_mode[selected_mode] = group_error_cases(results)
        result_rows = [asdict(result) for result in results]
        result_groups[selected_mode] = _group_results(result_rows)
        all_rows.extend(result_rows)

    summary = {
        "dataset": str(dataset),
        "alert_count": len(alerts),
        "warnings": warnings,
        "modes": metrics_by_mode,
        "baseline_comparison": _baseline_comparison(metrics_by_mode),
        "result_groups": result_groups,
        "error_analysis": errors_by_mode,
        "safety_log_summary": _safety_log_summary(all_rows),
    }

    output.mkdir(parents=True, exist_ok=True)
    (output / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    write_results_csv(output / "results.csv", all_rows)
    write_summary_markdown(output / "summary.md", summary)
    write_error_analysis_markdown(output / "error_analysis.md", summary)
    return summary


def _group_results(rows: list[dict]) -> dict[str, list[dict]]:
    return {
        "confirmed_vulnerabilities": [
            row for row in rows if row["final_decision"] == "True Positive" and row["classification"] == "TP"
        ],
        "discarded_false_positives": [
            row for row in rows if row["final_decision"] == "False Positive" and row["classification"] == "TN"
        ],
        "needs_review_cases": [row for row in rows if row["final_decision"] == "Needs Review"],
    }


def _baseline_comparison(metrics_by_mode: dict[str, dict]) -> dict[str, dict[str, float]]:
    sast = metrics_by_mode.get("sast_only", {})
    comparison: dict[str, dict[str, float]] = {}
    for mode, metrics in metrics_by_mode.items():
        if mode == "sast_only":
            continue
        comparison[mode] = {
            "accuracy_delta_vs_sast_only": metrics.get("accuracy", 0.0) - sast.get("accuracy", 0.0),
            "precision_delta_vs_sast_only": metrics.get("precision", 0.0) - sast.get("precision", 0.0),
            "false_positive_reduction_delta_vs_sast_only": metrics.get("false_positive_reduction_rate", 0.0)
            - sast.get("false_positive_reduction_rate", 0.0),
        }
    return comparison


def _safety_log_summary(rows: list[dict]) -> dict[str, int]:
    dry_run_requests = 0
    blocked_requests = 0
    live_requests = 0
    for row in rows:
        dast = row.get("metadata", {}).get("dast", {}) if isinstance(row.get("metadata"), dict) else {}
        request_log = dast.get("request_log", []) if isinstance(dast, dict) else []
        dry_run_requests += len(request_log)
        if dast.get("status") == "blocked":
            blocked_requests += 1
        if request_log and not row.get("metadata", {}).get("dry_run", True):
            live_requests += len(request_log)
        active = row.get("metadata", {}).get("active_validation", {}) if isinstance(row.get("metadata"), dict) else {}
        active_log = active.get("request_log", []) if isinstance(active, dict) else []
        if active.get("status") == "blocked":
            blocked_requests += 1
        if active_log and not row.get("metadata", {}).get("dry_run", True):
            live_requests += len(active_log)
    return {
        "dry_run_requests": dry_run_requests,
        "blocked_requests": blocked_requests,
        "live_requests": live_requests,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Heimdall V2 Phase 2 evaluation baselines.")
    parser.add_argument("--dataset", default="data/sample_alerts.jsonl", help="Path to JSONL alert dataset.")
    parser.add_argument("--mode", default="all", help=f"Evaluation mode: all, {', '.join(SUPPORTED_MODES)}")
    parser.add_argument("--output", default="reports", help="Directory for summary.json, results.csv, and summary.md")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary = run_experiment(Path(args.dataset), Path(args.output), args.mode)
    print(json.dumps({"alert_count": summary["alert_count"], "modes": summary["modes"]}, indent=2))


if __name__ == "__main__":
    main()
