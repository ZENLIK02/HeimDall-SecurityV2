from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path

from heimdall.ci_policy import policy_summary
from heimdall.config import HeimdallConfig
from heimdall.evaluation.models import EvaluationResult


def write_ci_reports(output_dir: str | Path, results: list[EvaluationResult], total_semgrep: int, config: HeimdallConfig) -> None:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    rows = [asdict(result) for result in results]
    (output / "ci_results.json").write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    _write_csv(output / "ci_results.csv", rows)
    _write_markdown(output / "ci_summary.md", results, total_semgrep, config)


def _write_csv(path: Path, rows: list[dict]) -> None:
    fields = [
        "alert_id",
        "severity",
        "vulnerability_type",
        "prediction",
        "classification",
        "final_decision",
        "evidence",
        "recommended_action",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: _csv_value(row.get(field, "")) for field in fields})


def _write_markdown(path: Path, results: list[EvaluationResult], total_semgrep: int, config: HeimdallConfig) -> None:
    confirmed = [row for row in results if row.final_decision == "True Positive" or row.classification == "TP"]
    false_positive = [row for row in results if row.final_decision == "False Positive" or row.classification in {"TN", "FN"}]
    review = [row for row in results if row.final_decision == "Needs Review" or row.classification == "REVIEW"]
    high_critical = [row for row in confirmed if row.severity.lower() in {"high", "critical"}]
    policy = policy_summary(results, config)
    lines = [
        "# Heimdall CI/CD Summary",
        "",
        f"Pipeline status: {'PASSED' if policy['passed'] else 'FAILED'}",
        "",
        "| Metric | Count |",
        "|---|---:|",
        f"| Total Semgrep findings | {total_semgrep} |",
        f"| Total validated findings | {len(results)} |",
        f"| Confirmed True Positives | {len(confirmed)} |",
        f"| False Positives | {len(false_positive)} |",
        f"| Needs Review | {len(review)} |",
        f"| High/Critical confirmed vulnerabilities | {len(high_critical)} |",
        "",
        "## Findings",
        "",
        "| Rule ID | Severity | File | Line | Heimdall Decision | Evidence | Recommended Action |",
        "|---|---|---|---:|---|---|---|",
    ]
    for result in results:
        metadata = result.metadata or {}
        file_path = metadata.get("file_path", "")
        line = metadata.get("line_number", "")
        lines.append(
            "| {rule} | {severity} | {file} | {line} | {decision} | {evidence} | {action} |".format(
                rule=_md(result.alert_id),
                severity=_md(result.severity),
                file=_md(str(file_path)),
                line=line,
                decision=_md(result.final_decision or result.prediction),
                evidence=_md((result.evidence or result.rationale)[:160]),
                action=_md((result.recommended_action or "Review finding.")[:160]),
            )
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def _csv_value(value: object) -> object:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return value


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
