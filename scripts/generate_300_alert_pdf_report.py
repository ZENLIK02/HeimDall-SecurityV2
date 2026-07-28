from __future__ import annotations

import argparse
import csv
import html
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image as PILImage
from PIL import ImageDraw, ImageFont
from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


REPORT_DIR = Path("reports/300_alert_eval")
DATASET_PATH = Path("test_data/heimdall_300_alerts.jsonl")
PDF_PATH = REPORT_DIR / "HeimdallV2_300_Alert_Evaluation_Summary.pdf"


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def read_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def git_commit_hash() -> str:
    try:
        completed = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True)
        return completed.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def dataset_summary(alerts: list[dict], distribution_path: Path) -> dict:
    summary = read_json(distribution_path) if distribution_path.exists() else {}
    summary.setdefault("total_alerts", len(alerts))
    summary.setdefault("categories", dict(Counter(row["vulnerability_type"] for row in alerts)))
    summary.setdefault("ground_truth_labels", dict(Counter(row["ground_truth_label"] for row in alerts)))
    summary.setdefault("severity", dict(Counter(row["severity"] for row in alerts)))
    summary.setdefault("expected_validation_behavior", dict(Counter(row.get("expected_validation_behavior", "unknown") for row in alerts)))
    return summary


def write_results_json(path: Path, summary: dict, result_rows: list[dict], dataset: dict, commit_hash: str) -> None:
    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "commit_hash": commit_hash,
        "dataset_summary": dataset,
        "experiment_summary": summary,
        "result_rows": result_rows,
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_confusion_matrices(path: Path, summary: dict) -> list[dict]:
    rows = []
    for mode, metrics in summary["modes"].items():
        row = {
            "mode": mode,
            "tp": metrics["tp"],
            "fp": metrics["fp"],
            "tn": metrics["tn"],
            "fn": metrics["fn"],
            "needs_review": metrics["manual_review"],
            "manual_review_real": metrics.get("manual_review_real", 0),
            "manual_review_false": metrics.get("manual_review_false", 0),
        }
        rows.append(row)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return rows


def short_mode(mode: str) -> str:
    return {
        "sast_only": "SAST",
        "rule_based_filtering": "Rules",
        "llm_only_stub": "LLM Stub",
        "heimdall_full_pipeline_stub": "Heimdall",
    }.get(mode, mode)


def draw_bar_chart(path: Path, title: str, series: dict[str, dict[str, float]], colors_by_series: dict[str, tuple[int, int, int]]) -> None:
    width, height = 1100, 650
    margin_left, margin_right, margin_top, margin_bottom = 90, 40, 80, 110
    image = PILImage.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default()
    draw.text((margin_left, 25), title, fill=(20, 30, 40), font=font)
    plot_w = width - margin_left - margin_right
    plot_h = height - margin_top - margin_bottom
    draw.line((margin_left, margin_top, margin_left, margin_top + plot_h), fill=(80, 80, 80), width=2)
    draw.line((margin_left, margin_top + plot_h, margin_left + plot_w, margin_top + plot_h), fill=(80, 80, 80), width=2)
    for tick in range(0, 101, 20):
        y = margin_top + plot_h - (tick / 100) * plot_h
        draw.line((margin_left - 5, y, margin_left + plot_w, y), fill=(230, 230, 230), width=1)
        draw.text((20, y - 6), f"{tick}%", fill=(60, 60, 60), font=font)
    modes = list(series)
    metric_names = list(next(iter(series.values())).keys())
    group_w = plot_w / len(modes)
    bar_w = min(48, group_w / (len(metric_names) + 1.5))
    for group_index, mode in enumerate(modes):
        group_x = margin_left + group_index * group_w + group_w * 0.18
        for metric_index, metric in enumerate(metric_names):
            value = series[mode][metric]
            bar_h = value * plot_h
            x0 = group_x + metric_index * (bar_w + 8)
            y0 = margin_top + plot_h - bar_h
            x1 = x0 + bar_w
            y1 = margin_top + plot_h
            draw.rectangle((x0, y0, x1, y1), fill=colors_by_series[metric])
            draw.text((x0, y0 - 14), f"{value:.2f}", fill=(40, 40, 40), font=font)
        draw.text((group_x, margin_top + plot_h + 15), short_mode(mode), fill=(40, 40, 40), font=font)
    legend_x = margin_left
    legend_y = height - 45
    for metric in metric_names:
        draw.rectangle((legend_x, legend_y, legend_x + 14, legend_y + 14), fill=colors_by_series[metric])
        draw.text((legend_x + 20, legend_y + 1), metric, fill=(40, 40, 40), font=font)
        legend_x += 155
    image.save(path)


def draw_single_metric_chart(path: Path, title: str, values: dict[str, float], color: tuple[int, int, int]) -> None:
    draw_bar_chart(path, title, {mode: {"rate": value} for mode, value in values.items()}, {"rate": color})


def draw_confusion_chart(path: Path, rows: list[dict]) -> None:
    width, height = 1100, 650
    margin_left, margin_right, margin_top, margin_bottom = 90, 40, 80, 130
    image = PILImage.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default()
    draw.text((margin_left, 25), "Confusion Matrix Counts By Mode", fill=(20, 30, 40), font=font)
    keys = ["tp", "fp", "tn", "fn", "needs_review"]
    palette = {
        "tp": (46, 125, 50),
        "fp": (198, 40, 40),
        "tn": (21, 101, 192),
        "fn": (245, 124, 0),
        "needs_review": (106, 27, 154),
    }
    max_total = max(sum(int(row[key]) for key in keys) for row in rows)
    plot_w = width - margin_left - margin_right
    plot_h = height - margin_top - margin_bottom
    draw.line((margin_left, margin_top + plot_h, margin_left + plot_w, margin_top + plot_h), fill=(80, 80, 80), width=2)
    group_w = plot_w / len(rows)
    bar_w = 90
    for index, row in enumerate(rows):
        x0 = margin_left + index * group_w + (group_w - bar_w) / 2
        y_cursor = margin_top + plot_h
        for key in keys:
            value = int(row[key])
            segment_h = (value / max_total) * plot_h if max_total else 0
            y0 = y_cursor - segment_h
            draw.rectangle((x0, y0, x0 + bar_w, y_cursor), fill=palette[key])
            if segment_h > 18:
                draw.text((x0 + 8, y0 + 4), str(value), fill="white", font=font)
            y_cursor = y0
        draw.text((x0 - 10, margin_top + plot_h + 15), short_mode(row["mode"]), fill=(40, 40, 40), font=font)
    legend_x = margin_left
    legend_y = height - 55
    for key in keys:
        draw.rectangle((legend_x, legend_y, legend_x + 14, legend_y + 14), fill=palette[key])
        draw.text((legend_x + 20, legend_y + 1), key.upper(), fill=(40, 40, 40), font=font)
        legend_x += 145
    image.save(path)


def create_charts(summary: dict, confusion_rows: list[dict], report_dir: Path) -> list[Path]:
    metrics_by_mode = summary["modes"]
    precision_recall_f1 = {
        mode: {
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1_score"],
        }
        for mode, metrics in metrics_by_mode.items()
    }
    fp_reduction = {mode: metrics["false_positive_reduction_rate"] for mode, metrics in metrics_by_mode.items()}
    review_rate = {mode: metrics["manual_review_rate"] for mode, metrics in metrics_by_mode.items()}
    chart_paths = [
        report_dir / "fig_precision_recall_f1.png",
        report_dir / "fig_fp_reduction.png",
        report_dir / "fig_manual_review_rate.png",
        report_dir / "fig_confusion_matrix_by_mode.png",
    ]
    draw_bar_chart(
        chart_paths[0],
        "Precision, Recall, and F1 By Evaluation Mode",
        precision_recall_f1,
        {"precision": (25, 118, 210), "recall": (56, 142, 60), "f1": (245, 124, 0)},
    )
    draw_single_metric_chart(chart_paths[1], "False-Positive Reduction Rate", fp_reduction, (21, 101, 192))
    draw_single_metric_chart(chart_paths[2], "Manual Review Rate", review_rate, (106, 27, 154))
    draw_confusion_chart(chart_paths[3], confusion_rows)
    return chart_paths


def table_style(header_color=colors.HexColor("#1f2937")) -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), header_color),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
        ]
    )


def format_metrics_table(summary: dict) -> list[list[str]]:
    rows = [
        [
            "Mode",
            "Accuracy",
            "Precision",
            "Recall",
            "F1",
            "FP Reduction",
            "Manual Review",
            "TP",
            "FP",
            "TN",
            "FN",
            "Needs Review",
        ]
    ]
    for mode, metrics in summary["modes"].items():
        rows.append(
            [
                mode,
                f"{metrics['accuracy']:.4f}",
                f"{metrics['precision']:.4f}",
                f"{metrics['recall']:.4f}",
                f"{metrics['f1_score']:.4f}",
                f"{metrics['false_positive_reduction_rate']:.4f}",
                f"{metrics['manual_review_rate']:.4f}",
                str(metrics["tp"]),
                str(metrics["fp"]),
                str(metrics["tn"]),
                str(metrics["fn"]),
                str(metrics["manual_review"]),
            ]
        )
    return rows


def add_counter_section(story: list, title: str, counter: dict, styles) -> None:
    story.append(Paragraph(title, styles["Heading2"]))
    rows = [["Item", "Count"]] + [[str(key), str(value)] for key, value in sorted(counter.items())]
    table = Table(rows, hAlign="LEFT")
    table.setStyle(table_style())
    story.append(table)
    story.append(Spacer(1, 0.15 * inch))


def build_pdf(pdf_path: Path, summary: dict, dataset: dict, chart_paths: list[Path], error_analysis: str, commit_hash: str) -> None:
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(pdf_path), pagesize=landscape(letter), rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph("Heimdall V2 300-Alert Evaluation Summary", styles["Title"]))
    story.append(Paragraph(f"Generated: {generated_at}", styles["Normal"]))
    story.append(Paragraph(f"Repository commit: {commit_hash}", styles["Normal"]))
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("Dataset Summary", styles["Heading2"]))
    story.append(
        Paragraph(
            "This experiment uses exactly 300 synthetic labeled SAST alerts generated with a fixed seed. "
            "All validation is dry-run/mock and local-only; no public websites, production systems, or third-party targets are scanned.",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))
    add_counter_section(story, "Class Distribution", dataset["ground_truth_labels"], styles)
    add_counter_section(story, "Vulnerability Category Distribution", dataset["categories"], styles)

    story.append(PageBreak())
    story.append(Paragraph("Evaluation Modes", styles["Heading2"]))
    story.append(
        Paragraph(
            "Modes include SAST-only, rule-based filtering, LLM-only stub, and Heimdall full-pipeline stub. "
            "The Heimdall full-pipeline mode uses the deterministic mock LLM and dry-run DAST safety controls.",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.15 * inch))
    metrics_table = Table(format_metrics_table(summary), repeatRows=1)
    metrics_table.setStyle(table_style())
    story.append(metrics_table)

    story.append(PageBreak())
    story.append(Paragraph("Charts", styles["Heading2"]))
    for chart in chart_paths:
        story.append(Image(str(chart), width=8.8 * inch, height=5.2 * inch))
        story.append(Spacer(1, 0.15 * inch))

    story.append(PageBreak())
    story.append(Paragraph("Error Analysis", styles["Heading2"]))
    story.append(Paragraph(html.escape(error_analysis[:6000]).replace("\n", "<br/>"), styles["BodyText"]))
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph("Safety Assumptions", styles["Heading2"]))
    story.append(
        Paragraph(
            "The experiment uses synthetic alerts, mock LLM behavior, dry-run validation, non-destructive payload hypotheses, "
            "and localhost-only safety assumptions. No external network validation is performed.",
            styles["BodyText"],
        )
    )
    story.append(Paragraph("Limitations", styles["Heading2"]))
    story.append(
        Paragraph(
            "The dataset is synthetic and does not prove real-world exploitability. The dry-run pipeline is intentionally conservative, "
            "especially for authentication-dependent, multi-step, or unsupported vulnerability classes. Live validation results may differ "
            "when applied to explicitly authorized local test applications.",
            styles["BodyText"],
        )
    )
    story.append(Paragraph("IEEE-Paper-Ready Summary", styles["Heading2"]))
    story.append(
        Paragraph(
            "A reproducible 300-alert synthetic evaluation was conducted to compare Heimdall V2 against SAST-only, rule-based, "
            "and LLM-only baselines. The benchmark used balanced vulnerability categories, labeled true-positive and false-positive "
            "cases, and a safety-first dry-run validation policy. Results demonstrate the trade-off between false-positive reduction "
            "and manual review introduced by conservative closed-loop validation, providing controlled evidence for evaluating Heimdall "
            "as a DevSecOps false-positive triage backend.",
            styles["BodyText"],
        )
    )
    doc.build(story)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate charts and PDF for the Heimdall 300-alert evaluation.")
    parser.add_argument("--dataset", default=str(DATASET_PATH))
    parser.add_argument("--distribution", default="test_data/heimdall_300_alerts_distribution.json")
    parser.add_argument("--report-dir", default=str(REPORT_DIR))
    args = parser.parse_args()

    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    summary = read_json(report_dir / "summary.json")
    result_rows = read_csv(report_dir / "results.csv")
    alerts = read_jsonl(Path(args.dataset))
    dataset = dataset_summary(alerts, Path(args.distribution))
    commit_hash = git_commit_hash()
    write_results_json(report_dir / "results.json", summary, result_rows, dataset, commit_hash)
    confusion_rows = write_confusion_matrices(report_dir / "confusion_matrices.csv", summary)
    chart_paths = create_charts(summary, confusion_rows, report_dir)
    error_analysis = (report_dir / "error_analysis.md").read_text(encoding="utf-8")
    build_pdf(report_dir / PDF_PATH.name, summary, dataset, chart_paths, error_analysis, commit_hash)
    print(f"Wrote PDF report to {report_dir / PDF_PATH.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
