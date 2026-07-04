from __future__ import annotations

import argparse
import csv
import html
import json
import math
import random
import shutil
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image as PILImage
from PIL import ImageDraw, ImageFont
from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


REPORT_DIR = Path("reports/ieee_final_eval")
PDF_NAME = "HeimdallV2_IEEE_Final_Evaluation_Report.pdf"
PAPER_DIR = Path("paper")


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


def write_csv(path: Path, rows: list[dict], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    names = fieldnames or list(rows[0])
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=names)
        writer.writeheader()
        writer.writerows(rows)


def git_commit_hash() -> str:
    try:
        completed = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True)
        return completed.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def dataset_summary(alerts: list[dict]) -> dict:
    source = Counter(row.get("source", "unknown") for row in alerts)
    return {
        "total_alerts": len(alerts),
        "categories": dict(sorted(Counter(row["vulnerability_type"] for row in alerts).items())),
        "ground_truth_labels": dict(sorted(Counter(row["ground_truth_label"] for row in alerts).items())),
        "severity": dict(sorted(Counter(row["severity"] for row in alerts).items())),
        "expected_validation_behavior": dict(
            sorted(Counter(row.get("expected_validation_behavior", "unknown") for row in alerts).items())
        ),
        "active_local_fixtures": sum(1 for row in alerts if row.get("active_local_fixture") is True),
        "synthetic_alerts": source.get("synthetic_300", 0),
        "source": dict(sorted(source.items())),
    }


def metrics_rows(summary: dict) -> list[dict]:
    rows = []
    for mode, metrics in summary["modes"].items():
        rows.append(
            {
                "mode": mode,
                "total": metrics["total"],
                "accuracy": f"{metrics['accuracy']:.4f}",
                "precision": f"{metrics['precision']:.4f}",
                "recall": f"{metrics['recall']:.4f}",
                "f1_score": f"{metrics['f1_score']:.4f}",
                "false_positive_reduction_rate": f"{metrics['false_positive_reduction_rate']:.4f}",
                "manual_review_rate": f"{metrics['manual_review_rate']:.4f}",
                "tp": metrics["tp"],
                "fp": metrics["fp"],
                "tn": metrics["tn"],
                "fn": metrics["fn"],
                "needs_review": metrics["manual_review"],
            }
        )
    return rows


def coverage_rows(summary: dict, ci_by_mode: dict[str, dict[str, tuple[float, float]]] | None = None) -> list[dict]:
    keys = [
        "coverage",
        "decision_rate",
        "abstention_rate",
        "selective_precision",
        "selective_recall",
        "false_negative_risk",
        "false_positive_pass_through_rate",
        "review_burden_reduction",
        "confirmed_true_positive_rate",
        "utility_score",
    ]
    rows = []
    for mode, metrics in summary["modes"].items():
        row = {"mode": mode}
        row.update({key: f"{metrics.get(key, 0.0):.4f}" for key in keys})
        for key, (low, high) in (ci_by_mode or {}).get(mode, {}).items():
            row[f"{key}_ci95_low"] = f"{low:.4f}"
            row[f"{key}_ci95_high"] = f"{high:.4f}"
        rows.append(row)
    return rows


def bootstrap_intervals(result_rows: list[dict], iterations: int = 1000, seed: int = 42) -> dict[str, dict[str, tuple[float, float]]]:
    rng = random.Random(seed)
    by_mode: dict[str, list[dict]] = defaultdict(list)
    for row in result_rows:
        by_mode[row["mode"]].append(row)
    intervals: dict[str, dict[str, tuple[float, float]]] = {}
    for mode, rows in by_mode.items():
        samples: dict[str, list[float]] = defaultdict(list)
        if not rows:
            continue
        for _ in range(iterations):
            sample = [rows[rng.randrange(len(rows))] for _ in rows]
            values = _selective_values(sample)
            for key, value in values.items():
                samples[key].append(value)
        intervals[mode] = {key: _percentile_interval(values) for key, values in samples.items()}
    return intervals


def _selective_values(rows: list[dict]) -> dict[str, float]:
    total = len(rows)
    tp = sum(1 for row in rows if row["classification"] == "TP")
    fp = sum(1 for row in rows if row["classification"] == "FP")
    tn = sum(1 for row in rows if row["classification"] == "TN")
    fn = sum(1 for row in rows if row["classification"] == "FN")
    review = sum(1 for row in rows if row["classification"] == "REVIEW")
    review_real = sum(1 for row in rows if row["classification"] == "REVIEW" and row["ground_truth_label"] == "true_positive")
    total_real = tp + fn + review_real
    decided = tp + fp + tn + fn
    coverage = decided / total if total else 0.0
    selective_precision = tp / (tp + fp) if tp + fp else 0.0
    selective_recall = tp / total_real if total_real else 0.0
    utility_score = (tp + tn - (2 * fp) - fn - (0.25 * review)) / total if total else 0.0
    return {
        "coverage": coverage,
        "selective_precision": selective_precision,
        "selective_recall": selective_recall,
        "utility_score": utility_score,
    }


def _percentile_interval(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    ordered = sorted(values)
    low = ordered[int(0.025 * (len(ordered) - 1))]
    high = ordered[int(0.975 * (len(ordered) - 1))]
    return low, high


def confusion_rows(summary: dict) -> list[dict]:
    rows = []
    for mode, metrics in summary["modes"].items():
        rows.append(
            {
                "mode": mode,
                "tp": metrics["tp"],
                "fp": metrics["fp"],
                "tn": metrics["tn"],
                "fn": metrics["fn"],
                "needs_review": metrics["manual_review"],
                "manual_review_real": metrics.get("manual_review_real", 0),
                "manual_review_false": metrics.get("manual_review_false", 0),
            }
        )
    return rows


def category_breakdown(result_rows: list[dict]) -> list[dict]:
    buckets: dict[tuple[str, str], Counter] = defaultdict(Counter)
    for row in result_rows:
        buckets[(row["mode"], row["vulnerability_type"])][row["classification"]] += 1
    rows = []
    for (mode, category), counter in sorted(buckets.items()):
        total = sum(counter.values())
        tp = counter.get("TP", 0)
        fp = counter.get("FP", 0)
        tn = counter.get("TN", 0)
        fn = counter.get("FN", 0)
        review = counter.get("REVIEW", 0)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        rows.append(
            {
                "mode": mode,
                "vulnerability_type": category,
                "total": total,
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "needs_review": review,
                "precision": f"{precision:.4f}",
                "recall": f"{recall:.4f}",
            }
        )
    return rows


def category_metrics(result_rows: list[dict]) -> list[dict]:
    rows = []
    for row in category_breakdown(result_rows):
        total = int(row["total"])
        tp = int(row["tp"])
        fp = int(row["fp"])
        tn = int(row["tn"])
        fn = int(row["fn"])
        review = int(row["needs_review"])
        decided = tp + fp + tn + fn
        rows.append(
            {
                "mode": row["mode"],
                "vulnerability_type": row["vulnerability_type"],
                "category_coverage": f"{decided / total if total else 0.0:.4f}",
                "category_abstention_rate": f"{review / total if total else 0.0:.4f}",
                "category_TP": tp,
                "category_FP": fp,
                "category_TN": tn,
                "category_FN": fn,
                "category_NeedsReview": review,
                "category_selective_precision": f"{tp / (tp + fp) if tp + fp else 0.0:.4f}",
                "category_selective_recall": f"{tp / (tp + fn) if tp + fn else 0.0:.4f}",
            }
        )
    return rows


def short_mode(mode: str) -> str:
    return {
        "sast_only": "SAST",
        "rule_based_filtering": "Rules",
        "llm_only_stub": "LLM",
        "heimdall_full_pipeline_stub": "Full Stub",
        "heimdall_dry_run_mock": "Dry Run",
        "heimdall_active_local_validation": "Active Local",
        "heimdall_gpt41mini_reasoning_ablation": "GPT-4.1 Mini",
    }.get(mode, mode)


def font(size: int = 16) -> ImageFont.ImageFont:
    for candidate in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "C:/Windows/Fonts/arial.ttf",
    ):
        try:
            return ImageFont.truetype(candidate, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def new_canvas(width: int = 1280, height: int = 720) -> tuple[PILImage.Image, ImageDraw.ImageDraw]:
    image = PILImage.new("RGB", (width, height), "white")
    return image, ImageDraw.Draw(image)


def draw_title(draw: ImageDraw.ImageDraw, title: str) -> None:
    draw.text((50, 28), title, fill=(17, 24, 39), font=font(24))


def draw_bar_chart(path: Path, title: str, values: dict[str, dict[str, float]], palette: dict[str, tuple[int, int, int]]) -> None:
    image, draw = new_canvas()
    draw_title(draw, title)
    left, top, width, height = 90, 90, 1130, 500
    draw.line((left, top, left, top + height), fill=(75, 85, 99), width=2)
    draw.line((left, top + height, left + width, top + height), fill=(75, 85, 99), width=2)
    for tick in range(0, 101, 20):
        y = top + height - int((tick / 100) * height)
        draw.line((left - 5, y, left + width, y), fill=(229, 231, 235), width=1)
        draw.text((38, y - 8), f"{tick}%", fill=(75, 85, 99), font=font(14))
    modes = list(values)
    metric_names = list(next(iter(values.values())))
    group_w = width / max(len(modes), 1)
    bar_w = min(40, max(12, group_w / (len(metric_names) + 2)))
    for index, mode in enumerate(modes):
        base_x = left + index * group_w + group_w * 0.18
        for metric_index, metric in enumerate(metric_names):
            value = values[mode][metric]
            x0 = int(base_x + metric_index * (bar_w + 8))
            bar_h = int(value * height)
            y0 = top + height - bar_h
            draw.rectangle((x0, y0, int(x0 + bar_w), top + height), fill=palette[metric])
            draw.text((x0, max(top, y0 - 20)), f"{value:.2f}", fill=(31, 41, 55), font=font(13))
        draw.text((int(base_x - 10), top + height + 18), short_mode(mode), fill=(31, 41, 55), font=font(13))
    legend_x = left
    for metric in metric_names:
        draw.rectangle((legend_x, 650, legend_x + 16, 666), fill=palette[metric])
        draw.text((legend_x + 23, 648), metric, fill=(31, 41, 55), font=font(14))
        legend_x += 180
    image.save(path)


def draw_scatter(path: Path, title: str, values: dict[str, tuple[float, float]], x_label: str, y_label: str) -> None:
    image, draw = new_canvas()
    draw_title(draw, title)
    left, top, width, height = 110, 100, 1050, 500
    draw.rectangle((left, top, left + width, top + height), outline=(156, 163, 175), width=2)
    for tick in range(0, 101, 20):
        x = left + int((tick / 100) * width)
        y = top + height - int((tick / 100) * height)
        draw.line((x, top, x, top + height), fill=(243, 244, 246), width=1)
        draw.line((left, y, left + width, y), fill=(243, 244, 246), width=1)
        draw.text((x - 9, top + height + 8), f"{tick}", fill=(75, 85, 99), font=font(14))
        draw.text((58, y - 8), f"{tick}", fill=(75, 85, 99), font=font(14))
    draw.text((left + width // 2 - 40, 645), x_label, fill=(31, 41, 55), font=font(15))
    draw.text((25, top + height // 2), y_label, fill=(31, 41, 55), font=font(15))
    colors_by_mode = [(37, 99, 235), (22, 163, 74), (234, 88, 12), (147, 51, 234), (14, 116, 144), (220, 38, 38)]
    occupied: dict[tuple[int, int], int] = {}
    for idx, (mode, (x_value, y_value)) in enumerate(values.items()):
        x = left + int(x_value * width)
        y = top + height - int(y_value * height)
        color = colors_by_mode[idx % len(colors_by_mode)]
        draw.ellipse((x - 7, y - 7, x + 7, y + 7), fill=color)
        bucket = (round(x / 20), round(y / 20))
        occupied[bucket] = occupied.get(bucket, 0) + 1
        vertical_offset = (occupied[bucket] - 1) * 22
        label = short_mode(mode)
        label_x = x + 12
        if x > left + width - 150:
            label_x = x - 118
        label_y = max(top + 4, min(top + height - 18, y - 9 + vertical_offset))
        draw.text((label_x, label_y), label, fill=color, font=font(14))
    image.save(path)


def draw_pipeline(path: Path, title: str, nodes: list[str]) -> None:
    image, draw = new_canvas()
    draw_title(draw, title)
    y = 310
    box_w = 150
    gap = 35
    total_w = len(nodes) * box_w + (len(nodes) - 1) * gap
    x = (1280 - total_w) // 2
    colors_list = [(219, 234, 254), (220, 252, 231), (254, 249, 195), (243, 232, 255), (224, 242, 254), (254, 226, 226)]
    for index, node in enumerate(nodes):
        x0 = x + index * (box_w + gap)
        draw.rounded_rectangle((x0, y, x0 + box_w, y + 88), radius=8, fill=colors_list[index % len(colors_list)], outline=(55, 65, 81), width=2)
        for line_index, part in enumerate(_wrap(node, 18)):
            draw.text((x0 + 14, y + 22 + line_index * 18), part, fill=(17, 24, 39), font=font(13))
        if index < len(nodes) - 1:
            ax = x0 + box_w + 7
            draw.line((ax, y + 44, ax + gap - 14, y + 44), fill=(55, 65, 81), width=3)
            draw.polygon([(ax + gap - 14, y + 38), (ax + gap - 14, y + 50), (ax + gap - 5, y + 44)], fill=(55, 65, 81))
    image.save(path)


def draw_confusion(path: Path, rows: list[dict]) -> None:
    image, draw = new_canvas()
    draw_title(draw, "Confusion Matrix Counts By Mode")
    keys = ["tp", "fp", "tn", "fn", "needs_review"]
    palette = {
        "tp": (22, 163, 74),
        "fp": (220, 38, 38),
        "tn": (37, 99, 235),
        "fn": (234, 88, 12),
        "needs_review": (147, 51, 234),
    }
    left, top, width, height = 100, 100, 1080, 480
    max_total = max(sum(int(row[key]) for key in keys) for row in rows) or 1
    group_w = width / len(rows)
    for idx, row in enumerate(rows):
        x0 = int(left + idx * group_w + group_w * 0.35)
        y_cursor = top + height
        for key in keys:
            value = int(row[key])
            segment = int(value / max_total * height)
            draw.rectangle((x0, y_cursor - segment, x0 + 70, y_cursor), fill=palette[key])
            if segment > 18:
                draw.text((x0 + 8, y_cursor - segment + 4), str(value), fill="white", font=font(13))
            y_cursor -= segment
        draw.text((x0 - 8, top + height + 18), short_mode(row["mode"]), fill=(31, 41, 55), font=font(13))
    legend_x = left
    for key in keys:
        draw.rectangle((legend_x, 650, legend_x + 16, 666), fill=palette[key])
        draw.text((legend_x + 23, 648), key.upper(), fill=(31, 41, 55), font=font(14))
        legend_x += 150
    image.save(path)


def draw_heatmap(path: Path, rows: list[dict]) -> None:
    active_rows = [row for row in rows if row["mode"] == "heimdall_active_local_validation"]
    categories = [row["vulnerability_type"] for row in active_rows]
    image, draw = new_canvas(1280, 820)
    draw_title(draw, "Active-Local Category Performance Heatmap")
    left, top, cell_w, cell_h = 360, 100, 210, 42
    headers = ["precision", "recall", "needs_review"]
    for idx, header in enumerate(headers):
        draw.text((left + idx * cell_w + 18, 70), header, fill=(31, 41, 55), font=font(14))
    for row_idx, row in enumerate(active_rows):
        y = top + row_idx * cell_h
        draw.text((50, y + 11), categories[row_idx], fill=(31, 41, 55), font=font(13))
        values = [
            float(row["precision"]),
            float(row["recall"]),
            int(row["needs_review"]) / max(int(row["total"]), 1),
        ]
        for col_idx, value in enumerate(values):
            color = _heat(value)
            x = left + col_idx * cell_w
            draw.rectangle((x, y, x + cell_w - 8, y + cell_h - 5), fill=color, outline="white")
            draw.text((x + 18, y + 11), f"{value:.2f}", fill=(17, 24, 39), font=font(13))
    image.save(path)


def draw_error_buckets(path: Path, summary: dict) -> None:
    buckets = Counter()
    for mode_buckets in summary.get("error_analysis", {}).values():
        buckets.update(mode_buckets)
    image, draw = new_canvas()
    draw_title(draw, "Error Bucket Counts")
    if not buckets:
        draw.text((90, 150), "No error buckets recorded.", fill=(31, 41, 55), font=font(16))
        image.save(path)
        return
    items = sorted(buckets.items(), key=lambda item: item[1], reverse=True)
    max_count = max(buckets.values())
    left, top, bar_w, bar_h = 430, 110, 710, 42
    for index, (bucket, count) in enumerate(items):
        y = top + index * 70
        wrapped = _wrap(bucket, 38)
        for line_index, line in enumerate(wrapped[:2]):
            draw.text((60, y + line_index * 18), line, fill=(31, 41, 55), font=font(13))
        width = int((count / max_count) * bar_w)
        draw.rectangle((left, y, left + width, y + bar_h), fill=(220, 38, 38))
        draw.text((left + width + 12, y + 10), str(count), fill=(31, 41, 55), font=font(14))
    image.save(path)


def draw_category_coverage(path: Path, category_metric_rows: list[dict]) -> None:
    active_rows = [row for row in category_metric_rows if row["mode"] == "heimdall_active_local_validation"]
    image, draw = new_canvas(1280, 820)
    draw_title(draw, "Active-Local Coverage By Category")
    if not active_rows:
        draw.text((90, 150), "No active-local category metrics available.", fill=(31, 41, 55), font=font(16))
        image.save(path)
        return
    left, top, width, bar_h = 430, 95, 700, 36
    for index, row in enumerate(active_rows):
        y = top + index * 56
        value = float(row["category_coverage"])
        draw.text((55, y + 8), row["vulnerability_type"], fill=(31, 41, 55), font=font(13))
        draw.rectangle((left, y, left + width, y + bar_h), fill=(243, 244, 246), outline=(209, 213, 219))
        draw.rectangle((left, y, left + int(width * value), y + bar_h), fill=(37, 99, 235))
        draw.text((left + int(width * value) + 10, y + 8), f"{value:.2f}", fill=(31, 41, 55), font=font(13))
    image.save(path)


def draw_decision_composition(path: Path, confusion: list[dict]) -> None:
    image, draw = new_canvas()
    draw_title(draw, "Decision Composition By Mode")
    keys = ["tp", "fp", "tn", "fn", "needs_review"]
    palette = {
        "tp": (22, 163, 74),
        "fp": (220, 38, 38),
        "tn": (37, 99, 235),
        "fn": (234, 88, 12),
        "needs_review": (147, 51, 234),
    }
    left, top, width, row_h = 230, 100, 850, 52
    for index, row in enumerate(confusion):
        y = top + index * 72
        total = sum(int(row[key]) for key in keys) or 1
        draw.text((55, y + 17), short_mode(row["mode"]), fill=(31, 41, 55), font=font(13))
        x = left
        for key in keys:
            value = int(row[key])
            segment = int((value / total) * width)
            draw.rectangle((x, y, x + segment, y + row_h), fill=palette[key])
            if segment > 45:
                draw.text((x + 8, y + 17), str(value), fill="white", font=font(13))
            x += segment
    legend_x = left
    for key in keys:
        draw.rectangle((legend_x, 650, legend_x + 16, 666), fill=palette[key])
        draw.text((legend_x + 23, 648), key.upper(), fill=(31, 41, 55), font=font(14))
        legend_x += 150
    image.save(path)


def draw_needs_review_by_category(path: Path, category_metric_rows: list[dict]) -> None:
    active_rows = [row for row in category_metric_rows if row["mode"] == "heimdall_active_local_validation"]
    image, draw = new_canvas(1280, 820)
    draw_title(draw, "Active-Local Needs Review By Category")
    if not active_rows:
        draw.text((90, 150), "No active-local category metrics available.", fill=(31, 41, 55), font=font(16))
        image.save(path)
        return
    left, top, width, bar_h = 430, 95, 700, 36
    max_review = max(int(row["category_NeedsReview"]) for row in active_rows) or 1
    for index, row in enumerate(active_rows):
        y = top + index * 56
        review = int(row["category_NeedsReview"])
        draw.text((55, y + 8), row["vulnerability_type"], fill=(31, 41, 55), font=font(13))
        draw.rectangle((left, y, left + width, y + bar_h), fill=(243, 244, 246), outline=(209, 213, 219))
        draw.rectangle((left, y, left + int(width * review / max_review), y + bar_h), fill=(147, 51, 234))
        draw.text((left + int(width * review / max_review) + 10, y + 8), str(review), fill=(31, 41, 55), font=font(13))
    image.save(path)


def _heat(value: float) -> tuple[int, int, int]:
    value = max(0.0, min(1.0, value))
    red = int(254 - value * 160)
    green = int(226 - value * 70)
    blue = int(226 + value * 20)
    return red, green, blue


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines[:4]


def create_charts(summary: dict, confusion: list[dict], category_rows: list[dict], category_metric_rows: list[dict], report_dir: Path) -> list[Path]:
    metrics = summary["modes"]
    chart_paths = [
        report_dir / "fig_architecture_pipeline.png",
        report_dir / "fig_evaluation_pipeline.png",
        report_dir / "fig_precision_recall_f1.png",
        report_dir / "fig_coverage_vs_f1.png",
        report_dir / "fig_fp_reduction_vs_manual_review.png",
        report_dir / "fig_utility_score_by_mode.png",
        report_dir / "fig_confusion_matrix_by_mode.png",
        report_dir / "fig_category_performance_heatmap.png",
        report_dir / "fig_error_buckets.png",
        report_dir / "fig_category_coverage.png",
        report_dir / "fig_decision_composition_by_mode.png",
        report_dir / "fig_needs_review_by_category.png",
    ]
    draw_pipeline(chart_paths[0], "Heimdall V2 Safety-First DevSecOps Architecture", ["SAST Alerts", "LLM Triage", "Payload Hypothesis", "Safety Gate", "DAST Validation", "CI Decision"])
    draw_pipeline(chart_paths[1], "IEEE Final Evaluation Workflow", ["Synthetic 300", "Active Local 180", "Seven Modes", "Metrics + CI", "Charts", "PDF + Paper"])
    draw_bar_chart(
        chart_paths[2],
        "Precision, Recall, and F1 By Mode",
        {
            mode: {
                "precision": values["precision"],
                "recall": values["recall"],
                "f1": values["f1_score"],
            }
            for mode, values in metrics.items()
        },
        {"precision": (37, 99, 235), "recall": (22, 163, 74), "f1": (234, 88, 12)},
    )
    draw_scatter(
        chart_paths[3],
        "Coverage vs F1",
        {mode: (values.get("coverage", 0), values["f1_score"]) for mode, values in metrics.items()},
        "coverage",
        "f1",
    )
    draw_scatter(
        chart_paths[4],
        "FP Reduction vs Manual Review",
        {
            mode: (values["false_positive_reduction_rate"], values["manual_review_rate"])
            for mode, values in metrics.items()
        },
        "fp reduction",
        "manual review",
    )
    draw_bar_chart(
        chart_paths[5],
        "Utility Score By Mode",
        {mode: {"utility": max(0.0, min(1.0, (values.get("utility_score", 0) + 1) / 2))} for mode, values in metrics.items()},
        {"utility": (14, 116, 144)},
    )
    draw_confusion(chart_paths[6], confusion)
    draw_heatmap(chart_paths[7], category_rows)
    draw_error_buckets(chart_paths[8], summary)
    draw_category_coverage(chart_paths[9], category_metric_rows)
    draw_decision_composition(chart_paths[10], confusion)
    draw_needs_review_by_category(chart_paths[11], category_metric_rows)
    return chart_paths


def write_results_json(path: Path, summary: dict, results: list[dict], dataset: dict, commit_hash: str) -> None:
    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "commit_hash": commit_hash,
        "dataset_summary": dataset,
        "experiment_summary": summary,
        "result_rows": results,
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_evidence_examples(path: Path, result_rows: list[dict]) -> None:
    by_category: dict[str, list[dict]] = defaultdict(list)
    for row in result_rows:
        if row["mode"] != "heimdall_active_local_validation":
            continue
        if row["classification"] not in {"TP", "TN"}:
            continue
        by_category[row["vulnerability_type"]].append(row)
    lines = ["# Evidence Examples", ""]
    for category in sorted(by_category):
        lines.extend([f"## {category}", ""])
        for row in by_category[category][:2]:
            metadata = _json_field(row.get("metadata", "{}")).get("active_validation", {})
            lines.extend(
                [
                    f"### {row['alert_id']}",
                    "",
                    f"- Category: {category}",
                    f"- Endpoint: `{metadata.get('url', '')}`",
                    f"- Method: `{metadata.get('method', '')}`",
                    f"- Controlled marker: `{metadata.get('expected_evidence', '')}`",
                    f"- Status code: `{metadata.get('status_code', '')}`",
                    f"- Evidence observed: `{metadata.get('evidence_found', False)}`",
                    f"- Final decision: `{row['final_decision']}`",
                    "- Why this is safe: validation is restricted to a localhost fixture, uses deterministic markers, and does not contact third-party systems.",
                    "- Why this is not proof of real-world exploitability: the fixture demonstrates controlled behavior only; production validation requires explicit authorization and environment-specific context.",
                    "",
                ]
            )
    path.write_text("\n".join(lines), encoding="utf-8")


def write_llm_ablation_status(path: Path, result_rows: list[dict]) -> None:
    rows = [row for row in result_rows if row["mode"] == "heimdall_gpt41mini_reasoning_ablation"]
    if not rows:
        status = "not configured"
        reason = "Mode was not included in this run."
    else:
        metadata = _json_field(rows[0].get("metadata", "{}")).get("llm_ablation", {})
        status = str(metadata.get("status", "not_run"))
        reason = str(metadata.get("reason", "No reason recorded."))
    path.write_text(
        "\n".join(
            [
                "# Optional GPT-4.1-mini Ablation Status",
                "",
                f"- Status: {status}",
                f"- Reason: {reason}",
                "- Default reproducibility mode does not require or use API keys.",
                "- To run a future authorized ablation, set `HEIMDALL_ENABLE_REAL_LLM=1`, `OPENAI_API_KEY`, and optionally `HEIMDALL_LLM_MODEL=gpt-4.1-mini`.",
                "- The LLM may propose hypotheses only; final decisions still require safety gating and localhost evidence.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _json_field(value: str) -> dict:
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def markdown_table(rows: list[dict], fields: list[str]) -> str:
    lines = ["| " + " | ".join(fields) + " |", "|" + "|".join("---" for _ in fields) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(field, "")) for field in fields) + " |")
    return "\n".join(lines)


def write_markdown_outputs(report_dir: Path, summary: dict, dataset: dict, metrics: list[dict], coverage: list[dict], category_metric_rows: list[dict], commit_hash: str) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    metric_fields = ["mode", "accuracy", "precision", "recall", "f1_score", "false_positive_reduction_rate", "manual_review_rate", "tp", "fp", "tn", "fn", "needs_review"]
    coverage_fields = ["mode", "coverage", "coverage_ci95_low", "coverage_ci95_high", "decision_rate", "abstention_rate", "selective_precision", "selective_recall", "utility_score"]
    category_fields = ["mode", "vulnerability_type", "category_coverage", "category_abstention_rate", "category_TP", "category_FP", "category_TN", "category_FN", "category_NeedsReview"]

    (report_dir / "paper_ready_tables.md").write_text(
        "\n".join(
            [
                "# Paper-Ready Tables",
                "",
                "## Table 1. Main Metrics",
                "",
                markdown_table(metrics, metric_fields),
                "",
                "## Table 2. Coverage and Selective Metrics",
                "",
                markdown_table(coverage, coverage_fields),
                "",
                "## Table 3. Category Metrics",
                "",
                markdown_table(category_metric_rows, category_fields),
                "",
            ]
        ),
        encoding="utf-8",
    )
    active = summary["modes"].get("heimdall_active_local_validation", {})
    (report_dir / "paper_ready_summary.md").write_text(
        "\n".join(
            [
                "# Paper-Ready Summary",
                "",
                f"Generated: {generated_at}",
                f"Commit: `{commit_hash}`",
                "",
                f"Heimdall V2 was evaluated on a reproducible {dataset['total_alerts']}-alert benchmark composed of {dataset.get('synthetic_alerts', 300)} synthetic labeled SAST alerts and {dataset['active_local_fixtures']} localhost-only active validation fixtures. The experiment compared SAST-only, rule-based, LLM-only stub, full-pipeline stub, dry-run mock, active-local validation, and optional GPT-4.1-mini ablation scaffolding. Active validation was restricted to `127.0.0.1:5005`, used non-destructive deterministic evidence markers, and abstained when authentication, multi-step state, or unavailable runtime context was required.",
                "",
                f"In active-local mode, Heimdall produced TP={active.get('tp', 0)}, FP={active.get('fp', 0)}, TN={active.get('tn', 0)}, FN={active.get('fn', 0)}, and Needs Review={active.get('manual_review', 0)} with F1={active.get('f1_score', 0):.4f}, coverage={active.get('coverage', 0):.4f}, and utility={active.get('utility_score', 0):.4f}.",
                "",
                "The result should be read as selective local validation evidence, not broad real-world exploit coverage.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (report_dir / "safety_audit.md").write_text(
        "\n".join(
            [
                "# Safety Audit",
                "",
                "- Active validation targets are restricted to localhost / 127.0.0.1.",
                "- The local lab application listens on `127.0.0.1:5005` only.",
                "- No public IPs, production domains, third-party systems, or real secrets are scanned.",
                "- Payloads are deterministic fixture probes and do not execute destructive actions.",
                "- Unsupported alerts and alerts requiring authentication/state are routed to Needs Review.",
                "- Default configuration keeps mock LLM and safety-first controls enabled.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (report_dir / "limitations.md").write_text(
        "\n".join(
            [
                "# Limitations",
                "",
                "- The benchmark is synthetic and measures controlled behavior, not broad real-world vulnerability discovery.",
                "- Active-local validation covers localhost fixtures and cannot generalize to production systems without explicit authorization and additional controls.",
                "- Mock LLM behavior makes the experiment reproducible but does not measure commercial LLM variance.",
                "- Optional GPT-4.1-mini ablation is scaffolded but not run without explicit API configuration.",
                "- Bootstrap confidence intervals are computed over synthetic/local fixtures; they do not remove benchmark construction bias.",
                "- Needs Review cases are intentional abstentions; they reduce automation coverage while preserving safety.",
                "- The paper still needs human review for academic framing, statistical validity, and citation completeness.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (report_dir / "reproducibility.md").write_text(
        "\n".join(
            [
                "# Reproducibility",
                "",
                "Run the complete workflow from the repository root:",
                "",
                "```bash",
                "bash scripts/run_ieee_final_evaluation.sh",
                "```",
                "",
                "Inputs are generated with seed 42. The active-local Flask lab is started on `127.0.0.1:5005`, health checked, used for validation, and stopped by the runner.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def table_style() -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 6.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
        ]
    )


def build_pdf(pdf_path: Path, summary: dict, dataset: dict, metric_rows: list[dict], coverage: list[dict], category_metric_rows: list[dict], chart_paths: list[Path], commit_hash: str) -> None:
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(pdf_path), pagesize=landscape(letter), rightMargin=34, leftMargin=34, topMargin=32, bottomMargin=32)
    story = []
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph("Heimdall V2 IEEE Final Evaluation Report", styles["Title"]))
    story.append(Paragraph(f"Generated: {generated_at}", styles["Normal"]))
    story.append(Paragraph(f"Repository commit: {commit_hash}", styles["Normal"]))
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph("Dataset Summary", styles["Heading2"]))
    story.append(Paragraph(
        f"The benchmark contains {dataset['total_alerts']} alerts: {dataset.get('synthetic_alerts', 300)} synthetic SAST alerts plus {dataset['active_local_fixtures']} localhost active-validation fixtures. All targets are synthetic, local, or dry-run/mock. This report is not a production security assessment and does not claim real-world exploit coverage.",
        styles["BodyText"],
    ))
    story.append(Spacer(1, 0.1 * inch))
    class_rows = [["Class", "Count"]] + [[key, str(value)] for key, value in dataset["ground_truth_labels"].items()]
    category_rows = [["Category", "Count"]] + [[key, str(value)] for key, value in dataset["categories"].items()]
    for title, rows in [("Class Distribution", class_rows), ("Vulnerability Category Distribution", category_rows)]:
        story.append(Paragraph(title, styles["Heading3"]))
        table = Table(rows, hAlign="LEFT")
        table.setStyle(table_style())
        story.append(table)
        story.append(Spacer(1, 0.12 * inch))

    story.append(PageBreak())
    story.append(Paragraph("Evaluation Modes and Metrics", styles["Heading2"]))
    fields = ["mode", "accuracy", "precision", "recall", "f1_score", "false_positive_reduction_rate", "manual_review_rate", "tp", "fp", "tn", "fn", "needs_review"]
    table = Table([fields] + [[str(row[field]) for field in fields] for row in metric_rows], repeatRows=1)
    table.setStyle(table_style())
    story.append(table)
    story.append(Spacer(1, 0.15 * inch))
    cov_fields = ["mode", "coverage", "coverage_ci95_low", "coverage_ci95_high", "decision_rate", "abstention_rate", "selective_precision", "selective_recall", "utility_score"]
    cov_table = Table([cov_fields] + [[str(row[field]) for field in cov_fields] for row in coverage], repeatRows=1)
    cov_table.setStyle(table_style())
    story.append(cov_table)
    story.append(PageBreak())
    story.append(Paragraph("Category-Level Analysis", styles["Heading2"]))
    cat_fields = ["vulnerability_type", "category_coverage", "category_abstention_rate", "category_TP", "category_FP", "category_TN", "category_FN", "category_NeedsReview"]
    active_category_rows = [row for row in category_metric_rows if row["mode"] == "heimdall_active_local_validation"]
    cat_table = Table([cat_fields] + [[str(row[field]) for field in cat_fields] for row in active_category_rows], repeatRows=1)
    cat_table.setStyle(table_style())
    story.append(cat_table)

    story.append(PageBreak())
    story.append(Paragraph("Charts", styles["Heading2"]))
    for index, chart in enumerate(chart_paths):
        story.append(Image(str(chart), width=8.8 * inch, height=4.95 * inch))
        if index != len(chart_paths) - 1:
            story.append(PageBreak())
        else:
            story.append(Spacer(1, 0.12 * inch))

    story.append(PageBreak())
    story.append(Paragraph("Safety Assumptions", styles["Heading2"]))
    story.append(Paragraph(
        "The evaluation uses synthetic alerts, mock LLM behavior, dry-run modes, and an explicitly allowlisted localhost Flask lab for active validation. No external network validation is performed. Unsupported, unsafe, authentication-dependent, or context-dependent alerts are routed to Needs Review instead of forcing a risky decision.",
        styles["BodyText"],
    ))
    story.append(Paragraph("Limitations", styles["Heading2"]))
    story.append(Paragraph(
        "The dataset is controlled and synthetic; it should be treated as reproducibility evidence and a safety demonstration, not as proof of real-world exploit coverage. A publication submission still requires manual literature review, statistical framing, optional real LLM ablation, and validation against additional authorized benchmarks.",
        styles["BodyText"],
    ))
    story.append(Paragraph("IEEE-Paper-Ready Paragraph", styles["Heading2"]))
    story.append(Paragraph(
        f"We evaluated Heimdall V2 on a reproducible {dataset['total_alerts']}-alert benchmark combining {dataset.get('synthetic_alerts', 300)} labeled synthetic SAST alerts with {dataset['active_local_fixtures']} localhost-only active validation fixtures across twelve vulnerability classes. The framework compared SAST-only, rule-based, LLM-only, dry-run, full-pipeline, active-local validation, and optional GPT-4.1-mini ablation scaffolding while enforcing a safety policy that blocks external targets and abstains on authentication- or workflow-dependent cases. The resulting metrics quantify the trade-off among precision, recall, false-positive reduction, coverage, and manual review burden, providing controlled evidence for a safety-first selective validation workflow.",
        styles["BodyText"],
    ))
    doc.build(story)


def write_paper_files(report_dir: Path, metric_rows: list[dict], coverage_rows_data: list[dict], category_metric_rows: list[dict], dataset: dict, commit_hash: str) -> None:
    PAPER_DIR.mkdir(parents=True, exist_ok=True)
    (PAPER_DIR / "figures").mkdir(parents=True, exist_ok=True)
    (PAPER_DIR / "tables").mkdir(parents=True, exist_ok=True)
    for fig in report_dir.glob("fig_*.png"):
        shutil.copy2(fig, PAPER_DIR / "figures" / fig.name)
    shutil.copy2(report_dir / "metrics_by_mode.csv", PAPER_DIR / "tables" / "metrics_by_mode.csv")
    shutil.copy2(report_dir / "coverage_metrics.csv", PAPER_DIR / "tables" / "coverage_metrics.csv")
    shutil.copy2(report_dir / "category_metrics.csv", PAPER_DIR / "tables" / "category_metrics.csv")
    table_md = markdown_table(metric_rows, ["mode", "accuracy", "precision", "recall", "f1_score", "false_positive_reduction_rate", "manual_review_rate"])
    coverage_md = markdown_table(coverage_rows_data, ["mode", "coverage", "abstention_rate", "selective_precision", "selective_recall", "utility_score"])
    category_md = markdown_table(
        [row for row in category_metric_rows if row["mode"] == "heimdall_active_local_validation"],
        ["vulnerability_type", "category_coverage", "category_abstention_rate", "category_TP", "category_TN", "category_NeedsReview"],
    )
    paper_md = f"""# Heimdall V2: Safety-First Selective Validation for Reducing SAST False Positives in DevSecOps Pipelines

## Abstract

Heimdall V2 is a safety-first DevSecOps research prototype for reducing SAST false positives through selective validation. The framework combines static alert ingestion, mockable LLM reasoning, safety-gated payload hypotheses, and deterministic localhost-only DAST evidence checks. The final benchmark contains {dataset['total_alerts']} alerts: {dataset.get('synthetic_alerts', 300)} synthetic SAST alerts and {dataset['active_local_fixtures']} active-local fixtures. The paper reports conventional and coverage-aware metrics and treats Needs Review as an intentional abstention, not a failure to hide uncertainty.

## 1. Introduction

SAST tools are useful early-warning systems, but alert volume and false positives can slow developer adoption. Heimdall V2 explores a selective validation workflow that confirms or dismisses only findings with controlled local evidence and routes the rest to manual review.

## 2. Background and Motivation

The project is motivated by SAST false positives, missing runtime context, and the risks of allowing LLMs to make unsupported security decisions. The system therefore separates LLM hypothesis generation from final evidence-based decisions.

## 3. Related Work

Related work spans static analysis for security, dynamic web testing, hybrid validation, DevSecOps, LLM vulnerability reasoning, prompt-injection risks, and human-in-the-loop triage. Notes and BibTeX entries are in `paper/related_work_notes.md` and `paper/references.bib`.

## 4. System Design

The pipeline ingests SAST alerts, extracts context, applies deterministic or optional LLM reasoning, generates non-destructive validation hypotheses, enforces a localhost-only safety gate, analyzes controlled evidence markers, and emits CI/reporting decisions.

## 5. Threat Model and Safety Model

The evaluation does not scan real websites, production domains, public IPs, or third-party systems. Active validation is restricted to `127.0.0.1:5005` and `localhost:5005`; external redirects are inspected but not followed. Real secrets, destructive payloads, and real authentication bypass are out of scope.

## 6. Implementation

The implementation includes a Flask local lab with controlled endpoints for twelve vulnerability categories, a JSONL benchmark loader, evaluation modes, active-local response analysis, bootstrap metrics, PDF reporting, and an optional GPT-4.1-mini ablation scaffold that skips cleanly without API keys.

## Method

## 7. Evaluation Methodology

The evaluation compares SAST-only, rule-based filtering, LLM-only stub, Heimdall full-pipeline stub, Heimdall dry-run mock, Heimdall active-local validation, and optional GPT-4.1-mini ablation scaffolding. The active-local mode validates only fixture-backed alerts and abstains on unsupported or context-dependent cases.

## Results

### Main Metrics

{table_md}

### Coverage-Aware Metrics

{coverage_md}

### Active-Local Category Metrics

{category_md}

## 8. Discussion

The active-local mode improves coverage over the previous 60-fixture run while keeping broad synthetic alerts in Needs Review. High-coverage categories are those with deterministic local evidence markers, such as SQL Injection simulation, XSS reflection, Path Traversal fixture access, Open Redirect header inspection, Command Injection simulation, Hardcoded Secret fixture, and Weak Crypto marker checks. Context-heavy categories retain higher abstention.

## 9. Limitations and Future Work

This benchmark is synthetic and local-only. It is appropriate for reproducibility evidence and safety framing, not for claiming production readiness or real-world exploit coverage. Future work should add authorized external benchmarks, real LLM ablations, stronger statistical design, and human triage studies.

## 10. Conclusion

Heimdall V2 demonstrates a safety-first selective validation pattern for SAST triage. Its strongest claim is not universal vulnerability detection, but disciplined handling of uncertainty: confirm when controlled evidence exists, dismiss when defensive behavior is observed, and abstain when validation would require unsafe or unavailable context.

## Acknowledgment

Acknowledgment placeholder for non-anonymous version.

## Reproducibility

Run `bash scripts/run_ieee_final_evaluation.sh` from the repository root. Commit used for this generated draft: `{commit_hash}`.
"""
    (PAPER_DIR / "HeimdallV2_IEEE_Final.md").write_text(paper_md, encoding="utf-8")
    anonymous_md = paper_md.replace("Acknowledgment placeholder for non-anonymous version.", "Acknowledgment removed for anonymous review.")
    anonymous_md = anonymous_md.replace(f"Commit used for this generated draft: `{commit_hash}`.", "Commit hash omitted for anonymous review.")
    (PAPER_DIR / "HeimdallV2_IEEE_Final_Anonymous.md").write_text(anonymous_md, encoding="utf-8")
    tex_table = "\n".join(
        f"{_tex_escape(row['mode'])} & {row['precision']} & {row['recall']} & {row['f1_score']} & {row['manual_review_rate']} \\\\"
        for row in metric_rows
    )
    tex = rf"""\documentclass[conference]{{IEEEtran}}
\usepackage{{graphicx}}
\usepackage{{booktabs}}
\title{{Heimdall V2: Safety-First Selective Validation for Reducing SAST False Positives in DevSecOps Pipelines}}
\author{{Author Placeholder}}
\begin{{document}}
\maketitle
\begin{{abstract}}
This paper evaluates Heimdall V2 on a reproducible {dataset['total_alerts']}-alert benchmark combining synthetic SAST findings with localhost-only active validation fixtures. The framework uses selective validation and intentional abstention to reduce unsupported true/false-positive claims.
\end{{abstract}}
\section{{Introduction}}
Static Application Security Testing can produce high alert volume and false positives. Heimdall V2 investigates a safety-first selective validation workflow.
\section{{Threat Model and Safety Model}}
No public websites, production domains, public IPs, real secrets, destructive payloads, or third-party systems are used. Active validation is restricted to localhost fixtures.
\section{{Evaluation Methodology}}
The benchmark compares SAST-only, rule-based filtering, LLM-only stub, full-pipeline stub, dry-run mock, active-local validation, and optional GPT-4.1-mini ablation scaffolding.
\section{{Results}}
\begin{{table}}[h]
\centering
\caption{{Main metrics by mode}}
\begin{{tabular}}{{lrrrr}}
\toprule
Mode & Precision & Recall & F1 & Review \\
\midrule
{tex_table}
\bottomrule
\end{{tabular}}
\end{{table}}
\section{{Discussion and Limitations}}
Results are controlled prototype evidence, not real-world exploit coverage. Needs Review represents intentional abstention for unsafe or unavailable runtime context.
\section{{Conclusion}}
Heimdall V2 shows that a safety-first selective validation workflow can report stronger precision on decided cases while honestly exposing coverage and abstention.
\bibliographystyle{{IEEEtran}}
\bibliography{{references}}
\end{{document}}
"""
    (PAPER_DIR / "HeimdallV2_IEEE_Final.tex").write_text(tex, encoding="utf-8")
    (PAPER_DIR / "HeimdallV2_IEEE_Final_Anonymous.tex").write_text(tex.replace("\\author{Author Placeholder}", "\\author{Anonymous Authors}"), encoding="utf-8")
    build_paper_pdf(PAPER_DIR / "HeimdallV2_IEEE_Final.pdf", "Heimdall V2 IEEE Final Draft", paper_md)
    build_paper_pdf(PAPER_DIR / "HeimdallV2_IEEE_Final_Anonymous.pdf", "Heimdall V2 IEEE Final Draft (Anonymous)", paper_md.replace("Acknowledgment placeholder for non-anonymous version.", "Acknowledgment removed for anonymous review."))
    (PAPER_DIR / "llm_ablation_plan.md").write_text(
        "\n".join(
            [
                "# GPT-4.1-mini Ablation Plan",
                "",
                "Default runs do not call external APIs. To run an authorized ablation, set:",
                "",
                "```bash",
                "export HEIMDALL_ENABLE_REAL_LLM=1",
                "export OPENAI_API_KEY=...",
                "export HEIMDALL_LLM_MODEL=gpt-4.1-mini",
                "```",
                "",
                "Record model, timestamp, prompt template hash, temperature, number of runs, latency, token usage, approximate cost, and output variance. The LLM may suggest validation hypotheses only; localhost evidence and the decision engine must still make the final decision.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (PAPER_DIR / "related_work_notes.md").write_text(
        "\n".join(
            [
                "# Related Work Notes",
                "",
                "## 1. Static analysis and false positives",
                "- Chess and McGraw discuss static analysis for security and the role of tooling in finding defects before runtime.",
                "- Livshits and Lam show static analysis applied to finding Java application vulnerabilities.",
                "",
                "## 2. Dynamic testing and runtime validation",
                "- Doupé, Cova, and Vigna evaluate black-box web vulnerability scanners, providing context for runtime validation limits.",
                "",
                "## 3. Hybrid SAST/DAST workflows",
                "- Use search query: `hybrid static dynamic analysis vulnerability validation web applications empirical` to expand the final literature review.",
                "",
                "## 4. LLM-assisted vulnerability reasoning",
                "- Pearce et al. evaluate security implications of AI code generation; this motivates caution when using LLMs for security tooling.",
                "- Use search query: `large language models vulnerability detection repair survey software security` for newer benchmark papers before submission.",
                "",
                "## 5. Safety risks of LLM security tools",
                "- Greshake et al. study indirect prompt injection against LLM-integrated applications; Heimdall separates LLM hypotheses from evidence-based decisions.",
                "",
                "## 6. DevSecOps and CI/CD security",
                "- Use search query: `DevSecOps empirical study CI/CD security SAST DAST` to add recent empirical DevSecOps references.",
                "",
                "## 7. Human-in-the-loop triage",
                "- Heimdall treats Needs Review as a first-class outcome for cases requiring authentication, workflow state, or human judgment.",
                "",
                "## 8. Software supply-chain security",
                "- Ohm et al. review open-source software supply-chain attacks, motivating CI/CD safety controls and cautious dependency handling.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (PAPER_DIR / "references.bib").write_text(
        "\n".join(
            [
                "@inproceedings{chess2004static,",
                "  title={Static Analysis for Security},",
                "  author={Chess, Brian and McGraw, Gary},",
                "  booktitle={IEEE Security \\& Privacy},",
                "  year={2004}",
                "}",
                "",
                "@inproceedings{livshits2005finding,",
                "  title={Finding Security Vulnerabilities in Java Applications with Static Analysis},",
                "  author={Livshits, Benjamin and Lam, Monica S.},",
                "  booktitle={USENIX Security Symposium},",
                "  year={2005}",
                "}",
                "",
                "@inproceedings{doupe2010johnny,",
                "  title={Why Johnny Can't Pentest: An Analysis of Black-box Web Vulnerability Scanners},",
                "  author={Doup\\'e, Adam and Cova, Marco and Vigna, Giovanni},",
                "  booktitle={Detection of Intrusions and Malware, and Vulnerability Assessment},",
                "  year={2010}",
                "}",
                "",
                "@inproceedings{pearce2022asleep,",
                "  title={Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions},",
                "  author={Pearce, Hammond and Ahmad, Baleegh and Tan, Benjamin and Dolan-Gavitt, Brendan and Karri, Ramesh},",
                "  booktitle={IEEE Symposium on Security and Privacy},",
                "  year={2022}",
                "}",
                "",
                "@inproceedings{greshake2023not,",
                "  title={Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection},",
                "  author={Greshake, Kai and Abdelnabi, Sahar and Mishra, Shailesh and Endres, Christoph and Holz, Thorsten and Fritz, Mario},",
                "  booktitle={ACM Workshop on Artificial Intelligence and Security},",
                "  year={2023}",
                "}",
                "",
                "@inproceedings{ohm2020backstabbers,",
                "  title={Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks},",
                "  author={Ohm, Marc and Plate, Henrik and Sykosch, Arnold and Meier, Michael},",
                "  booktitle={Detection of Intrusions and Malware, and Vulnerability Assessment},",
                "  year={2020}",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )


def build_paper_pdf(path: Path, title: str, paper_md: str) -> None:
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path), pagesize=letter, rightMargin=54, leftMargin=54, topMargin=54, bottomMargin=54)
    story = [Paragraph(title, styles["Title"]), Spacer(1, 0.15 * inch)]
    for raw in paper_md.splitlines():
        line = raw.strip()
        if not line:
            story.append(Spacer(1, 0.08 * inch))
        elif line.startswith("# "):
            story.append(Paragraph(html.escape(line[2:]), styles["Title"]))
        elif line.startswith("## "):
            story.append(Paragraph(html.escape(line[3:]), styles["Heading2"]))
        elif line.startswith("### "):
            story.append(Paragraph(html.escape(line[4:]), styles["Heading3"]))
        elif line.startswith("|"):
            continue
        else:
            story.append(Paragraph(html.escape(line), styles["BodyText"]))
    doc.build(story)


def _tex_escape(value: str) -> str:
    return str(value).replace("_", "\\_").replace("&", "\\&")


def write_repro_readme(root: Path) -> None:
    (root / "README_IEEE_REPRODUCIBILITY.md").write_text(
        "\n".join(
            [
                "# Heimdall V2 IEEE Reproducibility",
                "",
                "This repository includes a local-only, safety-first evaluation workflow for the Heimdall V2 prototype. It is not a production scanner and does not provide real-world exploit coverage.",
                "",
                "## Safety Warning",
                "",
                "Do not point this workflow at real websites, public IPs, production domains, third-party systems, or real secrets. Active validation is restricted to `127.0.0.1:5005` and `localhost:5005`.",
                "",
                "## Environment Setup",
                "",
                "- Python: 3.11+ recommended; tested with Python 3.12 in WSL.",
                "- Dependencies: `semgrep`, `pytest`, `flask`, `Pillow`, `reportlab`.",
                "- The runner creates/uses `.heimdall_eval_venv` if dependencies are missing.",
                "",
                "## One-command run",
                "",
                "```bash",
                "bash scripts/run_ieee_final_evaluation.sh",
                "```",
                "",
                "## Manual Steps Performed By The Runner",
                "",
                "1. Generate the 300-alert synthetic dataset.",
                "2. Generate the expanded 180-alert active-local dataset.",
                "3. Generate the combined 480-alert final dataset.",
                "4. Start the Flask lab on `127.0.0.1:5005`.",
                "5. Wait for `/health`.",
                "6. Validate safety configuration.",
                "7. Run all evaluation modes.",
                "8. Generate CSV, JSON, Markdown, charts, PDF, and paper artifacts.",
                "9. Stop the local lab.",
                "10. Run `pytest`.",
                "",
                "## Key outputs",
                "",
                "- `reports/ieee_final_eval/HeimdallV2_IEEE_Final_Evaluation_Report.pdf`",
                "- `reports/ieee_final_eval/metrics_by_mode.csv`",
                "- `reports/ieee_final_eval/coverage_metrics.csv`",
                "- `reports/ieee_final_eval/category_metrics.csv`",
                "- `reports/ieee_final_eval/paper_ready_summary.md`",
                "- `paper/HeimdallV2_IEEE_Final.md`",
                "- `paper/HeimdallV2_IEEE_Final.tex`",
                "- `paper/HeimdallV2_IEEE_Final_Anonymous.tex`",
                "",
                "## Optional Real LLM Ablation",
                "",
                "Leave disabled for reproducibility. To run only in an authorized environment:",
                "",
                "```bash",
                "export HEIMDALL_ENABLE_REAL_LLM=1",
                "export OPENAI_API_KEY=...",
                "export HEIMDALL_LLM_MODEL=gpt-4.1-mini",
                "```",
                "",
                "Without those variables, the ablation mode skips cleanly and writes a not-run note.",
                "",
                "## Verify No External Targets",
                "",
                "Inspect `reports/ieee_final_eval/safety_audit.md` and run `pytest tests/test_no_external_targets.py tests/test_active_validation_safety_policy.py`.",
                "",
                "## Troubleshooting",
                "",
                "- If `/health` fails, stop any process using port 5005 and rerun the one-command script.",
                "- If PDF generation fails, install `Pillow` and `reportlab` in the active Python environment.",
                "- If tests fail, read the exact pytest error and rerun `python3 -m pytest -x` after fixing only workflow-related issues.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate IEEE-ready Heimdall evaluation reports.")
    parser.add_argument("--dataset", default="test_data/heimdall_combined_ieee_alerts.jsonl")
    parser.add_argument("--report-dir", default=str(REPORT_DIR))
    args = parser.parse_args()
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    summary = read_json(report_dir / "summary.json")
    results = read_csv(report_dir / "results.csv")
    alerts = read_jsonl(Path(args.dataset))
    commit_hash = git_commit_hash()
    dataset = dataset_summary(alerts)
    ci_by_mode = bootstrap_intervals(results)
    metrics = metrics_rows(summary)
    coverage = coverage_rows(summary, ci_by_mode)
    confusion = confusion_rows(summary)
    categories = category_breakdown(results)
    category_metric_rows = category_metrics(results)
    write_csv(report_dir / "metrics_by_mode.csv", metrics)
    write_csv(report_dir / "coverage_metrics.csv", coverage)
    write_csv(report_dir / "confusion_matrices.csv", confusion)
    write_csv(report_dir / "category_breakdown.csv", categories)
    write_csv(report_dir / "category_metrics.csv", category_metric_rows)
    write_results_json(report_dir / "results.json", summary, results, dataset, commit_hash)
    chart_paths = create_charts(summary, confusion, categories, category_metric_rows, report_dir)
    write_evidence_examples(report_dir / "evidence_examples.md", results)
    write_llm_ablation_status(report_dir / "llm_ablation_status.md", results)
    write_markdown_outputs(report_dir, summary, dataset, metrics, coverage, category_metric_rows, commit_hash)
    build_pdf(report_dir / PDF_NAME, summary, dataset, metrics, coverage, category_metric_rows, chart_paths, commit_hash)
    write_paper_files(report_dir, metrics, coverage, category_metric_rows, dataset, commit_hash)
    write_repro_readme(Path.cwd())
    print(f"Wrote IEEE final PDF to {report_dir / PDF_NAME}")
    print(f"Wrote paper draft to {PAPER_DIR / 'HeimdallV2_IEEE_Final.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
