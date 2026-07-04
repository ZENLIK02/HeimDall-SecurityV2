from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Alert


REQUIRED_FIELDS = {
    "alert_id",
    "vulnerability_type",
    "severity",
    "file_path",
    "line_number",
    "code_snippet",
    "endpoint",
    "method",
    "parameters",
    "sast_message",
    "ground_truth_label",
    "notes",
}

TRUE_LABELS = {"true", "tp", "true_positive", "real", "confirmed", "vulnerable"}
FALSE_LABELS = {"false", "fp", "false_positive", "benign", "not_vulnerable", "dismissed"}


class DatasetValidationError(ValueError):
    """Raised when a dataset cannot be safely loaded."""


def normalize_label(value: Any) -> str:
    normalized = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in TRUE_LABELS:
        return "true_positive"
    if normalized in FALSE_LABELS:
        return "false_positive"
    raise DatasetValidationError(f"Unsupported ground_truth_label: {value!r}")


def _validate_row(row: dict[str, Any], line_number: int) -> Alert:
    row = dict(row)
    if "sast_message" not in row and "message" in row:
        row["sast_message"] = row["message"]
    if "endpoint" not in row and "endpoint_hint" in row:
        row["endpoint"] = row["endpoint_hint"]
    missing = sorted(REQUIRED_FIELDS - set(row))
    if missing:
        raise DatasetValidationError(f"Line {line_number}: missing required fields: {', '.join(missing)}")

    parameters = row["parameters"]
    if parameters is None:
        parameters = {}
    if not isinstance(parameters, dict):
        raise DatasetValidationError(f"Line {line_number}: parameters must be an object")

    try:
        alert_line = int(row["line_number"])
    except (TypeError, ValueError) as exc:
        raise DatasetValidationError(f"Line {line_number}: line_number must be an integer") from exc

    metadata = {key: value for key, value in row.items() if key not in REQUIRED_FIELDS}

    return Alert(
        alert_id=str(row["alert_id"]),
        vulnerability_type=str(row["vulnerability_type"]),
        severity=str(row["severity"]).lower(),
        file_path=str(row["file_path"]),
        line_number=alert_line,
        code_snippet=str(row["code_snippet"]),
        endpoint=str(row["endpoint"]),
        method=str(row["method"]).upper(),
        parameters=parameters,
        sast_message=str(row["sast_message"]),
        ground_truth_label=normalize_label(row["ground_truth_label"]),
        notes=str(row["notes"]),
        metadata=metadata,
    )


def load_alerts_jsonl(path: str | Path, *, strict: bool = False) -> tuple[list[Alert], list[str]]:
    """Load labeled SAST alerts from JSONL.

    Malformed rows are collected as warnings by default. Set strict=True to raise
    immediately on the first malformed row.
    """
    dataset_path = Path(path)
    alerts: list[Alert] = []
    warnings: list[str] = []

    with dataset_path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise DatasetValidationError(f"Line {line_number}: row must be a JSON object")
                alerts.append(_validate_row(row, line_number))
            except (json.JSONDecodeError, DatasetValidationError) as exc:
                message = str(exc)
                if strict:
                    raise DatasetValidationError(message) from exc
                warnings.append(message)

    return alerts, warnings

