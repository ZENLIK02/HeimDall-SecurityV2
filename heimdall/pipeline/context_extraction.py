from __future__ import annotations

from heimdall.evaluation.models import Alert

from .models import AlertContext


def extract_context(alert: Alert) -> AlertContext:
    return AlertContext(
        alert_id=alert.alert_id,
        vulnerability_type=alert.vulnerability_type,
        severity=alert.severity,
        file_path=alert.file_path,
        line_number=alert.line_number,
        code_snippet=alert.code_snippet,
        endpoint=alert.endpoint,
        method=alert.method,
        parameters=dict(alert.parameters),
        sast_message=alert.sast_message,
        notes=alert.notes,
    )

