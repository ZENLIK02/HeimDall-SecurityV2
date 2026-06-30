from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from heimdall.evaluation.models import Alert


def load_semgrep_alerts(path: str | Path) -> list[Alert]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    alerts: list[Alert] = []
    for index, finding in enumerate(data.get("results", []), start=1):
        extra = finding.get("extra", {})
        metadata = extra.get("metadata", {}) or {}
        start = finding.get("start", {}) or {}
        rule_id = finding.get("check_id") or finding.get("rule_id") or f"semgrep-{index}"
        severity = _normalize_severity(str(extra.get("severity") or finding.get("severity") or "INFO"))
        file_path = str(finding.get("path") or "")
        line_number = int(start.get("line") or 1)
        message = str(extra.get("message") or rule_id)
        snippet = _extract_snippet(finding, extra)
        vulnerability_type = _infer_vulnerability_type(rule_id, message, metadata)
        endpoint, method, parameters = _infer_request_context(vulnerability_type)
        alerts.append(
            Alert(
                alert_id=str(rule_id),
                vulnerability_type=vulnerability_type,
                severity=severity,
                file_path=file_path,
                line_number=line_number,
                code_snippet=snippet,
                endpoint=endpoint,
                method=method,
                parameters=parameters,
                sast_message=message,
                ground_truth_label="true_positive",
                notes=f"Imported from Semgrep rule {rule_id}",
            )
        )
    return alerts


def _extract_snippet(finding: dict[str, Any], extra: dict[str, Any]) -> str:
    lines = extra.get("lines")
    if isinstance(lines, str) and lines.strip():
        return lines.strip()
    metavars = extra.get("metavars") or {}
    if isinstance(metavars, dict) and metavars:
        return json.dumps(metavars, ensure_ascii=False)[:1200]
    return str(finding.get("path") or "Semgrep finding")


def _normalize_severity(value: str) -> str:
    severity = value.lower()
    return {
        "error": "high",
        "warning": "medium",
        "info": "low",
    }.get(severity, severity)


def _infer_vulnerability_type(rule_id: str, message: str, metadata: dict[str, Any]) -> str:
    text = f"{rule_id} {message} {metadata}".lower()
    if "xss" in text or "cross-site" in text:
        return "XSS"
    if "sql" in text:
        return "SQL Injection"
    if "command" in text or "subprocess" in text or "shell" in text:
        return "Command Injection"
    if "path traversal" in text or "directory traversal" in text:
        return "Path Traversal"
    if "ssrf" in text:
        return "SSRF"
    if "idor" in text or "access control" in text:
        return "Broken Access Control / IDOR"
    if "business logic" in text:
        return "Business Logic Flaw"
    cwe = str(metadata.get("cwe") or "").lower()
    if "79" in cwe:
        return "XSS"
    if "89" in cwe:
        return "SQL Injection"
    if "22" in cwe:
        return "Path Traversal"
    return "Unsupported"


def _infer_request_context(vulnerability_type: str) -> tuple[str, str, dict[str, str]]:
    vuln = vulnerability_type.lower()
    if "xss" in vuln:
        return "/xss", "GET", {"q": "heimdall_xss_probe"}
    if "sql" in vuln:
        return "/login", "POST", {"username": "alice", "password": "password"}
    if "path traversal" in vuln:
        return "/file", "GET", {"name": "readme.txt"}
    if "idor" in vuln or "access control" in vuln:
        return "/user/1", "GET", {}
    return "/", "GET", {}
