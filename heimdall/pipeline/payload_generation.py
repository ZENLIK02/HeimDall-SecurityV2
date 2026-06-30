from __future__ import annotations

from .models import AlertContext, ValidationPayload


def generate_safe_payloads(context: AlertContext) -> list[ValidationPayload]:
    vuln = context.vulnerability_type.lower()
    endpoint = context.endpoint or "/"
    method = context.method or "GET"

    if "xss" in vuln:
        return [
            ValidationPayload(
                context.vulnerability_type,
                method,
                endpoint,
                parameters={"q": "heimdall_xss_probe"},
                expected_evidence="heimdall_xss_probe reflected in response",
                safety_notes=["No script execution payload is used."],
            )
        ]
    if "sql" in vuln:
        return [
            ValidationPayload(
                context.vulnerability_type,
                method,
                endpoint,
                parameters={"username": "' OR '1'='1", "password": "heimdall-test"},
                expected_evidence="SQL error or authentication behavior change",
                safety_notes=["Read-only login-style probe; no data modification."],
            )
        ]
    if "command" in vuln:
        return [
            ValidationPayload(
                context.vulnerability_type,
                method,
                endpoint,
                parameters={"host": "127.0.0.1; echo HEIMDALL_CMD_PROBE"},
                expected_evidence="HEIMDALL_CMD_PROBE marker in response",
                safety_notes=["Echo marker only; no destructive command."],
            )
        ]
    if "path traversal" in vuln:
        return [
            ValidationPayload(
                context.vulnerability_type,
                method,
                endpoint,
                parameters={"file": "../README.md"},
                expected_evidence="controlled README marker or traversal block",
                safety_notes=["Only requests repository documentation placeholder."],
            )
        ]
    if "ssrf" in vuln:
        return [
            ValidationPayload(
                context.vulnerability_type,
                method,
                endpoint,
                parameters={"url": "http://127.0.0.1:9/heimdall-ssrf-probe"},
                expected_evidence="controlled local callback placeholder",
                safety_notes=["Local non-routable test endpoint only."],
            )
        ]
    if "idor" in vuln or "access control" in vuln:
        return [
            ValidationPayload(
                context.vulnerability_type,
                method,
                endpoint,
                parameters={"id": "baseline-owned-object", "alternate_id": "other-user-object"},
                expected_evidence="unauthorized object returned",
                safety_notes=["Requires synthetic auth context; do not use real accounts."],
            )
        ]
    if "business logic" in vuln:
        return [
            ValidationPayload(
                context.vulnerability_type,
                method,
                endpoint,
                parameters={"step": "dry-run-multi-step-placeholder"},
                expected_evidence="multi-step state transition inconsistency",
                safety_notes=["Dry-run only; business logic validation requires scenario harness."],
            )
        ]

    return [
        ValidationPayload(
            context.vulnerability_type,
            method,
            endpoint,
            parameters={"probe": "heimdall_safe_probe"},
            expected_evidence="generic controlled marker",
            safety_notes=["Generic non-destructive probe."],
        )
    ]

