from __future__ import annotations

import json
from urllib import error, parse, request

from .models import DastConfig, DastResult, ValidationPayload
from .safety import SafetyController


class SafeDastExecutor:
    def __init__(self, config: DastConfig | None = None):
        self.config = config or DastConfig()
        self.safety = SafetyController(self.config)

    def execute(self, payload: ValidationPayload) -> DastResult:
        url = self.safety.build_url(payload.endpoint)
        target_ok, target_reason = self.safety.validate_target(url)
        payload_ok, payload_reason = self.safety.validate_payload(payload)
        blocked_reason = target_reason or payload_reason

        if blocked_reason:
            self.safety.log_request(payload, url, blocked_reason)
            return DastResult(
                status="blocked",
                request_log=list(self.safety.request_log),
                blocked_reason=blocked_reason,
                dry_run=self.config.dry_run,
            )

        self.safety.rate_limit()
        self.safety.log_request(payload, url)

        if self.config.dry_run:
            return _dry_run_result(payload, list(self.safety.request_log))

        try:
            response = _send_request(payload, url, self.config.timeout_seconds)
        except OSError as exc:
            return DastResult(
                status="inconclusive",
                response_body=str(exc),
                request_log=list(self.safety.request_log),
                dry_run=False,
            )

        return DastResult(
            status="inconclusive",
            status_code=response["status_code"],
            response_body=response["body"][:2000],
            response_headers=response["headers"],
            request_log=list(self.safety.request_log),
            dry_run=False,
        )


def _dry_run_result(payload: ValidationPayload, request_log: list[dict]) -> DastResult:
    vuln = payload.vulnerability_type.lower()
    params = str(payload.parameters).lower()
    if "business logic" in vuln or "idor" in vuln or "access control" in vuln:
        return DastResult("inconclusive", 200, "dry-run requires authentication or multi-step state", request_log=request_log, dry_run=True)
    if "ssrf" in vuln and "127.0.0.1" in params:
        return DastResult("inconclusive", 200, "dry-run SSRF callback placeholder not executed", request_log=request_log, dry_run=True)
    if "xss" in vuln:
        return DastResult("not_confirmed", 200, "escaped response contains heimdall_xss_probe", request_log=request_log, dry_run=True)
    if "sql" in vuln:
        return DastResult("not_confirmed", 400, "Invalid username format", request_log=request_log, dry_run=True)
    if "command" in vuln:
        return DastResult("not_confirmed", 400, "Invalid host format", request_log=request_log, dry_run=True)
    if "path traversal" in vuln:
        return DastResult("not_confirmed", 400, "Traversal blocked", request_log=request_log, dry_run=True)
    return DastResult("inconclusive", 200, "dry-run generic response", request_log=request_log, dry_run=True)


def _send_request(payload: ValidationPayload, url: str, timeout_seconds: float) -> dict:
    method = payload.method.upper()
    final_url = url
    data = None
    headers = {"User-Agent": "Heimdall-Safe-DAST/2.0"}

    if method == "GET" and payload.parameters:
        query = parse.urlencode(payload.parameters, doseq=True)
        separator = "&" if parse.urlparse(url).query else "?"
        final_url = f"{url}{separator}{query}"
    elif payload.body or payload.parameters:
        data = json.dumps(payload.body or payload.parameters).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = request.Request(final_url, data=data, headers=headers, method=method)
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            body = response.read(2000).decode("utf-8", errors="replace")
            return {
                "status_code": response.status,
                "body": body,
                "headers": dict(response.headers.items()),
            }
    except error.HTTPError as exc:
        body = exc.read(2000).decode("utf-8", errors="replace")
        return {
            "status_code": exc.code,
            "body": body,
            "headers": dict(exc.headers.items()),
        }
