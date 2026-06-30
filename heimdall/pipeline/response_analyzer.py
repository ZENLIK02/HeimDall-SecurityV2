from __future__ import annotations

from .models import DastResult, ResponseAnalysis, ValidationPayload


def analyze_response(payload: ValidationPayload, result: DastResult) -> ResponseAnalysis:
    if result.status == "blocked":
        return ResponseAnalysis("inconclusive", result.blocked_reason or "Validation blocked by safety policy.", 0.70)
    if result.status == "inconclusive":
        return ResponseAnalysis("inconclusive", result.response_body or "No decisive evidence.", 0.45)

    body = (result.response_body or "").lower()
    vuln = payload.vulnerability_type.lower()

    if "xss" in vuln:
        if "<script" in body or "onerror=" in body:
            return ResponseAnalysis("confirmed", "Reflected executable XSS marker found.", 0.86)
        if "heimdall_xss_probe" in body:
            return ResponseAnalysis("not_confirmed", "Controlled marker appears escaped or inert.", 0.72)

    if "sql" in vuln:
        if any(marker in body for marker in ("sql syntax", "sqlite", "mysql", "postgres", "odbc")):
            return ResponseAnalysis("confirmed", "SQL error marker found.", 0.84)
        if result.status_code in {400, 401, 403}:
            return ResponseAnalysis("not_confirmed", "Input rejected or authentication failed without SQL error.", 0.70)

    if "command" in vuln:
        if "heimdall_cmd_probe" in body:
            return ResponseAnalysis("confirmed", "Command marker found in response.", 0.90)
        if result.status_code in {400, 403}:
            return ResponseAnalysis("not_confirmed", "Command probe rejected by validation.", 0.70)

    if "path traversal" in vuln:
        if "root:" in body or "heimdall traversal marker" in body:
            return ResponseAnalysis("confirmed", "Traversal marker found.", 0.86)
        if result.status_code in {400, 403, 404}:
            return ResponseAnalysis("not_confirmed", "Traversal probe blocked or missing.", 0.68)

    if "ssrf" in vuln:
        if "ssrf callback received" in body or "controlled internal response" in body:
            return ResponseAnalysis("confirmed", "Controlled SSRF callback evidence found.", 0.84)
        return ResponseAnalysis("inconclusive", "No controlled SSRF callback evidence.", 0.45)

    if "idor" in vuln or "access control" in vuln:
        if "other-user-object" in body or "unauthorized object" in body:
            return ResponseAnalysis("confirmed", "Unauthorized object access evidence found.", 0.85)
        return ResponseAnalysis("inconclusive", "Access control validation requires authentication context.", 0.42)

    if "business logic" in vuln:
        return ResponseAnalysis("inconclusive", "Business logic requires multi-step state validation.", 0.40)

    return ResponseAnalysis("inconclusive", "Unsupported or ambiguous response.", 0.35)

