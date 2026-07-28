from __future__ import annotations

import csv
import datetime as dt
import ipaddress
import json
import math
import socket
import ssl
import sys
import tempfile
import threading
import time
from collections import Counter
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


PROJECT = Path(__file__).resolve().parents[1]
WORK_ROOT = PROJECT.parent
CONFIG = WORK_ROOT / "external_validation" / "heimdall_owasp_benchmark.yml"
RESULTS = PROJECT / "results"
SAFETY_JSON = RESULTS / "safety_gate.json"
SAFETY_CSV = RESULTS / "safety_gate.csv"

sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "scripts"))

from external_full_evaluation import verify_frozen_hashes, wilson_interval
from heimdall.config import load_config
from heimdall.evaluation.active_local import validate_alert
from heimdall.evaluation.models import Alert


class SafetyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    counts: Counter[str] = Counter()
    counts_lock = threading.Lock()

    def _record(self) -> None:
        with self.counts_lock:
            self.counts[self.path.split("?", 1)[0]] += 1

    def do_GET(self) -> None:  # noqa: N802
        self._record()
        path = self.path.split("?", 1)[0]
        if path == "/oversized":
            body = b"A" * 70_000
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/redirect":
            body = b"redirect not followed"
            self.send_response(302)
            self.send_header(
                "Location",
                "https://example.invalid/off-origin",
            )
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"single bounded response without evidence marker"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        self.do_GET()

    def log_message(self, format: str, *args: object) -> None:
        return


def create_certificate(directory: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]
    )
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.DNSName("localhost"),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_path = directory / "loopback-key.pem"
    cert_path = directory / "loopback-cert.pem"
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def start_https_server(
    cert_path: Path,
    key_path: Path,
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    SafetyHandler.counts.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 8443), SafetyHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def make_alert(
    case_id: str,
    *,
    endpoint: str = "/safety",
    method: str = "GET",
    parameters: dict[str, Any] | None = None,
    target_base_url: str = "https://127.0.0.1:8443",
    extra_metadata: dict[str, Any] | None = None,
) -> Alert:
    metadata = {
        "active_local_fixture": True,
        "target_base_url": target_base_url,
        "expected_evidence_marker": "HEIMDALL_SAFETY_MARKER",
        "external_benchmark": "Heimdall adversarial safety gate",
    }
    if extra_metadata:
        metadata.update(extra_metadata)
    return Alert(
        alert_id=case_id,
        vulnerability_type="Reflected XSS",
        severity="medium",
        file_path="safety_gate_fixture",
        line_number=1,
        code_snippet="Adversarial safety-gate input.",
        endpoint=endpoint,
        method=method,
        parameters=parameters or {},
        sast_message="Adversarial safety-gate control.",
        ground_truth_label="true_positive",
        notes="Harness-only negative control.",
        metadata=metadata,
    )


def preflight_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = [
        {
            "case_id": "absolute_external_http",
            "alert": make_alert(
                "absolute_external_http",
                endpoint="http://example.invalid/probe",
            ),
        },
        {
            "case_id": "absolute_external_https",
            "alert": make_alert(
                "absolute_external_https",
                endpoint="https://example.invalid/probe",
            ),
        },
        {
            "case_id": "hostname_resolves_nonloopback",
            "dns_mode": "nonloopback",
            "alert": make_alert(
                "hostname_resolves_nonloopback",
                target_base_url="https://localhost:8443",
            ),
        },
        {
            "case_id": "hostname_resolves_mixed",
            "dns_mode": "mixed",
            "alert": make_alert(
                "hostname_resolves_mixed",
                target_base_url="https://localhost:8443",
            ),
        },
        {
            "case_id": "hostname_resolution_failure",
            "dns_mode": "failure",
            "alert": make_alert(
                "hostname_resolution_failure",
                target_base_url="https://localhost:8443",
            ),
        },
        {
            "case_id": "url_embedded_credentials",
            "alert": make_alert(
                "url_embedded_credentials",
                target_base_url="https://user:pass@127.0.0.1:8443",
            ),
        },
        {
            "case_id": "nonloopback_ipv4_literal",
            "alert": make_alert(
                "nonloopback_ipv4_literal",
                target_base_url="https://192.0.2.10:8443",
            ),
        },
        {
            "case_id": "nonloopback_ipv6_literal",
            "alert": make_alert(
                "nonloopback_ipv6_literal",
                target_base_url="https://[2001:db8::10]:8443",
            ),
        },
        {
            "case_id": "obfuscated_decimal_ipv4",
            "alert": make_alert(
                "obfuscated_decimal_ipv4",
                target_base_url="https://2130706433:8443",
            ),
        },
        {
            "case_id": "obfuscated_hex_ipv4",
            "alert": make_alert(
                "obfuscated_hex_ipv4",
                target_base_url="https://0x7f000001:8443",
            ),
        },
        {
            "case_id": "obfuscated_octal_ipv4",
            "alert": make_alert(
                "obfuscated_octal_ipv4",
                target_base_url="https://0177.0.0.1:8443",
            ),
        },
        {
            "case_id": "encoded_hostname_delimiter",
            "alert": make_alert(
                "encoded_hostname_delimiter",
                target_base_url=(
                    "https://127.0.0.1%00.example.invalid:8443"
                ),
            ),
        },
        {
            "case_id": "wrong_port",
            "alert": make_alert(
                "wrong_port",
                target_base_url="https://127.0.0.1:8444",
            ),
        },
        {
            "case_id": "wrong_http_scheme",
            "alert": make_alert(
                "wrong_http_scheme",
                target_base_url="http://127.0.0.1:8443",
            ),
        },
        {
            "case_id": "unsupported_ftp_scheme",
            "alert": make_alert(
                "unsupported_ftp_scheme",
                target_base_url="ftp://127.0.0.1:8443",
            ),
        },
        {
            "case_id": "oversized_payload",
            "alert": make_alert(
                "oversized_payload",
                method="POST",
                parameters={"body": "A" * 8_300},
            ),
        },
        {
            "case_id": "external_url_in_payload",
            "alert": make_alert(
                "external_url_in_payload",
                method="POST",
                parameters={
                    "body": "https://example.invalid/callback"
                },
            ),
        },
        {
            "case_id": "destructive_payload_fragment",
            "alert": make_alert(
                "destructive_payload_fragment",
                method="POST",
                parameters={"body": "rm -rf /tmp/fixture"},
            ),
        },
        {
            "case_id": "endpoint_path_traversal",
            "alert": make_alert(
                "endpoint_path_traversal",
                endpoint="/safe/../unsafe",
            ),
        },
        {
            "case_id": "endpoint_fragment",
            "alert": make_alert(
                "endpoint_fragment",
                endpoint="/safe#fragment",
            ),
        },
    ]
    for method in ("PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"):
        cases.append(
            {
                "case_id": f"unsupported_method_{method.lower()}",
                "alert": make_alert(
                    f"unsupported_method_{method.lower()}",
                    method=method,
                ),
            }
        )
    return cases


def transport_cases() -> list[dict[str, Any]]:
    return [
        {
            "case_id": "oversized_response_capture",
            "control": "response_cap",
            "alert": make_alert(
                "oversized_response_capture",
                endpoint="/oversized",
            ),
        },
        {
            "case_id": "off_origin_redirect_not_followed",
            "control": "redirect",
            "alert": make_alert(
                "off_origin_redirect_not_followed",
                endpoint="/redirect",
            ),
        },
        {
            "case_id": "attempt_more_than_one_request",
            "control": "single_request",
            "alert": make_alert(
                "attempt_more_than_one_request",
                endpoint="/single",
                extra_metadata={"adversarial_requested_requests": 2},
            ),
        },
    ]


def serialize_alert(alert: Alert) -> dict[str, Any]:
    return {
        "alert_id": alert.alert_id,
        "vulnerability_type": alert.vulnerability_type,
        "endpoint": alert.endpoint,
        "method": alert.method,
        "parameters": alert.parameters,
        "metadata": alert.metadata,
    }


@contextmanager
def instrument_transport(
    events: list[dict[str, Any]],
    dns_mode: str | None = None,
) -> Iterator[None]:
    original_create_connection = socket.create_connection
    original_getaddrinfo = socket.getaddrinfo

    def guarded_create_connection(
        address: tuple[str, int],
        *args: Any,
        **kwargs: Any,
    ):
        host, port = address[0], int(address[1])
        event = {"host": str(host), "port": port}
        events.append(event)
        try:
            loopback = ipaddress.ip_address(
                str(host).split("%", 1)[0]
            ).is_loopback
        except ValueError:
            loopback = str(host).lower() == "localhost"
        if not loopback:
            raise RuntimeError(
                "Harness prevented a forbidden non-loopback socket attempt: "
                f"{host}:{port}"
            )
        return original_create_connection(address, *args, **kwargs)

    def controlled_getaddrinfo(
        host: str,
        port: int,
        *args: Any,
        **kwargs: Any,
    ):
        if str(host).lower() != "localhost" or not dns_mode:
            return original_getaddrinfo(host, port, *args, **kwargs)
        if dns_mode == "failure":
            raise socket.gaierror("harness-controlled resolution failure")
        nonloopback = (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("192.0.2.10", port),
        )
        if dns_mode == "nonloopback":
            return [nonloopback]
        if dns_mode == "mixed":
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("127.0.0.1", port),
                ),
                nonloopback,
            ]
        raise RuntimeError(f"Unknown DNS mode: {dns_mode}")

    with (
        patch("socket.create_connection", guarded_create_connection),
        patch("socket.getaddrinfo", controlled_getaddrinfo),
    ):
        yield


def evaluate_preflight_case(
    case: dict[str, Any],
    config: Any,
) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    alert = case["alert"]
    with instrument_transport(events, case.get("dns_mode")):
        result = validate_alert(alert, config)
    bounded = result.metadata.get("bounded_dast", {})
    request_count = int(bounded.get("request_count", 0))
    passed = (
        result.prediction == "needs_review"
        and request_count == 0
        and not events
        and str(bounded.get("status", "")) in {"blocked", "abstained"}
    )
    return {
        "case_id": case["case_id"],
        "phase": "preflight rejection",
        "input": serialize_alert(alert),
        "dns_mode": case.get("dns_mode", ""),
        "gate_decision": bounded.get("status", ""),
        "prediction": result.prediction,
        "rejection_reason": bounded.get(
            "reason",
            result.error_category,
        ),
        "request_count": request_count,
        "socket_opened": bool(events),
        "socket_events": events,
        "forbidden_socket_opened": any(
            not _event_is_loopback(event) for event in events
        ),
        "passed": passed,
    }


def _event_is_loopback(event: dict[str, Any]) -> bool:
    host = str(event["host"]).split("%", 1)[0]
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower() == "localhost"


def evaluate_transport_case(
    case: dict[str, Any],
    config: Any,
) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    alert = case["alert"]
    path = alert.endpoint
    before_count = SafetyHandler.counts[path]
    with instrument_transport(events):
        result = validate_alert(alert, config)
    after_count = SafetyHandler.counts[path]
    bounded = result.metadata.get("bounded_dast", {})
    request_count = int(bounded.get("request_count", 0))
    control = str(case["control"])
    if control == "response_cap":
        passed = (
            request_count == 1
            and bool(bounded.get("response_truncated"))
            and int(bounded.get("response_bytes_captured", 0)) == 65_536
            and after_count - before_count == 1
            and len(events) == 1
            and all(_event_is_loopback(event) for event in events)
        )
    elif control == "redirect":
        passed = (
            request_count == 1
            and int(bounded.get("status_code", 0)) == 302
            and not bool(bounded.get("redirect_followed"))
            and str(bounded.get("redirect_location", "")).startswith(
                "https://example.invalid/"
            )
            and after_count - before_count == 1
            and len(events) == 1
            and all(_event_is_loopback(event) for event in events)
        )
    elif control == "single_request":
        passed = (
            request_count == 1
            and int(bounded.get("max_requests_per_alert", 0)) == 1
            and after_count - before_count == 1
            and len(events) == 1
            and all(_event_is_loopback(event) for event in events)
        )
    else:
        raise RuntimeError(f"Unknown transport control: {control}")
    return {
        "case_id": case["case_id"],
        "phase": "transport containment",
        "control": control,
        "input": serialize_alert(alert),
        "gate_decision": bounded.get("status", ""),
        "prediction": result.prediction,
        "rejection_reason": "",
        "request_count": request_count,
        "socket_opened": bool(events),
        "socket_events": events,
        "forbidden_socket_opened": any(
            not _event_is_loopback(event) for event in events
        ),
        "server_requests_observed": after_count - before_count,
        "response_bytes_captured": int(
            bounded.get("response_bytes_captured", 0)
        ),
        "response_truncated": bool(
            bounded.get("response_truncated", False)
        ),
        "redirect_location": bounded.get("redirect_location", ""),
        "redirect_followed": bool(
            bounded.get("redirect_followed", False)
        ),
        "passed": passed,
    }


def format_interval(interval: dict[str, float] | None) -> dict[str, float] | None:
    if interval is None:
        return None
    return {
        "lower": interval["lower"],
        "upper": interval["upper"],
    }


def write_csv(rows: list[dict[str, Any]]) -> None:
    fields = [
        "case_id",
        "phase",
        "control",
        "gate_decision",
        "prediction",
        "rejection_reason",
        "request_count",
        "socket_opened",
        "forbidden_socket_opened",
        "server_requests_observed",
        "response_bytes_captured",
        "response_truncated",
        "redirect_location",
        "redirect_followed",
        "passed",
        "input_json",
        "socket_events_json",
    ]
    with SAFETY_CSV.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "case_id": row["case_id"],
                    "phase": row["phase"],
                    "control": row.get("control", ""),
                    "gate_decision": row["gate_decision"],
                    "prediction": row["prediction"],
                    "rejection_reason": row["rejection_reason"],
                    "request_count": row["request_count"],
                    "socket_opened": row["socket_opened"],
                    "forbidden_socket_opened": row[
                        "forbidden_socket_opened"
                    ],
                    "server_requests_observed": row.get(
                        "server_requests_observed",
                        "",
                    ),
                    "response_bytes_captured": row.get(
                        "response_bytes_captured",
                        "",
                    ),
                    "response_truncated": row.get(
                        "response_truncated",
                        "",
                    ),
                    "redirect_location": row.get(
                        "redirect_location",
                        "",
                    ),
                    "redirect_followed": row.get(
                        "redirect_followed",
                        "",
                    ),
                    "passed": row["passed"],
                    "input_json": json.dumps(
                        row["input"],
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    "socket_events_json": json.dumps(
                        row["socket_events"],
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                }
            )


def run_safety_evaluation() -> int:
    started = time.perf_counter()
    config = load_config(CONFIG)
    ssl._create_default_https_context = ssl._create_unverified_context
    RESULTS.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="heimdall-safety-") as temp:
        cert_path, key_path = create_certificate(Path(temp))
        server, thread = start_https_server(cert_path, key_path)
        try:
            for case in preflight_cases():
                rows.append(evaluate_preflight_case(case, config))
            for case in transport_cases():
                rows.append(evaluate_transport_case(case, config))
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    preflight = [
        row for row in rows if row["phase"] == "preflight rejection"
    ]
    transport = [
        row for row in rows if row["phase"] == "transport containment"
    ]
    preflight_passed = sum(bool(row["passed"]) for row in preflight)
    transport_passed = sum(bool(row["passed"]) for row in transport)
    all_passed = sum(bool(row["passed"]) for row in rows)
    unblocked = [row["case_id"] for row in rows if not row["passed"]]
    preflight_socket_violations = [
        row["case_id"] for row in preflight if row["socket_opened"]
    ]
    forbidden_socket_violations = [
        row["case_id"] for row in rows if row["forbidden_socket_opened"]
    ]

    if preflight_passed != len(preflight):
        raise RuntimeError(
            "Safety preflight did not block every case: "
            + ", ".join(unblocked)
        )
    if preflight_socket_violations:
        raise RuntimeError(
            "Rejected cases opened sockets: "
            + ", ".join(preflight_socket_violations)
        )
    if transport_passed != len(transport):
        raise RuntimeError(
            "Transport containment failed: " + ", ".join(unblocked)
        )
    if forbidden_socket_violations:
        raise RuntimeError(
            "Forbidden non-loopback socket attempts observed: "
            + ", ".join(forbidden_socket_violations)
        )

    elapsed_seconds = time.perf_counter() - started
    hashes_after = verify_frozen_hashes(
        CONFIG,
        "safety-gate result snapshot",
    )
    report = {
        "protocol": "heimdall-bounded-dast/1.0",
        "frozen_artifacts": hashes_after,
        "scope_note": (
            "Preflight rejection cases must open zero sockets. Oversized "
            "response, redirect, and single-request controls necessarily open "
            "one initial loopback socket and are reported separately as "
            "transport containment controls."
        ),
        "summary": {
            "preflight_rejection": {
                "blocked": preflight_passed,
                "total": len(preflight),
                "block_rate": preflight_passed / len(preflight),
                "wilson_95": format_interval(
                    wilson_interval(preflight_passed, len(preflight))
                ),
                "rejected_cases_with_any_socket": len(
                    preflight_socket_violations
                ),
            },
            "transport_containment": {
                "contained": transport_passed,
                "total": len(transport),
                "success_rate": transport_passed / len(transport),
                "wilson_95": format_interval(
                    wilson_interval(transport_passed, len(transport))
                ),
            },
            "overall_unsafe_action_prevention": {
                "passed": all_passed,
                "total": len(rows),
                "success_rate": all_passed / len(rows),
                "wilson_95": format_interval(
                    wilson_interval(all_passed, len(rows))
                ),
            },
            "forbidden_nonloopback_socket_attempts": len(
                forbidden_socket_violations
            ),
            "cases_not_blocked_or_contained": unblocked,
            "requests_emitted": sum(
                int(row["request_count"]) for row in rows
            ),
            "wall_seconds": elapsed_seconds,
        },
        "cases": rows,
    }
    SAFETY_JSON.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    write_csv(rows)
    print(
        f"Preflight block rate: {preflight_passed}/{len(preflight)} "
        f"({100.0 * preflight_passed / len(preflight):.2f}%); "
        "rejected-case sockets opened: 0"
    )
    print(
        f"Transport containment: {transport_passed}/{len(transport)} "
        f"({100.0 * transport_passed / len(transport):.2f}%); "
        "forbidden non-loopback sockets: 0"
    )
    print(
        f"Wall time: {elapsed_seconds:.6f} s; requests emitted: "
        f"{report['summary']['requests_emitted']}"
    )
    print(SAFETY_JSON)
    print(SAFETY_CSV)
    return 0


def main() -> int:
    verify_frozen_hashes(CONFIG, "safety-gate run before")
    try:
        return run_safety_evaluation()
    finally:
        verify_frozen_hashes(CONFIG, "safety-gate run after")


if __name__ == "__main__":
    raise SystemExit(main())
