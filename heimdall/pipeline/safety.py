from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from .models import DastConfig, ValidationPayload


DESTRUCTIVE_MARKERS = (
    "rm -rf",
    "drop table",
    "delete from",
    "truncate table",
    "shutdown",
    "reboot",
    "format ",
    "reverse shell",
    "nc -e",
    "powershell -enc",
)


@dataclass
class SafetyController:
    config: DastConfig
    request_log: list[dict] = field(default_factory=list)
    _last_request_time: float = 0.0

    def build_url(self, endpoint: str) -> str:
        return urljoin(self.config.target_base_url.rstrip("/") + "/", endpoint.lstrip("/"))

    def validate_target(self, url: str) -> tuple[bool, str]:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if self.config.kill_switch:
            return False, "kill switch enabled"
        if host in self.config.blocked_hosts:
            return False, f"target host {host!r} is explicitly blocked"
        if host not in self.config.allowed_hosts:
            return False, f"target host {host!r} is not allowlisted"
        if not self.config.allow_production_targets and not _is_local_host(host):
            return False, "production or non-local targets are blocked by default"
        return True, ""

    def validate_payload(self, payload: ValidationPayload) -> tuple[bool, str]:
        haystack = f"{payload.method} {payload.endpoint} {payload.parameters} {payload.body}".lower()
        for marker in DESTRUCTIVE_MARKERS:
            if marker in haystack:
                return False, f"destructive marker blocked: {marker}"
        if payload.method.upper() in {"DELETE", "PATCH"}:
            return False, f"HTTP method {payload.method} is blocked by safety policy"
        return True, ""

    def rate_limit(self) -> None:
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < self.config.min_interval_seconds:
            time.sleep(self.config.min_interval_seconds - elapsed)
        self._last_request_time = time.monotonic()

    def log_request(self, payload: ValidationPayload, url: str, blocked_reason: str = "") -> None:
        self.request_log.append(
            {
                "method": payload.method,
                "url": url,
                "parameters": payload.parameters,
                "dry_run": self.config.dry_run,
                "blocked_reason": blocked_reason,
            }
        )


def _is_local_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}

