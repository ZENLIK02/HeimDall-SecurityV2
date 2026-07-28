from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class SecurityConfig:
    dry_run: bool = True
    allowed_targets: tuple[str, ...] = ("http://localhost:5000", "http://127.0.0.1:5000")
    blocked_targets: tuple[str, ...] = ("https://production.example.com",)
    fail_on_confirmed_high: bool = True
    fail_on_confirmed_critical: bool = True
    needs_review_does_not_fail: bool = True
    allow_external_targets: bool = False
    kill_switch: bool = False


@dataclass(frozen=True)
class DastRuntimeConfig:
    max_requests_per_scan: int = 50
    request_timeout_seconds: float = 5.0


@dataclass(frozen=True)
class ActiveValidationConfig:
    enabled: bool = False
    allowed_targets: tuple[str, ...] = ("http://127.0.0.1:5005", "http://localhost:5005")
    allow_external_targets: bool = False
    request_timeout_seconds: float = 2.0
    max_requests_per_alert: int = 1
    response_body_limit_bytes: int = 65536


@dataclass(frozen=True)
class LLMConfig:
    provider: str = "mock"
    use_mock_llm: bool = True


@dataclass(frozen=True)
class ReportsConfig:
    output_dir: str = "reports"


@dataclass(frozen=True)
class SemgrepConfig:
    output_path: str = "semgrep-results.json"


@dataclass(frozen=True)
class HeimdallConfig:
    security: SecurityConfig
    dast: DastRuntimeConfig
    llm: LLMConfig
    reports: ReportsConfig
    semgrep: SemgrepConfig
    active_validation: ActiveValidationConfig = field(default_factory=ActiveValidationConfig)


def load_config(path: str | Path) -> HeimdallConfig:
    raw = _parse_simple_yaml(Path(path).read_text(encoding="utf-8"))
    config = HeimdallConfig(
        security=SecurityConfig(**_known(raw.get("security", {}), SecurityConfig)),
        dast=DastRuntimeConfig(**_known(raw.get("dast", {}), DastRuntimeConfig)),
        active_validation=ActiveValidationConfig(
            **_known(raw.get("active_validation", {}), ActiveValidationConfig)
        ),
        llm=LLMConfig(**_known(raw.get("llm", {}), LLMConfig)),
        reports=ReportsConfig(**_known(raw.get("reports", {}), ReportsConfig)),
        semgrep=SemgrepConfig(**_known(raw.get("semgrep", {}), SemgrepConfig)),
    )
    validate_config(config)
    return config


def validate_config(config: HeimdallConfig) -> None:
    if not config.security.allowed_targets:
        raise ConfigError("security.allowed_targets must include at least one local or explicitly allowed target")
    if config.dast.max_requests_per_scan <= 0:
        raise ConfigError("dast.max_requests_per_scan must be greater than zero")
    if config.dast.request_timeout_seconds <= 0:
        raise ConfigError("dast.request_timeout_seconds must be greater than zero")
    if config.active_validation.request_timeout_seconds <= 0:
        raise ConfigError("active_validation.request_timeout_seconds must be greater than zero")
    if config.active_validation.max_requests_per_alert != 1:
        raise ConfigError("active_validation.max_requests_per_alert must be exactly one for the bounded DAST protocol")
    if config.active_validation.response_body_limit_bytes <= 0:
        raise ConfigError("active_validation.response_body_limit_bytes must be greater than zero")
    for target in config.security.allowed_targets:
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ConfigError(f"invalid allowed target: {target}")
        host = parsed.hostname or ""
        if _production_like(host) and not config.security.allow_external_targets:
            raise ConfigError(f"external target {target} requires security.allow_external_targets: true")
    for target in config.active_validation.allowed_targets:
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ConfigError(f"invalid active validation target: {target}")
        host = parsed.hostname or ""
        if _production_like(host) and not config.active_validation.allow_external_targets:
            raise ConfigError(f"active validation target {target} must be localhost unless explicitly enabled")
    blocked = set(config.security.blocked_targets)
    overlap = blocked.intersection(config.security.allowed_targets)
    if overlap:
        raise ConfigError(f"targets cannot be both allowed and blocked: {', '.join(sorted(overlap))}")
    if not config.llm.use_mock_llm and config.llm.provider == "mock":
        raise ConfigError("llm.provider must not be mock when llm.use_mock_llm is false")


def _known(values: dict, dataclass_type: type) -> dict:
    allowed = set(dataclass_type.__dataclass_fields__)
    return {key: value for key, value in values.items() if key in allowed}


def _parse_simple_yaml(text: str) -> dict:
    root: dict[str, object] = {}
    section: str | None = None
    list_key: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not line.startswith(" "):
            key = line.rstrip(":")
            root[key] = {}
            section = key
            list_key = None
            continue
        if section is None:
            raise ConfigError("invalid config structure")
        stripped = line.strip()
        current = root[section]
        if not isinstance(current, dict):
            raise ConfigError("invalid config section")
        if stripped.startswith("- "):
            if list_key is None:
                raise ConfigError("list item without key")
            current.setdefault(list_key, [])
            current[list_key].append(_coerce(stripped[2:].strip()))
            continue
        key, sep, value = stripped.partition(":")
        if not sep:
            raise ConfigError(f"invalid config line: {raw_line}")
        if value.strip() == "":
            current[key] = []
            list_key = key
        else:
            current[key] = _coerce(value.strip())
            list_key = None
    return root


def _coerce(value: str):
    value = value.strip().strip('"').strip("'")
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _production_like(host: str) -> bool:
    return host not in {"localhost", "127.0.0.1", "::1"} and not host.endswith(".local")
