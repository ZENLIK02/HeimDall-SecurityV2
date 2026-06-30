from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


Exploitability = Literal["likely_exploitable", "unlikely_exploitable", "uncertain"]
RecommendedAction = Literal["validate_with_dast", "mark_false_positive", "needs_review"]
DastStatus = Literal["confirmed", "not_confirmed", "inconclusive", "blocked"]
FinalDecision = Literal["True Positive", "False Positive", "Needs Review"]


@dataclass(frozen=True)
class AlertContext:
    alert_id: str
    vulnerability_type: str
    severity: str
    file_path: str
    line_number: int
    code_snippet: str
    endpoint: str
    method: str
    parameters: dict[str, Any]
    sast_message: str
    notes: str = ""


@dataclass(frozen=True)
class PromptBundle:
    system_instruction: str
    alert_context: dict[str, Any]
    output_schema: dict[str, Any]
    rejected: bool = False
    rejection_reason: str = ""
    safety_notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ValidationPayload:
    vulnerability_type: str
    method: str
    endpoint: str
    parameters: dict[str, Any] = field(default_factory=dict)
    body: dict[str, Any] = field(default_factory=dict)
    expected_evidence: str = ""
    safety_notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class LLMReasoningOutput:
    vulnerability_type: str
    exploitability: Exploitability
    confidence: float
    reasoning_summary: str
    validation_strategy: str
    payloads: list[ValidationPayload]
    safety_notes: list[str]
    recommended_action: RecommendedAction


@dataclass(frozen=True)
class DastConfig:
    target_base_url: str = "http://127.0.0.1:3000"
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost")
    allow_production_targets: bool = False
    dry_run: bool = True
    timeout_seconds: float = 3.0
    min_interval_seconds: float = 0.05
    kill_switch: bool = False


@dataclass(frozen=True)
class DastResult:
    status: DastStatus
    status_code: int | None = None
    response_body: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    request_log: list[dict[str, Any]] = field(default_factory=list)
    blocked_reason: str = ""
    dry_run: bool = True


@dataclass(frozen=True)
class ResponseAnalysis:
    status: Literal["confirmed", "not_confirmed", "inconclusive"]
    evidence: str
    confidence: float


@dataclass(frozen=True)
class PipelineDecision:
    decision: FinalDecision
    confidence: float
    reason: str
    error_category: str = ""

