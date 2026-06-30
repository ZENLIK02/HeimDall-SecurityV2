from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


NormalizedLabel = Literal["true_positive", "false_positive"]
PredictionLabel = Literal["confirmed", "dismissed", "needs_review"]


@dataclass(frozen=True)
class Alert:
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
    ground_truth_label: NormalizedLabel
    notes: str = ""

    @property
    def is_real_vulnerability(self) -> bool:
        return self.ground_truth_label == "true_positive"


@dataclass(frozen=True)
class EvaluationResult:
    alert_id: str
    mode: str
    vulnerability_type: str
    severity: str
    ground_truth_label: NormalizedLabel
    prediction: PredictionLabel
    classification: str
    confidence: float
    error_category: str = ""
    rationale: str = ""
    final_decision: str = ""
    evidence: str = ""
    explanation: str = ""
    safety_notes: list[str] = field(default_factory=list)
    recommended_action: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
