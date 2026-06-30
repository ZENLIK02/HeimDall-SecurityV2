from __future__ import annotations

from .models import DastResult, LLMReasoningOutput, PipelineDecision, ResponseAnalysis


def decide(llm_output: LLMReasoningOutput, dast_result: DastResult, analysis: ResponseAnalysis) -> PipelineDecision:
    vuln = llm_output.vulnerability_type.lower()
    if dast_result.status == "blocked":
        return PipelineDecision("Needs Review", 0.70, "Safety policy blocked validation.", "DAST blocked by safety policy")
    if llm_output.confidence < 0.55:
        return PipelineDecision("Needs Review", llm_output.confidence, "LLM confidence is low.", "ambiguous response")
    if "business logic" in vuln:
        return PipelineDecision("Needs Review", 0.65, "Business logic requires multi-step state.", "business logic requires multi-step state")
    if "idor" in vuln or "access control" in vuln:
        return PipelineDecision("Needs Review", 0.62, "Authentication or authorization context is required.", "missing authentication context")
    if analysis.status == "confirmed":
        return PipelineDecision("True Positive", max(llm_output.confidence, analysis.confidence), analysis.evidence)
    if analysis.status == "not_confirmed" and llm_output.exploitability == "unlikely_exploitable":
        return PipelineDecision("False Positive", max(llm_output.confidence, analysis.confidence), analysis.evidence)
    if analysis.status == "not_confirmed":
        return PipelineDecision("False Positive", analysis.confidence, analysis.evidence)
    return PipelineDecision("Needs Review", min(llm_output.confidence, analysis.confidence), analysis.evidence, "ambiguous response")

