# Heimdall V2: Safety-First Selective Validation for Reducing SAST False Positives in DevSecOps Pipelines

## Abstract

Heimdall V2 is a safety-first DevSecOps research prototype for reducing SAST false positives through selective validation. The framework combines static alert ingestion, mockable LLM reasoning, safety-gated payload hypotheses, and deterministic localhost-only DAST evidence checks. The final benchmark contains 480 alerts: 300 synthetic SAST alerts and 180 active-local fixtures. The paper reports conventional and coverage-aware metrics and treats Needs Review as an intentional abstention, not a failure to hide uncertainty.

## 1. Introduction

SAST tools are useful early-warning systems, but alert volume and false positives can slow developer adoption. Heimdall V2 explores a selective validation workflow that confirms or dismisses only findings with controlled local evidence and routes the rest to manual review.

## 2. Background and Motivation

The project is motivated by SAST false positives, missing runtime context, and the risks of allowing LLMs to make unsupported security decisions. The system therefore separates LLM hypothesis generation from final evidence-based decisions.

## 3. Related Work

Related work spans static analysis for security, dynamic web testing, hybrid validation, DevSecOps, LLM vulnerability reasoning, prompt-injection risks, and human-in-the-loop triage. Notes and BibTeX entries are in `paper/related_work_notes.md` and `paper/references.bib`.

## 4. System Design

The pipeline ingests SAST alerts, extracts context, applies deterministic or optional LLM reasoning, generates non-destructive validation hypotheses, enforces a localhost-only safety gate, analyzes controlled evidence markers, and emits CI/reporting decisions.

## 5. Threat Model and Safety Model

The evaluation does not scan real websites, production domains, public IPs, or third-party systems. Active validation is restricted to `127.0.0.1:5005` and `localhost:5005`; external redirects are inspected but not followed. Real secrets, destructive payloads, and real authentication bypass are out of scope.

## 6. Implementation

The implementation includes a Flask local lab with controlled endpoints for twelve vulnerability categories, a JSONL benchmark loader, evaluation modes, active-local response analysis, bootstrap metrics, PDF reporting, and an optional GPT-4.1-mini ablation scaffold that skips cleanly without API keys.

## Method

## 7. Evaluation Methodology

The evaluation compares SAST-only, rule-based filtering, LLM-only stub, Heimdall full-pipeline stub, Heimdall dry-run mock, Heimdall active-local validation, and optional GPT-4.1-mini ablation scaffolding. The active-local mode validates only fixture-backed alerts and abstains on unsupported or context-dependent cases.

## Results

### Main Metrics

| mode | accuracy | precision | recall | f1_score | false_positive_reduction_rate | manual_review_rate |
|---|---|---|---|---|---|---|
| sast_only | 0.6083 | 0.6083 | 1.0000 | 0.7565 | 0.0000 | 0.0000 |
| rule_based_filtering | 0.1792 | 0.8431 | 1.0000 | 0.9149 | 0.0000 | 0.7875 |
| llm_only_stub | 0.3792 | 0.8517 | 1.0000 | 0.9199 | 0.1143 | 0.5563 |
| heimdall_full_pipeline_stub | 0.1333 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.6667 |
| heimdall_dry_run_mock | 0.1333 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.6667 |
| heimdall_active_local_validation | 0.2833 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.7167 |
| heimdall_gpt41mini_reasoning_ablation | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 1.0000 |

### Coverage-Aware Metrics

| mode | coverage | abstention_rate | selective_precision | selective_recall | utility_score |
|---|---|---|---|---|---|
| sast_only | 1.0000 | 0.0000 | 0.6083 | 1.0000 | -0.1750 |
| rule_based_filtering | 0.2125 | 0.7875 | 0.8431 | 0.2945 | -0.0844 |
| llm_only_stub | 0.4437 | 0.5563 | 0.8517 | 0.6096 | 0.1109 |
| heimdall_full_pipeline_stub | 0.3333 | 0.6667 | 0.0000 | 0.0000 | -0.2333 |
| heimdall_dry_run_mock | 0.3333 | 0.6667 | 0.0000 | 0.0000 | -0.2333 |
| heimdall_active_local_validation | 0.2833 | 0.7167 | 1.0000 | 0.3151 | 0.1042 |
| heimdall_gpt41mini_reasoning_ablation | 0.0000 | 1.0000 | 0.0000 | 0.0000 | -0.2500 |

### Active-Local Category Metrics

| vulnerability_type | category_coverage | category_abstention_rate | category_TP | category_TN | category_NeedsReview |
|---|---|---|---|---|---|
| Broken Access Control | 0.2250 | 0.7750 | 6 | 3 | 31 |
| Business Logic | 0.2000 | 0.8000 | 5 | 3 | 32 |
| Command Injection | 0.3250 | 0.6750 | 9 | 4 | 27 |
| Hardcoded Secret | 0.3250 | 0.6750 | 9 | 4 | 27 |
| IDOR | 0.2250 | 0.7750 | 6 | 3 | 31 |
| Insecure Deserialization | 0.2000 | 0.8000 | 5 | 3 | 32 |
| Open Redirect | 0.3250 | 0.6750 | 9 | 4 | 27 |
| Path Traversal | 0.3250 | 0.6750 | 9 | 4 | 27 |
| Reflected XSS | 0.3250 | 0.6750 | 9 | 4 | 27 |
| SQL Injection | 0.3250 | 0.6750 | 9 | 4 | 27 |
| SSRF | 0.2750 | 0.7250 | 7 | 4 | 29 |
| Weak Crypto | 0.3250 | 0.6750 | 9 | 4 | 27 |

## 8. Discussion

The active-local mode improves coverage over the previous 60-fixture run while keeping broad synthetic alerts in Needs Review. High-coverage categories are those with deterministic local evidence markers, such as SQL Injection simulation, XSS reflection, Path Traversal fixture access, Open Redirect header inspection, Command Injection simulation, Hardcoded Secret fixture, and Weak Crypto marker checks. Context-heavy categories retain higher abstention.

## 9. Limitations and Future Work

This benchmark is synthetic and local-only. It is appropriate for reproducibility evidence and safety framing, not for claiming production readiness or real-world exploit coverage. Future work should add authorized external benchmarks, real LLM ablations, stronger statistical design, and human triage studies.

## 10. Conclusion

Heimdall V2 demonstrates a safety-first selective validation pattern for SAST triage. Its strongest claim is not universal vulnerability detection, but disciplined handling of uncertainty: confirm when controlled evidence exists, dismiss when defensive behavior is observed, and abstain when validation would require unsafe or unavailable context.

## Acknowledgment

Acknowledgment placeholder for non-anonymous version.

## Reproducibility

Run `bash scripts/run_ieee_final_evaluation.sh` from the repository root. Commit used for this generated draft: `1791663`.
