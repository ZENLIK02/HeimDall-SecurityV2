# Heimdall V2: Safety-First LLM-Assisted SAST Triage with Local DAST Validation

## Abstract

This draft presents Heimdall V2, a safety-first DevSecOps framework that uses a mockable LLM triage layer and controlled DAST validation to reduce SAST false positives. The experiment uses a reproducible 360-alert benchmark with synthetic labels and localhost-only active validation fixtures.

## Method

The evaluation compares six modes: SAST-only, rule-based filtering, LLM-only stub, Heimdall full-pipeline stub, Heimdall dry-run mock, and Heimdall active-local validation. Active validation is restricted to `127.0.0.1:5005` and uses deterministic non-destructive evidence markers.

## Results

| mode | accuracy | precision | recall | f1_score | false_positive_reduction_rate | manual_review_rate |
|---|---|---|---|---|---|---|
| sast_only | 0.5667 | 0.5667 | 1.0000 | 0.7234 | 0.0000 | 0.0000 |
| rule_based_filtering | 0.1778 | 0.9412 | 1.0000 | 0.9697 | 0.0000 | 0.8111 |
| llm_only_stub | 0.3639 | 0.9420 | 1.0000 | 0.9701 | 0.1111 | 0.6139 |
| heimdall_full_pipeline_stub | 0.1444 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.6667 |
| heimdall_dry_run_mock | 0.1444 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.6667 |
| heimdall_active_local_validation | 0.1333 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.8667 |

## Safety

The framework blocks external targets by default, preserves dry-run/mock execution, and routes alerts requiring authentication, state, or unavailable runtime context to Needs Review.

## Reproducibility

Run `bash scripts/run_ieee_ready_evaluation.sh` from the repository root. Commit used for this generated draft: `1791663`.

## Limitations

This is controlled evidence suitable for prototype and paper-supporting material. It still needs human review, broader authorized benchmarks, and complete citation verification before formal IEEE submission.
