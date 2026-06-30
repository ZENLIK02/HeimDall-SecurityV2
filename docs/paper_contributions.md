# Paper Contribution Summary

## Main Contributions

1. A closed-loop DevSecOps validation framework that integrates SAST, LLM-based exploitability reasoning, and DAST-based dynamic verification.

2. An exploitability-oriented payload generation and validation workflow that converts static alerts into testable validation hypotheses.

3. A reproducible evaluation workflow that compares Heimdall against SAST-only, rule-based, and LLM-only baselines using standard classification metrics.

## Research Positioning

Heimdall V2 studies false-positive reduction as a validation problem rather than a ranking-only problem. The framework keeps the SAST alert as the initial signal, uses structured LLM reasoning to form an exploitability hypothesis, and applies constrained DAST-style evidence collection before producing a final decision.

## Limitations

- The current dataset is small and synthetic, so results should be interpreted as a reproducibility demonstration rather than a statistically general benchmark.
- Business logic flaws may require multi-step workflows that are not represented by a single request payload.
- Missing authentication context can prevent reliable dynamic validation.
- Prompt injection risk remains relevant because code comments and SAST messages are untrusted input.
- Model uncertainty requires conservative decision thresholds and manual review paths.
- DAST safety restrictions intentionally prevent some forms of live validation.

## Future Work

- Add retrieval-augmented generation for framework-specific and repository-specific context.
- Add multi-language CI/CD support beyond the current Python-focused prototype.
- Add multi-step authenticated validation for IDOR and business logic workflows.
- Evaluate the framework on a larger independently labeled dataset.
- Replace the deterministic mock LLM provider with configurable production LLM backends while preserving schema validation and safety controls.
