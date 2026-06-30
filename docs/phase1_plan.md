# Heimdall V2 Phase 1 Inspection Plan

Date: 2026-06-30

Scope: Phase 1 only. This document inspects the current Heimdall codebase and defines a staged implementation plan for Heimdall V2. It does not propose testing against real production targets, embedding real secrets, or generating destructive payloads.

## 1. Repository Architecture Summary

The current repository is a small Streamlit application with most behavior concentrated in `app.py`.

```text
HeimDall-Project/
  .devcontainer/
    devcontainer.json
  app.py
  ai_engine.py
  dast_executor.py
  README.md
  requirements.txt
  sast_results.json
  .gitignore
```

Current roles:

- `app.py`: Main Streamlit UI and most pipeline logic. It handles ZIP upload, safe extraction, Semgrep execution, finding normalization, ranking, LLM payload generation, optional HTTP validation, heuristic response analysis, final verdict display, and developer guidance.
- `ai_engine.py`: Legacy/helper CLI that reads `sast_results.json`, sends the first finding to OpenAI, and writes `dast_payload.json`.
- `dast_executor.py`: Legacy/helper CLI that reads `dast_payload.json`, sends one HTTP request to a target URL, and asks OpenAI for a verdict.
- `requirements.txt`: Runtime dependencies: `streamlit`, `openai`, `requests`, and `semgrep`.
- `.devcontainer/devcontainer.json`: Codespaces/devcontainer setup that installs requirements and runs Streamlit.
- `sast_results.json`: Generated Semgrep output artifact. It should not be treated as source-of-truth application logic.

Architectural observation: Heimdall currently works as a prototype, but it is not modular. UI, scan orchestration, parsing, AI prompting, HTTP execution, decision logic, and reporting all live mostly in `app.py`. Heimdall V2 should preserve current behavior while extracting these into explicit modules with tests.

## 2. Current Pipeline Components

### Existing Flow In `app.py`

1. User uploads a ZIP.
2. `safe_extract_zip()` extracts files while blocking absolute paths, `..` traversal, and dependency directories.
3. `run_semgrep()` invokes `semgrep scan` with configurable rule packs and JSON output.
4. `simplify_finding()` converts raw Semgrep findings into a UI-friendly shape.
5. `sort_findings()` ranks findings by severity, file, line, and rule id.
6. User selects one finding.
7. `payload_prompt()` asks the LLM for a harmless validation payload.
8. `build_request()` converts the payload into an HTTP request.
9. `send_probe()` sends the request to an authorized target.
10. `summarize_response()` extracts response metadata, headers, redirects, and body excerpt.
11. `heuristic_verdict()` performs simple response-based classification.
12. OpenAI is asked to produce final validation and developer remediation JSON.
13. `render_validation_status()` displays True Positive / False Positive / Needs Review.

## 3. Capability Checklist

| Capability | Current Status | Evidence | Gap For V2 |
|---|---:|---|---|
| SAST ingestion | Partial | `run_semgrep()` runs Semgrep over extracted ZIPs. | Needs reusable scanner abstraction and stable result schema. |
| Semgrep JSON parsing | Partial | `simplify_finding()` parses `results`, `path`, `start`, and `extra.metadata`. | No JSONL support. Limited metadata normalization. No parser tests. |
| Context extraction | Minimal | Only normalized Semgrep finding fields are sent to the LLM. | No source-window extraction around vulnerable lines. No call graph, route, framework, or config context. |
| LLM reasoning | Partial | `payload_prompt()` and OpenAI calls exist in `app.py`; helper exists in `ai_engine.py`. | Prompting is inline, not versioned. No structured validation layer for model output beyond JSON parsing. |
| Payload generation | Partial | LLM returns `method`, `path`, `headers`, `params`, `json`, `data`, `confidence_score`, `expected_signal`, `reasoning`. | No payload schema class, guardrail policy, payload safety validator, or retry strategy. |
| DAST validation | Partial | `send_probe()` sends HTTP requests after user authorization. | No target allowlist, rate limits, auth/session handling, replay logs, or adapter abstraction. |
| Response analysis | Partial | `summarize_response()` and `heuristic_verdict()` inspect status, redirects, headers, and body text. | Heuristics are simple. No evidence scoring model or rule-specific validators. |
| Decision engine | Partial | `final_validation_status()` combines heuristic and AI verdict strings. | No explicit state machine, confidence calibration, or auditable rule set. |
| Reporting | Partial | Streamlit displays findings, payload, verdict, fix guidance, HTTP evidence. | No exportable HTML/PDF/JSON report schema. No report persistence. |
| Experiment runner | Missing in repo | No runner under `HeimDall-Project`. | Need benchmark runner for datasets, repeatable seeds, metrics, and CSV/JSON output. |
| Dataset format | Missing | No dataset schema or examples in repo. | Need JSONL schema for findings, ground truth, payloads, evidence, and labels. |
| Tests | Missing | No `tests/` directory or test framework config. | Need unit tests for parsers, extraction safety, decision logic, and payload validation. |
| CI/CD workflow | Missing | No `.github/workflows` directory. | Need lint/test/Semgrep workflow with no secrets committed. |
| Safety controls | Partial | ZIP traversal protection, dependency-dir skips, upload size limit, consent checkbox, harmless-payload prompt. | Need central policy module, target allowlist, destructive payload filter, outbound request restrictions, and audit log. |

## 4. Missing Modules For Heimdall V2

The following modules are missing or currently embedded in `app.py`:

- `sast` module: scanner interface, Semgrep execution, Semgrep JSON/JSONL parsers.
- `context` module: source file context extraction, line windows, route hints, framework hints, sanitization/control-flow hints.
- `llm` module: provider abstraction, prompt templates, response schema validation, retry and refusal handling.
- `payloads` module: payload schema, payload safety validation, route inference, request building.
- `dast` module: target configuration, allowlist, request executor, response capture, timeout/rate-limit policy.
- `decision` module: evidence scoring, confusion labels, true-positive/false-positive/needs-review decision rules.
- `reporting` module: JSON/CSV/HTML report generation and report persistence.
- `experiments` module: dataset loader, experiment runner, metrics, reproducible seeds.
- `datasets` directory: sample JSONL benchmark data and schema documentation.
- `tests` directory: unit/integration tests.
- `.github/workflows` directory: CI for tests, linting, and safe static checks.

## 5. Proposed Heimdall V2 Folder Structure

Keep `app.py` as the Streamlit entrypoint, but move implementation logic into a package.

```text
HeimDall-Project/
  app.py
  heimdall/
    __init__.py
    config.py
    models.py
    sast/
      __init__.py
      semgrep_runner.py
      semgrep_parser.py
    context/
      __init__.py
      extractor.py
      framework_hints.py
    llm/
      __init__.py
      providers.py
      prompts.py
      schemas.py
    payloads/
      __init__.py
      builder.py
      safety.py
    dast/
      __init__.py
      client.py
      targets.py
      evidence.py
    decision/
      __init__.py
      heuristics.py
      engine.py
      metrics.py
    reporting/
      __init__.py
      report.py
      exporters.py
    experiments/
      __init__.py
      runner.py
      datasets.py
  datasets/
    README.md
    schema.json
    sample_findings.jsonl
  tests/
    test_semgrep_parser.py
    test_safe_extract.py
    test_payload_safety.py
    test_decision_engine.py
  docs/
    phase1_plan.md
    v2_architecture.md
  .github/
    workflows/
      ci.yml
```

Compatibility assumption: `app.py` should continue to run the current Streamlit UI while importing V2 modules behind the scenes. This avoids a risky rewrite.

## 6. Phase 2 Implementation Plan: Stabilize Core Data Flow

Priority: make the current prototype modular and testable without changing its user-facing behavior.

1. Create `heimdall/models.py`.
   - Define dataclasses or Pydantic models for `Finding`, `SourceContext`, `Payload`, `HttpEvidence`, `Decision`, and `Report`.
   - Keep schemas small and serializable.

2. Extract Semgrep handling.
   - Move `run_semgrep()` to `heimdall/sast/semgrep_runner.py`.
   - Move `simplify_finding()` and metadata normalization to `heimdall/sast/semgrep_parser.py`.
   - Add JSONL parser support for future datasets.

3. Extract ZIP/source safety.
   - Move `normalize_zip_member()` and `safe_extract_zip()` to a source ingestion module.
   - Add tests for absolute paths, Windows drive paths, `..`, dependency directories, empty archives, and valid files.

4. Add context extraction.
   - Given a finding path and line number, extract a bounded code window.
   - Include file path, start/end lines, function/class hints if easy.
   - Do not perform complex static analysis yet.

5. Add initial tests.
   - Use `pytest`.
   - Test parser output, safe extraction, sort/ranking behavior, and simple context extraction.

6. Update `app.py` imports.
   - Replace duplicated inline helpers with imports from `heimdall/`.
   - Keep UI behavior unchanged.

Exit criteria for Phase 2:

- Existing Streamlit workflow still works.
- Unit tests pass.
- Semgrep JSON and JSONL can be parsed into one canonical finding schema.
- Source context is available for LLM prompts.

## 7. Phase 3 Implementation Plan: Safe LLM + DAST Orchestration

Priority: make AI and HTTP validation controlled, auditable, and safe.

1. Create LLM provider abstraction.
   - `heimdall/llm/providers.py` supports OpenAI first.
   - API keys only from environment or Streamlit secrets.
   - No real secrets in source or docs.

2. Version prompt templates.
   - Move prompts to `heimdall/llm/prompts.py`.
   - Include explicit instruction boundaries between system instructions and source-code context.
   - Add prompt-injection defensive language.

3. Add schema validation for LLM output.
   - Validate method, path, headers, params, JSON body, data, expected signal, and confidence.
   - Reject malformed output and fall back to "Needs Review".

4. Add payload safety controls.
   - Allow only harmless proof-of-concept probes.
   - Block destructive verbs or payload markers such as file deletion, reverse shells, credential exfiltration, and persistence.
   - Add tests for blocked payloads.

5. Add DAST target policy.
   - Require explicit authorization.
   - Add allowlist for localhost/private lab hosts by default.
   - Add timeout, redirect, request-size, and rate-limit controls.

6. Improve response analysis.
   - Rule-specific validators for SQLi, XSS, command injection, path traversal, SSRF, hardcoded secret.
   - Distinguish "endpoint missing" from "payload failed" from "confirmed exploit signal".

7. Implement decision engine.
   - Centralize final TP/FP/Needs Review logic.
   - Track heuristic verdict, LLM verdict, evidence strength, and confidence.
   - Produce auditable reasons.

Exit criteria for Phase 3:

- Every generated payload passes a safety validator before any HTTP request.
- The decision engine can classify evidence without relying only on free-form LLM text.
- DAST is restricted to explicitly authorized lab targets.

## 8. Phase 4 Implementation Plan: Reporting, Experiments, and CI

Priority: make the system research-ready and maintainable.

1. Add report generation.
   - Canonical JSON report containing finding, source context, payload, HTTP evidence, decision, and remediation guidance.
   - CSV export for experiments.
   - Optional HTML report for demos.

2. Add experiment runner.
   - Load JSONL benchmark datasets with ground truth.
   - Run pipeline in mock mode or live lab mode.
   - Compute TP, FP, TN, FN, accuracy, precision, recall, F1, and processing time.

3. Define dataset format.
   - Add `datasets/schema.json`.
   - Include fields: `vulnerability_id`, `file_path`, `line`, `cwe`, `code_snippet`, `source_context`, `ground_truth`, `expected_signal`, `notes`.
   - Include a small synthetic sample only.

4. Add CI/CD.
   - GitHub Actions workflow for `python -m compileall`, `pytest`, and optional Semgrep.
   - Do not run live DAST in CI.
   - Do not require real API keys in CI.

5. Add documentation.
   - `docs/v2_architecture.md`
   - `docs/safety_model.md`
   - `docs/dataset_format.md`
   - `docs/experiment_protocol.md`

6. Add evaluation outputs.
   - Store generated benchmark CSVs outside source control by default.
   - Track summary metrics in docs or release artifacts.

Exit criteria for Phase 4:

- A reviewer can reproduce experiments with a fixed seed.
- Reports are exportable.
- CI verifies core parsing, safety, and decision logic.
- No production targets or secrets are required.

## 9. Safety Assumptions And Constraints

- Only test against local lab targets or explicitly authorized systems.
- Do not store OpenAI, Anthropic, GitHub, or target credentials in source files.
- Do not generate destructive payloads.
- DAST should default to localhost or private lab addresses until a stricter target policy is implemented.
- If target ownership is unclear, Heimdall should generate a payload preview only and skip live HTTP validation.

## 10. Immediate Next Step

Start Phase 2 by adding the `heimdall/` package and moving the smallest stable units first:

1. `models.py`
2. Semgrep parser
3. safe ZIP extraction
4. source context extractor
5. tests for those modules

Do not start with a full rewrite of `app.py`. Keep the UI working and replace internals incrementally.
