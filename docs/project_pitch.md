# Project Pitch

## One-Sentence Pitch

Heimdall is an open-source DevSecOps validation backend that helps reduce SAST false positives with LLM-assisted reasoning and safe DAST-style verification.

## Problem

SAST tools find many possible security issues, but teams still spend time deciding which findings are exploitable, which are false positives, and which require more context.

## Solution

Heimdall ingests Semgrep JSON, converts findings into structured alerts, applies prompt-injection guardrails, performs dry-run or allowlisted validation, and generates reports that classify findings as `True Positive`, `False Positive`, or `Needs Review`.

## Target Users

- AppSec engineers.
- DevSecOps teams.
- Security researchers.
- Students learning CI/CD security validation.
- Maintainers evaluating SAST false-positive reduction workflows.

## Current Features

- Semgrep JSON ingestion.
- CLI validate and experiment modes.
- Baseline comparison.
- Dry-run validation pipeline.
- GitHub Actions workflow.
- Markdown/JSON/CSV reports.
- Local vulnerable demo app.

## Safety Defaults

- Dry-run mode by default.
- Mock LLM by default.
- Local/allowlisted targets only.
- Production-looking targets blocked.
- Destructive payload markers blocked.

## Call For Testers

Try Heimdall on non-production repositories and dry-run CI/CD workflows. Feedback on report clarity, decision quality, and adoption blockers is welcome.
