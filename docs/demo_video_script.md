# Demo Video Script

Length: 60-90 seconds.

## Script

SAST tools are great at finding possible security issues, but developers and AppSec teams still spend time deciding which alerts are real, which are false positives, and which need more context.

This is Heimdall-SecurityV2, an open-source DevSecOps validation backend for reducing SAST false positives.

First, Semgrep scans the code and saves findings as JSON.

Next, Heimdall ingests the Semgrep output, extracts context from each alert, applies prompt-injection guardrails, and uses LLM-assisted reasoning through a safe mock provider by default.

Then Heimdall generates non-destructive validation hypotheses and runs dry-run or allowlisted DAST-style verification.

Each finding is classified as True Positive, False Positive, or Needs Review.

The result is a CI-friendly report showing total findings, confirmed issues, false positives, review cases, evidence, and recommended actions.

Heimdall can run locally or inside GitHub Actions, and it is designed to stay safe by default: dry-run mode, mock LLM mode, local allowlists, and no production targets.

I am looking for feedback from AppSec and DevSecOps engineers. Try it on a non-production repository and share what would make it more useful for real triage workflows.
