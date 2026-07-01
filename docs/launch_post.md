# Launch Post Draft

I am building Heimdall, an open-source DevSecOps validation backend that helps reduce SAST false positives with LLM-assisted reasoning and safe DAST-style verification.

The current `v0.1.0-alpha` can:

- ingest Semgrep JSON,
- classify findings as True Positive / False Positive / Needs Review,
- run in dry-run mode by default,
- generate Markdown, JSON, and CSV reports,
- run inside GitHub Actions,
- provide a local vulnerable app for safe testing.

I am looking for feedback from AppSec and DevSecOps engineers:

- Does the report format make triage easier?
- Does the TP / FP / Needs Review model fit your workflow?
- What is missing before this could be useful in real CI/CD testing?

Please test only on non-production repositories and dry-run workflows.

Repository: https://github.com/ZENLIK02/HeimDall-SecurityV2
