# Community Feedback

## Suggested GitHub Discussions Post

### Call for DevSecOps testers

I am looking for AppSec and DevSecOps engineers to test Heimdall-SecurityV2 on safe, non-production repositories.

Heimdall is an open-source DevSecOps validation backend that ingests Semgrep JSON, runs a safety-first validation pipeline, and classifies findings as `True Positive`, `False Positive`, or `Needs Review`.

The current alpha focuses on:

- dry-run CI/CD workflows,
- Semgrep JSON ingestion,
- false-positive reduction research,
- Markdown/JSON/CSV reports,
- GitHub Actions integration,
- safe local testing.

What I am looking for:

1. Try the quickstart on a non-production repository.
2. Run the GitHub Actions workflow in dry-run mode.
3. Review whether the reports are understandable.
4. Share whether the decisions would reduce triage workload.
5. Suggest what is missing before real adoption.

Please do not share real secrets, private vulnerability data, production URLs, or customer code in public feedback.

Repository: https://github.com/ZENLIK02/HeimDall-SecurityV2
