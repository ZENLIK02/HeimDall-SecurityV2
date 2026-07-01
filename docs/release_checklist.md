# Release Checklist: v0.1.0-alpha

Use this checklist before creating the public alpha release.

## Verification

- [ ] Run tests:

  ```bash
  pytest
  ```

- [ ] Run config validation:

  ```bash
  python -m heimdall.cli check-config --config heimdall.yml
  ```

- [ ] Run sample experiment:

  ```bash
  python -m heimdall.cli experiment --dataset data/sample_alerts.jsonl --mode all --output reports/
  ```

- [ ] Run sample CI validation:

  ```bash
  python -m heimdall.cli validate --semgrep test_data/semgrep-results-sample.json --config heimdall.yml --output reports/
  ```

- [ ] Verify reports:
  - `reports/summary.md`
  - `reports/summary.json`
  - `reports/results.csv`
  - `reports/ci_summary.md`
  - `reports/ci_results.json`
  - `reports/ci_results.csv`

## Release Steps

- [ ] Update `CHANGELOG.md`.
- [ ] Confirm README quickstart works from a fresh clone.
- [ ] Confirm no real secrets or production URLs are included.
- [ ] Create GitHub release.
- [ ] Tag version `v0.1.0-alpha`.
- [ ] Attach a sample report ZIP if available.
- [ ] Announce feedback request using `docs/launch_post.md`.
