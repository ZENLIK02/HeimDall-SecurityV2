# Heimdall Demo Experiment Summary

This is a static demo report for public users. It uses synthetic sample data only.

| Mode | Accuracy | Precision | Recall | False-Positive Reduction | Manual Review Rate |
|---|---:|---:|---:|---:|---:|
| sast_only | 0.5000 | 0.5000 | 1.0000 | 0.0000 | 0.0000 |
| rule_based_filtering | 0.5714 | 0.8000 | 0.8000 | 0.8000 | 0.2857 |
| llm_only_stub | 0.5714 | 0.8000 | 0.8000 | 0.8000 | 0.2857 |
| heimdall_full_pipeline_stub | 0.2857 | 0.0000 | 0.0000 | 1.0000 | 0.4286 |

## Notes

- The demo is dry-run and synthetic.
- `Needs Review` indicates missing context or safety restrictions.
- Use `python -m heimdall.cli experiment --dataset data/sample_alerts.jsonl --mode all --output reports/` to regenerate real local reports.
