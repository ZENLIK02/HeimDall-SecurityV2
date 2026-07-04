# Heimdall V2 IEEE Reproducibility

This repository includes a local-only, safety-first evaluation workflow for the Heimdall V2 prototype. It is not a production scanner and does not provide real-world exploit coverage.

## Safety Warning

Do not point this workflow at real websites, public IPs, production domains, third-party systems, or real secrets. Active validation is restricted to `127.0.0.1:5005` and `localhost:5005`.

## Environment Setup

- Python: 3.11+ recommended; tested with Python 3.12 in WSL.
- Dependencies: `semgrep`, `pytest`, `flask`, `Pillow`, `reportlab`.
- The runner creates/uses `.heimdall_eval_venv` if dependencies are missing.

## One-command run

```bash
bash scripts/run_ieee_final_evaluation.sh
```

## Manual Steps Performed By The Runner

1. Generate the 300-alert synthetic dataset.
2. Generate the expanded 180-alert active-local dataset.
3. Generate the combined 480-alert final dataset.
4. Start the Flask lab on `127.0.0.1:5005`.
5. Wait for `/health`.
6. Validate safety configuration.
7. Run all evaluation modes.
8. Generate CSV, JSON, Markdown, charts, PDF, and paper artifacts.
9. Stop the local lab.
10. Run `pytest`.

## Key outputs

- `reports/ieee_final_eval/HeimdallV2_IEEE_Final_Evaluation_Report.pdf`
- `reports/ieee_final_eval/metrics_by_mode.csv`
- `reports/ieee_final_eval/coverage_metrics.csv`
- `reports/ieee_final_eval/category_metrics.csv`
- `reports/ieee_final_eval/paper_ready_summary.md`
- `paper/HeimdallV2_IEEE_Final.md`
- `paper/HeimdallV2_IEEE_Final.tex`
- `paper/HeimdallV2_IEEE_Final_Anonymous.tex`

## Optional Real LLM Ablation

Leave disabled for reproducibility. To run only in an authorized environment:

```bash
export HEIMDALL_ENABLE_REAL_LLM=1
export OPENAI_API_KEY=...
export HEIMDALL_LLM_MODEL=gpt-4.1-mini
```

Without those variables, the ablation mode skips cleanly and writes a not-run note.

## Verify No External Targets

Inspect `reports/ieee_final_eval/safety_audit.md` and run `pytest tests/test_no_external_targets.py tests/test_active_validation_safety_policy.py`.

## Troubleshooting

- If `/health` fails, stop any process using port 5005 and rerun the one-command script.
- If PDF generation fails, install `Pillow` and `reportlab` in the active Python environment.
- If tests fail, read the exact pytest error and rerun `python3 -m pytest -x` after fixing only workflow-related issues.
