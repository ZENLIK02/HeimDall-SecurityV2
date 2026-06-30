from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

from experiments.run_experiment import run_experiment
from heimdall.ci_policy import determine_exit_code
from heimdall.ci_reports import write_ci_reports
from heimdall.config import ConfigError, HeimdallConfig, load_config
from heimdall.evaluation.metrics import classify
from heimdall.pipeline.models import DastConfig
from heimdall.pipeline.runner import run_validation_pipeline
from heimdall.semgrep_ingest import load_semgrep_alerts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m heimdall.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="Validate Semgrep findings for CI/CD.")
    validate.add_argument("--semgrep", required=True)
    validate.add_argument("--config", default="heimdall.yml")
    validate.add_argument("--output", default=None)

    experiment = subparsers.add_parser("experiment", help="Run research evaluation modes.")
    experiment.add_argument("--dataset", default="data/sample_alerts.jsonl")
    experiment.add_argument("--mode", default="all")
    experiment.add_argument("--output", default="reports")

    check = subparsers.add_parser("check-config", help="Validate Heimdall config safety.")
    check.add_argument("--config", default="heimdall.yml")

    args = parser.parse_args(argv)
    try:
        if args.command == "check-config":
            load_config(args.config)
            print("Config OK")
            return 0
        if args.command == "experiment":
            summary = run_experiment(Path(args.dataset), Path(args.output), args.mode)
            print(json.dumps({"alert_count": summary["alert_count"], "modes": summary["modes"]}, indent=2))
            return 0
        if args.command == "validate":
            config = load_config(args.config)
            output = args.output or config.reports.output_dir
            return _validate(args.semgrep, output, config)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Runtime error: {exc}", file=sys.stderr)
        return 3
    return 3


def _validate(semgrep_path: str, output: str, config: HeimdallConfig) -> int:
    alerts = load_semgrep_alerts(semgrep_path)
    dast_config = _to_dast_config(config)
    if not dast_config.dry_run:
        print("WARNING: active DAST validation requested. Only allowlisted targets will be contacted.", file=sys.stderr)
    results = []
    for index, alert in enumerate(alerts):
        if index >= config.dast.max_requests_per_scan:
            break
        result = run_validation_pipeline(alert, dast_config)
        result.metadata.update({"file_path": alert.file_path, "line_number": alert.line_number})
        results.append(result)
    write_ci_reports(output, results, len(alerts), config)
    return determine_exit_code(results, config)


def _to_dast_config(config: HeimdallConfig) -> DastConfig:
    target_base_url = config.security.allowed_targets[0]
    hosts = tuple(sorted({urlparse(target).hostname or "" for target in config.security.allowed_targets}))
    blocked_hosts = tuple(sorted({urlparse(target).hostname or "" for target in config.security.blocked_targets}))
    return DastConfig(
        target_base_url=target_base_url,
        allowed_hosts=hosts,
        blocked_hosts=blocked_hosts,
        allow_production_targets=config.security.allow_external_targets,
        dry_run=config.security.dry_run,
        timeout_seconds=config.dast.request_timeout_seconds,
        kill_switch=config.security.kill_switch,
    )


if __name__ == "__main__":
    raise SystemExit(main())
