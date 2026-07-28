from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import ssl
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


PROJECT = Path(__file__).resolve().parents[1]
WORK_ROOT = PROJECT.parent
DEFAULT_BENCHMARK = Path(
    r"C:\Users\User\Documents\Codex\2026-07-25\figure-out-next-steps"
    r"\work\external_validation\BenchmarkJava"
)
DEFAULT_CONFIG = WORK_ROOT / "external_validation" / "heimdall_owasp_benchmark.yml"
DEFAULT_BALANCED_REFERENCE = (
    WORK_ROOT / "external_validation" / "owasp_benchmark_pilot_results.json"
)
RESULTS = PROJECT / "results"
ELIGIBLE_CASES = RESULTS / "eligible_cases.json"
EXTERNAL_JSON = RESULTS / "external_full.json"
EXTERNAL_CSV = RESULTS / "external_full.csv"

VALIDATOR = PROJECT / "heimdall" / "evaluation" / "bounded_dast.py"
EXPECTED_VALIDATOR_SHA256 = (
    "2bbb3b1086cdfe249b50856179854a325be870ce43d312788fb3f1b063d5ef31"
)
EXPECTED_CONFIG_SHA256 = (
    "b47cceefb35bd12878adb1ee9e9474f74bde862eb37004e6dfcc2b3ff08182b3"
)
EXPECTED_BENCHMARK_COMMIT_PREFIX = "79b9bd6177e0"
EXPECTED_BALANCED = {
    "tp": 10,
    "tn": 0,
    "fp": 0,
    "fn": 0,
    "nr": 30,
    "coverage": 0.25,
    "decided_accuracy": 1.0,
}

# These are copied byte-for-byte from the frozen 40-case pilot harness.
CATEGORY_PLAN = {
    "xss": {
        "heimdall_category": "Reflected XSS",
        "payload": "<script>HEIMDALL_XSS_MARKER</script>",
        "marker": "<script>HEIMDALL_XSS_MARKER</script>",
    },
    "sqli": {
        "heimdall_category": "SQL Injection",
        "payload": "HEIMDALL_SQLI_MARKER' OR '1'='1'--",
        "marker": "HEIMDALL_SQLI_MARKER",
    },
    "pathtraver": {
        "heimdall_category": "Path Traversal",
        "payload": "../pom.xml",
        "marker": "OWASP Benchmark for Java",
    },
    "cmdi": {
        "heimdall_category": "Command Injection",
        "payload": "probe & echo HEIMDALL_CMD_MARKER",
        "marker": "HEIMDALL_CMD_MARKER",
    },
}

CATEGORY_CWE = {
    "cmdi": 78,
    "sqli": 89,
    "pathtraver": 22,
    "xss": 79,
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_frozen_hashes(config_path: Path, phase: str) -> dict[str, str]:
    validator_hash = sha256(VALIDATOR)
    config_hash = sha256(config_path)
    print(f"[{phase}] validator SHA-256: {validator_hash}", file=sys.stderr)
    print(f"[{phase}] config SHA-256:    {config_hash}", file=sys.stderr)
    if validator_hash != EXPECTED_VALIDATOR_SHA256:
        raise RuntimeError(
            "ABORT: frozen validator hash changed "
            f"(expected {EXPECTED_VALIDATOR_SHA256}, got {validator_hash})"
        )
    if config_hash != EXPECTED_CONFIG_SHA256:
        raise RuntimeError(
            "ABORT: frozen external config hash changed "
            f"(expected {EXPECTED_CONFIG_SHA256}, got {config_hash})"
        )
    return {
        "validator_sha256": validator_hash,
        "config_sha256": config_hash,
    }


def benchmark_commit(benchmark: Path) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=benchmark,
        text=True,
    ).strip()


def verify_benchmark(benchmark: Path) -> str:
    commit = benchmark_commit(benchmark)
    print(f"BenchmarkJava commit: {commit}", file=sys.stderr)
    if not commit.startswith(EXPECTED_BENCHMARK_COMMIT_PREFIX):
        raise RuntimeError(
            "ABORT: BenchmarkJava is not at the frozen commit "
            f"{EXPECTED_BENCHMARK_COMMIT_PREFIX} (got {commit})"
        )
    return commit


def source_record(
    benchmark: Path,
    test_name: str,
) -> tuple[Path, str, str] | None:
    path = (
        benchmark
        / "src"
        / "main"
        / "java"
        / "org"
        / "owasp"
        / "benchmark"
        / "testcode"
        / f"{test_name}.java"
    )
    text = path.read_text(encoding="utf-8")
    parameter = re.search(
        r'request\.getParameter\("(BenchmarkTest\d{5})"\)',
        text,
    )
    servlet = re.search(r'@WebServlet\(value\s*=\s*"([^"]+)"\)', text)
    if parameter is None or servlet is None or "void doPost" not in text:
        return None
    return path, parameter.group(1), servlet.group(1)


def enumerate_cases(benchmark: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    expected_results = benchmark / "expectedresults-1.2.csv"
    with expected_results.open(encoding="utf-8", newline="") as handle:
        reader = csv.reader(line for line in handle if not line.startswith("#"))
        for test_name, category, real, cwe in reader:
            if category not in CATEGORY_PLAN:
                continue
            source = source_record(benchmark, test_name)
            if source is None:
                continue
            source_path, parameter, servlet = source
            cwe_number = int(cwe)
            if cwe_number != CATEGORY_CWE[category]:
                raise RuntimeError(
                    f"Unexpected CWE for {test_name}: {category} has CWE-{cwe_number}"
                )
            rows.append(
                {
                    "case_id": test_name,
                    "category": category,
                    "heimdall_category": CATEGORY_PLAN[category][
                        "heimdall_category"
                    ],
                    "cwe": cwe_number,
                    "ground_truth": (
                        "true_positive"
                        if real.lower() == "true"
                        else "false_positive"
                    ),
                    "source_path": source_path.relative_to(benchmark).as_posix(),
                    "parameter": parameter,
                    "servlet": servlet,
                    "endpoint": f"/benchmark{servlet}",
                }
            )

    counts: dict[str, dict[str, int]] = {}
    for category in CATEGORY_PLAN:
        category_rows = [row for row in rows if row["category"] == category]
        positives = sum(
            row["ground_truth"] == "true_positive" for row in category_rows
        )
        negatives = len(category_rows) - positives
        counts[category] = {
            "total": len(category_rows),
            "positive": positives,
            "negative": negatives,
        }
    return {
        "benchmark": {
            "name": "OWASP BenchmarkJava",
            "version": "1.2",
            "commit": verify_benchmark(benchmark),
            "expected_results_sha256": sha256(expected_results),
        },
        "eligibility_rule": (
            "doPost servlet with request.getParameter input, using the "
            "frozen pilot's exact source matcher"
        ),
        "category_order": list(CATEGORY_PLAN),
        "counts": counts,
        "total": len(rows),
        "cases": rows,
    }


def print_enumeration(enumeration: dict[str, Any]) -> None:
    print("Eligible OWASP BenchmarkJava cases (natural label distribution):")
    for category in enumeration["category_order"]:
        counts = enumeration["counts"][category]
        print(
            f"  {category}/CWE-{CATEGORY_CWE[category]}: "
            f"{counts['total']} total "
            f"({counts['positive']} positive, {counts['negative']} negative)"
        )
    print(f"  overall: {enumeration['total']} total")


def write_eligible_cases(enumeration: dict[str, Any]) -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    ELIGIBLE_CASES.write_text(
        json.dumps(enumeration, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote complete case list before execution: {ELIGIBLE_CASES}")


def make_alert(row: dict[str, Any], benchmark: Path):
    sys.path.insert(0, str(PROJECT))
    from heimdall.evaluation.models import Alert

    plan = CATEGORY_PLAN[str(row["category"])]
    return Alert(
        alert_id=str(row["case_id"]),
        vulnerability_type=str(plan["heimdall_category"]),
        severity="medium",
        file_path=str(row["source_path"]),
        line_number=1,
        code_snippet="Externally authored OWASP BenchmarkJava servlet.",
        endpoint=str(row["endpoint"]),
        method="POST",
        parameters={str(row["parameter"]): plan["payload"]},
        sast_message=f"OWASP Benchmark v1.2 candidate, CWE-{row['cwe']}.",
        ground_truth_label=str(row["ground_truth"]),
        notes="Full eligible-set case enumerated before execution.",
        metadata={
            "active_local_fixture": True,
            "target_base_url": "https://127.0.0.1:8443",
            "expected_evidence_marker": plan["marker"],
            "external_benchmark": "OWASP BenchmarkJava v1.2",
            "cwe": int(row["cwe"]),
        },
    )


def abstention_cause(result: Any) -> str:
    if result.prediction != "needs_review":
        return ""
    bounded = result.metadata.get("bounded_dast", {})
    reason = str(bounded.get("reason", ""))
    status = str(bounded.get("status", ""))
    if reason in {
        "runtime_mapping_not_authorized",
        "active_validation_disabled",
    }:
        return "no authorized target"
    if reason == "missing_authentication_context":
        return "missing auth context"
    if reason == "multi_step_workflow_required":
        return "multi-step state"
    if reason in {
        "missing_or_oversized_positive_marker",
        "unsupported_category",
    }:
        return "unsupported category"
    if status == "blocked" or result.error_category == "safety_policy_abstention":
        return "safety-gate rejection"
    if (
        status == "completed"
        and int(bounded.get("status_code") or 0) > 0
        and not str(bounded.get("negative_evidence") or "")
        and not bool(bounded.get("positive_evidence_found"))
    ):
        return "no declared negative predicate"
    return "other"


def counterfactual_classification(row: dict[str, Any]) -> str:
    if row["prediction"] == "confirmed":
        return "TP" if row["ground_truth"] == "true_positive" else "FP"
    if row["prediction"] == "dismissed":
        return "FN" if row["ground_truth"] == "true_positive" else "TN"
    if (
        int(row["request_count"]) == 1
        and int(row["status_code"]) > 0
        and not bool(row["positive_evidence_found"])
    ):
        return "FN" if row["ground_truth"] == "true_positive" else "TN"
    return "REVIEW"


def run_child(
    case_rows: list[dict[str, Any]],
    benchmark: Path,
    config_path: Path,
    run_label: str,
) -> dict[str, Any]:
    verify_frozen_hashes(config_path, f"{run_label} before")
    verify_benchmark(benchmark)

    sys.path.insert(0, str(PROJECT))
    from heimdall.config import load_config
    from heimdall.evaluation.active_local import validate_alert

    # The frozen local Benchmark uses a self-signed certificate. This changes
    # only the child process's TLS verification, not validator source or logic.
    ssl._create_default_https_context = ssl._create_unverified_context
    config = load_config(config_path)
    rows: list[dict[str, Any]] = []
    started = time.perf_counter()
    try:
        for case in case_rows:
            alert = make_alert(case, benchmark)
            before = time.perf_counter()
            result = validate_alert(alert, config)
            elapsed_ms = (time.perf_counter() - before) * 1000.0
            bounded = result.metadata.get("bounded_dast", {})
            row = {
                "case_id": alert.alert_id,
                "category": str(case["category"]),
                "heimdall_category": alert.vulnerability_type,
                "cwe": int(case["cwe"]),
                "ground_truth": alert.ground_truth_label,
                "prediction": result.prediction,
                "classification": result.classification,
                "abstention_cause": abstention_cause(result),
                "error_category": result.error_category,
                "gate_status": bounded.get("status", ""),
                "gate_reason": bounded.get("reason", ""),
                "request_count": int(bounded.get("request_count", 0)),
                "status_code": int(bounded.get("status_code") or 0),
                "positive_evidence_found": bool(
                    bounded.get("positive_evidence_found", False)
                ),
                "negative_evidence_declared": bool(
                    str(bounded.get("negative_evidence") or "")
                ),
                "negative_evidence_found": bool(
                    bounded.get("negative_evidence_found", False)
                ),
                "response_bytes_captured": int(
                    bounded.get("response_bytes_captured", 0)
                ),
                "response_truncated": bool(
                    bounded.get("response_truncated", False)
                ),
                "elapsed_ms": elapsed_ms,
            }
            row["counterfactual_classification"] = (
                counterfactual_classification(row)
            )
            rows.append(row)
    finally:
        after_hashes = verify_frozen_hashes(
            config_path,
            f"{run_label} after",
        )
    elapsed_seconds = time.perf_counter() - started
    return {
        "run_label": run_label,
        "hashes": after_hashes,
        "elapsed_seconds": elapsed_seconds,
        "requests_emitted": sum(int(row["request_count"]) for row in rows),
        "rows": rows,
    }


def wilson_interval(successes: int, total: int) -> dict[str, float] | None:
    if total == 0:
        return None
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1.0 + (z * z / total)
    center = (
        proportion + (z * z / (2.0 * total))
    ) / denominator
    half_width = (
        z
        * math.sqrt(
            proportion * (1.0 - proportion) / total
            + z * z / (4.0 * total * total)
        )
        / denominator
    )
    return {
        "lower": max(0.0, center - half_width),
        "upper": min(1.0, center + half_width),
    }


def metrics_from_classifications(
    rows: list[dict[str, Any]],
    classification_field: str,
) -> dict[str, Any]:
    counts = Counter(str(row[classification_field]) for row in rows)
    total = len(rows)
    decided = counts["TP"] + counts["TN"] + counts["FP"] + counts["FN"]
    correct = counts["TP"] + counts["TN"]
    coverage = decided / total if total else 0.0
    decided_accuracy = correct / decided if decided else None
    return {
        "n": total,
        "tp": counts["TP"],
        "tn": counts["TN"],
        "fp": counts["FP"],
        "fn": counts["FN"],
        "nr": counts["REVIEW"],
        "decided": decided,
        "coverage": coverage,
        "coverage_wilson_95": wilson_interval(decided, total),
        "decided_accuracy": decided_accuracy,
        "decided_accuracy_wilson_95": wilson_interval(correct, decided),
    }


def summarize_run(rows: list[dict[str, Any]]) -> dict[str, Any]:
    per_category: dict[str, Any] = {}
    for category in CATEGORY_PLAN:
        category_rows = [
            row for row in rows if str(row["category"]) == category
        ]
        per_category[category] = {
            "label_distribution": {
                "positive": sum(
                    row["ground_truth"] == "true_positive"
                    for row in category_rows
                ),
                "negative": sum(
                    row["ground_truth"] == "false_positive"
                    for row in category_rows
                ),
            },
            "actual": metrics_from_classifications(
                category_rows,
                "classification",
            ),
            "counterfactual_forced_label": metrics_from_classifications(
                category_rows,
                "counterfactual_classification",
            ),
        }
    return {
        "overall": {
            "actual": metrics_from_classifications(rows, "classification"),
            "counterfactual_forced_label": metrics_from_classifications(
                rows,
                "counterfactual_classification",
            ),
        },
        "per_category": per_category,
        "abstention_causes": dict(
            sorted(
                Counter(
                    str(row["abstention_cause"])
                    for row in rows
                    if row["classification"] == "REVIEW"
                ).items()
            )
        ),
    }


def invoke_isolated_child(
    cases_path: Path,
    benchmark: Path,
    config_path: Path,
    run_label: str,
    selected_case_ids: list[str] | None = None,
) -> dict[str, Any]:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--child-run",
        "--cases",
        str(cases_path),
        "--benchmark",
        str(benchmark),
        "--config",
        str(config_path),
        "--run-label",
        run_label,
    ]
    if selected_case_ids is not None:
        command.extend(
            ["--selected-case-ids-json", json.dumps(selected_case_ids)]
        )
    completed = subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.stderr:
        print(completed.stderr, end="", file=sys.stderr)
    if completed.returncode != 0:
        if completed.stdout:
            print(completed.stdout, file=sys.stderr)
        raise RuntimeError(
            f"{run_label} child process failed with exit code "
            f"{completed.returncode}"
        )
    return json.loads(completed.stdout)


def assert_repeatability(
    first: dict[str, Any],
    second: dict[str, Any],
) -> None:
    first_verdicts = [
        (
            row["case_id"],
            row["prediction"],
            row["classification"],
            row["abstention_cause"],
        )
        for row in first["rows"]
    ]
    second_verdicts = [
        (
            row["case_id"],
            row["prediction"],
            row["classification"],
            row["abstention_cause"],
        )
        for row in second["rows"]
    ]
    if first_verdicts != second_verdicts:
        mismatches = [
            {
                "run_1": left,
                "run_2": right,
            }
            for left, right in zip(first_verdicts, second_verdicts)
            if left != right
        ]
        raise RuntimeError(
            "DIVERGENCE: full-run verdicts differ: "
            + json.dumps(mismatches[:20], indent=2)
        )
    first_summary = summarize_run(first["rows"])
    second_summary = summarize_run(second["rows"])
    if first_summary["per_category"] != second_summary["per_category"]:
        raise RuntimeError(
            "DIVERGENCE: full-run per-category counts differ"
        )


def balanced_case_ids(reference_path: Path) -> list[str]:
    reference = json.loads(reference_path.read_text(encoding="utf-8"))
    case_ids = list(reference["selection"]["case_ids"])
    if len(case_ids) != 40 or len(set(case_ids)) != 40:
        raise RuntimeError("Balanced reference does not contain 40 unique IDs")
    return [str(case_id) for case_id in case_ids]


def assert_balanced_reproduction(run: dict[str, Any]) -> dict[str, Any]:
    metrics = metrics_from_classifications(
        run["rows"],
        "classification",
    )
    observed = {
        "tp": metrics["tp"],
        "tn": metrics["tn"],
        "fp": metrics["fp"],
        "fn": metrics["fn"],
        "nr": metrics["nr"],
        "coverage": metrics["coverage"],
        "decided_accuracy": metrics["decided_accuracy"],
    }
    if observed != EXPECTED_BALANCED:
        raise RuntimeError(
            "DIVERGENCE: balanced 40-case subset did not reproduce. "
            f"Expected {EXPECTED_BALANCED}, observed {observed}"
        )
    return observed


def write_external_csv(
    first_rows: list[dict[str, Any]],
    second_rows: list[dict[str, Any]],
) -> None:
    second_by_id = {
        str(row["case_id"]): row for row in second_rows
    }
    fields = [
        "case_id",
        "category",
        "heimdall_category",
        "cwe",
        "ground_truth",
        "run_1_prediction",
        "run_1_classification",
        "run_1_abstention_cause",
        "run_1_request_count",
        "run_1_status_code",
        "run_1_elapsed_ms",
        "run_2_prediction",
        "run_2_classification",
        "run_2_abstention_cause",
        "run_2_request_count",
        "run_2_status_code",
        "run_2_elapsed_ms",
        "counterfactual_classification",
    ]
    with EXTERNAL_CSV.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for first in first_rows:
            second = second_by_id[str(first["case_id"])]
            writer.writerow(
                {
                    "case_id": first["case_id"],
                    "category": first["category"],
                    "heimdall_category": first["heimdall_category"],
                    "cwe": first["cwe"],
                    "ground_truth": first["ground_truth"],
                    "run_1_prediction": first["prediction"],
                    "run_1_classification": first["classification"],
                    "run_1_abstention_cause": first["abstention_cause"],
                    "run_1_request_count": first["request_count"],
                    "run_1_status_code": first["status_code"],
                    "run_1_elapsed_ms": f"{float(first['elapsed_ms']):.6f}",
                    "run_2_prediction": second["prediction"],
                    "run_2_classification": second["classification"],
                    "run_2_abstention_cause": second["abstention_cause"],
                    "run_2_request_count": second["request_count"],
                    "run_2_status_code": second["status_code"],
                    "run_2_elapsed_ms": f"{float(second['elapsed_ms']):.6f}",
                    "counterfactual_classification": first[
                        "counterfactual_classification"
                    ],
                }
            )


def parent_run(
    benchmark: Path,
    config_path: Path,
    balanced_reference: Path,
) -> int:
    parent_started = time.perf_counter()
    verify_frozen_hashes(config_path, "external evaluation parent before")
    enumeration = enumerate_cases(benchmark)
    print_enumeration(enumeration)
    write_eligible_cases(enumeration)

    full_run_1 = invoke_isolated_child(
        ELIGIBLE_CASES,
        benchmark,
        config_path,
        "external full run 1",
    )
    full_run_2 = invoke_isolated_child(
        ELIGIBLE_CASES,
        benchmark,
        config_path,
        "external full run 2",
    )
    assert_repeatability(full_run_1, full_run_2)

    balanced_ids = balanced_case_ids(balanced_reference)
    eligible_ids = {
        str(row["case_id"]) for row in enumeration["cases"]
    }
    missing_balanced = sorted(set(balanced_ids) - eligible_ids)
    if missing_balanced:
        raise RuntimeError(
            "Balanced reference contains ineligible/missing cases: "
            + ", ".join(missing_balanced)
        )
    balanced_run = invoke_isolated_child(
        ELIGIBLE_CASES,
        benchmark,
        config_path,
        "balanced 40 reproduction",
        selected_case_ids=balanced_ids,
    )
    balanced_observed = assert_balanced_reproduction(balanced_run)

    run_1_summary = summarize_run(full_run_1["rows"])
    run_2_summary = summarize_run(full_run_2["rows"])
    full_requests = (
        int(full_run_1["requests_emitted"])
        + int(full_run_2["requests_emitted"])
    )
    full_seconds = (
        float(full_run_1["elapsed_seconds"])
        + float(full_run_2["elapsed_seconds"])
    )
    all_requests = full_requests + int(balanced_run["requests_emitted"])
    all_child_seconds = full_seconds + float(balanced_run["elapsed_seconds"])
    report = {
        "protocol": "heimdall-bounded-dast/1.0",
        "frozen_artifacts": verify_frozen_hashes(
            config_path,
            "external evaluation parent after",
        ),
        "benchmark": enumeration["benchmark"],
        "selection": {
            "eligibility_rule": enumeration["eligibility_rule"],
            "natural_label_distribution": True,
            "sampled": False,
            "balanced": False,
            "capped": False,
            "counts": enumeration["counts"],
            "total": enumeration["total"],
            "eligible_cases_file": str(
                ELIGIBLE_CASES.relative_to(PROJECT)
            ).replace("\\", "/"),
        },
        "payloads_and_evidence_unchanged": CATEGORY_PLAN,
        "full_run_1": {
            **full_run_1,
            "summary": run_1_summary,
        },
        "full_run_2": {
            **full_run_2,
            "summary": run_2_summary,
        },
        "repeatability": {
            "identical_verdicts": True,
            "identical_per_category_counts": True,
        },
        "balanced_40_reproduction": {
            **balanced_run,
            "case_ids": balanced_ids,
            "observed": balanced_observed,
            "matches_expected": True,
        },
        "timing": {
            "full_two_runs_wall_seconds": full_seconds,
            "full_two_runs_requests_emitted": full_requests,
            "full_two_runs_ms_per_emitted_request": (
                full_seconds * 1000.0 / full_requests
                if full_requests
                else None
            ),
            "all_child_runs_wall_seconds": all_child_seconds,
            "all_child_runs_requests_emitted": all_requests,
            "all_child_runs_ms_per_emitted_request": (
                all_child_seconds * 1000.0 / all_requests
                if all_requests
                else None
            ),
            "parent_total_wall_seconds": time.perf_counter()
            - parent_started,
        },
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    EXTERNAL_JSON.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    write_external_csv(full_run_1["rows"], full_run_2["rows"])

    actual = run_1_summary["overall"]["actual"]
    forced = run_1_summary["overall"][
        "counterfactual_forced_label"
    ]
    print("Full eligible-set actual results:")
    print(json.dumps(actual, indent=2))
    print("Counterfactual forced-label results:")
    print(json.dumps(forced, indent=2))
    print(
        "Repeatability: identical verdicts and per-category counts "
        "across isolated runs"
    )
    print(f"Balanced-40 reproduced exactly: {balanced_observed}")
    print(
        f"Full two-run wall time: {full_seconds:.6f} s; "
        f"requests emitted: {full_requests}; "
        f"{report['timing']['full_two_runs_ms_per_emitted_request']:.6f} "
        "ms/request"
    )
    print(EXTERNAL_JSON)
    print(EXTERNAL_CSV)
    return 0


def child_main(args: argparse.Namespace) -> int:
    enumeration = json.loads(
        Path(args.cases).read_text(encoding="utf-8")
    )
    case_rows = list(enumeration["cases"])
    if args.selected_case_ids_json:
        selected_ids = json.loads(args.selected_case_ids_json)
        by_id = {
            str(row["case_id"]): row for row in case_rows
        }
        case_rows = [by_id[str(case_id)] for case_id in selected_ids]
    report = run_child(
        case_rows,
        Path(args.benchmark),
        Path(args.config),
        args.run_label,
    )
    print(json.dumps(report, ensure_ascii=False))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--benchmark",
        default=str(DEFAULT_BENCHMARK),
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG),
    )
    parser.add_argument(
        "--balanced-reference",
        default=str(DEFAULT_BALANCED_REFERENCE),
    )
    parser.add_argument("--enumerate-only", action="store_true")
    parser.add_argument("--child-run", action="store_true")
    parser.add_argument("--cases", default=str(ELIGIBLE_CASES))
    parser.add_argument("--run-label", default="external child run")
    parser.add_argument("--selected-case-ids-json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    benchmark = Path(args.benchmark)
    config_path = Path(args.config)
    if args.child_run:
        return child_main(args)
    verify_frozen_hashes(config_path, "enumeration before")
    if args.enumerate_only:
        enumeration = enumerate_cases(benchmark)
        print_enumeration(enumeration)
        write_eligible_cases(enumeration)
        verify_frozen_hashes(config_path, "enumeration after")
        return 0
    return parent_run(
        benchmark,
        config_path,
        Path(args.balanced_reference),
    )


if __name__ == "__main__":
    raise SystemExit(main())
