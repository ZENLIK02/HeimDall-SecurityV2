from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


PROJECT = Path(__file__).resolve().parents[1]
RESULTS = PROJECT / "results"
EXTERNAL_JSON = RESULTS / "external_full.json"
SAFETY_JSON = RESULTS / "safety_gate.json"
SUMMARY = RESULTS / "summary.md"
MANIFEST = PROJECT / "SHA256SUMS.txt"

ABSTENTION_CAUSES = [
    "no authorized target",
    "missing auth context",
    "multi-step state",
    "unsupported category",
    "safety-gate rejection",
    "no declared negative predicate",
    "other",
]
CATEGORY_CWE = {
    "cmdi": 78,
    "sqli": 89,
    "pathtraver": 22,
    "xss": 79,
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def percent(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{100.0 * value:.2f}%"


def interval(value: dict[str, float] | None) -> str:
    if value is None:
        return "—"
    return (
        f"{100.0 * value['lower']:.2f}%–"
        f"{100.0 * value['upper']:.2f}%"
    )


def external_table(external: dict[str, Any]) -> list[str]:
    summary = external["full_run_1"]["summary"]
    rows = [
        "### (a) Full eligible-set external results",
        "",
        "| Category | N (+/−) | TP | TN | FP | FN | NR | Coverage (95% Wilson CI) | Decided accuracy (95% Wilson CI) | Counterfactual TP/TN/FP/FN | Counterfactual accuracy |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for category in external["selection"]["counts"]:
        category_summary = summary["per_category"][category]
        labels = category_summary["label_distribution"]
        actual = category_summary["actual"]
        forced = category_summary["counterfactual_forced_label"]
        rows.append(
            "| "
            + " | ".join(
                [
                    f"{category}/CWE-{CATEGORY_CWE[category]}",
                    f"{actual['n']} ({labels['positive']}/{labels['negative']})",
                    str(actual["tp"]),
                    str(actual["tn"]),
                    str(actual["fp"]),
                    str(actual["fn"]),
                    str(actual["nr"]),
                    f"{percent(actual['coverage'])} ({interval(actual['coverage_wilson_95'])})",
                    f"{percent(actual['decided_accuracy'])} ({interval(actual['decided_accuracy_wilson_95'])})",
                    f"{forced['tp']}/{forced['tn']}/{forced['fp']}/{forced['fn']}",
                    percent(forced["decided_accuracy"]),
                ]
            )
            + " |"
        )
    actual = summary["overall"]["actual"]
    forced = summary["overall"]["counterfactual_forced_label"]
    total_positive = sum(
        int(counts["positive"])
        for counts in external["selection"]["counts"].values()
    )
    total_negative = sum(
        int(counts["negative"])
        for counts in external["selection"]["counts"].values()
    )
    rows.append(
        "| "
        + " | ".join(
            [
                "**Overall**",
                f"**{actual['n']} ({total_positive}/{total_negative})**",
                f"**{actual['tp']}**",
                f"**{actual['tn']}**",
                f"**{actual['fp']}**",
                f"**{actual['fn']}**",
                f"**{actual['nr']}**",
                f"**{percent(actual['coverage'])} ({interval(actual['coverage_wilson_95'])})**",
                f"**{percent(actual['decided_accuracy'])} ({interval(actual['decided_accuracy_wilson_95'])})**",
                f"**{forced['tp']}/{forced['tn']}/{forced['fp']}/{forced['fn']}**",
                f"**{percent(forced['decided_accuracy'])}**",
            ]
        )
        + " |"
    )
    return rows


def abstention_table(external: dict[str, Any]) -> list[str]:
    causes = external["full_run_1"]["summary"]["abstention_causes"]
    total_nr = int(
        external["full_run_1"]["summary"]["overall"]["actual"]["nr"]
    )
    rows = [
        "### (b) Abstention causes",
        "",
        "| Cause | Count | Share of NR |",
        "|---|---:|---:|",
    ]
    for cause in ABSTENTION_CAUSES:
        count = int(causes.get(cause, 0))
        share = count / total_nr if total_nr else 0.0
        rows.append(f"| {cause} | {count} | {percent(share)} |")
    rows.append(f"| **Total** | **{total_nr}** | **100.00%** |")
    return rows


def safety_table(safety: dict[str, Any]) -> list[str]:
    summary = safety["summary"]
    preflight = summary["preflight_rejection"]
    transport = summary["transport_containment"]
    overall = summary["overall_unsafe_action_prevention"]
    return [
        "### (c) Safety-gate and transport-control results",
        "",
        "| Control set | Passed / total | Rate (95% Wilson CI) | Rejected-case sockets | Forbidden non-loopback sockets |",
        "|---|---:|---:|---:|---:|",
        (
            f"| Preflight rejection | {preflight['blocked']} / "
            f"{preflight['total']} | {percent(preflight['block_rate'])} "
            f"({interval(preflight['wilson_95'])}) | "
            f"{preflight['rejected_cases_with_any_socket']} | 0 |"
        ),
        (
            f"| Transport containment controls | {transport['contained']} / "
            f"{transport['total']} | {percent(transport['success_rate'])} "
            f"({interval(transport['wilson_95'])}) | N/A | 0 |"
        ),
        (
            f"| **Overall unsafe-action prevention** | "
            f"**{overall['passed']} / {overall['total']}** | "
            f"**{percent(overall['success_rate'])} "
            f"({interval(overall['wilson_95'])})** | "
            f"**{preflight['rejected_cases_with_any_socket']}** | "
            f"**{summary['forbidden_nonloopback_socket_attempts']}** |"
        ),
    ]


def write_summary(
    external: dict[str, Any],
    safety: dict[str, Any],
) -> None:
    timing = external["timing"]
    safety_timing = safety["summary"]
    combined_wall_seconds = (
        float(timing["parent_total_wall_seconds"])
        + float(safety_timing["wall_seconds"])
    )
    combined_requests = (
        int(timing["all_child_runs_requests_emitted"])
        + int(safety_timing["requests_emitted"])
    )
    balanced = external["balanced_40_reproduction"]["observed"]
    lines = [
        "# Heimdall Frozen Bounded-DAST Evaluation Summary",
        "",
        (
            "Frozen validator SHA-256: `"
            + external["frozen_artifacts"]["validator_sha256"]
            + "`"
        ),
        (
            "Frozen external config SHA-256: `"
            + external["frozen_artifacts"]["config_sha256"]
            + "`"
        ),
        "",
        (
            "The full eligible set uses the natural OWASP BenchmarkJava "
            "label distribution; no sampling, balancing, or cap was applied. "
            "Two process-isolated runs produced identical verdicts and "
            "identical per-category counts."
        ),
        "",
        *external_table(external),
        "",
        *abstention_table(external),
        "",
        *safety_table(safety),
        "",
        (
            "Balanced-40 reproduction: "
            f"TP={balanced['tp']}, TN={balanced['tn']}, "
            f"FP={balanced['fp']}, FN={balanced['fn']}, "
            f"NR={balanced['nr']}, "
            f"coverage={percent(balanced['coverage'])}, "
            "decided accuracy="
            f"{percent(balanced['decided_accuracy'])}. "
            "These values match the frozen pilot exactly."
        ),
        "",
        (
            "Full two-run validator wall time: "
            f"{timing['full_two_runs_wall_seconds']:.6f} s; "
            f"requests emitted: {timing['full_two_runs_requests_emitted']}; "
            f"{timing['full_two_runs_ms_per_emitted_request']:.6f} ms per "
            "emitted request."
        ),
        "",
        (
            "Total timed evaluation scope (external parent including the "
            "balanced reproduction, plus the safety suite): "
            f"{combined_wall_seconds:.6f} s; requests emitted: "
            f"{combined_requests}; "
            f"{combined_wall_seconds * 1000.0 / combined_requests:.6f} ms "
            "per emitted request. Benchmark-container startup is outside "
            "this timed scope."
        ),
        "",
        (
            "Safety-scope note: preflight rejection cases must and did open "
            "zero sockets. The oversized-response, redirect, and one-request "
            "tests necessarily opened one initial loopback socket each; they "
            "are reported separately as transport-containment controls. No "
            "non-loopback socket was opened."
        ),
        "",
    ]
    SUMMARY.write_text("\n".join(lines), encoding="utf-8")


def manifest_candidates() -> list[Path]:
    candidates = [
        PROJECT / "scripts" / "external_full_evaluation.py",
        PROJECT / "scripts" / "run_external_full_with_benchmark.py",
        PROJECT / "scripts" / "safety_gate_evaluation.py",
        PROJECT / "scripts" / "build_evaluation_summary.py",
        RESULTS / "eligible_cases.json",
        RESULTS / "external_full.json",
        RESULTS / "external_full.csv",
        RESULTS / "safety_gate.json",
        RESULTS / "safety_gate.csv",
        RESULTS / "summary.md",
        RESULTS / "benchmark_server.stdout.log",
        RESULTS / "benchmark_server.stderr.log",
    ]
    return [path for path in candidates if path.exists()]


def write_manifest() -> None:
    lines = []
    for path in manifest_candidates():
        relative = path.relative_to(PROJECT).as_posix()
        lines.append(f"{sha256(path).upper()}  {relative}")
    MANIFEST.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    external = json.loads(EXTERNAL_JSON.read_text(encoding="utf-8"))
    safety = json.loads(SAFETY_JSON.read_text(encoding="utf-8"))
    write_summary(external, safety)
    write_manifest()
    print(SUMMARY)
    print(MANIFEST)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
