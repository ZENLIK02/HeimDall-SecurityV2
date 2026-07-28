from __future__ import annotations

import argparse
import signal
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import psutil


PROJECT = Path(__file__).resolve().parents[1]
WORK_ROOT = PROJECT.parent
DEFAULT_BENCHMARK = Path(
    r"C:\Users\User\Documents\Codex\2026-07-25\figure-out-next-steps"
    r"\work\external_validation\BenchmarkJava"
)
DEFAULT_MAVEN = Path(
    r"C:\Users\User\Documents\Codex\2026-07-25\figure-out-next-steps"
    r"\work\external_validation\apache-maven-3.9.11\bin\mvn.cmd"
)
DEFAULT_CONFIG = WORK_ROOT / "external_validation" / "heimdall_owasp_benchmark.yml"
DEFAULT_BALANCED_REFERENCE = (
    WORK_ROOT / "external_validation" / "owasp_benchmark_pilot_results.json"
)
HEALTH_URL = "https://127.0.0.1:8443/benchmark/"

from external_full_evaluation import verify_frozen_hashes


def healthy() -> bool:
    context = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(
            HEALTH_URL,
            timeout=2,
            context=context,
        ) as response:
            return response.status > 0
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark", default=str(DEFAULT_BENCHMARK))
    parser.add_argument("--maven", default=str(DEFAULT_MAVEN))
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument(
        "--balanced-reference",
        default=str(DEFAULT_BALANCED_REFERENCE),
    )
    return parser.parse_args()


def invoke_evaluation(args: argparse.Namespace) -> int:
    command = [
        sys.executable,
        str(PROJECT / "scripts" / "external_full_evaluation.py"),
        "--benchmark",
        args.benchmark,
        "--config",
        args.config,
        "--balanced-reference",
        args.balanced_reference,
    ]
    return subprocess.run(command, check=False).returncode


def benchmark_tomcat_pids(benchmark: Path) -> set[int]:
    marker = str(benchmark).lower()
    output: set[int] = set()
    for process in psutil.process_iter(["pid", "cmdline"]):
        try:
            command = " ".join(process.info["cmdline"] or []).lower()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
        if (
            marker in command
            and "org.apache.catalina.startup.bootstrap" in command
        ):
            output.add(int(process.info["pid"]))
    return output


def stop_owned_tomcat_children(
    benchmark: Path,
    preexisting_pids: set[int],
) -> None:
    owned_pids = benchmark_tomcat_pids(benchmark) - preexisting_pids
    processes = []
    for pid in sorted(owned_pids):
        try:
            process = psutil.Process(pid)
            process.terminate()
            processes.append(process)
        except psutil.NoSuchProcess:
            continue
    _, alive = psutil.wait_procs(processes, timeout=5)
    for process in alive:
        process.kill()
    psutil.wait_procs(alive, timeout=5)


def main() -> int:
    args = parse_args()
    config_path = Path(args.config)
    benchmark_path = Path(args.benchmark)
    verify_frozen_hashes(config_path, "benchmark harness before")

    if healthy():
        print("Using already-running loopback BenchmarkJava container.")
        exit_code = invoke_evaluation(args)
        verify_frozen_hashes(config_path, "benchmark harness after")
        return exit_code

    stdout_path = PROJECT / "results" / "benchmark_server.stdout.log"
    stderr_path = PROJECT / "results" / "benchmark_server.stderr.log"
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stdout = stdout_path.open("w", encoding="utf-8")
    stderr = stderr_path.open("w", encoding="utf-8")
    flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    preexisting_tomcat_pids = benchmark_tomcat_pids(benchmark_path)
    process = subprocess.Popen(
        [args.maven, "cargo:run", "-Pdeploy"],
        cwd=benchmark_path,
        stdout=stdout,
        stderr=stderr,
        creationflags=flags,
    )
    try:
        print(
            "Started OWASP BenchmarkJava in its local Cargo/Tomcat "
            "container on https://127.0.0.1:8443."
        )
        for _ in range(360):
            if healthy():
                return invoke_evaluation(args)
            if process.poll() is not None:
                raise RuntimeError(
                    "BenchmarkJava container exited with code "
                    f"{process.returncode}; see {stderr_path}"
                )
            time.sleep(0.5)
        raise RuntimeError(
            "BenchmarkJava container did not become healthy within 180 s"
        )
    finally:
        if process.poll() is None:
            process.send_signal(signal.CTRL_BREAK_EVENT)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        stdout.close()
        stderr.close()
        stop_owned_tomcat_children(
            benchmark_path,
            preexisting_tomcat_pids,
        )
        verify_frozen_hashes(config_path, "benchmark harness after")


if __name__ == "__main__":
    raise SystemExit(main())
