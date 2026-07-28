from __future__ import annotations

import argparse
import json
import sys
import threading
from pathlib import Path

from werkzeug.serving import make_server

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from heimdall.cli import _run_bounded_dast
from local_lab.vulnerable_app.app import app
from scripts.generate_active_local_dataset import SEED, generate_dataset, write_distribution


def write_dataset(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the 180-alert controlled bounded DAST evaluation."
    )
    parser.add_argument(
        "--dataset",
        default="test_data/heimdall_active_local_alerts.jsonl",
    )
    parser.add_argument(
        "--distribution",
        default="test_data/heimdall_active_local_alerts_distribution.json",
    )
    parser.add_argument("--config", default="heimdall.yml")
    parser.add_argument("--output", default="reports/bounded_dast_controlled")
    args = parser.parse_args()

    rows = generate_dataset(SEED)
    dataset_path = Path(args.dataset)
    write_dataset(dataset_path, rows)
    write_distribution(Path(args.distribution), rows, SEED)

    server = make_server("127.0.0.1", 5005, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        return _run_bounded_dast(
            str(dataset_path),
            str(args.config),
            str(args.output),
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
