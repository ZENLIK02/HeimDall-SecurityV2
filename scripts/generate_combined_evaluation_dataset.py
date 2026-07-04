from __future__ import annotations

import argparse
import json
from pathlib import Path


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Combine 300 synthetic alerts with active-local validation fixtures.")
    parser.add_argument("--base", default="test_data/heimdall_300_alerts.jsonl")
    parser.add_argument("--active", default="test_data/heimdall_active_local_alerts.jsonl")
    parser.add_argument("--output", default="test_data/heimdall_combined_ieee_alerts.jsonl")
    args = parser.parse_args()
    rows = read_jsonl(Path(args.base)) + read_jsonl(Path(args.active))
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"Wrote {len(rows)} combined alerts to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
