#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -n "${PYTHON:-}" ]]; then
  PYTHON_BIN="$PYTHON"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "Python was not found on PATH." >&2
  exit 3
fi

if ! $PYTHON_BIN -c "import flask, PIL, reportlab, pytest" >/dev/null 2>&1; then
  EVAL_VENV=".heimdall_eval_venv"
  if [[ ! -x "$EVAL_VENV/bin/python" ]]; then
    $PYTHON_BIN -m venv "$EVAL_VENV" >/dev/null 2>&1 || true
  fi
  if [[ -x "$EVAL_VENV/bin/python" ]] && "$EVAL_VENV/bin/python" -m pip --version >/dev/null 2>&1; then
    PYTHON_BIN="$EVAL_VENV/bin/python"
    $PYTHON_BIN -m pip install --upgrade pip >/dev/null
    $PYTHON_BIN -m pip install Flask Pillow reportlab pytest >/dev/null
  else
    $PYTHON_BIN -m pip install --user --break-system-packages Flask Pillow reportlab pytest >/dev/null
  fi
fi

BASE_DATASET="test_data/heimdall_300_alerts.jsonl"
ACTIVE_DATASET="test_data/heimdall_active_local_alerts.jsonl"
COMBINED_DATASET="test_data/heimdall_combined_360_alerts.jsonl"
REPORT_DIR="reports/ieee_ready_eval"
PDF_PATH="$REPORT_DIR/HeimdallV2_IEEE_Ready_Evaluation_Summary.pdf"

mkdir -p "$REPORT_DIR"

$PYTHON_BIN scripts/generate_300_alert_dataset.py --output "$BASE_DATASET"
$PYTHON_BIN scripts/generate_active_local_dataset.py --output "$ACTIVE_DATASET" --profile legacy60
$PYTHON_BIN scripts/generate_combined_evaluation_dataset.py --base "$BASE_DATASET" --active "$ACTIVE_DATASET" --output "$COMBINED_DATASET"

$PYTHON_BIN local_lab/vulnerable_app/app.py > "$REPORT_DIR/local_vulnerable_app.log" 2>&1 &
APP_PID=$!
cleanup() {
  kill "$APP_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

$PYTHON_BIN - <<'PY'
import sys
import time
import urllib.request

for _ in range(40):
    try:
        with urllib.request.urlopen("http://127.0.0.1:5005/health", timeout=1) as response:
            if response.status == 200:
                sys.exit(0)
    except Exception:
        time.sleep(0.25)
print("Local vulnerable app did not become healthy on 127.0.0.1:5005", file=sys.stderr)
sys.exit(2)
PY

$PYTHON_BIN experiments/run_experiment.py --dataset "$COMBINED_DATASET" --mode all --output "$REPORT_DIR"
$PYTHON_BIN scripts/generate_ieee_ready_report.py --dataset "$COMBINED_DATASET" --report-dir "$REPORT_DIR"
$PYTHON_BIN -m pytest

echo "Final PDF: $PDF_PATH"
echo "Paper draft: paper/HeimdallV2_IEEE_Updated.md"
