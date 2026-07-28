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
elif command -v py >/dev/null 2>&1; then
  PYTHON_BIN="py -3"
else
  echo "Python was not found on PATH." >&2
  exit 3
fi

if ! $PYTHON_BIN -c "import PIL, reportlab" >/dev/null 2>&1; then
  echo "Installing report dependencies required for PNG/PDF generation..."
  EVAL_VENV=".heimdall_eval_venv"
  if [[ ! -x "$EVAL_VENV/bin/python" ]]; then
    $PYTHON_BIN -m venv "$EVAL_VENV" >/dev/null 2>&1 || true
  fi
  if [[ -x "$EVAL_VENV/bin/python" ]] && "$EVAL_VENV/bin/python" -m pip --version >/dev/null 2>&1; then
    PYTHON_BIN="$EVAL_VENV/bin/python"
    $PYTHON_BIN -m pip install --upgrade pip >/dev/null
    $PYTHON_BIN -m pip install Pillow reportlab >/dev/null
  else
    $PYTHON_BIN -m pip install --user --break-system-packages Pillow reportlab
  fi
fi

DATASET="test_data/heimdall_300_alerts.jsonl"
REPORT_DIR="reports/300_alert_eval"
PDF_PATH="$REPORT_DIR/HeimdallV2_300_Alert_Evaluation_Summary.pdf"

$PYTHON_BIN scripts/generate_300_alert_dataset.py --output "$DATASET"
$PYTHON_BIN experiments/run_experiment.py --dataset "$DATASET" --mode all --output "$REPORT_DIR"
$PYTHON_BIN scripts/generate_300_alert_pdf_report.py --dataset "$DATASET" --report-dir "$REPORT_DIR"

echo "Final PDF: $PDF_PATH"
