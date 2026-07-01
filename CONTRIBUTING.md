# Contributing

Thanks for helping test Heimdall-SecurityV2. This project is an alpha-stage DevSecOps validation backend, so clear bug reports and real workflow feedback are especially useful.

## Install

```bash
git clone https://github.com/ZENLIK02/HeimDall-SecurityV2.git
cd HeimDall-SecurityV2
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

For macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run Tests

```bash
pytest
```

## Run Sample Experiment

```bash
python -m heimdall.cli experiment --dataset data/sample_alerts.jsonl --mode all --output reports/
```

## Run Sample CI Validation

```bash
python -m heimdall.cli check-config --config heimdall.yml
python -m heimdall.cli validate --semgrep test_data/semgrep-results-sample.json --config heimdall.yml --output reports/
```

## Coding Style

- Keep validation safe by default.
- Prefer deterministic tests.
- Do not add real secrets, production URLs, or destructive payloads.
- Keep CLI output clear enough for CI logs.
- Preserve existing experiment and validate commands.

## Issues And Pull Requests

When opening issues or PRs, include:

- what command you ran,
- what you expected,
- what happened,
- relevant safe logs or sample data,
- whether the change affects safety policy.

Pull requests should include tests or a clear explanation when tests are not practical.
