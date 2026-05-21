# HeimDall AI-ASOC

HeimDall is a Streamlit-based security lab tool for combining SAST findings with optional DAST-style validation. Upload a source-code ZIP, let Semgrep rank the findings, then choose one finding for AI-assisted payload generation and evidence review.

This project is intended for authorized testing and classroom/lab use only.

## What Improved

- Safe ZIP extraction blocks path traversal and skips dependency folders such as `node_modules`, `.git`, and `__pycache__`.
- SAST-only mode no longer requires an OpenAI API key.
- Semgrep failures are shown clearly instead of silently producing empty results.
- All findings are ranked and displayed instead of only using the first result.
- Users choose which finding to validate.
- DAST validation requires an explicit authorization checkbox.
- AI verdicts are combined with simple HTTP-response heuristics for better accuracy.
- API keys are read from Streamlit input or `OPENAI_API_KEY`, not hardcoded in source files.

## Local Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

For macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Using The App

1. Prepare a small source-code ZIP, such as `website_easy_sast_test.zip`.
2. Upload the ZIP in the HeimDall web UI.
3. Click `Run SAST Scan`.
4. Review the ranked Semgrep findings.
5. Optionally add your OpenAI API key, a target URL that you own or are authorized to test, and confirm authorization.
6. Choose a finding and click `Generate Payload and Validate`.

## Useful Environment Variables

```bash
set OPENAI_API_KEY=sk-...
set HEIMDALL_TARGET_URL=http://localhost:3000
```

`HEIMDALL_TARGET_URL` is used by the optional `dast_executor.py` helper. The main Streamlit app uses the target URL field in the sidebar.
