# Heimdall Demo CI/CD Summary

This is a static demo CI report for public users. It contains no real vulnerabilities, secrets, or production URLs.

Pipeline status: PASSED

| Metric | Count |
|---|---:|
| Total Semgrep findings | 4 |
| Total validated findings | 4 |
| Confirmed True Positives | 0 |
| False Positives | 3 |
| Needs Review | 1 |
| High/Critical confirmed vulnerabilities | 0 |

## Findings

| Rule ID | Severity | File | Line | Heimdall Decision | Evidence | Recommended Action |
|---|---|---|---:|---|---|---|
| python.flask.security.xss.reflected-xss | high | test_apps/flask_vulnerable_app/app.py | 18 | False Positive | Controlled marker appears escaped or inert. | Document the defensive control or tune the SAST rule. |
| python.flask.security.sql-injection | high | test_apps/flask_vulnerable_app/app.py | 25 | False Positive | Input rejected or authentication failed without SQL error. | Review the query construction and prefer parameterized queries. |
| python.flask.security.idor | low | test_apps/flask_vulnerable_app/app.py | 47 | Needs Review | Authentication context is required. | Review manually before active validation. |
