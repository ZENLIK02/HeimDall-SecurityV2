# Heimdall Local Vulnerable App

This intentionally vulnerable Flask app is a localhost-only fixture for Heimdall active-local validation. It uses fake data, fake secrets, in-memory state, and controlled evidence markers across twelve vulnerability categories.

Run:

```bash
python local_lab/vulnerable_app/app.py
```

The app listens on `http://127.0.0.1:5005`.

Safety properties:

- No real shell commands are executed.
- No real sensitive files are read.
- No outbound SSRF request is sent.
- External redirects are not followed by the evaluator; only the local Location header is inspected.
- Deserialization and business-logic cases are safe simulations.
- All secrets are fake test fixtures.
- The app is not for deployment.
