# Local Intentionally Vulnerable Flask App

This app is a local-only test target for Heimdall DevSecOps validation. It uses dummy data only and must not be deployed to a production network.

## Run

```bash
cd test_apps/flask_vulnerable_app
python -m pip install flask
python app.py
```

The app listens on `http://127.0.0.1:5000`.

## Endpoints

- `/xss?q=...` reflected XSS demonstration.
- `/login` SQL injection-like behavior using fake in-memory users.
- `/file?name=...` controlled path traversal simulation inside `safe_files`.
- `/user/<id>` IDOR simulation with dummy users.
