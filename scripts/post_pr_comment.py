from __future__ import annotations

import json
import os
from pathlib import Path
from urllib import request


def main() -> int:
    token = os.getenv("GITHUB_TOKEN")
    repo = os.getenv("GITHUB_REPOSITORY")
    event_path = os.getenv("GITHUB_EVENT_PATH")
    report = Path("reports/ci_summary.md")
    if not token or not repo or not event_path or not report.exists():
        print("Skipping PR comment: missing token, repository, event, or report.")
        return 0

    event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    pr = event.get("pull_request")
    if not pr:
        print("Skipping PR comment: not a pull_request event.")
        return 0

    body = report.read_text(encoding="utf-8")[:60000]
    url = f"https://api.github.com/repos/{repo}/issues/{pr['number']}/comments"
    payload = json.dumps({"body": body}).encode("utf-8")
    req = request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "Heimdall-DevSecOps",
        },
    )
    try:
        with request.urlopen(req, timeout=10) as response:
            print(f"Posted PR comment: HTTP {response.status}")
    except OSError as exc:
        print(f"Skipping PR comment after API error: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
