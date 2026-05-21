import json
import os
import sys
from urllib.parse import urljoin, urlparse

import requests
from openai import OpenAI


def build_url(base_url, raw_path):
    parsed = urlparse(raw_path)
    if parsed.scheme and parsed.netloc:
        return raw_path
    return urljoin(base_url.rstrip("/") + "/", str(raw_path or "/").lstrip("/"))


def main():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("Set OPENAI_API_KEY before running this helper.")
        return 1

    base_url = os.getenv("HEIMDALL_TARGET_URL", "http://localhost:3000")

    try:
        with open("dast_payload.json", "r", encoding="utf-8") as file:
            payload = json.load(file)
    except OSError as exc:
        print(f"Could not read dast_payload.json: {exc}")
        return 1

    method = str(payload.get("method", "GET")).upper()
    target_url = build_url(base_url, payload.get("path") or payload.get("url") or "/")
    headers = payload.get("headers") or {}
    params = payload.get("params") or {}
    json_body = payload.get("json")
    data = payload.get("data")

    try:
        response = requests.request(
            method,
            target_url,
            headers=headers,
            params=params,
            json=json_body,
            data=data,
            timeout=10,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        print(f"DAST request failed: {exc}")
        return 1

    evidence = {
        "method": method,
        "url": target_url,
        "status_code": response.status_code,
        "response_excerpt": response.text[:1200],
    }

    client = OpenAI(api_key=api_key)
    ai_response = client.chat.completions.create(
        model="gpt-4o-mini",
        response_format={"type": "json_object"},
        messages=[
            {
                "role": "system",
                "content": "Return JSON with verdict, confidence, and reason based only on the HTTP evidence.",
            },
            {"role": "user", "content": json.dumps(evidence, ensure_ascii=False)},
        ],
    )

    print(json.dumps(evidence, indent=2, ensure_ascii=False))
    print(ai_response.choices[0].message.content)
    return 0


if __name__ == "__main__":
    sys.exit(main())
