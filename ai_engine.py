import json
import os
import sys

from openai import OpenAI


def read_sast_results(filename):
    with open(filename, "r", encoding="utf-8") as file:
        return json.load(file)


def main():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("Set OPENAI_API_KEY before running this helper.")
        return 1

    try:
        sast_data = read_sast_results("sast_results.json")
    except OSError as exc:
        print(f"Could not read sast_results.json: {exc}")
        return 1

    results = sast_data.get("results", [])
    if not results:
        print("No SAST findings found in sast_results.json.")
        return 0

    first_vuln = results[0]
    vuln_info = {
        "file": first_vuln.get("path"),
        "line": first_vuln.get("start", {}).get("line"),
        "message": first_vuln.get("extra", {}).get("message"),
        "cwe": first_vuln.get("extra", {}).get("metadata", {}).get("cwe"),
    }

    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        response_format={"type": "json_object"},
        messages=[
            {
                "role": "system",
                "content": (
                    "Return JSON with method, path, headers, params, json, data, "
                    "confidence_score, expected_signal, and reasoning for a harmless "
                    "authorized validation payload."
                ),
            },
            {"role": "user", "content": json.dumps(vuln_info, ensure_ascii=False)},
        ],
    )

    ai_payload = response.choices[0].message.content
    with open("dast_payload.json", "w", encoding="utf-8") as file:
        file.write(ai_payload)

    print(ai_payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
