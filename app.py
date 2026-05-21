import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import urljoin, urlparse

import requests
import streamlit as st
from openai import OpenAI


SEMGREP_CONFIGS = ["p/secrets", "p/python"]
SEVERITY_RANK = {"ERROR": 0, "WARNING": 1, "INFO": 2}
DEPENDENCY_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
}
MAX_UPLOAD_MB = 25


st.set_page_config(page_title="HeimDall AI-ASOC", page_icon="HD", layout="wide")

st.markdown(
    """
    <style>
    .stButton>button { width: 100%; border-radius: 8px; font-weight: 700; }
    .main-title { font-size: 2.35rem; font-weight: 800; color: #1E3A8A; text-align: center; margin-bottom: 0; }
    .sub-title { font-size: 1.05rem; color: #4B5563; text-align: center; margin-bottom: 1.8rem; }
    .small-note { color: #6B7280; font-size: .92rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


def normalize_zip_member(member_name):
    windows_path = PureWindowsPath(member_name)
    normalized_name = member_name.replace("\\", "/")
    posix_path = PurePosixPath(normalized_name)
    if windows_path.drive or windows_path.is_absolute() or posix_path.is_absolute():
        return None

    parts = [part for part in posix_path.parts if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        return None

    return Path(*parts)


def safe_extract_zip(uploaded_file, destination):
    extracted_files = 0
    skipped_files = []

    with zipfile.ZipFile(uploaded_file) as archive:
        for info in archive.infolist():
            relative_path = normalize_zip_member(info.filename)
            if relative_path is None:
                skipped_files.append(info.filename)
                continue

            path_parts = set(relative_path.parts)
            if path_parts & DEPENDENCY_DIRS:
                continue

            output_path = destination / relative_path
            if info.is_dir():
                output_path.mkdir(parents=True, exist_ok=True)
                continue

            output_path.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, open(output_path, "wb") as target:
                shutil.copyfileobj(source, target)
            extracted_files += 1

    return extracted_files, skipped_files


def run_semgrep(scan_dir, output_path, configs):
    command = ["semgrep", "scan"]
    for config in configs:
        command.extend(["--config", config])
    command.extend(["--json", "-o", str(output_path), str(scan_dir)])

    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=180)
    except FileNotFoundError:
        return None, "Semgrep is not installed in this environment."
    except subprocess.TimeoutExpired:
        return None, "Semgrep timed out after 180 seconds."

    if not output_path.exists():
        stderr = completed.stderr.strip() or completed.stdout.strip()
        return None, f"Semgrep did not create a JSON output file. {stderr}"

    with open(output_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    if completed.returncode not in (0, 1):
        stderr = completed.stderr.strip()
        data.setdefault("errors", []).append({"message": stderr or "Semgrep failed."})

    return data, None


def simplify_finding(finding, scan_root):
    path = str(finding.get("path", ""))
    try:
        display_path = str(Path(path).relative_to(scan_root))
    except ValueError:
        display_path = path.replace(str(scan_root), "").lstrip("\\/")

    extra = finding.get("extra", {})
    metadata = extra.get("metadata", {})

    return {
        "rule_id": finding.get("check_id", ""),
        "file": display_path,
        "line": finding.get("start", {}).get("line"),
        "severity": extra.get("severity", "INFO"),
        "message": extra.get("message", ""),
        "cwe": format_metadata_value(metadata.get("cwe")),
        "owasp": format_metadata_value(metadata.get("owasp")),
        "confidence": metadata.get("confidence", "UNKNOWN"),
        "category": metadata.get("category", "security"),
    }


def format_metadata_value(value):
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item) for item in value)
    return str(value)


def sort_findings(findings):
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_RANK.get(item["severity"], 3),
            item["file"],
            item["line"] or 0,
            item["rule_id"],
        ),
    )


def payload_prompt(finding, base_url):
    return [
        {
            "role": "system",
            "content": (
                "You are helping validate an authorized SAST finding in a lab app. "
                "Return only JSON with keys: method, path, headers, params, json, data, "
                "confidence_score, expected_signal, reasoning. "
                "Use the smallest harmless proof-of-concept payload possible. "
                "The path must be relative unless the finding clearly provides a route. "
                f"The target base URL is {base_url}."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(finding, ensure_ascii=False),
        },
    ]


def build_request(base_url, payload):
    raw_path = payload.get("path") or payload.get("url") or "/"
    parsed = urlparse(raw_path)
    if parsed.scheme and parsed.netloc:
        target_url = raw_path
    else:
        target_url = urljoin(base_url.rstrip("/") + "/", raw_path.lstrip("/"))

    return {
        "method": str(payload.get("method", "GET")).upper(),
        "url": target_url,
        "headers": payload.get("headers") or {},
        "params": payload.get("params") or {},
        "json": payload.get("json"),
        "data": payload.get("data"),
    }


def send_probe(request_spec):
    method = request_spec["method"]
    if method == "GET":
        return requests.get(
            request_spec["url"],
            headers=request_spec["headers"],
            params=request_spec["params"],
            timeout=10,
            allow_redirects=False,
        )

    return requests.request(
        method,
        request_spec["url"],
        headers=request_spec["headers"],
        params=request_spec["params"],
        json=request_spec["json"],
        data=request_spec["data"],
        timeout=10,
        allow_redirects=False,
    )


def heuristic_verdict(status_code, response_text, expected_signal):
    text = response_text.lower()
    signal = str(expected_signal or "").lower()

    suspicious_terms = [
        "sql",
        "sqlite",
        "syntax error",
        "traceback",
        "exception",
        "stack trace",
        "command not found",
        "root:",
        "uid=",
        "<script",
    ]
    if any(term in text for term in suspicious_terms):
        return "Likely True Positive", 80, "The response contains a common exploit/error signal."

    if signal and signal in text:
        return "Likely True Positive", 75, "The response contains the expected validation signal."

    if status_code >= 500:
        return "Needs Review", 60, "The target returned a server error after the probe."

    if status_code in (401, 403, 404, 405):
        return "Likely False Positive", 65, "The probed endpoint was blocked, missing, or unsupported."

    return "Needs Review", 50, "No strong positive or negative signal was observed."


with st.sidebar:
    st.header("Settings")
    user_api_key = st.text_input(
        "OpenAI API Key",
        type="password",
        value=os.getenv("OPENAI_API_KEY", ""),
        help="Optional for SAST-only mode. Required for payload generation and AI validation.",
    )
    target_url = st.text_input("DAST Target URL", placeholder="http://localhost:3000")
    consent = st.checkbox("I own or am authorized to test this target")
    custom_configs = st.text_input("Semgrep configs", value=", ".join(SEMGREP_CONFIGS))

st.markdown('<p class="main-title">HeimDall AI-ASOC</p>', unsafe_allow_html=True)
st.markdown(
    '<p class="sub-title">Upload a source ZIP, rank SAST findings, then optionally validate one against an authorized target.</p>',
    unsafe_allow_html=True,
)

uploaded_file = st.file_uploader("Upload source code ZIP", type=["zip"])
run_btn = st.button("Run SAST Scan", type="primary")

if "findings" not in st.session_state:
    st.session_state.findings = []
if "semgrep_errors" not in st.session_state:
    st.session_state.semgrep_errors = []

if run_btn:
    if not uploaded_file:
        st.error("Please upload a .zip file first.")
    elif uploaded_file.size > MAX_UPLOAD_MB * 1024 * 1024:
        st.error(f"Upload is too large. Please keep ZIP files under {MAX_UPLOAD_MB} MB.")
    else:
        configs = [item.strip() for item in custom_configs.split(",") if item.strip()]
        st.session_state.findings = []
        st.session_state.semgrep_errors = []

        with tempfile.TemporaryDirectory(prefix="heimdall_scan_") as temp_root:
            temp_path = Path(temp_root)
            scan_dir = temp_path / "source"
            output_path = temp_path / "sast_results.json"
            scan_dir.mkdir(parents=True, exist_ok=True)

            with st.status("Preparing source and running Semgrep...", expanded=True) as status:
                try:
                    extracted_count, skipped_files = safe_extract_zip(uploaded_file, scan_dir)
                except zipfile.BadZipFile:
                    st.error("The uploaded file is not a valid ZIP archive.")
                    st.stop()

                st.write(f"Extracted {extracted_count} source files.")
                if skipped_files:
                    st.warning(f"Skipped {len(skipped_files)} unsafe archive paths.")

                if extracted_count == 0:
                    st.error("No source files were extracted from the ZIP.")
                    st.stop()

                st.write("Running Semgrep...")
                sast_data, semgrep_error = run_semgrep(scan_dir, output_path, configs)
                if semgrep_error:
                    st.error(semgrep_error)
                    st.stop()

                raw_findings = sast_data.get("results", [])
                findings = [simplify_finding(finding, scan_dir) for finding in raw_findings]
                st.session_state.findings = sort_findings(findings)
                st.session_state.semgrep_errors = sast_data.get("errors", [])
                status.update(label="SAST scan complete", state="complete", expanded=False)

if st.session_state.semgrep_errors:
    with st.expander("Semgrep warnings and errors"):
        st.json(st.session_state.semgrep_errors)

findings = st.session_state.findings
if findings:
    st.subheader("Ranked SAST Findings")
    st.dataframe(findings, width="stretch", hide_index=True)

    finding_labels = [
        f"{idx + 1}. [{finding['severity']}] {finding['rule_id']} - {finding['file']}:{finding['line']}"
        for idx, finding in enumerate(findings)
    ]
    selected_index = st.selectbox(
        "Choose one finding to validate",
        range(len(finding_labels)),
        format_func=lambda index: finding_labels[index],
    )
    selected_finding = findings[selected_index]

    left, right = st.columns(2)
    with left:
        st.subheader("Selected Finding")
        st.json(selected_finding)

    with right:
        st.subheader("Validation")
        can_generate = bool(user_api_key)
        if not can_generate:
            st.info("Add an OpenAI API key to generate a validation payload.")
        if not target_url:
            st.info("Add a DAST target URL to send a live validation request.")
        if target_url and not consent:
            st.warning("Confirm authorization before sending DAST traffic.")

        if st.button("Generate Payload and Validate", disabled=not can_generate):
            client = OpenAI(api_key=user_api_key)
            base_url = target_url.strip() or "http://localhost"

            with st.spinner("Generating a focused validation payload..."):
                payload_response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    response_format={"type": "json_object"},
                    messages=payload_prompt(selected_finding, base_url),
                )
                payload = json.loads(payload_response.choices[0].message.content)

            st.write("Generated payload")
            st.json(payload)

            if target_url and consent:
                request_spec = build_request(base_url, payload)
                st.write("Request")
                st.json(request_spec)

                try:
                    response = send_probe(request_spec)
                    response_text = response.text[:1200]
                    verdict, confidence, reason = heuristic_verdict(
                        response.status_code,
                        response_text,
                        payload.get("expected_signal"),
                    )

                    with st.spinner("Asking AI to review the HTTP evidence..."):
                        ai_review = client.chat.completions.create(
                            model="gpt-4o-mini",
                            response_format={"type": "json_object"},
                            messages=[
                                {
                                    "role": "system",
                                    "content": (
                                        "Return JSON with verdict, confidence, and reason. "
                                        "Use only the provided SAST finding and HTTP evidence. "
                                        "Do not claim exploitation succeeded unless the evidence supports it."
                                    ),
                                },
                                {
                                    "role": "user",
                                    "content": json.dumps(
                                        {
                                            "finding": selected_finding,
                                            "request": request_spec,
                                            "status_code": response.status_code,
                                            "response_excerpt": response_text,
                                            "heuristic_verdict": verdict,
                                            "heuristic_confidence": confidence,
                                            "heuristic_reason": reason,
                                        },
                                        ensure_ascii=False,
                                    ),
                                },
                            ],
                        )
                    ai_verdict = json.loads(ai_review.choices[0].message.content)

                    st.metric("HTTP status", response.status_code)
                    st.write("Heuristic verdict")
                    st.json({"verdict": verdict, "confidence": confidence, "reason": reason})
                    st.write("AI verdict")
                    st.json(ai_verdict)
                    with st.expander("Response excerpt"):
                        st.code(response_text)
                except requests.RequestException as exc:
                    st.error(f"DAST request failed: {exc}")
            else:
                st.info("Payload generated only. Add target URL and authorization consent to run DAST.")
elif run_btn:
    st.success("No Semgrep findings were detected.")
