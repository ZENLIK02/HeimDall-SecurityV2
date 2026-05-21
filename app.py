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
    :root {
        --heimdall-blue: #2563eb;
        --heimdall-ink: #f8fafc;
        --heimdall-muted: #cbd5e1;
        --heimdall-line: rgba(148, 163, 184, .28);
        --heimdall-soft: rgba(37, 99, 235, .14);
        --heimdall-panel: rgba(15, 23, 42, .68);
    }

    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1180px;
    }

    .stButton>button {
        width: 100%;
        border-radius: 8px;
        font-weight: 700;
        min-height: 2.75rem;
        border: 1px solid var(--heimdall-line);
        transition: transform .16s ease, box-shadow .16s ease, border-color .16s ease;
    }

    .stButton>button:hover {
        transform: translateY(-1px);
        box-shadow: 0 10px 24px rgba(15, 23, 42, .12);
        border-color: rgba(37, 99, 235, .45);
    }

    .main-title {
        font-size: 2.45rem;
        font-weight: 850;
        color: var(--heimdall-ink);
        text-align: center;
        margin-bottom: .35rem;
        letter-spacing: 0;
    }

    .sub-title {
        font-size: 1.05rem;
        color: var(--heimdall-muted);
        text-align: center;
        margin-bottom: 1.4rem;
    }

    .hero-block {
        border: 1px solid var(--heimdall-line);
        border-radius: 8px;
        padding: 1.4rem 1.25rem;
        margin-bottom: 1.25rem;
        background: linear-gradient(180deg, rgba(37, 99, 235, .16), rgba(15, 23, 42, .72));
    }

    .section-heading {
        border: 1px solid var(--heimdall-line);
        border-left: 5px solid var(--heimdall-blue);
        border-radius: 8px;
        padding: .9rem 1rem;
        margin: 1.15rem 0 .7rem 0;
        background: linear-gradient(90deg, rgba(37, 99, 235, .18), rgba(15, 23, 42, .62));
        box-shadow: 0 8px 22px rgba(15, 23, 42, .05);
    }

    .section-heading h2 {
        margin: 0;
        color: var(--heimdall-ink);
        font-size: 1.12rem;
        line-height: 1.35;
        letter-spacing: 0;
    }

    .section-heading p {
        margin: .25rem 0 0 0;
        color: var(--heimdall-muted);
        font-size: .92rem;
    }

    div[data-testid="stVerticalBlockBorderWrapper"] {
        border-radius: 8px;
        border-color: var(--heimdall-line);
        box-shadow: 0 10px 26px rgba(15, 23, 42, .06);
    }

    div[data-testid="stExpander"] {
        border-radius: 8px;
        border-color: var(--heimdall-line);
        overflow: hidden;
    }

    div[data-testid="stMetric"] {
        border: 1px solid var(--heimdall-line);
        border-radius: 8px;
        padding: .85rem 1rem;
        background: rgba(148, 163, 184, .06);
    }

    .small-note { color: var(--heimdall-muted); font-size: .92rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


def section_header(title, description=""):
    description_html = f"<p>{description}</p>" if description else ""
    st.markdown(
        f"""
        <div class="section-heading">
            <h2>{title}</h2>
            {description_html}
        </div>
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


def static_fix_guidance(finding):
    rule_text = f"{finding.get('rule_id', '')} {finding.get('message', '')}".lower()

    if "sql" in rule_text or "sqli" in rule_text:
        return {
            "risk": "User input may reach a SQL query without parameterization.",
            "fix_steps": [
                "Replace string-built SQL with parameterized queries or ORM-safe filters.",
                "Validate expected input shape before querying.",
                "Avoid returning raw database errors to users.",
            ],
            "safe_pattern": "cursor.execute('SELECT * FROM users WHERE name = ?', (username,))",
        }

    if "command" in rule_text or "shell" in rule_text or "subprocess" in rule_text:
        return {
            "risk": "User input may be executed by the operating system.",
            "fix_steps": [
                "Avoid shell=True.",
                "Pass command arguments as a list.",
                "Allowlist expected values such as known hostnames or commands.",
            ],
            "safe_pattern": "subprocess.run(['ping', '-c', '1', host], check=True, capture_output=True, text=True)",
        }

    if "xss" in rule_text or "html" in rule_text:
        return {
            "risk": "User-controlled text may be rendered as HTML or script.",
            "fix_steps": [
                "Render user text as plain text.",
                "Escape or sanitize HTML with a trusted sanitizer.",
                "Avoid unsafe HTML rendering unless the content is trusted.",
            ],
            "safe_pattern": "st.write(display_name)",
        }

    if "secret" in rule_text or "credential" in rule_text or "password" in rule_text:
        return {
            "risk": "A secret or credential appears to be stored in source code.",
            "fix_steps": [
                "Move the secret to environment variables or a secret manager.",
                "Rotate the exposed credential immediately.",
                "Add secret scanning to CI before code is merged.",
            ],
            "safe_pattern": "api_key = os.getenv('OPENAI_API_KEY')",
        }

    if "pickle" in rule_text or "deserialization" in rule_text or "yaml.load" in rule_text:
        return {
            "risk": "Untrusted serialized data may lead to code execution.",
            "fix_steps": [
                "Do not deserialize untrusted data with unsafe loaders.",
                "Use JSON or a strict schema for user-provided data.",
                "For YAML, use yaml.safe_load instead of yaml.load.",
            ],
            "safe_pattern": "config = yaml.safe_load(user_yaml)",
        }

    if "md5" in rule_text or "sha1" in rule_text or "weak" in rule_text:
        return {
            "risk": "Weak cryptography may make stored values easier to crack or forge.",
            "fix_steps": [
                "Use a modern password hashing function for passwords.",
                "Use SHA-256 or stronger only for non-password integrity hashing.",
                "Add salts and work factors where appropriate.",
            ],
            "safe_pattern": "hashlib.sha256(data).hexdigest()",
        }

    return {
        "risk": "This pattern may be unsafe depending on runtime context.",
        "fix_steps": [
            "Trace whether user-controlled input can reach the reported code.",
            "Add validation, encoding, or parameterization at the trust boundary.",
            "Add a regression test that covers the vulnerable data flow.",
        ],
        "safe_pattern": "Review the Semgrep message and replace the risky data flow with a framework-safe API.",
    }


def payload_prompt(finding, base_url):
    return [
        {
            "role": "system",
            "content": (
                "You are helping validate an authorized SAST finding in a lab app. "
                "Return only JSON with keys: method, path, headers, params, json, data, "
                "confidence_score, expected_signal, reasoning. "
                "Use the smallest harmless proof-of-concept payload possible. "
                "Do not invent API endpoints. If the finding does not clearly provide "
                "an HTTP route, use path '/' and explain the uncertainty in reasoning. "
                "For Streamlit apps, most user interactions are not normal REST routes, "
                "so prefer '/' unless a real endpoint is visible in the finding. "
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
            allow_redirects=True,
        )

    return requests.request(
        method,
        request_spec["url"],
        headers=request_spec["headers"],
        params=request_spec["params"],
        json=request_spec["json"],
        data=request_spec["data"],
        timeout=10,
        allow_redirects=True,
    )


def summarize_response(response):
    redirect_chain = [
        {
            "status_code": item.status_code,
            "url": item.url,
            "location": item.headers.get("Location", ""),
        }
        for item in response.history
    ]
    body = response.text or ""

    return {
        "status_code": response.status_code,
        "original_url": response.request.url if response.request else "",
        "final_url": response.url,
        "redirect_chain": redirect_chain,
        "content_type": response.headers.get("Content-Type", ""),
        "body_length": len(body),
        "headers": dict(response.headers),
        "body_excerpt": body[:1200],
    }


def response_excerpt_for_display(evidence):
    if evidence["body_excerpt"]:
        return evidence["body_excerpt"]

    lines = [
        "No response body was returned.",
        f"HTTP status: {evidence['status_code']}",
        f"Original URL: {evidence['original_url']}",
        f"Final URL: {evidence['final_url']}",
        f"Content-Type: {evidence['content_type'] or '(none)'}",
    ]
    if evidence["redirect_chain"]:
        lines.append("Redirect chain:")
        for redirect in evidence["redirect_chain"]:
            location = redirect["location"] or redirect["url"]
            lines.append(f"- {redirect['status_code']} -> {location}")

    return "\n".join(lines)


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


def final_validation_status(heuristic_verdict_text, ai_verdict):
    combined = f"{heuristic_verdict_text} {ai_verdict.get('verdict', '')}".lower()

    if "true positive" in combined or "likely true positive" in combined:
        return "True Positive", False
    if "false positive" in combined or "likely false positive" in combined:
        return "False Positive", True
    return "Needs Review", None


def normalize_optional_bool(value):
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("true", "yes", "1"):
            return True
        if normalized in ("false", "no", "0"):
            return False
    return None


def render_validation_status(status, is_false_positive):
    is_false_positive = normalize_optional_bool(is_false_positive)

    if status == "True Positive":
        st.error("Validation Status: True Positive")
        st.write("This finding looks real enough that a developer should fix it.")
    elif status == "False Positive":
        st.success("Validation Status: False Positive")
        st.write("The available evidence does not show an exploitable issue.")
    else:
        st.warning("Validation Status: Needs Review")
        st.write("Heimdall does not have enough evidence to safely call this true or false.")

    if is_false_positive is None:
        st.metric("False positive?", "Unclear")
    else:
        st.metric("False positive?", "Yes" if is_false_positive else "No")


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

st.markdown(
    """
    <div class="hero-block">
        <p class="main-title">HeimDall AI-ASOC</p>
        <p class="sub-title">Correlate SAST findings with live HTTP evidence, then produce a developer-ready validation report.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

section_header("Source Upload", "Upload a ZIP file, then HeimDall extracts only source files and runs Semgrep.")
with st.container(border=True):
    upload_col, scan_col = st.columns([3, 1])
    with upload_col:
        uploaded_file = st.file_uploader("Upload source code ZIP", type=["zip"])
    with scan_col:
        st.write("")
        st.write("")
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
    section_header("Semgrep Messages", "Warnings or tool errors from the scan are shown here.")
    with st.expander("Semgrep warnings and errors"):
        st.json(st.session_state.semgrep_errors)

findings = st.session_state.findings
if findings:
    section_header("Ranked SAST Findings", "Findings are sorted by severity, file, and line so the riskiest items stay near the top.")
    with st.container(border=True):
        st.dataframe(findings, width="stretch", hide_index=True)

    finding_labels = [
        f"{idx + 1}. [{finding['severity']}] {finding['rule_id']} - {finding['file']}:{finding['line']}"
        for idx, finding in enumerate(findings)
    ]
    section_header("Finding Selection", "Choose one alert for AI-assisted payload generation and optional DAST validation.")
    with st.container(border=True):
        selected_index = st.selectbox(
            "Choose one finding to validate",
            range(len(finding_labels)),
            format_func=lambda index: finding_labels[index],
        )
    selected_finding = findings[selected_index]

    left, right = st.columns(2)
    with left:
        section_header("Selected Finding", "The normalized Semgrep result that HeimDall will reason over.")
        with st.container(border=True):
            st.json(selected_finding)
        section_header("Developer Guidance", "Immediate fix advice based on the vulnerability class.")
        with st.container(border=True):
            st.json(static_fix_guidance(selected_finding))

    with right:
        section_header("Validation", "Generate a focused payload and, when authorized, validate it against the target.")
        with st.container(border=True):
            can_generate = bool(user_api_key)
            if not can_generate:
                st.info("Add an OpenAI API key to generate a validation payload.")
            if not target_url:
                st.info("Add a DAST target URL to send a live validation request.")
            if target_url and not consent:
                st.warning("Confirm authorization before sending DAST traffic.")

            validate_btn = st.button("Generate Payload and Validate", disabled=not can_generate)

        if validate_btn:
            client = OpenAI(api_key=user_api_key)
            base_url = target_url.strip() or "http://localhost"

            with st.spinner("Generating a focused validation payload..."):
                payload_response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    response_format={"type": "json_object"},
                    messages=payload_prompt(selected_finding, base_url),
                )
                payload = json.loads(payload_response.choices[0].message.content)

            section_header("Generated Payload", "The AI-generated request candidate used for validation.")
            with st.container(border=True):
                st.json(payload)

            if target_url and consent:
                request_spec = build_request(base_url, payload)
                section_header("Request", "The exact HTTP request HeimDall will send to the authorized target.")
                with st.container(border=True):
                    st.json(request_spec)

                try:
                    response = send_probe(request_spec)
                    response_evidence = summarize_response(response)
                    response_text = response_evidence["body_excerpt"]
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
                                        "Return JSON with keys: verdict, is_false_positive, confidence, "
                                        "reason, evidence_summary, developer_fix_summary, fix_steps, "
                                        "suggested_code_change, and test_recommendation. "
                                        "verdict must be one of: True Positive, False Positive, Needs Review. "
                                        "is_false_positive must be true, false, or null. "
                                        "Use only the provided SAST finding and HTTP evidence. "
                                        "Do not claim exploitation succeeded unless the evidence supports it. "
                                        "Write developer-facing remediation advice aligned with an AI-ASOC report: "
                                        "validation status, targeted payload evidence, HTTP evidence, and fix guidance."
                                    ),
                                },
                                {
                                    "role": "user",
                                    "content": json.dumps(
                                        {
                                            "finding": selected_finding,
                                            "request": request_spec,
                                            "response": response_evidence,
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
                    final_status, is_false_positive = final_validation_status(verdict, ai_verdict)

                    section_header("Validation Result", "The final true-positive or false-positive decision.")
                    with st.container(border=True):
                        st.metric("HTTP status", response.status_code)
                        render_validation_status(
                            ai_verdict.get("verdict", final_status),
                            normalize_optional_bool(ai_verdict.get("is_false_positive", is_false_positive)),
                        )
                    section_header("Decision Evidence", "Heuristic and AI reasoning behind the final validation status.")
                    with st.container(border=True):
                        st.json(
                            {
                                "heuristic": {"verdict": verdict, "confidence": confidence, "reason": reason},
                                "ai": {
                                    "verdict": ai_verdict.get("verdict", final_status),
                                    "confidence": ai_verdict.get("confidence", "UNKNOWN"),
                                    "reason": ai_verdict.get("reason", ""),
                                    "evidence_summary": ai_verdict.get("evidence_summary", ""),
                                },
                            }
                        )
                    section_header("Developer Fix", "Concrete remediation steps to hand to the engineering team.")
                    with st.container(border=True):
                        st.json(
                            {
                                "summary": ai_verdict.get("developer_fix_summary", ""),
                                "fix_steps": ai_verdict.get("fix_steps", static_fix_guidance(selected_finding)["fix_steps"]),
                                "suggested_code_change": ai_verdict.get(
                                    "suggested_code_change",
                                    static_fix_guidance(selected_finding)["safe_pattern"],
                                ),
                                "test_recommendation": ai_verdict.get(
                                    "test_recommendation",
                                    "Add a regression test proving the unsafe input is handled safely.",
                                ),
                            }
                        )
                    section_header("HTTP Evidence", "Response metadata, body excerpt, and headers captured during validation.")
                    with st.container(border=True):
                        with st.expander("Response metadata", expanded=True):
                            st.json(
                                {
                                    "status_code": response_evidence["status_code"],
                                    "original_url": response_evidence["original_url"],
                                    "final_url": response_evidence["final_url"],
                                    "redirect_chain": response_evidence["redirect_chain"],
                                    "content_type": response_evidence["content_type"],
                                    "body_length": response_evidence["body_length"],
                                }
                            )
                        with st.expander("Response excerpt", expanded=True):
                            st.code(response_excerpt_for_display(response_evidence))
                        with st.expander("Response headers"):
                            st.json(response_evidence["headers"])
                except requests.RequestException as exc:
                    st.error(f"DAST request failed: {exc}")
            else:
                st.info("Payload generated only. Add target URL and authorization consent to run DAST.")
elif run_btn:
    st.success("No Semgrep findings were detected.")
