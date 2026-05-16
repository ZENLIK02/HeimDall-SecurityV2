import streamlit as st
import json
import subprocess
import os
import zipfile
import shutil
import requests
from openai import OpenAI

st.set_page_config(page_title="AI-ASOC Cloud Sandbox", page_icon="🛡️", layout="wide")
st.title("🛡️ AI-ASOC: Custom Code Scanner & DAST")

# แถบด้านซ้าย: ตั้งค่า
st.sidebar.header("⚙️ Settings & Auth")
user_api_key = st.sidebar.text_input("1. OpenAI API Key", type="password")
target_url = st.sidebar.text_input("2. Target URL (สำหรับ DAST)", placeholder="เช่น https://my-test-app.com")
consent = st.sidebar.checkbox("⚠️ ฉันยืนยันว่าเป็นเจ้าของ URL นี้และอนุญาตให้ระบบยิงทดสอบเจาะระบบ")

# แถบหลัก: อัปโหลดและแสดงผล
uploaded_file = st.file_uploader("อัปโหลดไฟล์ Source Code (.zip) ของเป้าหมาย", type=["zip"])

if st.button("🚀 เริ่มการวิเคราะห์ (SAST + DAST)", type="primary"):
    # ตรวจสอบเงื่อนไขความปลอดภัย
    if not user_api_key:
        st.error("❌ กรุณาใส่ API Key")
    elif not uploaded_file:
        st.error("❌ กรุณาอัปโหลดไฟล์ Source Code (.zip)")
    elif target_url and not consent:
        st.error("❌ กรุณากดยืนยันสิทธิ์ (Consent) ก่อนทำการทดสอบ DAST")
    else:
        temp_dir = "temp_scan"
        sast_output = "sast_results.json"
        
        if os.path.exists(temp_dir): shutil.rmtree(temp_dir)
        os.makedirs(temp_dir, exist_ok=True)

        try:
            # --- 1. SAST SCAN ---
            zip_path = os.path.join(temp_dir, "upload.zip")
            with open(zip_path, "wb") as f: f.write(uploaded_file.getbuffer())
            with zipfile.ZipFile(zip_path, 'r') as zip_ref: zip_ref.extractall(temp_dir)

            st.info("🔍 ขั้นตอนที่ 1: สแกน Source Code ด้วย Semgrep (SAST)...")
            subprocess.run(f"semgrep scan --config auto --json -o {sast_output} {temp_dir}", shell=True, capture_output=True)

            if os.path.exists(sast_output):
                with open(sast_output, "r", encoding="utf-8") as f: sast_data = json.load(f)
            else:
                sast_data = {}

            if "results" in sast_data and len(sast_data["results"]) > 0:
                vuln = sast_data["results"][0]
                vuln_info = {
                    "file": vuln.get("path").replace(f"{temp_dir}/", ""),
                    "line": vuln.get("start", {}).get("line"),
                    "message": vuln.get("extra", {}).get("message")
                }
                
                st.warning(f"⚠️ **พบช่องโหว่ (SAST):** ไฟล์ `{vuln_info['file']}` (บรรทัด {vuln_info['line']})")
                
                # --- 2. AI PAYLOAD GENERATOR ---
                st.info("🧠 ขั้นตอนที่ 2: AI กำลังสร้าง Exploit Payload...")
                client = OpenAI(api_key=user_api_key)
                
                # บังคับให้ AI ใช้ URL ที่ผู้ใช้กรอกเป็นฐาน
                base_url = target_url if target_url else "http://localhost"
                system_prompt = f"You are a DAST Payload Generator. Return a JSON object with keys: 'method', 'url' (starting with {base_url}), 'headers', and 'data'."
                
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": f"สร้าง Payload สำหรับช่องโหว่นี้: {json.dumps(vuln_info, ensure_ascii=False)}"}
                    ]
                )
                
                payload = json.loads(response.choices[0].message.content)
                st.json(payload)

                # --- 3. DAST EXECUTION (ถ้าผู้ใช้กรอก URL และกดยืนยัน) ---
                if target_url and consent:
                    st.info("🔫 ขั้นตอนที่ 3: กำลังยิง Payload ใส่ระบบเป้าหมาย (DAST)...")
                    try:
                        method = payload.get("method", "GET").upper()
                        req_url = payload.get("url")
                        headers = payload.get("headers", {})
                        data = payload.get("data", "")

                        # ตั้งเวลา Timeout เพื่อป้องกันเซิร์ฟเวอร์ค้าง
                        if method == "GET":
                            res = requests.get(req_url, headers=headers, params=data, timeout=10)
                        else:
                            res = requests.post(req_url, headers=headers, json=data, timeout=10)
                        
                        http_status = res.status_code
                        res_text = res.text[:300]
                        st.write(f"**Status Code:** `{http_status}`")
                        
                        # --- 4. AI VALIDATION ---
                        st.info("🧠 ขั้นตอนที่ 4: AI กำลังตัดสินผลลัพธ์ (True/False Positive)...")
                        val_prompt = f"สถานะการโจมตี: Status {http_status}, Response: {res_text}. สำเร็จ (True Positive) หรือล้มเหลว (False Positive)? ตอบสั้นๆ พร้อมเหตุผล"
                        val_res = client.chat.completions.create(
                            model="gpt-4o-mini",
                            messages=[{"role": "user", "content": val_prompt}]
                        )
                        decision = val_res.choices[0].message.content
                        
                        if "False Positive" in decision:
                            st.success(f"🛡️ **AI ตัดสินว่า:** {decision}")
                        else:
                            st.error(f"🚨 **AI ตัดสินว่า:** {decision}")

                    except requests.exceptions.RequestException as e:
                        st.error(f"❌ ไม่สามารถเชื่อมต่อเป้าหมายได้: {e}")
                else:
                    st.info("💡 ข้ามการยิง DAST เนื่องจากไม่มีการระบุ URL เป้าหมาย หรือไม่ได้กดยืนยันสิทธิ์")
            else:
                st.success("✅ โค้ดปลอดภัย ไม่พบช่องโหว่")

        except Exception as e:
            st.error(f"❌ เกิดข้อผิดพลาด: {str(e)}")
        finally:
            if os.path.exists(temp_dir): shutil.rmtree(temp_dir)
            if os.path.exists(sast_output): os.remove(sast_output)