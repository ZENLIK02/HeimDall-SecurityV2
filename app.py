import streamlit as st
import json
import subprocess
import os
import zipfile
import shutil
import requests
from openai import OpenAI

# ==========================================
# 1. PAGE CONFIGURATION & CUSTOM CSS
# ==========================================
st.set_page_config(page_title="AI-ASOC Sandbox", page_icon="🛡️", layout="wide")

# ตกแต่ง UI เล็กน้อยให้ดูมินิมอลและสะอาดตา
st.markdown("""
    <style>
    /* ปรับปุ่มให้โค้งมนและกว้างเต็มกรอบ */
    .stButton>button { width: 100%; border-radius: 8px; font-weight: bold; }
    /* ปรับแต่งหัวข้อ */
    .main-title { font-size: 2.5rem; font-weight: 800; color: #1E3A8A; text-align: center; margin-bottom: 0; }
    .sub-title { font-size: 1.1rem; color: #6B7280; text-align: center; margin-bottom: 2rem; }
    </style>
""", unsafe_allow_html=True)

# ==========================================
# 2. SIDEBAR (การตั้งค่า)
# ==========================================
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=60) # โลโก้จำลอง
    st.header("⚙️ Settings")
    st.markdown("---")
    
    st.subheader("1. Authentication")
    user_api_key = st.text_input("🔑 OpenAI API Key", type="password", help="คีย์จะถูกลบเมื่อปิดหน้าเว็บ")
    
    st.markdown("---")
    st.subheader("2. DAST Target (Optional)")
    target_url = st.text_input("🔗 Target URL", placeholder="http://localhost:3000")
    consent = st.checkbox("⚠️ ยืนยันว่าคุณเป็นเจ้าของระบบนี้", help="ต้องกดยืนยันเพื่ออนุญาตให้ AI ยิงทดสอบ")

# ==========================================
# 3. MAIN INTERFACE
# ==========================================
st.markdown('<p class="main-title">🛡️ AI-ASOC Sandbox</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-title">ระบบวิเคราะห์ช่องโหว่และจำลองการเจาะระบบอัตโนมัติ เพื่อคัดกรอง False Positive</p>', unsafe_allow_html=True)

# ใช้ Columns จัดให้อัปโหลดไฟล์อยู่ตรงกลางจอ ดูเป็นระเบียบ
col_spacer1, col_center, col_spacer2 = st.columns([1, 2, 1])

with col_center:
    uploaded_file = st.file_uploader("📂 อัปโหลดไฟล์ Source Code ของคุณ (.zip)", type=["zip"])
    run_btn = st.button("🚀 เริ่มการวิเคราะห์ระบบ", type="primary")

st.markdown("---")

# ==========================================
# 4. EXECUTION ENGINE (การประมวลผล)
# ==========================================
if run_btn:
    if not user_api_key:
        st.error("❌ กรุณาใส่ API Key ที่แถบการตั้งค่าด้านซ้ายมือ")
    elif not uploaded_file:
        st.error("❌ กรุณาอัปโหลดไฟล์ Source Code (.zip)")
    elif target_url and not consent:
        st.error("❌ กรุณากดยืนยันสิทธิ์ (Consent) เพื่ออนุญาตการยิง DAST")
    else:
        temp_dir = "temp_scan"
        sast_output = "sast_results.json"
        payload = {}
        decision = ""
        http_status = None
        
        if os.path.exists(temp_dir): shutil.rmtree(temp_dir)
        os.makedirs(temp_dir, exist_ok=True)

        try:
            # ใช้ st.status เพื่อรวมขั้นตอนการทำงานไว้ในกล่องเดียว (ดูสวยและล้ำมาก)
            with st.status("🔄 ระบบกำลังดำเนินการ กรุณารอสักครู่...", expanded=True) as status:
                
                # --- Step 1: SAST ---
                st.write("📂 กำลังแตกไฟล์ซอร์สโค้ด...")
                zip_path = os.path.join(temp_dir, "upload.zip")
                with open(zip_path, "wb") as f: f.write(uploaded_file.getbuffer())
                with zipfile.ZipFile(zip_path, 'r') as zip_ref: zip_ref.extractall(temp_dir)

                st.write("🔍 สแกน Source Code ด้วย Semgrep...")
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
                    
                    # --- Step 2: AI Payload ---
                    st.write("🧠 AI กำลังสร้าง Exploit Payload...")
                    client = OpenAI(api_key=user_api_key)
                    base_url = target_url if target_url else "http://localhost"
                    
                    res_payload = client.chat.completions.create(
                        model="gpt-4o-mini",
                        response_format={"type": "json_object"},
                        messages=[
                            {"role": "system", "content": f"You are a DAST Payload Generator. Return JSON: 'method', 'url' (start with {base_url}), 'headers', 'data'."},
                            {"role": "user", "content": f"สร้าง Payload สำหรับช่องโหว่: {json.dumps(vuln_info, ensure_ascii=False)}"}
                        ]
                    )
                    payload = json.loads(res_payload.choices[0].message.content)

                    # --- Step 3: DAST & Validation ---
                    if target_url and consent:
                        st.write(f"🔫 กำลังยิงทดสอบระบบไปที่ {base_url} ...")
                        try:
                            method = payload.get("method", "GET").upper()
                            req_url = payload.get("url")
                            headers = payload.get("headers", {})
                            data = payload.get("data", "")

                            if method == "GET":
                                res = requests.get(req_url, headers=headers, params=data, timeout=10)
                            else:
                                res = requests.post(req_url, headers=headers, json=data, timeout=10)
                            
                            http_status = res.status_code
                            res_text = res.text[:300]
                            
                            st.write("🤖 AI กำลังวิเคราะห์ผลการโจมตี...")
                            val_res = client.chat.completions.create(
                                model="gpt-4o-mini",
                                messages=[{"role": "user", "content": f"โจมตีได้ Status {http_status}, Response: {res_text}. สำเร็จ(True Positive) หรือ ล้มเหลว(False Positive)? ตอบสั้นๆ พร้อมเหตุผล"}]
                            )
                            decision = val_res.choices[0].message.content
                            
                        except requests.exceptions.RequestException as e:
                            decision = f"Error: เชื่อมต่อเป้าหมายไม่ได้ ({e})"
                            
                status.update(label="✅ การวิเคราะห์เสร็จสมบูรณ์!", state="complete", expanded=False)

            # ==========================================
            # 5. RESULTS DASHBOARD (หน้าต่างแสดงผลลัพธ์)
            # ==========================================
            if "results" in sast_data and len(sast_data["results"]) > 0:
                st.subheader("📊 สรุปผลการประมวลผล (Analysis Results)")
                
                # แบ่งหน้าจอเป็น 2 ฝั่งเพื่อความสวยงาม
                res_col1, res_col2 = st.columns(2)
                
                with res_col1:
                    st.error("🚨 SAST Alert (ตรวจพบความเสี่ยง)")
                    st.write(f"**ไฟล์:** `{vuln_info['file']}` (บรรทัด {vuln_info['line']})")
                    st.write(f"**สาเหตุ:** {vuln_info['message']}")
                
                with res_col2:
                    if target_url and consent:
                        if "False Positive" in decision:
                            st.success("🛡️ AI Verdict: False Positive (แจ้งเตือนขยะ)")
                        else:
                            st.warning("⚠️ AI Verdict: True Positive (อันตรายจริง)")
                        st.write(f"**เหตุผล:** {decision}")
                    else:
                        st.info("💡 ข้ามการทดสอบเจาะระบบ")
                        st.write("ระบบจำลองเฉพาะ Payload เนื่องจากผู้ใช้ไม่ได้ระบุ Target URL สำหรับการยิงทดสอบจริง")
                
                # ซ่อน Payload ไว้ใน Expander ให้ดูเป็นระเบียบ
                with st.expander("🛠️ ดู HTTP Payload ที่ AI สร้างขึ้น (คลิกเพื่อขยาย)"):
                    st.json(payload)
                    
            else:
                st.success("🎉 โค้ดของคุณปลอดภัย ไม่พบช่องโหว่ใดๆ ในระบบ!")

        except Exception as e:
            st.error(f"❌ เกิดข้อผิดพลาดของระบบ: {str(e)}")
        finally:
            # ทำความสะอาดระบบ
            if os.path.exists(temp_dir): shutil.rmtree(temp_dir)
            if os.path.exists(sast_output): os.remove(sast_output)