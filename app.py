import streamlit as st
import json
import requests
import time
from openai import OpenAI

# ตั้งค่าหน้าเว็บ
st.set_page_config(page_title="AI-ASOC Dashboard", page_icon="🛡️", layout="wide")
st.title("🛡️ AI-ASOC: Automated Security Orchestration")

# 1. สร้างช่องกรอก API Key ที่ Sidebar (ซ่อนข้อความด้วย type="password")
st.sidebar.header("🔑 Authentication")
user_api_key = st.sidebar.text_input(
    "Enter OpenAI API Key", 
    type="password", 
    help="Key ของคุณจะไม่ถูกบันทึกลงในระบบเซิร์ฟเวอร์"
)

st.divider()

# ฟังก์ชันอ่านไฟล์ SAST (คงเดิมจากเวอร์ชันก่อนหน้า)
def load_sast_data():
    try:
        with open("sast_results.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            if "results" in data and len(data["results"]) > 0:
                first_vuln = data["results"][0]
                return {
                    "file": first_vuln.get("path"),
                    "line": first_vuln.get("start", {}).get("line"),
                    "message": first_vuln.get("extra", {}).get("message")
                }
    except Exception:
        return None

st.subheader("1️⃣ ข้อมูลการแจ้งเตือนจาก SAST (Source Code Scanner)")
vuln_data = load_sast_data()

if vuln_data:
    st.error(f"**พบโค้ดต้องสงสัยในไฟล์:** `{vuln_data['file']}` (บรรทัดที่ {vuln_data['line']})")
    st.info(f"**รายละเอียด:** {vuln_data['message']}")
else:
    st.warning("ไม่พบไฟล์ sast_results.json หรือไม่พบช่องโหว่")

st.divider()

# ปุ่มเริ่มทำงาน AI
if st.button("🚀 สั่ง AI วิเคราะห์และทดสอบเจาะระบบ (Run AI-ASOC)", type="primary"):
    # 2. ตรวจสอบเงื่อนไขว่าผู้ใช้กรอก API Key หรือยัง
    if not user_api_key:
        st.error("❌ กรุณากรอก OpenAI API Key ที่แถบเมนูด้านซ้าย (Sidebar) ก่อนกดปุ่มรันระบบ")
    elif not vuln_data:
        st.error("❌ ไม่มีข้อมูล SAST ให้วิเคราะห์")
    else:
        # 3. เรียกใช้งาน OpenAI Client โดยใช้ Key จากหน้าเว็บโดยตรง
        client = OpenAI(api_key=user_api_key)
        
        # ส่วนที่ 2: AI สร้าง Payload
        st.subheader("2️⃣ AI กำลังสร้าง Exploit Payload...")
        with st.spinner("AI กำลังวิเคราะห์ Source Code และประกอบร่าง HTTP Request..."):
            try:
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": "You are a DAST Payload Generator. Analyze SAST input and return a JSON object with keys: 'method', 'url', 'headers', 'data'."},
                        {"role": "user", "content": f"สร้าง Payload สำหรับช่องโหว่นี้: {json.dumps(vuln_data, ensure_ascii=False)}"}
                    ]
                )
                payload = json.loads(response.choices[0].message.content)
                st.success("✅ สร้าง Payload สำเร็จ!")
                st.json(payload)
                
                # [ส่วนที่ 3 และ 4: การรัน DAST และวิเคราะห์ผลลัพธ์ ให้คงการทำงานเดิมไว้]
                
            except Exception as api_error:
                st.error(f"❌ เกิดข้อผิดพลาดกับ API: {api_error}")
                st.info("กรุณาตรวจสอบความถูกต้องของ API Key หรือเครดิตคงเหลือในบัญชี OpenAI ของคุณ")