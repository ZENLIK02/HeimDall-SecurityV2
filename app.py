import streamlit as st
import json
import requests
import time
from openai import OpenAI

# 1. ใส่ API Key ของคุณตรงนี้
api_key = "sk-proj-"
client = OpenAI(api_key=api_key)

# ตั้งค่าหน้าเว็บ
st.set_page_config(page_title="AI-ASOC Dashboard", page_icon="🛡️", layout="wide")
st.title("🛡️ AI-ASOC: Automated Security Orchestration")
st.markdown("ระบบ AI ศูนย์กลางสำหรับกรองแจ้งเตือนขยะ (False Positive) และยืนยันช่องโหว่อัตโนมัติ")

st.divider()

# ฟังก์ชันอ่านไฟล์ SAST
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

# ส่วนที่ 1: แสดงข้อมูลสแกน (SAST)
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
    if not vuln_data:
        st.error("ไม่มีข้อมูล SAST ให้วิเคราะห์")
    else:
        # ส่วนที่ 2: AI สร้าง Payload
        st.subheader("2️⃣ AI กำลังสร้าง Exploit Payload...")
        with st.spinner("AI กำลังวิเคราะห์ Source Code และประกอบร่าง HTTP Request..."):
            time.sleep(1) # หน่วงเวลาให้ดูเหมือนกำลังคิด
            
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": "คุณคือ DAST Payload Generator รับข้อมูล SAST แล้วส่งออกเป็น JSON ที่มี keys: 'method', 'url' (ใช้ http://localhost:3000 นำหน้าเสมอ), 'headers', 'data'"},
                    {"role": "user", "content": f"สร้าง Payload สำหรับช่องโหว่นี้: {json.dumps(vuln_data, ensure_ascii=False)}"}
                ]
            )
            payload = json.loads(response.choices[0].message.content)
            
        st.success("✅ สร้าง Payload สำเร็จ!")
        st.json(payload)

        # ส่วนที่ 3: ยิงทดสอบ (DAST)
        st.subheader("3️⃣ ทดสอบยิงระบบเป้าหมาย (DAST Execution)")
        with st.spinner("กำลังส่ง Payload ไปที่เป้าหมาย..."):
            method = payload.get("method", "GET").upper()
            target_url = payload.get("url")
            headers = payload.get("headers", {})
            data = payload.get("data", "")

            try:
                if method == "GET":
                    res = requests.get(target_url, headers=headers, params=data, timeout=5)
                else:
                    res = requests.post(target_url, headers=headers, json=data, timeout=5)
                
                http_status = res.status_code
                response_text = res.text[:300]
                st.write(f"**Status Code:** `{http_status}`")
                
            except Exception as e:
                http_status = "Error"
                response_text = str(e)
                st.error("ยิงไม่สำเร็จ เช็คว่าเปิด Juice Shop (Docker) อยู่หรือไม่")

        # ส่วนที่ 4: AI ตัดสินผล (Validation)
        st.subheader("4️⃣ คำตัดสิน (Validation Result)")
        with st.spinner("AI กำลังวิเคราะห์ผลลัพธ์..."):
            val_prompt = f"สถานะการโจมตี: Status {http_status}, Response {response_text}. สำเร็จ (True Positive) หรือล้มเหลว (False Positive)? ตอบสั้นๆ พร้อมเหตุผล"
            val_res = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": val_prompt}]
            )
            decision = val_res.choices[0].message.content
            
        if "False Positive" in decision:
            st.success(f"🛡️ **AI ตัดสินว่า:** {decision}")
        else:
            st.error(f"🚨 **AI ตัดสินว่า:** {decision}")