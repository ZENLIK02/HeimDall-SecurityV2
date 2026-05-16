import streamlit as st
import json
import subprocess
import os
import zipfile
import shutil
from openai import OpenAI

# 1. ตั้งค่าหน้าเว็บ
st.set_page_config(page_title="AI-ASOC Cloud Sandbox", page_icon="🛡️", layout="wide")
st.title("🛡️ AI-ASOC: Custom Code Scanner")
st.markdown("อัปโหลดไฟล์ Source Code (.zip) เพื่อค้นหาช่องโหว่และสร้าง Exploit Payload อัตโนมัติ")

# 2. รับค่า API Key
st.sidebar.header("🔑 Authentication")
user_api_key = st.sidebar.text_input("Enter OpenAI API Key", type="password")

# 3. รับไฟล์อัปโหลด
uploaded_file = st.file_uploader("อัปโหลดไฟล์โปรเจกต์ (.zip)", type=["zip"])

if st.button("🚀 เริ่มการสแกนและวิเคราะห์", type="primary"):
    if not user_api_key:
        st.error("❌ กรุณาใส่ OpenAI API Key ที่แถบด้านซ้าย")
    elif not uploaded_file:
        st.error("❌ กรุณาอัปโหลดไฟล์ .zip")
    else:
        temp_dir = "temp_scan"
        sast_output = "sast_results.json"
        
        # ล้างโฟลเดอร์เก่า (ถ้ามี)
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir, exist_ok=True)

        try:
            # 4. แตกไฟล์ ZIP
            zip_path = os.path.join(temp_dir, "upload.zip")
            with open(zip_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
                
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)

            # 5. รัน Semgrep สแกนโค้ด
            st.info("🔍 ขั้นตอนที่ 1: กำลังสแกน Source Code ด้วย Semgrep...")
            cmd = f"semgrep scan --config auto --json -o {sast_output} {temp_dir}"
            subprocess.run(cmd, shell=True, capture_output=True)

            # 6. อ่านผลลัพธ์
            if os.path.exists(sast_output):
                with open(sast_output, "r", encoding="utf-8") as f:
                    sast_data = json.load(f)
            else:
                sast_data = {}

            if "results" in sast_data and len(sast_data["results"]) > 0:
                # ดึงช่องโหว่แรกมาแสดงผล
                vuln = sast_data["results"][0]
                vuln_info = {
                    "file": vuln.get("path").replace(f"{temp_dir}/", ""), # ลบชื่อโฟลเดอร์ temp ออกเพื่อความสวยงาม
                    "line": vuln.get("start", {}).get("line"),
                    "message": vuln.get("extra", {}).get("message")
                }
                
                st.warning(f"⚠️ **พบช่องโหว่ในไฟล์:** `{vuln_info['file']}` (บรรทัดที่ {vuln_info['line']})")
                st.write(f"**รายละเอียด:** {vuln_info['message']}")
                
                # 7. ส่งข้อมูลให้ AI วิเคราะห์
                st.info("🧠 ขั้นตอนที่ 2: AI กำลังสร้าง Exploit Payload...")
                client = OpenAI(api_key=user_api_key)
                
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": "You are a Cyber Security Expert. Analyze the SAST result and generate a DAST testing payload in JSON format with keys: 'method', 'url' (use relative path), 'headers', and 'data'."},
                        {"role": "user", "content": f"สร้าง Payload สำหรับช่องโหว่นี้: {json.dumps(vuln_info, ensure_ascii=False)}"}
                    ]
                )
                
                payload = json.loads(response.choices[0].message.content)
                st.success("✅ สร้าง Payload สำเร็จ!")
                st.json(payload)
                
                # หมายเหตุ: ตัดการยิง DAST ออก เพราะเป้าหมายไม่ได้ถูกรันเป็นเซิร์ฟเวอร์บนระบบ Cloud
                st.info("💡 หมายเหตุ: ระบบจำลอง Payload เสร็จสิ้น (ข้ามขั้นตอนการยิงทดสอบจริงบน Cloud เพื่อความปลอดภัย)")
                
            else:
                st.success("✅ โค้ดปลอดภัย ไม่พบช่องโหว่ต้องสงสัย")

        except Exception as e:
            st.error(f"❌ เกิดข้อผิดพลาดของระบบ: {str(e)}")
            
        finally:
            # 8. ทำความสะอาดไฟล์ชั่วคราวเสมอ
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            if os.path.exists(sast_output):
                os.remove(sast_output)