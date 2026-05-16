import json
import requests
from openai import OpenAI

# 1. ใส่ API Key ของคุณตรงนี้ (ใช้ Key เดียวกับ Phase 3)
api_key = "sk-proj-" 
client = OpenAI(api_key=api_key)

def run_dast_and_validate():
    print("🔫 [DAST] กำลังเตรียมกระสุน (อ่าน Payload จาก Phase 3)...")
    try:
        with open("dast_payload.json", "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception as e:
        print("❌ ไม่พบไฟล์ dast_payload.json ต้องรัน Phase 3 ก่อน")
        return

    method = payload.get("method", "GET").upper()
    raw_url = payload.get("url", "")
    
    # ถ้า URL ไม่มี http นำหน้า ให้ชี้เป้าไปที่ localhost:3000
    if not raw_url.startswith("http"):
        target_url = f"http://localhost:3000{raw_url}"
    else:
        target_url = raw_url

    headers = payload.get("headers", {})
    data = payload.get("data", "")

    print(f"🚀 กำลังยิงจรวดไปที่: [{method}] {target_url}")

    # 2. ยิง HTTP Request ไปที่เป้าหมาย
    try:
        if method == "GET":
            response = requests.get(target_url, headers=headers, params=data, timeout=5)
        else:
            # ตรวจสอบว่าต้องส่งข้อมูลเป็น JSON หรือข้อความปกติ
            if "application/json" in str(headers).lower() and isinstance(data, dict):
                 response = requests.post(target_url, headers=headers, json=data, timeout=5)
            else:
                 response = requests.request(method, target_url, headers=headers, data=data, timeout=5)
        
        http_status = response.status_code
        # เอาคำตอบมาแค่ 500 ตัวอักษร เพื่อไม่ให้ข้อความยาวเกินไปตอนส่งให้ AI
        response_text = response.text[:500] 
        
        print(f"🎯 ผลลัพธ์การยิง (Status Code): {http_status}")
        
    except requests.exceptions.ConnectionError:
        print("❌ ยิงไม่สำเร็จ: ไม่สามารถเชื่อมต่อเป้าหมายได้ (ลืมเปิด Docker Juice Shop หรือเปล่า?)")
        return
    except Exception as e:
        print(f"❌ เกิดข้อผิดพลาดในการยิง: {e}")
        return

    # 3. ให้ AI ช่วยวิเคราะห์ผลลัพธ์ (Validation)
    print("🧠 กำลังส่งผลลัพธ์ให้ AI ยืนยันว่าเป็น True หรือ False Positive...")
    validation_prompt = f"""
    คุณคือผู้เชี่ยวชาญด้าน Cyber Security
    นี่คือผลลัพธ์จากการนำ Exploit Payload ไปยิงทดสอบระบบ:
    - HTTP Status Code: {http_status}
    - Response Text: {response_text}

    จงวิเคราะห์ว่าการโจมตีนี้สำเร็จหรือไม่?
    - หากสำเร็จ (เจาะเข้า, ข้อมูลรั่วไหล, หรือเกิด Error ของระบบฐานข้อมูล) ให้ขึ้นต้นว่า "True Positive:" 
    - หากไม่สำเร็จ (เช่น 404 Not Found, 403 Forbidden, 401 Unauthorized หรือไม่มีอะไรพัง) ให้ขึ้นต้นว่า "False Positive:"
    
    พร้อมอธิบายเหตุผลสั้นๆ 1-2 บรรทัด
    """

    ai_response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": validation_prompt}]
    )

    print("\n==============================================")
    print("🛡️ คำตัดสินจากระบบ AI-ASOC Orchestrator 🛡️")
    print("==============================================")
    print(ai_response.choices[0].message.content)
    print("==============================================")

if __name__ == "__main__":
    run_dast_and_validate()