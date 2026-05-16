import json
from openai import OpenAI

# 1. ใส่ API Key ของคุณตรงนี้ (เอารหัส sk-... มาใส่ในเครื่องหมายคำพูด)
api_key = "sk-proj-" 
client = OpenAI(api_key=api_key)

# 2. ฟังก์ชันสำหรับอ่านไฟล์ SAST
def read_sast_results(filename):
    try:
        with open(filename, "r", encoding="utf-8") as file:
            data = json.load(file)
            return data
    except Exception as e:
        print(f"❌ อ่านไฟล์ไม่สำเร็จ: {e}")
        return None

# 3. อ่านไฟล์ sast_results.json
print("🔍 กำลังอ่านผลลัพธ์จาก SAST...")
sast_data = read_sast_results("sast_results.json")

# เช็คว่ามีช่องโหว่หรือไม่ (ดึงมาแค่ 1 ช่องโหว่แรกเพื่อทดสอบ)
if sast_data and "results" in sast_data and len(sast_data["results"]) > 0:
    first_vuln = sast_data["results"][0] # ดึงช่องโหว่แรกมา
    
    # ดึงเฉพาะข้อมูลที่สำคัญเพื่อส่งให้ AI (ตัดน้ำทิ้ง)
    vuln_info = {
        "file": first_vuln.get("path"),
        "line": first_vuln.get("start", {}).get("line"),
        "message": first_vuln.get("extra", {}).get("message"),
        "cwe": first_vuln.get("extra", {}).get("metadata", {}).get("cwe")
    }
    
    print(f"⚠️ พบช่องโหว่ที่ไฟล์: {vuln_info['file']} (บรรทัด {vuln_info['line']})")
    print("🧠 กำลังส่งข้อมูลให้ AI วิเคราะห์และสร้าง Payload... (รอสักครู่)")

    # 4. สั่งงาน AI (GPT-4o-mini)
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        response_format={"type": "json_object"}, # บังคับให้ AI ตอบมาเป็น JSON
        messages=[
            {
                "role": "system", 
                "content": "คุณคือผู้เชี่ยวชาญด้าน Cyber Security หน้าที่ของคุณคืออ่านผลสแกน SAST แล้วสร้าง HTTP Request Payload สำหรับไปทดสอบเจาะระบบเป้าหมาย (DAST) ที่ http://localhost:3000 ให้ตอบกลับมาเป็นรูปแบบ JSON เท่านั้น โดยต้องมี keys ดังนี้: 'method' (เช่น GET, POST), 'url' (เช่น /api/users), 'headers' (ถ้ามี), และ 'data' (payload ที่ใช้เจาะ เช่น SQLi หรือ XSS)"
            },
            {
                "role": "user", 
                "content": f"นี่คือช่องโหว่ที่พบ: {json.dumps(vuln_info, ensure_ascii=False)}\nจงสร้าง Payload สำหรับเจาะช่องโหว่นี้"
            }
        ]
    )

    # 5. แสดงผลลัพธ์
    ai_payload = response.choices[0].message.content
    print("\n🎯 Payload ที่ AI สร้างเสร็จแล้ว (พร้อมใช้งานใน Phase 4):")
    print(ai_payload)
    
    # เซฟ Payload เก็บไว้ใช้ต่อใน Phase 4
    with open("dast_payload.json", "w", encoding="utf-8") as f:
        f.write(ai_payload)

else:
    print("✅ ไม่พบช่องโหว่ในไฟล์ JSON หรือไฟล์ว่างเปล่า")