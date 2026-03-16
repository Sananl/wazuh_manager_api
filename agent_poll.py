import time
import requests
import subprocess
import os

# --- ตั้งค่าคอนฟิก ---
API_BASE_URL = "https://wazuh-manager-api-2zfc.vercel.app" # เปลี่ยนเป็น IP ของ API Server
AGENT_ID = "002"                           # เปลี่ยนเป็น ID ของ Agent ตัวนี้
POLLING_INTERVAL = 10                       # ตรวจสอบทุก 10 วินาที

def execute_command(action):
    """ฟังก์ชันสำหรับรันคำสั่งในเครื่อง"""
    try:
        if action == "restart":
            print("Executing: Restarting Wazuh Agent...")
            # สำหรับ Windows
            if os.name == 'nt':
                subprocess.run(["net", "stop", "Wazuh"], check=True)
                subprocess.run(["net", "start", "Wazuh"], check=True)
            else:
                # สำหรับ Linux
                subprocess.run(["systemctl", "restart", "wazuh-agent"], check=True)
            return "Wazuh Agent restarted successfully"

        elif action == "stop":
            print("Executing: Stopping Wazuh Agent...")
            if os.name == 'nt':
                subprocess.run(["net", "stop", "Wazuh"], check=True)
            else:
                subprocess.run(["systemctl", "stop", "wazuh-agent"], check=True)
            return "Wazuh Agent stopped successfully"

        elif action == "start":
            print("Executing: Starting Wazuh Agent...")
            if os.name == 'nt':
                subprocess.run(["net", "start", "Wazuh"], check=True)
            else:
                subprocess.run(["systemctl", "start", "wazuh-agent"], check=True)
            return "Wazuh Agent started successfully"

        else:
            return f"Unknown action: {action}"

    except Exception as e:
        return f"Error executing {action}: {str(e)}"

def poll_and_execute():
    print(f"Agent {AGENT_ID} polling started (Interval: {POLLING_INTERVAL}s)...")
    
    while True:
        try:
            # 1. ดึงคำสั่งจาก API (Pull)
            pull_url = f"{API_BASE_URL}/agent-commands/pull?agent_id={AGENT_ID}"
            response = requests.get(pull_url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                command_id = data.get("command_id")
                action = data.get("action")
                
                print(f"New command received: {action} (ID: {command_id})")
                
                # 2. ทำงานตามคำสั่ง
                result_output = execute_command(action)
                
                # 3. ส่งผลลัพธ์กลับไปบอก API (Ack)
                ack_url = f"{API_BASE_URL}/agent-commands/ack"
                ack_payload = {
                    "command_id": command_id,
                    "status": "done",
                    "output": result_output
                }
                requests.post(ack_url, json=ack_payload, timeout=5)
                print(f"Command {command_id} acknowledged with result: {result_output}")
            
            elif response.status_code == 204:
                # ไม่มีคำสั่งค้างอยู่ (No Content)
                pass
            else:
                print(f"Error pulling command: {response.status_code}")

        except Exception as e:
            print(f"Connection error: {str(e)}")

        time.sleep(POLLING_INTERVAL)

if __name__ == "__main__":
    poll_and_execute()
