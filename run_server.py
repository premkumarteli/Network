import uvicorn
from dotenv import load_dotenv
import socket

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

if __name__ == "__main__":
    load_dotenv()
    print("-" * 40)
    print("Netvisor Server Starting...")
    print("Local access:   http://localhost:8000")
    print(f"Network access: http://{get_local_ip()}:8000")
    print("-" * 40)
    uvicorn.run("netvisor.backend.app.main:app", host="0.0.0.0", port=8000, reload=True)