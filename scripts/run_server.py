import uvicorn
from dotenv import load_dotenv
import socket
import os

def cleanup_runtime_on_process_exit():
    if os.getenv("NETVISOR_BACKUP_AND_RESET_ON_SHUTDOWN", "true").lower() != "true":
        return
    if os.getenv("NETVISOR_RELOAD", "false").lower() == "true":
        return

    try:
        from app.db.session import get_db_connection
        from app.services.system_service import system_service

        conn = get_db_connection()
        try:
            result = system_service.backup_and_reset_runtime_data(conn, reason="process_exit")
            print(f"[*] Process-exit runtime cleanup: {result['message']}")
        finally:
            conn.close()
    except Exception as exc:
        print(f"[!] Process-exit runtime cleanup failed: {exc}")


def get_local_ip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("10.255.255.255", 1))
        ip_address = sock.getsockname()[0]
    except Exception:
        ip_address = "127.0.0.1"
    finally:
        sock.close()  # pyright: ignore[reportPossiblyUnboundVariable]
    return ip_address


if __name__ == "__main__":
    load_dotenv()
    local_ip = get_local_ip()
    reload_enabled = os.getenv("NETVISOR_RELOAD", "false").lower() == "true"
    print("[*] Netvisor Server Starting...")
    print("[*] Local Access:   http://127.0.0.1:8000")
    print(f"[*] Network Access: http://{local_ip}:8000")
    print(f"[*] Auto Reload:    {'enabled' if reload_enabled else 'disabled'}")
    try:
        uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=reload_enabled)
    finally:
        cleanup_runtime_on_process_exit()
