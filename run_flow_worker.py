import asyncio
from dotenv import load_dotenv


if __name__ == "__main__":
    load_dotenv()

    from app.main import _validate_runtime_config
    from app.services.flow_service import flow_service

    print("[*] NetVisor Flow Worker Starting...")
    _validate_runtime_config()

    try:
        asyncio.run(flow_service.flow_writer_worker())
    except KeyboardInterrupt:
        print("[*] NetVisor Flow Worker Stopped.")
