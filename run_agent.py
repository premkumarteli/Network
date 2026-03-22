from agent.main import NetworkAgent
from pathlib import Path
from dotenv.main import load_dotenv

if __name__ == "__main__":
    load_dotenv()
    config_path = Path(__file__).resolve().parent / "config" / "agent.json"
    if not config_path.exists():
        raise FileNotFoundError(f"Missing agent config: {config_path}")

    print(f"[*] Starting SOC Agent using config: {config_path}")
    NetworkAgent(config_path).start()
