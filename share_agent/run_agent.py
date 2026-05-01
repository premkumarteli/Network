from pathlib import Path

from dotenv.main import load_dotenv

from agent.main import main as agent_main

if __name__ == "__main__":
    load_dotenv()
    config_path = Path(__file__).resolve().parent / "config" / "agent.json"
    if not config_path.exists():
        raise FileNotFoundError(f"Missing agent config: {config_path}")

    print(f"[*] Starting SOC Agent using config: {config_path}")
    agent_main(config_path)
