from agent.main import NetworkAgent
import os
from dotenv import load_dotenv

if __name__ == "__main__":
    load_dotenv()
    # Check if core/config.json exists
    config_path = "core/config.json"
    if not os.path.exists(config_path):
        # Fallback for when running from a different folder
        config_path = os.path.join(os.path.dirname(__file__), "core", "config.json")
        
    print(f"[*] Starting SOC Agent using config: {config_path}")
    NetworkAgent(config_path).start()
