from dotenv import load_dotenv

from gateway.main import GatewayCollector


if __name__ == "__main__":
    load_dotenv()
    GatewayCollector().start()

