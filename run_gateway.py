from dotenv import load_dotenv

from gateway.main import main as gateway_main


if __name__ == "__main__":
    load_dotenv()
    gateway_main()

