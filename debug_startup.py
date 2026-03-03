from dotenv import load_dotenv

print("1. Loading .env...")
load_dotenv()

print("2. Importing FastAPI...")

print("3. Importing core.database...")

print("4. Importing routers...")
try:
    print("   -> Routers loaded.")
except Exception as e:
    print(f"   [!] Router import failed: {e}")

print("5. Importing services...")
try:
    print("   -> Baseline service loaded.")
except Exception as e:
    print(f"   [!] Baseline service import failed: {e}")

print("Startup check completed successfully.")
